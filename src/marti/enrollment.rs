//! Marti-compatible certificate enrollment HTTP endpoint.
//!
//! Implements the enrollment half of `docs/TEST-PLAN.md` §4: `GET
//! /Marti/api/tls/config` (no auth, CSR subject naming hints -- real
//! `certificateConfig` XML, confirmed from `dfpc-coe/node-tak`'s real
//! client source), `GET /Marti/api/tls/ca.pem` (no auth, MicroTAK's own
//! addition for CA cert distribution), and `POST
//! /Marti/api/tls/signClient/v2` (CSR submission, TC-ENROLL-02/03/06/07,
//! plus a real-password-authenticated path for CloudTAK/TAK-Server-style
//! clients -- see that handler's own comment). A successfully-signed
//! device is recorded in the [`DeviceRegistry`]. `v1` (`POST
//! /Marti/api/tls/signClient/`, no suffix) is deliberately not implemented
//! — research found no authoritative source for its real behavior, and at
//! least one reference implementation's `v1` is a non-functional stub;
//! guessing at it risked shipping a fabricated contract, so it's left
//! unimplemented rather than faked.
//!
//! **Known simplification**: served over plain HTTP for now, not wrapped
//! in TLS. The real Marti spec serves enrollment over HTTPS with
//! `clientAuth=false` specifically to prevent a MITM from substituting a
//! different CA/response in transit. Neither the CSR nor the signed cert
//! are secrets (only the private key, which never leaves the client), so
//! the confidentiality impact of plain HTTP here is low, but the integrity
//! concern (a MITM swapping in an attacker's own CA) is real. Production
//! deployments should front this with TLS (reverse proxy, or a future
//! direct TLS listener here) until that gap is closed.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

use super::PeerIp;
use crate::app::EnrollmentMode;
use crate::bootstrap::{BootstrapError, BootstrapToken};
use crate::enrollment_tokens::EnrollmentTokenStore;
use crate::pki::CertificateAuthority;
use crate::ratelimit::{user_key, AuthLimiter};
use crate::registry::{DeviceRegistry, RegistryError};
use crate::users::UserStore;

pub struct EnrollmentState {
    pub ca: CertificateAuthority,
    pub registry: Arc<DeviceRegistry>,
    pub cert_validity: Duration,
    pub tokens: Arc<EnrollmentTokenStore>,
    /// See [`EnrollmentMode`]'s own doc comment.
    pub enrollment_mode: EnrollmentMode,
    /// The admin's cert Common Name -- same value `marti::admin::AdminState`
    /// gates on. Reserved here: only the bootstrap token can enroll it.
    pub admin_common_name: Option<String>,
    /// Real TAK-Server-compatible password auth: a request presenting a
    /// valid `Authorization: Basic` credential on `signClient/v2` is
    /// accepted regardless of `enrollment_mode` -- see that handler's own
    /// comment for why.
    pub users: Arc<UserStore>,
    /// The one-time token that alone can enroll `admin_common_name` -- see
    /// [`crate::bootstrap`].
    pub bootstrap: Arc<BootstrapToken>,
    /// Failed-attempt limiting and bounded password checks -- see
    /// [`crate::ratelimit`]. Shared with `/oauth/token`.
    pub limiter: Arc<AuthLimiter>,
}

impl EnrollmentState {
    /// Whether a request that presents no password credential must carry
    /// a valid invite token. `Auto` is locked from the very first start --
    /// there is no open window before the admin enrolls (the admin itself
    /// enrolls with the bootstrap token, see [`crate::bootstrap`]).
    fn is_locked_down(&self) -> bool {
        match self.enrollment_mode {
            EnrollmentMode::Open => false,
            EnrollmentMode::Auto => true,
        }
    }

    fn is_admin_cn(&self, common_name: &str) -> bool {
        self.admin_common_name.as_deref() == Some(common_name)
    }
}

/// Largest accepted enrollment request body -- a real CSR is a few
/// kilobytes; anything far beyond that is refused before being buffered
/// and parsed (TC-LIMIT-09).
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Build the enrollment router. Bind it with [`super::PlainHttpServer`].
pub fn router(state: Arc<EnrollmentState>) -> Router {
    Router::new()
        .route("/Marti/api/tls/config", get(get_config))
        .route("/Marti/api/tls/ca.pem", get(get_ca_pem))
        .route("/Marti/api/tls/signClient/v2", post(sign_client_v2))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// TC-ENROLL-01: reachable with no client cert / no auth of any kind.
///
/// Real Marti/TAK-Server contract, confirmed from `dfpc-coe/node-tak`'s
/// real client source (`lib/api/credentials.ts`'s `config()`/`generate()`):
/// an XML `certificateConfig` document naming the `O`/`OU` values a client
/// should embed in its CSR subject -- **not** the CA certificate itself
/// (an earlier "known simplification" here served the bare CA PEM from
/// this same path instead, before this schema had been confirmed from an
/// authoritative source; see [`get_ca_pem`] for where that moved).
async fn get_config() -> impl IntoResponse {
    const NAME_ENTRIES_XML: &str = "<ns2:certificateConfig><nameEntries>\
        <nameEntry name=\"O\" value=\"MicroTAK\"/>\
        <nameEntry name=\"OU\" value=\"MicroTAK\"/>\
        </nameEntries></ns2:certificateConfig>";
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/xml")],
        NAME_ENTRIES_XML,
    )
}

/// MicroTAK's own addition (no real Marti path defines this): the bare CA
/// certificate, for a client/operator that needs to build a truststore --
/// what `/Marti/api/tls/config` used to serve before it was fixed to match
/// the real `certificateConfig` XML schema instead (see [`get_config`]).
async fn get_ca_pem(State(state): State<Arc<EnrollmentState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        state.ca.ca_cert_pem(),
    )
}

#[derive(Deserialize)]
struct EnrollQuery {
    #[serde(default)]
    token: Option<String>,
}

/// TC-ENROLL-02/03/06/07, plus the identity rules of TC-ENROLL-13/15:
///
/// 1. **Password credential** (`Authorization: Basic`, the real TAK-Server /
///    CloudTAK `Credentials.generate()` path): its own trust path,
///    independent of `enrollment_mode`. The CSR's CN must equal the
///    authenticated username, and this is the *only* path that may
///    re-enroll (rotate) an existing identity -- the one that proves it
///    owns that identity. Invalid credentials are a hard failure, never a
///    fall-through to the other paths.
/// 2. **The admin CN** is reserved: only the one-time bootstrap token
///    (`?token=`) can enroll it, in every mode.
/// 3. **Everything else** may only ever create a *new* identity: an
///    already-enrolled CN is refused with 409 before any token is spent.
///    In `Auto` mode a valid invite token is required; `Open` needs none.
///
/// Failed credential checks count against the client's address (and, for
/// passwords, the username) in [`AuthLimiter`]; once exhausted, requests
/// are refused with 429 before any check runs.
async fn sign_client_v2(
    State(state): State<Arc<EnrollmentState>>,
    peer: PeerIp,
    Query(query): Query<EnrollQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // TC-ENROLL-03: reject a form-encoded (or otherwise non-raw-body)
    // submission with a clear, specific error, rather than silently
    // misparsing it -- the exact bug confirmed in a real reference
    // implementation this project studied.
    if !is_acceptable_csr_content_type(content_type) {
        warn!(
            content_type,
            "rejected CSR submission with unacceptable Content-Type"
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!(
                "Content-Type must be application/octet-stream or application/pkcs10 (got '{content_type}')"
            ),
        );
    }

    let csr_pem = match normalize_csr_body(&body) {
        Ok(pem) => pem,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, &message),
    };

    // TC-ENROLL-06: a malformed/non-CSR payload is rejected cleanly.
    // Signing is side-effect free (nothing is recorded or returned until
    // every check below passes); it's done first to learn the CSR's CN.
    let signed = match state.ca.sign_csr(&csr_pem, state.cert_validity) {
        Ok(signed) => signed,
        Err(error) => {
            warn!(%error, "CSR signing failed");
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("failed to sign CSR: {error}"),
            );
        }
    };
    let common_name = signed.common_name.as_str();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let ip_key = peer.limit_key();

    let enrolled = match basic_auth_credentials(&headers) {
        Some((username, password)) => {
            let user_key = user_key(&username);
            if state.limiter.is_blocked(&ip_key) || state.limiter.is_blocked(&user_key) {
                warn!(%username, "signClient/v2 rate-limited after repeated failed attempts");
                return too_many_attempts();
            }
            if !state.limiter.verify_password(&state.users, &username, &password).await {
                state.limiter.record_failure(&ip_key);
                state.limiter.record_failure(&user_key);
                warn!(%username, "signClient/v2 rejected: invalid username or password");
                return error_response(StatusCode::UNAUTHORIZED, "invalid username or password");
            }
            // The CSR's CN is the identity being requested -- without this
            // check, any authenticated user could mint a cert for any
            // other identity just by asking, defeating the point of
            // requiring authentication at all.
            if common_name != username {
                warn!(
                    %username,
                    requested_cn = %common_name,
                    "signClient/v2 rejected: CSR Common Name must match the authenticated username"
                );
                return error_response(
                    StatusCode::FORBIDDEN,
                    "CSR Common Name must match the authenticated username",
                );
            }
            if state.is_admin_cn(common_name) {
                warn!(%username, "signClient/v2 rejected: the admin identity can't be enrolled with a password");
                return admin_requires_bootstrap();
            }
            // Proven owner of this identity: may create or rotate it.
            state.registry.enroll(common_name, &signed.cert_pem, now)
        }
        None if state.is_admin_cn(common_name) => {
            let Some(token) = query.token.as_deref() else {
                warn!(common_name, "admin enrollment rejected: no bootstrap token");
                return admin_requires_bootstrap();
            };
            if state.limiter.is_blocked(&ip_key) {
                return too_many_attempts();
            }
            match state.bootstrap.consume_with(token, || {
                state.registry.enroll_new(common_name, &signed.cert_pem, now)
            }) {
                Ok(record) => {
                    info!(common_name, "admin device enrolled with the bootstrap token");
                    Ok(record)
                }
                Err(BootstrapError::Action(error)) => Err(error),
                Err(error) => {
                    state.limiter.record_failure(&ip_key);
                    warn!(common_name, %error, "admin enrollment rejected");
                    return admin_requires_bootstrap();
                }
            }
        }
        None => {
            if state.registry.find(common_name).is_some() {
                warn!(common_name, "enrollment rejected: identity already enrolled");
                return already_enrolled(common_name);
            }
            if state.is_locked_down() {
                let Some(token) = query.token.as_deref() else {
                    warn!(common_name, "enrollment rejected: no token provided");
                    return error_response(
                        StatusCode::FORBIDDEN,
                        "a valid enrollment token is required",
                    );
                };
                if state.limiter.is_blocked(&ip_key) {
                    return too_many_attempts();
                }
                if let Err(error) = state.tokens.validate_and_consume(token, common_name, now) {
                    state.limiter.record_failure(&ip_key);
                    warn!(common_name, %error, "enrollment rejected: invalid token");
                    return error_response(
                        StatusCode::FORBIDDEN,
                        &format!("invalid enrollment token: {error}"),
                    );
                }
            }
            state.registry.enroll_new(common_name, &signed.cert_pem, now)
        }
    };

    match enrolled {
        Ok(_) => {}
        Err(RegistryError::AlreadyEnrolled(_)) => return already_enrolled(common_name),
        Err(error) => {
            warn!(%error, common_name, "failed to record enrolled device");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to record device");
        }
    }

    info!(common_name, "device enrolled");
    shaped_success_response(&headers, &signed.cert_pem, &state.ca.ca_cert_pem())
}

fn too_many_attempts() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "too many failed attempts, try again later",
    )
}

fn admin_requires_bootstrap() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "the admin identity can only be enrolled with the server's bootstrap token",
    )
}

fn already_enrolled(common_name: &str) -> Response {
    error_response(
        StatusCode::CONFLICT,
        &format!(
            "'{common_name}' is already enrolled; re-enrolling an existing identity requires that identity's own password credentials"
        ),
    )
}

/// Decode an `Authorization: Basic base64(username:password)` header, if
/// present. Returns `None` for a missing header, a non-Basic scheme, or a
/// malformed value -- all treated as "no credentials presented," not an
/// error, since Basic Auth here is optional (an alternative to the invite
/// token, not a requirement).
fn basic_auth_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

/// Strip PEM armor (`-----BEGIN/END...-----` lines), leaving just the
/// base64 body -- the real Marti wire format for a `signedCert`/`ca0`
/// field, confirmed from `node-tak`'s real client (`credentials.ts`'s
/// `generate()` hardcodes re-wrapping this itself:
/// `'-----BEGIN CERTIFICATE-----\n' + res.signedCert + '\n-----END CERTIFICATE-----'`).
fn strip_pem_armor(cert_pem: &str) -> String {
    cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_acceptable_csr_content_type(content_type: &str) -> bool {
    let base = content_type.split(';').next().unwrap_or("").trim();
    // `text/plain` added after finding a real client (OmniTAK-iOS, a
    // third-party TAK client) sends its base64 CSR body with this exact
    // Content-Type unconditionally, with no way to configure otherwise --
    // see wiki/OmniTAK-iOS.md.
    matches!(
        base,
        "application/octet-stream" | "application/pkcs10" | "text/plain" | ""
    )
}

/// Accept either a fully PEM-armored CSR or bare base64 with the
/// `BEGIN/END CERTIFICATE REQUEST` markers stripped -- matching the
/// leniency a real reference implementation's enrollment endpoint has,
/// confirmed useful since some clients omit the armor.
fn normalize_csr_body(body: &[u8]) -> Result<String, String> {
    let text =
        std::str::from_utf8(body).map_err(|_| "CSR body is not valid UTF-8 text".to_string())?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("CSR body is empty".to_string());
    }
    if trimmed.contains("BEGIN CERTIFICATE REQUEST") {
        Ok(trimmed.to_string())
    } else {
        Ok(format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{trimmed}\n-----END CERTIFICATE REQUEST-----\n"
        ))
    }
}

/// TC-ENROLL-07: shape the success response per the requesting client's
/// `Accept` header, matching a real, deliberate quirk found in a reference
/// implementation's enrollment endpoint (one real client expects a JSON
/// body served under `Content-Type: text/plain`).
fn shaped_success_response(headers: &HeaderMap, cert_pem: &str, ca_cert_pem: &str) -> Response {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Bare base64, PEM armor stripped -- the real Marti wire format (see
    // `strip_pem_armor`'s own doc comment). `ca0` is optional per the real
    // client's own parsing (`if (res.ca0) chain.push(res.ca0)`), included
    // here so a caller gets a real trust chain, not just the leaf.
    let bare_cert = strip_pem_armor(cert_pem);
    let bare_ca = strip_pem_armor(ca_cert_pem);
    let body = json!({ "signedCert": bare_cert, "ca0": bare_ca });

    if accept.contains("text/plain") {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            body.to_string(),
        )
            .into_response()
    } else if accept.is_empty() || accept.contains("application/json") || accept.contains("*/*") {
        (StatusCode::OK, Json(body)).into_response()
    } else {
        let xml = format!(
            "<enrollmentResponse><signedCert><![CDATA[{bare_cert}]]></signedCert><ca0><![CDATA[{bare_ca}]]></ca0></enrollmentResponse>"
        );
        (StatusCode::OK, [(header::CONTENT_TYPE, "application/xml")], xml).into_response()
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::build_csr;
    use reqwest::header::{ACCEPT, CONTENT_TYPE};

    fn test_state() -> Arc<EnrollmentState> {
        Arc::new(EnrollmentState {
            ca: CertificateAuthority::generate("MicroTAK Test CA").unwrap(),
            registry: Arc::new(DeviceRegistry::in_memory()),
            cert_validity: Duration::days(365),
            tokens: Arc::new(EnrollmentTokenStore::in_memory()),
            enrollment_mode: EnrollmentMode::Open,
            admin_common_name: None,
            users: Arc::new(UserStore::in_memory()),
            bootstrap: Arc::new(BootstrapToken::none()),
            limiter: Arc::new(AuthLimiter::default()),
        })
    }

    async fn spawn_server(state: Arc<EnrollmentState>) -> String {
        let server = super::super::PlainHttpServer::bind("127.0.0.1:0".parse().unwrap(), router(state))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());
        format!("http://{addr}")
    }

    /// Re-armor a bare-base64 `signedCert`/`ca0` value into full PEM, the
    /// same way a real client (`node-tak`'s `credentials.ts`) does before
    /// using it -- for tests that need to actually parse the result.
    fn wrap_pem(bare_base64: &str) -> String {
        format!("-----BEGIN CERTIFICATE-----\n{bare_base64}\n-----END CERTIFICATE-----\n")
    }

    /// TC-ENROLL-01: reachable with no auth, returns real CSR-naming XML
    /// (not the CA cert -- see [`get_ca_pem`] for that).
    #[tokio::test]
    async fn tc_enroll_01_config_endpoint_requires_no_auth() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let response = reqwest::get(format!("{base_url}/Marti/api/tls/config"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert!(body.contains("certificateConfig"));
        assert!(body.contains("name=\"O\""));
        assert!(body.contains("name=\"OU\""));
    }

    /// MicroTAK's own CA-distribution endpoint: no auth required, returns
    /// the real, full-PEM CA certificate.
    #[tokio::test]
    async fn ca_pem_endpoint_requires_no_auth_and_returns_the_real_ca() {
        let state = test_state();
        let ca_pem = state.ca.ca_cert_pem();
        let base_url = spawn_server(state).await;

        let response = reqwest::get(format!("{base_url}/Marti/api/tls/ca.pem"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert_eq!(body, ca_pem);
    }

    /// TC-ENROLL-02: a raw-body octet-stream CSR (PEM headers stripped) is
    /// accepted and produces a real, CA-signed certificate.
    #[tokio::test]
    async fn tc_enroll_02_accepts_raw_octet_stream_csr() {
        let state = test_state();
        let ca_pem = state.ca.ca_cert_pem();
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-e2e").unwrap();
        let bare_base64: String = csr_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(bare_base64)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        let signed_cert = body["signedCert"].as_str().unwrap();
        // Real Marti wire format: bare base64, no PEM armor -- a real
        // client (`node-tak`'s `credentials.ts`) re-wraps this itself.
        assert!(!signed_cert.contains("BEGIN CERTIFICATE"));
        assert!(!body["ca0"].as_str().unwrap().is_empty(), "expected a CA chain cert too");

        // Cryptographically verify the returned cert against the CA --
        // proves the enrollment endpoint's output is actually usable, not
        // just "the server said 200." Re-armor it first, matching what a
        // real client does with this same bare value.
        use x509_parser::prelude::{FromDer, X509Certificate};
        let ca_der = pem::parse(&ca_pem).unwrap();
        let (_, ca_x509) = X509Certificate::from_der(ca_der.contents()).unwrap();
        let leaf_der = pem::parse(wrap_pem(signed_cert)).unwrap();
        let (_, leaf_x509) = X509Certificate::from_der(leaf_der.contents()).unwrap();
        assert!(leaf_x509
            .verify_signature(Some(ca_x509.public_key()))
            .is_ok());
    }

    /// TC-ENROLL-03: the exact real-world bug this project found twice
    /// independently -- a form-encoded submission must be rejected with a
    /// clear error, not silently misparsed.
    #[tokio::test]
    async fn tc_enroll_03_rejects_form_encoded_csr_submission() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-form").unwrap();

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["error"].as_str().unwrap().contains("Content-Type"));
    }

    /// A real client (OmniTAK-iOS) sends its raw base64 CSR body under
    /// `Content-Type: text/plain`, unconditionally, with no way to
    /// configure otherwise -- must be accepted, not treated like the
    /// form-encoded case above.
    #[tokio::test]
    async fn accepts_csr_submitted_as_text_plain() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-omnitak").unwrap();
        let bare_base64: String = csr_pem.lines().filter(|line| !line.starts_with("-----")).collect();

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(bare_base64)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    /// TC-ENROLL-06: a malformed/non-CSR payload is rejected cleanly.
    #[tokio::test]
    async fn tc_enroll_06_rejects_malformed_csr_payload() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body("this is not a CSR")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
    }

    /// TC-ENROLL-07: an `Accept: text/plain` request gets a JSON body under
    /// a `text/plain` Content-Type -- matching a real client compatibility
    /// quirk found in a reference implementation.
    #[tokio::test]
    async fn tc_enroll_07_shapes_response_for_text_plain_accept() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-quirk").unwrap();

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(ACCEPT, "text/plain")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain"
        );
        let body_text = response.text().await.unwrap();
        // Still a JSON *body*, just served with a text/plain Content-Type.
        let parsed: serde_json::Value = serde_json::from_str(&body_text).unwrap();
        assert!(!parsed["signedCert"].as_str().unwrap().is_empty());
    }

    /// A successfully enrolled device is recorded in the registry.
    #[tokio::test]
    async fn enrollment_records_device_in_registry() {
        let state = test_state();
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-registry-check").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let record = registry_check.registry.find("device-registry-check");
        assert!(record.is_some());
    }

    /// `Auto` mode *with the admin device already enrolled* -- the state
    /// that actually locks enrollment down (see `EnrollmentState::is_locked_down`).
    /// Pre-enrolling the admin directly into the registry (bypassing HTTP)
    /// simulates "the admin already bootstrapped," the same way other
    /// tests in this project seed store state directly rather than only
    /// ever going through the HTTP layer being tested.
    fn test_state_requiring_tokens() -> Arc<EnrollmentState> {
        let registry = Arc::new(DeviceRegistry::in_memory());
        registry.enroll("test-admin", "fake-admin-cert-pem", 0).unwrap();
        Arc::new(EnrollmentState {
            ca: CertificateAuthority::generate("MicroTAK Test CA").unwrap(),
            registry,
            cert_validity: Duration::days(365),
            tokens: Arc::new(EnrollmentTokenStore::in_memory()),
            enrollment_mode: EnrollmentMode::Auto,
            admin_common_name: Some("test-admin".to_string()),
            users: Arc::new(UserStore::in_memory()),
            bootstrap: Arc::new(BootstrapToken::none()),
            limiter: Arc::new(AuthLimiter::default()),
        })
    }

    /// The gate is off by default (no admin enrolled yet): `test_state()`
    /// already proves enrollment works with no token at all in that state
    /// (every test above uses it). This proves the *other* half: once the
    /// admin device has actually enrolled under `Auto` mode, a request
    /// with no token at all is rejected, and the device is never
    /// registered.
    #[tokio::test]
    async fn rejects_enrollment_with_no_token_when_gating_is_enabled() {
        let state = test_state_requiring_tokens();
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-no-token").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 403);
        assert!(registry_check.registry.find("device-no-token").is_none());
    }

    /// A valid, freshly-minted token lets enrollment through, and is
    /// consumed by it (single-use).
    #[tokio::test]
    async fn accepts_enrollment_with_a_valid_token_and_consumes_it() {
        let state = test_state_requiring_tokens();
        let tokens = Arc::clone(&state.tokens);
        let base_url = spawn_server(state).await;

        let token = tokens.mint(None, None, 1_000).unwrap();
        let (csr_pem, _key) = build_csr("device-with-token").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!(
                "{base_url}/Marti/api/tls/signClient/v2?token={token}"
            ))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let all = tokens.list();
        assert!(all[0].used, "the token should be consumed after use");
        assert_eq!(all[0].used_by_common_name.as_deref(), Some("device-with-token"));
    }

    /// The same token can't be used twice -- the second device is rejected
    /// and never registered, even though the token was real.
    #[tokio::test]
    async fn rejects_reusing_an_already_consumed_token() {
        let state = test_state_requiring_tokens();
        let tokens = Arc::clone(&state.tokens);
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let token = tokens.mint(None, None, 1_000).unwrap();
        let client = reqwest::Client::new();

        let (csr_a, _key_a) = build_csr("device-a").unwrap();
        let first = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2?token={token}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_a)
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), 200);

        let (csr_b, _key_b) = build_csr("device-b").unwrap();
        let second = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2?token={token}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_b)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 403);
        assert!(registry_check.registry.find("device-b").is_none());
    }

    /// A revoked token is rejected even if it was never used.
    #[tokio::test]
    async fn rejects_a_revoked_token() {
        let state = test_state_requiring_tokens();
        let tokens = Arc::clone(&state.tokens);
        let base_url = spawn_server(state).await;

        let token = tokens.mint(None, None, 1_000).unwrap();
        tokens.revoke(&token).unwrap();

        let (csr_pem, _key) = build_csr("device-revoked-token").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2?token={token}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }

    /// `Open` is a real, permanent override: enrollment stays open even
    /// once the admin device has enrolled, unlike `Auto`. Distinguishes
    /// "we deliberately keep this open" from "Auto just hasn't locked down
    /// yet" -- both would otherwise look identical from the outside if
    /// this branch were ever accidentally collapsed into `Auto`'s check.
    #[tokio::test]
    async fn open_mode_stays_open_even_after_the_admin_has_enrolled() {
        let registry = Arc::new(DeviceRegistry::in_memory());
        registry.enroll("open-mode-admin", "fake-cert-pem", 0).unwrap();
        let state = Arc::new(EnrollmentState {
            ca: CertificateAuthority::generate("MicroTAK Test CA").unwrap(),
            registry,
            cert_validity: Duration::days(365),
            tokens: Arc::new(EnrollmentTokenStore::in_memory()),
            enrollment_mode: EnrollmentMode::Open,
            admin_common_name: Some("open-mode-admin".to_string()),
            users: Arc::new(UserStore::in_memory()),
            bootstrap: Arc::new(BootstrapToken::none()),
            limiter: Arc::new(AuthLimiter::default()),
        });
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-still-open").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    /// Real password-authenticated enrollment (the CloudTAK/`node-tak`
    /// `Credentials.generate()` path) bypasses the invite-token gate
    /// entirely, even while locked down -- a valid password credential is
    /// its own trust path, not conditional on `enrollment_mode`.
    #[tokio::test]
    async fn basic_auth_enrollment_bypasses_the_token_gate_even_when_locked_down() {
        let state = test_state_requiring_tokens();
        state.users.mint("device-with-password", "hunter2", 0).unwrap();
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-with-password").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .basic_auth("device-with-password", Some("hunter2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(!body["signedCert"].as_str().unwrap().is_empty());
        assert!(registry_check.registry.find("device-with-password").is_some());
    }

    /// Presenting *wrong* Basic-Auth credentials is a hard failure -- it
    /// must not silently fall through to the (in this case, wide-open)
    /// token gate just because that gate would have allowed the request
    /// anyway.
    #[tokio::test]
    async fn basic_auth_with_wrong_password_is_rejected_even_in_open_mode() {
        let state = test_state(); // Open mode: no token would be required at all.
        state.users.mint("device-with-password", "hunter2", 0).unwrap();
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-with-password").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .basic_auth("device-with-password", Some("wrong-password"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
        assert!(registry_check.registry.find("device-with-password").is_none());
    }

    async fn post_csr(base_url: &str, query: &str, csr_pem: String) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{base_url}/Marti/api/tls/signClient/v2{query}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap()
    }

    /// TC-ENROLL-13: an invite token only ever creates a *new* identity. A
    /// token-holder asking for an already-enrolled CN (here: an ordinary
    /// device) is rejected before the token is consumed, and the existing
    /// device's certificate is left untouched.
    #[tokio::test]
    async fn tc_enroll_13_token_cannot_take_over_an_existing_identity() {
        let state = test_state_requiring_tokens();
        state.registry.enroll("device-victim", "victim-cert-pem", 0).unwrap();
        let tokens = Arc::clone(&state.tokens);
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let token = tokens.mint(None, None, 1_000).unwrap();
        let (csr_pem, _key) = build_csr("device-victim").unwrap();
        let response = post_csr(&base_url, &format!("?token={token}"), csr_pem).await;

        assert_eq!(response.status(), 409);
        assert!(!tokens.list()[0].used, "a rejected request must not consume the token");
        assert_eq!(
            registry_check.registry.find("device-victim").unwrap().cert_pem,
            "victim-cert-pem"
        );
    }

    /// TC-ENROLL-13, the admin variant: the one takeover that matters
    /// most -- an invite token must not yield a cert for the admin CN
    /// (admin API access is gated on CN alone).
    #[tokio::test]
    async fn tc_enroll_13_token_cannot_take_over_the_admin_identity() {
        let state = test_state_requiring_tokens();
        let tokens = Arc::clone(&state.tokens);
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let token = tokens.mint(None, None, 1_000).unwrap();
        let (csr_pem, _key) = build_csr("test-admin").unwrap();
        let response = post_csr(&base_url, &format!("?token={token}"), csr_pem).await;

        assert!(
            response.status() == 403 || response.status() == 409,
            "got {}",
            response.status()
        );
        assert!(!tokens.list()[0].used);
        assert_eq!(
            registry_check.registry.find("test-admin").unwrap().cert_pem,
            "fake-admin-cert-pem"
        );
    }

    /// Open mode keeps enrollment open for *new* identities only -- it
    /// must not hand out a fresh cert for an identity someone else already
    /// holds, with no credential at all.
    #[tokio::test]
    async fn open_mode_cannot_re_enroll_an_existing_identity_without_credentials() {
        let state = test_state();
        state.registry.enroll("device-victim", "victim-cert-pem", 0).unwrap();
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-victim").unwrap();
        let response = post_csr(&base_url, "", csr_pem).await;

        assert_eq!(response.status(), 409);
        assert_eq!(
            registry_check.registry.find("device-victim").unwrap().cert_pem,
            "victim-cert-pem"
        );
    }

    /// TC-ENROLL-13 under contention: of many simultaneous requests for the
    /// same *new* identity, exactly one wins and the rest get 409 -- none
    /// silently replaces the winner's cert. Note: in practice the early
    /// "already enrolled?" check answers most of these; the narrower race
    /// where two requests both pass it is closed by `enroll_new`'s atomic
    /// check-and-insert, which this test does not reliably hit -- that
    /// guarantee is covered directly by the registry's own
    /// `enroll_new_refuses_an_existing_common_name_and_keeps_its_cert`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_enrollments_of_one_new_identity_yield_exactly_one_cert() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let attempts = (0..24).map(|_| {
            let base_url = base_url.clone();
            tokio::spawn(async move {
                let (csr_pem, _key) = build_csr("device-contested").unwrap();
                post_csr(&base_url, "", csr_pem).await.status().as_u16()
            })
        });
        let mut statuses = Vec::new();
        for attempt in attempts {
            statuses.push(attempt.await.unwrap());
        }
        assert_eq!(statuses.iter().filter(|&&s| s == 200).count(), 1, "{statuses:?}");
        assert!(statuses.iter().all(|&s| s == 200 || s == 409), "{statuses:?}");
    }

    /// TC-ENROLL-15: before the admin has enrolled, nobody on the network
    /// can simply claim the admin CN -- not in `Auto`, not in `Open`.
    #[tokio::test]
    async fn tc_enroll_15_admin_cn_cannot_be_claimed_without_the_bootstrap_token() {
        for mode in [EnrollmentMode::Auto, EnrollmentMode::Open] {
            let state = Arc::new(EnrollmentState {
                ca: CertificateAuthority::generate("MicroTAK Test CA").unwrap(),
                registry: Arc::new(DeviceRegistry::in_memory()),
                cert_validity: Duration::days(365),
                tokens: Arc::new(EnrollmentTokenStore::in_memory()),
                enrollment_mode: mode,
                admin_common_name: Some("test-admin".to_string()),
                users: Arc::new(UserStore::in_memory()),
                bootstrap: Arc::new(BootstrapToken::none()),
                limiter: Arc::new(AuthLimiter::default()),
            });
            let registry_check = Arc::clone(&state);
            let base_url = spawn_server(state).await;

            let (csr_pem, _key) = build_csr("test-admin").unwrap();
            let response = post_csr(&base_url, "", csr_pem).await;

            assert_eq!(response.status(), 403, "mode {mode:?}");
            assert!(registry_check.registry.find("test-admin").is_none(), "mode {mode:?}");
        }
    }

    fn test_state_with_bootstrap(bootstrap: &str) -> Arc<EnrollmentState> {
        Arc::new(EnrollmentState {
            ca: CertificateAuthority::generate("MicroTAK Test CA").unwrap(),
            registry: Arc::new(DeviceRegistry::in_memory()),
            cert_validity: Duration::days(365),
            tokens: Arc::new(EnrollmentTokenStore::in_memory()),
            enrollment_mode: EnrollmentMode::Auto,
            admin_common_name: Some("test-admin".to_string()),
            users: Arc::new(UserStore::in_memory()),
            bootstrap: Arc::new(BootstrapToken::in_memory(bootstrap)),
            limiter: Arc::new(AuthLimiter::default()),
        })
    }

    /// TC-ENROLL-15: the bootstrap token enrolls the admin exactly once.
    #[tokio::test]
    async fn tc_enroll_15_bootstrap_token_enrolls_the_admin_once() {
        let bootstrap = "b".repeat(64);
        let state = test_state_with_bootstrap(&bootstrap);
        let check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("test-admin").unwrap();
        let first = post_csr(&base_url, &format!("?token={bootstrap}"), csr_pem).await;
        assert_eq!(first.status(), 200);
        let admin_cert = check.registry.find("test-admin").unwrap().cert_pem;
        assert!(!check.bootstrap.is_outstanding());

        let (csr_pem, _key) = build_csr("test-admin").unwrap();
        let second = post_csr(&base_url, &format!("?token={bootstrap}"), csr_pem).await;
        assert_eq!(second.status(), 403);
        assert_eq!(check.registry.find("test-admin").unwrap().cert_pem, admin_cert);
    }

    /// The bootstrap token is not a general-purpose invite: it can't
    /// enroll any other identity, and it isn't spent by trying.
    #[tokio::test]
    async fn bootstrap_token_cannot_enroll_a_non_admin_identity() {
        let bootstrap = "b".repeat(64);
        let state = test_state_with_bootstrap(&bootstrap);
        let check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-sneaky").unwrap();
        let response = post_csr(&base_url, &format!("?token={bootstrap}"), csr_pem).await;
        assert_eq!(response.status(), 403);
        assert!(check.registry.find("device-sneaky").is_none());
        assert!(check.bootstrap.is_outstanding());
    }

    /// A wrong bootstrap token is refused and doesn't burn the real one.
    #[tokio::test]
    async fn a_wrong_bootstrap_token_is_rejected() {
        let state = test_state_with_bootstrap(&"b".repeat(64));
        let check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("test-admin").unwrap();
        let response = post_csr(&base_url, &format!("?token={}", "c".repeat(64)), csr_pem).await;
        assert_eq!(response.status(), 403);
        assert!(check.registry.find("test-admin").is_none());
        assert!(check.bootstrap.is_outstanding());
    }

    /// The password path is the one way to rotate an existing identity's
    /// cert -- it proves ownership of that identity.
    #[tokio::test]
    async fn basic_auth_can_re_enroll_its_own_existing_identity() {
        let state = test_state_requiring_tokens();
        state.users.mint("device-rotating", "hunter2", 0).unwrap();
        state.registry.enroll("device-rotating", "old-cert-pem", 0).unwrap();
        let check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-rotating").unwrap();
        let response = reqwest::Client::new()
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .basic_auth("device-rotating", Some("hunter2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_ne!(check.registry.find("device-rotating").unwrap().cert_pem, "old-cert-pem");
    }

    /// Even a valid password account can't obtain the admin identity.
    #[tokio::test]
    async fn basic_auth_cannot_enroll_the_admin_identity() {
        let state = test_state_with_bootstrap(&"b".repeat(64));
        // Seeded directly: the admin API refuses to create this account.
        state.users.mint("test-admin", "hunter2", 0).unwrap();
        let check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("test-admin").unwrap();
        let response = reqwest::Client::new()
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .basic_auth("test-admin", Some("hunter2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        assert!(check.registry.find("test-admin").is_none());
    }

    /// `Auto` is locked from the very first start -- not only once the
    /// admin has enrolled -- so there is no open window at all.
    #[tokio::test]
    async fn auto_mode_is_locked_before_the_admin_has_enrolled() {
        let state = Arc::new(EnrollmentState {
            ca: CertificateAuthority::generate("MicroTAK Test CA").unwrap(),
            registry: Arc::new(DeviceRegistry::in_memory()),
            cert_validity: Duration::days(365),
            tokens: Arc::new(EnrollmentTokenStore::in_memory()),
            enrollment_mode: EnrollmentMode::Auto,
            admin_common_name: Some("test-admin".to_string()),
            users: Arc::new(UserStore::in_memory()),
            bootstrap: Arc::new(BootstrapToken::none()),
            limiter: Arc::new(AuthLimiter::default()),
        });
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("device-early-bird").unwrap();
        let response = post_csr(&base_url, "", csr_pem).await;

        assert_eq!(response.status(), 403);
        assert!(registry_check.registry.find("device-early-bird").is_none());
    }

    /// TC-LIMIT-08: repeated failed password attempts are cut off with 429
    /// before reaching the (deliberately slow) Argon2 check -- after which
    /// even the right password is refused for the rest of the window.
    #[tokio::test]
    async fn tc_limit_08_repeated_failed_basic_auth_is_rate_limited() {
        let state = test_state();
        state.users.mint("device-with-password", "hunter2", 0).unwrap();
        let base_url = spawn_server(state).await;
        let client = reqwest::Client::new();

        let mut statuses = Vec::new();
        for _ in 0..12 {
            let (csr_pem, _key) = build_csr("device-with-password").unwrap();
            let response = client
                .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
                .basic_auth("device-with-password", Some("wrong"))
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(csr_pem)
                .send()
                .await
                .unwrap();
            statuses.push(response.status().as_u16());
        }
        assert!(statuses.contains(&401));
        assert_eq!(*statuses.last().unwrap(), 429, "got {statuses:?}");

        let (csr_pem, _key) = build_csr("device-with-password").unwrap();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .basic_auth("device-with-password", Some("hunter2"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 429);
    }

    /// TC-LIMIT-09: a request body far larger than any real CSR is refused
    /// before being buffered and parsed.
    #[tokio::test]
    async fn tc_limit_09_oversized_enrollment_body_is_rejected() {
        let state = test_state();
        let base_url = spawn_server(state).await;

        let response = post_csr(&base_url, "", "A".repeat(1024 * 1024)).await;
        assert_eq!(response.status(), 413);
    }

    /// An authenticated user can't mint a cert for a *different* identity
    /// just by asking -- the CSR's Common Name must match who actually
    /// authenticated.
    #[tokio::test]
    async fn basic_auth_rejects_csr_cn_not_matching_authenticated_username() {
        let state = test_state();
        state.users.mint("alice", "correct horse battery staple", 0).unwrap();
        let registry_check = Arc::clone(&state);
        let base_url = spawn_server(state).await;

        let (csr_pem, _key) = build_csr("bob").unwrap();
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base_url}/Marti/api/tls/signClient/v2"))
            .basic_auth("alice", Some("correct horse battery staple"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(csr_pem)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 403);
        assert!(registry_check.registry.find("bob").is_none());
    }
}
