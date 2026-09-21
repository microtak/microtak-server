//! Marti-compatible certificate enrollment HTTP endpoint.
//!
//! Implements the enrollment half of `docs/TEST-PLAN.md` §4: `GET
//! /Marti/api/tls/config` (no auth, CA info) and `POST
//! /Marti/api/tls/signClient/v2` (CSR submission, TC-ENROLL-02/03/06/07). A
//! successfully-signed device is recorded in the [`DeviceRegistry`].
//! `v1` (`POST /Marti/api/tls/signClient/`, no suffix) is deliberately not
//! implemented — research found no authoritative source for its real
//! behavior, and at least one reference implementation's `v1` is a
//! non-functional stub; guessing at it risked shipping a fabricated
//! contract, so it's left unimplemented rather than faked.
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

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

use crate::pki::CertificateAuthority;
use crate::registry::DeviceRegistry;

pub struct EnrollmentState {
    pub ca: CertificateAuthority,
    pub registry: DeviceRegistry,
    pub cert_validity: Duration,
}

pub fn router(state: Arc<EnrollmentState>) -> Router {
    Router::new()
        .route("/Marti/api/tls/config", get(get_config))
        .route("/Marti/api/tls/signClient/v2", post(sign_client_v2))
        .with_state(state)
}

/// Bind a real TCP listener and serve the enrollment API on it until the
/// process exits or the listener errors.
pub async fn serve(addr: SocketAddr, state: Arc<EnrollmentState>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await
}

/// TC-ENROLL-01: reachable with no client cert / no auth of any kind,
/// returns the CA's certificate so a client can build its truststore.
///
/// **Known simplification**: returns the bare PEM certificate rather than
/// the real Marti API's `certificateConfig` XML schema — this project
/// could not confirm that schema's exact field names from an authoritative
/// source (see `docs/TEST-PLAN.md` §4), so this is EdgeTAK's own minimal
/// contract for now, not a verified compatibility target.
async fn get_config(State(state): State<Arc<EnrollmentState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        state.ca.ca_cert_pem(),
    )
}

/// TC-ENROLL-02/03/06/07.
async fn sign_client_v2(
    State(state): State<Arc<EnrollmentState>>,
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

    if let Err(error) = state.registry.enroll(
        &signed.common_name,
        &signed.cert_pem,
        OffsetDateTime::now_utc().unix_timestamp(),
    ) {
        warn!(%error, common_name = %signed.common_name, "failed to record enrolled device");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to record device");
    }

    info!(common_name = %signed.common_name, "device enrolled");
    shaped_success_response(&headers, &signed.cert_pem)
}

fn is_acceptable_csr_content_type(content_type: &str) -> bool {
    let base = content_type.split(';').next().unwrap_or("").trim();
    matches!(base, "application/octet-stream" | "application/pkcs10" | "")
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
fn shaped_success_response(headers: &HeaderMap, cert_pem: &str) -> Response {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = json!({ "signedCert": cert_pem });

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
            "<enrollmentResponse><signedCert><![CDATA[{cert_pem}]]></signedCert></enrollmentResponse>"
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
            ca: CertificateAuthority::generate("EdgeTAK Test CA").unwrap(),
            registry: DeviceRegistry::in_memory(),
            cert_validity: Duration::days(365),
        })
    }

    async fn spawn_server(state: Arc<EnrollmentState>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// TC-ENROLL-01: reachable with no auth, returns CA cert info.
    #[tokio::test]
    async fn tc_enroll_01_config_endpoint_requires_no_auth() {
        let state = test_state();
        let ca_pem = state.ca.ca_cert_pem();
        let base_url = spawn_server(state).await;

        let response = reqwest::get(format!("{base_url}/Marti/api/tls/config"))
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
        assert!(signed_cert.contains("BEGIN CERTIFICATE"));

        // Cryptographically verify the returned cert against the CA --
        // proves the enrollment endpoint's output is actually usable, not
        // just "the server said 200."
        use x509_parser::prelude::{FromDer, X509Certificate};
        let ca_der = pem::parse(&ca_pem).unwrap();
        let (_, ca_x509) = X509Certificate::from_der(ca_der.contents()).unwrap();
        let leaf_der = pem::parse(signed_cert).unwrap();
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
        assert!(parsed["signedCert"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
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
}
