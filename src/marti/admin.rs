//! Admin API: mint/list/revoke enrollment invite tokens
//! (`/Marti/api/admin/enrollmentTokens`) and user accounts
//! (`/Marti/api/admin/users`), plus a real TAK-Server-compatible
//! certificate-admin lookup (`/Marti/api/certadmin/cert/:hash`).
//!
//! mTLS-authenticated like the rest of the Marti API (served via
//! [`super::MtlsHttpServer`]), but with an additional identity check on top:
//! only the cert Common Name configured as [`crate::app::AppConfig::admin_common_name`]
//! may call these routes at all -- every other authenticated caller gets
//! 403, same as an unauthenticated one. If no `admin_common_name` is
//! configured, the admin API is unreachable by anyone (fails closed, not
//! open).
//!
//! **Bootstrap order, still real even with [`crate::app::EnrollmentMode::Auto`]'s
//! live transition**: these endpoints are only reachable over mTLS using a
//! cert enrollment already issued, so the admin's own device necessarily
//! has to enroll first -- which it can, since `Auto` only locks enrollment
//! down *after* that device exists in the registry (see
//! `marti::enrollment::EnrollmentState::is_locked_down`). No restart is
//! needed for this to happen, unlike the two-phase restart-based design
//! this replaced: enroll the admin device, and enrollment is locked for
//! everyone else from that same moment on, in the same running process.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use time::OffsetDateTime;

use super::PeerIdentity;
use crate::enrollment_tokens::{EnrollmentTokenError, EnrollmentTokenStore};
use crate::pki;
use crate::registry::DeviceRegistry;
use crate::users::UserStore;

#[derive(Clone)]
pub struct AdminState {
    pub tokens: Arc<EnrollmentTokenStore>,
    pub users: Arc<UserStore>,
    pub registry: Arc<DeviceRegistry>,
    /// `None` means the admin API is unreachable by anyone.
    pub admin_common_name: Option<String>,
}

pub fn router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/Marti/api/admin/enrollmentTokens",
            post(mint_token).get(list_tokens),
        )
        .route(
            "/Marti/api/admin/enrollmentTokens/:token",
            axum::routing::delete(revoke_token),
        )
        .route("/Marti/api/admin/users", post(mint_user).get(list_users))
        .route(
            "/Marti/api/admin/users/:username",
            axum::routing::delete(revoke_user),
        )
        .route("/Marti/api/certadmin/cert/:hash", axum::routing::get(get_cert_by_hash))
        .with_state(state)
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn token_error_response(error: EnrollmentTokenError) -> Response {
    match error {
        EnrollmentTokenError::NotFound => {
            error_response(StatusCode::NOT_FOUND, "unknown enrollment token".to_string())
        }
        other => error_response(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// Fails closed: `None` configured admin CN, or a mismatched authenticated
/// identity, are both rejected -- there is no "open" state for this API.
fn require_admin(state: &AdminState, identity: &PeerIdentity) -> Option<Response> {
    match &state.admin_common_name {
        Some(admin_cn) if admin_cn == &identity.0 => None,
        _ => Some(error_response(
            StatusCode::FORBIDDEN,
            "not authorized to use the admin API".to_string(),
        )),
    }
}

#[derive(Deserialize)]
struct MintTokenRequest {
    #[serde(rename = "expiresInSecs", default)]
    expires_in_secs: Option<i64>,
    #[serde(default)]
    note: Option<String>,
}

async fn mint_token(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    // An empty body is a valid "mint with defaults" request -- don't force
    // a caller to send `{}` just to get a never-expiring, unnoted token.
    let request: MintTokenRequest = if body.is_empty() {
        MintTokenRequest {
            expires_in_secs: None,
            note: None,
        }
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                return error_response(StatusCode::BAD_REQUEST, format!("invalid request body: {error}"))
            }
        }
    };

    match state
        .tokens
        .mint(request.expires_in_secs, request.note, now_unix())
    {
        Ok(token) => (StatusCode::CREATED, Json(serde_json::json!({ "token": token }))).into_response(),
        Err(error) => token_error_response(error),
    }
}

async fn list_tokens(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    Json(state.tokens.list()).into_response()
}

async fn revoke_token(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(token): Path<String>,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    match state.tokens.revoke(&token) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => token_error_response(error),
    }
}

fn user_error_response(error: crate::users::UserError) -> Response {
    match error {
        crate::users::UserError::NotFound => {
            error_response(StatusCode::NOT_FOUND, "unknown user".to_string())
        }
        crate::users::UserError::AlreadyExists => {
            error_response(StatusCode::CONFLICT, "user already exists".to_string())
        }
        other => error_response(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

#[derive(Deserialize)]
struct MintUserRequest {
    username: String,
    /// If omitted, a random password is generated and returned once --
    /// same ergonomics as an enrollment token's own single-reveal value.
    #[serde(default)]
    password: Option<String>,
}

async fn mint_user(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    let request: MintUserRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, format!("invalid request body: {error}"))
        }
    };
    let password = request.password.unwrap_or_else(random_password);
    match state.users.mint(&request.username, &password, now_unix()) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "username": request.username, "password": password })),
        )
            .into_response(),
        Err(error) => user_error_response(error),
    }
}

async fn list_users(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    Json(state.users.list()).into_response()
}

async fn revoke_user(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(username): Path<String>,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    match state.users.revoke(&username) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => user_error_response(error),
    }
}

fn random_password() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `GET /Marti/api/certadmin/cert/:hash` -- confirmed from real client
/// source (`dfpc-coe/node-tak`'s `lib/api/certificate.ts`'s `validate()`/
/// `get()`): a real client looks up a certificate by the SHA-256
/// fingerprint (colon-separated uppercase hex) it computed locally from its
/// own copy of the cert, to check whether the server still considers it
/// valid (known, not revoked). O(n) scan over the device registry
/// computing each stored cert's fingerprint on the fly -- simple, and fine
/// at this project's scale (see `pki::fingerprint_sha256_colon_hex`).
async fn get_cert_by_hash(
    State(state): State<AdminState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(hash): Path<String>,
) -> Response {
    if let Some(response) = require_admin(&state, &identity) {
        return response;
    }
    let Some(record) = state.registry.all().into_iter().find(|record| {
        pki::fingerprint_sha256_colon_hex(&record.cert_pem).as_deref() == Some(hash.as_str())
    }) else {
        return error_response(StatusCode::NOT_FOUND, "unknown certificate".to_string());
    };
    Json(serde_json::json!({
        "version": "3",
        "type": "TakCert",
        "data": {
            "hash": hash,
            "subjectDn": format!("CN={}", record.common_name),
            "userDn": format!("CN={}", record.common_name),
            "clientUid": record.common_name,
            "revocationDate": if record.revoked { Some("revoked") } else { None },
        },
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app_with_admin(
        admin_cn: Option<&str>,
    ) -> (Router, Arc<EnrollmentTokenStore>, Arc<UserStore>, Arc<DeviceRegistry>) {
        let tokens = Arc::new(EnrollmentTokenStore::in_memory());
        let users = Arc::new(UserStore::in_memory());
        let registry = Arc::new(DeviceRegistry::in_memory());
        let state = AdminState {
            tokens: Arc::clone(&tokens),
            users: Arc::clone(&users),
            registry: Arc::clone(&registry),
            admin_common_name: admin_cn.map(str::to_string),
        };
        (router(state), tokens, users, registry)
    }

    async fn request_as(
        app: &mut Router,
        identity: &str,
        method: &str,
        uri: &str,
        body: &str,
    ) -> Response {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .extension(PeerIdentity(identity.to_string()))
            .body(Body::from(body.to_string()))
            .unwrap();
        app.clone().oneshot(request).await.unwrap()
    }

    /// The core happy path: the configured admin mints a token, it shows
    /// up in the list, and it can then be revoked.
    #[tokio::test]
    async fn admin_can_mint_list_and_revoke_a_token() {
        let (mut app, _tokens, _users, _registry) = app_with_admin(Some("jz-admin"));

        let mint_response = request_as(&mut app, "jz-admin", "POST", "/Marti/api/admin/enrollmentTokens", "{}").await;
        assert_eq!(mint_response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(mint_response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = parsed["token"].as_str().unwrap().to_string();
        assert_eq!(token.len(), 64);

        let list_response = request_as(&mut app, "jz-admin", "GET", "/Marti/api/admin/enrollmentTokens", "").await;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX).await.unwrap();
        let list: Vec<serde_json::Value> = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["token"], token);

        let revoke_response = request_as(
            &mut app,
            "jz-admin",
            "DELETE",
            &format!("/Marti/api/admin/enrollmentTokens/{token}"),
            "",
        )
        .await;
        assert_eq!(revoke_response.status(), StatusCode::NO_CONTENT);
    }

    /// A non-admin authenticated caller is rejected, not silently allowed
    /// just because it's a valid mTLS connection.
    #[tokio::test]
    async fn non_admin_identity_is_rejected() {
        let (mut app, tokens, _users, _registry) = app_with_admin(Some("jz-admin"));
        let response = request_as(&mut app, "some-other-device", "POST", "/Marti/api/admin/enrollmentTokens", "{}").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(tokens.list().is_empty(), "the rejected request must not have minted anything");
    }

    /// No admin configured at all means the API is unreachable by anyone,
    /// not "open by default."
    #[tokio::test]
    async fn no_configured_admin_rejects_every_caller() {
        let (mut app, _tokens, _users, _registry) = app_with_admin(None);
        let response = request_as(&mut app, "anyone", "GET", "/Marti/api/admin/enrollmentTokens", "").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn revoking_unknown_token_is_404() {
        let (mut app, _tokens, _users, _registry) = app_with_admin(Some("jz-admin"));
        let response = request_as(
            &mut app,
            "jz-admin",
            "DELETE",
            "/Marti/api/admin/enrollmentTokens/does-not-exist",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn mint_accepts_expiry_and_note() {
        let (mut app, tokens, _users, _registry) = app_with_admin(Some("jz-admin"));
        let response = request_as(
            &mut app,
            "jz-admin",
            "POST",
            "/Marti/api/admin/enrollmentTokens",
            r#"{"expiresInSecs": 3600, "note": "for jz_pixel"}"#,
        )
        .await;
        // Confirm the request body's fields actually took effect on the
        // store (camelCase JSON -> the struct's renamed fields), not just
        // that the endpoint returned 201.
        assert_eq!(response.status(), StatusCode::CREATED);
        let list = tokens.list();
        assert_eq!(list.len(), 1);
        assert!(list[0].expires_at_unix.is_some());
        assert_eq!(list[0].note.as_deref(), Some("for jz_pixel"));
    }

    #[tokio::test]
    async fn admin_can_mint_list_and_revoke_a_user() {
        let (mut app, _tokens, users, _registry) = app_with_admin(Some("jz-admin"));

        let mint_response = request_as(
            &mut app,
            "jz-admin",
            "POST",
            "/Marti/api/admin/users",
            r#"{"username": "alice", "password": "correct horse battery staple"}"#,
        )
        .await;
        assert_eq!(mint_response.status(), StatusCode::CREATED);
        assert!(users.authenticate("alice", "correct horse battery staple"));

        let list_response = request_as(&mut app, "jz-admin", "GET", "/Marti/api/admin/users", "").await;
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX).await.unwrap();
        let list: Vec<serde_json::Value> = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["username"], "alice");

        let revoke_response = request_as(&mut app, "jz-admin", "DELETE", "/Marti/api/admin/users/alice", "").await;
        assert_eq!(revoke_response.status(), StatusCode::NO_CONTENT);
        assert!(!users.authenticate("alice", "correct horse battery staple"));
    }

    /// Omitting a password auto-generates one and returns it once --
    /// mirrors an enrollment token's own single-reveal ergonomics.
    #[tokio::test]
    async fn mint_user_without_a_password_generates_one() {
        let (mut app, _tokens, users, _registry) = app_with_admin(Some("jz-admin"));
        let response = request_as(
            &mut app,
            "jz-admin",
            "POST",
            "/Marti/api/admin/users",
            r#"{"username": "bob"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let generated_password = body["password"].as_str().unwrap();
        assert!(!generated_password.is_empty());
        assert!(users.authenticate("bob", generated_password));
    }

    #[tokio::test]
    async fn non_admin_cannot_manage_users() {
        let (mut app, _tokens, users, _registry) = app_with_admin(Some("jz-admin"));
        let response = request_as(
            &mut app,
            "some-other-device",
            "POST",
            "/Marti/api/admin/users",
            r#"{"username": "alice", "password": "hunter2"}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(users.list().is_empty(), "the rejected request must not have minted anything");
    }

    #[tokio::test]
    async fn certadmin_lookup_finds_an_enrolled_devices_real_fingerprint() {
        let (mut app, _tokens, _users, registry) = app_with_admin(Some("jz-admin"));
        let ca = crate::pki::CertificateAuthority::generate("Test CA").unwrap();
        let (csr_pem, _key) = crate::pki::build_csr("device-a").unwrap();
        let signed = ca.sign_csr(&csr_pem, time::Duration::days(365)).unwrap();
        registry.enroll("device-a", &signed.cert_pem, 1_000).unwrap();
        let hash = crate::pki::fingerprint_sha256_colon_hex(&signed.cert_pem).unwrap();

        let response = request_as(
            &mut app,
            "jz-admin",
            "GET",
            &format!("/Marti/api/certadmin/cert/{hash}"),
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["data"]["clientUid"], "device-a");
        assert!(body["data"]["revocationDate"].is_null());
    }

    #[tokio::test]
    async fn certadmin_lookup_reports_revocation_status() {
        let (mut app, _tokens, _users, registry) = app_with_admin(Some("jz-admin"));
        let ca = crate::pki::CertificateAuthority::generate("Test CA").unwrap();
        let (csr_pem, _key) = crate::pki::build_csr("device-revoked").unwrap();
        let signed = ca.sign_csr(&csr_pem, time::Duration::days(365)).unwrap();
        registry.enroll("device-revoked", &signed.cert_pem, 1_000).unwrap();
        registry.revoke("device-revoked").unwrap();
        let hash = crate::pki::fingerprint_sha256_colon_hex(&signed.cert_pem).unwrap();

        let response = request_as(
            &mut app,
            "jz-admin",
            "GET",
            &format!("/Marti/api/certadmin/cert/{hash}"),
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(!body["data"]["revocationDate"].is_null());
    }

    #[tokio::test]
    async fn certadmin_lookup_of_unknown_hash_is_404() {
        let (mut app, _tokens, _users, _registry) = app_with_admin(Some("jz-admin"));
        let response = request_as(
            &mut app,
            "jz-admin",
            "GET",
            "/Marti/api/certadmin/cert/00:11:22",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
