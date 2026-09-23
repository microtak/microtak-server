//! Admin API: mint/list/revoke enrollment invite tokens
//! (`/Marti/api/admin/enrollmentTokens`).
//!
//! mTLS-authenticated like the rest of the Marti API (served via
//! [`super::MtlsHttpServer`]), but with an additional identity check on top:
//! only the cert Common Name configured as [`crate::app::AppConfig::admin_common_name`]
//! may call these routes at all -- every other authenticated caller gets
//! 403, same as an unauthenticated one. If no `admin_common_name` is
//! configured, the admin API is unreachable by anyone (fails closed, not
//! open).
//!
//! **Bootstrap order**: the admin's own device must be enrolled *before*
//! [`crate::app::AppConfig::enrollment_requires_token`] is turned on --
//! these endpoints are only reachable over mTLS using a cert enrollment
//! already issued, so there's no way to mint the very first token through
//! this API if enrollment is already locked down and nobody holds a valid
//! token yet. Enroll the admin device while enrollment is still open, then
//! flip `enrollment_requires_token` on and restart.

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

#[derive(Clone)]
pub struct AdminState {
    pub tokens: Arc<EnrollmentTokenStore>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app_with_admin(admin_cn: Option<&str>) -> (Router, Arc<EnrollmentTokenStore>) {
        let tokens = Arc::new(EnrollmentTokenStore::in_memory());
        let state = AdminState {
            tokens: Arc::clone(&tokens),
            admin_common_name: admin_cn.map(str::to_string),
        };
        (router(state), tokens)
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
        let (mut app, _tokens) = app_with_admin(Some("jz-admin"));

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
        let (mut app, tokens) = app_with_admin(Some("jz-admin"));
        let response = request_as(&mut app, "some-other-device", "POST", "/Marti/api/admin/enrollmentTokens", "{}").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(tokens.list().is_empty(), "the rejected request must not have minted anything");
    }

    /// No admin configured at all means the API is unreachable by anyone,
    /// not "open by default."
    #[tokio::test]
    async fn no_configured_admin_rejects_every_caller() {
        let (mut app, _tokens) = app_with_admin(None);
        let response = request_as(&mut app, "anyone", "GET", "/Marti/api/admin/enrollmentTokens", "").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn revoking_unknown_token_is_404() {
        let (mut app, _tokens) = app_with_admin(Some("jz-admin"));
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
        let (mut app, tokens) = app_with_admin(Some("jz-admin"));
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
}
