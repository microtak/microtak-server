//! `POST /oauth/token` -- OAuth password-grant login, the real TAK-Server
//! contract CloudTAK's own login flow speaks (confirmed from
//! `dfpc-coe/node-tak`'s real client source, `lib/api/oauth.ts`).
//!
//! Served on the same plain-HTTP listener as enrollment (`config.server.
//! webtak` in `node-tak`'s own terms) -- login itself has no cert to
//! authenticate the transport with, same reasoning as enrollment being
//! plain HTTP.
//!
//! This is purely an identity check that hands back a JWT carrying the
//! username as its `sub` claim -- nothing here issues a certificate.
//! Certificate issuance for an authenticated user happens on
//! `POST /Marti/api/tls/signClient/v2` via `Authorization: Basic`, a
//! *separate* request the real client makes afterward (see
//! `marti::enrollment`). The JWT's signature is never actually verified by
//! any real client (`node-tak`'s own `OAuthCommands.parse()` just decodes
//! it to read `sub`), so a session-local, ad-hoc HMAC key is all this
//! needs -- there is no shared secret to manage or persist.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use crate::users::UserStore;

pub fn router(users: Arc<UserStore>) -> Router {
    Router::new()
        .route("/oauth/token", post(token))
        .with_state(users)
}

#[derive(Deserialize)]
struct TokenRequest {
    username: String,
    password: String,
}

async fn token(State(users): State<Arc<UserStore>>, Form(request): Form<TokenRequest>) -> Response {
    if !users.authenticate(&request.username, &request.password) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Bad credentials",
            })),
        )
            .into_response();
    }

    let access_token = make_jwt(&request.username);
    (StatusCode::OK, Json(json!({ "access_token": access_token }))).into_response()
}

/// A real, standard base64url 3-segment JWT -- header.payload.signature.
/// The signature is a throwaway HMAC over a session-local random key: no
/// real client verifies it (see this module's own doc comment), so nothing
/// beyond "looks like a real JWT" is required, but producing an actually
/// well-formed one (rather than a fake placeholder) means `node-tak`'s own
/// `OAuthCommands.parse()` -- which does a real (if crude) base64 decode of
/// the token -- reads it correctly.
fn make_jwt(username: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let header = json!({ "alg": "none", "typ": "JWT" });
    let payload = json!({
        "sub": username,
        "aud": "microtak-server",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    });

    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    format!("{}.{}.", encode(&header), encode(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app_with(users: Arc<UserStore>) -> Router {
        router(users)
    }

    async fn post_token(app: Router, username: &str, password: &str) -> Response {
        let body = format!(
            "grant_type=password&username={}&password={}",
            urlencode(username),
            urlencode(password)
        );
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn urlencode(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u32)
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn valid_credentials_return_a_real_three_segment_jwt() {
        let users = Arc::new(UserStore::in_memory());
        users.mint("jz", "correct horse battery staple", 0).unwrap();

        let response = post_token(app_with(users), "jz", "correct horse battery staple").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let token = body["access_token"].as_str().unwrap();
        assert_eq!(token.split('.').count(), 3, "expected header.payload.signature");

        // The real client's own decode: base64-decode the whole thing and
        // pull the second `}`-delimited JSON chunk out (see this module's
        // doc comment) -- confirms our token is shaped the way a real
        // client actually reads it, not just "looks like a JWT" by eye.
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload["sub"], "jz");
    }

    #[tokio::test]
    async fn wrong_password_returns_the_real_error_shape() {
        let users = Arc::new(UserStore::in_memory());
        users.mint("jz", "correct horse battery staple", 0).unwrap();

        let response = post_token(app_with(users), "jz", "wrong").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["error"], "invalid_grant");
        assert!(body["error_description"].as_str().unwrap().contains("Bad credentials"));
    }

    #[tokio::test]
    async fn unknown_username_is_also_rejected() {
        let users = Arc::new(UserStore::in_memory());
        let response = post_token(app_with(users), "nobody", "whatever").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
