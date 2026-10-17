//! `POST /oauth/token` -- OAuth password-grant login, the real TAK-Server
//! contract CloudTAK's own login flow speaks (confirmed from
//! `dfpc-coe/node-tak`'s real client source, `lib/api/oauth.ts`).
//!
//! Served on the same HTTPS-only listener as enrollment (`config.server.
//! webtak` in `node-tak`'s own terms) -- login itself has no client cert to
//! authenticate the transport with, same reasoning as enrollment.
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

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::PeerIp;
use crate::ratelimit::{AuthLimiter, user_key};
use crate::users::UserStore;
use tracing::warn;

#[derive(Clone)]
pub struct OAuthState {
    pub users: Arc<UserStore>,
    pub limiter: Arc<AuthLimiter>,
    pub signer: Arc<JwtSigner>,
}

pub fn router(users: Arc<UserStore>, limiter: Arc<AuthLimiter>, signer: Arc<JwtSigner>) -> Router {
    Router::new()
        .route("/oauth/token", post(token))
        .layer(DefaultBodyLimit::max(
            super::enrollment::MAX_REQUEST_BODY_BYTES,
        ))
        .with_state(OAuthState {
            users,
            limiter,
            signer,
        })
}

/// Access-token lifetime: the official default `httpSessionTimeoutMinutes`
/// (60), which the official login client's token settings use.
const TOKEN_TTL_SECONDS: i64 = 60 * 60;

/// Signs access tokens the way the official server does: Spring
/// Authorization Server's `JwtGenerator` with a `NimbusJwtEncoder` over an
/// RSA key whose `kid` is a random UUID per server start
/// (`ServerConfiguration.jwkSource`). RS256, header `{"kid", "alg"}`.
pub struct JwtSigner {
    key: ring::signature::RsaKeyPair,
    kid: String,
}

#[derive(Debug, thiserror::Error)]
pub enum JwtSignerError {
    #[error("generating the RSA signing key failed: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("invalid RSA signing key: {0}")]
    Key(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl JwtSigner {
    /// A fresh 2048-bit RSA key (tests; servers use [`Self::load_or_create`]).
    pub fn generate() -> Result<Self, JwtSignerError> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
        Self::from_pkcs8(&key.serialize_der())
    }

    /// The server's signing key from `data_dir/oauth-signing-key.pem`,
    /// created (owner-only) on first start.
    pub fn load_or_create(data_dir: &std::path::Path) -> Result<Self, JwtSignerError> {
        let path = data_dir.join("oauth-signing-key.pem");
        if let Ok(pem) = std::fs::read_to_string(&path) {
            let key =
                rcgen::KeyPair::from_pem(&pem).map_err(|e| JwtSignerError::Key(e.to_string()))?;
            return Self::from_pkcs8(&key.serialize_der());
        }
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
        crate::bootstrap::write_private_file(&path, key.serialize_pem().as_bytes())?;
        Self::from_pkcs8(&key.serialize_der())
    }

    fn from_pkcs8(der: &[u8]) -> Result<Self, JwtSignerError> {
        let key = ring::signature::RsaKeyPair::from_pkcs8(der)
            .map_err(|e| JwtSignerError::Key(e.to_string()))?;
        Ok(Self {
            key,
            kid: super::envelope::random_uuid(),
        })
    }

    /// DER `RSAPublicKey` (PKCS#1), for verifying.
    pub fn public_key_der(&self) -> &[u8] {
        use ring::signature::KeyPair;
        self.key.public_key().as_ref()
    }

    /// An access token for `username` issued at `now` (Unix seconds), with
    /// the official claims: sub and aud are the username (the login client's
    /// id is the username), nbf = iat, exp = iat + TTL, jti; no iss, no
    /// scope (no authorization server context, no authorized scopes).
    pub fn token(&self, username: &str, now: i64) -> String {
        // Written out by hand: serde_json's map sorts keys, and the official
        // header order matters -- clients such as node-tak find the claims by
        // decoding the whole token as one base64 string, which only works
        // because this 60-byte header encodes to a whole number of base64
        // quanta.
        let username = serde_json::Value::from(username).to_string();
        let header = format!(r#"{{"kid":"{}","alg":"RS256"}}"#, self.kid);
        let claims = format!(
            r#"{{"sub":{username},"aud":{username},"nbf":{now},"exp":{},"iat":{now},"jti":"{}"}}"#,
            now + TOKEN_TTL_SECONDS,
            super::envelope::random_uuid()
        );
        let encode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let signing_input = format!("{}.{}", encode(&header), encode(&claims));
        let mut signature = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .expect("RSA signing with a valid key");
        format!(
            "{signing_input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        )
    }
}

#[derive(Deserialize)]
struct TokenRequest {
    username: String,
    password: String,
}

async fn token(
    State(state): State<OAuthState>,
    peer: PeerIp,
    Form(request): Form<TokenRequest>,
) -> Response {
    let ip_key = peer.limit_key();
    let user_key = user_key(&request.username);
    if state.limiter.is_blocked(&ip_key) || state.limiter.is_blocked(&user_key) {
        warn!(username = %request.username, "oauth login rate-limited after repeated failed attempts");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Too many failed attempts, try again later",
            })),
        )
            .into_response();
    }
    if !state
        .limiter
        .verify_password(&state.users, &request.username, &request.password)
        .await
    {
        state.limiter.record_failure(&ip_key);
        state.limiter.record_failure(&user_key);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_grant",
                "error_description": "Bad credentials",
            })),
        )
            .into_response();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let access_token = state.signer.token(&request.username, now);
    // As the official PasswordGrantAuthenticationSuccessHandler answers: the
    // OAuth2 token response, plus the token as an `access_token` cookie.
    let cookie = format!("access_token={access_token}; Path=/; Secure; HttpOnly; SameSite=Strict");
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// node-tak's `OAuthCommands.parse` (what CloudTAK runs on login),
    /// byte for byte: Node's lenient base64 decoder over the *whole* token
    /// (dots skipped, decoding straight across the segments), split at `}`,
    /// the second piece parsed as JSON. Works only if the header's base64
    /// length is a multiple of 4 -- true for the official
    /// `{"kid":"<uuid>","alg":"RS256"}` (60 bytes, 80 characters).
    fn node_tak_parse(jwt: &str) -> serde_json::Value {
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let sextets: Vec<u8> = jwt
            .chars()
            .filter_map(|c| match c {
                '-' => Some(62),
                '_' => Some(63),
                c => ALPHABET.find(c).map(|i| i as u8),
            })
            .collect();
        let mut bytes = Vec::new();
        for chunk in sextets.chunks(4) {
            let n =
                chunk.iter().fold(0u32, |acc, s| (acc << 6) | *s as u32) << (6 * (4 - chunk.len()));
            let out = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            bytes.extend_from_slice(&out[..chunk.len().saturating_sub(1)]);
        }
        let text = String::from_utf8_lossy(&bytes);
        let pieces: Vec<String> = text.split('}').map(|p| format!("{p}}}")).collect();
        serde_json::from_str(&pieces[1]).expect("node-tak would fail here with 'is not valid JSON'")
    }

    fn decode_segment(segment: &str) -> serde_json::Value {
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segment)
                .unwrap(),
        )
        .unwrap()
    }

    /// The official token (Spring Authorization Server JwtGenerator +
    /// NimbusJwtEncoder over an RSA key with a random UUID kid): header
    /// {kid, alg: RS256}; claims sub/aud = username, nbf, exp, iat, jti; no
    /// iss, no scope. RS256-signed. And node-tak can read it.
    #[test]
    fn tokens_have_the_official_shape_and_node_tak_can_parse_them() {
        let signer = JwtSigner::generate().unwrap();
        let token = signer.token("jz", 1_760_000_000);
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3);

        let header = decode_segment(segments[0]);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"].as_str().unwrap().len(), 36);
        assert_eq!(
            segments[0].len() % 4,
            0,
            "header must decode on a 4-char boundary"
        );
        let raw_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[0])
            .unwrap();
        let raw_header = String::from_utf8(raw_header).unwrap();
        assert!(
            raw_header.starts_with(r#"{"kid":""#),
            "Spring/Nimbus header order: {raw_header}"
        );
        assert!(
            raw_header.ends_with(r#"","alg":"RS256"}"#),
            "Spring/Nimbus header order: {raw_header}"
        );

        let claims = decode_segment(segments[1]);
        assert_eq!(claims["sub"], "jz");
        assert_eq!(claims["aud"], "jz");
        assert_eq!(claims["iat"], 1_760_000_000);
        assert_eq!(claims["nbf"], 1_760_000_000);
        assert_eq!(claims["exp"], 1_760_000_000 + 3600);
        assert_eq!(claims["jti"].as_str().unwrap().len(), 36);
        assert!(claims.get("iss").is_none() && claims.get("scope").is_none());

        let parsed = node_tak_parse(&token);
        assert_eq!(parsed["sub"], "jz");
        assert_eq!(parsed["exp"], 1_760_000_000 + 3600);

        let signing_input = format!("{}.{}", segments[0], segments[1]);
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[2])
            .unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            signer.public_key_der(),
        )
        .verify(signing_input.as_bytes(), &signature)
        .expect("a valid RS256 signature");
    }

    #[test]
    fn the_signing_key_is_persisted_owner_only() {
        let dir = std::env::temp_dir().join(format!("microtak-oauth-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = JwtSigner::load_or_create(&dir).unwrap();
        let second = JwtSigner::load_or_create(&dir).unwrap();
        assert_eq!(first.public_key_der(), second.public_key_der());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("oauth-signing-key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app_with(users: Arc<UserStore>) -> Router {
        router(
            users,
            Arc::new(AuthLimiter::default()),
            Arc::new(JwtSigner::generate().unwrap()),
        )
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
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let token = body["access_token"].as_str().unwrap();
        assert_eq!(
            token.split('.').count(),
            3,
            "expected header.payload.signature"
        );

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
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "invalid_grant");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap()
                .contains("Bad credentials")
        );
    }

    #[tokio::test]
    async fn unknown_username_is_also_rejected() {
        let users = Arc::new(UserStore::in_memory());
        let response = post_token(app_with(users), "nobody", "whatever").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// TC-LIMIT-08 for the login endpoint: after repeated wrong passwords
    /// the account is refused with 429 -- even the right password -- for
    /// the rest of the window.
    #[tokio::test]
    async fn repeated_wrong_passwords_are_rate_limited() {
        let users = Arc::new(UserStore::in_memory());
        users
            .mint("alice", "correct horse battery staple", 0)
            .unwrap();
        let app = router(
            users,
            Arc::new(AuthLimiter::new(
                3,
                std::time::Duration::from_secs(300),
                100,
                1,
            )),
            Arc::new(JwtSigner::generate().unwrap()),
        );

        for _ in 0..3 {
            let response = post_token(app.clone(), "alice", "wrong").await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = post_token(app.clone(), "alice", "correct horse battery staple").await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
