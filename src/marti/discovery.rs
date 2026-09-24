//! Small, mostly-static Marti "discovery" endpoints: version/config probes
//! real TAK-Server clients use to confirm they're actually talking to a
//! working, authenticated connection, not proof of any particular feature.
//!
//! Confirmed from real client source (`dfpc-coe/node-tak`'s
//! `lib/api/certificate.ts`'s `probe()`, and CloudTAK's own
//! `api/stateless/lib/provider.ts`): a real client hits `GET
//! /Marti/api/version` as "the cheapest authoritative check" that its
//! client certificate is still accepted (the X509 filter runs on every
//! request, so any 200 response here proves that), and separately,
//! CloudTAK's own application code (not just the generic client library)
//! hits `GET /Marti/api/version/config` for the same purpose. Both are
//! implemented here, mTLS-authenticated the same way as every other
//! `marti` endpoint except enrollment.
//!
//! `GET /files/api/config` is Enterprise Sync's own upload-limit discovery
//! endpoint (`node-tak`'s `lib/api/files.ts`'s `config()`) -- served here
//! since nothing about it needs `content_store`'s own state beyond a
//! constant limit.

use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

/// Reported in `GET /Marti/api/version`'s body -- purely informational, no
/// client parses this beyond "did I get a 200."
const VERSION_STRING: &str = concat!("MicroTAK ", env!("CARGO_PKG_VERSION"));

/// MicroTAK doesn't enforce a real upload size limit today (see
/// `content_store`/`marti::content`) -- this is a conservative, honestly-
/// documented placeholder, not a real configured value.
const UPLOAD_SIZE_LIMIT_BYTES: u64 = 100 * 1024 * 1024;

pub fn router() -> Router {
    Router::new()
        .route("/Marti/api/version", get(version))
        .route("/Marti/api/version/config", get(version_config))
        .route("/files/api/config", get(files_config))
}

async fn version() -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/plain")], VERSION_STRING)
}

async fn version_config() -> impl IntoResponse {
    Json(json!({ "version": VERSION_STRING, "api": "3" }))
}

async fn files_config() -> impl IntoResponse {
    Json(json!({ "uploadSizeLimit": UPLOAD_SIZE_LIMIT_BYTES }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn get(app: Router, path: &str) -> axum::response::Response {
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn version_returns_200_with_a_real_body() {
        let response = get(router(), "/Marti/api/version").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(body.starts_with("MicroTAK "));
    }

    #[tokio::test]
    async fn version_config_returns_200_json() {
        let response = get(router(), "/Marti/api/version/config").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn files_config_reports_an_upload_size_limit() {
        let response = get(router(), "/files/api/config").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        assert!(body["uploadSizeLimit"].as_u64().unwrap() > 0);
    }
}
