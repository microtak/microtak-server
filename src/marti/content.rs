//! DataSync file content upload/download — `docs/TEST-PLAN.md` §5,
//! TC-MARTI-07/08 — on top of [`crate::content_store::ContentStore`].
//!
//! **Endpoint naming is MicroTAK's own choice, not a copied contract**: no
//! single authoritative source for these two routes was found across the
//! reference implementations this project studied (taky documents
//! `GET /Marti/api/sync/content?hash=<h>` for download; a real deployed
//! community server instead uses `POST /Marti/sync/upload` for upload,
//! under a different path prefix entirely). MicroTAK keeps both routes under
//! one consistent `/Marti/api/sync/*` prefix:
//! - `POST /Marti/api/sync/missionupload?hash=<sha256>` — raw request body
//!   is the file's bytes; `hash` is optional but, if given, must match the
//!   server's own computed SHA-256 of the body or the upload is rejected
//!   with 400 (TC-MARTI-07). Returns `{"hash": "<sha256>"}` — the real,
//!   server-computed hash the content is now stored under.
//! - `GET /Marti/api/sync/content?hash=<h>` — returns the raw bytes stored
//!   under `h`, or 404 if nothing is stored there (or `h` isn't a
//!   well-formed hash).
//!
//! This module only stores/serves bytes by hash; associating a hash with a
//! particular mission is still [`crate::marti::missions::add_content`]'s
//! job (`PUT /Marti/api/missions/:name/contents`) — the two are
//! deliberately decoupled, same as [`crate::missions`]'s own doc comment
//! describes.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::content_store::{ContentStore, ContentStoreError};

pub fn router(store: Arc<ContentStore>) -> Router {
    Router::new()
        .route("/Marti/api/sync/missionupload", post(upload))
        .route("/Marti/api/sync/content", get(download))
        .with_state(store)
}

fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[derive(Deserialize)]
struct UploadQuery {
    hash: Option<String>,
}

async fn upload(
    State(store): State<Arc<ContentStore>>,
    Query(query): Query<UploadQuery>,
    body: axum::body::Bytes,
) -> Response {
    match store.put(&body, query.hash.as_deref()) {
        Ok(hash) => Json(serde_json::json!({ "hash": hash })).into_response(),
        Err(ContentStoreError::HashMismatch { claimed, actual }) => error_response(
            StatusCode::BAD_REQUEST,
            format!("claimed hash {claimed} does not match uploaded content's actual hash {actual}"),
        ),
        Err(error) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
    }
}

#[derive(Deserialize)]
struct DownloadQuery {
    hash: String,
}

async fn download(
    State(store): State<Arc<ContentStore>>,
    Query(query): Query<DownloadQuery>,
) -> Response {
    match store.get(&query.hash) {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            format!("no content stored under hash '{}'", query.hash),
        ),
        Err(ContentStoreError::InvalidHash(hash)) => {
            error_response(StatusCode::BAD_REQUEST, format!("'{hash}' is not a valid content hash"))
        }
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn temp_store() -> Arc<ContentStore> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "microtak-marti-content-{}-{n}",
            std::process::id()
        ));
        Arc::new(ContentStore::open(dir).unwrap())
    }

    /// TC-MARTI-08 (integration level): an upload with no claimed hash
    /// succeeds and a subsequent download by the returned hash returns the
    /// exact same bytes -- the round trip a real ATAK Data Sync client
    /// depends on.
    #[tokio::test]
    async fn uploads_and_downloads_content_round_trip() {
        let app = router(temp_store());

        let upload_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/Marti/api/sync/missionupload")
                    .body(Body::from("some file bytes"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upload_response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(upload_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let hash = body["hash"].as_str().unwrap().to_string();

        let download_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/Marti/api/sync/content?hash={hash}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(download_response.status(), StatusCode::OK);
        let downloaded = axum::body::to_bytes(download_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&downloaded[..], b"some file bytes");
    }

    /// TC-MARTI-07: an upload whose claimed `hash` query param doesn't
    /// match the actual uploaded bytes is rejected with 400, and nothing is
    /// stored.
    #[tokio::test]
    async fn rejects_upload_with_mismatched_claimed_hash() {
        let store = temp_store();
        let app = router(store.clone());

        let wrong_hash = "0".repeat(64);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/Marti/api/sync/missionupload?hash={wrong_hash}"))
                    .body(Body::from("actual bytes"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.get(&wrong_hash).unwrap().is_none());
    }

    /// Downloading a hash nothing was ever uploaded under is a clean 404,
    /// not a 500 or a served-empty-body.
    #[tokio::test]
    async fn download_of_unknown_hash_is_404() {
        let app = router(temp_store());
        let unknown = "a".repeat(64);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/Marti/api/sync/content?hash={unknown}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A malformed hash in the download query param (here, a path-traversal
    /// attempt) is rejected as a 400, not passed through to a filesystem
    /// lookup.
    #[tokio::test]
    async fn download_with_path_traversal_hash_is_rejected() {
        let app = router(temp_store());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/Marti/api/sync/content?hash=..%2F..%2Fetc%2Fpasswd")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
