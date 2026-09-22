//! Mission (Data Sync) metadata HTTP API — `/Marti/api/missions/*`.
//!
//! Implements the metadata half of `docs/TEST-PLAN.md` §5 on top of
//! [`crate::missions::MissionStore`]. **Not implemented**: DataSync file
//! *content* upload/download (TC-MARTI-07/08), `clientEndPoints`
//! (TC-MARTI-09), groups/device-profile-gated visibility.
//!
//! **TC-MARTI-10**: served mTLS-authenticated via
//! [`super::MtlsHttpServer`], which also injects the connecting cert's CN
//! as a [`super::PeerIdentity`] request extension. Every handler that
//! accepts a `creatorUid`/`actorUid`/`uid` claim in the request rejects
//! (403) if it doesn't match the authenticated [`PeerIdentity`] — EdgeTAK's
//! policy: an HTTP API caller's identity *is* its cert's CN, so a caller
//! can't act as any identity it merely claims in a request body/query
//! param, closing the gap this module used to have.
//!
//! **`PUT` vs `PATCH` (TC-MARTI-02/12)**: `PUT /missions/:name` is
//! strict-create-only (409 if the name is already taken); updates go
//! through `PATCH /missions/:name` and only touch the fields provided.
//! This is EdgeTAK's own, deliberately stricter contract — a real reference
//! implementation's `PUT` silently merges into an existing mission with no
//! way for the caller to distinguish "created" from "updated," which this
//! design avoids by construction rather than replicating.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use time::OffsetDateTime;

use super::PeerIdentity;
use crate::missions::{Mission, MissionContentRef, MissionError, MissionStore, MissionUpdate};

pub fn router(store: Arc<MissionStore>) -> Router {
    Router::new()
        .route("/Marti/api/missions", get(list_missions))
        .route(
            "/Marti/api/missions/:name",
            put(create_mission)
                .get(get_mission)
                .patch(update_mission)
                .delete(delete_mission),
        )
        .route("/Marti/api/missions/:name/changes", get(get_changes))
        .route(
            "/Marti/api/missions/:name/contents",
            put(add_content),
        )
        .route(
            "/Marti/api/missions/:name/subscription",
            put(subscribe).delete(unsubscribe),
        )
        .with_state(store)
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// TC-MARTI-10's residual gap, closed: reject a request whose claimed
/// identity (`creatorUid`/`actorUid`/`uid`) doesn't match the
/// authenticated connection's own cert CN. EdgeTAK's policy is that an
/// HTTP API caller's identity *is* its cert's CN — the same identity
/// enrollment issued it — so this needs no prior CoT-relay interaction,
/// unlike checking against a `registry`-bound `uid` would.
/// `None` if `claimed` matches; `Some(rejection)` to return immediately
/// otherwise. Not `Result<(), Response>` -- `axum::response::Response` is
/// large enough that clippy's `result_large_err` flags it, and there's no
/// success payload to carry anyway.
fn require_matching_identity(identity: &PeerIdentity, claimed: &str) -> Option<Response> {
    if identity.0 == claimed {
        None
    } else {
        Some(error_response(
            StatusCode::FORBIDDEN,
            format!(
                "claimed identity '{claimed}' does not match authenticated connection '{}'",
                identity.0
            ),
        ))
    }
}

fn mission_error_response(error: MissionError) -> Response {
    match error {
        MissionError::AlreadyExists(name) => {
            error_response(StatusCode::CONFLICT, format!("mission '{name}' already exists"))
        }
        MissionError::NotFound(name) => {
            error_response(StatusCode::NOT_FOUND, format!("no mission named '{name}'"))
        }
        other => error_response(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

async fn list_missions(State(store): State<Arc<MissionStore>>) -> Json<Vec<Mission>> {
    Json(store.list())
}

#[derive(Deserialize)]
struct CreateMissionRequest {
    description: Option<String>,
    #[serde(rename = "creatorUid")]
    creator_uid: String,
    #[serde(default)]
    keywords: Vec<String>,
}

/// TC-MARTI-01/02: strict create.
async fn create_mission(
    State(store): State<Arc<MissionStore>>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<CreateMissionRequest>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &request.creator_uid) {
        return response;
    }
    match store.create(
        &name,
        request.description,
        &request.creator_uid,
        request.keywords,
        now_unix(),
    ) {
        Ok(mission) => (StatusCode::CREATED, Json(mission)).into_response(),
        Err(error) => mission_error_response(error),
    }
}

async fn get_mission(
    State(store): State<Arc<MissionStore>>,
    Path(name): Path<String>,
) -> Response {
    match store.get(&name) {
        Some(mission) => Json(mission).into_response(),
        None => mission_error_response(MissionError::NotFound(name)),
    }
}

#[derive(Deserialize)]
struct UpdateMissionRequest {
    description: Option<String>,
    keywords: Option<Vec<String>>,
    #[serde(rename = "actorUid")]
    actor_uid: String,
}

/// TC-MARTI-12: partial update, only provided fields change.
async fn update_mission(
    State(store): State<Arc<MissionStore>>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<UpdateMissionRequest>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &request.actor_uid) {
        return response;
    }
    let update = MissionUpdate {
        description: request.description,
        keywords: request.keywords,
    };
    match store.update(&name, update, &request.actor_uid, now_unix()) {
        Ok(mission) => Json(mission).into_response(),
        Err(error) => mission_error_response(error),
    }
}

async fn delete_mission(
    State(store): State<Arc<MissionStore>>,
    Path(name): Path<String>,
) -> Response {
    match store.delete(&name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => mission_error_response(error),
    }
}

/// TC-MARTI-05.
async fn get_changes(
    State(store): State<Arc<MissionStore>>,
    Path(name): Path<String>,
) -> Response {
    match store.changes(&name) {
        Ok(changes) => Json(changes).into_response(),
        Err(error) => mission_error_response(error),
    }
}

#[derive(Deserialize)]
struct AddContentRequest {
    hash: String,
    filename: String,
    #[serde(rename = "creatorUid")]
    creator_uid: String,
}

async fn add_content(
    State(store): State<Arc<MissionStore>>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<AddContentRequest>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &request.creator_uid) {
        return response;
    }
    let content = MissionContentRef {
        hash: request.hash,
        filename: request.filename,
        added_at_unix: now_unix(),
        creator_uid: request.creator_uid,
    };
    match store.add_content(&name, content, now_unix()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => mission_error_response(error),
    }
}

#[derive(Deserialize)]
struct SubscriptionQuery {
    uid: String,
}

/// TC-MARTI-04. A caller may only subscribe *itself* — `uid` must match the
/// authenticated identity, same policy as every other identity claim in
/// this module.
async fn subscribe(
    State(store): State<Arc<MissionStore>>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &query.uid) {
        return response;
    }
    match store.subscribe(&name, &query.uid, now_unix()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => mission_error_response(error),
    }
}

async fn unsubscribe(
    State(store): State<Arc<MissionStore>>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &query.uid) {
        return response;
    }
    match store.unsubscribe(&name, &query.uid, now_unix()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => mission_error_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode as Status};
    use crate::missions::MissionChange;
    use tower::ServiceExt;

    fn app() -> Router {
        router(Arc::new(MissionStore::in_memory()))
    }

    /// Real `MtlsHttpServer` usage injects `PeerIdentity` via a
    /// per-connection router layer (see `super::super::MtlsHttpServer`);
    /// these module-level tests don't go through a real TLS handshake, so
    /// they attach the extension directly on the request, simulating "this
    /// request arrived over a connection authenticated as `identity`."
    async fn json_request_as(
        app: &mut Router,
        identity: &str,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (Status, serde_json::Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .extension(PeerIdentity(identity.to_string()))
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if body_bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body_bytes).unwrap()
        };
        (status, json)
    }

    async fn get_as(app: &mut Router, identity: &str, uri: &str) -> Response {
        let request = Request::builder()
            .uri(uri)
            .extension(PeerIdentity(identity.to_string()))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(request).await.unwrap()
    }

    /// TC-MARTI-01.
    #[tokio::test]
    async fn creates_and_fetches_a_mission_over_http() {
        let mut app = app();
        let (status, body) = json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/Recon%20Alpha",
            serde_json::json!({"creatorUid": "user-1", "description": "test"}),
        )
        .await;
        assert_eq!(status, Status::CREATED);
        assert_eq!(body["name"], "Recon Alpha");

        let response = get_as(&mut app, "user-1", "/Marti/api/missions/Recon%20Alpha").await;
        assert_eq!(response.status(), Status::OK);
    }

    /// TC-MARTI-02.
    #[tokio::test]
    async fn rejects_duplicate_creation_with_409() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/dup",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;
        let (status, _) = json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/dup",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;
        assert_eq!(status, Status::CONFLICT);
    }

    /// The residual TC-MARTI-10 gap, closed: a caller claiming a
    /// `creatorUid` that doesn't match its authenticated identity is
    /// rejected, not silently trusted.
    #[tokio::test]
    async fn rejects_creatoruid_claim_not_matching_authenticated_identity() {
        let mut app = app();
        let (status, _) = json_request_as(
            &mut app,
            "real-device",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "someone-else"}),
        )
        .await;
        assert_eq!(status, Status::FORBIDDEN);

        // The rejected request must not have created anything.
        let response = get_as(&mut app, "real-device", "/Marti/api/missions/m").await;
        assert_eq!(response.status(), Status::NOT_FOUND);
    }

    /// TC-MARTI-04.
    #[tokio::test]
    async fn subscribes_and_unsubscribes_via_query_param() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;

        let request = Request::builder()
            .method("PUT")
            .uri("/Marti/api/missions/m/subscription?uid=device-1")
            .extension(PeerIdentity("device-1".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), Status::OK);

        let response = get_as(&mut app, "user-1", "/Marti/api/missions/m").await;
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mission: Mission = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(mission.subscribers, vec!["device-1"]);
    }

    /// A device can't subscribe claiming to be a *different* uid than its
    /// own authenticated identity.
    #[tokio::test]
    async fn rejects_subscribing_as_a_different_uid() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;

        let request = Request::builder()
            .method("PUT")
            .uri("/Marti/api/missions/m/subscription?uid=someone-else")
            .extension(PeerIdentity("device-1".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), Status::FORBIDDEN);
    }

    /// TC-MARTI-05.
    #[tokio::test]
    async fn changes_endpoint_reflects_history() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;

        let response = get_as(&mut app, "user-1", "/Marti/api/missions/m/changes").await;
        assert_eq!(response.status(), Status::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let changes: Vec<MissionChange> = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(changes.len(), 1);
    }

    #[tokio::test]
    async fn get_on_missing_mission_returns_404() {
        let mut app = app();
        let response = get_as(&mut app, "user-1", "/Marti/api/missions/nope").await;
        assert_eq!(response.status(), Status::NOT_FOUND);
    }
}
