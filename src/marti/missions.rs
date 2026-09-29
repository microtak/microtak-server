//! Mission (Data Sync) metadata HTTP API — `/Marti/api/missions/*`.
//!
//! Implements the metadata half of `docs/TEST-PLAN.md` §5 on top of
//! [`crate::missions::MissionStore`]. **Not implemented**: DataSync file
//! *content* upload/download (TC-MARTI-07/08), `clientEndPoints`
//! (TC-MARTI-09), device-profile-gated visibility.
//!
//! **Groups** (`crate::groups`, 2026-09-29): every mission is visible in a
//! set of groups (default: its creator's). A caller outside all of them
//! gets 404 on every mission endpoint and doesn't see it listed -- the
//! official server's mission group check; the admin sees everything. A
//! non-admin can only put a mission into groups it belongs to.
//!
//! **TC-MARTI-10**: served mTLS-authenticated via
//! [`super::MtlsHttpServer`], which also injects the connecting cert's CN
//! as a [`super::PeerIdentity`] request extension. Every handler that
//! accepts a `creatorUid`/`actorUid`/`uid` claim in the request rejects
//! (403) if it doesn't match the authenticated [`PeerIdentity`] — MicroTAK's
//! policy: an HTTP API caller's identity *is* its cert's CN, so a caller
//! can't act as any identity it merely claims in a request body/query
//! param, closing the gap this module used to have.
//!
//! **Roles (`docs/ARCHITECTURE.md` "Enrollment lockdown / admin API" and
//! the mission-roles follow-up it names)**: on top of the identity-claim
//! check above, some actions also require a specific
//! [`crate::missions::MissionRole`] on the target mission, mirroring the
//! official roles: `delete_mission` and `update_mission` (incl. its
//! groups) require `Owner` (`MISSION_OWNER`); `add_content` requires a
//! writing role, `Owner` or `Subscriber` (`MISSION_WRITE`) -- not
//! `ReadOnlySubscriber` (`MISSION_READONLY_SUBSCRIBER`). Subscribing grants
//! the mission's `defaultRole`. `assign_role`/`revoke_role` are
//! `Owner`-only. Reading (`list`/`get`/`changes`) needs no role -- only
//! membership of one of the mission's groups (see above).
//!
//! **`PUT` vs `PATCH` (TC-MARTI-02/12)**: `PUT /missions/:name` is
//! strict-create-only (409 if the name is already taken); updates go
//! through `PATCH /missions/:name` and only touch the fields provided.
//! This is MicroTAK's own, deliberately stricter contract — a real reference
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
use crate::groups::GroupStore;
use crate::missions::{
    Mission, MissionContentRef, MissionError, MissionRole, MissionStore, MissionUpdate,
};

/// What the mission API needs: the store, plus groups for visibility.
#[derive(Clone)]
pub struct MissionsState {
    pub store: Arc<MissionStore>,
    pub groups: Arc<GroupStore>,
    /// The admin identity sees every mission.
    pub admin_common_name: Option<String>,
}

/// The mission API with no groups configured (everyone is `__ANON__`, so
/// every mission is visible to everyone) -- see [`router_with`].
pub fn router(store: Arc<MissionStore>) -> Router {
    router_with(MissionsState {
        store,
        groups: Arc::new(GroupStore::in_memory()),
        admin_common_name: None,
    })
}

pub fn router_with(state: MissionsState) -> Router {
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
        .route("/Marti/api/missions/:name/role", put(assign_role))
        .route(
            "/Marti/api/missions/:name/role/:uid",
            axum::routing::delete(revoke_role),
        )
        .with_state(state)
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn error_response(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// TC-MARTI-10's residual gap, closed: reject a request whose claimed
/// identity (`creatorUid`/`actorUid`/`uid`) doesn't match the
/// authenticated connection's own cert CN. MicroTAK's policy is that an
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
        MissionError::CannotRemoveLastOwner { name, uid } => error_response(
            StatusCode::CONFLICT,
            format!("cannot remove '{uid}' from mission '{name}': it is the last remaining owner"),
        ),
        other => error_response(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// `Owner`-only actions (delete, update, role management). `None` if
/// `identity` holds `Owner` on `name`; `Some(rejection)` otherwise --
/// including if the mission doesn't exist, so a caller can't distinguish
/// "not found" from "not yours" through this check alone (the handler's own
/// subsequent `NotFound` handling covers the former distinctly where it
/// matters, e.g. after a real mutation attempt).
fn require_owner(store: &MissionStore, name: &str, identity: &PeerIdentity) -> Option<Response> {
    match store.role_of(name, &identity.0) {
        Some(MissionRole::Owner) => None,
        _ => Some(error_response(
            StatusCode::FORBIDDEN,
            "this action requires the Owner role on this mission".to_string(),
        )),
    }
}

/// Adding content -- official `MISSION_WRITE`: `Owner` or `Subscriber`.
/// A caller with no role, or `ReadOnlySubscriber`, is rejected.
fn require_write_role(store: &MissionStore, name: &str, identity: &PeerIdentity) -> Option<Response> {
    match store.role_of(name, &identity.0) {
        Some(role) if role.can_write() => None,
        _ => Some(error_response(
            StatusCode::FORBIDDEN,
            "this action requires a writing role (Owner or Subscriber) on this mission".to_string(),
        )),
    }
}

fn is_admin(state: &MissionsState, identity: &PeerIdentity) -> bool {
    state.admin_common_name.as_deref() == Some(identity.0.as_str())
}

/// Whether `identity` may see `mission` at all: it shares one of the
/// mission's groups (either direction), or it's the admin -- the official
/// server's mission group check (`isGroupVectorAllowed`).
fn can_see(state: &MissionsState, mission: &Mission, identity: &PeerIdentity) -> bool {
    if is_admin(state, identity) {
        return true;
    }
    let mine = state.groups.all_group_names(&identity.0);
    mission.groups.iter().any(|group| mine.contains(group))
}

/// 404 -- not 403 -- for a mission the caller can't see, so its existence
/// doesn't leak outside its groups.
fn require_visible(state: &MissionsState, name: &str, identity: &PeerIdentity) -> Option<Response> {
    match state.store.get(name) {
        Some(mission) if can_see(state, &mission, identity) => None,
        _ => Some(mission_error_response(MissionError::NotFound(name.to_string()))),
    }
}

/// Validate a requested group list: every group must exist, and a
/// non-admin may only use groups it belongs to (it can't place a mission
/// where it couldn't see it itself).
fn validate_groups(state: &MissionsState, groups: &[String], identity: &PeerIdentity) -> Option<Response> {
    if groups.is_empty() {
        return Some(error_response(StatusCode::BAD_REQUEST, "a mission needs at least one group".to_string()));
    }
    if let Some(unknown) = groups.iter().find(|g| !state.groups.exists(g)) {
        return Some(error_response(StatusCode::BAD_REQUEST, format!("unknown group '{unknown}'")));
    }
    if !is_admin(state, identity) {
        let mine = state.groups.all_group_names(&identity.0);
        if let Some(foreign) = groups.iter().find(|g| !mine.contains(*g)) {
            return Some(error_response(
                StatusCode::FORBIDDEN,
                format!("not a member of group '{foreign}'"),
            ));
        }
    }
    None
}

async fn list_missions(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
) -> Json<Vec<Mission>> {
    Json(
        state
            .store
            .list()
            .into_iter()
            .filter(|mission| can_see(&state, mission, &identity))
            .collect(),
    )
}

#[derive(Deserialize)]
struct CreateMissionRequest {
    description: Option<String>,
    #[serde(rename = "creatorUid")]
    creator_uid: String,
    #[serde(default)]
    keywords: Vec<String>,
    /// Groups the mission is visible in; default: the creator's groups.
    #[serde(default)]
    groups: Option<Vec<String>>,
    /// Role subscribers get (official `defaultRole`): `subscriber`
    /// (default) or `readonly_subscriber` (`MISSION_READONLY_SUBSCRIBER`).
    #[serde(rename = "defaultRole", default)]
    default_role: Option<MissionRole>,
}

/// TC-MARTI-01/02: strict create.
async fn create_mission(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<CreateMissionRequest>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &request.creator_uid) {
        return response;
    }
    let groups = match request.groups {
        Some(groups) => groups,
        None => state.groups.all_group_names(&identity.0).into_iter().collect(),
    };
    if let Some(response) = validate_groups(&state, &groups, &identity) {
        return response;
    }
    let default_role = request.default_role.unwrap_or(MissionRole::Subscriber);
    if default_role == MissionRole::Owner {
        return error_response(StatusCode::BAD_REQUEST, "defaultRole can't be Owner".to_string());
    }
    match state.store.create_with(
        &name,
        request.description,
        &request.creator_uid,
        request.keywords,
        groups,
        default_role,
        now_unix(),
    ) {
        Ok(mission) => (StatusCode::CREATED, Json(mission)).into_response(),
        Err(error) => mission_error_response(error),
    }
}

async fn get_mission(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
) -> Response {
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    match state.store.get(&name) {
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
    /// Replace the groups the mission is visible in (official
    /// `MISSION_UPDATE_GROUPS`, Owner only).
    #[serde(default)]
    groups: Option<Vec<String>>,
}

/// TC-MARTI-12: partial update, only provided fields change.
async fn update_mission(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<UpdateMissionRequest>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &request.actor_uid) {
        return response;
    }
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    if let Some(response) = require_owner(&state.store, &name, &identity) {
        return response;
    }
    if let Some(groups) = request.groups {
        if let Some(response) = validate_groups(&state, &groups, &identity) {
            return response;
        }
        if let Err(error) = state.store.set_groups(&name, groups, &request.actor_uid, now_unix()) {
            return mission_error_response(error);
        }
    }
    let update = MissionUpdate {
        description: request.description,
        keywords: request.keywords,
    };
    match state.store.update(&name, update, &request.actor_uid, now_unix()) {
        Ok(mission) => Json(mission).into_response(),
        Err(error) => mission_error_response(error),
    }
}

async fn delete_mission(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
) -> Response {
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    if let Some(response) = require_owner(&state.store, &name, &identity) {
        return response;
    }
    match state.store.delete(&name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => mission_error_response(error),
    }
}

/// TC-MARTI-05.
async fn get_changes(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
) -> Response {
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    match state.store.changes(&name) {
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
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<AddContentRequest>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &request.creator_uid) {
        return response;
    }
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    if let Some(response) = require_write_role(&state.store, &name, &identity) {
        return response;
    }
    let content = MissionContentRef {
        hash: request.hash,
        filename: request.filename,
        added_at_unix: now_unix(),
        creator_uid: request.creator_uid,
    };
    match state.store.add_content(&name, content, now_unix()) {
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
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &query.uid) {
        return response;
    }
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    match state.store.subscribe(&name, &query.uid, now_unix()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => mission_error_response(error),
    }
}

async fn unsubscribe(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    if let Some(response) = require_matching_identity(&identity, &query.uid) {
        return response;
    }
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    match state.store.unsubscribe(&name, &query.uid, now_unix()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => mission_error_response(error),
    }
}

#[derive(Deserialize)]
struct AssignRoleRequest {
    uid: String,
    role: MissionRole,
}

/// `Owner`-only: grant (or overwrite) another identity's role on this
/// mission. Rejects demoting the mission's last `Owner` (see
/// `MissionStore::assign_role`'s own doc comment) with 409, the same
/// status this module already uses for other real state conflicts.
async fn assign_role(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(name): Path<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Response {
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    if let Some(response) = require_owner(&state.store, &name, &identity) {
        return response;
    }
    match state.store.assign_role(&name, &request.uid, request.role, &identity.0, now_unix()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => mission_error_response(error),
    }
}

/// `Owner`-only: revoke another identity's role entirely. Same last-owner
/// protection as [`assign_role`].
async fn revoke_role(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    Path((name, uid)): Path<(String, String)>,
) -> Response {
    if let Some(response) = require_visible(&state, &name, &identity) {
        return response;
    }
    if let Some(response) = require_owner(&state.store, &name, &identity) {
        return response;
    }
    match state.store.revoke_role(&name, &uid, &identity.0, now_unix()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
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

    /// A mission API with groups Red (red-1, red-2) and Blue (blue-1),
    /// and "admin" as the admin identity.
    fn app_with_groups() -> (Router, Arc<GroupStore>, Arc<MissionStore>) {
        use crate::groups::Membership;
        let groups = Arc::new(GroupStore::in_memory());
        groups.create("Red", None, 0).unwrap();
        groups.create("Blue", None, 0).unwrap();
        groups.set_member("Red", "red-1", Some(Membership::Both)).unwrap();
        groups.set_member("Red", "red-2", Some(Membership::Out)).unwrap();
        groups.set_member("Blue", "blue-1", Some(Membership::Both)).unwrap();
        let store = Arc::new(MissionStore::in_memory());
        let app = router_with(MissionsState {
            store: Arc::clone(&store),
            groups: Arc::clone(&groups),
            admin_common_name: Some("admin".into()),
        });
        (app, groups, store)
    }

    async fn status_of(app: &mut Router, identity: &str, method: &str, uri: &str, body: serde_json::Value) -> Status {
        json_request_as(app, identity, method, uri, body).await.0
    }

    /// A mission defaults to its creator's groups and is invisible -- 404,
    /// not 403 -- to anyone outside them; the admin sees everything.
    #[tokio::test]
    async fn missions_are_only_visible_within_their_groups() {
        let (mut app, _, _) = app_with_groups();
        let (status, body) = json_request_as(&mut app, "red-1", "PUT", "/Marti/api/missions/op", serde_json::json!({"creatorUid": "red-1"})).await;
        assert_eq!(status, Status::CREATED);
        assert_eq!(body["groups"], serde_json::json!(["Red"]));

        let listed = |body: serde_json::Value| body.as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        let (_, body) = json_request_as(&mut app, "red-2", "GET", "/Marti/api/missions", serde_json::Value::Null).await;
        assert_eq!(listed(body), vec!["op"], "OUT-only member of Red sees it");
        let (_, body) = json_request_as(&mut app, "blue-1", "GET", "/Marti/api/missions", serde_json::Value::Null).await;
        assert!(listed(body).is_empty());
        let (_, body) = json_request_as(&mut app, "admin", "GET", "/Marti/api/missions", serde_json::Value::Null).await;
        assert_eq!(listed(body), vec!["op"]);

        for (method, uri, body) in [
            ("GET", "/Marti/api/missions/op", serde_json::Value::Null),
            ("GET", "/Marti/api/missions/op/changes", serde_json::Value::Null),
            ("PUT", "/Marti/api/missions/op/subscription?uid=blue-1", serde_json::Value::Null),
            ("PUT", "/Marti/api/missions/op/contents", serde_json::json!({"hash": "h", "filename": "f", "creatorUid": "blue-1"})),
        ] {
            assert_eq!(status_of(&mut app, "blue-1", method, uri, body).await, Status::NOT_FOUND, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn creating_a_mission_in_foreign_or_unknown_groups_is_refused() {
        let (mut app, _, store) = app_with_groups();
        let create = |groups: serde_json::Value| serde_json::json!({"creatorUid": "red-1", "groups": groups});
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/a", create(serde_json::json!(["Blue"]))).await, Status::FORBIDDEN);
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/b", create(serde_json::json!(["Nope"]))).await, Status::BAD_REQUEST);
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/c", create(serde_json::json!([]))).await, Status::BAD_REQUEST);
        assert!(store.list().is_empty());
        // The admin may place a mission in any group.
        let admin = serde_json::json!({"creatorUid": "admin", "groups": ["Blue"]});
        assert_eq!(status_of(&mut app, "admin", "PUT", "/Marti/api/missions/d", admin).await, Status::CREATED);
    }

    /// Official `MISSION_READONLY_SUBSCRIBER`: a mission created with
    /// `defaultRole` read-only gives subscribers read access only.
    #[tokio::test]
    async fn a_readonly_default_role_lets_subscribers_read_but_not_write() {
        let (mut app, _, store) = app_with_groups();
        let create = serde_json::json!({"creatorUid": "red-1", "defaultRole": "MISSION_READONLY_SUBSCRIBER"});
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/briefing", create).await, Status::CREATED);
        assert_eq!(status_of(&mut app, "red-2", "PUT", "/Marti/api/missions/briefing/subscription?uid=red-2", serde_json::Value::Null).await, Status::OK);
        assert_eq!(store.role_of("briefing", "red-2"), Some(MissionRole::ReadOnlySubscriber));
        let content = serde_json::json!({"hash": "h", "filename": "f", "creatorUid": "red-2"});
        assert_eq!(status_of(&mut app, "red-2", "PUT", "/Marti/api/missions/briefing/contents", content).await, Status::FORBIDDEN);
        assert_eq!(status_of(&mut app, "red-2", "GET", "/Marti/api/missions/briefing", serde_json::Value::Null).await, Status::OK);

        // The owner can promote it; the owner can also assign read-only.
        let promote = serde_json::json!({"uid": "red-2", "role": "MISSION_SUBSCRIBER"});
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/briefing/role", promote).await, Status::OK);
        let content = serde_json::json!({"hash": "h", "filename": "f", "creatorUid": "red-2"});
        assert_eq!(status_of(&mut app, "red-2", "PUT", "/Marti/api/missions/briefing/contents", content).await, Status::OK);
        let demote = serde_json::json!({"uid": "red-2", "role": "readonly_subscriber"});
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/briefing/role", demote).await, Status::OK);
        assert_eq!(store.role_of("briefing", "red-2"), Some(MissionRole::ReadOnlySubscriber));

        let owner_default = serde_json::json!({"creatorUid": "red-1", "defaultRole": "owner"});
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/x", owner_default).await, Status::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_owner_can_move_a_mission_between_its_groups() {
        use crate::groups::Membership;
        let (mut app, groups, _) = app_with_groups();
        groups.set_member("Blue", "red-1", Some(Membership::Both)).unwrap();
        assert_eq!(status_of(&mut app, "red-1", "PUT", "/Marti/api/missions/op", serde_json::json!({"creatorUid": "red-1", "groups": ["Red"]})).await, Status::CREATED);
        assert_eq!(status_of(&mut app, "blue-1", "GET", "/Marti/api/missions/op", serde_json::Value::Null).await, Status::NOT_FOUND);

        let (status, body) = json_request_as(&mut app, "red-1", "PATCH", "/Marti/api/missions/op", serde_json::json!({"actorUid": "red-1", "groups": ["Blue"]})).await;
        assert_eq!(status, Status::OK, "{body}");
        assert_eq!(status_of(&mut app, "blue-1", "GET", "/Marti/api/missions/op", serde_json::Value::Null).await, Status::OK);
        assert_eq!(status_of(&mut app, "red-2", "GET", "/Marti/api/missions/op", serde_json::Value::Null).await, Status::NOT_FOUND);
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

    /// A device can't add content claiming a `creatorUid` other than its own
    /// authenticated identity -- the same policy `create_mission` and
    /// `subscribe` already have tests for, but `add_content` didn't (a real
    /// gap found by this project's own red-team review of its test suite:
    /// removing this check from `add_content` alone left every other test
    /// green).
    #[tokio::test]
    async fn rejects_add_content_claim_not_matching_authenticated_identity() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;

        let (status, _) = json_request_as(
            &mut app,
            "real-device",
            "PUT",
            "/Marti/api/missions/m/contents",
            serde_json::json!({"hash": "abc123", "filename": "f.kml", "creatorUid": "someone-else"}),
        )
        .await;
        assert_eq!(status, Status::FORBIDDEN);

        // The rejected request must not have added anything.
        let response = get_as(&mut app, "user-1", "/Marti/api/missions/m").await;
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mission: Mission = serde_json::from_slice(&body_bytes).unwrap();
        assert!(mission.contents.is_empty());
    }

    /// A device can't update a mission claiming an `actorUid` other than its
    /// own authenticated identity -- another real gap found by the same
    /// red-team review (removing this check from `update_mission` alone
    /// left every other test green).
    #[tokio::test]
    async fn rejects_update_actoruid_not_matching_authenticated_identity() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "user-1", "description": "original"}),
        )
        .await;

        let (status, _) = json_request_as(
            &mut app,
            "real-device",
            "PATCH",
            "/Marti/api/missions/m",
            serde_json::json!({"description": "tampered", "actorUid": "someone-else"}),
        )
        .await;
        assert_eq!(status, Status::FORBIDDEN);

        // The rejected request must not have changed anything.
        let response = get_as(&mut app, "user-1", "/Marti/api/missions/m").await;
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mission: Mission = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(mission.description.as_deref(), Some("original"));
    }

    /// A device can't unsubscribe claiming to be a *different* uid than its
    /// own authenticated identity -- another real gap found by the same
    /// red-team review (removing this check from `unsubscribe` alone left
    /// every other test green, including `subscribes_and_unsubscribes_via_
    /// query_param`, since that test only ever unsubscribes as itself).
    #[tokio::test]
    async fn rejects_unsubscribe_as_a_different_uid() {
        let mut app = app();
        json_request_as(
            &mut app,
            "user-1",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "user-1"}),
        )
        .await;
        let subscribe_request = Request::builder()
            .method("PUT")
            .uri("/Marti/api/missions/m/subscription?uid=device-1")
            .extension(PeerIdentity("device-1".to_string()))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(subscribe_request).await.unwrap();

        // device-2 tries to unsubscribe device-1 by simply naming its uid in
        // the query param.
        let unsubscribe_request = Request::builder()
            .method("DELETE")
            .uri("/Marti/api/missions/m/subscription?uid=device-1")
            .extension(PeerIdentity("device-2".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(unsubscribe_request).await.unwrap();
        assert_eq!(response.status(), Status::FORBIDDEN);

        // device-1 must still be subscribed.
        let response = get_as(&mut app, "user-1", "/Marti/api/missions/m").await;
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mission: Mission = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(mission.subscribers, vec!["device-1"]);
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

    /// A device that isn't the mission's Owner can't delete it, even if it
    /// correctly claims its own identity everywhere -- the real gap this
    /// project's own red-team review flagged as historically missing on
    /// this exact handler.
    #[tokio::test]
    async fn rejects_delete_from_a_non_owner() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;

        let request = Request::builder()
            .method("DELETE")
            .uri("/Marti/api/missions/m")
            .extension(PeerIdentity("someone-else".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), Status::FORBIDDEN);

        // The rejected request must not have deleted anything.
        let response = get_as(&mut app, "owner", "/Marti/api/missions/m").await;
        assert_eq!(response.status(), Status::OK);
    }

    /// The Owner (the creator, by default) can delete their own mission.
    #[tokio::test]
    async fn owner_can_delete_their_own_mission() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;

        let request = Request::builder()
            .method("DELETE")
            .uri("/Marti/api/missions/m")
            .extension(PeerIdentity("owner".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), Status::NO_CONTENT);
    }

    /// A non-owner (even one correctly claiming its own actorUid) can't
    /// update mission metadata.
    #[tokio::test]
    async fn rejects_update_from_a_non_owner() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner", "description": "original"}),
        )
        .await;

        let (status, _) = json_request_as(
            &mut app,
            "someone-else",
            "PATCH",
            "/Marti/api/missions/m",
            serde_json::json!({"description": "tampered", "actorUid": "someone-else"}),
        )
        .await;
        assert_eq!(status, Status::FORBIDDEN);

        let response = get_as(&mut app, "owner", "/Marti/api/missions/m").await;
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mission: Mission = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(mission.description.as_deref(), Some("original"));
    }

    /// A device with no role on the mission at all (never subscribed, not
    /// the creator) can't add content, even if the identity-claim check
    /// alone would have let it through.
    #[tokio::test]
    async fn rejects_add_content_from_a_device_with_no_role() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;

        let (status, _) = json_request_as(
            &mut app,
            "uninvolved-device",
            "PUT",
            "/Marti/api/missions/m/contents",
            serde_json::json!({"hash": "abc123", "filename": "f.kml", "creatorUid": "uninvolved-device"}),
        )
        .await;
        assert_eq!(status, Status::FORBIDDEN);
    }

    /// A Subscriber (not just the Owner) can add content -- real
    /// collaborative Data Sync usage, not locked to the creator alone.
    #[tokio::test]
    async fn subscriber_can_add_content() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;
        let subscribe_request = Request::builder()
            .method("PUT")
            .uri("/Marti/api/missions/m/subscription?uid=subscriber-1")
            .extension(PeerIdentity("subscriber-1".to_string()))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(subscribe_request).await.unwrap();

        let (status, _) = json_request_as(
            &mut app,
            "subscriber-1",
            "PUT",
            "/Marti/api/missions/m/contents",
            serde_json::json!({"hash": "abc123", "filename": "f.kml", "creatorUid": "subscriber-1"}),
        )
        .await;
        assert_eq!(status, Status::OK);
    }

    /// The Owner can promote another identity to Owner via the role API.
    #[tokio::test]
    async fn owner_can_assign_a_role() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;

        let (status, _) = json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m/role",
            serde_json::json!({"uid": "co-owner", "role": "owner"}),
        )
        .await;
        assert_eq!(status, Status::OK);

        let response = get_as(&mut app, "owner", "/Marti/api/missions/m").await;
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let mission: Mission = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(mission.roles.get("co-owner"), Some(&MissionRole::Owner));
    }

    /// A non-owner can't assign roles to anyone, including themselves.
    #[tokio::test]
    async fn non_owner_cannot_assign_roles() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;

        let (status, _) = json_request_as(
            &mut app,
            "someone-else",
            "PUT",
            "/Marti/api/missions/m/role",
            serde_json::json!({"uid": "someone-else", "role": "owner"}),
        )
        .await;
        assert_eq!(status, Status::FORBIDDEN);
    }

    /// The Owner can revoke another identity's role, and the last-owner
    /// protection surfaces as a real, distinguishable 409 through the HTTP
    /// layer, not just at the store level.
    #[tokio::test]
    async fn owner_can_revoke_a_role_but_not_the_last_owner() {
        let mut app = app();
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m",
            serde_json::json!({"creatorUid": "owner"}),
        )
        .await;
        json_request_as(
            &mut app,
            "owner",
            "PUT",
            "/Marti/api/missions/m/role",
            serde_json::json!({"uid": "co-owner", "role": "owner"}),
        )
        .await;

        let revoke_request = Request::builder()
            .method("DELETE")
            .uri("/Marti/api/missions/m/role/co-owner")
            .extension(PeerIdentity("owner".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(revoke_request).await.unwrap();
        assert_eq!(response.status(), Status::NO_CONTENT);

        let last_owner_request = Request::builder()
            .method("DELETE")
            .uri("/Marti/api/missions/m/role/owner")
            .extension(PeerIdentity("owner".to_string()))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(last_owner_request).await.unwrap();
        assert_eq!(response.status(), Status::CONFLICT);
    }
}
