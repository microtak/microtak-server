//! Client-facing group ("channel") endpoints, matching the official TAK
//! Server's contract (read from `TAK-Product-Center/Server`:
//! `GroupsApi.getAllGroups`, `SubscriptionApi.setActiveGroups`), served
//! mTLS-authenticated like the rest of the Marti API. See `crate::groups`
//! for the model.
//!
//! - `GET /Marti/api/groups/all[?useCache=true]` -- the caller's groups.
//!   With `useCache=true` (what ATAK's channel selector asks for): every
//!   membership, IN and OUT, with its `active` flag. Without it: OUT
//!   memberships only -- the official server's cache-miss behaviour. The
//!   admin identity sees every group.
//! - `PUT /Marti/api/groups/active` -- body: a list of Group objects; the
//!   ones with `"active": true` stay on, the caller's other groups go off.
//! - `PUT /Marti/api/groups/activebits` -- body: a list of `bitpos` values
//!   to keep on.
//!
//! Group JSON, as the official server emits it: `name`, `direction`
//! (`IN`/`OUT`), `created` (`yyyy-MM-dd`), `type` (`SYSTEM`), `bitpos`,
//! `active`, and `description` when set. Responses use the official
//! `ApiResponse` wrapper (`version`, `type`, `data`).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::PeerIdentity;
use crate::groups::{Direction, GroupStore, MemberGroup};

#[derive(Clone)]
pub struct GroupsState {
    pub groups: Arc<GroupStore>,
    pub admin_common_name: Option<String>,
}

pub fn router(state: GroupsState) -> Router {
    Router::new()
        .route("/Marti/api/groups/all", get(list_groups))
        .route("/Marti/api/groups/active", put(set_active_groups))
        .route("/Marti/api/groups/activebits", put(set_active_bits))
        .with_state(state)
}

/// The official `com.bbn.marti.remote.groups.Group` JSON shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupJson {
    pub name: String,
    #[serde(default = "default_direction")]
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "type", default = "default_type")]
    pub group_type: String,
    #[serde(default)]
    pub bitpos: u32,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

fn default_direction() -> Direction {
    Direction::Out
}
fn default_type() -> String {
    "SYSTEM".to_string()
}
fn default_true() -> bool {
    true
}

fn created_date(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| t.date().to_string())
        .unwrap_or_else(|_| "1970-01-01".to_string())
}

impl From<MemberGroup> for GroupJson {
    fn from(group: MemberGroup) -> Self {
        GroupJson {
            name: group.name,
            direction: group.direction,
            created: Some(created_date(group.created_at_unix)),
            group_type: default_type(),
            bitpos: group.bitpos,
            active: group.active,
            description: group.description,
        }
    }
}

fn api_response(groups: Vec<GroupJson>) -> Response {
    Json(json!({
        "version": "3",
        "type": "com.bbn.marti.remote.groups.Group",
        "data": groups,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(rename = "useCache", default)]
    use_cache: bool,
}

async fn list_groups(
    State(state): State<GroupsState>,
    Extension(identity): Extension<PeerIdentity>,
    Query(query): Query<ListQuery>,
) -> Response {
    if state.admin_common_name.as_deref() == Some(identity.0.as_str()) {
        let all = state
            .groups
            .list()
            .into_iter()
            .map(|group| GroupJson {
                name: group.name,
                direction: Direction::Out,
                created: Some(created_date(group.created_at_unix)),
                group_type: default_type(),
                bitpos: group.bitpos,
                active: true,
                description: group.description,
            })
            .collect();
        return api_response(all);
    }
    let groups = state
        .groups
        .memberships(&identity.0)
        .into_iter()
        .filter(|group| query.use_cache || group.direction == Direction::Out)
        .map(GroupJson::from)
        .collect();
    api_response(groups)
}

async fn set_active_groups(
    State(state): State<GroupsState>,
    Extension(identity): Extension<PeerIdentity>,
    Json(groups): Json<Vec<GroupJson>>,
) -> Response {
    let active: BTreeSet<String> = groups.into_iter().filter(|g| g.active).map(|g| g.name).collect();
    apply_active(&state, &identity.0, &active)
}

async fn set_active_bits(
    State(state): State<GroupsState>,
    Extension(identity): Extension<PeerIdentity>,
    Json(bits): Json<Vec<u32>>,
) -> Response {
    let active = state.groups.names_for_bitpos(&bits);
    apply_active(&state, &identity.0, &active)
}

fn apply_active(state: &GroupsState, identity: &str, active: &BTreeSet<String>) -> Response {
    match state.groups.set_active(identity, active) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error.to_string() }))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::Membership;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn app() -> (Router, Arc<GroupStore>) {
        let groups = Arc::new(GroupStore::in_memory());
        groups.create("Red", Some("red team".into()), 0).unwrap();
        groups.create("Blue", None, 0).unwrap();
        groups.set_member("Red", "alpha", Some(Membership::Both)).unwrap();
        groups.set_member("Blue", "alpha", Some(Membership::Out)).unwrap();
        let state = GroupsState {
            groups: Arc::clone(&groups),
            admin_common_name: Some("admin".into()),
        };
        (router(state), groups)
    }

    async fn call(app: &Router, identity: &str, method: &str, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .extension(PeerIdentity(identity.to_string()))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn names_dirs(body: &serde_json::Value) -> Vec<(String, String, bool)> {
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                (
                    g["name"].as_str().unwrap().to_string(),
                    g["direction"].as_str().unwrap().to_string(),
                    g["active"].as_bool().unwrap(),
                )
            })
            .collect()
    }

    /// Official shape and the `useCache` split: all memberships with it,
    /// OUT only without it.
    #[tokio::test]
    async fn lists_the_callers_groups_in_the_official_shape() {
        let (app, _) = app();
        let (status, body) = call(&app, "alpha", "GET", "/Marti/api/groups/all?useCache=true", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["type"], "com.bbn.marti.remote.groups.Group");
        let red_in = body["data"].as_array().unwrap().iter().find(|g| g["name"] == "Red" && g["direction"] == "IN").unwrap();
        assert_eq!(red_in["type"], "SYSTEM");
        assert_eq!(red_in["bitpos"], 1);
        assert_eq!(red_in["description"], "red team");
        assert!(red_in["created"].as_str().unwrap().len() == 10, "yyyy-MM-dd");
        assert_eq!(
            names_dirs(&body),
            vec![
                ("Blue".into(), "OUT".into(), true),
                ("Red".into(), "IN".into(), true),
                ("Red".into(), "OUT".into(), true)
            ]
        );

        let (_, body) = call(&app, "alpha", "GET", "/Marti/api/groups/all", "").await;
        assert_eq!(names_dirs(&body), vec![("Blue".into(), "OUT".into(), true), ("Red".into(), "OUT".into(), true)]);
    }

    #[tokio::test]
    async fn an_identity_without_groups_sees_anon_and_the_admin_sees_all() {
        let (app, _) = app();
        let (_, body) = call(&app, "stranger", "GET", "/Marti/api/groups/all", "").await;
        assert_eq!(names_dirs(&body), vec![("__ANON__".into(), "OUT".into(), true)]);
        let (_, body) = call(&app, "admin", "GET", "/Marti/api/groups/all", "").await;
        assert_eq!(body["data"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn set_active_by_objects_and_by_bits() {
        let (app, groups) = app();
        let (status, _) = call(
            &app,
            "alpha",
            "PUT",
            "/Marti/api/groups/active?clientUid=x",
            r#"[{"name":"Red","direction":"IN","active":true},{"name":"Blue","direction":"OUT","active":false}]"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(groups.active_groups(Some("alpha"), Direction::Out), BTreeSet::from(["Red".to_string()]));

        let (status, _) = call(&app, "alpha", "PUT", "/Marti/api/groups/activebits", "[2]").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(groups.active_groups(Some("alpha"), Direction::Out), BTreeSet::from(["Blue".to_string()]));

        // Switching everything off is refused.
        let (status, _) = call(&app, "alpha", "PUT", "/Marti/api/groups/activebits", "[]").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(groups.active_groups(Some("alpha"), Direction::Out), BTreeSet::from(["Blue".to_string()]));
    }

    /// A device can only switch its *own* groups -- naming groups it isn't
    /// in doesn't join them.
    #[tokio::test]
    async fn activating_a_foreign_group_does_not_join_it() {
        let (app, groups) = app();
        groups.create("Secret", None, 0).unwrap();
        let (status, _) = call(&app, "alpha", "PUT", "/Marti/api/groups/activebits", "[1,3]").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(groups.active_groups(Some("alpha"), Direction::Out), BTreeSet::from(["Red".to_string()]));
        assert!(!groups.all_group_names("alpha").contains("Secret"));
    }
}
