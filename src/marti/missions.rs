//! The official Mission API (`/Marti/api/missions/*`), as
//! `TAK-Product-Center/Server`'s `MissionApi` serves it, on top of
//! [`crate::missions::MissionStore`]. The full contract, with sources, is
//! the wiki page `Official-Mission-API`; this module follows it:
//!
//! - **Mission lookup and role** (`MissionRoleAssignmentRequestHolderFilterBean`,
//!   `getRoleForRequest`): an unknown mission is an empty 404 (a deleted
//!   one 410) except on create; the caller's role comes from a mission
//!   token (`MissionAuthorization`, else `Authorization: Bearer`) --
//!   ACCESS → the default role, SUBSCRIPTION → that subscription's role --
//!   else admin → owner, else nothing for password-protected or
//!   invite-only missions, else the default role.
//! - Permissions per endpoint as in the official `@PreAuthorize`
//!   annotations; the official envelope `type` strings, date formats and
//!   `ErrorResponse` bodies.
//! - Groups: a mission is visible to callers sharing one of its groups
//!   (the admin sees all); `__ANON__` alone at create means the caller's
//!   own groups.
//!
//! Changes are announced to subscribers as the official server does
//! ([`super::mission_notify`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use serde_json::{Value, json};

use super::PeerIdentity;
use super::envelope::{api_response, cot_date_millis, random_uuid};
use super::mission_notify::{Announcement, ChangeKind, MissionNotifier};
use super::mission_token::{MissionTokenSigner, TokenType};
use crate::groups::GroupStore;
use crate::latest_cot::LatestCot;
use crate::missions::{
    ChangeRecord, Content, InvitationRecord, InvitationType, LayerRecord, LayerTree, LayerType,
    LogEntryRecord, MissionError, MissionFields, MissionRecord, MissionStore, NewMission,
    Permission, Role, SubscriptionRecord, Window,
};
use crate::sync::ResourceStore;
use crate::transport::connections::ConnectedClients;

#[derive(Clone)]
pub struct MissionsState {
    pub store: Arc<MissionStore>,
    pub groups: Arc<GroupStore>,
    pub admin_common_name: Option<String>,
    pub tokens: Arc<MissionTokenSigner>,
    pub resources: Arc<ResourceStore>,
    pub latest_cot: Arc<LatestCot>,
    pub notifier: Arc<MissionNotifier>,
    pub clients: ConnectedClients,
    /// File bytes, for mission packages.
    pub content: Arc<crate::content_store::ContentStore>,
}

impl MissionsState {
    /// No groups, no admin, fresh keys -- for tests.
    pub fn in_memory() -> Self {
        Self::with_hub(tokio::sync::broadcast::channel(64).0)
    }

    /// In memory, notifications going to `hub` -- for tests.
    pub fn with_hub(hub: tokio::sync::broadcast::Sender<crate::transport::hub::Outbound>) -> Self {
        let store = Arc::new(MissionStore::in_memory());
        let groups = Arc::new(GroupStore::in_memory());
        let resources = Arc::new(ResourceStore::in_memory());
        let latest_cot = Arc::new(LatestCot::in_memory());
        let notifier = Arc::new(MissionNotifier::new(
            hub,
            Arc::clone(&store),
            Arc::clone(&resources),
            Arc::clone(&latest_cot),
            Arc::clone(&groups),
        ));
        Self {
            store,
            groups,
            admin_common_name: None,
            tokens: Arc::new(MissionTokenSigner::generate()),
            resources,
            latest_cot,
            notifier,
            clients: ConnectedClients::new(),
            content: Arc::new(
                crate::content_store::ContentStore::open(
                    std::env::temp_dir()
                        .join(format!("microtak-mission-content-{}", random_uuid())),
                )
                .expect("temp content store"),
            ),
        }
    }
}

pub fn router_with(state: MissionsState) -> Router {
    Router::new()
        .route(
            "/Marti/api/missions",
            get(list_missions).delete(delete_mission_by_guid),
        )
        .route("/Marti/api/pagedmissions", get(paged_missions))
        .route(
            "/Marti/api/missions/:name/maplayers",
            post(add_map_layer_by_name).put(update_map_layer_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/maplayers",
            post(add_map_layer_by_guid).put(update_map_layer_by_guid),
        )
        // `/missions/{missionName:.+}/maplayers/{uid}` and
        // `/missions/{missionGuid:.+}/maplayers/{uid}` are equally specific
        // to Spring: every DELETE is "Ambiguous handler methods" (500).
        .route(
            "/Marti/api/missions/:name/maplayers/:uid",
            axum::routing::delete(|| async { ApiError::Internal }),
        )
        .route(
            "/Marti/api/missions/:name/externaldata",
            post(set_external_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/externaldata",
            post(set_external_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/externaldata/:id",
            axum::routing::delete(delete_external_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/externaldata/:id",
            axum::routing::delete(delete_external_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/externaldata/:id/change",
            post(notify_external_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/externaldata/:id/change",
            post(notify_external_by_guid),
        )
        .route("/Marti/api/missioncount", get(mission_count))
        .route(
            "/Marti/api/missions/all/subscriptions",
            get(all_subscriptions),
        )
        .route(
            "/Marti/api/missions/all/subscriptions/guid",
            get(all_subscriptions_with_guid),
        )
        .route(
            "/Marti/api/missions/all/invitations",
            get(all_invitation_names),
        )
        .route("/Marti/api/missions/invitations", get(my_invitations))
        .route("/Marti/api/missions/all/logs", get(all_logs))
        .route(
            "/Marti/api/missions/logs/entries",
            post(post_log_entry).put(put_log_entry),
        )
        .route(
            "/Marti/api/missions/logs/entries/:id",
            get(get_log_entry).delete(delete_log_entry),
        )
        .route(
            "/Marti/api/missions/:name",
            get(get_mission_by_name)
                .put(create_mission_put)
                .post(create_mission_post)
                .delete(delete_mission_by_name),
        )
        .route("/Marti/api/missions/guid/:guid", get(get_mission_by_guid))
        .route(
            "/Marti/api/missions/:name/contents",
            put(add_contents_by_name).delete(remove_content_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/contents",
            put(add_contents_by_guid).delete(remove_content_by_guid),
        )
        .route("/Marti/api/missions/:name/changes", get(changes_by_name))
        .route(
            "/Marti/api/missions/guid/:guid/changes",
            get(changes_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/keywords",
            put(set_keywords).delete(clear_keywords),
        )
        .route(
            "/Marti/api/missions/:name/keywords/:keyword",
            delete(remove_keyword),
        )
        .route(
            "/Marti/api/missions/:name/uid/:uid/keywords",
            put(set_uid_keywords).delete(clear_uid_keywords),
        )
        .route(
            "/Marti/api/missions/:name/content/:hash/keywords",
            put(set_hash_keywords).delete(clear_hash_keywords),
        )
        .route("/Marti/api/missions/:name/token", get(access_token))
        .route(
            "/Marti/api/missions/:name/subscription",
            get(subscription_by_name)
                .put(subscribe_by_name)
                .post(set_subscription_roles_by_name)
                .delete(unsubscribe_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/subscription",
            get(subscription_by_guid)
                .put(subscribe_by_guid)
                .post(set_subscription_roles_by_guid)
                .delete(unsubscribe_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/subscriptions",
            get(subscribers_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/subscriptions",
            get(subscribers_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/subscriptions/roles",
            get(subscription_roles_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/subscriptions/roles",
            get(subscription_roles_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/role",
            get(role_by_name).put(set_role_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/role",
            get(role_by_guid).put(set_role_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/invitations",
            get(invitations_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/invitations",
            get(invitations_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/invite/:kind/:invitee",
            put(invite_by_name).delete(uninvite_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/invite/:kind/:invitee",
            put(invite_by_guid).delete(uninvite_by_guid),
        )
        .route("/Marti/api/missions/:name/log", get(logs_for_mission))
        .route("/Marti/api/missions/:name/cot", get(cot_by_name))
        .route("/Marti/api/missions/guid/:guid/cot", get(cot_by_guid))
        .route(
            "/Marti/api/missions/:name/layers",
            get(layers_by_name)
                .put(create_layer_by_name)
                .delete(delete_layers_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/layers",
            get(layers_by_guid)
                .put(create_layer_by_guid)
                .delete(delete_layers_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/layers/parent",
            put(set_layer_parent_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/layers/parent",
            put(set_layer_parent_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/layers/:layer",
            get(layer_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/layers/:layer",
            get(layer_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/layers/:layer/name",
            put(rename_layer_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/layers/:layer/name",
            put(rename_layer_by_guid),
        )
        .route("/Marti/api/missions/:name/archive", get(archive_mission))
        .route("/Marti/api/missions/:name/contacts", get(contacts_by_name))
        .route(
            "/Marti/api/missions/guid/:guid/contacts",
            get(contacts_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/contents/missionpackage",
            put(add_mission_package),
        )
        .route(
            "/Marti/api/missions/:name/password",
            put(set_password_by_name).delete(remove_password_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/password",
            put(set_password_by_guid).delete(remove_password_by_guid),
        )
        .route(
            "/Marti/api/missions/:name/expiration",
            put(set_expiration_by_name),
        )
        .route(
            "/Marti/api/missions/guid/:guid/expiration",
            put(set_expiration_by_guid),
        )
        .with_state(state)
}

fn now_ms() -> i64 {
    crate::cot::now_unix_millis()
}

/// `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'` (`COT_DATE_FORMAT_PAD_MILLIS`).
fn pad_millis(ms: i64) -> String {
    let unpadded = cot_date_millis(ms);
    let (head, millis) = unpadded.rsplit_once('.').expect("cot date has millis");
    format!("{head}.{:0>3}Z", millis.trim_end_matches('Z'))
}

// --- errors -------------------------------------------------------------

/// The official `CustomExceptionHandler` responses, plus the filter's
/// body-less 404/410 and Spring Security's access-denied 403.
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    /// `handleMissingJsonBodyException`: "Invalid Request Body".
    InvalidBody,
    Forbidden(String),
    Gone(String),
    Internal,
    /// The request filter: unknown mission.
    NoMission,
    /// The request filter: deleted mission.
    MissionGone,
    /// A `@PreAuthorize` permission the caller's role lacks.
    AccessDenied,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = |status: StatusCode, name: &str, code: u32, message: String| {
            (
                status,
                Json(json!({ "status": name, "code": code, "message": message })),
            )
                .into_response()
        };
        let suffix = |m: &str| {
            if m.is_empty() {
                String::new()
            } else {
                format!(": {m}")
            }
        };
        match self {
            ApiError::NotFound(m) => body(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                1,
                format!("Not Found{}", suffix(&m)),
            ),
            ApiError::InvalidBody => body(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                2,
                "Invalid Request Body".into(),
            ),
            ApiError::BadRequest(m) => body(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                2,
                format!("Invalid Request{}", suffix(&m)),
            ),
            ApiError::Forbidden(m) => body(StatusCode::FORBIDDEN, "FORBIDDEN", 10, suffix(&m)),
            ApiError::Gone(m) => body(StatusCode::GONE, "GONE", 8, suffix(&m)),
            ApiError::Internal => body(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                6,
                String::new(),
            ),
            ApiError::NoMission => StatusCode::NOT_FOUND.into_response(),
            ApiError::MissionGone => StatusCode::GONE.into_response(),
            ApiError::AccessDenied => StatusCode::FORBIDDEN.into_response(),
        }
    }
}

impl From<MissionError> for ApiError {
    fn from(error: MissionError) -> Self {
        match error {
            MissionError::NotFound(guid) => {
                ApiError::NotFound(format!("Mission guid '{guid}' not found - not deleted"))
            }
            MissionError::EventLog(e) => {
                tracing::error!(error = %e, "mission store write failed");
                ApiError::Internal
            }
        }
    }
}

type ApiResult = Result<Response, ApiError>;

// --- request parameters ---------------------------------------------------

/// Query parameters, repeatable (Spring binds `group=a&group=b` to an array).
struct Params(Vec<(String, String)>);

impl Params {
    fn parse(raw: Option<String>) -> Result<Self, ApiError> {
        let raw = raw.unwrap_or_default();
        serde_urlencoded::from_str(&raw)
            .map(Params)
            .map_err(|e| ApiError::BadRequest(format!("bad query string: {e}")))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn string(&self, name: &str) -> String {
        self.get(name).unwrap_or("").to_string()
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Spring's boolean conversion (`true/false/on/off/yes/no/1/0`).
    fn bool(&self, name: &str, default: bool) -> Result<bool, ApiError> {
        match self.get(name).map(|v| v.trim().to_ascii_lowercase()) {
            None => Ok(default),
            Some(v) if v.is_empty() => Ok(default),
            Some(v) => match v.as_str() {
                "true" | "on" | "yes" | "1" => Ok(true),
                "false" | "off" | "no" | "0" => Ok(false),
                _ => Err(ApiError::BadRequest(format!(
                    "invalid boolean for '{name}'"
                ))),
            },
        }
    }

    fn long(&self, name: &str) -> Result<Option<i64>, ApiError> {
        match self.get(name).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => v
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| ApiError::BadRequest(format!("invalid number for '{name}'"))),
        }
    }

    fn role(&self, name: &str) -> Result<Option<Role>, ApiError> {
        match self.get(name).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => Role::parse(v)
                .map(Some)
                .ok_or_else(|| ApiError::BadRequest(format!("invalid role '{v}'"))),
        }
    }

    /// `secago` / `start` / `end` (`TimeUtils.validateTimeInterval`).
    fn window(&self) -> Result<Window, ApiError> {
        let parse_date = |name: &str| -> Result<Option<i64>, ApiError> {
            match self.get(name).filter(|v| !v.is_empty()) {
                None => Ok(None),
                Some(v) => {
                    time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc3339)
                        .map(|t| Some((t.unix_timestamp_nanos() / 1_000_000) as i64))
                        .map_err(|_| ApiError::BadRequest(format!("invalid date for '{name}'")))
                }
            }
        };
        let mut start = parse_date("start")?;
        let end = parse_date("end")?;
        if let Some(secago) = self.long("secago")?.filter(|s| *s > 0) {
            start = Some(now_ms() - secago * 1000);
        }
        let window = Window {
            start_ms: start.unwrap_or(i64::MIN),
            end_ms: end.unwrap_or(i64::MAX),
        };
        if window.start_ms >= window.end_ms {
            return Err(ApiError::BadRequest("invalid time range".into()));
        }
        Ok(window)
    }
}

/// Who is asking: the certificate's CN is the username.
struct Caller {
    username: String,
    admin: bool,
    groups: BTreeSet<String>,
    token: Option<String>,
    api_version: u32,
}

fn caller(state: &MissionsState, identity: &PeerIdentity, headers: &HeaderMap) -> Caller {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let token = header("MissionAuthorization")
        .or_else(|| header("Authorization"))
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(String::from);
    Caller {
        username: identity.0.clone(),
        admin: state.admin_common_name.as_deref() == Some(identity.0.as_str()),
        groups: state.groups.all_group_names(&identity.0),
        token,
        // `getApiVersionNumberFromRequest`: absent or unparsable → 2.
        api_version: header("API_VERSION")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(2),
    }
}

fn visible(caller: &Caller, mission: &MissionRecord) -> bool {
    caller.admin || mission.groups.iter().any(|g| caller.groups.contains(g))
}

enum Key<'a> {
    Name(&'a str),
    Guid(&'a str),
}

/// The request filter's lookup: `Ok(None)` only when `create` and nothing
/// of that name exists for the caller.
fn lookup(
    state: &MissionsState,
    caller: &Caller,
    key: Key<'_>,
    create: bool,
) -> Result<Option<MissionRecord>, ApiError> {
    match key {
        Key::Name(name) => {
            let name = name.trim();
            if name.is_empty() {
                return Err(ApiError::BadRequest("empty 'name' path parameter".into()));
            }
            match state.store.by_name(name, |m| visible(caller, m)) {
                Some(m) => Ok(Some(m)),
                None if create => Ok(None),
                None if state.store.is_deleted_name(name) => Err(ApiError::MissionGone),
                None => Err(ApiError::NoMission),
            }
        }
        Key::Guid(guid) => {
            if uuid_parse(guid).is_none() {
                return Err(ApiError::BadRequest("invalid mission UUID".into()));
            }
            match state.store.by_guid(guid) {
                Some(m) if m.deleted => Err(ApiError::MissionGone),
                Some(m) if visible(caller, &m) => Ok(Some(m)),
                _ => Err(ApiError::NoMission),
            }
        }
    }
}

fn existing(
    state: &MissionsState,
    caller: &Caller,
    key: Key<'_>,
) -> Result<MissionRecord, ApiError> {
    lookup(state, caller, key, false).map(|m| m.expect("not a create"))
}

fn uuid_parse(s: &str) -> Option<()> {
    let parts: Vec<&str> = s.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    (parts.len() == 5
        && parts
            .iter()
            .zip(lens)
            .all(|(p, l)| p.len() == l && p.chars().all(|c| c.is_ascii_hexdigit())))
    .then_some(())
}

/// `getRoleFromToken` for the given token types.
fn role_from_token(
    state: &MissionsState,
    mission: &MissionRecord,
    caller: &Caller,
    types: &[TokenType],
) -> Option<Role> {
    let token = caller.token.as_deref()?;
    let claims = state.tokens.decode(token)?;
    if !types.contains(&claims.token_type) || claims.mission_name != mission.name {
        return None;
    }
    match claims.token_type {
        TokenType::Subscription => state
            .store
            .subscription_by_id(&mission.guid, &claims.id)
            .map(|s| s.role),
        TokenType::Invitation => state
            .store
            .invitation_by_token(token)
            .filter(|i| i.mission_name.eq_ignore_ascii_case(&mission.name))
            .map(|i| i.role),
        TokenType::Access => Some(mission.effective_default_role()),
    }
}

/// `getRoleForRequest`.
fn role_for(state: &MissionsState, mission: &MissionRecord, caller: &Caller) -> Option<Role> {
    if let Some(role) = role_from_token(
        state,
        mission,
        caller,
        &[TokenType::Access, TokenType::Subscription],
    ) {
        return Some(role);
    }
    if caller.admin {
        return Some(Role::Owner);
    }
    if mission.password_protected() || mission.invite_only {
        return None;
    }
    Some(mission.effective_default_role())
}

fn require(role: Option<Role>, permission: Permission) -> Result<(), ApiError> {
    match role {
        Some(r) if r.has(permission) => Ok(()),
        _ => Err(ApiError::AccessDenied),
    }
}

/// `validateRoleAssignment`.
fn may_assign(mission: &MissionRecord, current: Option<Role>, assign: Role) -> bool {
    let Some(current) = current else { return false };
    current.has_all(assign)
        && (mission.password_protected() || assign.has_all(mission.effective_default_role()))
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    Ok(crate::users::hash_password(password))
}

fn password_matches(mission: &MissionRecord, password: &str) -> bool {
    mission
        .password_hash
        .as_deref()
        .is_some_and(|hash| crate::users::verify_password(password, hash))
}

// --- JSON -------------------------------------------------------------------

fn role_json(role: Role) -> Value {
    let permissions: Vec<Value> = role
        .permissions()
        .iter()
        .map(|p| serde_json::to_value(p).expect("enum"))
        .collect();
    json!({ "type": role.name(), "permissions": permissions })
}

fn resource_json(state: &MissionsState, hash: &str) -> Option<Value> {
    state
        .resources
        .by_hash(hash, None)
        .into_iter()
        .next()
        .map(|r| r.resource_json())
}

#[derive(Default)]
struct MissionExtras {
    token: Option<String>,
    owner_role: Option<Role>,
    changes: Option<Vec<ChangeRecord>>,
    logs: Option<Vec<LogEntryRecord>>,
    /// `Mission.clear()`: no content (forbidden reads at API ≥ 3,
    /// password-protected missions in the list).
    cleared: bool,
    /// Details and keywords on the adds (`hydrateDetails`).
    details: bool,
}

fn mission_json(
    state: &MissionsState,
    m: &MissionRecord,
    groups: &BTreeSet<String>,
    extras: MissionExtras,
) -> Value {
    let f = &m.fields;
    let mut uids = Vec::new();
    let mut contents = Vec::new();
    if !extras.cleared {
        for add in &m.contents {
            let mut entry = serde_json::Map::new();
            match &add.content {
                Content::Uid(uid) => {
                    entry.insert("data".into(), uid.clone().into());
                }
                Content::Hash(hash) => {
                    if let Some(resource) = resource_json(state, hash) {
                        entry.insert("data".into(), resource);
                    }
                }
            }
            entry.insert("timestamp".into(), pad_millis(add.timestamp_ms).into());
            entry.insert("creatorUid".into(), add.creator_uid.clone().into());
            if extras.details {
                if let Some(keywords) = m.content_keywords.get(&add.content) {
                    entry.insert("keywords".into(), json!(keywords));
                }
                if let Content::Uid(uid) = &add.content
                    && let Some(details) = state.latest_cot.uid_details(uid)
                {
                    entry.insert("details".into(), details);
                }
            }
            match add.content {
                Content::Uid(_) => uids.push(Value::Object(entry)),
                Content::Hash(_) => contents.push(Value::Object(entry)),
            }
        }
    }
    let mut out = serde_json::Map::new();
    let mut put = |k: &str, v: Value| {
        out.insert(k.to_string(), v);
    };
    put("name", m.name.clone().into());
    put("description", f.description.clone().into());
    put("chatRoom", f.chat_room.clone().into());
    put("baseLayer", f.base_layer.clone().into());
    put("bbox", f.bbox.clone().into());
    if !f.bounding_polygon.is_empty() {
        put("boundingPolygon", f.bounding_polygon.clone().into());
    }
    put("path", f.path.clone().into());
    put("classification", f.classification.clone().into());
    put("tool", m.tool.clone().into());
    put("keywords", json!(m.keywords));
    put("creatorUid", m.creator_uid.clone().into());
    put("createTime", pad_millis(m.create_time_ms).into());
    put("lastEdited", pad_millis(m.last_edited_ms).into());
    put("groups", json!(groups));
    let external: Vec<Value> = state
        .store
        .external_data_of(&m.guid)
        .iter()
        .map(external_json)
        .collect();
    put("externalData", external.into());
    put("feeds", json!([]));
    let layers: Vec<Value> = state
        .store
        .map_layers_of(&m.guid)
        .iter()
        .map(map_layer_json)
        .collect();
    put("mapLayers", layers.into());
    if let Some(role) = m.default_role {
        put("defaultRole", role_json(role));
    }
    if let Some(role) = extras.owner_role {
        put("ownerRole", role_json(role));
    }
    put("inviteOnly", m.invite_only.into());
    put("expiration", f.expiration.into());
    put("guid", m.guid.clone().into());
    put("uids", uids.into());
    put("contents", contents.into());
    put("passwordProtected", m.password_protected().into());
    if let Some(token) = extras.token {
        put("token", token.into());
    }
    if let Some(changes) = extras.changes {
        put(
            "missionChanges",
            changes.iter().map(|c| change_json(state, c)).collect(),
        );
    }
    if let Some(logs) = extras.logs {
        put("logs", logs.iter().map(log_json).collect());
    }
    Value::Object(out)
}

/// The mission's groups as the caller sees them
/// (`getGroupNamesForBitVectorString(mission, userGroups)`).
fn groups_seen(caller: &Caller, mission: &MissionRecord) -> BTreeSet<String> {
    if caller.admin {
        mission.groups.clone()
    } else {
        mission
            .groups
            .intersection(&caller.groups)
            .cloned()
            .collect()
    }
}

fn change_json(state: &MissionsState, c: &ChangeRecord) -> Value {
    let mut out = serde_json::Map::new();
    out.insert(
        "type".into(),
        serde_json::to_value(c.change_type).expect("enum"),
    );
    out.insert("missionName".into(), c.mission_name.clone().into());
    out.insert("missionGuid".into(), c.mission_guid.clone().into());
    out.insert("timestamp".into(), pad_millis(c.timestamp_ms).into());
    out.insert("serverTime".into(), pad_millis(c.server_time_ms).into());
    out.insert("creatorUid".into(), c.creator_uid.clone().into());
    out.insert("isFederatedChange".into(), false.into());
    match &c.content {
        Some(Content::Uid(uid)) => {
            out.insert("contentUid".into(), uid.clone().into());
            if let Some(details) = state.latest_cot.uid_details(uid) {
                out.insert("details".into(), details);
            }
        }
        Some(Content::Hash(hash)) => {
            // `findContentResource`: a placeholder with only the hash if gone.
            let resource = resource_json(state, hash).unwrap_or_else(|| json!({ "hash": hash }));
            out.insert("contentResource".into(), resource);
        }
        None => {}
    }
    if let Some(uid) = &c.map_layer_uid {
        // findMapLayer: the current layer, or one with just the uid.
        let layer = match state.store.map_layer(uid) {
            Some(l) => map_layer_json(&l),
            None => Value::Object(map_layer_placeholder(uid).into_iter().collect()),
        };
        out.insert("mapLayer".into(), layer);
    }
    if let Some(ext) = &c.external_data {
        let record = state.store.external_data(&ext.uid);
        out.insert(
            "externalData".into(),
            external_change_json(record.as_ref(), ext),
        );
    }
    Value::Object(out)
}

fn subscription_json(
    state: &MissionsState,
    s: &SubscriptionRecord,
    mission: Option<Value>,
    with_token: bool,
) -> Value {
    let _ = state;
    let mut out = serde_json::Map::new();
    if with_token {
        out.insert("token".into(), s.token.clone().into());
    }
    if let Some(mission) = mission {
        out.insert("mission".into(), mission);
    }
    out.insert("clientUid".into(), s.client_uid.clone().into());
    out.insert("username".into(), s.username.clone().into());
    out.insert(
        "createTime".into(),
        cot_date_millis(s.create_time_ms).into(),
    );
    out.insert("role".into(), role_json(s.role));
    Value::Object(out)
}

fn invitation_json(i: &InvitationRecord) -> Value {
    json!({
        "missionName": i.mission_name,
        "invitee": i.invitee,
        "type": i.invitation_type.name(),
        "creatorUid": i.creator_uid,
        "createTime": cot_date_millis(i.create_time_ms),
        "token": i.token,
        "missionGuid": i.mission_guid,
        "role": role_json(i.role),
    })
}

fn log_json(e: &LogEntryRecord) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("id".into(), e.id.clone().into());
    out.insert("content".into(), e.content.clone().into());
    out.insert("creatorUid".into(), e.creator_uid.clone().into());
    out.insert("entryUid".into(), e.entry_uid.clone().into());
    out.insert("missionNames".into(), json!(e.mission_names));
    out.insert("servertime".into(), pad_millis(e.server_time_ms).into());
    if let Some(dtg) = e.dtg_ms {
        out.insert("dtg".into(), pad_millis(dtg).into());
    }
    if let Some(created) = e.created_ms {
        out.insert("created".into(), pad_millis(created).into());
    }
    out.insert("contentHashes".into(), json!(e.content_hashes));
    out.insert("keywords".into(), json!(e.keywords));
    Value::Object(out)
}

fn ok(kind: &'static str, data: Value) -> ApiResult {
    Ok(api_response(kind, data).into_response())
}

fn created(kind: &'static str, data: Value) -> ApiResult {
    Ok((StatusCode::CREATED, api_response(kind, data)).into_response())
}

// --- list / get ----------------------------------------------------------------

async fn list_missions(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let params = Params::parse(query)?;
    let include_protected = params.bool("passwordProtected", false)?;
    let include_roles = params.bool("defaultRole", false)?;
    let tool = params
        .get("tool")
        .filter(|t| !t.is_empty())
        .unwrap_or("public")
        .to_string();
    // `getAllMissionsByToolNoGroupCheck`, newest first, then a set ordered
    // (and de-duplicated) by lowercase name.
    let mut candidates: Vec<MissionRecord> = state
        .store
        .list()
        .into_iter()
        .filter(|m| {
            !m.invite_only
                && (include_protected || !m.password_protected())
                && (include_roles || matches!(m.default_role, None | Some(Role::Subscriber)))
                && m.tool == tool
        })
        .collect();
    candidates.sort_by_key(|m| std::cmp::Reverse(m.create_time_ms));
    let mut by_name: std::collections::BTreeMap<String, MissionRecord> =
        std::collections::BTreeMap::new();
    for m in candidates {
        by_name.entry(m.name.to_lowercase()).or_insert(m);
    }
    let missions: Vec<Value> = by_name
        .values()
        .filter(|m| visible(&caller, m))
        .map(|m| {
            let extras = MissionExtras {
                cleared: m.password_protected(),
                ..Default::default()
            };
            mission_json(&state, m, &groups_seen(&caller, m), extras)
        })
        .collect();
    ok("Mission", missions.into())
}

/// The `getAllMissions*` filters: no invite-only missions, password ones
/// only if asked for, roles other than none/`MISSION_SUBSCRIBER` only if
/// asked for (`default_role_id is null or default_role_id = 2`).
fn listed(m: &MissionRecord, include_protected: bool, include_roles: bool) -> bool {
    !m.invite_only
        && (include_protected || !m.password_protected())
        && (include_roles || matches!(m.default_role, None | Some(Role::Subscriber)))
}

/// Text order under PostgreSQL's `en_US.UTF-8` collation, approximated:
/// case-insensitive first, lowercase before uppercase on a tie.
fn collate(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| b.cmp(a))
}

/// `order by <column>` over the `missionAttributes` columns; `None` for a
/// column that doesn't exist (an SQL error on the official server).
fn column_order(column: &str) -> Option<fn(&MissionRecord, &MissionRecord) -> std::cmp::Ordering> {
    Some(match column {
        "id" => |a, b| a.id.cmp(&b.id),
        "name" => |a, b| collate(&a.name, &b.name),
        "create_time" => |a, b| a.create_time_ms.cmp(&b.create_time_ms),
        "last_edited" => |a, b| a.last_edited_ms.cmp(&b.last_edited_ms),
        "creatoruid" => |a, b| collate(&a.creator_uid, &b.creator_uid),
        "description" => |a, b| collate(&a.fields.description, &b.fields.description),
        "chatroom" => |a, b| collate(&a.fields.chat_room, &b.fields.chat_room),
        "tool" => |a, b| collate(&a.tool, &b.tool),
        "expiration" => |a, b| a.fields.expiration.cmp(&b.fields.expiration),
        "guid" => |a, b| a.guid.cmp(&b.guid),
        "invite_only" => |a, b| a.invite_only.cmp(&b.invite_only),
        _ => return None,
    })
}

/// `getPagedMissions` / `getMissionsFiltered`.
async fn paged_missions(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let params = Params::parse(query)?;
    let include_protected = params.bool("passwordProtected", true)?;
    let include_roles = params.bool("defaultRole", true)?;
    let int = |name: &str, default: i64| -> Result<i64, ApiError> {
        match params.get(name) {
            None => Ok(default),
            Some(v) => v
                .trim()
                .parse::<i32>()
                .map(i64::from)
                .map_err(|_| ApiError::BadRequest(String::new())),
        }
    };
    let (page, limit) = (int("page", 0)?, int("pagesize", 10)?);
    let sort = params.string("sort");
    let ascending = params.bool("ascending", true)?;
    let (name_filter, uid_filter) = (params.string("nameFilter"), params.string("uidFilter"));
    let tool = params.get("tool").map(str::to_string);
    // `int page = offset / limit`, then `PageRequest.of(page, limit)`.
    if limit == 0 {
        return Err(ApiError::Internal);
    }
    if page < 0 || limit < 1 {
        return Err(ApiError::BadRequest(String::new()));
    }
    let order = if sort.is_empty() {
        None
    } else {
        Some(column_order(&sort).ok_or(ApiError::Internal)?)
    };
    let mut missions: Vec<MissionRecord> = state
        .store
        .list()
        .into_iter()
        .filter(|m| listed(m, include_protected, include_roles) && visible(&caller, m))
        .collect();
    // No ORDER BY: storage order.
    missions.sort_by_key(|m| (m.id, m.create_time_ms));
    let uid_rows = tool.is_none() && name_filter.trim().is_empty() && !uid_filter.trim().is_empty();
    if let Some(tool) = &tool {
        missions.retain(|m| &m.tool == tool);
    } else if !name_filter.trim().is_empty() {
        let pattern = format!("%{name_filter}%");
        missions.retain(|m| super::file_manager::like(&m.name, &pattern));
    } else if uid_rows {
        // An inner join on mission_uid: a row per matching uid.
        let pattern = format!("%{uid_filter}%");
        missions = missions
            .into_iter()
            .flat_map(|m| {
                let n = m.uids().filter(|c| matches!(&c.content, Content::Uid(u) if super::file_manager::like(u, &pattern))).count();
                std::iter::repeat_n(m, n)
            })
            .collect();
    }
    if let Some(order) = order {
        missions.sort_by(order);
        if !ascending {
            missions.reverse();
        }
    }
    let offset = (page * limit) as usize;
    let details = uid_rows && !sort.is_empty();
    let out: Vec<Value> = missions
        .iter()
        .skip(offset)
        .take(limit as usize)
        .map(|m| {
            let extras = MissionExtras {
                cleared: m.password_protected(),
                details: details && !m.password_protected(),
                ..Default::default()
            };
            mission_json(&state, m, &groups_seen(&caller, m), extras)
        })
        .collect();
    ok("Mission", out.into())
}

/// `countAllMissions`: the list filters only -- no group check, `tool`
/// ignored.
async fn mission_count(State(state): State<MissionsState>, RawQuery(query): RawQuery) -> ApiResult {
    let params = Params::parse(query)?;
    let include_protected = params.bool("passwordProtected", true)?;
    let include_roles = params.bool("defaultRole", true)?;
    let n = state
        .store
        .list()
        .iter()
        .filter(|m| listed(m, include_protected, include_roles))
        .count();
    ok("Mission", json!(n))
}

async fn get_mission_impl(
    state: MissionsState,
    caller: Caller,
    key: Key<'_>,
    params: Params,
) -> ApiResult {
    let mission = existing(&state, &caller, key)?;
    let window = params.window()?;
    let password = params.string("password");
    let mut extras = MissionExtras {
        details: true,
        ..Default::default()
    };
    let readable = if !password.is_empty() {
        if !password_matches(&mission, &password) {
            return Err(ApiError::Forbidden(
                "Illegal attempt to access mission! Password did not match.".into(),
            ));
        }
        extras.token = Some(state.tokens.create(
            &random_uuid(),
            TokenType::Access,
            &mission.name,
            &mission.guid,
            now_ms() / 1000,
        ));
        true
    } else {
        role_for(&state, &mission, &caller).is_some_and(|r| r.has(Permission::MissionRead))
    };
    if !readable {
        if caller.api_version <= 2 {
            return Err(ApiError::Forbidden(
                "Illegal attempt to access mission! Request did not have read access.".into(),
            ));
        }
        extras.cleared = true;
    } else {
        if params.bool("changes", false)? {
            extras.changes = Some(state.store.changes(&mission.guid, window, false)?);
        }
        if params.bool("logs", false)? {
            extras.logs = Some(state.store.log_entries_for(&mission.name, window));
        }
    }
    let json = mission_json(&state, &mission, &groups_seen(&caller, &mission), extras);
    ok("Mission", json!([json]))
}

async fn get_mission_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    get_mission_impl(state, caller, Key::Name(&name), Params::parse(query)?).await
}

async fn get_mission_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    get_mission_impl(state, caller, Key::Guid(&guid), Params::parse(query)?).await
}

// --- create / update / delete ------------------------------------------------------

/// What a create/update request asks for, query parameters overridden by
/// a JSON `Mission` body (`doCreateMissionAllowDupe`).
struct CreateRequest {
    creator_uid: String,
    groups: Vec<String>,
    fields: MissionFields,
    tool: String,
    password: Option<String>,
    default_role: Option<Role>,
    expiration_given: bool,
    invite_only: bool,
}

fn parse_create(
    params: &Params,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<CreateRequest, ApiError> {
    let mut groups = params.all("group");
    if groups.is_empty() {
        groups.push(crate::groups::ANON_GROUP.to_string());
    }
    let expiration = params.long("expiration")?;
    let mut request = CreateRequest {
        creator_uid: params.string("creatorUid"),
        groups,
        fields: MissionFields {
            description: params.string("description"),
            chat_room: params.string("chatRoom"),
            base_layer: params.string("baseLayer"),
            bbox: params.string("bbox"),
            bounding_polygon: params
                .all("boundingPolygon")
                .into_iter()
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(","),
            path: params.string("path"),
            classification: params.string("classification"),
            expiration: expiration.unwrap_or(-1),
        },
        tool: params
            .get("tool")
            .filter(|t| !t.is_empty())
            .unwrap_or("public")
            .to_string(),
        password: params.get("password").map(String::from),
        default_role: params.role("defaultRole")?,
        expiration_given: expiration.is_some(),
        invite_only: params.bool("inviteOnly", false)?,
    };
    let is_json = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("application/json"));
    if is_json && !body.is_empty() {
        let mission: Value = serde_json::from_slice(body)
            .map_err(|_| ApiError::BadRequest("exception parsing mission json!".into()))?;
        let s = |k: &str| mission.get(k).and_then(|v| v.as_str()).map(String::from);
        let f = &mut request.fields;
        if let Some(v) = s("description") {
            f.description = v;
        }
        if let Some(v) = s("chatRoom") {
            f.chat_room = v;
        }
        if let Some(v) = s("baseLayer") {
            f.base_layer = v;
        }
        if let Some(v) = s("bbox") {
            f.bbox = v;
        }
        if let Some(v) = s("boundingPolygon") {
            f.bounding_polygon = v;
        }
        if let Some(v) = s("path") {
            f.path = v;
        }
        if let Some(v) = s("classification") {
            f.classification = v;
        }
        if let Some(v) = s("tool") {
            request.tool = v;
        }
        if let Some(v) = mission
            .get("defaultRole")
            .and_then(|r| r.get("type"))
            .and_then(|t| t.as_str())
        {
            request.default_role =
                Some(Role::parse(v).ok_or_else(|| {
                    ApiError::BadRequest("exception parsing mission json!".into())
                })?);
        }
        if let Some(v) = mission.get("expiration").and_then(|v| v.as_i64()) {
            f.expiration = v;
            request.expiration_given = true;
        }
        if let Some(groups) = mission.get("groups").and_then(|g| g.as_array()) {
            request.groups = groups
                .iter()
                .filter_map(|g| g.as_str().map(String::from))
                .collect();
        }
        if let Some(v) = mission.get("inviteOnly").and_then(|v| v.as_bool()) {
            request.invite_only = v;
        }
    }
    Ok(request)
}

/// The mission's groups for a request: `__ANON__` alone means the caller's
/// own; otherwise they must exist and be a subset of the caller's.
fn mission_groups(
    state: &MissionsState,
    caller: &Caller,
    requested: &[String],
) -> Result<BTreeSet<String>, ApiError> {
    if caller.groups.is_empty() && !caller.admin {
        return Err(ApiError::Forbidden("Missing groups for user!".into()));
    }
    if requested.len() == 1
        && requested[0] == crate::groups::ANON_GROUP
        && !caller.groups.contains(crate::groups::ANON_GROUP)
    {
        return Ok(caller.groups.clone());
    }
    let requested: BTreeSet<String> = requested
        .iter()
        .filter(|g| state.groups.exists(g) || g.as_str() == crate::groups::ANON_GROUP)
        .cloned()
        .collect();
    if requested.is_empty() {
        return Err(ApiError::Forbidden("Missing groups for mission!".into()));
    }
    if !caller.admin && !requested.is_subset(&caller.groups) {
        return Err(ApiError::Forbidden(
            "Illegal attempt to set groupVector for Mission!".into(),
        ));
    }
    Ok(requested)
}

/// `doCreateMissionAllowDupe`'s `allowDupe` / `allowDupeInDifferentGroups`.
struct Dupe {
    allow: bool,
    in_different_groups: bool,
}

async fn create_impl(
    state: MissionsState,
    caller: Caller,
    name: String,
    params: Params,
    headers: HeaderMap,
    body: Bytes,
    dupe: Dupe,
) -> ApiResult {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::BadRequest("empty 'name' path parameter".into()));
    }
    let request = parse_create(&params, &headers, &body)?;
    let groups = mission_groups(&state, &caller, &request.groups)?;
    let existing = lookup(&state, &caller, Key::Name(&name), true)?;
    let now = now_ms();
    match existing {
        Some(mission) if !(dupe.allow && dupe.in_different_groups) => update_existing(
            &state,
            &caller,
            mission,
            request,
            groups,
            params.bool("allowGroupChange", false)?,
            now,
        ),
        _ => {
            let password_hash = match request.password.as_deref().filter(|p| !p.is_empty()) {
                Some(p) => Some(hash_password(p)?),
                None => None,
            };
            let mission = state.store.create(
                NewMission {
                    guid: random_uuid(),
                    name,
                    fields: request.fields,
                    tool: request.tool,
                    creator_uid: request.creator_uid.clone(),
                    groups,
                    password_hash,
                    default_role: request.default_role,
                    invite_only: request.invite_only,
                },
                now,
            )?;
            let tokens = Arc::clone(&state.tokens);
            let (mname, mguid) = (mission.name.clone(), mission.guid.clone());
            let owner = state.store.subscribe(
                &mission.guid,
                &request.creator_uid,
                &caller.username,
                Role::Owner,
                now,
                |id| tokens.create(id, TokenType::Subscription, &mname, &mguid, now / 1000),
            )?;
            let extras = MissionExtras {
                token: Some(owner.token),
                owner_role: Some(Role::Owner),
                details: true,
                ..Default::default()
            };
            let json = mission_json(&state, &mission, &groups_seen(&caller, &mission), extras);
            // `missionSubscribe` also makes the creator a live subscriber.
            state.notifier.connect(&mission.guid, &request.creator_uid);
            state
                .notifier
                .broadcast(&mission, Announcement::Create, &request.creator_uid);
            created("Mission", json!([json]))
        }
    }
}

fn update_existing(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    request: CreateRequest,
    groups: BTreeSet<String>,
    allow_group_change: bool,
    now: i64,
) -> ApiResult {
    let role = role_for(state, &mission, caller);
    if groups != mission.groups {
        let may = caller.admin || role == Some(Role::Owner);
        if !(may && allow_group_change) {
            return Err(ApiError::Forbidden(
                "Illegal attempt to change Mission groups!".into(),
            ));
        }
    }
    if !role.is_some_and(|r| r.has(Permission::MissionWrite)) {
        return Err(ApiError::Forbidden(
            "Illegal attempt to update mission!".into(),
        ));
    }
    let mut fields = request.fields.clone();
    if !request.expiration_given {
        fields.expiration = -1;
    }
    if fields != mission.fields {
        state.store.set_fields(&mission.guid, fields, now)?;
    }
    if let Some(password) = request.password.as_deref().filter(|p| !p.is_empty()) {
        if !role.is_some_and(|r| r.has(Permission::MissionSetPassword)) {
            return Err(ApiError::Forbidden(
                "Illegal attempt to update mission password!".into(),
            ));
        }
        state
            .store
            .set_password(&mission.guid, Some(hash_password(password)?), now)?;
    }
    if let Some(default_role) = request.default_role
        && mission.default_role != Some(default_role)
    {
        let token_role = if caller.admin {
            Some(Role::Owner)
        } else {
            role_from_token(state, &mission, caller, &[TokenType::Subscription])
        };
        let Some(token_role) = token_role else {
            return Err(ApiError::Forbidden(
                "Could not extract role from token to set mission default role!".into(),
            ));
        };
        if !token_role.has(Permission::MissionSetRole) {
            return Err(ApiError::Forbidden(
                "Illegal attempt to update default mission role with insufficient permissions!"
                    .into(),
            ));
        }
        if !token_role.has_all(default_role) {
            return Err(ApiError::Forbidden(
                "Illegal attempt to update default mission role beyond current permissions!".into(),
            ));
        }
        state
            .store
            .set_default_role(&mission.guid, Some(default_role), now)?;
    }
    if groups != mission.groups && role.is_some_and(|r| r.has(Permission::MissionUpdateGroups)) {
        state.store.set_groups(&mission.guid, groups, now)?;
    }
    let updated = state
        .store
        .by_guid(&mission.guid)
        .ok_or(ApiError::Internal)?;
    if updated.fields != mission.fields
        || updated.password_hash != mission.password_hash
        || updated.default_role != mission.default_role
        || updated.groups != mission.groups
    {
        state
            .notifier
            .broadcast(&updated, Announcement::Metadata, &request.creator_uid);
    }
    let json = mission_json(
        state,
        &updated,
        &updated.groups,
        MissionExtras {
            details: true,
            ..Default::default()
        },
    );
    ok("Mission", json!([json]))
}

async fn create_mission_put(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    create_impl(
        state,
        caller,
        name,
        Params::parse(query)?,
        headers,
        body,
        Dupe {
            allow: false,
            in_different_groups: false,
        },
    )
    .await
}

async fn create_mission_post(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let params = Params::parse(query)?;
    let allow_dupe = params.bool("allowDupe", false)?;
    create_impl(
        state,
        caller,
        name,
        params,
        headers,
        body,
        Dupe {
            allow: allow_dupe,
            in_different_groups: true,
        },
    )
    .await
}

fn delete_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    let role = role_for(state, &mission, caller);
    require(role, Permission::MissionWrite)?;
    if params.bool("deepDelete", false)? && !role.is_some_and(|r| r.has(Permission::MissionDelete))
    {
        return Err(ApiError::Forbidden(format!(
            "Attempt to deepDelete mission: {}, by unauthorized user: {}",
            mission.name,
            params.string("creatorUid")
        )));
    }
    let deleted = state
        .store
        .delete(&mission.guid, &params.string("creatorUid"), now_ms())?;
    state
        .notifier
        .broadcast(&deleted, Announcement::Delete, &params.string("creatorUid"));
    let json = mission_json(
        state,
        &deleted,
        &groups_seen(caller, &deleted),
        MissionExtras::default(),
    );
    ok("Mission", json!([json]))
}

async fn delete_mission_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    delete_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn delete_mission_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let params = Params::parse(query)?;
    let guid = params.string("guid");
    if guid.is_empty() {
        return Err(ApiError::BadRequest("empty 'guid' path parameter".into()));
    }
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    delete_impl(&state, &caller, mission, &params)
}

// --- contents -----------------------------------------------------------------------

fn add_contents_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
    body: &Bytes,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let content: Value =
        serde_json::from_slice(body).map_err(|_| ApiError::BadRequest(String::new()))?;
    let list = |k: &str| -> Vec<String> {
        content
            .get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (hashes, uids) = (list("hashes"), list("uids"));
    let has_paths = content
        .get("paths")
        .and_then(|p| p.as_object())
        .is_some_and(|p| !p.is_empty());
    if hashes.is_empty() && uids.is_empty() && !has_paths {
        return Err(ApiError::BadRequest(
            "at least one hash or uid must be provided in request".into(),
        ));
    }
    let creator = params.string("creatorUid");
    let now = now_ms();
    let mut added = 0;
    for hash in hashes {
        // `getCachedResourcesByHash`: unknown hashes are skipped.
        if !state.resources.by_hash(&hash, None).is_empty() {
            state
                .store
                .add_content(&mission.guid, Content::Hash(hash), &creator, now)?;
            added += 1;
        }
    }
    for uid in uids {
        state
            .store
            .add_content(&mission.guid, Content::Uid(uid), &creator, now)?;
        added += 1;
    }
    announce_latest_changes(state, &mission, added, &creator)?;
    // `paths`: each item is also filed as an ITEM layer under the path's
    // layer, chained by `after` (`addMissionContentImpl`).
    if let Some(paths) = content.get("paths").and_then(|p| p.as_object()) {
        for (path, contents) in paths {
            for item in contents.as_array().into_iter().flatten() {
                let list = |k: &str| -> Vec<String> {
                    item.get(k)
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let mut after = item.get("after").and_then(|a| a.as_str()).map(String::from);
                let mut filed = Vec::new();
                for hash in list("hashes") {
                    if !state.resources.by_hash(&hash, None).is_empty() {
                        filed.push(Content::Hash(hash));
                    }
                }
                filed.extend(list("uids").into_iter().map(Content::Uid));
                for content in filed {
                    state
                        .store
                        .add_content(&mission.guid, content.clone(), &creator, now)?;
                    announce_latest_changes(state, &mission, 1, &creator)?;
                    let uid = match &content {
                        Content::Hash(h) | Content::Uid(h) => h.clone(),
                    };
                    add_layer(
                        state,
                        &mission,
                        Some(uid.clone()),
                        None,
                        LayerType::Item,
                        Some(path.clone()),
                        after.clone(),
                        &creator,
                    )?;
                    after = Some(uid);
                }
            }
        }
    }
    let updated = state
        .store
        .by_guid(&mission.guid)
        .ok_or(ApiError::Internal)?;
    // The official response copies the mission and clears its groups.
    let json = mission_json(state, &updated, &BTreeSet::new(), MissionExtras::default());
    ok("Mission", json!([json]))
}

async fn add_contents_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    add_contents_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn add_contents_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    add_contents_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

fn remove_content_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let creator = params.string("creatorUid");
    let now = now_ms();
    let mut removed = 0;
    if let Some(hash) = params.get("hash").filter(|h| !h.is_empty()) {
        state.store.remove_content(
            &mission.guid,
            Content::Hash(hash.to_string()),
            &creator,
            now,
        )?;
        removed += 1;
    }
    if let Some(uid) = params.get("uid").filter(|u| !u.is_empty()) {
        state
            .store
            .remove_content(&mission.guid, Content::Uid(uid.to_string()), &creator, now)?;
        removed += 1;
    }
    let updated = state
        .store
        .by_guid(&mission.guid)
        .ok_or(ApiError::Internal)?;
    announce_latest_changes(state, &updated, removed, &creator)?;
    let json = mission_json(
        state,
        &updated,
        &groups_seen(caller, &updated),
        MissionExtras::default(),
    );
    ok("Mission", json!([json]))
}

async fn remove_content_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    remove_content_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn remove_content_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    remove_content_impl(&state, &caller, mission, &Params::parse(query)?)
}

// --- mission map layers ------------------------------------------------------

/// `MapLayer` bean properties and their JSON types.
const MAP_LAYER_INTS: &[&str] = &["maxZoom", "minZoom", "opacity"];
const MAP_LAYER_DOUBLES: &[&str] = &["east", "north", "south", "west"];
const MAP_LAYER_STRINGS: &[&str] = &[
    "additionalParameters",
    "after",
    "backgroundColor",
    "coordinateSystem",
    "creatorUid",
    "description",
    "layers",
    "name",
    "path",
    "serverParts",
    "tileType",
    "tileUpdate",
    "type",
    "url",
    "version",
];
const MAP_LAYER_BOOLS: &[&str] = &[
    "defaultLayer",
    "enabled",
    "ignoreErrors",
    "invertYCoordinate",
];

/// A `MapLayer` as Jackson binds the request body: unknown and `null`
/// properties left out, `type` defaulting to `MapTile`, booleans `false`.
fn map_layer_props(v: &Value) -> BTreeMap<String, Value> {
    let mut props = BTreeMap::new();
    props.insert("type".to_string(), Value::from("MapTile"));
    for k in MAP_LAYER_BOOLS {
        props.insert(
            k.to_string(),
            Value::Bool(v.get(*k).and_then(|b| b.as_bool()).unwrap_or(false)),
        );
    }
    for (k, val) in v.as_object().into_iter().flatten() {
        let k = k.as_str();
        if val.is_null() {
            if MAP_LAYER_STRINGS.contains(&k)
                || MAP_LAYER_INTS.contains(&k)
                || MAP_LAYER_DOUBLES.contains(&k)
            {
                props.remove(k);
            }
            continue;
        }
        if MAP_LAYER_STRINGS.contains(&k) {
            let s = val
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| val.to_string());
            props.insert(k.into(), Value::from(s));
        } else if MAP_LAYER_INTS.contains(&k)
            && let Some(n) = val.as_i64().or_else(|| val.as_f64().map(|f| f as i64))
        {
            props.insert(k.into(), n.into());
        } else if MAP_LAYER_DOUBLES.contains(&k)
            && let Some(f) = val.as_f64()
        {
            props.insert(k.into(), json!(f));
        }
    }
    props
}

/// JAXB's `java.util.Date`: `yyyy-MM-ddTHH:mm:ss[.SSS]Z`, no fraction at 0 ms.
fn jaxb_date(ms: i64) -> String {
    let full = pad_millis(ms);
    if ms.rem_euclid(1000) == 0 {
        format!("{}Z", &full[..19])
    } else {
        full
    }
}

fn map_layer_json(l: &crate::missions::MapLayerRecord) -> Value {
    let mut out: serde_json::Map<String, Value> = l.props.clone().into_iter().collect();
    out.insert("uid".into(), l.uid.clone().into());
    out.insert(
        "createTime".into(),
        cot_date_millis(l.create_time_ms).into(),
    );
    out.insert(
        "modifiedTime".into(),
        cot_date_millis(l.modified_time_ms).into(),
    );
    Value::Object(out)
}

/// `findMapLayer`'s placeholder: `new MapLayer()` with only the uid.
fn map_layer_placeholder(uid: &str) -> BTreeMap<String, Value> {
    let mut props = BTreeMap::new();
    props.insert("uid".to_string(), Value::from(uid));
    props.insert("type".to_string(), Value::from("MapTile"));
    for k in MAP_LAYER_BOOLS {
        props.insert(k.to_string(), Value::Bool(false));
    }
    props
}

/// `<mapLayer>` as JAXB writes a `MapLayer`: properties in name order.
fn map_layer_xml(l: Option<&crate::missions::MapLayerRecord>, uid: &str) -> String {
    let mut props: BTreeMap<String, String> = BTreeMap::new();
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => format!("{:?}", n.as_f64().unwrap_or(0.0)),
        other => other.to_string(),
    };
    match l {
        Some(l) => {
            for (k, v) in &l.props {
                props.insert(k.clone(), text(v));
            }
            props.insert("uid".into(), l.uid.clone());
            props.insert("createTime".into(), jaxb_date(l.create_time_ms));
            props.insert("modifiedTime".into(), jaxb_date(l.modified_time_ms));
        }
        None => {
            for (k, v) in map_layer_placeholder(uid) {
                props.insert(k, text(&v));
            }
        }
    }
    let inner: String = props
        .iter()
        .map(|(k, v)| format!("<{k}>{}</{k}>", super::mission_notify::escape(v)))
        .collect();
    format!("<mapLayer>{inner}</mapLayer>")
}

fn add_map_layer_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
    body: &Bytes,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let creator = params
        .get("creatorUid")
        .ok_or_else(|| ApiError::BadRequest(String::new()))?
        .to_string();
    let v: Value = serde_json::from_slice(body).map_err(|_| ApiError::InvalidBody)?;
    let props = map_layer_props(&v);
    // name, type and url are NOT NULL: the save fails (TakException).
    if ["name", "type", "url"]
        .iter()
        .any(|k| !props.contains_key(*k))
    {
        return Err(ApiError::Internal);
    }
    let now = now_ms();
    let layer = crate::missions::MapLayerRecord {
        uid: random_uuid().replace('-', ""),
        mission_guid: mission.guid.clone(),
        create_time_ms: now,
        modified_time_ms: now,
        props,
    };
    let change = state
        .store
        .add_map_layer(&mission.guid, layer.clone(), &creator)?;
    let layer_xml = map_layer_xml(Some(&layer), &layer.uid);
    let xml = state
        .notifier
        .change_xml_with(&change, None, Some(&layer_xml));
    state
        .notifier
        .announce(&mission, ChangeKind::Content, &creator, Some(&xml));
    ok("MapLayer", map_layer_json(&layer))
}

/// `MapLayerService.updateMapLayer`: creatorUid, name, description, type,
/// url, defaultLayer and enabled; an unknown uid is a TakException (500).
fn update_map_layer_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
    body: &Bytes,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    params
        .get("creatorUid")
        .ok_or_else(|| ApiError::BadRequest(String::new()))?;
    let v: Value = serde_json::from_slice(body).map_err(|_| ApiError::InvalidBody)?;
    let uid = v.get("uid").and_then(|u| u.as_str()).unwrap_or("");
    let mut record = state.store.map_layer(uid).ok_or(ApiError::Internal)?;
    let given = map_layer_props(&v);
    for k in [
        "creatorUid",
        "name",
        "description",
        "type",
        "url",
        "defaultLayer",
        "enabled",
    ] {
        match given.get(k) {
            Some(val) => record.props.insert(k.into(), val.clone()),
            None => record.props.remove(k),
        };
    }
    if ["name", "type", "url"]
        .iter()
        .any(|k| !record.props.contains_key(*k))
    {
        return Err(ApiError::Internal);
    }
    record.modified_time_ms = now_ms();
    state.store.update_map_layer(record.clone())?;
    let current = state.store.map_layer(uid).unwrap_or(record);
    ok("MapLayer", map_layer_json(&current))
}

async fn add_map_layer_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    add_map_layer_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn add_map_layer_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    add_map_layer_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn update_map_layer_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    update_map_layer_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn update_map_layer_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    update_map_layer_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

// --- external mission data ---------------------------------------------------

/// `ExternalMissionData` JSON (`@JsonInclude(NON_NULL)`).
fn external_json(e: &crate::missions::ExternalDataRecord) -> Value {
    json!({ "uid": e.id, "name": e.name, "tool": e.tool, "urlData": e.url_data, "urlView": e.url_display, "notes": e.notes })
}

/// `hydrate(externalDataUid, …)`: the change's fields, the current record's
/// URLs (none once it is gone), `?token=` appended for a change notice.
fn external_change_json(
    record: Option<&crate::missions::ExternalDataRecord>,
    c: &crate::missions::ExternalDataChange,
) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("uid".into(), c.uid.clone().into());
    out.insert("name".into(), c.name.clone().into());
    out.insert("tool".into(), c.tool.clone().into());
    if let Some(r) = record {
        let token = c
            .token
            .as_ref()
            .map(|t| format!("?token={t}"))
            .unwrap_or_default();
        out.insert("urlData".into(), format!("{}{token}", r.url_data).into());
        out.insert("urlView".into(), format!("{}{token}", r.url_display).into());
    }
    if let Some(notes) = &c.notes {
        out.insert("notes".into(), notes.clone().into());
    }
    Value::Object(out)
}

fn announce_external(
    state: &MissionsState,
    mission: &MissionRecord,
    change: &ChangeRecord,
    record: Option<&crate::missions::ExternalDataRecord>,
    creator: &str,
) {
    let ext = change
        .external_data
        .as_ref()
        .map(|c| external_change_json(record, c));
    let xml = state.notifier.change_xml_with(change, ext.as_ref(), None);
    state
        .notifier
        .announce(mission, ChangeKind::ExternalData, creator, Some(&xml));
}

fn set_external_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
    body: &Bytes,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let creator = params
        .get("creatorUid")
        .ok_or_else(|| ApiError::BadRequest(String::new()))?
        .to_string();
    let v: Value = serde_json::from_slice(body).map_err(|_| ApiError::InvalidBody)?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    if s("uid").is_empty() {
        return Err(ApiError::BadRequest(
            "ExternalMissionData id must be included".into(),
        ));
    }
    let record = crate::missions::ExternalDataRecord {
        id: s("uid"),
        name: s("name"),
        tool: s("tool"),
        url_data: s("urlData"),
        url_display: s("urlView"),
        notes: s("notes"),
        mission_guid: mission.guid.clone(),
    };
    let change =
        state
            .store
            .set_external_data(&mission.guid, record.clone(), &creator, now_ms())?;
    announce_external(state, &mission, &change, Some(&record), &creator);
    let mut response = ok(
        "com.bbn.marti.sync.model.ExternalMissionData",
        external_json(&record),
    )?;
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

/// Delete (`remove`) or change notice: the record by id, whichever mission
/// holds it; the change is recorded on this mission.
fn external_change_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    id: &str,
    params: &Params,
    action: crate::missions::ExternalDataAction,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let creator = params
        .get("creatorUid")
        .ok_or_else(|| ApiError::BadRequest(String::new()))?
        .to_string();
    let notes = params
        .get("notes")
        .ok_or_else(|| ApiError::BadRequest(String::new()))?
        .to_string();
    // Hydrated before the delete, as the official change is.
    let record = state.store.external_data(id);
    let change = state
        .store
        .external_data_change(&mission.guid, id, action, &notes, &creator, now_ms())?
        .ok_or_else(|| ApiError::NotFound(format!("externalMissionDataId {id} not found")))?;
    announce_external(state, &mission, &change, record.as_ref(), &creator);
    Ok(StatusCode::OK.into_response())
}

async fn set_external_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    set_external_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn set_external_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    set_external_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn delete_external_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    external_change_impl(
        &state,
        &caller,
        mission,
        &id,
        &Params::parse(query)?,
        crate::missions::ExternalDataAction::Delete,
    )
}

async fn delete_external_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((guid, id)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    external_change_impl(
        &state,
        &caller,
        mission,
        &id,
        &Params::parse(query)?,
        crate::missions::ExternalDataAction::Delete,
    )
}

async fn notify_external_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, id)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: String,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    external_change_impl(
        &state,
        &caller,
        mission,
        &id,
        &Params::parse(query)?,
        crate::missions::ExternalDataAction::Changed { token: body },
    )
}

async fn notify_external_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((guid, id)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: String,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    external_change_impl(
        &state,
        &caller,
        mission,
        &id,
        &Params::parse(query)?,
        crate::missions::ExternalDataAction::Changed { token: body },
    )
}

/// Announces the mission's `count` newest changes, oldest first.
fn announce_latest_changes(
    state: &MissionsState,
    mission: &MissionRecord,
    count: usize,
    creator: &str,
) -> Result<(), ApiError> {
    if count == 0 {
        return Ok(());
    }
    let mut latest: Vec<ChangeRecord> = state
        .store
        .changes(&mission.guid, Window::ALL, false)?
        .into_iter()
        .take(count)
        .collect();
    latest.reverse();
    state.notifier.announce_content(mission, &latest, creator);
    Ok(())
}

// --- changes ------------------------------------------------------------------------

fn changes_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let changes = state.store.changes(
        &mission.guid,
        params.window()?,
        params.bool("squashed", true)?,
    )?;
    ok(
        "MissionChange",
        changes.iter().map(|c| change_json(state, c)).collect(),
    )
}

async fn changes_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    changes_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn changes_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    changes_impl(&state, &caller, mission, &Params::parse(query)?)
}

// --- keywords -------------------------------------------------------------------------

fn keyword_list(body: &Bytes) -> Result<Vec<String>, ApiError> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice::<Vec<String>>(body).map_err(|_| ApiError::InvalidBody)
}

fn writable_by_name(
    state: &MissionsState,
    identity: &PeerIdentity,
    headers: &HeaderMap,
    name: &str,
) -> Result<(Caller, MissionRecord), ApiError> {
    let caller = caller(state, identity, headers);
    let mission = existing(state, &caller, Key::Name(name))?;
    require(role_for(state, &mission, &caller), Permission::MissionWrite)?;
    Ok((caller, mission))
}

fn mission_response(state: &MissionsState, caller: &Caller, guid: &str) -> ApiResult {
    let m = state.store.by_guid(guid).ok_or(ApiError::Internal)?;
    let json = mission_json(
        state,
        &m,
        &groups_seen(caller, &m),
        MissionExtras::default(),
    );
    ok("Mission", json!([json]))
}

async fn set_keywords(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let (caller, mission) = writable_by_name(&state, &identity, &headers, &name)?;
    state.store.set_keywords(
        &mission.guid,
        keyword_list(&body)?.into_iter().collect(),
        now_ms(),
    )?;
    state.notifier.broadcast(
        &mission,
        Announcement::Keyword,
        &Params::parse(query)?.string("creatorUid"),
    );
    mission_response(&state, &caller, &mission.guid)
}

async fn clear_keywords(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let (caller, mission) = writable_by_name(&state, &identity, &headers, &name)?;
    state
        .store
        .set_keywords(&mission.guid, BTreeSet::new(), now_ms())?;
    state.notifier.broadcast(
        &mission,
        Announcement::Keyword,
        &Params::parse(query)?.string("creatorUid"),
    );
    mission_response(&state, &caller, &mission.guid)
}

async fn remove_keyword(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, keyword)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let (caller, mission) = writable_by_name(&state, &identity, &headers, &name)?;
    let mut keywords = mission.keywords.clone();
    if !keywords.remove(&keyword) {
        return Err(ApiError::BadRequest(format!(
            "mission '{name}' did not contain keyword {keyword}"
        )));
    }
    state
        .store
        .set_keywords(&mission.guid, keywords, now_ms())?;
    state.notifier.broadcast(
        &mission,
        Announcement::Keyword,
        &Params::parse(query)?.string("creatorUid"),
    );
    mission_response(&state, &caller, &mission.guid)
}

/// The change XML of `addUidKeyword` / `addContentKeyword` (as dom4j
/// re-serializes it into the notification); `None` keywords = cleared.
fn content_keywords_xml(content: &Content, keywords: Option<&[String]>) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('"', "&quot;")
    };
    match (content, keywords) {
        (Content::Uid(uid), Some(k)) => format!(
            r#"<uidKeywords uid="{}">{}</uidKeywords>"#,
            esc(uid),
            k.iter()
                .map(|k| format!(r#"<uidKeyword keyword="{}"/>"#, esc(k)))
                .collect::<String>()
        ),
        (Content::Uid(uid), None) => format!(r#"<uidKeywords uid="{}"/>"#, esc(uid)),
        (Content::Hash(hash), Some(k)) => format!(
            r#"<contentKeywords hash="{}">{}</contentKeywords>"#,
            esc(hash),
            k.iter()
                .map(|k| format!(r#"<contentKeyword keyword="{}"/>"#, esc(k)))
                .collect::<String>()
        ),
        (Content::Hash(_), None) => "<contentKeywords/>".to_string(),
    }
}

fn content_keyword_kind(content: &Content) -> ChangeKind {
    match content {
        Content::Uid(_) => ChangeKind::UidKeyword,
        Content::Hash(_) => ChangeKind::ResourceKeyword,
    }
}

async fn set_content_keywords_impl(
    state: MissionsState,
    identity: PeerIdentity,
    headers: HeaderMap,
    name: String,
    content: Content,
    query: Option<String>,
    body: Bytes,
) -> ApiResult {
    let (_, mission) = writable_by_name(&state, &identity, &headers, &name)?;
    let keywords = keyword_list(&body)?;
    if keywords.is_empty() {
        return Err(ApiError::BadRequest("empty keywords array".into()));
    }
    state
        .store
        .set_content_keywords(&mission.guid, content.clone(), keywords.clone())?;
    let xml = content_keywords_xml(&content, Some(&keywords));
    state.notifier.announce(
        &mission,
        content_keyword_kind(&content),
        &Params::parse(query)?.string("creatorUid"),
        Some(&xml),
    );
    Ok(StatusCode::OK.into_response())
}

async fn clear_content_keywords_impl(
    state: MissionsState,
    identity: PeerIdentity,
    headers: HeaderMap,
    name: String,
    content: Content,
    query: Option<String>,
) -> ApiResult {
    let (_, mission) = writable_by_name(&state, &identity, &headers, &name)?;
    state
        .store
        .set_content_keywords(&mission.guid, content.clone(), Vec::new())?;
    let xml = content_keywords_xml(&content, None);
    state.notifier.announce(
        &mission,
        content_keyword_kind(&content),
        &Params::parse(query)?.string("creatorUid"),
        Some(&xml),
    );
    Ok(StatusCode::OK.into_response())
}

async fn set_uid_keywords(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, uid)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    set_content_keywords_impl(
        state,
        identity,
        headers,
        name,
        Content::Uid(uid),
        query,
        body,
    )
    .await
}

async fn set_hash_keywords(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, hash)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    set_content_keywords_impl(
        state,
        identity,
        headers,
        name,
        Content::Hash(hash),
        query,
        body,
    )
    .await
}

async fn clear_uid_keywords(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, uid)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    clear_content_keywords_impl(state, identity, headers, name, Content::Uid(uid), query).await
}

async fn clear_hash_keywords(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, hash)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    clear_content_keywords_impl(state, identity, headers, name, Content::Hash(hash), query).await
}

// --- layers ----------------------------------------------------------------------------------

/// `addMissionLayer`: an existing uid is moved instead; a new layer is
/// inserted after `after` under `parent` (stored as given) and announced.
#[allow(clippy::too_many_arguments)]
fn add_layer(
    state: &MissionsState,
    mission: &MissionRecord,
    uid: Option<String>,
    name: Option<String>,
    layer_type: LayerType,
    parent: Option<String>,
    after: Option<String>,
    creator: &str,
) -> Result<Value, ApiError> {
    if let Some(uid) = &uid
        && let Some(existing) = state.store.layer(&mission.guid, uid)
    {
        move_layer(
            state,
            mission,
            uid,
            parent.as_deref(),
            after.as_deref(),
            creator,
        )?;
        return Ok(layer_json(
            &existing,
            state
                .store
                .layer(&mission.guid, existing.parent.as_deref().unwrap_or(""))
                .map(|p| p.uid),
        ));
    }
    let layer = LayerRecord {
        uid: uid.unwrap_or_else(random_uuid),
        name,
        layer_type,
        parent: parent.clone(),
        after,
    };
    state.store.add_layer(&mission.guid, layer.clone())?;
    // The announced object's parent is the parent *found* (null if none).
    let found_parent = parent
        .as_deref()
        .and_then(|p| state.store.layer(&mission.guid, p))
        .map(|p| p.uid);
    let xml = MissionNotifier::layer_xml(&layer, found_parent.as_deref());
    state
        .notifier
        .announce(mission, ChangeKind::MissionLayer, creator, Some(&xml));
    Ok(layer_json(&layer, found_parent))
}

/// `setLayerParent`: 404 if the layer, or a given parent, doesn't exist.
fn move_layer(
    state: &MissionsState,
    mission: &MissionRecord,
    uid: &str,
    parent: Option<&str>,
    after: Option<&str>,
    creator: &str,
) -> Result<(), ApiError> {
    let Some(layer) = state.store.layer(&mission.guid, uid) else {
        return Err(ApiError::NotFound(String::new()));
    };
    if let Some(parent) = parent
        && state.store.layer(&mission.guid, parent).is_none()
    {
        return Err(ApiError::NotFound(String::new()));
    }
    state.store.move_layer(&mission.guid, uid, parent, after)?;
    let updated = LayerRecord {
        parent: parent.map(String::from),
        after: after.map(String::from),
        ..layer
    };
    let xml = MissionNotifier::layer_xml(&updated, parent);
    state
        .notifier
        .announce(mission, ChangeKind::MissionLayer, creator, Some(&xml));
    Ok(())
}

/// `MissionLayer` JSON (`NON_EMPTY`) without children or content.
fn layer_json(layer: &LayerRecord, parent_uid: Option<String>) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("uid".into(), layer.uid.clone().into());
    if let Some(name) = layer.name.as_ref().filter(|n| !n.is_empty()) {
        out.insert("name".into(), name.clone().into());
    }
    out.insert("type".into(), layer.layer_type.name().into());
    if let Some(parent) = parent_uid {
        out.insert("parentUid".into(), parent.into());
    }
    Value::Object(out)
}

/// `hydrateMissionLayers`: each level as `MissionLayer` JSON; ITEM children
/// are folded into their UID / CONTENTS parent's `uids` / `contents` (and
/// dropped from `mission_layers`) wherever they have a parent.
fn hydrated_layers(
    state: &MissionsState,
    mission: &MissionRecord,
    trees: &[LayerTree],
    parent: Option<&LayerTree>,
) -> Vec<Value> {
    let adds = mission_json(
        state,
        mission,
        &BTreeSet::new(),
        MissionExtras {
            details: true,
            ..Default::default()
        },
    );
    hydrate_level(&adds, trees, parent)
}

fn hydrate_level(adds: &Value, trees: &[LayerTree], parent: Option<&LayerTree>) -> Vec<Value> {
    trees
        .iter()
        .filter(|t| parent.is_none() || t.layer.layer_type != LayerType::Item)
        .map(|tree| {
            let mut json = layer_json(
                &tree.layer,
                tree.layer.parent.clone().filter(|_| parent.is_some()),
            );
            let map = json.as_object_mut().expect("object");
            let items: Vec<&LayerTree> = tree
                .children
                .iter()
                .filter(|c| c.layer.layer_type == LayerType::Item)
                .collect();
            let pick = |key: &str, id: &dyn Fn(&Value) -> Option<String>| -> Vec<Value> {
                items
                    .iter()
                    .filter_map(|item| {
                        adds[key]
                            .as_array()?
                            .iter()
                            .find(|a| id(a).as_deref() == Some(item.layer.uid.as_str()))
                            .cloned()
                    })
                    .collect()
            };
            match tree.layer.layer_type {
                LayerType::Uid => {
                    let uids = pick("uids", &|a| a["data"].as_str().map(String::from));
                    if !uids.is_empty() {
                        map.insert("uids".into(), uids.into());
                    }
                }
                LayerType::Contents => {
                    let contents = pick("contents", &|a| {
                        a["data"]["hash"].as_str().map(String::from)
                    });
                    if !contents.is_empty() {
                        map.insert("contents".into(), contents.into());
                    }
                }
                _ => {}
            }
            let children = hydrate_level(adds, &tree.children, Some(tree));
            if !children.is_empty() {
                map.insert("mission_layers".into(), children.into());
            }
            json
        })
        .collect()
}

fn layers_impl(state: &MissionsState, caller: &Caller, mission: MissionRecord) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let trees = state.store.layer_trees(&mission.guid);
    ok(
        "MissionLayer",
        hydrated_layers(state, &mission, &trees, None).into(),
    )
}

fn layer_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    uid: &str,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let tree = state
        .store
        .layer_tree(&mission.guid, uid)
        .ok_or_else(|| ApiError::NotFound(String::new()))?;
    let mut hydrated = hydrated_layers(state, &mission, std::slice::from_ref(&tree), None);
    let mut layer = hydrated.remove(0);
    if let Some(parent) = &tree.layer.parent {
        layer["parentUid"] = parent.clone().into();
    }
    ok("MissionLayer", layer)
}

fn required<'a>(params: &'a Params, name: &str) -> Result<&'a str, ApiError> {
    params.get(name).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "Required request parameter '{name}' is not present"
        ))
    })
}

fn create_layer_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let name = required(params, "name")?.to_string();
    let layer_type = required(params, "type")?;
    let layer_type = LayerType::parse(layer_type)
        .ok_or_else(|| ApiError::BadRequest(format!("invalid layer type '{layer_type}'")))?;
    let creator = required(params, "creatorUid")?.to_string();
    let opt = |k: &str| params.get(k).filter(|v| !v.is_empty()).map(String::from);
    let json = add_layer(
        state,
        &mission,
        opt("uid"),
        Some(name),
        layer_type,
        opt("parentUid"),
        opt("afterUid"),
        &creator,
    )?;
    ok("MissionLayer", json)
}

fn rename_layer_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    uid: &str,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let name = required(params, "name")?.to_string();
    let creator = required(params, "creatorUid")?.to_string();
    let layer = state
        .store
        .layer(&mission.guid, uid)
        .ok_or_else(|| ApiError::NotFound(String::new()))?;
    state.store.rename_layer(&mission.guid, uid, &name)?;
    let updated = LayerRecord {
        name: Some(name),
        ..layer
    };
    let parent = updated
        .parent
        .as_deref()
        .and_then(|p| state.store.layer(&mission.guid, p))
        .map(|p| p.uid);
    let xml = MissionNotifier::layer_xml(&updated, parent.as_deref());
    state
        .notifier
        .announce(&mission, ChangeKind::MissionLayer, &creator, Some(&xml));
    Ok(StatusCode::OK.into_response())
}

fn set_layer_parent_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let creator = required(params, "creatorUid")?.to_string();
    let layers = params.all("layerUid");
    if layers.is_empty() {
        return Err(ApiError::BadRequest(
            "Required request parameter 'layerUid' is not present".into(),
        ));
    }
    let parent = params
        .get("parentUid")
        .filter(|p| !p.is_empty())
        .map(String::from);
    let mut after = params
        .get("afterUid")
        .filter(|a| !a.is_empty())
        .map(String::from);
    for uid in layers {
        move_layer(
            state,
            &mission,
            &uid,
            parent.as_deref(),
            after.as_deref(),
            &creator,
        )?;
        after = Some(uid);
    }
    Ok(StatusCode::OK.into_response())
}

/// `removeMissionLayer`: the layer, its descendants, and the content filed
/// in it (removed from the mission); an unknown layer is ignored.
fn delete_layers_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionWrite)?;
    let creator = required(params, "creatorUid")?.to_string();
    let uids = params.all("uid");
    if uids.is_empty() {
        return Err(ApiError::BadRequest(
            "Required request parameter 'uid' is not present".into(),
        ));
    }
    for uid in uids {
        let Some(tree) = state.store.layer_tree(&mission.guid, &uid) else {
            continue;
        };
        remove_layer_tree(state, &mission, &tree, &creator)?;
        let xml = MissionNotifier::layer_xml(&tree.layer, tree.layer.parent.as_deref());
        state
            .notifier
            .announce(&mission, ChangeKind::MissionLayer, &creator, Some(&xml));
    }
    Ok(StatusCode::OK.into_response())
}

fn remove_layer_tree(
    state: &MissionsState,
    mission: &MissionRecord,
    tree: &LayerTree,
    creator: &str,
) -> Result<(), ApiError> {
    for child in &tree.children {
        remove_layer_tree(state, mission, child, creator)?;
    }
    let current = state
        .store
        .by_guid(&mission.guid)
        .ok_or(ApiError::Internal)?;
    let filed: Vec<Content> = tree
        .children
        .iter()
        .filter(|c| c.layer.layer_type == LayerType::Item)
        .filter_map(|c| match tree.layer.layer_type {
            LayerType::Uid => Some(Content::Uid(c.layer.uid.clone())),
            LayerType::Contents => Some(Content::Hash(c.layer.uid.clone())),
            _ => None,
        })
        .filter(|c| current.has(c))
        .collect();
    for content in filed {
        state
            .store
            .remove_content(&mission.guid, content, creator, now_ms())?;
        announce_latest_changes(state, mission, 1, creator)?;
    }
    state.store.delete_layer(&mission.guid, &tree.layer.uid)?;
    Ok(())
}

macro_rules! layer_handlers {
    ($by_name:ident, $by_guid:ident, $impl_fn:ident) => {
        async fn $by_name(
            State(state): State<MissionsState>,
            Extension(identity): Extension<PeerIdentity>,
            headers: HeaderMap,
            Path(name): Path<String>,
            RawQuery(query): RawQuery,
        ) -> ApiResult {
            let caller = caller(&state, &identity, &headers);
            let mission = existing(&state, &caller, Key::Name(&name))?;
            $impl_fn(&state, &caller, mission, &Params::parse(query)?)
        }

        async fn $by_guid(
            State(state): State<MissionsState>,
            Extension(identity): Extension<PeerIdentity>,
            headers: HeaderMap,
            Path(guid): Path<String>,
            RawQuery(query): RawQuery,
        ) -> ApiResult {
            let caller = caller(&state, &identity, &headers);
            let mission = existing(&state, &caller, Key::Guid(&guid))?;
            $impl_fn(&state, &caller, mission, &Params::parse(query)?)
        }
    };
}

fn layers_list_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    _params: &Params,
) -> ApiResult {
    layers_impl(state, caller, mission)
}

layer_handlers!(layers_by_name, layers_by_guid, layers_list_impl);
layer_handlers!(
    create_layer_by_name,
    create_layer_by_guid,
    create_layer_impl
);
layer_handlers!(
    delete_layers_by_name,
    delete_layers_by_guid,
    delete_layers_impl
);
layer_handlers!(
    set_layer_parent_by_name,
    set_layer_parent_by_guid,
    set_layer_parent_impl
);

async fn layer_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, layer)): Path<(String, String)>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    layer_impl(&state, &caller, mission, &layer)
}

async fn layer_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((guid, layer)): Path<(String, String)>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    layer_impl(&state, &caller, mission, &layer)
}

async fn rename_layer_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, layer)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    rename_layer_impl(&state, &caller, mission, &layer, &Params::parse(query)?)
}

async fn rename_layer_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((guid, layer)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    rename_layer_impl(&state, &caller, mission, &layer, &Params::parse(query)?)
}

// --- contacts ----------------------------------------------------------------------------------

/// `getMissionContacts`: the connected clients the mission's groups reach,
/// as a bare `RemoteSubscription` list (no envelope).
fn contacts_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    _params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let reachable =
        super::contacts::reachable(&state.clients, &state.groups, Some(&mission.groups));
    let list: Vec<Value> = reachable
        .iter()
        .map(|c| super::contacts::remote_subscription(c, &state.latest_cot))
        .collect();
    Ok(Json(list).into_response())
}

layer_handlers!(contacts_by_name, contacts_by_guid, contacts_impl);

// --- mission packages --------------------------------------------------------------------------

/// `getMissionArchive` (`archiveMission`): the mission as a data package --
/// the latest CoT of each uid under `cot/`, the files under `contents/`.
async fn archive_mission(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    use super::mission_package as mp;
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    require(role_for(&state, &mission, &caller), Permission::MissionRead)?;
    // `request.getServerName()`: the Host header without its port.
    let server_name = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            h.rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or(h)
                .to_string()
        })
        .unwrap_or_default();
    let mut files = Vec::new();
    for add in mission.uids() {
        if let Content::Uid(uid) = &add.content {
            // Unknown uids are skipped ("Unable to add cot to mission archive").
            if let Some(event) = state.latest_cot.get(uid) {
                files.push(mp::ArchiveFile {
                    zip_entry: format!("cot/{uid}.cot"),
                    bytes: event.xml.into_bytes(),
                    attributes: Vec::new(),
                    uid_parameter: Some(uid.clone()),
                });
            }
        }
    }
    let mut ndx = 0;
    for add in mission.hashes() {
        let Content::Hash(hash) = &add.content else {
            continue;
        };
        let Some(record) = state.resources.by_hash(hash, None).into_iter().next() else {
            continue;
        };
        let Ok(Some(bytes)) = state.content.get(hash) else {
            continue;
        };
        let resource = record.resource_json();
        let filename = match resource.get("name").and_then(|n| n.as_str()) {
            Some(name) => {
                let f = format!("{ndx}_{name}");
                ndx += 1;
                f
            }
            None => hash.clone(),
        };
        files.push(mp::ArchiveFile {
            zip_entry: format!("contents/{filename}"),
            bytes,
            attributes: mp::content_attributes(&resource),
            uid_parameter: None,
        });
    }
    let groups: Vec<String> = mission.groups.iter().cloned().collect();
    let role = mission.default_role.map(|r| {
        let permissions = r
            .permissions()
            .iter()
            .map(|p| {
                serde_json::to_value(p)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default()
            })
            .collect();
        (r.name(), permissions)
    });
    let manifest = mp::manifest_xml(
        &mp::archive_parameters(&mission, &server_name),
        &files,
        &groups,
        role,
    );
    let zip = mp::build_archive(&manifest, &files);
    let encoded: String = url_encode_form(&name);
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            // As the official handler writes it: the quote before `.zip`.
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{encoded}\".zip"),
            ),
        ],
        zip,
    )
        .into_response())
}

/// `URLEncoder` (form encoding, as ESAPI's `URLEncoder.DEFAULT.encode`).
fn url_encode_form(s: &str) -> String {
    serde_urlencoded::to_string([("", s)])
        .map(|e| e.trim_start_matches('=').to_string())
        .unwrap_or_default()
}

/// `addMissionPackage` without `changes.json`: CoT files become uid
/// content (and reach the live subscribers), other files become Enterprise
/// Sync resources in the mission. Answers the (empty) conflict list.
async fn add_mission_package(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    use super::mission_package as mp;
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    require(
        role_for(&state, &mission, &caller),
        Permission::MissionWrite,
    )?;
    let creator = required(&Params::parse(query)?, "creatorUid")?.to_string();
    let Ok(files) = mp::extract(&body) else {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            api_response("MissionChange", json!([])),
        )
            .into_response());
    };
    if files.iter().any(|(n, _)| n == "changes.json") {
        tracing::warn!(mission = %mission.name, "mission package with offline changes (changes.json) not supported yet");
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            api_response("MissionChange", json!([])),
        )
            .into_response());
    }
    for (filename, bytes) in files {
        if filename.to_lowercase().contains("manifest.xml") {
            continue;
        }
        let now = now_ms();
        if filename.ends_with(".cot") {
            let xml = String::from_utf8_lossy(&bytes).to_string();
            let Some(uid) = mp::cot_uid(&xml) else {
                continue;
            };
            let xml = mp::trim_bom(&xml).to_string();
            state.latest_cot.record(&uid, &xml, now);
            state
                .store
                .add_content(&mission.guid, Content::Uid(uid), &creator, now)?;
            announce_latest_changes(&state, &mission, 1, &creator)?;
            let start = xml.find("<event").unwrap_or(0);
            let subscribers: Vec<String> = state
                .notifier
                .live_subscribers(&mission.guid)
                .into_iter()
                .filter(|u| u != &creator)
                .collect();
            if !subscribers.is_empty() {
                state
                    .notifier
                    .send_event(subscribers, xml[start..].to_string());
            }
        } else {
            let filename = filename.rsplit('/').next().unwrap_or(&filename).to_string();
            let hash = state
                .content
                .put(&bytes, None)
                .map_err(|_| ApiError::Internal)?;
            state
                .resources
                .insert(
                    crate::sync::NewResource {
                        uid: random_uuid(),
                        name: Some(filename.clone()),
                        download_path: Some(filename),
                        tool: Some("public".into()),
                        submission_user: caller.username.clone(),
                        visible_in: mission.groups.iter().cloned().collect(),
                        ..Default::default()
                    },
                    &hash,
                    bytes.len() as u64,
                    now,
                )
                .map_err(|_| ApiError::Internal)?;
            state
                .store
                .add_content(&mission.guid, Content::Hash(hash), &creator, now)?;
            announce_latest_changes(&state, &mission, 1, &creator)?;
        }
    }
    ok("MissionChange", json!([]))
}

// --- token / password / expiration ---------------------------------------------------------

async fn access_token(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    let params = Params::parse(query)?;
    // `validatePassword`: only checked when the mission has one.
    if mission.password_protected() && !password_matches(&mission, &params.string("password")) {
        return Err(ApiError::Forbidden(
            "Illegal attempt to access mission! Password did not match.".into(),
        ));
    }
    let token = state.tokens.create(
        &random_uuid(),
        TokenType::Access,
        &mission.name,
        &mission.guid,
        now_ms() / 1000,
    );
    created("java.lang.String", token.into())
}

fn set_password_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    password: Option<&str>,
    params: &Params,
) -> ApiResult {
    require(
        role_for(state, &mission, caller),
        Permission::MissionSetPassword,
    )?;
    let hash = match password {
        // The official PUT hashes whatever it gets, the empty default too.
        Some(p) => Some(hash_password(p)?),
        None => None,
    };
    state.store.set_password(&mission.guid, hash, now_ms())?;
    state.notifier.broadcast(
        &mission,
        Announcement::Metadata,
        &params.string("creatorUid"),
    );
    Ok(StatusCode::OK.into_response())
}

async fn set_password_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    let params = Params::parse(query)?;
    let password = params.string("password");
    set_password_impl(&state, &caller, mission, Some(&password), &params)
}

async fn set_password_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    let params = Params::parse(query)?;
    let password = params.string("password");
    set_password_impl(&state, &caller, mission, Some(&password), &params)
}

async fn remove_password_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    set_password_impl(&state, &caller, mission, None, &Params::parse(query)?)
}

async fn remove_password_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    set_password_impl(&state, &caller, mission, None, &Params::parse(query)?)
}

fn set_expiration_impl(
    state: &MissionsState,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    // No `@PreAuthorize` on the official endpoint.
    let mut fields = mission.fields.clone();
    fields.expiration = params.long("expiration")?.unwrap_or(-1);
    state.store.set_fields(&mission.guid, fields, now_ms())?;
    Ok(StatusCode::OK.into_response())
}

async fn set_expiration_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    set_expiration_impl(&state, mission, &Params::parse(query)?)
}

async fn set_expiration_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    set_expiration_impl(&state, mission, &Params::parse(query)?)
}

// --- subscriptions ----------------------------------------------------------------------

fn subscription_get_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    let sub = state
        .store
        .find_subscription(&mission.guid, &params.string("uid"), &caller.username)
        .ok_or_else(|| ApiError::NotFound("Mission subscription not found".into()))?;
    ok(
        "com.bbn.marti.sync.model.MissionSubscription",
        subscription_json(state, &sub, None, true),
    )
}

async fn subscription_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    subscription_get_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn subscription_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    subscription_get_impl(&state, &caller, mission, &Params::parse(query)?)
}

/// `createMissionSubscription`.
fn subscribe_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    let window = params.window()?;
    let password = params.string("password");
    let mut sub_role = role_from_token(
        state,
        &mission,
        caller,
        &[
            TokenType::Invitation,
            TokenType::Subscription,
            TokenType::Access,
        ],
    );
    if mission.password_protected() {
        if !password.is_empty() {
            if !password_matches(&mission, &password) {
                return Err(ApiError::Forbidden(
                    "Illegal attempt to subscribe to mission! Password did not match.".into(),
                ));
            }
        } else if sub_role.is_none() {
            return Err(ApiError::Forbidden(
                "Illegal attempt to subscribe to mission! No token role provided.".into(),
            ));
        }
    } else if !password.is_empty() {
        return Err(ApiError::Forbidden(
            "Illegal attempt to subscribe to mission! No password provided.".into(),
        ));
    } else if mission.invite_only && sub_role.is_none() {
        sub_role = state
            .store
            .invitations_for(&caller.username, InvitationType::UserName)
            .into_iter()
            .find(|i| i.mission_guid == mission.guid)
            .map(|i| i.role);
        if sub_role.is_none() {
            return Err(ApiError::Forbidden(
                "Illegal attempt to subscribe to invite only mission!".into(),
            ));
        }
    }
    let role = sub_role.unwrap_or_else(|| mission.effective_default_role());
    let (uid, topic) = (params.string("uid"), params.string("topic"));
    if uid.is_empty() && topic.is_empty() {
        return Err(ApiError::BadRequest(
            "either 'uid' or 'topic' parameter must be specified".into(),
        ));
    }
    let client_uid = if topic.is_empty() {
        uid.clone()
    } else {
        format!("topic:{topic}")
    };
    let now = now_ms();
    let tokens = Arc::clone(&state.tokens);
    let (name, guid) = (mission.name.clone(), mission.guid.clone());
    let sub = state.store.subscribe(
        &mission.guid,
        &client_uid,
        &caller.username,
        role,
        now,
        |id| tokens.create(id, TokenType::Subscription, &name, &guid, now / 1000),
    )?;
    state.notifier.connect(&mission.guid, &client_uid);
    // Subscribing consumes the client's clientUid invitation.
    state
        .store
        .uninvite(&mission.guid, &uid, InvitationType::ClientUid)?;
    let mission_value = (caller.api_version >= 3).then(|| {
        let extras = MissionExtras {
            changes: state.store.changes(&mission.guid, window, false).ok(),
            logs: Some(state.store.log_entries_for(&mission.name, window)),
            details: true,
            ..Default::default()
        };
        mission_json(state, &mission, &groups_seen(caller, &mission), extras)
    });
    created(
        "com.bbn.marti.sync.model.MissionSubscription",
        subscription_json(state, &sub, mission_value, true),
    )
}

async fn subscribe_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    subscribe_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn subscribe_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    subscribe_impl(&state, &caller, mission, &Params::parse(query)?)
}

/// `deleteMissionSubscription`: with `disconnectOnly` (default true) the
/// stored subscription stays; only the live routing ends.
fn unsubscribe_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let (uid, topic) = (params.string("uid"), params.string("topic"));
    let client_uid = if topic.is_empty() {
        uid
    } else {
        format!("topic:{topic}")
    };
    state.notifier.disconnect(&mission.guid, &client_uid);
    if !params.bool("disconnectOnly", true)? {
        state
            .store
            .unsubscribe(&mission.guid, &client_uid, Some(&caller.username))?;
    }
    Ok(StatusCode::OK.into_response())
}

async fn unsubscribe_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    unsubscribe_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn unsubscribe_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    unsubscribe_impl(&state, &caller, mission, &Params::parse(query)?)
}

/// `setSubscriptionRole` → `inviteOrUpdate`.
fn set_subscription_roles_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
    body: &Bytes,
) -> ApiResult {
    let role = role_for(state, &mission, caller);
    require(role, Permission::MissionSetRole)?;
    let creator = params
        .get("creatorUid")
        .ok_or_else(|| ApiError::BadRequest("missing creatorUid".into()))?
        .to_string();
    let subs: Vec<Value> = serde_json::from_slice(body).map_err(|_| ApiError::InvalidBody)?;
    let mut parsed = Vec::new();
    for s in &subs {
        let client_uid = s.get("clientUid").and_then(|v| v.as_str());
        let new_role = s
            .get("role")
            .and_then(|r| r.get("type"))
            .and_then(|t| t.as_str())
            .and_then(Role::parse);
        let (Some(client_uid), Some(new_role)) = (client_uid, new_role) else {
            return Err(ApiError::BadRequest("missing clientUid or role".into()));
        };
        if !may_assign(&mission, role, new_role) {
            return Err(ApiError::Forbidden(format!(
                "validateRoleAssignment failed! Illegal attempt to assign role {}",
                new_role.name()
            )));
        }
        let username = s
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        parsed.push((client_uid.to_string(), username, new_role));
    }
    let now = now_ms();
    for (client_uid, username, new_role) in parsed {
        let exists = state.store.subscriptions(&mission.guid).iter().any(|s| {
            if !username.is_empty() {
                s.username == username
            } else {
                s.client_uid == client_uid
            }
        });
        if exists {
            set_role(state, &mission, &client_uid, &username, Some(new_role))?;
        } else {
            let (invitee, kind) = if !username.is_empty() {
                (username, InvitationType::UserName)
            } else {
                (client_uid, InvitationType::ClientUid)
            };
            invite_record(state, &mission, &invitee, kind, new_role, &creator, now)?;
        }
    }
    Ok(StatusCode::OK.into_response())
}

async fn set_subscription_roles_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    set_subscription_roles_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

async fn set_subscription_roles_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    set_subscription_roles_impl(&state, &caller, mission, &Params::parse(query)?, &body)
}

fn subscribers_impl(state: &MissionsState, caller: &Caller, mission: MissionRecord) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let uids: Vec<Value> = state
        .store
        .subscriptions(&mission.guid)
        .into_iter()
        .map(|s| s.client_uid.into())
        .collect();
    ok("MissionSubscription", uids.into())
}

async fn subscribers_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    subscribers_impl(&state, &caller, mission)
}

async fn subscribers_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    subscribers_impl(&state, &caller, mission)
}

fn subscription_roles_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let subs: Vec<Value> = state
        .store
        .subscriptions(&mission.guid)
        .iter()
        .map(|s| subscription_json(state, s, None, false))
        .collect();
    ok("MissionSubscription", subs.into())
}

async fn subscription_roles_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    subscription_roles_impl(&state, &caller, mission)
}

async fn subscription_roles_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    subscription_roles_impl(&state, &caller, mission)
}

async fn all_subscriptions(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
) -> ApiResult {
    if !caller(&state, &identity, &headers).admin {
        return Err(ApiError::AccessDenied);
    }
    // `List<Map.Entry<String, String>>` → `{"<mission name>": "<client uid>"}` each.
    let entries: Vec<Value> = state
        .store
        .all_subscriptions()
        .into_iter()
        .map(|(_, name, uid)| json!({ name: uid }))
        .collect();
    ok("MissionSubscription", entries.into())
}

async fn all_subscriptions_with_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
) -> ApiResult {
    if !caller(&state, &identity, &headers).admin {
        return Err(ApiError::AccessDenied);
    }
    let entries: Vec<Value> = state
        .store
        .all_subscriptions()
        .into_iter()
        // A `Map.Entry` key is serialized with its `toString`, `guid=name`.
        .map(|(guid, name, uid)| json!({ format!("{guid}={name}"): uid }))
        .collect();
    ok("MissionSubscription", entries.into())
}

// --- roles ---------------------------------------------------------------------------------

fn role_get_impl(state: &MissionsState, caller: &Caller, mission: MissionRecord) -> ApiResult {
    let role = role_for(state, &mission, caller);
    require(role, Permission::MissionRead)?;
    ok(
        "com.bbn.marti.sync.model.MissionRole",
        role.map(role_json).unwrap_or(Value::Null),
    )
}

async fn role_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    role_get_impl(&state, &caller, mission)
}

async fn role_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    role_get_impl(&state, &caller, mission)
}

/// `setMissionRole`: needs `MISSION_SET_ROLE` and a mission with a
/// default role; no `role` unsubscribes them.
fn role_set_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    params: &Params,
) -> ApiResult {
    let role = role_for(state, &mission, caller);
    require(role, Permission::MissionSetRole)?;
    if mission.default_role.is_none() {
        return Err(ApiError::BadRequest(String::new()));
    }
    let (client_uid, username) = (params.string("clientUid"), params.string("username"));
    let new_role = params.role("role")?;
    if let Some(new_role) = new_role
        && !may_assign(&mission, role, new_role)
    {
        return Err(ApiError::Forbidden(format!(
            "validateRoleAssignment failed! Illegal attempt to assign role {}",
            new_role.name()
        )));
    }
    set_role(state, &mission, &client_uid, &username, new_role)?;
    Ok(StatusCode::OK.into_response())
}

/// `MissionService.setRole`: change the stored role (none = unsubscribe),
/// then tell the client (`t-x-m-r`) -- for a username, its live connection.
fn set_role(
    state: &MissionsState,
    mission: &MissionRecord,
    client_uid: &str,
    username: &str,
    role: Option<Role>,
) -> Result<(), ApiError> {
    match role {
        Some(role) => {
            state
                .store
                .set_subscription_role(&mission.guid, client_uid, username, role)?;
        }
        None => {
            state.notifier.disconnect(&mission.guid, client_uid);
            state
                .store
                .unsubscribe(&mission.guid, client_uid, Some(username))?;
        }
    }
    let mut target = client_uid.to_string();
    if !username.is_empty()
        && let Some(uid) = state
            .clients
            .list()
            .into_iter()
            .find(|c| c.common_name.as_deref() == Some(username))
            .and_then(|c| c.uid)
    {
        target = uid;
    }
    if !target.is_empty() {
        state.notifier.role_change(mission, &target, "", role);
    }
    Ok(())
}

async fn set_role_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    role_set_impl(&state, &caller, mission, &Params::parse(query)?)
}

async fn set_role_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    role_set_impl(&state, &caller, mission, &Params::parse(query)?)
}

// --- invitations -----------------------------------------------------------------------------

/// `missionInvite`: stores the invitation (`false` for a duplicate) and
/// sends the invite (`t-x-m-i`) to the invitee's live connections.
fn invite_record(
    state: &MissionsState,
    mission: &MissionRecord,
    invitee: &str,
    kind: InvitationType,
    role: Role,
    creator: &str,
    now: i64,
) -> Result<bool, ApiError> {
    let token = state.tokens.create(
        &random_uuid(),
        TokenType::Invitation,
        &mission.name,
        &mission.guid,
        now / 1000,
    );
    let stored = state.store.invite(InvitationRecord {
        mission_guid: mission.guid.clone(),
        mission_name: mission.name.clone(),
        invitee: invitee.to_string(),
        invitation_type: kind,
        creator_uid: creator.to_string(),
        create_time_ms: now,
        token: token.clone(),
        role,
    })?;
    if stored {
        let connected: Vec<(Option<String>, Option<String>)> = state
            .clients
            .list()
            .into_iter()
            .map(|c| (c.common_name, c.uid))
            .collect();
        let uids = state.notifier.invitees(kind, invitee, &connected);
        state.notifier.invite(mission, uids, creator, &token, role);
    }
    Ok(stored)
}

/// Invitations for the caller: by client uid, by username (and, in the
/// official server, by the live callsign of that client uid).
fn invitations_for_caller(
    state: &MissionsState,
    caller: &Caller,
    client_uid: &str,
) -> Vec<InvitationRecord> {
    let mut found = state
        .store
        .invitations_for(client_uid, InvitationType::ClientUid);
    for i in state
        .store
        .invitations_for(&caller.username, InvitationType::UserName)
    {
        if !found.contains(&i) {
            found.push(i);
        }
    }
    found.retain(|i| {
        state
            .store
            .by_guid(&i.mission_guid)
            .is_some_and(|m| visible(caller, &m))
    });
    found
}

async fn my_invitations(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let params = Params::parse(query)?;
    let client_uid = params.get("clientUid").ok_or_else(|| {
        ApiError::BadRequest("Required parameter 'clientUid' is not present.".into())
    })?;
    let found: Vec<Value> = invitations_for_caller(&state, &caller, client_uid)
        .iter()
        .map(invitation_json)
        .collect();
    ok("MissionInvitation", found.into())
}

async fn all_invitation_names(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let params = Params::parse(query)?;
    let names: BTreeSet<String> =
        invitations_for_caller(&state, &caller, &params.string("clientUid"))
            .into_iter()
            .map(|i| i.mission_name)
            .collect();
    ok("MissionInvitation", json!(names))
}

fn invitations_impl(state: &MissionsState, caller: &Caller, mission: MissionRecord) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let found: Vec<Value> = state
        .store
        .invitations(&mission.guid)
        .iter()
        .map(invitation_json)
        .collect();
    ok("MissionInvitation", found.into())
}

async fn invitations_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    invitations_impl(&state, &caller, mission)
}

async fn invitations_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    invitations_impl(&state, &caller, mission)
}

fn invite_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    kind: &str,
    invitee: &str,
    params: &Params,
) -> ApiResult {
    let kind = InvitationType::parse(kind)
        .ok_or_else(|| ApiError::BadRequest(format!("invalid invitation type '{kind}'")))?;
    let creator = params.get("creatorUid").ok_or_else(|| {
        ApiError::BadRequest("Required parameter 'creatorUid' is not present.".into())
    })?;
    let invite_role = params
        .role("role")?
        .unwrap_or_else(|| mission.effective_default_role());
    if !may_assign(&mission, role_for(state, &mission, caller), invite_role) {
        return Err(ApiError::Forbidden(format!(
            "validateRoleAssignment failed! Illegal attempt to assign role {}",
            invite_role.name()
        )));
    }
    if !invite_record(
        state,
        &mission,
        invitee,
        kind,
        invite_role,
        creator,
        now_ms(),
    )? {
        // A duplicate: the official `missionInvite` returns false → 500.
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    Ok(StatusCode::OK.into_response())
}

async fn invite_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, kind, invitee)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    invite_impl(
        &state,
        &caller,
        mission,
        &kind,
        &invitee,
        &Params::parse(query)?,
    )
}

async fn invite_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((guid, kind, invitee)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    invite_impl(
        &state,
        &caller,
        mission,
        &kind,
        &invitee,
        &Params::parse(query)?,
    )
}

fn uninvite_impl(
    state: &MissionsState,
    caller: &Caller,
    mission: MissionRecord,
    kind: &str,
    invitee: &str,
    params: &Params,
) -> ApiResult {
    let kind = InvitationType::parse(kind)
        .ok_or_else(|| ApiError::BadRequest(format!("invalid invitation type '{kind}'")))?;
    params.get("creatorUid").ok_or_else(|| {
        ApiError::BadRequest("Required parameter 'creatorUid' is not present.".into())
    })?;
    let token_role = role_from_token(
        state,
        &mission,
        caller,
        &[TokenType::Invitation, TokenType::Subscription],
    );
    if mission.password_protected() && token_role.is_none() {
        // The official handler catches its own exceptions and answers 500.
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    state.store.uninvite(&mission.guid, invitee, kind)?;
    Ok(StatusCode::OK.into_response())
}

async fn uninvite_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((name, kind, invitee)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    uninvite_impl(
        &state,
        &caller,
        mission,
        &kind,
        &invitee,
        &Params::parse(query)?,
    )
}

async fn uninvite_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path((guid, kind, invitee)): Path<(String, String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    uninvite_impl(
        &state,
        &caller,
        mission,
        &kind,
        &invitee,
        &Params::parse(query)?,
    )
}

// --- log entries ------------------------------------------------------------------------------

fn parse_log_entry(body: &Bytes) -> Result<Value, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::InvalidBody)
}

fn json_date(v: Option<&Value>) -> Result<Option<i64>, ApiError> {
    match v.and_then(|v| v.as_str()) {
        None => Ok(None),
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map(|t| Some((t.unix_timestamp_nanos() / 1_000_000) as i64))
            .map_err(|_| ApiError::InvalidBody),
    }
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The role check every log endpoint makes on each named mission: a
/// mission without a role for the caller is skipped, one with a role
/// lacking `permission` is forbidden.
fn check_log_missions(
    state: &MissionsState,
    caller: &Caller,
    names: &[String],
    permission: Permission,
) -> Result<(), ApiError> {
    for name in names {
        let mission = state
            .store
            .by_name(name, |m| visible(caller, m))
            .ok_or_else(|| {
                ApiError::NotFound(format!(
                    "Mission named '{}' not found - not deleted",
                    name.trim()
                ))
            })?;
        if let Some(role) = role_for(state, &mission, caller)
            && !role.has(permission)
        {
            return Err(ApiError::Forbidden(
                "Illegal attempt to access mission!".into(),
            ));
        }
    }
    Ok(())
}

/// `addUpdateLogEntry` / `deleteLogEntry`: a `t-x-m-c-l` to each named
/// mission's live subscribers.
fn announce_log(state: &MissionsState, caller: &Caller, entry: &LogEntryRecord) {
    for name in &entry.mission_names {
        if let Some(mission) = state.store.by_name(name, |m| visible(caller, m)) {
            state
                .notifier
                .announce(&mission, ChangeKind::Log, &entry.creator_uid, None);
        }
    }
}

fn log_entry_from(v: &Value, id: String, server_time_ms: i64) -> Result<LogEntryRecord, ApiError> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    Ok(LogEntryRecord {
        id,
        content: s("content"),
        creator_uid: s("creatorUid"),
        entry_uid: s("entryUid"),
        mission_names: strings(v.get("missionNames")),
        server_time_ms,
        dtg_ms: json_date(v.get("dtg"))?,
        // `addUpdateLogEntry(entry, new Date(), ...)` on every add/update.
        created_ms: Some(server_time_ms),
        content_hashes: strings(v.get("contentHashes")),
        keywords: strings(v.get("keywords")),
    })
}

async fn post_log_entry(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let v = parse_log_entry(&body)?;
    if v.get("id")
        .and_then(|i| i.as_str())
        .is_some_and(|i| !i.is_empty())
    {
        return Err(ApiError::BadRequest(
            "log entry id must not be included for POST".into(),
        ));
    }
    let entry = log_entry_from(&v, random_uuid(), now_ms())?;
    check_log_missions(
        &state,
        &caller,
        &entry.mission_names,
        Permission::MissionWrite,
    )?;
    let saved = state.store.save_log_entry(entry)?;
    announce_log(&state, &caller, &saved);
    ok("com.bbn.marti.sync.model.LogEntry", log_json(&saved))
}

async fn put_log_entry(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let v = parse_log_entry(&body)?;
    let id = v
        .get("id")
        .and_then(|i| i.as_str())
        .filter(|i| !i.is_empty())
        .map(String::from);
    let Some(id) = id else {
        return Err(ApiError::BadRequest(
            "log entry id must be included for PUT".into(),
        ));
    };
    if v.get("servertime").is_some_and(|s| !s.is_null()) {
        return Err(ApiError::BadRequest("servertime can't be modified".into()));
    }
    let entry = log_entry_from(&v, id.clone(), now_ms())?;
    check_log_missions(
        &state,
        &caller,
        &entry.mission_names,
        Permission::MissionWrite,
    )?;
    if state.store.log_entry(&id).is_none() {
        return Err(ApiError::BadRequest(format!("Log entry {id} not found")));
    }
    let saved = state.store.save_log_entry(entry)?;
    announce_log(&state, &caller, &saved);
    ok("com.bbn.marti.sync.model.LogEntry", log_json(&saved))
}

async fn get_log_entry(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let entry = state
        .store
        .log_entry(&id)
        .ok_or_else(|| ApiError::NotFound(format!("log entry {id} not found")))?;
    check_log_missions(
        &state,
        &caller,
        &entry.mission_names,
        Permission::MissionRead,
    )?;
    ok(
        "com.bbn.marti.sync.model.LogEntry",
        json!([log_json(&entry)]),
    )
}

async fn delete_log_entry(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let entry = state
        .store
        .log_entry(&id)
        .ok_or_else(|| ApiError::NotFound(format!("log entry {id} not found")))?;
    check_log_missions(
        &state,
        &caller,
        &entry.mission_names,
        Permission::MissionWrite,
    )?;
    state.store.delete_log_entry(&id)?;
    announce_log(&state, &caller, &entry);
    Ok(StatusCode::OK.into_response())
}

async fn all_logs(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
) -> ApiResult {
    if !caller(&state, &identity, &headers).admin {
        return Err(ApiError::AccessDenied);
    }
    ok(
        "com.bbn.marti.sync.model.LogEntry",
        state.store.all_log_entries().iter().map(log_json).collect(),
    )
}

async fn logs_for_mission(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    require(role_for(&state, &mission, &caller), Permission::MissionRead)?;
    let window = Params::parse(query)?.window()?;
    ok(
        "com.bbn.marti.sync.model.LogEntry",
        state
            .store
            .log_entries_for(&mission.name, window)
            .iter()
            .map(log_json)
            .collect(),
    )
}

// --- CoT ------------------------------------------------------------------------------------------

/// `getCachedCotImpl`: the XML header, `<events>`, the latest event of each
/// mission uid (one per line), `</events>`.
fn cot_impl(state: &MissionsState, caller: &Caller, mission: MissionRecord) -> ApiResult {
    require(role_for(state, &mission, caller), Permission::MissionRead)?;
    let mut xml = String::from("<?xml version='1.0' encoding='UTF-8' standalone='yes'?><events>");
    for add in mission.uids() {
        if let Content::Uid(uid) = &add.content
            && let Some(event) = state.latest_cot.get(uid)
        {
            xml.push_str(&event.xml);
            xml.push('\n');
        }
    }
    xml.push_str("</events>");
    Ok(([(axum::http::header::CONTENT_TYPE, "application/xml")], xml).into_response())
}

async fn cot_by_name(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Name(&name))?;
    cot_impl(&state, &caller, mission)
}

async fn cot_by_guid(
    State(state): State<MissionsState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> ApiResult {
    let caller = caller(&state, &identity, &headers);
    let mission = existing(&state, &caller, Key::Guid(&guid))?;
    cot_impl(&state, &caller, mission)
}

#[cfg(test)]
#[path = "missions_tests.rs"]
mod tests;
