//! Device profiles over HTTP: the official `ProfileAPI` (what devices call)
//! and `ProfileAdminAPI` (`/Marti/api/device/profile/*`, admin-only through
//! the official URL table in [`super::access`]), on [`crate::profiles`].
//!
//! Devices get a profile as a mission package (`profile.zip`, each file in
//! its own `file<N>/` directory, `onReceiveImport`/`onReceiveDelete`), or
//! 204 when nothing applies:
//! - `GET /Marti/api/tls/profile/enrollment?clientUid=` on the enrollment
//!   port, right after enrolling, as the user it enrolled with (Basic auth:
//!   a password account, or the invite token that enrolled that name);
//! - `GET /Marti/api/device/profile/connection?syncSecago=&clientUid=` on
//!   every connect (only profiles changed in the last `syncSecago` seconds,
//!   `-1` for all);
//! - `GET /Marti/api/device/profile/tool/{tool}`.
//!
//! Not implemented: profile *directories* (files served from directories
//! under the official server's `profiles/` folder) -- MicroTAK has none, so
//! `GET /device/profile/directories` lists none.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde_json::json;
use tracing::warn;

use super::PeerIdentity;
use super::PeerIp;
use super::envelope::api_response;
use super::mission_notify::MissionNotifier;
use super::mission_package::{ArchiveFile, manifest_xml};
use crate::enrollment_tokens::EnrollmentTokenStore;
use crate::groups::GroupStore;
use crate::profiles::{Applies, Profile, ProfileFile, ProfileStore, ProfileUpdate};
use crate::ratelimit::{AuthLimiter, user_key};
use crate::users::UserStore;

/// `ProfileService.defaultFilename`.
const FILENAME: &str = "profile.zip";
/// The official update form's "all groups" choice.
const ALL_GROUPS: &str = "APPLY_TO_ALL_GROUPS";

#[derive(Clone)]
pub struct ProfilesState {
    pub store: Arc<ProfileStore>,
    pub groups: Arc<GroupStore>,
    pub notifier: Arc<MissionNotifier>,
    pub max_upload_bytes: u64,
}

/// What the enrollment port needs to know who asks.
#[derive(Clone)]
pub struct EnrollmentProfilesState {
    pub store: Arc<ProfileStore>,
    pub groups: Arc<GroupStore>,
    pub users: Arc<UserStore>,
    pub tokens: Arc<EnrollmentTokenStore>,
    pub limiter: Arc<AuthLimiter>,
}

fn now_ms() -> i64 {
    crate::cot::now_unix_millis()
}

/// The mission package (`ProfileService.createProfileMissionPackage`).
pub fn package(store: &ProfileStore, uid: &str, name: &str, files: &[ProfileFile]) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut contents = Vec::new();
    for (ndx, file) in files.iter().enumerate() {
        let entry = format!("file{ndx}/{}", file.name);
        entries.push((format!("file{ndx}/"), Vec::new()));
        entries.push((entry.clone(), store.contents(file).unwrap_or_default()));
        contents.push(ArchiveFile {
            zip_entry: entry,
            bytes: Vec::new(),
            attributes: Vec::new(),
            uid_parameter: None,
        });
    }
    let manifest = manifest_xml(
        &[
            ("uid", Some(uid.to_string())),
            ("name", Some(name.to_string())),
            ("onReceiveImport", Some("true".into())),
            ("onReceiveDelete", Some("true".into())),
        ],
        &contents,
        &[],
        None,
    );
    entries.push(("MANIFEST/".into(), Vec::new()));
    entries.push(("MANIFEST/manifest.xml".into(), manifest.into_bytes()));
    crate::zip::stored(&entries)
}

fn package_response(bytes: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename={FILENAME}"),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// Files to hand out, or 204 (`SC_NO_CONTENT`) when none apply.
fn deliver(store: &ProfileStore, name: &str, files: Vec<ProfileFile>) -> Response {
    if files.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let uid = super::envelope::random_uuid();
    package_response(package(store, &uid, name, &files))
}

fn params(raw: Option<&str>) -> Vec<(String, String)> {
    serde_urlencoded::from_str(raw.unwrap_or("")).unwrap_or_default()
}

fn param<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// `syncSecago`: `-1` (all) or seconds back; `Err` for a missing (when
/// required) or unparseable value -- Spring's 400.
fn changed_since(pairs: &[(String, String)], required: bool) -> Result<Option<i64>, StatusCode> {
    let secago = match param(pairs, "syncSecago") {
        Some(v) => v.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST)?,
        None if required => return Err(StatusCode::BAD_REQUEST),
        None => -1,
    };
    Ok((secago != -1).then(|| now_ms() - secago.saturating_mul(1000)))
}

pub fn router(state: ProfilesState) -> Router {
    let upload_limit = usize::try_from(state.max_upload_bytes).unwrap_or(usize::MAX);
    Router::new()
        .route("/Marti/api/device/profile", get(list))
        .route("/Marti/api/device/profile/connection", get(connection))
        .route("/Marti/api/device/profile/directories", get(directories))
        .route("/Marti/api/device/profile/tool/:tool", get(tool))
        .route(
            "/Marti/api/device/profile/:name/missionpackage",
            get(mission_package).head(|| async { StatusCode::OK }),
        )
        .route(
            "/Marti/api/device/profile/:name",
            get(one).post(create).put(update).delete(delete),
        )
        .route("/Marti/api/device/profile/:name/files", get(files))
        .route(
            "/Marti/api/device/profile/:name/file",
            axum::routing::put(add_file).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route(
            "/Marti/api/device/profile/:name/file/:id",
            get(file).delete(delete_file),
        )
        .route(
            "/Marti/api/device/profile/:name/send",
            axum::routing::post(send),
        )
        .with_state(state)
}

pub fn enrollment_router(state: EnrollmentProfilesState) -> Router {
    Router::new()
        .route("/Marti/api/tls/profile/enrollment", get(enrollment))
        .with_state(state)
}

/// A profile as Jackson writes the official `Profile` (`groups`: the names
/// of its groups; `updated`: epoch milliseconds, `java.util.Date` through a
/// plain `ObjectMapper`).
fn profile_json(groups: &GroupStore, profile: &Profile) -> serde_json::Value {
    let names: Vec<String> = if profile.all_groups {
        groups.list().into_iter().map(|g| g.name).collect()
    } else {
        profile.groups.iter().cloned().collect()
    };
    json!({
        "id": profile.id,
        "name": profile.name,
        "active": profile.active,
        "applyOnEnrollment": profile.apply_on_enrollment,
        "applyOnConnect": profile.apply_on_connect,
        "type": profile.kind(),
        "updated": profile.updated_ms,
        "tool": profile.tool,
        "groups": names,
    })
}

fn file_json(file: &ProfileFile) -> serde_json::Value {
    json!({ "id": file.id, "name": file.name })
}

async fn list(State(state): State<ProfilesState>) -> Response {
    let all: Vec<_> = state
        .store
        .all()
        .iter()
        .map(|p| profile_json(&state.groups, p))
        .collect();
    api_response("Profile", all).into_response()
}

async fn one(State(state): State<ProfilesState>, Path(name): Path<String>) -> Response {
    match state.store.by_name(&name) {
        Some(p) => api_response("Profile", profile_json(&state.groups, &p)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `createProfile`: 201, or 200 if it exists; `group=` names unknown to
/// the server are ignored (`findGroups`).
async fn create(
    State(state): State<ProfilesState>,
    Path(name): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let groups: BTreeSet<String> = params(raw.as_deref())
        .into_iter()
        .filter(|(k, _)| k == "group")
        .map(|(_, v)| v)
        .filter(|g| state.groups.exists(g))
        .collect();
    match state.store.create(&name, groups, now_ms()) {
        Ok(true) => StatusCode::CREATED.into_response(),
        Ok(false) => StatusCode::OK.into_response(),
        Err(error) => {
            warn!(%error, "creating a device profile failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `updateProfile`: the posted profile (by its `id`) as sent -- name,
/// active, tool, groups -- with `type` deciding when it applies. Anything
/// missing or wrong is the official 500.
async fn update(State(state): State<ProfilesState>, body: Bytes) -> Response {
    let fail = || StatusCode::INTERNAL_SERVER_ERROR.into_response();
    let Ok(posted) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (Some(id), Some(name), Some(kind)) = (
        posted.get("id").and_then(|v| v.as_i64()),
        posted.get("name").and_then(|v| v.as_str()),
        posted.get("type").and_then(|v| v.as_str()),
    ) else {
        return fail();
    };
    let names: Vec<String> = posted
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|g| g.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let all_groups = names.iter().any(|g| g == ALL_GROUPS);
    let update = ProfileUpdate {
        name: name.to_string(),
        active: posted
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        apply_on_enrollment: kind == "Enrollment",
        apply_on_connect: kind == "Connection",
        tool: posted
            .get("tool")
            .and_then(|v| v.as_str())
            .map(String::from),
        groups: if all_groups {
            BTreeSet::new()
        } else {
            names
                .into_iter()
                .filter(|g| state.groups.exists(g))
                .collect()
        },
        all_groups,
    };
    match state.store.update(id, update, now_ms()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => fail(),
    }
}

/// `deleteProfile` (`/device/profile/{id}`).
async fn delete(State(state): State<ProfilesState>, Path(id): Path<String>) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.store.delete(id) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn files(State(state): State<ProfilesState>, Path(name): Path<String>) -> Response {
    let Some(profile) = state.store.by_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let files: Vec<_> = state
        .store
        .files(profile.id)
        .iter()
        .map(file_json)
        .collect();
    api_response("ProfileFile", files).into_response()
}

async fn add_file(
    State(state): State<ProfilesState>,
    Path(name): Path<String>,
    RawQuery(raw): RawQuery,
    body: Bytes,
) -> Response {
    let pairs = params(raw.as_deref());
    let Some(filename) = param(&pairs, "filename") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(profile) = state.store.by_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match state.store.add_file(profile.id, filename, &body, now_ms()) {
        Ok(file) => api_response("ProfileFile", file_json(&file)).into_response(),
        Err(error) => {
            warn!(%error, "adding a device profile file failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn file_id(id: &str) -> Result<i64, StatusCode> {
    id.parse::<i64>().map_err(|_| StatusCode::BAD_REQUEST)
}

async fn file(
    State(state): State<ProfilesState>,
    Path((_name, id)): Path<(String, String)>,
) -> Response {
    let id = match file_id(&id) {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    let Some(file) = state.store.file(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = state.store.contents(&file).unwrap_or_default();
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename={}", file.name),
            ),
        ],
        bytes,
    )
        .into_response()
}

async fn delete_file(
    State(state): State<ProfilesState>,
    Path((_name, id)): Path<(String, String)>,
) -> Response {
    let id = match file_id(&id) {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };
    match state.store.delete_file(id, now_ms()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn directories() -> Response {
    api_response("String", Vec::<String>::new()).into_response()
}

/// The caller's groups, either direction (`getGroupVectorBitString`).
fn caller_groups(groups: &GroupStore, identity: &str) -> BTreeSet<String> {
    groups.all_group_names(identity)
}

async fn connection(
    State(state): State<ProfilesState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    RawQuery(raw): RawQuery,
) -> Response {
    let pairs = params(raw.as_deref());
    if param(&pairs, "clientUid").is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let since = match changed_since(&pairs, true) {
        Ok(since) => since,
        Err(status) => return status.into_response(),
    };
    let files = state.store.files_for(
        Applies::OnConnect,
        &caller_groups(&state.groups, &cn),
        since,
    );
    deliver(&state.store, "Connection", files)
}

async fn tool(
    State(state): State<ProfilesState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    Path(tool): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let pairs = params(raw.as_deref());
    if param(&pairs, "clientUid").is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let since = match changed_since(&pairs, false) {
        Ok(since) => since,
        Err(status) => return status.into_response(),
    };
    let files = state
        .store
        .files_for_tool(&tool, &caller_groups(&state.groups, &cn), since);
    deliver(&state.store, &tool, files)
}

/// `getProfileMp`: the named profile if it reaches the caller (active or
/// not), uid `ProfileMissionPackage-<id>`.
async fn mission_package(
    State(state): State<ProfilesState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    Path(name): Path<String>,
) -> Response {
    let profile = state
        .store
        .by_name(&name)
        .filter(|p| p.reaches(&caller_groups(&state.groups, &cn)));
    let Some(profile) = profile else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let files = state.store.files(profile.id);
    package_response(package(
        &state.store,
        &format!("ProfileMissionPackage-{}", profile.id),
        &name,
        &files,
    ))
}

/// `sendProfile`: a file transfer (`b-f-t-r`) of the profile's package to
/// the given client uids, from "TAK Server".
async fn send(
    State(state): State<ProfilesState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(selected) = serde_json::from_slice::<Vec<String>>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if selected.is_empty() {
        return StatusCode::OK.into_response();
    }
    let Some(profile) = state.store.by_name(&name) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let files = state.store.files(profile.id);
    let bytes = package(
        &state.store,
        &format!("ProfileMissionPackage-{}", profile.id),
        &name,
        &files,
    );
    let hash = crate::content_store::hex_sha256(&bytes);
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let server_name = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    // `URLEncoder.encode` (form encoding, space as `+`).
    let encoded = serde_urlencoded::to_string([("n", name.as_str())])
        .map(|s| s[2..].to_string())
        .unwrap_or_default();
    let url =
        format!("https://{server_name}:8443/Marti/api/device/profile/{encoded}/missionpackage");
    let now = now_ms();
    let (time, stale) = (
        crate::cot::cot_time(now),
        crate::cot::cot_time(now + 100_000),
    );
    // `getFileTransferCotMessage`; its `<marti><dest>`s are the recipients.
    let xml = format!(
        "<?xml version='1.0' encoding='UTF-8' standalone='yes'?><event version='2.0' uid='{hash}' type='b-f-t-r' time='{time}' start='{time}' stale='{stale}' how='h-e'><point lat='0.0' lon='0.0' hae='9999999.0' ce='9999999' le='9999999' /><detail><fileshare sha256='{hash}' senderUid='{hash}' name='{FILENAME}' filename='{FILENAME}' senderUrl='{url}' sizeInBytes='{}' senderCallsign='TAK Server'/></detail></event>",
        bytes.len()
    );
    state.notifier.send_event(selected, xml);
    StatusCode::OK.into_response()
}

/// Who asks on the enrollment port: Basic auth as a password account, or
/// as the name an invite token enrolled.
async fn enrollment_user(
    state: &EnrollmentProfilesState,
    peer: &PeerIp,
    headers: &HeaderMap,
) -> Result<String, StatusCode> {
    let Some((username, secret)) = super::enrollment::basic_auth_credentials(headers) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let ip_key = peer.limit_key();
    let name_key = user_key(&username);
    if state.limiter.is_blocked(&ip_key) || state.limiter.is_blocked(&name_key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let ok = if state.users.exists(&username) {
        state
            .limiter
            .verify_password(&state.users, &username, &secret)
            .await
    } else {
        state.tokens.get(&secret).is_some_and(|t| {
            !t.revoked && t.used_by_common_name.as_deref() == Some(username.as_str())
        })
    };
    if !ok {
        state.limiter.record_failure(&ip_key);
        state.limiter.record_failure(&name_key);
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(username)
}

async fn enrollment(
    State(state): State<EnrollmentProfilesState>,
    peer: PeerIp,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let user = match enrollment_user(&state, &peer, &headers).await {
        Ok(user) => user,
        Err(StatusCode::UNAUTHORIZED) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"TAK Server\"")],
            )
                .into_response();
        }
        Err(status) => return status.into_response(),
    };
    if param(&params(raw.as_deref()), "clientUid").is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let files = state.store.files_for(
        Applies::OnEnrollment,
        &caller_groups(&state.groups, &user),
        None,
    );
    deliver(&state.store, "Enrollment", files)
}

#[cfg(test)]
#[path = "profiles_tests.rs"]
mod tests;
