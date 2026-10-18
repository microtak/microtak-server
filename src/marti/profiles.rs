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
//! Profile *directories*: subfolders of `data_dir/profiles` (the official
//! server's `profiles/`) attached to tool profiles and served file by file
//! (`GET /Marti/api/{device,tls}/profile/tool/{tool}/file?relativePath=`):
//! one file as itself, several (a folder) as a `multiFile` mission package,
//! with `Last-Modified` / `If-Modified-Since` (304).

use std::collections::BTreeSet;
use std::path::{Path as FsPath, PathBuf};
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
    /// The profiles folder (canonical), whose subfolders are directories.
    pub profiles_dir: PathBuf,
}

/// What the enrollment port needs to know who asks.
#[derive(Clone)]
pub struct EnrollmentProfilesState {
    pub store: Arc<ProfileStore>,
    pub groups: Arc<GroupStore>,
    pub users: Arc<UserStore>,
    pub tokens: Arc<EnrollmentTokenStore>,
    pub limiter: Arc<AuthLimiter>,
    pub profiles_dir: PathBuf,
    pub max_upload_bytes: u64,
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
            "/Marti/api/device/profile/tool/:tool/file",
            get(device_tool_file),
        )
        .route(
            "/Marti/api/device/profile/:name/directories",
            get(list_directories).delete(clear_directories),
        )
        .route(
            "/Marti/api/device/profile/:name/directories/:dirs",
            axum::routing::put(add_directories),
        )
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
        .route("/Marti/api/tls/profile/tool/:tool/file", get(tls_tool_file))
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

/// `getValidDirectories`: the profiles folder's immediate subfolders.
pub fn valid_directories(root: &FsPath) -> Vec<String> {
    let mut dirs: Vec<String> = std::fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs
}

async fn directories(State(state): State<ProfilesState>) -> Response {
    api_response("String", valid_directories(&state.profiles_dir)).into_response()
}

fn directory_json(d: &crate::profiles::ProfileDirectory) -> serde_json::Value {
    json!({ "id": d.id, "path": d.path })
}

async fn list_directories(
    State(state): State<ProfilesState>,
    Path(name): Path<String>,
) -> Response {
    let Some(profile) = state.store.by_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let dirs: Vec<_> = state
        .store
        .directories(profile.id)
        .iter()
        .map(directory_json)
        .collect();
    api_response("ProfileDirectory", dirs).into_response()
}

/// `updateDirectories` (`{directories}` comma-separated): every one must
/// be a valid directory, else 500.
async fn add_directories(
    State(state): State<ProfilesState>,
    Path((name, dirs)): Path<(String, String)>,
) -> Response {
    let Some(profile) = state.store.by_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let valid = valid_directories(&state.profiles_dir);
    let wanted: Vec<String> = dirs.split(',').map(str::to_string).collect();
    if wanted.iter().any(|d| !valid.contains(d)) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match state.store.add_directories(profile.id, &wanted, now_ms()) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn clear_directories(
    State(state): State<ProfilesState>,
    Path(name): Path<String>,
) -> Response {
    let Some(profile) = state.store.by_name(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match state.store.clear_directories(profile.id) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// One file found under a profile directory.
struct DirContent {
    file: PathBuf,
    bytes: Vec<u8>,
    modified_secs: i64,
    /// The profile directory's own name (`ProfileDirectory.path`).
    dir_name: String,
}

/// `checkFile`: the path is what it says (no symlinks, `.`, `//`) and
/// inside the profiles folder.
fn check_file(root: &FsPath, absolute: &FsPath) -> bool {
    match std::fs::canonicalize(absolute) {
        Ok(canonical) => canonical == absolute && canonical.starts_with(root),
        // Nothing there: nothing to escape to.
        Err(_) => !absolute.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }),
    }
}

fn modified_secs(path: &FsPath) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `loadDirectoryContents`: every file below `dir`; a bad path anywhere
/// empties the result, as officially.
fn load_directory(root: &FsPath, dir: &FsPath, dir_name: &str, out: &mut Vec<DirContent>) -> bool {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(e) => e.flatten().map(|e| e.path()).collect(),
        Err(_) => return true,
    };
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if !load_directory(root, &path, dir_name, out) {
                return false;
            }
        } else {
            if !check_file(root, &path) {
                out.clear();
                return false;
            }
            out.push(DirContent {
                bytes: std::fs::read(&path).unwrap_or_default(),
                modified_secs: modified_secs(&path),
                file: path,
                dir_name: dir_name.to_string(),
            });
        }
    }
    true
}

/// `getProfileDirectoryContent` for one relative path: `Ok(None)` when no
/// directory has it (404), `Err` for a traversal attempt or a file over
/// the size limit (500).
fn find_content(
    root: &FsPath,
    dirs: &[crate::profiles::ProfileDirectory],
    relative: &str,
    limit: u64,
) -> Result<Option<Vec<DirContent>>, ()> {
    for dir in dirs {
        // String concatenation, as officially ("profiles/" + path + relativePath).
        let absolute = PathBuf::from(format!("{}/{}{relative}", root.display(), dir.path));
        if absolute.to_string_lossy().contains("//") || !check_file(root, &absolute) {
            return Err(());
        }
        if !absolute.exists() {
            continue;
        }
        let mut out = Vec::new();
        if absolute.is_dir() {
            load_directory(root, &absolute, &dir.path, &mut out);
            return Ok(Some(out));
        }
        let size = std::fs::metadata(&absolute).map(|m| m.len()).unwrap_or(0);
        if size > limit {
            return Err(());
        }
        out.push(DirContent {
            bytes: std::fs::read(&absolute).map_err(|_| ())?,
            modified_secs: modified_secs(&absolute),
            file: absolute,
            dir_name: dir.path.clone(),
        });
        return Ok(Some(out));
    }
    Ok(None)
}

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Java's `DateTimeFormatter.RFC_1123_DATE_TIME` in UTC (day not padded).
fn rfc1123(secs: i64) -> String {
    let t =
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{}, {} {} {} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[t.weekday().number_days_from_monday() as usize],
        t.day(),
        MONTHS[t.month() as usize - 1],
        t.year(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn parse_rfc1123(s: &str) -> Option<i64> {
    let rest = s.split_once(", ").map(|(_, r)| r).unwrap_or(s);
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let [day, month, year, hms, zone] = parts.as_slice() else {
        return None;
    };
    if *zone != "GMT" && *zone != "UTC" && *zone != "Z" {
        return None;
    }
    let month = MONTHS.iter().position(|m| m == month)? as u8 + 1;
    let mut hms = hms.split(':').map(|v| v.parse::<u8>());
    let (h, m, sec) = (hms.next()?.ok()?, hms.next()?.ok()?, hms.next()?.ok()?);
    let date = time::Date::from_calendar_date(
        year.parse().ok()?,
        time::Month::try_from(month).ok()?,
        day.parse().ok()?,
    )
    .ok()?;
    let t = date.with_hms(h, m, sec).ok()?.assume_utc();
    Some(t.unix_timestamp())
}

/// `URLConnection.guessContentTypeFromName` for common files.
fn content_type(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" | "jpe" => "image/jpeg",
        "gif" => "image/gif",
        "txt" | "text" | "java" | "c" | "h" => "text/plain",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// `createProfileFileMissionPackage`: each file under its folders relative
/// to its profile directory.
fn multi_file_package(contents: &[DirContent]) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen_dirs: BTreeSet<String> = BTreeSet::new();
    let mut manifest_files = Vec::new();
    for content in contents {
        let mut dirs: Vec<String> = Vec::new();
        let mut cursor = content.file.parent();
        while let Some(dir) = cursor {
            if dir.file_name().is_none()
                || dir
                    .file_name()
                    .is_some_and(|n| n == content.dir_name.as_str())
            {
                break;
            }
            dirs.push(dir.file_name().unwrap().to_string_lossy().into_owned());
            cursor = dir.parent();
        }
        let mut prefix = String::new();
        for d in dirs.iter().rev() {
            prefix.push_str(d);
            prefix.push('/');
            if seen_dirs.insert(prefix.clone()) {
                entries.push((prefix.clone(), Vec::new()));
            }
        }
        let name = content
            .file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let entry = format!("{prefix}{name}");
        entries.push((entry.clone(), content.bytes.clone()));
        manifest_files.push(ArchiveFile {
            zip_entry: entry,
            bytes: Vec::new(),
            attributes: Vec::new(),
            uid_parameter: None,
        });
    }
    let manifest = manifest_xml(
        &[
            ("uid", Some(super::envelope::random_uuid())),
            ("name", Some("multiFile".into())),
            ("onReceiveImport", Some("true".into())),
            ("onReceiveDelete", Some("true".into())),
        ],
        &manifest_files,
        &[],
        None,
    );
    entries.push(("MANIFEST/".into(), Vec::new()));
    entries.push(("MANIFEST/manifest.xml".into(), manifest.into_bytes()));
    crate::zip::stored(&entries)
}

/// `ProfileService.getProfileDirectoryContent`.
#[allow(clippy::too_many_arguments)]
fn tool_file(
    store: &ProfileStore,
    root: &FsPath,
    limit: u64,
    user_groups: &BTreeSet<String>,
    tool: &str,
    pairs: &[(String, String)],
    headers: &HeaderMap,
) -> Response {
    let relatives: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "relativePath")
        .map(|(_, v)| v.as_str())
        .collect();
    // `PreventDirectoryTraversal` (`^(?!.*\.\.).+`, 255 characters).
    if relatives.is_empty()
        || param(pairs, "clientUid").is_none()
        || relatives
            .iter()
            .any(|r| r.is_empty() || r.contains("..") || r.len() > 255)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let since = match changed_since(pairs, false) {
        Ok(since) => since,
        Err(status) => return status.into_response(),
    };
    let valid = valid_directories(root);
    let mut contents: Vec<DirContent> = Vec::new();
    for relative in relatives {
        let dirs = store.directories_for_tool(tool, user_groups, since);
        if dirs.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if dirs.iter().any(|d| !valid.contains(&d.path)) {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        match find_content(root, &dirs, relative, limit) {
            Ok(Some(found)) => contents.extend(found),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(()) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    if contents.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let last_modified = contents.iter().map(|c| c.modified_secs).max().unwrap_or(0);
    if let Some(value) = headers.get(header::IF_MODIFIED_SINCE) {
        let Some(since) = value.to_str().ok().and_then(parse_rfc1123) else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        contents.retain(|c| c.modified_secs > since);
    }
    let last_modified = (header::LAST_MODIFIED, rfc1123(last_modified));
    match contents.len() {
        0 => (StatusCode::NOT_MODIFIED, [last_modified]).into_response(),
        1 => {
            let c = contents.remove(0);
            let name = c
                .file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (
                [
                    last_modified,
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename={name}"),
                    ),
                    (header::CONTENT_TYPE, content_type(&name).to_string()),
                ],
                c.bytes,
            )
                .into_response()
        }
        _ => (
            [
                last_modified,
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename={FILENAME}"),
                ),
                (header::CONTENT_TYPE, "application/zip".to_string()),
            ],
            multi_file_package(&contents),
        )
            .into_response(),
    }
}

async fn device_tool_file(
    State(state): State<ProfilesState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    Path(tool): Path<String>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let groups = caller_groups(&state.groups, &cn);
    tool_file(
        &state.store,
        &state.profiles_dir,
        state.max_upload_bytes,
        &groups,
        &tool,
        &params(raw.as_deref()),
        &headers,
    )
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

async fn tls_tool_file(
    State(state): State<EnrollmentProfilesState>,
    peer: PeerIp,
    Path(tool): Path<String>,
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
    let groups = caller_groups(&state.groups, &user);
    tool_file(
        &state.store,
        &state.profiles_dir,
        state.max_upload_bytes,
        &groups,
        &tool,
        &params(raw.as_deref()),
        &headers,
    )
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
