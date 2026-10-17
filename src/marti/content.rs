//! Enterprise Sync -- the official TAK Server's file APIs, on top of
//! [`crate::content_store`] (bytes by hash) and [`crate::sync`] (metadata).
//! Every route mirrors an official servlet or controller in
//! `TAK-Product-Center/Server` (paths under `/Marti`):
//!
//! | Route | Official source |
//! |---|---|
//! | `POST /sync/missionupload` | `MissionPackageUploadServlet` -- multipart (`assetfile`, or `resource`), `filename` required; answers the content URL as text |
//! | `POST /sync/upload` | `UploadServlet` -- raw or multipart body, `Metadata` field names as query parameters; answers the stored `Metadata` JSON |
//! | `GET /sync/content?hash=\|uid=` | `ContentServlet` -- type and name from the metadata, `offset`/`length` |
//! | `GET /sync/missionquery?hash=` | `MissionPackageQueryServlet` -- the content URL, or 404 |
//! | `GET /sync/search` | `SearchServlet` -- `{resultCount, results: [Metadata]}` |
//! | `DELETE /sync/delete?Hash=\|PrimaryKey=` | `DeleteServlet` |
//! | `GET /api/sync/search` | `MissionApi.searchSync` -- envelope of `Resource` |
//! | `GET /api/resources/{hash}` | `MissionApi.getResource` (admin) |
//! | `PUT /api/sync/metadata/{hash}/keywords\|expiration` | `MetadataApi` |
//!
//! Files are visible within their groups ([`crate::sync`]); the admin sees
//! all, as on the official server.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Path, Query, RawQuery, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use futures_util::StreamExt;
use serde::Deserialize;

use super::{PeerIdentity, envelope};
use crate::content_store::{ContentStore, ContentStoreError};
use crate::groups::GroupStore;
use crate::sync::{NewResource, ResourceRecord, ResourceStore};

/// Default upload size limit: 100 MB (photos, videos, data packages).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone)]
pub struct SyncState {
    pub content: Arc<ContentStore>,
    pub resources: Arc<ResourceStore>,
    pub groups: Arc<GroupStore>,
    pub admin_common_name: Option<String>,
    pub max_upload_bytes: u64,
}

pub fn router(state: SyncState) -> Router {
    Router::new()
        .route("/Marti/sync/missionupload", post(mission_upload))
        .route("/Marti/sync/upload", post(upload))
        .route("/Marti/sync/content", get(content))
        .route("/Marti/sync/missionquery", get(mission_query))
        .route("/Marti/sync/search", get(search_servlet))
        .route("/Marti/sync/delete", delete(delete_servlet))
        .route("/Marti/api/sync/search", get(search_api))
        .route("/Marti/api/resources/:hash", get(get_resource))
        .route("/Marti/api/sync/metadata/:hash/keywords", put(set_keywords))
        .route("/Marti/api/sync/metadata/:hash/expiration", put(set_expiration))
        // Bodies are streamed to disk; the configured upload limit applies.
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(state)
}

fn now_millis() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

/// `None` for the admin (sees everything), else the caller's groups.
fn viewer_groups(state: &SyncState, identity: &PeerIdentity) -> Option<BTreeSet<String>> {
    if state.admin_common_name.as_deref() == Some(identity.0.as_str()) {
        None
    } else {
        Some(state.groups.all_group_names(&identity.0))
    }
}

/// The groups a new file is visible in: the requested `Groups` (only those
/// the uploader is in -- the official `validateAccess`), else all of the
/// uploader's.
fn upload_groups(state: &SyncState, identity: &PeerIdentity, requested: &[String]) -> Result<Vec<String>, Box<Response>> {
    let mine = state.groups.all_group_names(&identity.0);
    if requested.is_empty() {
        return Ok(mine.into_iter().collect());
    }
    let is_admin = state.admin_common_name.as_deref() == Some(identity.0.as_str());
    if !is_admin && requested.iter().any(|g| !mine.contains(g)) {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    Ok(requested.to_vec())
}

/// `<scheme>://<host>:<port>` of the request, as the official
/// `getBaseUrl` builds it (the Marti API is always HTTPS here).
fn base_url(headers: &HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("localhost");
    format!("https://{host}")
}

fn text(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

fn bad_request(message: &str) -> Response {
    text(StatusCode::BAD_REQUEST, message.to_string())
}

fn store_error(error: ContentStoreError) -> Response {
    match error {
        ContentStoreError::TooLarge { limit } => bad_request(&format!(
            "Uploaded file exceeds server's size limit of {} MB!",
            limit / (1024 * 1024)
        )),
        other => text(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// Query parameters as (name, value) pairs, repeated names kept.
fn query_pairs(raw: Option<&str>) -> Vec<(String, String)> {
    serde_urlencoded::from_str::<Vec<(String, String)>>(raw.unwrap_or("")).unwrap_or_default()
}

fn values<'a>(pairs: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    pairs.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
}

// ---------------------------------------------------------------------
// POST /Marti/sync/missionupload
// ---------------------------------------------------------------------

/// The first multipart part named `assetfile` (ATAK) or `resource`
/// (browsers), streamed into the content store: (hash, size, part
/// filename, part content type).
async fn store_multipart(
    state: &SyncState,
    request: Request,
) -> Result<(String, u64, Option<String>, Option<String>), Box<Response>> {
    let mut multipart = axum::extract::Multipart::from_request(request, &())
        .await
        .map_err(|_| Box::new(bad_request("Upload request was not formatted in a way Marti can understand.")))?;
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name != "assetfile" && name != "resource" {
            continue;
        }
        let filename = field.file_name().map(str::to_string);
        let content_type = field.content_type().map(str::to_string);
        let stream = Box::pin(field.map(|chunk| chunk.map_err(std::io::Error::other)));
        let hash = state
            .content
            .put_stream(stream, None, state.max_upload_bytes)
            .await
            .map_err(|e| Box::new(store_error(e)))?;
        let size = state.content.open_file(&hash).await.ok().flatten().map(|(_, len)| len).unwrap_or(0);
        return Ok((hash, size, filename, content_type));
    }
    Err(Box::new(bad_request(
        "Upload request was not formatted in a way Marti can understand.\nPlease try a different browser.",
    )))
}

async fn mission_upload(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    RawQuery(raw): RawQuery,
    request: Request,
) -> Response {
    let pairs = query_pairs(raw.as_deref());
    let is_multipart = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("multipart/form-data"));
    if !is_multipart {
        return bad_request(
            "Data package upload must use multipart/form-data POST. Part name should be named 'assetfile'",
        );
    }
    let Some(filename) = values(&pairs, "filename").first().map(|s| s.to_string()) else {
        return bad_request("Required parameter filename is not present");
    };
    // `Groups` (capital G, as the official servlet reads it) sets who sees
    // the file; lowercase `groups` is only a metadata field.
    let requested: Vec<String> = values(&pairs, "Groups").iter().map(|s| s.to_string()).collect();
    let visible_in = match upload_groups(&state, &identity, &requested) {
        Ok(groups) => groups,
        Err(response) => return *response,
    };
    let base = base_url(request.headers());
    let (hash, size, _, _) = match store_multipart(&state, request).await {
        Ok(stored) => stored,
        Err(response) => return *response,
    };
    let keywords: Vec<String> = match values(&pairs, "keyword") {
        k if k.is_empty() => vec!["missionpackage".to_string()],
        k => k.iter().map(|s| s.to_string()).collect(),
    };
    let first = |name: &str, default: &str| {
        values(&pairs, name).first().map(|s| s.to_string()).unwrap_or_else(|| default.to_string())
    };
    let new = NewResource {
        // The hash is the uid (the official servlet lets the database
        // compute it; a client-supplied `hash` is ignored).
        uid: hash.clone(),
        name: Some(filename),
        mime_type: Some(first("mimetype", "application/x-zip-compressed")),
        keywords,
        submission_user: identity.0.clone(),
        creator_uid: Some(first("creatorUid", "")),
        tool: Some(first("tool", "public")),
        visible_in,
        groups_field: values(&pairs, "groups").iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    if let Err(error) = state.resources.insert(new, &hash, size, now_millis()) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
    }
    text(StatusCode::OK, format!("{base}/Marti/sync/content?hash={hash}"))
}

// ---------------------------------------------------------------------
// POST /Marti/sync/upload
// ---------------------------------------------------------------------

/// The official `Metadata.Field` names (matched case-insensitively, `MIME`
/// meaning `MIMEType`), and whether each is an array field.
const METADATA_FIELDS: &[(&str, bool)] = &[
    ("Altitude", false),
    ("DownloadPath", false),
    ("Keywords", true),
    ("Latitude", false),
    ("Longitude", false),
    ("Hash", false),
    ("MIMEType", false),
    ("Name", false),
    ("Permissions", true),
    ("Size", false),
    ("Remarks", false),
    ("SubmissionUser", false),
    ("PrimaryKey", false),
    ("SubmissionDateTime", false),
    ("UID", false),
    ("Contacts", true),
    ("CreatorUid", false),
    ("Tool", false),
    ("EXPIRATION", false),
    ("PluginClassName", false),
    ("Groups", true),
    ("MissionName", false),
];

fn metadata_field(name: &str) -> Option<(&'static str, bool)> {
    if name.eq_ignore_ascii_case("MIME") {
        return Some(("MIMEType", false));
    }
    METADATA_FIELDS.iter().copied().find(|(field, _)| field.eq_ignore_ascii_case(name))
}

async fn upload(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    RawQuery(raw): RawQuery,
    request: Request,
) -> Response {
    let mut fields: std::collections::HashMap<&'static str, Vec<String>> = std::collections::HashMap::new();
    for (key, value) in query_pairs(raw.as_deref()) {
        let Some((field, is_array)) = metadata_field(&key) else {
            return bad_request(&format!("Unrecognized parameter {key}"));
        };
        let entry = fields.entry(field).or_default();
        if is_array {
            entry.extend(value.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()));
        } else {
            entry.push(value);
        }
    }
    let first = |name: &str| fields.get(name).and_then(|v| v.first().cloned());
    let parse = |name: &str| first(name).and_then(|v| v.parse::<f64>().ok());
    let visible_in = match upload_groups(&state, &identity, fields.get("Groups").map(Vec::as_slice).unwrap_or(&[])) {
        Ok(groups) => groups,
        Err(response) => return *response,
    };

    let content_type = request.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let declared_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared_length.is_some_and(|len| len > state.max_upload_bytes) {
        return store_error(ContentStoreError::TooLarge { limit: state.max_upload_bytes });
    }
    let (hash, size, part_name, mime_type) = if content_type.as_deref().is_some_and(|t| t.contains("multipart/form-data")) {
        match store_multipart(&state, request).await {
            Ok(stored) => stored,
            Err(response) => return *response,
        }
    } else {
        let stream = request.into_body().into_data_stream();
        let hash = match state.content.put_stream(stream, None, state.max_upload_bytes).await {
            Ok(hash) => hash,
            Err(error) => return store_error(error),
        };
        let size = state.content.open_file(&hash).await.ok().flatten().map(|(_, len)| len).unwrap_or(0);
        (hash, size, None, content_type)
    };
    if size == 0 {
        return bad_request("HTTP request body has no content.");
    }
    let new = NewResource {
        uid: first("UID").unwrap_or_else(uuid_v4),
        name: first("Name").or_else(|| part_name.clone()),
        download_path: part_name.or_else(|| first("DownloadPath")),
        // The request's (or part's) Content-Type wins, as in the servlet.
        mime_type: mime_type.or_else(|| first("MIMEType")),
        keywords: fields.get("Keywords").cloned().unwrap_or_default(),
        submission_user: identity.0.clone(),
        creator_uid: first("CreatorUid"),
        tool: first("Tool"),
        latitude: parse("Latitude"),
        longitude: parse("Longitude"),
        altitude: parse("Altitude"),
        expiration: first("EXPIRATION").and_then(|v| v.parse::<f64>().ok()).map(|v| v as i64).filter(|v| *v >= 0),
        visible_in,
        groups_field: fields.get("Groups").cloned().unwrap_or_default(),
        mission_name: first("MissionName"),
        remarks: first("Remarks"),
    };
    match state.resources.insert(new, &hash, size, now_millis()) {
        Ok(record) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/json")],
            record.metadata_json().to_string(),
        )
            .into_response(),
        Err(error) => text(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}

/// A random (version 4) UUID, as the official servlet assigns when the
/// upload names no `UID`.
fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("OS RNG must be available");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

// ---------------------------------------------------------------------
// GET /Marti/sync/content, /Marti/sync/missionquery
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct ContentQuery {
    hash: Option<String>,
    uid: Option<String>,
    offset: Option<u64>,
    length: Option<u64>,
}

fn not_found() -> Response {
    text(StatusCode::NOT_FOUND, "File not found".to_string())
}

async fn content(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    Query(query): Query<ContentQuery>,
) -> Response {
    let groups = viewer_groups(&state, &identity);
    let matches: Vec<ResourceRecord> = match (&query.hash, &query.uid) {
        (Some(hash), _) => state.resources.by_hash(hash, groups.as_ref()),
        (None, Some(uid)) => state.resources.by_uid(uid, groups.as_ref()),
        (None, None) => return bad_request("hash or uid required"),
    };
    // Newest first; the official servlet takes the first.
    let Some(record) = matches.into_iter().next() else { return not_found() };
    let Ok(Some((file, total))) = state.content.open_file(&record.hash).await else {
        return text(StatusCode::INTERNAL_SERVER_ERROR, String::new());
    };
    let filename = record.download_path.clone().or(record.name.clone()).unwrap_or_else(|| "file".to_string());
    let mut headers = vec![
        ("api-version".to_string(), envelope::API_VERSION.to_string()),
        (
            header::CONTENT_DISPOSITION.to_string(),
            format!("inline; filename=\"{}\"", urlencode_filename(&filename)),
        ),
    ];
    if let Some(mime) = &record.mime_type {
        headers.push((header::CONTENT_TYPE.to_string(), mime.clone()));
    }

    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let offset = query.offset.unwrap_or(0).min(total);
    let mut file = file;
    if offset > 0 && file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
        return text(StatusCode::INTERNAL_SERVER_ERROR, String::new());
    }
    let remaining = total - offset;
    let (status, len) = match query.length {
        Some(length) if length > 0 && offset + length < total => (StatusCode::PARTIAL_CONTENT, length),
        _ => (StatusCode::OK, remaining),
    };
    headers.push((header::CONTENT_LENGTH.to_string(), len.to_string()));
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file.take(len)));
    let mut response = (status, body).into_response();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

/// `URLEncoder.encode(filename, UTF-8)` as the official servlet applies it
/// (spaces become `+`).
fn urlencode_filename(name: &str) -> String {
    let mut out = String::new();
    for byte in name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(byte as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[derive(Deserialize)]
struct MissionQuery {
    hash: Option<String>,
}

async fn mission_query(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    headers: HeaderMap,
    Query(query): Query<MissionQuery>,
) -> Response {
    let Some(hash) = query.hash else { return bad_request("HTTP post missing required param hash.") };
    let groups = viewer_groups(&state, &identity);
    // The servlet looks the hash up as a UID (mission packages use their
    // hash as uid).
    match state.resources.by_uid(&hash, groups.as_ref()).into_iter().next() {
        Some(record) => text(StatusCode::OK, format!("{}/Marti/sync/content?hash={}", base_url(&headers), record.uid)),
        None => not_found(),
    }
}

// ---------------------------------------------------------------------
// Searches
// ---------------------------------------------------------------------

async fn search_servlet(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    RawQuery(raw): RawQuery,
) -> Response {
    let groups = viewer_groups(&state, &identity);
    let pairs = query_pairs(raw.as_deref());
    let mut results = state.resources.visible(groups.as_ref());
    for (key, value) in &pairs {
        if key.eq_ignore_ascii_case("tool") {
            results.retain(|r| r.tool.as_deref() == Some(value.as_str()));
        } else if let Some((field, _)) = metadata_field(key) {
            results.retain(|r| match field {
                "Keywords" => r.keywords.iter().any(|k| k == value),
                "Name" => r.name.as_deref() == Some(value.as_str()),
                "UID" => r.uid == *value,
                "Hash" => r.hash == value.to_ascii_lowercase(),
                "MIMEType" => r.mime_type.as_deref() == Some(value.as_str()),
                "CreatorUid" => r.creator_uid.as_deref() == Some(value.as_str()),
                "SubmissionUser" => r.submission_user == *value,
                "MissionName" => r.mission_name.as_deref() == Some(value.as_str()),
                _ => true,
            });
        }
    }
    let array: Vec<serde_json::Value> = results.iter().map(ResourceRecord::metadata_json).collect();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/json")],
        serde_json::json!({ "resultCount": array.len(), "results": array }).to_string(),
    )
        .into_response()
}

async fn search_api(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    RawQuery(raw): RawQuery,
) -> Response {
    let pairs = query_pairs(raw.as_deref());
    let one = |name: &str| values(&pairs, name).first().map(|s| s.to_string());
    let keywords: Vec<String> = values(&pairs, "keyword").iter().map(|s| s.to_string()).collect();
    let (mimetype, name, filename, uid, hash, tool, mission) =
        (one("mimetype"), one("name"), one("filename"), one("uid"), one("hash"), one("tool"), one("mission"));
    let groups = viewer_groups(&state, &identity);
    let results: Vec<serde_json::Value> = state
        .resources
        .visible(groups.as_ref())
        .into_iter()
        .filter(|r| keywords.is_empty() || keywords.iter().all(|k| r.keywords.contains(k)))
        .filter(|r| mimetype.as_ref().is_none_or(|m| r.mime_type.as_ref() == Some(m)))
        .filter(|r| name.as_ref().is_none_or(|n| r.name.as_ref() == Some(n)))
        .filter(|r| filename.as_ref().is_none_or(|f| r.download_path.as_ref().or(r.name.as_ref()) == Some(f)))
        .filter(|r| uid.as_ref().is_none_or(|u| r.uid == *u))
        .filter(|r| hash.as_ref().is_none_or(|h| r.hash == h.to_ascii_lowercase()))
        .filter(|r| tool.as_ref().is_none_or(|t| r.tool.as_ref() == Some(t)))
        .filter(|r| mission.as_ref().is_none_or(|m| r.mission_name.as_ref() == Some(m)))
        .map(|r| r.resource_json())
        .collect();
    envelope::api_response("Resource", results).into_response()
}

// ---------------------------------------------------------------------
// Delete, resources, metadata
// ---------------------------------------------------------------------

async fn delete_servlet(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    RawQuery(raw): RawQuery,
) -> Response {
    let groups = viewer_groups(&state, &identity);
    let pairs = query_pairs(raw.as_deref());
    let mut keys = Vec::new();
    let mut hash = None;
    for (key, value) in &pairs {
        if key.eq_ignore_ascii_case("PrimaryKey") {
            match value.parse::<i64>() {
                Ok(k) if k >= 0 => keys.push(k),
                _ => return bad_request("PrimaryKey must be numeric."),
            }
        } else if key.eq_ignore_ascii_case("Hash") && hash.is_none() {
            hash = Some(value.clone());
        }
    }
    let hashes: Vec<String> = match &hash {
        Some(h) => vec![h.to_ascii_lowercase()],
        None => state
            .resources
            .visible(groups.as_ref())
            .into_iter()
            .filter(|r| keys.contains(&r.primary_key))
            .map(|r| r.hash)
            .collect(),
    };
    let deleted = match &hash {
        Some(h) => state.resources.delete_hash(h, groups.as_ref()),
        None => state.resources.delete_keys(&keys, groups.as_ref()),
    };
    if let Err(error) = deleted {
        return text(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to process delete request: {error}"));
    }
    // Remove the bytes once nothing references them any more.
    for h in hashes {
        if !state.resources.hash_in_use(&h) {
            state.content.remove(&h);
        }
    }
    let count = if hash.is_some() { "1".to_string() } else { keys.len().to_string() };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html")],
        format!(
            "<html>\n\n<head>\n\n<title>Enterprise Sync Status</title>\n\n</head>\n\n<h1>Success</h1>\n\n<p>Deleted {count} resource(s).</p>\n\n</html>\n\n"
        ),
    )
        .into_response()
}

async fn get_resource(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(hash): Path<String>,
) -> Response {
    // Admin only: this path doesn't check group membership.
    if state.admin_common_name.as_deref() != Some(identity.0.as_str()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.resources.by_hash(&hash, None).into_iter().next() {
        Some(record) => envelope::api_response("Resource", vec![record.resource_json()]).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn set_keywords(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(hash): Path<String>,
    Json(keywords): Json<Vec<String>>,
) -> Response {
    let groups = viewer_groups(&state, &identity);
    if state.resources.by_hash(&hash, groups.as_ref()).is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.resources.set_keywords(&hash, keywords) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct ExpirationQuery {
    expiration: Option<i64>,
}

async fn set_expiration(
    State(state): State<SyncState>,
    Extension(identity): Extension<PeerIdentity>,
    Path(hash): Path<String>,
    Query(query): Query<ExpirationQuery>,
) -> Response {
    let groups = viewer_groups(&state, &identity);
    if state.resources.by_hash(&hash, groups.as_ref()).is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.resources.set_expiration(&hash, query.expiration.filter(|e| *e >= 0)) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_field_names_match_case_insensitively_like_the_official_enum() {
        assert_eq!(metadata_field("keywords"), Some(("Keywords", true)));
        assert_eq!(metadata_field("mime"), Some(("MIMEType", false)));
        assert_eq!(metadata_field("creatorUid"), Some(("CreatorUid", false)));
        assert_eq!(metadata_field("expiration"), Some(("EXPIRATION", false)));
        assert_eq!(metadata_field("bogus"), None);
    }

    #[test]
    fn filenames_are_encoded_like_javas_url_encoder() {
        assert_eq!(urlencode_filename("Recon Pack.zip"), "Recon+Pack.zip");
        assert_eq!(urlencode_filename("a/b"), "a%2Fb");
    }

    #[test]
    fn generated_uids_are_version_4_uuids() {
        let uid = uuid_v4();
        assert_eq!(uid.len(), 36);
        assert_eq!(&uid[14..15], "4");
    }
}
