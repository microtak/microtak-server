//! `/Marti/api/datafeeds`: the official `SubmissionApi` data feed CRUD and
//! `DataFeedApi`'s list, on [`crate::datafeeds`].
//!
//! The request body is the CoreConfig `DataFeed` as Jackson binds it
//! (`name`, `type`, `tag`, `auth`, `authRequired`, `protocol`, `port`,
//! `filtergroup`, ...; unknown properties ignored), the response the
//! `tak.server.feeds.DataFeed` model (`tags`, `filterGroups`, port 0 as
//! null, nulls left out).
//!
//! Officially every user may create, change and delete feeds (a streaming
//! feed opens a port). MicroTAK restricts that to the admin unless
//! `datafeeds_admin_only` is switched off.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde_json::{Value, json};

use super::PeerIdentity;
use crate::datafeeds::{DataFeed, DataFeedError, DataFeedStore};
use crate::groups::{ANON_GROUP, GroupStore};

/// `DataFeed.class.getName()`, the envelope's type.
const KIND: &str = "tak.server.feeds.DataFeed";
/// `SubmissionApi.PROTOCOLS`.
const PROTOCOLS: [&str; 10] = [
    "tcp", "udp", "stcp", "tls", "mcast", "cotmcast", "prototls", "cottls", "quic", "grpc",
];
const TYPES: [&str; 5] = ["Streaming", "API", "Plugin", "Federation", "Predicate"];
/// JAXB `AuthType` constants, as Jackson binds them.
const AUTH_TYPES: [&str; 4] = ["LDAP", "FILE", "ANONYMOUS", "X_509"];

#[derive(Clone)]
pub struct DataFeedsState {
    pub store: Arc<DataFeedStore>,
    pub groups: Arc<GroupStore>,
    pub admin_common_name: Option<String>,
    /// Only the admin may create, change or delete feeds (MicroTAK's
    /// default; officially everyone may).
    pub admin_only: bool,
}

impl DataFeedsState {
    fn is_admin(&self, identity: &str) -> bool {
        self.admin_common_name.as_deref() == Some(identity)
    }

    fn may_manage(&self, identity: &str) -> bool {
        !self.admin_only || self.is_admin(identity)
    }
}

pub fn router(state: DataFeedsState) -> Router {
    Router::new()
        .route("/Marti/api/datafeeds", get(list).post(create))
        .route(
            "/Marti/api/datafeeds/:name",
            get(one).put(update).delete(delete),
        )
        .with_state(state)
}

/// The envelope, `data` and `messages` left out when absent (`NON_NULL`).
fn envelope(status: StatusCode, data: Option<Value>, messages: Option<Vec<String>>) -> Response {
    let mut body = json!({
        "version": super::envelope::API_VERSION,
        "type": KIND,
        "nodeId": super::envelope::server_id(),
    });
    if let Some(data) = data {
        body["data"] = data;
    }
    if let Some(messages) = messages {
        body["messages"] = json!(messages);
    }
    (status, Json(body)).into_response()
}

/// `tak.server.feeds.DataFeed` as Jackson writes it (getter names, nulls
/// left out -- including the `sSyncCacheRetentionSeconds` quirk of its
/// `getsSyncCacheRetentionSeconds` getter).
pub fn feed_json(feed: &DataFeed, uuid_known: bool) -> Value {
    let mut v = json!({
        "name": feed.name,
        "tags": feed.tags,
        "type": TYPES.iter().find(|t| t.eq_ignore_ascii_case(&feed.feed_type)).copied().unwrap_or("Streaming"),
        "auth": feed.auth,
        "authRequired": feed.auth_required,
        "protocol": feed.protocol,
        "archive": feed.archive,
        "anongroup": feed.anongroup,
        "archiveOnly": feed.archive_only,
        "sync": feed.sync,
        "coreVersion": feed.core_version,
        "filterGroups": feed.filter_groups,
        "sSyncCacheRetentionSeconds": feed.sync_cache_retention_seconds,
        "syncCacheRetentionSeconds": feed.sync_cache_retention_seconds,
        "federated": feed.federated,
        "binaryPayloadWebsocketOnly": feed.binary_payload_websocket_only,
    });
    if uuid_known {
        v["uuid"] = json!(feed.uuid);
    }
    for (key, value) in [
        ("port", feed.port.map(|p| json!(p))),
        ("group", feed.group.clone().map(|g| json!(g))),
        ("iface", feed.iface.clone().map(|i| json!(i))),
        (
            "coreVersion2TlsVersions",
            feed.core_version2_tls_versions.clone().map(|t| json!(t)),
        ),
    ] {
        if let Some(value) = value {
            v[key] = value;
        }
    }
    v
}

/// `getInputNameValidationErrors`.
fn name_errors(name: Option<&str>) -> Vec<String> {
    match name.map(str::trim) {
        None | Some("") => vec!["Missing input name.".into()],
        Some(n) if n.chars().count() > 30 => vec!["Invalid input name length.".into()],
        Some(n)
            if !n
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c.is_whitespace()) =>
        {
            vec!["Invalid input name.".into()]
        }
        _ => vec![],
    }
}

/// The posted CoreConfig `DataFeed` with its JAXB defaults; `Err` for a
/// body Jackson can't bind (400).
struct Posted {
    uuid: Option<String>,
    name: Option<String>,
    feed_type: Option<String>,
    feed: DataFeed,
}

fn parse(body: &[u8]) -> Result<Posted, ()> {
    let v: Value = serde_json::from_slice(body).map_err(|_| ())?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let b = |k: &str, default: bool| v.get(k).and_then(|x| x.as_bool()).unwrap_or(default);
    let i = |k: &str, default: i64| v.get(k).and_then(|x| x.as_i64()).unwrap_or(default);
    let list = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let auth = s("auth").unwrap_or_else(|| "X_509".into());
    if !AUTH_TYPES.contains(&auth.as_str()) {
        return Err(());
    }
    let port = i("port", 0) as i32;
    Ok(Posted {
        uuid: s("uuid"),
        name: s("name"),
        feed_type: s("type"),
        feed: DataFeed {
            uuid: s("uuid").unwrap_or_default(),
            name: s("name").unwrap_or_default().trim().to_string(),
            feed_type: s("type").unwrap_or_default(),
            tags: list("tag"),
            auth,
            auth_required: b("authRequired", false),
            protocol: s("protocol").unwrap_or_default(),
            port: (port != 0).then_some(port),
            group: s("group")
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty()),
            iface: s("iface")
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty()),
            archive: b("archive", true),
            anongroup: b("anongroup", false),
            archive_only: b("archiveOnly", false),
            sync: b("sync", false),
            core_version: i("coreVersion", 2) as i32,
            core_version2_tls_versions: Some(
                s("coreVersion2TlsVersions").unwrap_or_else(|| "TLSv1.2,TLSv1.3".into()),
            ),
            filter_groups: list("filtergroup"),
            sync_cache_retention_seconds: i("syncCacheRetentionSeconds", 3600) as i32,
            federated: b("federated", true),
            binary_payload_websocket_only: b("binaryPayloadWebsocketOnly", false),
            visible_to: BTreeSet::new(),
        },
    })
}

/// `getDataFeedValidationErrors`.
fn validation_errors(posted: &Posted) -> Vec<String> {
    let feed = &posted.feed;
    let mut errors = name_errors(posted.name.as_deref());
    if posted.feed_type.is_none() {
        errors.push("Null data feed type provided".into());
    }
    if let Some(group) = &feed.group {
        let ipv4 = group.split('.').count() == 4
            && group
                .split('.')
                .all(|p| (1..=3).contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit()));
        if !ipv4 {
            errors.push("Invalid multicast group value.".into());
        }
    }
    if let Some(iface) = &feed.iface
        && !iface.chars().all(|c| c.is_ascii_alphanumeric())
    {
        errors.push("Invalid interface value.".into());
    }
    let streaming = ["stcp", "tls", "prototls", "cottls"].contains(&feed.protocol.as_str());
    if (feed.auth == "FILE" || feed.auth == "LDAP") && !streaming {
        errors.push("If Authentication Type is set to File or LDAP, then Protocol should be be Streaming TCP or Secure Streaming TCP.".into());
    }
    let mcast = feed.protocol == "mcast" || feed.protocol == "cotmcast";
    if mcast && feed.group.is_none() {
        errors.push(
            "If Protocol is set to Multicast, then the Multicast Group must be provided.".into(),
        );
    }
    if feed.group.is_some() && !mcast {
        errors.push(
            "If the Multicast Group is provided, then Protocol should be set to Multicast.".into(),
        );
    }
    errors
}

fn caller_groups(state: &DataFeedsState, identity: &str) -> BTreeSet<String> {
    state.groups.all_group_names(identity)
}

/// `findGroups`: the named groups that exist.
fn existing_groups(state: &DataFeedsState, names: &[String]) -> BTreeSet<String> {
    names
        .iter()
        .filter(|g| g.as_str() == ANON_GROUP || state.groups.exists(g))
        .cloned()
        .collect()
}

/// `DataFeedApi.getDataFeeds`: the feeds the caller's groups reach.
async fn list(
    State(state): State<DataFeedsState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
) -> Response {
    let groups = caller_groups(&state, &cn);
    let feeds: Vec<Value> = state
        .store
        .all()
        .iter()
        .filter(|f| f.reaches(&groups))
        .map(|f| feed_json(f, true))
        .collect();
    envelope(StatusCode::OK, Some(json!(feeds)), None)
}

async fn one(
    State(state): State<DataFeedsState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    Path(name): Path<String>,
) -> Response {
    if !name_errors(Some(&name)).is_empty() {
        return envelope(StatusCode::BAD_REQUEST, None, None);
    }
    match state.store.by_name(&name) {
        Some(feed) if feed.reaches(&caller_groups(&state, &cn)) => {
            envelope(StatusCode::OK, Some(feed_json(&feed, true)), None)
        }
        _ => envelope(StatusCode::BAD_REQUEST, None, None),
    }
}

/// `createDataFeed`: 400 with the validation errors, else 200 with the
/// feed as posted (its uuid only if the request had one).
async fn create(
    State(state): State<DataFeedsState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    body: Bytes,
) -> Response {
    if !state.may_manage(&cn) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(mut posted) = parse(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if posted.feed.filter_groups.is_empty() {
        posted.feed.filter_groups.push(ANON_GROUP.to_string());
    }
    let returned = feed_json(&posted.feed, posted.uuid.is_some());
    let errors = validation_errors(&posted);
    if !errors.is_empty() {
        return envelope(StatusCode::BAD_REQUEST, Some(returned), Some(errors));
    }
    let Some(feed_type) = posted
        .feed_type
        .as_deref()
        .filter(|t| TYPES.contains(t))
        .map(str::to_string)
    else {
        // `DataFeedType.valueOf` throws for anything else.
        return envelope(StatusCode::INTERNAL_SERVER_ERROR, None, Some(vec![]));
    };
    if !PROTOCOLS.contains(&posted.feed.protocol.as_str()) && feed_type == "Streaming" {
        return envelope(
            StatusCode::BAD_REQUEST,
            Some(returned),
            Some(vec![format!(
                "Unsupported protocol '{}'.",
                posted.feed.protocol
            )]),
        );
    }
    let mut feed = posted.feed;
    feed.feed_type = feed_type;
    if feed.uuid.is_empty() {
        feed.uuid = super::envelope::random_uuid();
    }
    feed.visible_to = existing_groups(&state, &feed.filter_groups);
    match state.store.create(feed) {
        Ok(()) => envelope(StatusCode::OK, Some(returned), None),
        Err(error @ DataFeedError::NameTaken) => envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            Some(vec![error.to_string()]),
        ),
        Err(error) => envelope(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            Some(vec![error.to_string()]),
        ),
    }
}

/// `modifyDataFeed`: the feed called `name`, replaced by the posted one
/// (tags and filter groups only if any are posted), visible to the
/// updating user's groups from then on.
async fn update(
    State(state): State<DataFeedsState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    if !state.may_manage(&cn) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(posted) = parse(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(feed_type) = posted.feed_type.as_deref().filter(|t| TYPES.contains(t)) else {
        return envelope(StatusCode::INTERNAL_SERVER_ERROR, None, None);
    };
    let groups = caller_groups(&state, &cn);
    let Some(existing) = state.store.by_name(&name) else {
        return envelope(StatusCode::BAD_REQUEST, None, None);
    };
    if !name_errors(Some(&name)).is_empty() || !existing.reaches(&groups) {
        return envelope(StatusCode::BAD_REQUEST, None, None);
    }
    let mut feed = posted.feed;
    feed.feed_type = feed_type.to_string();
    if feed.uuid.is_empty() {
        feed.uuid = existing.uuid.clone();
    }
    if feed.tags.is_empty() {
        feed.tags = existing.tags.clone();
    }
    if feed.filter_groups.is_empty() {
        feed.filter_groups = existing.filter_groups.clone();
    }
    feed.visible_to = groups;
    match state.store.replace(&name, feed) {
        Ok(()) => envelope(StatusCode::OK, None, None),
        Err(_) => envelope(StatusCode::INTERNAL_SERVER_ERROR, None, None),
    }
}

/// `deleteDataFeed`: by name, among the caller's feeds unless admin.
async fn delete(
    State(state): State<DataFeedsState>,
    Extension(PeerIdentity(cn)): Extension<PeerIdentity>,
    Path(name): Path<String>,
) -> Response {
    if !state.may_manage(&cn) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !name_errors(Some(&name)).is_empty() {
        return envelope(StatusCode::BAD_REQUEST, None, None);
    }
    let visible = state
        .store
        .by_name(&name)
        .filter(|f| state.is_admin(&cn) || f.reaches(&caller_groups(&state, &cn)));
    if visible.is_none() {
        return envelope(StatusCode::BAD_REQUEST, None, None);
    }
    match state.store.delete(&name) {
        Ok(()) => envelope(StatusCode::OK, None, None),
        Err(_) => envelope(StatusCode::INTERNAL_SERVER_ERROR, None, None),
    }
}

#[cfg(test)]
#[path = "datafeeds_tests.rs"]
mod tests;
