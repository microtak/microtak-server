//! Enterprise Sync: metadata for every file stored through the official TAK
//! Server file APIs (`/Marti/sync/*`, `/Marti/api/sync/*`), on top of the
//! hash-addressed bytes in [`crate::content_store`].
//!
//! Mirrors the official server's `resource` table and its two JSON views:
//! - `Metadata` (`com.bbn.marti.sync.Metadata`, used by the `/Marti/sync/*`
//!   servlets): every field a string, array fields lists, keyed by the
//!   official field names (`UID`, `Name`, `MIMEType`, `PrimaryKey`, ...).
//! - `Resource` (`com.bbn.marti.sync.model.Resource`, used by the REST
//!   API and missions): camelCase, NON_NULL.
//!
//! Visibility follows groups like missions: a file belongs to the groups it
//! was uploaded into (the `Groups` parameter, checked against the
//! uploader's groups) or else the uploader's groups, `__ANON__` for an
//! identity without groups.
//!
//! Persisted as an append-only event log (see [`crate::eventlog`]).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
}

/// One stored file and its metadata (a row of the official `resource`
/// table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceRecord {
    pub primary_key: i64,
    pub uid: String,
    /// SHA-256 of the content, lowercase hex (as the official database
    /// computes it).
    pub hash: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub download_path: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    pub size: u64,
    pub submission_time_millis: i64,
    /// The authenticated uploader (certificate CN).
    pub submission_user: String,
    #[serde(default)]
    pub creator_uid: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub latitude: Option<f64>,
    #[serde(default)]
    pub longitude: Option<f64>,
    #[serde(default)]
    pub altitude: Option<f64>,
    /// Unix seconds; `None` = never (`-1` on the wire).
    #[serde(default)]
    pub expiration: Option<i64>,
    /// Who may see it (group names).
    pub visible_in: Vec<String>,
    /// The `groups` metadata field as given by the uploader.
    #[serde(default)]
    pub groups_field: Vec<String>,
    #[serde(default)]
    pub mission_name: Option<String>,
    #[serde(default)]
    pub remarks: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum SyncEvent {
    Inserted {
        record: Box<ResourceRecord>,
    },
    Deleted {
        primary_key: i64,
    },
    KeywordsSet {
        hash: String,
        keywords: Vec<String>,
    },
    ExpirationSet {
        hash: String,
        expiration: Option<i64>,
    },
    /// `FileManagerApi.putMetadata` on the caller's rows.
    SubmitterSet {
        keys: Vec<i64>,
        user: String,
    },
    ExpirationSetKeys {
        keys: Vec<i64>,
        expiration: Option<i64>,
    },
}

#[derive(Debug, Default)]
struct SyncState {
    resources: Vec<ResourceRecord>,
    next_key: i64,
}

fn apply(state: &mut SyncState, event: &SyncEvent) {
    match event {
        SyncEvent::Inserted { record } => {
            state.next_key = state.next_key.max(record.primary_key);
            state.resources.push((**record).clone());
        }
        SyncEvent::Deleted { primary_key } => {
            state.resources.retain(|r| r.primary_key != *primary_key)
        }
        SyncEvent::KeywordsSet { hash, keywords } => {
            for r in state.resources.iter_mut().filter(|r| r.hash == *hash) {
                r.keywords = keywords.clone();
            }
        }
        SyncEvent::ExpirationSet { hash, expiration } => {
            for r in state.resources.iter_mut().filter(|r| r.hash == *hash) {
                r.expiration = *expiration;
            }
        }
        SyncEvent::SubmitterSet { keys, user } => {
            for r in state
                .resources
                .iter_mut()
                .filter(|r| keys.contains(&r.primary_key))
            {
                r.submission_user = user.clone();
            }
        }
        SyncEvent::ExpirationSetKeys { keys, expiration } => {
            for r in state
                .resources
                .iter_mut()
                .filter(|r| keys.contains(&r.primary_key))
            {
                r.expiration = *expiration;
            }
        }
    }
}

/// The metadata an upload supplies; the store adds key, size, hash, time.
#[derive(Debug, Clone, Default)]
pub struct NewResource {
    pub uid: String,
    pub name: Option<String>,
    pub download_path: Option<String>,
    pub mime_type: Option<String>,
    pub keywords: Vec<String>,
    pub submission_user: String,
    pub creator_uid: Option<String>,
    pub tool: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub altitude: Option<f64>,
    pub expiration: Option<i64>,
    pub visible_in: Vec<String>,
    pub groups_field: Vec<String>,
    pub mission_name: Option<String>,
    pub remarks: Option<String>,
}

pub struct ResourceStore {
    state: RwLock<SyncState>,
    log: Option<EventLog<SyncEvent>>,
}

impl ResourceStore {
    pub fn in_memory() -> Self {
        Self {
            state: RwLock::new(SyncState::default()),
            log: None,
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, SyncError> {
        let mut state = SyncState::default();
        let log = EventLog::open_and_replay(path, &mut state, apply)?;
        Ok(Self {
            state: RwLock::new(state),
            log: Some(log),
        })
    }

    fn record(&self, state: &mut SyncState, event: SyncEvent) -> Result<(), SyncError> {
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply(state, &event);
        Ok(())
    }

    /// Store the metadata of content already in the content store under
    /// `hash` (`size` bytes).
    pub fn insert(
        &self,
        new: NewResource,
        hash: &str,
        size: u64,
        now_millis: i64,
    ) -> Result<ResourceRecord, SyncError> {
        let mut state = self.state.write().unwrap();
        let record = ResourceRecord {
            primary_key: state.next_key + 1,
            uid: new.uid,
            hash: hash.to_string(),
            name: new.name,
            download_path: new.download_path,
            mime_type: new.mime_type,
            keywords: new.keywords,
            size,
            submission_time_millis: now_millis,
            submission_user: new.submission_user,
            creator_uid: new.creator_uid,
            tool: new.tool,
            latitude: new.latitude,
            longitude: new.longitude,
            altitude: new.altitude,
            expiration: new.expiration,
            visible_in: new.visible_in,
            groups_field: new.groups_field,
            mission_name: new.mission_name,
            remarks: new.remarks,
        };
        self.record(
            &mut state,
            SyncEvent::Inserted {
                record: Box::new(record.clone()),
            },
        )?;
        Ok(record)
    }

    /// Every resource, newest first (the official queries order by
    /// submission time descending).
    pub fn all(&self) -> Vec<ResourceRecord> {
        let mut all = self.state.read().unwrap().resources.clone();
        all.sort_by(|a, b| {
            b.submission_time_millis
                .cmp(&a.submission_time_millis)
                .then(b.primary_key.cmp(&a.primary_key))
        });
        all
    }

    /// Resources visible to someone in `groups` (`None` = admin, sees all).
    pub fn visible(&self, groups: Option<&BTreeSet<String>>) -> Vec<ResourceRecord> {
        self.all()
            .into_iter()
            .filter(|r| match groups {
                None => true,
                Some(groups) => r.visible_in.iter().any(|g| groups.contains(g)),
            })
            .collect()
    }

    pub fn by_hash(&self, hash: &str, groups: Option<&BTreeSet<String>>) -> Vec<ResourceRecord> {
        let hash = hash.to_ascii_lowercase();
        self.visible(groups)
            .into_iter()
            .filter(|r| r.hash == hash)
            .collect()
    }

    pub fn by_uid(&self, uid: &str, groups: Option<&BTreeSet<String>>) -> Vec<ResourceRecord> {
        self.visible(groups)
            .into_iter()
            .filter(|r| r.uid == uid)
            .collect()
    }

    /// Delete by primary keys (only those visible); returns how many.
    pub fn delete_keys(
        &self,
        keys: &[i64],
        groups: Option<&BTreeSet<String>>,
    ) -> Result<usize, SyncError> {
        let visible: Vec<i64> = self.visible(groups).iter().map(|r| r.primary_key).collect();
        let mut state = self.state.write().unwrap();
        let mut count = 0;
        for key in keys.iter().filter(|k| visible.contains(k)) {
            self.record(&mut state, SyncEvent::Deleted { primary_key: *key })?;
            count += 1;
        }
        Ok(count)
    }

    /// Delete every visible resource with `hash`; returns how many.
    pub fn delete_hash(
        &self,
        hash: &str,
        groups: Option<&BTreeSet<String>>,
    ) -> Result<usize, SyncError> {
        let keys: Vec<i64> = self
            .by_hash(hash, groups)
            .iter()
            .map(|r| r.primary_key)
            .collect();
        self.delete_keys(&keys, groups)
    }

    pub fn set_keywords(&self, hash: &str, keywords: Vec<String>) -> Result<(), SyncError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            SyncEvent::KeywordsSet {
                hash: hash.to_ascii_lowercase(),
                keywords,
            },
        )
    }

    pub fn set_expiration(&self, hash: &str, expiration: Option<i64>) -> Result<(), SyncError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            SyncEvent::ExpirationSet {
                hash: hash.to_ascii_lowercase(),
                expiration,
            },
        )
    }

    pub fn set_submission_user(&self, keys: &[i64], user: &str) -> Result<(), SyncError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            SyncEvent::SubmitterSet {
                keys: keys.to_vec(),
                user: user.to_string(),
            },
        )
    }

    pub fn set_expiration_keys(
        &self,
        keys: &[i64],
        expiration: Option<i64>,
    ) -> Result<(), SyncError> {
        let mut state = self.state.write().unwrap();
        self.record(
            &mut state,
            SyncEvent::ExpirationSetKeys {
                keys: keys.to_vec(),
                expiration,
            },
        )
    }

    /// Whether any resource (of any visibility) still references `hash` --
    /// the content bytes may only be removed when none does.
    pub fn hash_in_use(&self, hash: &str) -> bool {
        let hash = hash.to_ascii_lowercase();
        self.state
            .read()
            .unwrap()
            .resources
            .iter()
            .any(|r| r.hash == hash)
    }
}

impl ResourceRecord {
    /// The official `Metadata.toJSONObject()`: field names as in
    /// `Metadata.Field`, single values as strings, array fields as lists.
    pub fn metadata_json(&self) -> serde_json::Value {
        let mut json = serde_json::Map::new();
        let mut put = |key: &str, value: String| {
            json.insert(key.to_string(), serde_json::Value::String(value));
        };
        if let Some(alt) = self.altitude {
            put("Altitude", alt.to_string());
        }
        if let Some(path) = &self.download_path {
            put("DownloadPath", path.clone());
        }
        if let Some(lat) = self.latitude {
            put("Latitude", lat.to_string());
        }
        if let Some(lon) = self.longitude {
            put("Longitude", lon.to_string());
        }
        put("Hash", self.hash.clone());
        if let Some(mime) = &self.mime_type {
            put("MIMEType", mime.clone());
        }
        if let Some(name) = &self.name {
            put("Name", name.clone());
        }
        put("Size", self.size.to_string());
        if let Some(remarks) = &self.remarks {
            put("Remarks", remarks.clone());
        }
        put("SubmissionUser", self.submission_user.clone());
        put("PrimaryKey", self.primary_key.to_string());
        put(
            "SubmissionDateTime",
            crate::marti::envelope::cot_date_millis(self.submission_time_millis),
        );
        put("UID", self.uid.clone());
        if let Some(creator) = &self.creator_uid {
            put("CreatorUid", creator.clone());
        }
        if let Some(tool) = &self.tool {
            put("Tool", tool.clone());
        }
        put("EXPIRATION", self.expiration.unwrap_or(-1).to_string());
        if let Some(mission) = &self.mission_name {
            put("MissionName", mission.clone());
        }
        let list = |values: &[String]| {
            serde_json::Value::Array(
                values
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            )
        };
        json.insert("Keywords".to_string(), list(&self.keywords));
        if !self.groups_field.is_empty() {
            json.insert("Groups".to_string(), list(&self.groups_field));
        }
        serde_json::Value::Object(json)
    }

    /// The official `Resource` (REST API and mission contents): camelCase,
    /// NON_NULL.
    pub fn resource_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "keywords": self.keywords,
            "submissionTime": crate::marti::envelope::cot_date_millis(self.submission_time_millis),
            "submitter": self.submission_user,
            "uid": self.uid,
            "hash": self.hash,
            "size": self.size,
            "expiration": self.expiration.unwrap_or(-1),
            "groups": self.visible_in,
        });
        let map = json.as_object_mut().expect("an object");
        let mut opt = |key: &str, value: Option<serde_json::Value>| {
            if let Some(value) = value {
                map.insert(key.to_string(), value);
            }
        };
        opt(
            "filename",
            self.download_path
                .clone()
                .or_else(|| self.name.clone())
                .map(Into::into),
        );
        opt("name", self.name.clone().map(Into::into));
        opt("mimeType", self.mime_type.clone().map(Into::into));
        opt("creatorUid", self.creator_uid.clone().map(Into::into));
        opt("tool", self.tool.clone().map(Into::into));
        opt("latitude", self.latitude.map(Into::into));
        opt("longitude", self.longitude.map(Into::into));
        opt("altitude", self.altitude.map(Into::into));
        json
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new(uid: &str, groups: &[&str]) -> NewResource {
        NewResource {
            uid: uid.into(),
            name: Some(format!("{uid}.zip")),
            mime_type: Some("application/x-zip-compressed".into()),
            keywords: vec!["missionpackage".into()],
            submission_user: "alice".into(),
            creator_uid: Some("ANDROID-1".into()),
            tool: Some("public".into()),
            visible_in: groups.iter().map(|g| g.to_string()).collect(),
            ..Default::default()
        }
    }

    fn groups(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|g| g.to_string()).collect()
    }

    #[test]
    fn resources_are_visible_only_within_their_groups() {
        let store = ResourceStore::in_memory();
        store
            .insert(new("a", &["Red"]), &"a".repeat(64), 10, 1)
            .unwrap();
        store
            .insert(new("b", &["__ANON__"]), &"b".repeat(64), 10, 2)
            .unwrap();
        assert_eq!(store.visible(Some(&groups(&["Red"]))).len(), 1);
        assert_eq!(store.visible(Some(&groups(&["Blue"]))).len(), 0);
        assert_eq!(store.visible(None).len(), 2, "admin sees all");
    }

    #[test]
    fn metadata_json_uses_the_official_field_names_and_string_values() {
        let store = ResourceStore::in_memory();
        let r = store
            .insert(
                new("pkg", &["__ANON__"]),
                &"c".repeat(64),
                1234,
                1_760_716_800_005,
            )
            .unwrap();
        let json = r.metadata_json();
        assert_eq!(json["UID"], "pkg");
        assert_eq!(json["Size"], "1234");
        assert_eq!(json["PrimaryKey"], "1");
        assert_eq!(json["SubmissionDateTime"], "2025-10-17T16:00:00.5Z");
        assert_eq!(json["Keywords"], serde_json::json!(["missionpackage"]));
        assert_eq!(json["MIMEType"], "application/x-zip-compressed");
        let resource = r.resource_json();
        assert_eq!(resource["size"], 1234);
        assert_eq!(resource["expiration"], -1);
        assert!(resource.get("latitude").is_none(), "NON_NULL");
    }

    #[test]
    fn deletes_keywords_and_expiration_survive_a_reload() {
        let dir = std::env::temp_dir().join(format!("microtak-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("resources.log");
        let hash = "d".repeat(64);
        {
            let store = ResourceStore::load_or_create(&path).unwrap();
            store.insert(new("x", &["__ANON__"]), &hash, 1, 1).unwrap();
            store
                .insert(new("y", &["__ANON__"]), &"e".repeat(64), 1, 2)
                .unwrap();
            store.set_keywords(&hash, vec!["k1".into()]).unwrap();
            store.set_expiration(&hash, Some(99)).unwrap();
            store.delete_hash(&"e".repeat(64), None).unwrap();
        }
        let store = ResourceStore::load_or_create(&path).unwrap();
        let all = store.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].keywords, vec!["k1".to_string()]);
        assert_eq!(all[0].expiration, Some(99));
        assert!(store.hash_in_use(&hash) && !store.hash_in_use(&"e".repeat(64)));
        // Keys keep counting after a reload.
        assert_eq!(
            store
                .insert(new("z", &["__ANON__"]), &hash, 1, 3)
                .unwrap()
                .primary_key,
            3
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
