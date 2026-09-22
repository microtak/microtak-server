//! Mission (Data Sync) metadata store: create/update/delete missions,
//! track a change log per mission, and manage subscriptions.
//!
//! Implements the metadata half of `docs/TEST-PLAN.md` §5 — TC-MARTI-01,
//! 02, 03, 04, 05, 06, 11, and 12. **Not implemented here**: DataSync file
//! *content* storage (hash-addressed upload/download, TC-MARTI-07/08) —
//! this module tracks content *references* (a hash + filename a client
//! claims to have uploaded elsewhere), not the files themselves.
//!
//! Same JSON-file-backed design as [`crate::registry::DeviceRegistry`], for
//! the same reasons (see that module's doc comment) — kept consistent
//! rather than introducing a different persistence approach for a second
//! piece of state at a similar scale.
//!
//! **Concurrency policy (TC-MARTI-06)**: all mutations take the same
//! process-wide write lock, so concurrent requests are serialized, not
//! interleaved — the second of two concurrent updates to the same mission
//! simply applies after the first completes (last-writer-wins per field),
//! never a torn/partially-applied write. No field-level conflict detection
//! (e.g. optimistic locking via a version number) is implemented.
//!
//! **Name handling (TC-MARTI-03/11)**: mission names are used verbatim as
//! an opaque `HashMap` key — no sanitization (HTML-stripping or otherwise)
//! is applied anywhere, on purpose. A real reference implementation this
//! project studied sanitized a mission's name on creation but looked it up
//! unsanitized everywhere else, orphaning any mission whose name contained
//! sanitizable characters. Never sanitizing avoids that entire bug class by
//! construction, since names are never rendered as HTML or otherwise
//! interpreted here — they're just an identifier.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MissionError {
    #[error("mission '{0}' already exists")]
    AlreadyExists(String),
    #[error("no mission found named '{0}'")]
    NotFound(String),
    #[error("failed to read mission store file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write mission store file {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to (de)serialize mission store: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mission {
    pub name: String,
    pub description: Option<String>,
    pub creator_uid: String,
    pub created_at_unix: i64,
    pub keywords: Vec<String>,
    pub contents: Vec<MissionContentRef>,
    pub subscribers: Vec<String>,
}

/// A reference to Data Package content associated with a mission — just
/// the hash/filename a client claims, not the file itself (see this
/// module's doc comment on scope).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissionContentRef {
    pub hash: String,
    pub filename: String,
    pub added_at_unix: i64,
    pub creator_uid: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissionChange {
    pub change_type: ChangeType,
    pub timestamp_unix: i64,
    pub creator_uid: String,
    /// Set for `AddContent`/`RemoveContent`; `None` otherwise.
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Create,
    Update,
    AddContent,
    RemoveContent,
    Subscribe,
    Unsubscribe,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct MissionRecord {
    mission: Option<Mission>,
    changes: Vec<MissionChange>,
}

/// Fields an update (`MissionStore::update`) may change; a `None` field is
/// left as-is, matching PATCH's "only touch what's provided" semantics
/// (contrast with a reference implementation's `PUT`-as-merge behavior,
/// documented as a real, confirmed gap in `docs/TEST-PLAN.md` TC-MARTI-12 —
/// EdgeTAK's own `PUT`, by contrast, is strict-create-only; see
/// `marti::missions`).
#[derive(Debug, Default)]
pub struct MissionUpdate {
    pub description: Option<String>,
    pub keywords: Option<Vec<String>>,
}

pub struct MissionStore {
    path: Option<PathBuf>,
    missions: RwLock<HashMap<String, MissionRecord>>,
}

impl MissionStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            missions: RwLock::new(HashMap::new()),
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, MissionError> {
        let path = path.into();
        let missions = match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(source) => return Err(MissionError::Read { path, source }),
        };
        Ok(Self {
            path: Some(path),
            missions: RwLock::new(missions),
        })
    }

    /// TC-MARTI-01/02: strict create — errors if `name` is already taken.
    pub fn create(
        &self,
        name: &str,
        description: Option<String>,
        creator_uid: &str,
        keywords: Vec<String>,
        now_unix: i64,
    ) -> Result<Mission, MissionError> {
        let mut missions = self.missions.write().unwrap();
        if missions
            .get(name)
            .is_some_and(|record| record.mission.is_some())
        {
            return Err(MissionError::AlreadyExists(name.to_string()));
        }

        let mission = Mission {
            name: name.to_string(),
            description,
            creator_uid: creator_uid.to_string(),
            created_at_unix: now_unix,
            keywords,
            contents: Vec::new(),
            subscribers: Vec::new(),
        };
        let record = missions.entry(name.to_string()).or_default();
        record.mission = Some(mission.clone());
        record.changes.push(MissionChange {
            change_type: ChangeType::Create,
            timestamp_unix: now_unix,
            creator_uid: creator_uid.to_string(),
            content_hash: None,
        });
        drop(missions);
        self.persist()?;
        Ok(mission)
    }

    /// TC-MARTI-12: EdgeTAK's own answer — a partial update (only the
    /// provided fields change), not the full-replace semantics `PUT` would
    /// otherwise invite ambiguity about.
    pub fn update(
        &self,
        name: &str,
        changes: MissionUpdate,
        actor_uid: &str,
        now_unix: i64,
    ) -> Result<Mission, MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get_mut(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        let mission = record.mission.as_mut().unwrap();

        if let Some(description) = changes.description {
            mission.description = Some(description);
        }
        if let Some(keywords) = changes.keywords {
            mission.keywords = keywords;
        }
        let updated = mission.clone();
        record.changes.push(MissionChange {
            change_type: ChangeType::Update,
            timestamp_unix: now_unix,
            creator_uid: actor_uid.to_string(),
            content_hash: None,
        });
        drop(missions);
        self.persist()?;
        Ok(updated)
    }

    pub fn get(&self, name: &str) -> Option<Mission> {
        self.missions
            .read()
            .unwrap()
            .get(name)
            .and_then(|r| r.mission.clone())
    }

    pub fn list(&self) -> Vec<Mission> {
        self.missions
            .read()
            .unwrap()
            .values()
            .filter_map(|r| r.mission.clone())
            .collect()
    }

    /// Deletes the mission itself but keeps its change log (with a final
    /// entry appended would be the natural next step; not yet done here) --
    /// simplest correct behavior for now: the mission becomes not-found for
    /// `get`/`update`, while `changes` still returns its history.
    pub fn delete(&self, name: &str) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get_mut(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        record.mission = None;
        drop(missions);
        self.persist()
    }

    /// TC-MARTI-05.
    pub fn changes(&self, name: &str) -> Result<Vec<MissionChange>, MissionError> {
        self.missions
            .read()
            .unwrap()
            .get(name)
            .map(|r| r.changes.clone())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))
    }

    pub fn add_content(
        &self,
        name: &str,
        content: MissionContentRef,
        now_unix: i64,
    ) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get_mut(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        let hash = content.hash.clone();
        record.mission.as_mut().unwrap().contents.push(content);
        record.changes.push(MissionChange {
            change_type: ChangeType::AddContent,
            timestamp_unix: now_unix,
            creator_uid: record.mission.as_ref().unwrap().creator_uid.clone(),
            content_hash: Some(hash),
        });
        drop(missions);
        self.persist()
    }

    /// TC-MARTI-04: idempotent -- subscribing an already-subscribed uid is
    /// a no-op success, not an error.
    pub fn subscribe(&self, name: &str, uid: &str, now_unix: i64) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get_mut(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        let mission = record.mission.as_mut().unwrap();
        if mission.subscribers.iter().any(|s| s == uid) {
            return Ok(());
        }
        mission.subscribers.push(uid.to_string());
        record.changes.push(MissionChange {
            change_type: ChangeType::Subscribe,
            timestamp_unix: now_unix,
            creator_uid: uid.to_string(),
            content_hash: None,
        });
        drop(missions);
        self.persist()
    }

    /// TC-MARTI-04. Idempotent in the same sense as `subscribe`.
    pub fn unsubscribe(&self, name: &str, uid: &str, now_unix: i64) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get_mut(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        let mission = record.mission.as_mut().unwrap();
        let before = mission.subscribers.len();
        mission.subscribers.retain(|s| s != uid);
        if mission.subscribers.len() != before {
            record.changes.push(MissionChange {
                change_type: ChangeType::Unsubscribe,
                timestamp_unix: now_unix,
                creator_uid: uid.to_string(),
                content_hash: None,
            });
        }
        drop(missions);
        self.persist()
    }

    fn persist(&self) -> Result<(), MissionError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let missions = self.missions.read().unwrap();
        let json = serde_json::to_string_pretty(&*missions)?;
        write_atomically(path, &json).map_err(|source| MissionError::Write {
            path: path.clone(),
            source,
        })
    }
}

fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_marti_01_creates_gets_and_deletes_a_mission() {
        let store = MissionStore::in_memory();
        let created = store
            .create("Recon Alpha", Some("desc".into()), "user-1", vec![], 1_000)
            .unwrap();
        assert_eq!(created.name, "Recon Alpha");

        let fetched = store.get("Recon Alpha").unwrap();
        assert_eq!(fetched, created);

        store.delete("Recon Alpha").unwrap();
        assert!(store.get("Recon Alpha").is_none());
    }

    #[test]
    fn tc_marti_02_rejects_creating_a_duplicate_name() {
        let store = MissionStore::in_memory();
        store.create("dup", None, "user-1", vec![], 1_000).unwrap();
        let result = store.create("dup", None, "user-1", vec![], 2_000);
        assert!(matches!(result, Err(MissionError::AlreadyExists(_))));
    }

    #[test]
    fn tc_marti_03_names_with_url_reserved_characters_round_trip() {
        let store = MissionStore::in_memory();
        let name = "Recon Reppenstedt & Buchholz/Nord 50%";
        store.create(name, None, "user-1", vec![], 1_000).unwrap();
        assert!(store.get(name).is_some());
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn tc_marti_12_update_only_changes_provided_fields() {
        let store = MissionStore::in_memory();
        store
            .create(
                "m",
                Some("original".into()),
                "user-1",
                vec!["k1".into()],
                1_000,
            )
            .unwrap();

        let updated = store
            .update(
                "m",
                MissionUpdate {
                    description: Some("new".into()),
                    keywords: None,
                },
                "user-2",
                2_000,
            )
            .unwrap();

        assert_eq!(updated.description.as_deref(), Some("new"));
        assert_eq!(updated.keywords, vec!["k1".to_string()]); // untouched
    }

    #[test]
    fn update_on_missing_mission_errors() {
        let store = MissionStore::in_memory();
        let result = store.update("nope", MissionUpdate::default(), "user-1", 1_000);
        assert!(matches!(result, Err(MissionError::NotFound(_))));
    }

    #[test]
    fn tc_marti_05_changes_reflect_full_history() {
        let store = MissionStore::in_memory();
        store.create("m", None, "user-1", vec![], 1_000).unwrap();
        store
            .update(
                "m",
                MissionUpdate {
                    description: Some("d".into()),
                    keywords: None,
                },
                "user-1",
                2_000,
            )
            .unwrap();
        store
            .add_content(
                "m",
                MissionContentRef {
                    hash: "abc123".into(),
                    filename: "map.kml".into(),
                    added_at_unix: 3_000,
                    creator_uid: "user-1".into(),
                },
                3_000,
            )
            .unwrap();
        store.subscribe("m", "user-2", 4_000).unwrap();

        let changes = store.changes("m").unwrap();
        assert_eq!(changes.len(), 4);
        assert_eq!(changes[0].change_type, ChangeType::Create);
        assert_eq!(changes[1].change_type, ChangeType::Update);
        assert_eq!(changes[2].change_type, ChangeType::AddContent);
        assert_eq!(changes[2].content_hash.as_deref(), Some("abc123"));
        assert_eq!(changes[3].change_type, ChangeType::Subscribe);
    }

    #[test]
    fn tc_marti_04_subscribe_and_unsubscribe_are_idempotent() {
        let store = MissionStore::in_memory();
        store.create("m", None, "user-1", vec![], 1_000).unwrap();

        store.subscribe("m", "user-2", 2_000).unwrap();
        store.subscribe("m", "user-2", 3_000).unwrap(); // no-op, no error
        assert_eq!(store.get("m").unwrap().subscribers, vec!["user-2"]);

        store.unsubscribe("m", "user-2", 4_000).unwrap();
        store.unsubscribe("m", "user-2", 5_000).unwrap(); // no-op, no error
        assert!(store.get("m").unwrap().subscribers.is_empty());
    }

    #[test]
    fn tc_marti_06_concurrent_updates_serialize_without_corruption() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(MissionStore::in_memory());
        store.create("m", None, "user-1", vec![], 1_000).unwrap();

        let mut handles = Vec::new();
        for i in 0..20 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store
                    .update(
                        "m",
                        MissionUpdate {
                            description: Some(format!("update-{i}")),
                            keywords: None,
                        },
                        "user-1",
                        1_000 + i,
                    )
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        // Not corrupted: exactly one well-formed description survives (one
        // of the 20 writers', not a torn/partial value), and the full
        // change history has one Create + 20 Update entries.
        let final_mission = store.get("m").unwrap();
        assert!(final_mission
            .description
            .as_deref()
            .is_some_and(|d| d.starts_with("update-")));
        assert_eq!(store.changes("m").unwrap().len(), 21);
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir().join(format!("edgetak-missions-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missions.json");

        {
            let store = MissionStore::load_or_create(&path).unwrap();
            store.create("m", Some("d".into()), "user-1", vec![], 1_000).unwrap();
        }

        let reloaded = MissionStore::load_or_create(&path).unwrap();
        let mission = reloaded.get("m").unwrap();
        assert_eq!(mission.description.as_deref(), Some("d"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
