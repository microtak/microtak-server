//! Mission (Data Sync) metadata store: create/update/delete missions,
//! track a change log per mission, and manage subscriptions.
//!
//! Implements the metadata half of `docs/TEST-PLAN.md` §5 — TC-MARTI-01,
//! 02, 03, 04, 05, 06, 11, and 12. **Not implemented here**: DataSync file
//! *content* storage (hash-addressed upload/download, TC-MARTI-07/08) —
//! this module tracks content *references* (a hash + filename a client
//! claims to have uploaded elsewhere), not the files themselves.
//!
//! Persisted as an append-only, replayable event log (see
//! [`crate::eventlog`]) — same design as
//! [`crate::registry::DeviceRegistry`], for the same reasons (see that
//! module's doc comment): cheap incremental backup, a full audit trail as
//! a side effect of the durability mechanism, and replay reconstructs
//! identical state rather than trusting a single snapshot file wasn't
//! left mid-write.
//!
//! **Concurrency policy (TC-MARTI-06)**: all mutations take the same
//! process-wide write lock (held across the fsync'd log append), so
//! concurrent requests are serialized, not interleaved — the second of two
//! concurrent updates to the same mission simply applies (and durably logs)
//! after the first completes (last-writer-wins per field), never a
//! torn/partially-applied write. No field-level conflict detection (e.g.
//! optimistic locking via a version number) is implemented.
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
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum MissionError {
    #[error("mission '{0}' already exists")]
    AlreadyExists(String),
    #[error("no mission found named '{0}'")]
    NotFound(String),
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
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
/// MicroTAK's own `PUT`, by contrast, is strict-create-only; see
/// `marti::missions`).
#[derive(Debug, Default)]
pub struct MissionUpdate {
    pub description: Option<String>,
    pub keywords: Option<Vec<String>>,
}

/// A durable, replayable record of one mission-store mutation. This is the
/// actual source of truth on disk — [`Mission`]/[`MissionChange`]/the
/// in-memory `HashMap` are a materialized view rebuilt by replaying these.
/// Deliberately mirrors the *inputs* to each public mutator method (not the
/// derived [`MissionChange`] shape, which is lighter and omits payload
/// `update`/`create` don't need replayed twice) — see [`apply_event`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum MissionEvent {
    Created {
        name: String,
        description: Option<String>,
        creator_uid: String,
        keywords: Vec<String>,
        at_unix: i64,
    },
    Updated {
        name: String,
        description: Option<String>,
        keywords: Option<Vec<String>>,
        actor_uid: String,
        at_unix: i64,
    },
    Deleted {
        name: String,
    },
    ContentAdded {
        name: String,
        hash: String,
        filename: String,
        creator_uid: String,
        at_unix: i64,
    },
    Subscribed {
        name: String,
        uid: String,
        at_unix: i64,
    },
    Unsubscribed {
        name: String,
        uid: String,
        at_unix: i64,
    },
}

pub struct MissionStore {
    missions: RwLock<HashMap<String, MissionRecord>>,
    log: Option<EventLog<MissionEvent>>,
}

impl MissionStore {
    pub fn in_memory() -> Self {
        Self {
            missions: RwLock::new(HashMap::new()),
            log: None,
        }
    }

    /// Load an existing store from `path` by replaying its event log, or
    /// start empty if the file doesn't exist yet. Every subsequent
    /// mutation appends to this same log.
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, MissionError> {
        let mut missions = HashMap::new();
        let log = EventLog::open_and_replay(path, &mut missions, apply_event)?;
        Ok(Self {
            missions: RwLock::new(missions),
            log: Some(log),
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

        let event = MissionEvent::Created {
            name: name.to_string(),
            description,
            creator_uid: creator_uid.to_string(),
            keywords,
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut missions, &event);
        Ok(missions.get(name).unwrap().mission.clone().unwrap())
    }

    /// TC-MARTI-12: MicroTAK's own answer — a partial update (only the
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
        if missions
            .get(name)
            .is_none_or(|record| record.mission.is_none())
        {
            return Err(MissionError::NotFound(name.to_string()));
        }

        let event = MissionEvent::Updated {
            name: name.to_string(),
            description: changes.description,
            keywords: changes.keywords,
            actor_uid: actor_uid.to_string(),
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut missions, &event);
        Ok(missions.get(name).unwrap().mission.clone().unwrap())
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

    /// Deletes the mission itself but keeps its change log queryable (see
    /// `apply_event` — no change-log entry is added for a delete, matching
    /// the pre-event-log behavior this preserves exactly): the mission
    /// becomes not-found for `get`/`update`, while `changes` still returns
    /// its history.
    pub fn delete(&self, name: &str) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        if missions
            .get(name)
            .is_none_or(|record| record.mission.is_none())
        {
            return Err(MissionError::NotFound(name.to_string()));
        }

        let event = MissionEvent::Deleted {
            name: name.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut missions, &event);
        Ok(())
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
        if missions
            .get(name)
            .is_none_or(|record| record.mission.is_none())
        {
            return Err(MissionError::NotFound(name.to_string()));
        }

        let event = MissionEvent::ContentAdded {
            name: name.to_string(),
            hash: content.hash,
            filename: content.filename,
            creator_uid: content.creator_uid,
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut missions, &event);
        Ok(())
    }

    /// TC-MARTI-04: idempotent -- subscribing an already-subscribed uid is
    /// a no-op success (and appends no event), not an error.
    pub fn subscribe(&self, name: &str, uid: &str, now_unix: i64) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        if record
            .mission
            .as_ref()
            .unwrap()
            .subscribers
            .iter()
            .any(|s| s == uid)
        {
            return Ok(());
        }

        let event = MissionEvent::Subscribed {
            name: name.to_string(),
            uid: uid.to_string(),
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut missions, &event);
        Ok(())
    }

    /// TC-MARTI-04. Idempotent in the same sense as `subscribe`.
    pub fn unsubscribe(&self, name: &str, uid: &str, now_unix: i64) -> Result<(), MissionError> {
        let mut missions = self.missions.write().unwrap();
        let record = missions
            .get(name)
            .filter(|r| r.mission.is_some())
            .ok_or_else(|| MissionError::NotFound(name.to_string()))?;
        if !record
            .mission
            .as_ref()
            .unwrap()
            .subscribers
            .iter()
            .any(|s| s == uid)
        {
            return Ok(());
        }

        let event = MissionEvent::Unsubscribed {
            name: name.to_string(),
            uid: uid.to_string(),
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut missions, &event);
        Ok(())
    }
}

/// The reducer: apply one durable event to in-memory state. Used both for
/// live mutations and for replaying the log on startup. Trusts its input —
/// idempotency/existence checks happen in the public methods *before* an
/// event is constructed and logged, so an event reaching here always
/// represents a genuine, already-validated state transition.
fn apply_event(missions: &mut HashMap<String, MissionRecord>, event: &MissionEvent) {
    match event {
        MissionEvent::Created {
            name,
            description,
            creator_uid,
            keywords,
            at_unix,
        } => {
            let mission = Mission {
                name: name.clone(),
                description: description.clone(),
                creator_uid: creator_uid.clone(),
                created_at_unix: *at_unix,
                keywords: keywords.clone(),
                contents: Vec::new(),
                subscribers: Vec::new(),
            };
            let record = missions.entry(name.clone()).or_default();
            record.mission = Some(mission);
            record.changes.push(MissionChange {
                change_type: ChangeType::Create,
                timestamp_unix: *at_unix,
                creator_uid: creator_uid.clone(),
                content_hash: None,
            });
        }
        MissionEvent::Updated {
            name,
            description,
            keywords,
            actor_uid,
            at_unix,
        } => {
            if let Some(record) = missions.get_mut(name) {
                if let Some(mission) = record.mission.as_mut() {
                    if let Some(description) = description {
                        mission.description = Some(description.clone());
                    }
                    if let Some(keywords) = keywords {
                        mission.keywords = keywords.clone();
                    }
                }
                record.changes.push(MissionChange {
                    change_type: ChangeType::Update,
                    timestamp_unix: *at_unix,
                    creator_uid: actor_uid.clone(),
                    content_hash: None,
                });
            }
        }
        MissionEvent::Deleted { name } => {
            if let Some(record) = missions.get_mut(name) {
                record.mission = None;
            }
        }
        MissionEvent::ContentAdded {
            name,
            hash,
            filename,
            creator_uid,
            at_unix,
        } => {
            if let Some(record) = missions.get_mut(name) {
                // Matches the pre-event-log behavior exactly: the change
                // log entry's creator_uid is the *mission's* creator, not
                // necessarily the uploader's -- preserved as-is rather than
                // silently changed by this refactor.
                let mission_creator_uid = record
                    .mission
                    .as_ref()
                    .map(|m| m.creator_uid.clone())
                    .unwrap_or_else(|| creator_uid.clone());
                if let Some(mission) = record.mission.as_mut() {
                    mission.contents.push(MissionContentRef {
                        hash: hash.clone(),
                        filename: filename.clone(),
                        added_at_unix: *at_unix,
                        creator_uid: creator_uid.clone(),
                    });
                }
                record.changes.push(MissionChange {
                    change_type: ChangeType::AddContent,
                    timestamp_unix: *at_unix,
                    creator_uid: mission_creator_uid,
                    content_hash: Some(hash.clone()),
                });
            }
        }
        MissionEvent::Subscribed { name, uid, at_unix } => {
            if let Some(record) = missions.get_mut(name) {
                if let Some(mission) = record.mission.as_mut() {
                    mission.subscribers.push(uid.clone());
                }
                record.changes.push(MissionChange {
                    change_type: ChangeType::Subscribe,
                    timestamp_unix: *at_unix,
                    creator_uid: uid.clone(),
                    content_hash: None,
                });
            }
        }
        MissionEvent::Unsubscribed { name, uid, at_unix } => {
            if let Some(record) = missions.get_mut(name) {
                if let Some(mission) = record.mission.as_mut() {
                    mission.subscribers.retain(|s| s != uid);
                }
                record.changes.push(MissionChange {
                    change_type: ChangeType::Unsubscribe,
                    timestamp_unix: *at_unix,
                    creator_uid: uid.clone(),
                    content_hash: None,
                });
            }
        }
    }
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
        let dir = std::env::temp_dir().join(format!("microtak-missions-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missions.log");

        {
            let store = MissionStore::load_or_create(&path).unwrap();
            store.create("m", Some("d".into()), "user-1", vec![], 1_000).unwrap();
        }

        let reloaded = MissionStore::load_or_create(&path).unwrap();
        let mission = reloaded.get("m").unwrap();
        assert_eq!(mission.description.as_deref(), Some("d"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The whole point: replaying the log reproduces identical state,
    /// including a delete (no change-log entry, verified via `changes`
    /// still returning history for a now-deleted mission) and idempotent
    /// operations that deliberately appended no event.
    #[test]
    fn replay_reconstructs_a_realistic_mutation_sequence_exactly() {
        let dir = std::env::temp_dir().join(format!("microtak-missions-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missions.log");

        {
            let store = MissionStore::load_or_create(&path).unwrap();
            store.create("m1", None, "user-1", vec![], 1_000).unwrap();
            store.create("m2", Some("keep".into()), "user-2", vec![], 1_100).unwrap();
            store.subscribe("m1", "device-a", 1_200).unwrap();
            store.subscribe("m1", "device-a", 1_300).unwrap(); // idempotent, no event
            store
                .update(
                    "m2",
                    MissionUpdate { description: Some("updated".into()), keywords: None },
                    "user-2",
                    1_400,
                )
                .unwrap();
            store.delete("m1").unwrap();
        }

        let replayed = MissionStore::load_or_create(&path).unwrap();
        assert!(replayed.get("m1").is_none(), "m1 was deleted");
        assert_eq!(
            replayed.changes("m1").unwrap().len(),
            2,
            "m1's history (create + subscribe) survives even though the mission itself is gone"
        );
        let m2 = replayed.get("m2").unwrap();
        assert_eq!(m2.description.as_deref(), Some("updated"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
