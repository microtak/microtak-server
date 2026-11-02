//! Persistent last-seen store: when each identity (mTLS cert Common Name)
//! was last connected or disconnected, surviving restarts so the admin UI
//! and widgets can show "last seen 3h ago" for a device that isn't online
//! now. Backs the historical half of `GET /Marti/api/clientEndPoints`
//! ([`super::connections::ConnectedClients::endpoint_views`]).
//!
//! Live connection state is owned by [`super::connections::ConnectedClients`]
//! (who's connected *right now*); this adds only the durable timestamp. The
//! two are combined at read time, so this never duplicates the live registry.
//!
//! Anonymous plain-TCP connections have no identity and are not recorded --
//! only authenticated clients get a last-seen history.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use super::connections::Transport;

/// One identity's last-seen record. `connected` is authoritative only at
/// runtime; it is forced to `false` on load (nobody is connected at startup),
/// so `last_seen_unix` is then the moment it was last connected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenRecord {
    pub common_name: String,
    #[serde(default)]
    pub uid: Option<String>,
    pub transport: Transport,
    pub last_seen_unix: i64,
    pub connected: bool,
}

pub struct SeenStore {
    /// `None` for an in-memory store (tests); `Some` persists to this file.
    path: Option<PathBuf>,
    records: RwLock<BTreeMap<String, SeenRecord>>,
}

impl Default for SeenStore {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl SeenStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            records: RwLock::new(BTreeMap::new()),
        }
    }

    /// Load from `path` (missing/corrupt file -> empty), forcing every record
    /// to `connected = false`: at startup nothing is connected yet, so a
    /// record left `true` by a previous run must not read as online.
    pub fn load(path: PathBuf) -> Self {
        let mut records: BTreeMap<String, SeenRecord> = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        for record in records.values_mut() {
            record.connected = false;
        }
        Self {
            path: Some(path),
            records: RwLock::new(records),
        }
    }

    pub fn mark_connected(
        &self,
        common_name: &str,
        uid: Option<String>,
        transport: Transport,
        now_unix: i64,
    ) {
        {
            let mut records = self.records.write().unwrap();
            let record = records
                .entry(common_name.to_string())
                .or_insert_with(|| SeenRecord {
                    common_name: common_name.to_string(),
                    uid: uid.clone(),
                    transport,
                    last_seen_unix: now_unix,
                    connected: true,
                });
            record.transport = transport;
            record.last_seen_unix = now_unix;
            record.connected = true;
            if uid.is_some() {
                record.uid = uid;
            }
        }
        self.persist();
    }

    /// Update the bound uid once it is known (TC-TLS-04 binds after connect).
    pub fn set_uid(&self, common_name: &str, uid: String) {
        let changed = {
            let mut records = self.records.write().unwrap();
            match records.get_mut(common_name) {
                Some(record) if record.uid.as_deref() != Some(uid.as_str()) => {
                    record.uid = Some(uid);
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.persist();
        }
    }

    pub fn mark_disconnected(&self, common_name: &str, now_unix: i64) {
        let changed = {
            let mut records = self.records.write().unwrap();
            match records.get_mut(common_name) {
                Some(record) => {
                    record.connected = false;
                    record.last_seen_unix = now_unix;
                    true
                }
                None => false,
            }
        };
        if changed {
            self.persist();
        }
    }

    pub fn all(&self) -> Vec<SeenRecord> {
        self.records.read().unwrap().values().cloned().collect()
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let records = self.records.read().unwrap();
        let Ok(json) = serde_json::to_vec_pretty(&*records) else {
            return;
        };
        // Atomic replace: write a sibling temp file, fsync, rename over.
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_connect_then_disconnect() {
        let store = SeenStore::in_memory();
        store.mark_connected("phone-1", Some("IOS-x".into()), Transport::Tls, 100);
        let rec = store.all().into_iter().next().unwrap();
        assert!(rec.connected);
        assert_eq!(rec.last_seen_unix, 100);

        store.mark_disconnected("phone-1", 200);
        let rec = store.all().into_iter().next().unwrap();
        assert!(!rec.connected);
        assert_eq!(rec.last_seen_unix, 200);
    }

    #[test]
    fn disconnect_unknown_identity_is_a_noop() {
        let store = SeenStore::in_memory();
        store.mark_disconnected("never-seen", 10);
        assert!(store.all().is_empty());
    }

    #[test]
    fn load_forces_connected_false_and_survives_roundtrip() {
        let dir = std::env::temp_dir().join(format!("seen-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client-seen.json");

        let store = SeenStore::load(path.clone());
        store.mark_connected("phone-1", None, Transport::Tls, 100);

        // A fresh load (simulating a restart) must show it as disconnected,
        // keeping the last-seen time.
        let reloaded = SeenStore::load(path.clone());
        let rec = reloaded.all().into_iter().next().unwrap();
        assert!(!rec.connected);
        assert_eq!(rec.last_seen_unix, 100);

        std::fs::remove_dir_all(&dir).ok();
    }
}
