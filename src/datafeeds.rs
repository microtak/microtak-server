//! Data feeds, as the official TAK Server keeps them (`data_feed` with its
//! tags and filter groups; `com.bbn.marti.config.DataFeed` in CoreConfig):
//! named inputs whose events are marked as coming from the feed. A
//! streaming feed listens on its own port (see
//! [`crate::transport::feeds`]); missions can link feeds
//! (`/missions/{name}/feed`).
//!
//! Who may see a feed follows the official group vector: on creation the
//! feed's filter groups, after an update the updating user's groups
//! (`updateDataFeedWithGroupVector` with the request's vector).
//!
//! Persisted as an append-only, replayable event log like every other store.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum DataFeedError {
    #[error("no such data feed")]
    NotFound,
    #[error("An input with this name already exists.")]
    NameTaken,
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
}

/// One data feed: the official model's fields, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataFeed {
    pub uuid: String,
    pub name: String,
    /// `Streaming`, `API`, `Plugin`, `Federation` or `Predicate`.
    pub feed_type: String,
    pub tags: Vec<String>,
    /// The JAXB `AuthType` constant: `LDAP`, `FILE`, `ANONYMOUS`, `X_509`.
    pub auth: String,
    pub auth_required: bool,
    pub protocol: String,
    /// `None` for port 0 / none.
    pub port: Option<i32>,
    pub group: Option<String>,
    pub iface: Option<String>,
    pub archive: bool,
    pub anongroup: bool,
    pub archive_only: bool,
    pub sync: bool,
    pub core_version: i32,
    pub core_version2_tls_versions: Option<String>,
    pub filter_groups: Vec<String>,
    pub sync_cache_retention_seconds: i32,
    pub federated: bool,
    pub binary_payload_websocket_only: bool,
    /// Who may see it (the official `groups` bit vector), group names.
    pub visible_to: BTreeSet<String>,
}

impl DataFeed {
    pub fn reaches(&self, user_groups: &BTreeSet<String>) -> bool {
        !self.visible_to.is_disjoint(user_groups)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum DataFeedEvent {
    Saved { feed: Box<DataFeed> },
    Deleted { name: String },
}

fn apply(state: &mut Vec<DataFeed>, event: &DataFeedEvent) {
    match event {
        DataFeedEvent::Saved { feed } => {
            state.retain(|f| f.uuid != feed.uuid && f.name != feed.name);
            state.push((**feed).clone());
        }
        DataFeedEvent::Deleted { name } => state.retain(|f| f.name != *name),
    }
}

pub struct DataFeedStore {
    feeds: RwLock<Vec<DataFeed>>,
    log: Option<EventLog<DataFeedEvent>>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl DataFeedStore {
    pub fn in_memory() -> Self {
        Self {
            feeds: RwLock::new(Vec::new()),
            log: None,
            changes: tokio::sync::watch::Sender::new(0),
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, DataFeedError> {
        let mut feeds = Vec::new();
        let log = EventLog::open_and_replay(path, &mut feeds, apply)?;
        Ok(Self {
            feeds: RwLock::new(feeds),
            log: Some(log),
            changes: tokio::sync::watch::Sender::new(0),
        })
    }

    /// Ticks on every change, for whoever runs the feeds' listeners.
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn record(&self, feeds: &mut Vec<DataFeed>, event: DataFeedEvent) -> Result<(), DataFeedError> {
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply(feeds, &event);
        self.changes.send_modify(|n| *n += 1);
        Ok(())
    }

    pub fn all(&self) -> Vec<DataFeed> {
        let mut all = self.feeds.read().unwrap().clone();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        all
    }

    pub fn by_name(&self, name: &str) -> Option<DataFeed> {
        self.feeds
            .read()
            .unwrap()
            .iter()
            .find(|f| f.name == name)
            .cloned()
    }

    pub fn by_uuid(&self, uuid: &str) -> Option<DataFeed> {
        self.feeds
            .read()
            .unwrap()
            .iter()
            .find(|f| f.uuid == uuid)
            .cloned()
    }

    /// A new feed; its name must be free.
    pub fn create(&self, feed: DataFeed) -> Result<(), DataFeedError> {
        let mut feeds = self.feeds.write().unwrap();
        if feeds.iter().any(|f| f.name == feed.name) {
            return Err(DataFeedError::NameTaken);
        }
        self.record(
            &mut feeds,
            DataFeedEvent::Saved {
                feed: Box::new(feed),
            },
        )
    }

    /// Replace the feed called `name` with `feed` (which may rename it).
    pub fn replace(&self, name: &str, feed: DataFeed) -> Result<(), DataFeedError> {
        let mut feeds = self.feeds.write().unwrap();
        if !feeds.iter().any(|f| f.name == name) {
            return Err(DataFeedError::NotFound);
        }
        if feed.name != name && feeds.iter().any(|f| f.name == feed.name) {
            return Err(DataFeedError::NameTaken);
        }
        self.record(
            &mut feeds,
            DataFeedEvent::Deleted {
                name: name.to_string(),
            },
        )?;
        self.record(
            &mut feeds,
            DataFeedEvent::Saved {
                feed: Box::new(feed),
            },
        )
    }

    pub fn delete(&self, name: &str) -> Result<(), DataFeedError> {
        let mut feeds = self.feeds.write().unwrap();
        if !feeds.iter().any(|f| f.name == name) {
            return Err(DataFeedError::NotFound);
        }
        self.record(
            &mut feeds,
            DataFeedEvent::Deleted {
                name: name.to_string(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn feed(name: &str, uuid: &str) -> DataFeed {
        DataFeed {
            uuid: uuid.into(),
            name: name.into(),
            feed_type: "Streaming".into(),
            tags: vec![],
            auth: "ANONYMOUS".into(),
            auth_required: false,
            protocol: "stcp".into(),
            port: Some(18_088),
            group: None,
            iface: None,
            archive: true,
            anongroup: false,
            archive_only: false,
            sync: false,
            core_version: 2,
            core_version2_tls_versions: None,
            filter_groups: vec!["__ANON__".into()],
            sync_cache_retention_seconds: 3600,
            federated: true,
            binary_payload_websocket_only: false,
            visible_to: BTreeSet::from(["__ANON__".to_string()]),
        }
    }

    #[test]
    fn names_are_unique_and_changes_are_signalled() {
        let store = DataFeedStore::in_memory();
        let changes = store.changes();
        store.create(feed("aprs", "u1")).unwrap();
        assert!(matches!(
            store.create(feed("aprs", "u2")),
            Err(DataFeedError::NameTaken)
        ));
        assert_eq!(*changes.borrow(), 1);
        store.replace("aprs", feed("aprs2", "u1")).unwrap();
        assert!(store.by_name("aprs").is_none());
        assert_eq!(store.by_uuid("u1").unwrap().name, "aprs2");
        assert!(matches!(store.delete("nope"), Err(DataFeedError::NotFound)));
        store.delete("aprs2").unwrap();
        assert!(store.all().is_empty());
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-datafeeds-{}-{}",
            std::process::id(),
            crate::marti::envelope::random_uuid()
        ));
        let path = dir.join("datafeeds.log");
        {
            let store = DataFeedStore::load_or_create(&path).unwrap();
            store.create(feed("aprs", "u1")).unwrap();
            store.create(feed("mesh", "u2")).unwrap();
            store.delete("mesh").unwrap();
        }
        let store = DataFeedStore::load_or_create(&path).unwrap();
        assert_eq!(store.all(), vec![feed("aprs", "u1")]);
        std::fs::remove_dir_all(dir).ok();
    }
}
