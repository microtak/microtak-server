//! Generic append-only, replayable event log — the durability and audit
//! mechanism for EdgeTAK's administrative state ([`crate::registry`],
//! [`crate::missions`]).
//!
//! Each mutation appends one fsync'd JSON-Lines record instead of
//! rewriting a full-state snapshot; startup replays every record in order
//! to reconstruct state. This doubles as the backup mechanism (see
//! `docs/ARCHITECTURE.md`'s backup section): because the file is
//! append-only, `rsync`/`scp`/`aws s3 sync` only need to transfer bytes
//! appended since the last backup, not the whole file every time — and
//! replaying a backed-up log elsewhere reconstructs byte-identical state,
//! not "hopefully this snapshot wasn't mid-write." It's also, as a direct
//! consequence rather than a bolted-on feature, a full audit trail of who
//! changed what and when.
//!
//! **Crash-consistency contract**: [`EventLog::append`] fsyncs before
//! returning. Callers apply an event to in-memory state only *after* a
//! successful append (see `registry.rs`/`missions.rs`), so nothing becomes
//! visible to a reader until it's already durable — there's no window
//! where an operation looks like it succeeded but isn't actually persisted.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventLogError {
    #[error("failed to open event log {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to append to event log {path}: {source}")]
    Append {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read event log {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("corrupt event log {path} at line {line}: {source}")]
    Corrupt {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

pub struct EventLog<E> {
    path: PathBuf,
    file: Mutex<File>,
    _marker: PhantomData<E>,
}

impl<E: Serialize + DeserializeOwned> EventLog<E> {
    /// Open (creating if needed) the log at `path`, replaying every
    /// existing record through `apply` in order to reconstruct `state`
    /// before returning. A log that doesn't exist yet replays zero events
    /// (an empty/fresh store), matching
    /// [`crate::registry::DeviceRegistry::in_memory`]-style "start empty"
    /// semantics.
    pub fn open_and_replay<S>(
        path: impl Into<PathBuf>,
        state: &mut S,
        mut apply: impl FnMut(&mut S, &E),
    ) -> Result<Self, EventLogError> {
        let path = path.into();

        if let Ok(existing) = File::open(&path) {
            let reader = BufReader::new(existing);
            for (i, line) in reader.lines().enumerate() {
                let line = line.map_err(|source| EventLogError::Read {
                    path: path.clone(),
                    source,
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let event: E = serde_json::from_str(&line).map_err(|source| {
                    EventLogError::Corrupt {
                        path: path.clone(),
                        line: i + 1,
                        source,
                    }
                })?;
                apply(state, &event);
            }
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| EventLogError::Open {
                path: path.clone(),
                source,
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| EventLogError::Open {
                path: path.clone(),
                source,
            })?;

        Ok(Self {
            path,
            file: Mutex::new(file),
            _marker: PhantomData,
        })
    }

    /// Append one event, fsync'd before returning. See the module-level
    /// doc comment's crash-consistency contract: callers must not apply
    /// the event to in-memory state until this returns `Ok`.
    pub fn append(&self, event: &E) -> Result<(), EventLogError> {
        let mut file = self.file.lock().unwrap();
        let json = serde_json::to_string(event).expect("event serialization should not fail");
        writeln!(file, "{json}").map_err(|source| EventLogError::Append {
            path: self.path.clone(),
            source,
        })?;
        file.sync_data().map_err(|source| EventLogError::Append {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    enum TestEvent {
        Set(i64),
        Add(i64),
    }

    fn apply(state: &mut i64, event: &TestEvent) {
        match event {
            TestEvent::Set(n) => *state = *n,
            TestEvent::Add(n) => *state += *n,
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "edgetak-eventlog-test-{label}-{}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn replays_events_in_order_to_reconstruct_state() {
        let path = unique_temp_path("replay");
        std::fs::remove_file(&path).ok();

        {
            let mut state = 0i64;
            let log = EventLog::open_and_replay(&path, &mut state, apply).unwrap();
            log.append(&TestEvent::Set(10)).unwrap();
            log.append(&TestEvent::Add(5)).unwrap();
            log.append(&TestEvent::Add(-3)).unwrap();
        }

        let mut state = 0i64;
        let _log = EventLog::open_and_replay(&path, &mut state, apply).unwrap();
        assert_eq!(state, 12);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn creates_a_missing_parent_directory() {
        let dir = std::env::temp_dir().join(format!(
            "edgetak-eventlog-test-parentdir-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok(); // must not exist yet
        let path = dir.join("nested").join("events.jsonl");

        let mut state = 0i64;
        let log = EventLog::open_and_replay(&path, &mut state, apply).unwrap();
        log.append(&TestEvent::Set(1)).unwrap();
        assert!(path.exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_log_file_replays_as_empty() {
        let path = unique_temp_path("missing");
        std::fs::remove_file(&path).ok();

        let mut state = 42i64;
        let _log = EventLog::open_and_replay(&path, &mut state, apply).unwrap();
        assert_eq!(state, 42, "no events to replay -- state must be untouched");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_line_is_a_clean_error_not_a_panic() {
        let path = unique_temp_path("corrupt");
        std::fs::write(&path, "{\"Set\":1}\nnot valid json\n").unwrap();

        let mut state = 0i64;
        let result = EventLog::<TestEvent>::open_and_replay(&path, &mut state, apply);
        assert!(matches!(result, Err(EventLogError::Corrupt { line: 2, .. })));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn append_is_durable_across_a_fresh_open() {
        let path = unique_temp_path("durable");
        std::fs::remove_file(&path).ok();

        {
            let mut state = 0i64;
            let log = EventLog::open_and_replay(&path, &mut state, apply).unwrap();
            log.append(&TestEvent::Set(7)).unwrap();
        } // log dropped, file closed

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);

        std::fs::remove_file(&path).ok();
    }
}
