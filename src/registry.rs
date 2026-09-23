//! Device (EUD) registry: tracks enrolled devices by certificate Common
//! Name, and binds each to the CoT `uid` it's authorized to assert.
//!
//! Persisted as an append-only, replayable event log (see
//! [`crate::eventlog`]) rather than a snapshot rewritten on every
//! mutation — appropriate at the scale this project targets (a home/ham
//! deployment, not thousands of concurrent devices), and it's what makes
//! this store's file cheap to back up incrementally (only newly-appended
//! events need shipping) and gives a full audit trail as a side effect of
//! the durability mechanism, not a bolted-on feature — see
//! `docs/ARCHITECTURE.md`'s backup section.
//!
//! Implements the enrollment side of `docs/TEST-PLAN.md` §4 (recording a
//! signed device alongside its cert) and the identity-binding side of §3
//! TC-TLS-04 (rejecting a connection that claims a `uid` belonging to a
//! different, already-enrolled device).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("no device found with common name '{0}'")]
    NotFound(String),
    #[error("uid '{uid}' is already bound to a different device (common name '{owner}')")]
    UidOwnedByOtherDevice { uid: String, owner: String },
    #[error(
        "device '{common_name}' already claims uid '{existing}', cannot rebind to '{claimed}'"
    )]
    DeviceUidMismatch {
        common_name: String,
        existing: String,
        claimed: String,
    },
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub common_name: String,
    pub cert_pem: String,
    pub enrolled_at_unix: i64,
    pub revoked: bool,
    /// The CoT `uid` this device has been observed asserting, bound on
    /// first use (trust-on-first-use) — `None` until the device's first
    /// CoT event arrives over an authenticated connection. See TC-TLS-04.
    pub uid: Option<String>,
}

/// A durable, replayable record of one registry mutation. This is the
/// actual source of truth on disk — [`DeviceRecord`]/the in-memory
/// `HashMap` are a materialized view rebuilt by replaying these.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum RegistryEvent {
    Enrolled {
        common_name: String,
        cert_pem: String,
        at_unix: i64,
    },
    Revoked {
        common_name: String,
    },
    UidBound {
        common_name: String,
        uid: String,
    },
}

pub struct DeviceRegistry {
    devices: RwLock<HashMap<String, DeviceRecord>>,
    log: Option<EventLog<RegistryEvent>>,
}

impl DeviceRegistry {
    /// An ephemeral, non-persisted registry — for tests, or a deliberately
    /// stateless run.
    pub fn in_memory() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            log: None,
        }
    }

    /// Load an existing registry from `path` by replaying its event log,
    /// or start empty if the file doesn't exist yet. Every subsequent
    /// mutation appends to this same log.
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let mut devices = HashMap::new();
        let log = EventLog::open_and_replay(path, &mut devices, apply_event)?;
        Ok(Self {
            devices: RwLock::new(devices),
            log: Some(log),
        })
    }

    /// Enroll a device, or re-enroll an already-known common name with a
    /// new certificate (rotation) — see TC-ENROLL-04/TC-OTS-12. The
    /// existing `uid` binding *and* revocation status, if any, are
    /// preserved across re-enrollment: re-enrolling must not be usable as a
    /// backdoor to silently clear a prior revocation. Un-revoking is a
    /// separate, explicit action (not yet implemented — no `unrevoke`
    /// method exists today).
    pub fn enroll(
        &self,
        common_name: &str,
        cert_pem: &str,
        now_unix: i64,
    ) -> Result<DeviceRecord, RegistryError> {
        let mut devices = self.devices.write().unwrap();
        let event = RegistryEvent::Enrolled {
            common_name: common_name.to_string(),
            cert_pem: cert_pem.to_string(),
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut devices, &event);
        Ok(devices.get(common_name).unwrap().clone())
    }

    pub fn find(&self, common_name: &str) -> Option<DeviceRecord> {
        self.devices.read().unwrap().get(common_name).cloned()
    }

    pub fn is_revoked(&self, common_name: &str) -> bool {
        self.devices
            .read()
            .unwrap()
            .get(common_name)
            .map(|d| d.revoked)
            .unwrap_or(false)
    }

    pub fn revoke(&self, common_name: &str) -> Result<(), RegistryError> {
        let mut devices = self.devices.write().unwrap();
        if !devices.contains_key(common_name) {
            return Err(RegistryError::NotFound(common_name.to_string()));
        }
        let event = RegistryEvent::Revoked {
            common_name: common_name.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut devices, &event);
        Ok(())
    }

    /// Bind `uid` to `common_name`, enforcing TC-TLS-04: a `uid` already
    /// claimed by a *different* enrolled device is rejected outright
    /// (cross-device spoofing defense). The same device re-asserting the
    /// same `uid` it already owns is a no-op success (the expected steady
    /// state, since a connected device re-sends its self-ID atom
    /// periodically) and does **not** append a new event — the log only
    /// ever records genuine state transitions. A device that has already
    /// bound a different `uid` attempting to bind yet another one is also
    /// rejected — MicroTAK treats a device's `uid` as fixed once bound, a
    /// deliberate simplification (see `docs/ARCHITECTURE.md`) vs.
    /// real-world devices that might legitimately change identity (e.g.
    /// app reinstall); revoking and re-enrolling is the escape hatch for
    /// that case.
    pub fn bind_uid(&self, common_name: &str, uid: &str) -> Result<(), RegistryError> {
        let mut devices = self.devices.write().unwrap();

        if let Some(owner) = devices
            .values()
            .find(|d| d.uid.as_deref() == Some(uid) && d.common_name != common_name)
        {
            return Err(RegistryError::UidOwnedByOtherDevice {
                uid: uid.to_string(),
                owner: owner.common_name.clone(),
            });
        }

        let device = devices
            .get(common_name)
            .ok_or_else(|| RegistryError::NotFound(common_name.to_string()))?;

        match &device.uid {
            None => {}
            Some(existing) if existing == uid => return Ok(()), // idempotent, no event
            Some(existing) => {
                return Err(RegistryError::DeviceUidMismatch {
                    common_name: common_name.to_string(),
                    existing: existing.clone(),
                    claimed: uid.to_string(),
                });
            }
        }

        let event = RegistryEvent::UidBound {
            common_name: common_name.to_string(),
            uid: uid.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut devices, &event);
        Ok(())
    }
}

/// The reducer: apply one durable event to in-memory state. Used both for
/// live mutations and for replaying the log on startup — one
/// implementation of "what does this event mean," not two.
fn apply_event(devices: &mut HashMap<String, DeviceRecord>, event: &RegistryEvent) {
    match event {
        RegistryEvent::Enrolled {
            common_name,
            cert_pem,
            at_unix,
        } => {
            let existing = devices.get(common_name);
            let existing_uid = existing.and_then(|d| d.uid.clone());
            let was_revoked = existing.map(|d| d.revoked).unwrap_or(false);
            devices.insert(
                common_name.clone(),
                DeviceRecord {
                    common_name: common_name.clone(),
                    cert_pem: cert_pem.clone(),
                    enrolled_at_unix: *at_unix,
                    revoked: was_revoked,
                    uid: existing_uid,
                },
            );
        }
        RegistryEvent::Revoked { common_name } => {
            if let Some(device) = devices.get_mut(common_name) {
                device.revoked = true;
            }
        }
        RegistryEvent::UidBound { common_name, uid } => {
            if let Some(device) = devices.get_mut(common_name) {
                device.uid = Some(uid.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolls_and_finds_a_device() {
        let registry = DeviceRegistry::in_memory();
        let record = registry.enroll("device-a", "-----BEGIN CERTIFICATE-----...", 1_000).unwrap();
        assert_eq!(record.common_name, "device-a");
        assert!(!record.revoked);
        assert!(record.uid.is_none());

        let found = registry.find("device-a").unwrap();
        assert_eq!(found, record);
    }

    #[test]
    fn re_enrollment_rotates_cert_but_preserves_uid_binding() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert-v1", 1_000).unwrap();
        registry.bind_uid("device-a", "UID-A").unwrap();

        let rotated = registry.enroll("device-a", "cert-v2", 2_000).unwrap();
        assert_eq!(rotated.cert_pem, "cert-v2");
        assert_eq!(rotated.uid.as_deref(), Some("UID-A"));
    }

    #[test]
    fn tc_tls_04_binds_uid_on_first_use() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert", 1_000).unwrap();
        registry.bind_uid("device-a", "UID-A").unwrap();
        assert_eq!(registry.find("device-a").unwrap().uid.as_deref(), Some("UID-A"));
    }

    #[test]
    fn tc_tls_04_same_device_reasserting_same_uid_is_idempotent() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert", 1_000).unwrap();
        registry.bind_uid("device-a", "UID-A").unwrap();
        registry.bind_uid("device-a", "UID-A").unwrap(); // no error
        assert_eq!(registry.find("device-a").unwrap().uid.as_deref(), Some("UID-A"));
    }

    #[test]
    fn tc_tls_04_rejects_uid_already_owned_by_a_different_device() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert-a", 1_000).unwrap();
        registry.enroll("device-b", "cert-b", 1_000).unwrap();
        registry.bind_uid("device-a", "UID-A").unwrap();

        let result = registry.bind_uid("device-b", "UID-A");
        assert!(matches!(
            result,
            Err(RegistryError::UidOwnedByOtherDevice { .. })
        ));
    }

    #[test]
    fn tc_tls_04_rejects_device_rebinding_to_a_different_uid() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert", 1_000).unwrap();
        registry.bind_uid("device-a", "UID-A").unwrap();

        let result = registry.bind_uid("device-a", "UID-B");
        assert!(matches!(
            result,
            Err(RegistryError::DeviceUidMismatch { .. })
        ));
    }

    #[test]
    fn revokes_a_device() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert", 1_000).unwrap();
        assert!(!registry.is_revoked("device-a"));
        registry.revoke("device-a").unwrap();
        assert!(registry.is_revoked("device-a"));
    }

    #[test]
    fn re_enrollment_does_not_clear_revocation() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll("device-a", "cert-v1", 1_000).unwrap();
        registry.revoke("device-a").unwrap();

        let rotated = registry.enroll("device-a", "cert-v2", 2_000).unwrap();
        assert!(
            rotated.revoked,
            "re-enrolling a revoked device must not silently un-revoke it"
        );
        assert!(registry.is_revoked("device-a"));
    }

    #[test]
    fn revoking_unknown_device_errors() {
        let registry = DeviceRegistry::in_memory();
        assert!(matches!(
            registry.revoke("nonexistent"),
            Err(RegistryError::NotFound(_))
        ));
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir().join(format!("microtak-registry-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.log");

        {
            let registry = DeviceRegistry::load_or_create(&path).unwrap();
            registry.enroll("device-a", "cert", 1_000).unwrap();
            registry.bind_uid("device-a", "UID-A").unwrap();
        }

        let reloaded = DeviceRegistry::load_or_create(&path).unwrap();
        let record = reloaded.find("device-a").unwrap();
        assert_eq!(record.cert_pem, "cert");
        assert_eq!(record.uid.as_deref(), Some("UID-A"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loading_nonexistent_path_starts_empty() {
        let dir = std::env::temp_dir().join(format!("microtak-registry-empty-{}", std::process::id()));
        let path = dir.join("does-not-exist.log");
        let registry = DeviceRegistry::load_or_create(&path).unwrap();
        assert!(registry.find("anything").is_none());
    }

    /// The whole point: replaying the log reproduces identical state,
    /// including a mutation (idempotent re-bind) that deliberately does
    /// *not* append a new event, and a revoke that happens after the
    /// device was re-enrolled -- exercises replay ordering, not just a
    /// single write-then-read.
    #[test]
    fn replay_reconstructs_a_realistic_mutation_sequence_exactly() {
        let dir = std::env::temp_dir().join(format!("microtak-registry-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.log");

        {
            let registry = DeviceRegistry::load_or_create(&path).unwrap();
            registry.enroll("device-a", "cert-v1", 1_000).unwrap();
            registry.enroll("device-b", "cert-b", 1_100).unwrap();
            registry.bind_uid("device-a", "UID-A").unwrap();
            registry.bind_uid("device-a", "UID-A").unwrap(); // idempotent, no event
            registry.enroll("device-a", "cert-v2", 2_000).unwrap(); // rotation
            registry.revoke("device-b").unwrap();
        }

        let replayed = DeviceRegistry::load_or_create(&path).unwrap();
        let a = replayed.find("device-a").unwrap();
        assert_eq!(a.cert_pem, "cert-v2");
        assert_eq!(a.uid.as_deref(), Some("UID-A"));
        assert!(!a.revoked);
        assert!(replayed.is_revoked("device-b"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
