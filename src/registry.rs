//! Device (EUD) registry: tracks enrolled devices by certificate Common
//! Name, and binds each to the CoT `uid` it's authorized to assert.
//!
//! Simple JSON-file-backed store (load on startup, rewrite atomically on
//! every mutation) rather than an embedded database — appropriate at the
//! scale this project targets (a home/ham deployment, not thousands of
//! concurrent devices), and keeps the dependency footprint and deployment
//! model minimal (a single file, trivially covered by the planned backup
//! strategy — see `docs/ARCHITECTURE.md`).
//!
//! Implements the enrollment side of `docs/TEST-PLAN.md` §4 (recording a
//! signed device alongside its cert) and the identity-binding side of §3
//! TC-TLS-04 (rejecting a connection that claims a `uid` belonging to a
//! different, already-enrolled device).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    #[error("failed to read device registry file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write device registry file {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to (de)serialize device registry: {0}")]
    Serde(#[from] serde_json::Error),
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

pub struct DeviceRegistry {
    path: Option<PathBuf>,
    devices: RwLock<HashMap<String, DeviceRecord>>,
}

impl DeviceRegistry {
    /// An ephemeral, non-persisted registry — for tests, or a deliberately
    /// stateless run.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            devices: RwLock::new(HashMap::new()),
        }
    }

    /// Load an existing registry from `path`, or start empty if the file
    /// doesn't exist yet. Every subsequent mutation persists back to this
    /// same path.
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        let devices = match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(source) => {
                return Err(RegistryError::Read { path, source });
            }
        };
        Ok(Self {
            path: Some(path),
            devices: RwLock::new(devices),
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
        let existing = devices.get(common_name);
        let existing_uid = existing.and_then(|d| d.uid.clone());
        let was_revoked = existing.map(|d| d.revoked).unwrap_or(false);
        let record = DeviceRecord {
            common_name: common_name.to_string(),
            cert_pem: cert_pem.to_string(),
            enrolled_at_unix: now_unix,
            revoked: was_revoked,
            uid: existing_uid,
        };
        devices.insert(common_name.to_string(), record.clone());
        drop(devices);
        self.persist()?;
        Ok(record)
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
        {
            let mut devices = self.devices.write().unwrap();
            let device = devices
                .get_mut(common_name)
                .ok_or_else(|| RegistryError::NotFound(common_name.to_string()))?;
            device.revoked = true;
        }
        self.persist()
    }

    /// Bind `uid` to `common_name`, enforcing TC-TLS-04: a `uid` already
    /// claimed by a *different* enrolled device is rejected outright
    /// (cross-device spoofing defense). The same device re-asserting the
    /// same `uid` it already owns is a no-op success (the expected steady
    /// state, since a connected device re-sends its self-ID atom
    /// periodically). A device that has already bound a different `uid`
    /// attempting to bind yet another one is also rejected — EdgeTAK treats
    /// a device's `uid` as fixed once bound, a deliberate simplification
    /// (see `docs/ARCHITECTURE.md`) vs. real-world devices that might
    /// legitimately change identity (e.g. app reinstall); revoking and
    /// re-enrolling is the escape hatch for that case.
    pub fn bind_uid(&self, common_name: &str, uid: &str) -> Result<(), RegistryError> {
        {
            let devices = self.devices.read().unwrap();
            if let Some(owner) = devices
                .values()
                .find(|d| d.uid.as_deref() == Some(uid) && d.common_name != common_name)
            {
                return Err(RegistryError::UidOwnedByOtherDevice {
                    uid: uid.to_string(),
                    owner: owner.common_name.clone(),
                });
            }
        }

        let mut devices = self.devices.write().unwrap();
        let device = devices
            .get_mut(common_name)
            .ok_or_else(|| RegistryError::NotFound(common_name.to_string()))?;

        match &device.uid {
            None => {
                device.uid = Some(uid.to_string());
            }
            Some(existing) if existing == uid => {
                return Ok(()); // idempotent re-assertion, no persist needed
            }
            Some(existing) => {
                return Err(RegistryError::DeviceUidMismatch {
                    common_name: common_name.to_string(),
                    existing: existing.clone(),
                    claimed: uid.to_string(),
                });
            }
        }
        drop(devices);
        self.persist()
    }

    fn persist(&self) -> Result<(), RegistryError> {
        let Some(path) = &self.path else {
            return Ok(()); // in-memory mode: nothing to write
        };
        let devices = self.devices.read().unwrap();
        let json = serde_json::to_string_pretty(&*devices)?;
        write_atomically(path, &json).map_err(|source| RegistryError::Write {
            path: path.clone(),
            source,
        })
    }
}

/// Write `contents` to `path` via a temp-file-then-rename, so a crash
/// mid-write can never leave a truncated/corrupt registry file on disk.
fn write_atomically(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, path)
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
        let dir = std::env::temp_dir().join(format!("edgetak-registry-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");

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
        let dir = std::env::temp_dir().join(format!("edgetak-registry-empty-{}", std::process::id()));
        let path = dir.join("does-not-exist.json");
        let registry = DeviceRegistry::load_or_create(&path).unwrap();
        assert!(registry.find("anything").is_none());
    }
}
