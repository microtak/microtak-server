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
    #[error("a device with common name '{0}' is already enrolled")]
    AlreadyEnrolled(String),
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
    #[error("'{0}' is not a SHA-256 certificate fingerprint")]
    InvalidFingerprint(String),
    #[error("device '{0}' has no readable certificate on record")]
    NoCertificate(String),
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
        /// The enrolling client's `clientUid` query parameter (ATAK sends
        /// its device uid), kept for the certificate admin API.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_uid: Option<String>,
    },
    Revoked {
        common_name: String,
    },
    UidBound {
        common_name: String,
        uid: String,
    },
    /// One certificate (by SHA-256 fingerprint) is revoked for good, e.g. a
    /// lost device's. The identity stays usable with a new certificate.
    CertRevoked {
        fingerprint: String,
        /// When (absent in logs written before revocation dates were kept).
        #[serde(default)]
        at_unix: i64,
    },
    /// Certificate rows removed (official `certadmin/cert/delete/{ids}`).
    CertDeleted {
        id: i64,
    },
    /// Lifts a `Revoked` (identity block). Revoked certificates stay revoked.
    Unblocked {
        common_name: String,
    },
}

/// Whether a connecting certificate may be used -- see
/// [`DeviceRegistry::access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allowed,
    /// The identity is blocked (any certificate).
    Blocked,
    /// This particular certificate is revoked.
    CertRevoked,
}

/// One issued certificate -- a row of the official TAK Server's
/// `certificate` table (`TakCert`). Every enrollment issues one; ids are
/// assigned in log order, so they are stable across restarts.
#[derive(Debug, Clone, PartialEq)]
pub struct CertRecord {
    pub id: i64,
    pub common_name: String,
    pub cert_pem: String,
    pub client_uid: Option<String>,
    pub issued_at_unix: i64,
}

#[derive(Debug, Default)]
struct RegistryState {
    devices: HashMap<String, DeviceRecord>,
    /// Revoked certificate fingerprints (uppercase colon hex) -> when.
    revoked_certs: HashMap<String, i64>,
    certificates: Vec<CertRecord>,
    next_cert_id: i64,
}

pub struct DeviceRegistry {
    state: RwLock<RegistryState>,
    log: Option<EventLog<RegistryEvent>>,
    /// Bumped on every revocation, block or unblock, so live connections
    /// re-check their access -- see [`Self::revocations`].
    revocations: tokio::sync::watch::Sender<u64>,
}

impl DeviceRegistry {
    /// An ephemeral, non-persisted registry — for tests, or a deliberately
    /// stateless run.
    pub fn in_memory() -> Self {
        Self {
            state: RwLock::new(RegistryState::default()),
            log: None,
            revocations: tokio::sync::watch::Sender::new(0),
        }
    }

    /// Load an existing registry from `path` by replaying its event log,
    /// or start empty if the file doesn't exist yet. Every subsequent
    /// mutation appends to this same log.
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let mut state = RegistryState::default();
        let log = EventLog::open_and_replay(path, &mut state, apply_event)?;
        Ok(Self {
            state: RwLock::new(state),
            log: Some(log),
            revocations: tokio::sync::watch::Sender::new(0),
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
        self.enroll_with_client_uid(common_name, cert_pem, now_unix, None)
    }

    /// [`Self::enroll`], recording the client's `clientUid` with the
    /// issued certificate.
    pub fn enroll_with_client_uid(
        &self,
        common_name: &str,
        cert_pem: &str,
        now_unix: i64,
        client_uid: Option<&str>,
    ) -> Result<DeviceRecord, RegistryError> {
        let mut state = self.state.write().unwrap();
        let event = RegistryEvent::Enrolled {
            common_name: common_name.to_string(),
            cert_pem: cert_pem.to_string(),
            at_unix: now_unix,
            client_uid: client_uid.map(str::to_string),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut state, &event);
        Ok(state.devices.get(common_name).unwrap().clone())
    }

    /// Enroll a *new* device, failing with
    /// [`RegistryError::AlreadyEnrolled`] if the common name is already
    /// taken -- checked and recorded under one write lock, so two
    /// concurrent requests for the same new name can't both succeed. Used
    /// by every enrollment path that doesn't prove ownership of an
    /// existing identity (invite tokens, `Open` mode): those may only ever
    /// create identities, never replace one (TC-ENROLL-13).
    pub fn enroll_new(
        &self,
        common_name: &str,
        cert_pem: &str,
        now_unix: i64,
    ) -> Result<DeviceRecord, RegistryError> {
        self.enroll_new_with_client_uid(common_name, cert_pem, now_unix, None)
    }

    /// [`Self::enroll_new`], recording the client's `clientUid`.
    pub fn enroll_new_with_client_uid(
        &self,
        common_name: &str,
        cert_pem: &str,
        now_unix: i64,
        client_uid: Option<&str>,
    ) -> Result<DeviceRecord, RegistryError> {
        let mut state = self.state.write().unwrap();
        if state.devices.contains_key(common_name) {
            return Err(RegistryError::AlreadyEnrolled(common_name.to_string()));
        }
        let event = RegistryEvent::Enrolled {
            common_name: common_name.to_string(),
            cert_pem: cert_pem.to_string(),
            at_unix: now_unix,
            client_uid: client_uid.map(str::to_string),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut state, &event);
        Ok(state.devices.get(common_name).unwrap().clone())
    }

    /// The common name of the device that has bound `uid`, if any.
    pub fn owner_of_uid(&self, uid: &str) -> Option<String> {
        self.state
            .read()
            .unwrap()
            .devices
            .values()
            .find(|d| d.uid.as_deref() == Some(uid))
            .map(|d| d.common_name.clone())
    }

    pub fn find(&self, common_name: &str) -> Option<DeviceRecord> {
        self.state.read().unwrap().devices.get(common_name).cloned()
    }

    /// Every enrolled device, in no particular order. Used by
    /// `marti::admin`'s certificate-admin lookup, which needs to scan for
    /// a matching cert fingerprint -- fine at this project's scale (see
    /// this module's own doc comment).
    pub fn all(&self) -> Vec<DeviceRecord> {
        self.state.read().unwrap().devices.values().cloned().collect()
    }

    pub fn is_revoked(&self, common_name: &str) -> bool {
        self.state
            .read()
            .unwrap()
            .devices
            .get(common_name)
            .map(|d| d.revoked)
            .unwrap_or(false)
    }

    /// Block an identity: every certificate it holds or gets is refused
    /// until [`Self::unblock`]. (For a lost device, revoke just its
    /// certificate instead: [`Self::revoke_current_cert`].)
    pub fn revoke(&self, common_name: &str) -> Result<(), RegistryError> {
        let mut state = self.state.write().unwrap();
        if !state.devices.contains_key(common_name) {
            return Err(RegistryError::NotFound(common_name.to_string()));
        }
        let event = RegistryEvent::Revoked {
            common_name: common_name.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut state, &event);
        drop(state);
        self.signal_revocation();
        Ok(())
    }

    /// Whether `common_name` presenting the certificate `cert_der` may
    /// connect or call the API: not if the identity is blocked, or this
    /// certificate is revoked. Checked at every connection and request.
    pub fn access(&self, common_name: &str, cert_der: &[u8]) -> Access {
        let state = self.state.read().unwrap();
        if state.devices.get(common_name).is_some_and(|d| d.revoked) {
            return Access::Blocked;
        }
        let fingerprint = crate::pki::fingerprint_sha256_colon_hex_der(cert_der);
        if state.revoked_certs.contains_key(&fingerprint) {
            return Access::CertRevoked;
        }
        Access::Allowed
    }

    /// Every issued certificate still on record, oldest first.
    pub fn certificates(&self) -> Vec<CertRecord> {
        self.state.read().unwrap().certificates.clone()
    }

    /// When the certificate with this fingerprint was revoked, if it was
    /// (`Some(0)`: revoked before dates were recorded).
    pub fn cert_revoked_at(&self, fingerprint: &str) -> Option<i64> {
        let fp = crate::pki::normalize_fingerprint(fingerprint)?;
        self.state.read().unwrap().revoked_certs.get(&fp).copied()
    }

    /// Remove certificate rows (official `certadmin/cert/delete/{ids}`);
    /// returns the ids that existed. A deleted certificate that was revoked
    /// stays revoked -- deleting a row must not revive it.
    pub fn delete_certs(&self, ids: &[i64]) -> Result<Vec<i64>, RegistryError> {
        let mut state = self.state.write().unwrap();
        let mut deleted = Vec::new();
        for &id in ids {
            if state.certificates.iter().any(|c| c.id == id) {
                let event = RegistryEvent::CertDeleted { id };
                if let Some(log) = &self.log {
                    log.append(&event)?;
                }
                apply_event(&mut state, &event);
                deleted.push(id);
            }
        }
        Ok(deleted)
    }

    /// How many certificates are revoked (for metrics).
    pub fn revoked_cert_count(&self) -> usize {
        self.state.read().unwrap().revoked_certs.len()
    }

    /// Whether the certificate with this fingerprint (any format accepted by
    /// [`crate::pki::normalize_fingerprint`]) is revoked.
    pub fn is_cert_revoked(&self, fingerprint: &str) -> bool {
        crate::pki::normalize_fingerprint(fingerprint)
            .is_some_and(|fp| self.state.read().unwrap().revoked_certs.contains_key(&fp))
    }

    /// Revoke one certificate by SHA-256 fingerprint -- the official
    /// `certadmin` revoke. Idempotent.
    pub fn revoke_cert(&self, fingerprint: &str) -> Result<(), RegistryError> {
        let fingerprint = crate::pki::normalize_fingerprint(fingerprint)
            .ok_or_else(|| RegistryError::InvalidFingerprint(fingerprint.to_string()))?;
        let mut state = self.state.write().unwrap();
        if !state.revoked_certs.contains_key(&fingerprint) {
            let at_unix = time::OffsetDateTime::now_utc().unix_timestamp();
            let event = RegistryEvent::CertRevoked { fingerprint, at_unix };
            if let Some(log) = &self.log {
                log.append(&event)?;
            }
            apply_event(&mut state, &event);
        }
        drop(state);
        self.signal_revocation();
        Ok(())
    }

    /// Revoke the certificate `common_name` currently holds (a lost or
    /// compromised device). Returns its fingerprint. The identity can
    /// enroll a new certificate with its credentials.
    pub fn revoke_current_cert(&self, common_name: &str) -> Result<String, RegistryError> {
        let cert_pem = self
            .find(common_name)
            .ok_or_else(|| RegistryError::NotFound(common_name.to_string()))?
            .cert_pem;
        let fingerprint = crate::pki::fingerprint_sha256_colon_hex(&cert_pem)
            .ok_or_else(|| RegistryError::NoCertificate(common_name.to_string()))?;
        self.revoke_cert(&fingerprint)?;
        Ok(fingerprint)
    }

    /// Lift an identity block ([`Self::revoke`]). Certificates revoked
    /// individually stay revoked.
    pub fn unblock(&self, common_name: &str) -> Result<(), RegistryError> {
        let mut state = self.state.write().unwrap();
        if !state.devices.contains_key(common_name) {
            return Err(RegistryError::NotFound(common_name.to_string()));
        }
        let event = RegistryEvent::Unblocked {
            common_name: common_name.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut state, &event);
        drop(state);
        self.signal_revocation();
        Ok(())
    }

    /// Changes whenever a certificate is revoked or an identity blocked or
    /// unblocked; connections watch it and re-check [`Self::access`].
    pub fn revocations(&self) -> tokio::sync::watch::Receiver<u64> {
        self.revocations.subscribe()
    }

    fn signal_revocation(&self) {
        self.revocations.send_modify(|generation| *generation += 1);
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
        let mut state = self.state.write().unwrap();

        if let Some(owner) = state
            .devices
            .values()
            .find(|d| d.uid.as_deref() == Some(uid) && d.common_name != common_name)
        {
            return Err(RegistryError::UidOwnedByOtherDevice {
                uid: uid.to_string(),
                owner: owner.common_name.clone(),
            });
        }

        let device = state
            .devices
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
        apply_event(&mut state, &event);
        Ok(())
    }
}

/// The reducer: apply one durable event to in-memory state. Used both for
/// live mutations and for replaying the log on startup — one
/// implementation of "what does this event mean," not two.
fn apply_event(state: &mut RegistryState, event: &RegistryEvent) {
    match event {
        RegistryEvent::Enrolled {
            common_name,
            cert_pem,
            at_unix,
            client_uid,
        } => {
            state.next_cert_id += 1;
            state.certificates.push(CertRecord {
                id: state.next_cert_id,
                common_name: common_name.clone(),
                cert_pem: cert_pem.clone(),
                client_uid: client_uid.clone(),
                issued_at_unix: *at_unix,
            });
            let devices = &mut state.devices;
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
            if let Some(device) = state.devices.get_mut(common_name) {
                device.revoked = true;
            }
        }
        RegistryEvent::UidBound { common_name, uid } => {
            if let Some(device) = state.devices.get_mut(common_name) {
                device.uid = Some(uid.clone());
            }
        }
        RegistryEvent::CertRevoked { fingerprint, at_unix } => {
            state.revoked_certs.entry(fingerprint.clone()).or_insert(*at_unix);
        }
        RegistryEvent::CertDeleted { id } => {
            state.certificates.retain(|c| c.id != *id);
        }
        RegistryEvent::Unblocked { common_name } => {
            if let Some(device) = state.devices.get_mut(common_name) {
                device.revoked = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_new_refuses_an_existing_common_name_and_keeps_its_cert() {
        let registry = DeviceRegistry::in_memory();
        registry.enroll_new("device-a", "first-cert", 1).unwrap();
        let result = registry.enroll_new("device-a", "second-cert", 2);
        assert!(matches!(result, Err(RegistryError::AlreadyEnrolled(cn)) if cn == "device-a"));
        assert_eq!(registry.find("device-a").unwrap().cert_pem, "first-cert");
    }

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
    fn all_lists_every_enrolled_device() {
        let registry = DeviceRegistry::in_memory();
        assert!(registry.all().is_empty());
        registry.enroll("device-a", "cert-a", 1_000).unwrap();
        registry.enroll("device-b", "cert-b", 1_100).unwrap();

        let mut names: Vec<_> = registry.all().into_iter().map(|d| d.common_name).collect();
        names.sort();
        assert_eq!(names, vec!["device-a", "device-b"]);
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

    /// A real CA-issued certificate for `cn`: (PEM, DER) -- revocation by
    /// certificate needs real fingerprints.
    fn issue(ca: &crate::pki::CertificateAuthority, cn: &str) -> (String, Vec<u8>) {
        let (csr, _key) = crate::pki::build_csr(cn).unwrap();
        let signed = ca.sign_csr(&csr, time::Duration::days(1)).unwrap();
        let der = crate::pki::cert_pem_to_der(&signed.cert_pem).unwrap().as_ref().to_vec();
        (signed.cert_pem, der)
    }

    fn test_ca() -> crate::pki::CertificateAuthority {
        crate::pki::CertificateAuthority::generate("Registry Test CA").unwrap()
    }

    /// A lost phone: its certificate stops working, but the identity can
    /// enroll a new certificate (e.g. via its password account) and use it.
    #[test]
    fn revoking_a_certificate_rejects_only_that_certificate() {
        let ca = test_ca();
        let registry = DeviceRegistry::in_memory();
        let (old_pem, old_der) = issue(&ca, "alice");
        registry.enroll("alice", &old_pem, 1).unwrap();
        assert_eq!(registry.access("alice", &old_der), Access::Allowed);

        registry.revoke_current_cert("alice").unwrap();
        assert_eq!(registry.access("alice", &old_der), Access::CertRevoked);
        assert!(!registry.is_revoked("alice"), "the identity itself is not blocked");

        let (new_pem, new_der) = issue(&ca, "alice");
        registry.enroll("alice", &new_pem, 2).unwrap();
        assert_eq!(registry.access("alice", &new_der), Access::Allowed);
        assert_eq!(registry.access("alice", &old_der), Access::CertRevoked);
    }

    /// Blocking locks the identity out whatever certificate it presents,
    /// until it's explicitly unblocked.
    #[test]
    fn blocking_rejects_every_certificate_until_unblocked() {
        let ca = test_ca();
        let registry = DeviceRegistry::in_memory();
        let (pem, der) = issue(&ca, "bob");
        registry.enroll("bob", &pem, 1).unwrap();

        registry.revoke("bob").unwrap();
        assert_eq!(registry.access("bob", &der), Access::Blocked);

        registry.unblock("bob").unwrap();
        assert_eq!(registry.access("bob", &der), Access::Allowed);
        assert!(!registry.is_revoked("bob"));
    }

    #[test]
    fn unblocking_does_not_revive_a_revoked_certificate() {
        let ca = test_ca();
        let registry = DeviceRegistry::in_memory();
        let (pem, der) = issue(&ca, "carol");
        registry.enroll("carol", &pem, 1).unwrap();
        registry.revoke_current_cert("carol").unwrap();
        registry.revoke("carol").unwrap();
        registry.unblock("carol").unwrap();
        assert_eq!(registry.access("carol", &der), Access::CertRevoked);
    }

    #[test]
    fn revoking_by_fingerprint_matches_the_certadmin_hash_format() {
        let ca = test_ca();
        let registry = DeviceRegistry::in_memory();
        let (pem, der) = issue(&ca, "dave");
        registry.enroll("dave", &pem, 1).unwrap();
        let hash = crate::pki::fingerprint_sha256_colon_hex(&pem).unwrap();
        registry.revoke_cert(&hash.to_lowercase()).unwrap();
        assert_eq!(registry.access("dave", &der), Access::CertRevoked);
        assert!(registry.is_cert_revoked(&hash));
    }

    #[test]
    fn unblocking_or_revoking_the_cert_of_an_unknown_device_errors() {
        let registry = DeviceRegistry::in_memory();
        assert!(matches!(registry.unblock("nobody"), Err(RegistryError::NotFound(_))));
        assert!(matches!(registry.revoke_current_cert("nobody"), Err(RegistryError::NotFound(_))));
    }

    /// Live connections re-check their access when this changes.
    #[test]
    fn revocations_are_signalled() {
        let ca = test_ca();
        let registry = DeviceRegistry::in_memory();
        let (pem, _) = issue(&ca, "erin");
        registry.enroll("erin", &pem, 1).unwrap();
        let mut changes = registry.revocations();
        changes.mark_unchanged();

        registry.revoke_current_cert("erin").unwrap();
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        registry.revoke("erin").unwrap();
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();
        registry.unblock("erin").unwrap();
        assert!(changes.has_changed().unwrap());
    }

    #[test]
    fn certificate_revocations_and_unblocks_survive_a_reload() {
        let ca = test_ca();
        let dir = std::env::temp_dir().join(format!("microtak-registry-revoke-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.log");
        let (pem_a, der_a) = issue(&ca, "frank");
        let (pem_b, der_b) = issue(&ca, "grace");
        {
            let registry = DeviceRegistry::load_or_create(&path).unwrap();
            registry.enroll("frank", &pem_a, 1).unwrap();
            registry.enroll("grace", &pem_b, 1).unwrap();
            registry.revoke_current_cert("frank").unwrap();
            registry.revoke("grace").unwrap();
            registry.unblock("grace").unwrap();
        }
        let replayed = DeviceRegistry::load_or_create(&path).unwrap();
        assert_eq!(replayed.access("frank", &der_a), Access::CertRevoked);
        assert_eq!(replayed.access("grace", &der_b), Access::Allowed);
        std::fs::remove_dir_all(&dir).ok();
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
