//! User accounts for password-based authentication -- the login half of
//! real TAK Server / CloudTAK wire compatibility.
//!
//! Nothing else in MicroTAK has a notion of a "user": device identity is a
//! cert Common Name, full stop. This exists solely because CloudTAK's real
//! login flow needs an OAuth password grant (`POST /oauth/token`) followed
//! by authenticated cert issuance -- a genuinely different trust model from
//! enrollment's own invite-token gate, not a replacement for it (see
//! `marti::enrollment`'s Basic-Auth path).
//!
//! Persisted the same way as every other piece of MicroTAK state: an
//! append-only, replayable event log (see `crate::eventlog`). Passwords are
//! stored only as Argon2 PHC hashes, never in plaintext, not even in the
//! event log itself.
//!
//! No self-service signup: an admin mints a user (via the admin API or
//! `microtak-admin-cli user mint`), the same way enrollment invite tokens
//! are minted -- see `marti::admin`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum UserError {
    #[error("unknown user")]
    NotFound,
    #[error("user already exists")]
    AlreadyExists,
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
}

/// Public-facing snapshot of a user -- deliberately carries no password
/// material at all, not even the hash, so it's always safe to serialize
/// straight into an admin API response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub created_at_unix: i64,
    pub revoked: bool,
}

struct UserRecord {
    password_hash: String,
    created_at_unix: i64,
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum UserEvent {
    Created {
        username: String,
        password_hash: String,
        created_at_unix: i64,
    },
    Revoked {
        username: String,
    },
}

pub struct UserStore {
    users: RwLock<HashMap<String, UserRecord>>,
    log: Option<EventLog<UserEvent>>,
}

impl UserStore {
    /// An ephemeral, non-persisted store -- for tests, or a deliberately
    /// stateless run.
    pub fn in_memory() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            log: None,
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, UserError> {
        let mut users = HashMap::new();
        let log = EventLog::open_and_replay(path, &mut users, apply_event)?;
        Ok(Self {
            users: RwLock::new(users),
            log: Some(log),
        })
    }

    /// Create a new user with the given plaintext password (hashed
    /// immediately, never stored or logged as-is). Errors if the username
    /// already exists, revoked or not -- revoke then mint a differently-
    /// named account instead of trying to reuse a name.
    pub fn mint(&self, username: &str, password: &str, now_unix: i64) -> Result<(), UserError> {
        let mut users = self.users.write().unwrap();
        if users.contains_key(username) {
            return Err(UserError::AlreadyExists);
        }
        let event = UserEvent::Created {
            username: username.to_string(),
            password_hash: hash_password(password),
            created_at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut users, &event);
        Ok(())
    }

    pub fn revoke(&self, username: &str) -> Result<(), UserError> {
        let mut users = self.users.write().unwrap();
        if !users.contains_key(username) {
            return Err(UserError::NotFound);
        }
        let event = UserEvent::Revoked {
            username: username.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut users, &event);
        Ok(())
    }

    pub fn list(&self) -> Vec<UserInfo> {
        let mut all: Vec<_> = self
            .users
            .read()
            .unwrap()
            .iter()
            .map(|(username, record)| UserInfo {
                username: username.clone(),
                created_at_unix: record.created_at_unix,
                revoked: record.revoked,
            })
            .collect();
        all.sort_by_key(|u| u.created_at_unix);
        all
    }

    /// Real credential check against the stored Argon2 hash. Returns
    /// `false` for a revoked user even with the correct password --
    /// revocation takes effect immediately, not just on future mints.
    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        let users = self.users.read().unwrap();
        let Some(record) = users.get(username) else {
            return false;
        };
        if record.revoked {
            return false;
        }
        verify_password(password, &record.password_hash)
    }
}

fn apply_event(users: &mut HashMap<String, UserRecord>, event: &UserEvent) {
    match event {
        UserEvent::Created {
            username,
            password_hash,
            created_at_unix,
        } => {
            users.insert(
                username.clone(),
                UserRecord {
                    password_hash: password_hash.clone(),
                    created_at_unix: *created_at_unix,
                    revoked: false,
                },
            );
        }
        UserEvent::Revoked { username } => {
            if let Some(record) = users.get_mut(username) {
                record.revoked = true;
            }
        }
    }
}

fn hash_password(password: &str) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("argon2 hashing should not fail")
        .to_string()
}

fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_user_authenticates_with_the_right_password() {
        let store = UserStore::in_memory();
        store.mint("jz", "correct horse battery staple", 1_000).unwrap();
        assert!(store.authenticate("jz", "correct horse battery staple"));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let store = UserStore::in_memory();
        store.mint("jz", "correct horse battery staple", 1_000).unwrap();
        assert!(!store.authenticate("jz", "wrong password"));
    }

    #[test]
    fn unknown_username_is_rejected() {
        let store = UserStore::in_memory();
        assert!(!store.authenticate("nobody", "whatever"));
    }

    #[test]
    fn minting_a_duplicate_username_errors() {
        let store = UserStore::in_memory();
        store.mint("jz", "pw1", 1_000).unwrap();
        assert!(matches!(store.mint("jz", "pw2", 1_100), Err(UserError::AlreadyExists)));
    }

    /// The whole point of revocation: it must actually block login, not
    /// just prevent re-minting the same username.
    #[test]
    fn a_revoked_user_cannot_authenticate_even_with_the_right_password() {
        let store = UserStore::in_memory();
        store.mint("jz", "correct horse battery staple", 1_000).unwrap();
        store.revoke("jz").unwrap();
        assert!(!store.authenticate("jz", "correct horse battery staple"));
    }

    #[test]
    fn revoking_unknown_user_errors() {
        let store = UserStore::in_memory();
        assert!(matches!(store.revoke("nobody"), Err(UserError::NotFound)));
    }

    #[test]
    fn passwords_are_never_stored_in_plaintext() {
        let store = UserStore::in_memory();
        store.mint("jz", "correct horse battery staple", 1_000).unwrap();
        let record = store.users.read().unwrap();
        let hash = &record.get("jz").unwrap().password_hash;
        assert_ne!(hash, "correct horse battery staple");
        assert!(hash.starts_with("$argon2"), "expected a real Argon2 PHC hash, got: {hash}");
    }

    #[test]
    fn list_reflects_mint_and_revoke_state() {
        let store = UserStore::in_memory();
        store.mint("jz", "pw1", 1_000).unwrap();
        store.mint("other", "pw2", 1_100).unwrap();
        store.revoke("jz").unwrap();

        let all = store.list();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].username, "jz");
        assert!(all[0].revoked);
        assert_eq!(all[1].username, "other");
        assert!(!all[1].revoked);
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir().join(format!("microtak-users-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("users.log");

        {
            let store = UserStore::load_or_create(&path).unwrap();
            store.mint("jz", "correct horse battery staple", 1_000).unwrap();
        }

        let reloaded = UserStore::load_or_create(&path).unwrap();
        assert!(reloaded.authenticate("jz", "correct horse battery staple"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
