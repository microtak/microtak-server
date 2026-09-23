//! Enrollment invite tokens: a secure-by-default gate on device enrollment.
//!
//! `/Marti/api/tls/signClient/v2` is wide open to anyone who can reach it --
//! deliberate, matching the real Marti enrollment contract (see
//! `marti::enrollment`'s own doc comment), but a real gap for any deployment
//! not fully isolated on a trusted network. [`crate::app::EnrollmentMode::Auto`]
//! (the default) requires a caller to also present a valid, unused,
//! unexpired token (`?token=...` on the enrollment request) once the
//! configured admin device has actually enrolled -- minted ahead of time
//! via the admin API (`marti::admin`), single-use, and revocable.
//!
//! Persisted the same way as every other piece of MicroTAK state: an
//! append-only, replayable event log (see [`crate::eventlog`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eventlog::{EventLog, EventLogError};

#[derive(Debug, Error)]
pub enum EnrollmentTokenError {
    #[error("unknown enrollment token")]
    NotFound,
    #[error("enrollment token has already been used")]
    AlreadyUsed,
    #[error("enrollment token has been revoked")]
    Revoked,
    #[error("enrollment token has expired")]
    Expired,
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub token: String,
    pub created_at_unix: i64,
    /// `None` means it never expires.
    pub expires_at_unix: Option<i64>,
    pub note: Option<String>,
    pub used: bool,
    pub used_by_common_name: Option<String>,
    pub used_at_unix: Option<i64>,
    pub revoked: bool,
}

impl EnrollmentToken {
    fn is_usable_at(&self, now_unix: i64) -> Result<(), EnrollmentTokenError> {
        if self.revoked {
            return Err(EnrollmentTokenError::Revoked);
        }
        if self.used {
            return Err(EnrollmentTokenError::AlreadyUsed);
        }
        if let Some(expires_at) = self.expires_at_unix {
            if now_unix >= expires_at {
                return Err(EnrollmentTokenError::Expired);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum TokenEvent {
    Minted {
        token: String,
        created_at_unix: i64,
        expires_at_unix: Option<i64>,
        note: Option<String>,
    },
    Consumed {
        token: String,
        common_name: String,
        at_unix: i64,
    },
    Revoked {
        token: String,
    },
}

pub struct EnrollmentTokenStore {
    tokens: RwLock<HashMap<String, EnrollmentToken>>,
    log: Option<EventLog<TokenEvent>>,
}

impl EnrollmentTokenStore {
    /// An ephemeral, non-persisted store -- for tests, or a deliberately
    /// stateless run.
    pub fn in_memory() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            log: None,
        }
    }

    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, EnrollmentTokenError> {
        let mut tokens = HashMap::new();
        let log = EventLog::open_and_replay(path, &mut tokens, apply_event)?;
        Ok(Self {
            tokens: RwLock::new(tokens),
            log: Some(log),
        })
    }

    /// Mint a new, single-use token. `expires_in_secs` of `None` means it
    /// never expires. Returns the token's own value (a random 256-bit
    /// value, hex-encoded) -- this is the only time it's returned in full;
    /// callers should treat it like a credential, since presenting it is
    /// all enrollment requires.
    pub fn mint(
        &self,
        expires_in_secs: Option<i64>,
        note: Option<String>,
        now_unix: i64,
    ) -> Result<String, EnrollmentTokenError> {
        let token = random_token();
        let mut tokens = self.tokens.write().unwrap();
        let event = TokenEvent::Minted {
            token: token.clone(),
            created_at_unix: now_unix,
            expires_at_unix: expires_in_secs.map(|secs| now_unix + secs),
            note,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut tokens, &event);
        Ok(token)
    }

    /// Validate `token` is usable right now, and if so, atomically consume
    /// it (marking it used by `common_name`) so it can never be reused.
    /// Validation and consumption happen under the same write lock so two
    /// concurrent enrollment requests can't both succeed with the same
    /// single-use token.
    pub fn validate_and_consume(
        &self,
        token: &str,
        common_name: &str,
        now_unix: i64,
    ) -> Result<(), EnrollmentTokenError> {
        let mut tokens = self.tokens.write().unwrap();
        let existing = tokens.get(token).ok_or(EnrollmentTokenError::NotFound)?;
        existing.is_usable_at(now_unix)?;

        let event = TokenEvent::Consumed {
            token: token.to_string(),
            common_name: common_name.to_string(),
            at_unix: now_unix,
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut tokens, &event);
        Ok(())
    }

    pub fn revoke(&self, token: &str) -> Result<(), EnrollmentTokenError> {
        let mut tokens = self.tokens.write().unwrap();
        if !tokens.contains_key(token) {
            return Err(EnrollmentTokenError::NotFound);
        }
        let event = TokenEvent::Revoked {
            token: token.to_string(),
        };
        if let Some(log) = &self.log {
            log.append(&event)?;
        }
        apply_event(&mut tokens, &event);
        Ok(())
    }

    pub fn list(&self) -> Vec<EnrollmentToken> {
        let mut all: Vec<_> = self.tokens.read().unwrap().values().cloned().collect();
        all.sort_by_key(|t| t.created_at_unix);
        all
    }
}

fn apply_event(tokens: &mut HashMap<String, EnrollmentToken>, event: &TokenEvent) {
    match event {
        TokenEvent::Minted {
            token,
            created_at_unix,
            expires_at_unix,
            note,
        } => {
            tokens.insert(
                token.clone(),
                EnrollmentToken {
                    token: token.clone(),
                    created_at_unix: *created_at_unix,
                    expires_at_unix: *expires_at_unix,
                    note: note.clone(),
                    used: false,
                    used_by_common_name: None,
                    used_at_unix: None,
                    revoked: false,
                },
            );
        }
        TokenEvent::Consumed {
            token,
            common_name,
            at_unix,
        } => {
            if let Some(t) = tokens.get_mut(token) {
                t.used = true;
                t.used_by_common_name = Some(common_name.clone());
                t.used_at_unix = Some(*at_unix);
            }
        }
        TokenEvent::Revoked { token } => {
            if let Some(t) = tokens.get_mut(token) {
                t.revoked = true;
            }
        }
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_a_usable_token() {
        let store = EnrollmentTokenStore::in_memory();
        let token = store.mint(None, None, 1_000).unwrap();
        assert_eq!(token.len(), 64, "expected a 256-bit hex token");
        store.validate_and_consume(&token, "device-a", 1_100).unwrap();
    }

    #[test]
    fn two_mints_produce_different_tokens() {
        let store = EnrollmentTokenStore::in_memory();
        let a = store.mint(None, None, 1_000).unwrap();
        let b = store.mint(None, None, 1_000).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_token_can_only_be_used_once() {
        let store = EnrollmentTokenStore::in_memory();
        let token = store.mint(None, None, 1_000).unwrap();
        store.validate_and_consume(&token, "device-a", 1_100).unwrap();

        let result = store.validate_and_consume(&token, "device-b", 1_200);
        assert!(matches!(result, Err(EnrollmentTokenError::AlreadyUsed)));
    }

    #[test]
    fn unknown_token_is_rejected() {
        let store = EnrollmentTokenStore::in_memory();
        let result = store.validate_and_consume("not-a-real-token", "device-a", 1_000);
        assert!(matches!(result, Err(EnrollmentTokenError::NotFound)));
    }

    #[test]
    fn a_revoked_token_cannot_be_used_even_if_never_consumed() {
        let store = EnrollmentTokenStore::in_memory();
        let token = store.mint(None, None, 1_000).unwrap();
        store.revoke(&token).unwrap();

        let result = store.validate_and_consume(&token, "device-a", 1_100);
        assert!(matches!(result, Err(EnrollmentTokenError::Revoked)));
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let store = EnrollmentTokenStore::in_memory();
        let token = store.mint(Some(60), None, 1_000).unwrap(); // expires at 1060
        let result = store.validate_and_consume(&token, "device-a", 1_060);
        assert!(matches!(result, Err(EnrollmentTokenError::Expired)));
    }

    #[test]
    fn a_token_just_before_its_expiry_is_still_usable() {
        let store = EnrollmentTokenStore::in_memory();
        let token = store.mint(Some(60), None, 1_000).unwrap(); // expires at 1060
        store.validate_and_consume(&token, "device-a", 1_059).unwrap();
    }

    #[test]
    fn list_reflects_mint_and_consumption_state() {
        let store = EnrollmentTokenStore::in_memory();
        let token = store.mint(None, Some("for jz_pixel".to_string()), 1_000).unwrap();
        store.validate_and_consume(&token, "jz_pixel", 1_100).unwrap();

        let all = store.list();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].note.as_deref(), Some("for jz_pixel"));
        assert!(all[0].used);
        assert_eq!(all[0].used_by_common_name.as_deref(), Some("jz_pixel"));
    }

    #[test]
    fn revoking_unknown_token_errors() {
        let store = EnrollmentTokenStore::in_memory();
        assert!(matches!(
            store.revoke("nonexistent"),
            Err(EnrollmentTokenError::NotFound)
        ));
    }

    #[test]
    fn persists_across_reload() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-tokens-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens.log");

        let token = {
            let store = EnrollmentTokenStore::load_or_create(&path).unwrap();
            let token = store.mint(None, None, 1_000).unwrap();
            store.validate_and_consume(&token, "device-a", 1_100).unwrap();
            token
        };

        let reloaded = EnrollmentTokenStore::load_or_create(&path).unwrap();
        let result = reloaded.validate_and_consume(&token, "device-b", 1_200);
        assert!(
            matches!(result, Err(EnrollmentTokenError::AlreadyUsed)),
            "a reloaded store must remember the token was already consumed"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two "concurrent" enrollment attempts racing to use the same
    /// single-use token: only one may succeed. Uses real OS threads (not
    /// just sequential calls) to actually exercise the write lock under
    /// contention, not just assert the logic reads correctly in isolation.
    #[test]
    fn concurrent_consumption_of_the_same_token_only_succeeds_once() {
        use std::sync::Arc;
        let store = Arc::new(EnrollmentTokenStore::in_memory());
        let token = store.mint(None, None, 1_000).unwrap();

        let mut handles = vec![];
        for i in 0..8 {
            let store = Arc::clone(&store);
            let token = token.clone();
            handles.push(std::thread::spawn(move || {
                store.validate_and_consume(&token, &format!("device-{i}"), 1_100)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "exactly one of 8 racing attempts should succeed");
    }
}
