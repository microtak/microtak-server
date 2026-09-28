//! Brute-force protection for the unauthenticated enrollment/OAuth
//! listener (TC-LIMIT-08).
//!
//! Two independent guards:
//!
//! - **Failed-attempt limiting**: after `max_failures` failed credential
//!   checks for a key (the client IP, and separately the username) within
//!   one `window`, further attempts for that key are refused with 429
//!   *before* any credential check runs -- for the rest of that window, even
//!   with the right credentials. Per-username limiting covers an attacker
//!   spreading guesses over many addresses; per-IP limiting covers one
//!   address spraying many usernames.
//! - **Bounded password verification**: every password check is Argon2
//!   (deliberately slow), so it runs on the blocking pool behind a small
//!   semaphore -- a flood of concurrent login attempts queues up instead of
//!   starving the async runtime that also carries CoT traffic.
//!
//! State is in memory only (a restart clears it) and the tracked-key table
//! is bounded, so the limiter itself can't be used to exhaust memory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tracing::warn;

use crate::users::UserStore;

pub struct AuthLimiter {
    max_failures: u32,
    window: Duration,
    max_tracked_keys: usize,
    failures: Mutex<HashMap<String, Failures>>,
    verify_permits: Arc<Semaphore>,
}

#[derive(Clone, Copy)]
struct Failures {
    window_start: Instant,
    count: u32,
}

impl Default for AuthLimiter {
    /// 10 failures per 5 minutes per key; password checks limited to the
    /// machine's parallelism.
    fn default() -> Self {
        let parallelism = std::thread::available_parallelism().map_or(2, |n| n.get());
        Self::new(10, Duration::from_secs(300), 10_000, parallelism)
    }
}

impl AuthLimiter {
    pub fn new(
        max_failures: u32,
        window: Duration,
        max_tracked_keys: usize,
        concurrent_password_checks: usize,
    ) -> Self {
        Self {
            max_failures,
            window,
            max_tracked_keys,
            failures: Mutex::new(HashMap::new()),
            verify_permits: Arc::new(Semaphore::new(concurrent_password_checks.max(1))),
        }
    }

    /// Whether `key` has used up its failed attempts for the current
    /// window.
    pub fn is_blocked(&self, key: &str) -> bool {
        self.is_blocked_at(key, Instant::now())
    }

    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now());
    }

    fn is_blocked_at(&self, key: &str, now: Instant) -> bool {
        let failures = self.failures.lock().unwrap();
        failures.get(key).is_some_and(|entry| {
            now.duration_since(entry.window_start) < self.window
                && entry.count >= self.max_failures
        })
    }

    fn record_failure_at(&self, key: &str, now: Instant) {
        let mut failures = self.failures.lock().unwrap();
        if !failures.contains_key(key) && failures.len() >= self.max_tracked_keys {
            let window = self.window;
            failures.retain(|_, entry| now.duration_since(entry.window_start) < window);
            if failures.len() >= self.max_tracked_keys {
                // Still full of live entries: keep the ones already being
                // tracked rather than evicting a key that may be mid-attack.
                warn!("auth rate limiter is tracking its maximum number of keys; not tracking a new one");
                return;
            }
        }
        let entry = failures.entry(key.to_string()).or_insert(Failures {
            window_start: now,
            count: 0,
        });
        if now.duration_since(entry.window_start) >= self.window {
            *entry = Failures {
                window_start: now,
                count: 0,
            };
        }
        entry.count = entry.count.saturating_add(1);
    }

    /// Check a password against `users` on the blocking pool, at most
    /// `concurrent_password_checks` at a time.
    pub async fn verify_password(
        &self,
        users: &Arc<UserStore>,
        username: &str,
        password: &str,
    ) -> bool {
        let Ok(_permit) = self.verify_permits.acquire().await else {
            return false;
        };
        let users = Arc::clone(users);
        let username = username.to_string();
        let password = password.to_string();
        tokio::task::spawn_blocking(move || users.authenticate(&username, &password))
            .await
            .unwrap_or(false)
    }
}

/// Rate-limit key for a client address.
pub fn ip_key(ip: std::net::IpAddr) -> String {
    format!("ip:{ip}")
}

/// Rate-limit key for a claimed username.
pub fn user_key(username: &str) -> String {
    format!("user:{username}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_within_the_window() {
        let limiter = AuthLimiter::new(3, Duration::from_secs(60), 100, 1);
        let start = Instant::now();
        for _ in 0..2 {
            limiter.record_failure_at("ip:1.2.3.4", start);
        }
        assert!(!limiter.is_blocked_at("ip:1.2.3.4", start));
        limiter.record_failure_at("ip:1.2.3.4", start);
        assert!(limiter.is_blocked_at("ip:1.2.3.4", start));
        assert!(!limiter.is_blocked_at("ip:5.6.7.8", start), "keys are independent");
    }

    #[test]
    fn a_block_expires_with_its_window() {
        let limiter = AuthLimiter::new(1, Duration::from_secs(60), 100, 1);
        let start = Instant::now();
        limiter.record_failure_at("user:alice", start);
        assert!(limiter.is_blocked_at("user:alice", start + Duration::from_secs(59)));
        assert!(!limiter.is_blocked_at("user:alice", start + Duration::from_secs(60)));

        // A failure after the window starts a fresh count.
        limiter.record_failure_at("user:alice", start + Duration::from_secs(61));
        let limiter2 = AuthLimiter::new(2, Duration::from_secs(60), 100, 1);
        limiter2.record_failure_at("k", start);
        limiter2.record_failure_at("k", start + Duration::from_secs(61));
        assert!(!limiter2.is_blocked_at("k", start + Duration::from_secs(61)));
    }

    #[test]
    fn the_tracked_key_table_is_bounded() {
        let limiter = AuthLimiter::new(1, Duration::from_secs(60), 2, 1);
        let now = Instant::now();
        limiter.record_failure_at("a", now);
        limiter.record_failure_at("b", now);
        limiter.record_failure_at("c", now);
        assert_eq!(limiter.failures.lock().unwrap().len(), 2);
        assert!(limiter.is_blocked_at("a", now), "existing entries are kept");

        // Expired entries make room again.
        let later = now + Duration::from_secs(61);
        limiter.record_failure_at("c", later);
        assert!(limiter.is_blocked_at("c", later));
    }

    #[tokio::test]
    async fn verify_password_checks_the_real_user_store() {
        let users = Arc::new(UserStore::in_memory());
        users.mint("alice", "correct horse", 0).unwrap();
        let limiter = AuthLimiter::default();
        assert!(limiter.verify_password(&users, "alice", "correct horse").await);
        assert!(!limiter.verify_password(&users, "alice", "wrong").await);
        assert!(!limiter.verify_password(&users, "nobody", "x").await);
    }
}
