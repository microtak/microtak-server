//! One-time bootstrap token for enrolling the admin device.
//!
//! Closes the "first user wins" window `EnrollmentMode::Auto` used to have:
//! previously, whoever reached the enrollment endpoint first could enroll
//! under the configured admin Common Name and *become* the admin. Now the
//! admin CN is reserved from the very first start -- it can only be
//! enrolled by presenting this token, which is generated once, written to
//! a file in `data_dir` readable only by the server's own user (`0600`),
//! and never sent over the network by the server itself. Whoever can read
//! that file already controls the server (it sits next to the CA's private
//! key), so possession of it is exactly the right proof of "operator".
//!
//! Single-use: consumed by the admin's successful enrollment, after which
//! the file is deleted. On restart, an already-enrolled admin means no
//! token is created at all; a not-yet-enrolled admin reuses the existing
//! file, so the value an operator already copied stays valid.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use thiserror::Error;
use tracing::warn;

/// File name of the bootstrap token inside `data_dir`.
pub const BOOTSTRAP_TOKEN_FILE: &str = "bootstrap-token";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapError<E> {
    /// No bootstrap token is outstanding -- the admin already enrolled (or
    /// no admin CN is configured).
    #[error("no bootstrap token is outstanding")]
    NotAvailable,
    #[error("invalid bootstrap token")]
    Mismatch,
    /// The token matched, but the enrollment action itself failed; the
    /// token is *not* consumed in that case.
    #[error("{0}")]
    Action(E),
}

pub struct BootstrapToken {
    token: Mutex<Option<String>>,
    path: Option<PathBuf>,
}

impl BootstrapToken {
    /// No token outstanding: the admin CN can't be enrolled at all.
    pub fn none() -> Self {
        Self {
            token: Mutex::new(None),
            path: None,
        }
    }

    /// A non-persisted token -- for tests.
    pub fn in_memory(token: impl Into<String>) -> Self {
        Self {
            token: Mutex::new(Some(token.into())),
            path: None,
        }
    }

    /// Load the outstanding token from `path`, or create one there if the
    /// admin hasn't enrolled yet. If the admin *has* enrolled, any stale
    /// file is removed and no token is outstanding.
    pub fn load_or_create(path: &Path, admin_already_enrolled: bool) -> std::io::Result<Self> {
        if admin_already_enrolled {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            return Ok(Self::none());
        }

        let existing = match std::fs::read_to_string(path) {
            Ok(contents) => Some(contents.trim().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let token = match existing {
            Some(token) if is_well_formed(&token) => token,
            _ => {
                let token = random_token();
                write_private(path, &token)?;
                token
            }
        };
        Ok(Self {
            token: Mutex::new(Some(token)),
            path: Some(path.to_path_buf()),
        })
    }

    pub fn is_outstanding(&self) -> bool {
        self.token.lock().unwrap().is_some()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// If `presented` matches the outstanding token, run `action` (the
    /// admin's actual enrollment) and consume the token only if it
    /// succeeds. The lock is held across `action`, so two concurrent
    /// requests presenting the same token can't both enroll.
    pub fn consume_with<T, E>(
        &self,
        presented: &str,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, BootstrapError<E>> {
        let mut guard = self.token.lock().unwrap();
        let Some(expected) = guard.as_deref() else {
            return Err(BootstrapError::NotAvailable);
        };
        if !constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
            return Err(BootstrapError::Mismatch);
        }
        let value = action().map_err(BootstrapError::Action)?;
        *guard = None;
        if let Some(path) = &self.path
            && let Err(error) = std::fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(path = %path.display(), %error, "failed to delete used bootstrap token file");
        }
        Ok(value)
    }
}

fn is_well_formed(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare without an early exit on the first differing byte, so response
/// timing doesn't reveal how much of a guess was right.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Create (or replace) `path` with `contents`, readable and writable by the
/// owner only.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` only applies when the file is newly created -- tighten an
        // existing file too.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "microtak-bootstrap-{label}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(BOOTSTRAP_TOKEN_FILE)
    }

    #[test]
    fn creates_a_256_bit_token_in_an_owner_only_file() {
        let path = temp_path("create");
        let token = BootstrapToken::load_or_create(&path, false).unwrap();
        assert!(token.is_outstanding());

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(is_well_formed(contents.trim()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn a_restart_before_the_admin_enrolls_keeps_the_same_token() {
        let path = temp_path("restart");
        BootstrapToken::load_or_create(&path, false).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        let reloaded = BootstrapToken::load_or_create(&path, false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        assert!(reloaded.consume_with(first.trim(), || Ok::<_, ()>(())).is_ok());
    }

    #[test]
    fn once_the_admin_has_enrolled_no_token_exists_and_the_file_is_removed() {
        let path = temp_path("enrolled");
        BootstrapToken::load_or_create(&path, false).unwrap();
        let token = BootstrapToken::load_or_create(&path, true).unwrap();
        assert!(!token.is_outstanding());
        assert!(!path.exists());
    }

    #[test]
    fn consuming_is_single_use_and_deletes_the_file() {
        let path = temp_path("consume");
        let token = BootstrapToken::load_or_create(&path, false).unwrap();
        let value = std::fs::read_to_string(&path).unwrap().trim().to_string();

        assert_eq!(token.consume_with(&value, || Ok::<_, ()>(7)), Ok(7));
        assert!(!path.exists());
        assert_eq!(
            token.consume_with(&value, || Ok::<_, ()>(7)),
            Err(BootstrapError::NotAvailable)
        );
    }

    #[test]
    fn a_wrong_token_is_rejected_and_the_action_never_runs() {
        let token = BootstrapToken::in_memory("a".repeat(64));
        let result = token.consume_with(&"b".repeat(64), || -> Result<(), ()> {
            panic!("action must not run for a wrong token")
        });
        assert_eq!(result, Err(BootstrapError::Mismatch));
        assert!(token.is_outstanding());
    }

    #[test]
    fn a_failed_action_does_not_consume_the_token() {
        let token = BootstrapToken::in_memory("a".repeat(64));
        assert_eq!(
            token.consume_with(&"a".repeat(64), || Err::<(), _>("boom")),
            Err(BootstrapError::Action("boom"))
        );
        assert!(token.is_outstanding());
    }

    #[test]
    fn constant_time_eq_matches_plain_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
