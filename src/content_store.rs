//! Hash-addressed DataSync file content storage (`docs/TEST-PLAN.md` §5,
//! TC-MARTI-07/08) — the actual file bytes behind a
//! [`crate::missions::MissionContentRef`], which only ever tracked a hash
//! and filename a client *claimed*, never the content itself.
//!
//! **TC-MARTI-07**: [`ContentStore::put`] always computes the SHA-256 of the
//! bytes it's given and uses *that* as the storage key, ignoring whatever
//! hash a caller claims beyond using it as an optional integrity check on
//! upload — so a stored file's key is unconditionally its real hash, not
//! trusted metadata. A reference implementation studied for this project
//! (taky) does not verify this at all, trusting stored metadata blindly.
//!
//! **TC-MARTI-08**: [`ContentStore::put`] writes to a uniquely-named
//! temporary file in the same directory, `fsync`s it, then atomically
//! renames it into place at its final hash-addressed path — a crash
//! mid-write leaves at most an orphaned `.tmp-*` file, never a partially-written
//! file visible at its content-addressed name. Storage is naturally
//! idempotent/deduplicating: re-uploading identical bytes is a cheap no-op
//! once the destination already exists.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ContentStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("uploaded content's actual hash {actual} does not match the claimed hash {claimed}")]
    HashMismatch { claimed: String, actual: String },
    #[error("'{0}' is not a valid content hash (expected 64 lowercase hex characters)")]
    InvalidHash(String),
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct ContentStore {
    dir: PathBuf,
}

impl ContentStore {
    pub fn open(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Store `bytes`, returning their SHA-256 hex hash (the key they're
    /// stored under). If `claimed_hash` is `Some`, it must match the
    /// actually-computed hash or the write is rejected before anything
    /// touches disk (TC-MARTI-07).
    pub fn put(
        &self,
        bytes: &[u8],
        claimed_hash: Option<&str>,
    ) -> Result<String, ContentStoreError> {
        let actual = hex_sha256(bytes);
        if let Some(claimed) = claimed_hash {
            let claimed_lower = claimed.to_lowercase();
            if claimed_lower != actual {
                return Err(ContentStoreError::HashMismatch {
                    claimed: claimed_lower,
                    actual,
                });
            }
        }

        let final_path = self.path_for(&actual);
        if final_path.exists() {
            // Content-addressed storage: identical bytes already stored
            // under this hash, nothing left to do.
            return Ok(actual);
        }

        let nonce = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .dir
            .join(format!(".tmp-{}-{nonce}", std::process::id()));
        let file = std::fs::File::create(&tmp_path)?;
        {
            use std::io::Write;
            let mut file = &file;
            file.write_all(bytes)?;
            file.sync_data()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(actual)
    }

    /// Read back previously-stored content by hash. `None` if no content is
    /// stored under that hash, or if `hash` isn't a syntactically valid
    /// SHA-256 hex hash (rejected rather than passed through to a path
    /// lookup, since it arrives from a caller-controlled query parameter and
    /// an unvalidated value could otherwise be used to traverse outside
    /// [`Self::dir`]).
    pub fn get(&self, hash: &str) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let normalized = validate_hash(hash)?;
        match std::fs::read(self.path_for(&normalized)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.dir.join(hash)
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

/// A SHA-256 hex hash is exactly 64 hex characters -- anything else
/// (including path separators, `..`, or the wrong length) is rejected
/// outright rather than normalized/truncated.
fn validate_hash(hash: &str) -> Result<String, ContentStoreError> {
    let lower = hash.to_lowercase();
    if lower.len() == 64 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(lower)
    } else {
        Err(ContentStoreError::InvalidHash(hash.to_string()))
    }
}

/// Exposed for callers (e.g. HTTP handlers) that want to validate a
/// caller-supplied hash before doing anything else with it.
pub fn is_valid_hash(hash: &str) -> bool {
    validate_hash(hash).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "edgetak-content-{label}-{}-{n}",
            std::process::id()
        ))
    }

    #[test]
    fn stores_content_under_its_actual_sha256_hash() {
        let dir = temp_dir("roundtrip");
        let store = ContentStore::open(dir.clone()).unwrap();

        let hash = store.put(b"hello world", None).unwrap();
        assert_eq!(hash, hex_sha256(b"hello world"));
        assert_eq!(hash.len(), 64, "SHA-256 hex hash must be 64 characters");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn get_returns_previously_stored_bytes() {
        let dir = temp_dir("get");
        let store = ContentStore::open(dir.clone()).unwrap();

        let hash = store.put(b"some file content", None).unwrap();
        let fetched = store.get(&hash).unwrap();
        assert_eq!(fetched.as_deref(), Some(&b"some file content"[..]));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn get_on_unknown_hash_is_none_not_an_error() {
        let dir = temp_dir("missing");
        let store = ContentStore::open(dir.clone()).unwrap();
        let unknown = "a".repeat(64);
        assert!(store.get(&unknown).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// TC-MARTI-07: a claimed hash that doesn't match the actual content is
    /// rejected -- nothing is written to disk under either hash.
    #[test]
    fn rejects_a_claimed_hash_not_matching_the_actual_content() {
        let dir = temp_dir("mismatch");
        let store = ContentStore::open(dir.clone()).unwrap();

        let wrong_hash = "0".repeat(64);
        let result = store.put(b"real content", Some(&wrong_hash));
        assert!(matches!(
            result,
            Err(ContentStoreError::HashMismatch { .. })
        ));

        // Nothing should have been written under the wrong hash.
        assert!(store.get(&wrong_hash).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn accepts_a_correctly_claimed_hash() {
        let dir = temp_dir("correct-claim");
        let store = ContentStore::open(dir.clone()).unwrap();

        let actual = hex_sha256(b"matching content");
        let hash = store.put(b"matching content", Some(&actual)).unwrap();
        assert_eq!(hash, actual);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Re-uploading identical bytes is a harmless no-op, not a second write
    /// or an error -- content-addressed storage naturally deduplicates.
    #[test]
    fn re_uploading_identical_content_is_idempotent() {
        let dir = temp_dir("dedup");
        let store = ContentStore::open(dir.clone()).unwrap();

        let hash_a = store.put(b"duplicate me", None).unwrap();
        let hash_b = store.put(b"duplicate me", None).unwrap();
        assert_eq!(hash_a, hash_b);
        assert_eq!(store.get(&hash_a).unwrap().as_deref(), Some(&b"duplicate me"[..]));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A malformed hash (wrong length, non-hex characters, or a path
    /// traversal attempt) is rejected outright rather than used to build a
    /// filesystem path -- a hash arrives from a caller-controlled query
    /// parameter, so this is a real path-traversal guard, not defensive
    /// paranoia.
    #[test]
    fn rejects_malformed_or_path_traversal_hash_on_get() {
        let dir = temp_dir("traversal");
        let store = ContentStore::open(dir.clone()).unwrap();

        for bad in ["../../etc/passwd", "not-hex-at-all", "abc", ""] {
            let result = store.get(bad);
            assert!(
                matches!(result, Err(ContentStoreError::InvalidHash(_))),
                "expected {bad:?} to be rejected as an invalid hash, got {result:?}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_valid_hash_accepts_only_well_formed_sha256_hex() {
        assert!(is_valid_hash(&"a".repeat(64)));
        assert!(!is_valid_hash(&"a".repeat(63)));
        assert!(!is_valid_hash("../escape"));
    }

    /// TC-MARTI-08: `put`'s temp file is cleaned up by the rename -- no
    /// `.tmp-*` artifact is left behind in the store directory once a
    /// write completes.
    #[test]
    fn put_leaves_no_temp_file_behind() {
        let dir = temp_dir("no-tmp-leftover");
        let store = ContentStore::open(dir.clone()).unwrap();

        store.put(b"clean up after yourself", None).unwrap();

        let leftover_tmp_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".tmp-"))
            .collect();
        assert!(
            leftover_tmp_files.is_empty(),
            "expected no leftover temp files, found: {leftover_tmp_files:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// TC-MARTI-08's core atomicity claim, tested directly rather than by
    /// inspection: a reader racing a writer must never observe a partially
    /// written file at the final, content-addressed path -- it either sees
    /// nothing (the rename hasn't happened yet) or the complete, correct
    /// content (the rename already happened), never a truncated read. A
    /// naive `put` that wrote straight to the final path (skipping the
    /// temp-file + rename step this module claims to use) would fail this
    /// test under load, since a concurrent reader could open the file
    /// mid-write and read a short prefix.
    #[test]
    fn concurrent_reader_never_observes_a_partially_written_file() {
        let dir = temp_dir("atomicity-race");
        let store = std::sync::Arc::new(ContentStore::open(dir.clone()).unwrap());

        // Large enough that a naive non-atomic write is very likely to be
        // observable mid-flight by a concurrent reader on any real filesystem.
        let payload: Vec<u8> = (0..8_000_000).map(|i| (i % 251) as u8).collect();
        let expected_hash = hex_sha256(&payload);

        let reader_store = std::sync::Arc::clone(&store);
        let reader_hash = expected_hash.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_stop = std::sync::Arc::clone(&stop);
        let reader_payload_len = payload.len();
        let reader = std::thread::spawn(move || {
            let mut observations = 0usize;
            while !reader_stop.load(Ordering::Relaxed) {
                if let Ok(Some(bytes)) = reader_store.get(&reader_hash) {
                    assert_eq!(
                        bytes.len(),
                        reader_payload_len,
                        "observed a partially written file: {} of {} bytes",
                        bytes.len(),
                        reader_payload_len
                    );
                    observations += 1;
                }
            }
            observations
        });

        let final_path = dir.join(&expected_hash);
        for _ in 0..20 {
            // `put` dedups once the destination exists, so the temp-file +
            // rename dance only actually happens if the destination is
            // removed first -- forcing it to run repeatedly gives the
            // reader many real chances to race the writer within the
            // test's short lifetime.
            std::fs::remove_file(&final_path).ok();
            store.put(&payload, None).unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }
}
