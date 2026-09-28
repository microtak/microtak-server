//! Where the enrollment listener's (`:8446`) TLS certificate comes from.
//!
//! - [`CertSource::Internal`] (the default): a server certificate issued by
//!   MicroTAK's own CA, with the configured `server_names` as SANs. Works
//!   fully offline -- no public DNS, no Let's Encrypt, nothing installed on
//!   devices: TAK clients trust the enrollment endpoint on first contact
//!   (OmniTAK's default, and the QR flow) and then pin the CA they receive
//!   in the enrollment response.
//! - [`CertSource::Files`]: a certificate chain + private key read from PEM
//!   files, e.g. issued by Let's Encrypt via certbot/lego when the server
//!   does have internet and a DNS name. The files are re-checked
//!   periodically and a changed pair is picked up **without a restart**; a
//!   broken or mismatched pair is rejected with a logged error and the
//!   previous certificate keeps serving. MicroTAK deliberately has no
//!   built-in ACME client: HTTP-01 needs plain HTTP on port 80 and
//!   TLS-ALPN-01 needs port 443 -- both extra attack surface on a server
//!   whose whole point is to serve no plain HTTP.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertSource {
    Internal,
    Files { cert_file: PathBuf, key_file: PathBuf },
}

#[derive(Debug, thiserror::Error)]
pub enum CertLoadError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    #[error("{0} contains no certificates")]
    NoCertificates(PathBuf),
    #[error("certificate and private key don't form a usable pair: {0}")]
    InvalidPair(rustls::Error),
}

/// A [`ResolvesServerCert`] whose certificate can be swapped at runtime.
#[derive(Debug)]
pub struct SwappableCert {
    current: RwLock<Arc<CertifiedKey>>,
}

impl SwappableCert {
    pub fn new(initial: CertifiedKey) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
        }
    }

    pub fn replace(&self, key: CertifiedKey) {
        *self.current.write().unwrap() = Arc::new(key);
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.current.read().unwrap())
    }
}

impl ResolvesServerCert for SwappableCert {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Build a [`CertifiedKey`] from DER parts, checking that the key actually
/// matches the leaf certificate.
pub fn certified_key(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey, CertLoadError> {
    let provider = rustls::crypto::ring::default_provider();
    CertifiedKey::from_der(chain, key, &provider).map_err(CertLoadError::InvalidPair)
}

/// Load a PEM certificate chain and private key from disk.
pub fn load_files(cert_file: &Path, key_file: &Path) -> Result<CertifiedKey, CertLoadError> {
    let chain = CertificateDer::pem_file_iter(cert_file)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|source| CertLoadError::Read {
            path: cert_file.to_path_buf(),
            source,
        })?;
    if chain.is_empty() {
        return Err(CertLoadError::NoCertificates(cert_file.to_path_buf()));
    }
    let key = PrivateKeyDer::from_pem_file(key_file).map_err(|source| CertLoadError::Read {
        path: key_file.to_path_buf(),
        source,
    })?;
    certified_key(chain, key)
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Poll `cert_file`/`key_file` every `interval` and swap a changed, valid
/// pair into `target`. Runs until the process exits.
pub async fn watch_files(
    target: Arc<SwappableCert>,
    cert_file: PathBuf,
    key_file: PathBuf,
    interval: Duration,
) {
    let mut last_seen = (modified(&cert_file), modified(&key_file));
    loop {
        tokio::time::sleep(interval).await;
        let now_seen = (modified(&cert_file), modified(&key_file));
        if now_seen == last_seen {
            continue;
        }
        last_seen = now_seen;
        match load_files(&cert_file, &key_file) {
            Ok(key) => {
                target.replace(key);
                info!(cert_file = %cert_file.display(), "reloaded enrollment TLS certificate");
            }
            Err(error) => warn!(
                cert_file = %cert_file.display(),
                %error,
                "enrollment TLS certificate changed but failed to load; keeping the previous one"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{build_csr, CertificateAuthority};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("microtak-certsource-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A server cert + key pair as PEM strings, issued by a throwaway CA.
    fn pem_pair(name: &str) -> (String, String) {
        let ca = CertificateAuthority::generate("Test CA").unwrap();
        let (csr, key) = build_csr(name).unwrap();
        let signed = ca
            .sign_server_csr(&csr, &[name.to_string()], time::Duration::days(1))
            .unwrap();
        (signed.cert_pem, key.serialize_pem())
    }

    fn leaf(key: &CertifiedKey) -> Vec<u8> {
        key.cert[0].as_ref().to_vec()
    }

    #[test]
    fn loads_a_valid_pem_pair() {
        let dir = temp_dir();
        let (cert, key) = pem_pair("tak.example.com");
        std::fs::write(dir.join("cert.pem"), cert).unwrap();
        std::fs::write(dir.join("key.pem"), key).unwrap();
        assert!(load_files(&dir.join("cert.pem"), &dir.join("key.pem")).is_ok());
    }

    /// TC-TLS-10: a key that doesn't belong to the certificate is refused.
    #[test]
    fn rejects_a_mismatched_pair() {
        let dir = temp_dir();
        let (cert, _) = pem_pair("tak.example.com");
        let (_, other_key) = pem_pair("tak.example.com");
        std::fs::write(dir.join("cert.pem"), cert).unwrap();
        std::fs::write(dir.join("key.pem"), other_key).unwrap();
        assert!(matches!(
            load_files(&dir.join("cert.pem"), &dir.join("key.pem")),
            Err(CertLoadError::InvalidPair(_))
        ));
    }

    #[test]
    fn rejects_missing_or_empty_files() {
        let dir = temp_dir();
        std::fs::write(dir.join("empty.pem"), "").unwrap();
        let (_, key) = pem_pair("x");
        std::fs::write(dir.join("key.pem"), key).unwrap();
        assert!(load_files(&dir.join("missing.pem"), &dir.join("key.pem")).is_err());
        assert!(matches!(
            load_files(&dir.join("empty.pem"), &dir.join("key.pem")),
            Err(CertLoadError::NoCertificates(_))
        ));
    }

    /// TC-TLS-10: replacing the files is picked up without a restart; a
    /// broken replacement leaves the previous certificate serving.
    #[tokio::test]
    async fn watch_swaps_in_a_changed_pair_and_ignores_a_broken_one() {
        let dir = temp_dir();
        let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
        let (cert_a, key_a) = pem_pair("a.example.com");
        std::fs::write(&cert_path, &cert_a).unwrap();
        std::fs::write(&key_path, &key_a).unwrap();
        let target = Arc::new(SwappableCert::new(load_files(&cert_path, &key_path).unwrap()));
        let first = leaf(&target.current());

        tokio::spawn(watch_files(
            Arc::clone(&target),
            cert_path.clone(),
            key_path.clone(),
            Duration::from_millis(20),
        ));

        // Mtime resolution can be coarse: make sure the change is visible.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (cert_b, key_b) = pem_pair("b.example.com");
        std::fs::write(&key_path, &key_b).unwrap();
        std::fs::write(&cert_path, &cert_b).unwrap();
        let mut swapped = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if leaf(&target.current()) != first {
                swapped = true;
                break;
            }
        }
        assert!(swapped, "a valid replacement pair must be picked up");
        let second = leaf(&target.current());

        tokio::time::sleep(Duration::from_millis(1100)).await;
        std::fs::write(&cert_path, "not a certificate").unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(leaf(&target.current()), second, "a broken pair must not replace a working one");
    }
}
