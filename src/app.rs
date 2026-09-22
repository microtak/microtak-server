//! Assembles every EdgeTAK component — CA, device registry, mission store,
//! shared relay hub, enrollment HTTP endpoint, Marti missions HTTP
//! endpoint, plain-TCP relay, and mTLS relay — into one runnable server.
//! This is both `edgetakd`'s actual implementation (`src/main.rs`) and what
//! `tests/e2e.rs` drives: prior to this module, every test built its own
//! scaffolding in isolation (its own CA, its own registry, its own single
//! relay), so nothing had ever exercised the pieces wired together the way
//! a real deployment actually runs them. Building this module immediately
//! surfaced one real bug: see `src/transport/hub.rs`'s doc comment.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::PrivateKeyDer;
use rustls::ServerConfig;
use time::Duration;

use crate::marti::enrollment::EnrollmentState;
use crate::marti::{enrollment, missions as missions_api, MtlsHttpServer, PlainHttpServer};
use crate::missions::{MissionError, MissionStore};
use crate::pki::{self, CertificateAuthority, PkiError};
use crate::registry::{DeviceRegistry, RegistryError};
use crate::transport::hub::RelayHub;
use crate::transport::tcp::TcpRelay;
use crate::transport::tls::{self, TlsRelay, TlsSetupError};

#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Where the enrollment HTTP endpoint listens.
    pub enrollment_addr: SocketAddr,
    /// Where the Marti missions HTTP endpoint listens.
    pub marti_api_addr: SocketAddr,
    /// Where the unauthenticated plain-TCP CoT relay listens.
    pub plain_tcp_addr: SocketAddr,
    /// Where the mTLS CoT relay listens.
    pub mtls_addr: SocketAddr,
    /// Common Name for a freshly-generated CA (ignored if a CA already
    /// exists in `data_dir`).
    pub ca_common_name: String,
    /// Common Name (and DNS SAN) for the mTLS listener's own server
    /// certificate, freshly issued by the CA on every startup (the server's
    /// own leaf cert doesn't need continuity across restarts the way the CA
    /// itself does -- clients trust the CA and the SAN hostname, not a
    /// pinned exact server certificate).
    pub server_common_name: String,
    /// Validity period for certificates this CA issues.
    pub cert_validity: Duration,
    /// Directory holding persistent state: `ca-cert.pem`/`ca-key.pem`,
    /// `devices.json`, `missions.json`. Created if it doesn't exist. Reused
    /// across restarts -- an existing CA here is loaded rather than
    /// regenerated, which matters because regenerating the CA invalidates
    /// every previously-issued client certificate.
    pub data_dir: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            enrollment_addr: "0.0.0.0:8446".parse().unwrap(),
            marti_api_addr: "0.0.0.0:8443".parse().unwrap(),
            plain_tcp_addr: "0.0.0.0:8087".parse().unwrap(),
            mtls_addr: "0.0.0.0:8089".parse().unwrap(),
            ca_common_name: "EdgeTAK CA".to_string(),
            server_common_name: "edgetak-server".to_string(),
            cert_validity: Duration::days(365),
            data_dir: PathBuf::from("./data"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("PKI setup failed: {0}")]
    Pki(#[from] PkiError),
    #[error("TLS setup failed: {0}")]
    Tls(#[from] TlsSetupError),
    #[error("device registry setup failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("mission store setup failed: {0}")]
    Missions(#[from] MissionError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A fully-bound (but not yet running) EdgeTAK server: every listener has
/// already claimed its port, so real addresses (including resolved
/// ephemeral ports) are available before [`App::run`] is called — this is
/// what lets `tests/e2e.rs` bind on `:0` and learn the real ports to
/// connect test clients to.
///
/// CA, device registry, and mission store all persist to
/// [`AppConfig::data_dir`] and reload on the next `App::bind` against the
/// same directory — see that field's own doc comment. **Known
/// simplification**: the Marti missions API's request handlers don't yet
/// cross-check a claimed `creatorUid`/`actorUid` against the connecting
/// cert's identity — only connection-level cert validation is enforced so
/// far (see `marti::mod`'s doc comment).
pub struct App {
    pub ca_cert_pem: String,
    pub registry: Arc<DeviceRegistry>,
    pub missions: Arc<MissionStore>,
    enrollment: PlainHttpServer,
    marti_api: MtlsHttpServer,
    tcp: TcpRelay,
    tls: TlsRelay,
}

impl App {
    pub async fn bind(config: AppConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir)?;

        let ca = load_or_generate_ca(&config.data_dir, &config.ca_common_name)?;
        let ca_cert_pem = ca.ca_cert_pem();
        let registry = Arc::new(DeviceRegistry::load_or_create(
            config.data_dir.join("devices.json"),
        )?);
        let missions = Arc::new(MissionStore::load_or_create(
            config.data_dir.join("missions.json"),
        )?);
        let hub = RelayHub::new();

        // The mTLS listener's own server identity, issued by the same CA a
        // client would enroll against.
        let (server_csr, server_key) = pki::build_csr_with_san(
            &config.server_common_name,
            vec![config.server_common_name.clone()],
        )?;
        let signed_server_cert = ca.sign_csr(&server_csr, config.cert_validity)?;
        let server_cert_der = pki::cert_pem_to_der(&signed_server_cert.cert_pem)?;
        let ca_cert_der = pki::cert_pem_to_der(&ca_cert_pem)?;
        // Shared between the CoT mTLS relay and the Marti API's mTLS HTTP
        // listener -- same server identity, same CA-based client
        // verification policy, no reason to issue a second server cert or
        // build a second ServerConfig for what is otherwise a second
        // protocol on a second port.
        let tls_server_config: Arc<ServerConfig> = Arc::new(tls::server_config(
            ca_cert_der,
            vec![server_cert_der],
            PrivateKeyDer::from(server_key),
        )?);

        let enrollment_state = Arc::new(EnrollmentState {
            ca,
            registry: Arc::clone(&registry),
            cert_validity: config.cert_validity,
        });

        let enrollment = PlainHttpServer::bind(
            config.enrollment_addr,
            enrollment::router(enrollment_state),
        )
        .await?;
        let marti_api = MtlsHttpServer::bind(
            config.marti_api_addr,
            Arc::clone(&tls_server_config),
            missions_api::router(Arc::clone(&missions)),
        )
        .await?;
        let tcp = TcpRelay::bind(config.plain_tcp_addr, hub.clone()).await?;
        let tls = TlsRelay::bind(
            config.mtls_addr,
            tls_server_config,
            hub,
            Arc::clone(&registry),
        )
        .await?;

        Ok(Self {
            ca_cert_pem,
            registry,
            missions,
            enrollment,
            marti_api,
            tcp,
            tls,
        })
    }

    pub fn enrollment_addr(&self) -> std::io::Result<SocketAddr> {
        self.enrollment.local_addr()
    }

    pub fn marti_api_addr(&self) -> std::io::Result<SocketAddr> {
        self.marti_api.local_addr()
    }

    pub fn plain_tcp_addr(&self) -> std::io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    pub fn mtls_addr(&self) -> std::io::Result<SocketAddr> {
        self.tls.local_addr()
    }

    /// Run every listener concurrently until one of them hits a fatal
    /// error (a healthy server runs this forever).
    pub async fn run(self) -> std::io::Result<()> {
        let Self {
            enrollment,
            marti_api,
            tcp,
            tls,
            ..
        } = self;
        tokio::try_join!(enrollment.run(), marti_api.run(), tcp.run(), tls.run())?;
        Ok(())
    }
}

/// Load an existing CA from `data_dir` if both `ca-cert.pem` and
/// `ca-key.pem` are present, otherwise generate a fresh one and persist it
/// there. Regenerating on every startup (the pre-persistence behavior)
/// would invalidate every previously-issued client certificate, so this
/// distinction matters.
fn load_or_generate_ca(
    data_dir: &std::path::Path,
    ca_common_name: &str,
) -> Result<CertificateAuthority, AppError> {
    let cert_path = data_dir.join("ca-cert.pem");
    let key_path = data_dir.join("ca-key.pem");

    if let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        return Ok(CertificateAuthority::from_pem(&cert_pem, &key_pem)?);
    }

    let ca = CertificateAuthority::generate(ca_common_name)?;
    std::fs::write(&cert_path, ca.ca_cert_pem())?;
    std::fs::write(&key_path, ca.ca_key_pem())?;
    Ok(ca)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh, uniquely-named temp directory -- needed because `cargo
    /// test` runs test functions concurrently within one process, so a
    /// shared fixed directory would race across tests.
    fn unique_temp_dir(label: &str) -> PathBuf {
        let n = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("edgetak-app-{label}-{}-{n}", std::process::id()))
    }

    fn ephemeral_config(data_dir: PathBuf) -> AppConfig {
        AppConfig {
            enrollment_addr: "127.0.0.1:0".parse().unwrap(),
            marti_api_addr: "127.0.0.1:0".parse().unwrap(),
            plain_tcp_addr: "127.0.0.1:0".parse().unwrap(),
            mtls_addr: "127.0.0.1:0".parse().unwrap(),
            data_dir,
            ..AppConfig::default()
        }
    }

    /// The core persistence guarantee: a second `App::bind` against the
    /// same data_dir sees the same CA (so previously-issued client certs
    /// stay valid) and the same enrolled devices/missions -- not a fresh
    /// CA and empty stores, which was the behavior before this change and
    /// would silently invalidate every prior enrollment on every restart.
    #[tokio::test]
    async fn persists_ca_registry_and_missions_across_a_restart() {
        let data_dir = unique_temp_dir("persistence");

        let first = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        let ca_cert_pem = first.ca_cert_pem.clone();
        first
            .registry
            .enroll("device-a", "fake-cert-pem", 1_000)
            .unwrap();
        first
            .missions
            .create("m", None, "user-1", vec![], 1_000)
            .unwrap();
        drop(first); // never `.run()`, so nothing is actually listening to tear down

        let second = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert_eq!(
            second.ca_cert_pem, ca_cert_pem,
            "CA must survive a restart -- regenerating it would invalidate every issued cert"
        );
        assert!(second.registry.find("device-a").is_some());
        assert!(second.missions.get("m").is_some());

        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[tokio::test]
    async fn a_fresh_data_dir_generates_a_new_ca() {
        let data_dir = unique_temp_dir("fresh");
        let app = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert!(app.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(data_dir.join("ca-cert.pem").exists());
        assert!(data_dir.join("ca-key.pem").exists());
        std::fs::remove_dir_all(&data_dir).ok();
    }
}
