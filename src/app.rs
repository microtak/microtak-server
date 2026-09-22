//! Assembles every EdgeTAK component — CA, device registry, shared relay
//! hub, enrollment HTTP endpoint, plain-TCP relay, and mTLS relay — into
//! one runnable server. This is both `edgetakd`'s actual implementation
//! (`src/main.rs`) and what `tests/e2e.rs` drives: prior to this module,
//! every test built its own scaffolding in isolation (its own CA, its own
//! registry, its own single relay), so nothing had ever exercised the
//! pieces wired together the way a real deployment actually runs them.
//! Building this module immediately surfaced one real bug: see
//! `src/transport/hub.rs`'s doc comment.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::PrivateKeyDer;
use rustls::ServerConfig;
use time::Duration;

use crate::marti::enrollment::{EnrollmentServer, EnrollmentState};
use crate::pki::{self, CertificateAuthority, PkiError};
use crate::registry::DeviceRegistry;
use crate::transport::hub::RelayHub;
use crate::transport::tcp::TcpRelay;
use crate::transport::tls::{self, TlsRelay, TlsSetupError};

#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Where the enrollment HTTP endpoint listens.
    pub enrollment_addr: SocketAddr,
    /// Where the unauthenticated plain-TCP CoT relay listens.
    pub plain_tcp_addr: SocketAddr,
    /// Where the mTLS CoT relay listens.
    pub mtls_addr: SocketAddr,
    /// Common Name for the freshly-generated CA.
    pub ca_common_name: String,
    /// Common Name (and DNS SAN) for the mTLS listener's own server
    /// certificate, issued by the CA at startup.
    pub server_common_name: String,
    /// Validity period for certificates this CA issues.
    pub cert_validity: Duration,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            enrollment_addr: "0.0.0.0:8446".parse().unwrap(),
            plain_tcp_addr: "0.0.0.0:8087".parse().unwrap(),
            mtls_addr: "0.0.0.0:8089".parse().unwrap(),
            ca_common_name: "EdgeTAK CA".to_string(),
            server_common_name: "edgetak-server".to_string(),
            cert_validity: Duration::days(365),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("PKI setup failed: {0}")]
    Pki(#[from] PkiError),
    #[error("TLS setup failed: {0}")]
    Tls(#[from] TlsSetupError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A fully-bound (but not yet running) EdgeTAK server: every listener has
/// already claimed its port, so real addresses (including resolved
/// ephemeral ports) are available before [`App::run`] is called — this is
/// what lets `tests/e2e.rs` bind on `:0` and learn the real ports to
/// connect test clients to.
///
/// **Known simplification**: the device registry is always in-memory here
/// (no config option to persist it to disk yet, unlike
/// [`DeviceRegistry::load_or_create`] which already supports that) — see
/// `docs/ARCHITECTURE.md`'s backup-strategy roadmap item.
pub struct App {
    pub ca_cert_pem: String,
    pub registry: Arc<DeviceRegistry>,
    enrollment: EnrollmentServer,
    tcp: TcpRelay,
    tls: TlsRelay,
}

impl App {
    pub async fn bind(config: AppConfig) -> Result<Self, AppError> {
        let ca = CertificateAuthority::generate(&config.ca_common_name)?;
        let ca_cert_pem = ca.ca_cert_pem();
        let registry = Arc::new(DeviceRegistry::in_memory());
        let hub = RelayHub::new();

        // The mTLS listener's own server identity, issued by the same CA a
        // client would enroll against.
        let (server_csr, server_key) =
            pki::build_csr_with_san(&config.server_common_name, vec![config.server_common_name.clone()])?;
        let signed_server_cert = ca.sign_csr(&server_csr, config.cert_validity)?;
        let server_cert_der = pki::cert_pem_to_der(&signed_server_cert.cert_pem)?;
        let ca_cert_der = pki::cert_pem_to_der(&ca_cert_pem)?;
        let tls_server_config: ServerConfig = tls::server_config(
            ca_cert_der,
            vec![server_cert_der],
            PrivateKeyDer::from(server_key),
        )?;

        let enrollment_state = Arc::new(EnrollmentState {
            ca,
            registry: Arc::clone(&registry),
            cert_validity: config.cert_validity,
        });

        let enrollment = EnrollmentServer::bind(config.enrollment_addr, enrollment_state).await?;
        let tcp = TcpRelay::bind(config.plain_tcp_addr, hub.clone()).await?;
        let tls = TlsRelay::bind(
            config.mtls_addr,
            Arc::new(tls_server_config),
            hub,
            Arc::clone(&registry),
        )
        .await?;

        Ok(Self {
            ca_cert_pem,
            registry,
            enrollment,
            tcp,
            tls,
        })
    }

    pub fn enrollment_addr(&self) -> std::io::Result<SocketAddr> {
        self.enrollment.local_addr()
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
            tcp,
            tls,
            ..
        } = self;
        tokio::try_join!(enrollment.run(), tcp.run(), tls.run())?;
        Ok(())
    }
}
