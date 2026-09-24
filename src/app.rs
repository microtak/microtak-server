//! Assembles every MicroTAK component — CA, device registry, mission store,
//! shared relay hub, enrollment HTTP endpoint, Marti missions HTTP
//! endpoint, plain-TCP relay, and mTLS relay — into one runnable server.
//! This is both `microtakd`'s actual implementation (`src/main.rs`) and what
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

use crate::backup::{BackupRunner, OffsiteTarget};
use crate::content_store::ContentStore;
use crate::enrollment_tokens::{EnrollmentTokenError, EnrollmentTokenStore};
use crate::marti::admin::AdminState;
use crate::marti::enrollment::EnrollmentState;
use crate::marti::{
    admin, client_endpoints, contacts, content as content_api, discovery, enrollment, groups,
    missions as missions_api, oauth, MtlsHttpServer, PlainHttpServer,
};
use crate::missions::{MissionError, MissionStore};
use crate::pki::{self, CertificateAuthority, PkiError};
use crate::registry::{DeviceRegistry, RegistryError};
use crate::transport::connections::ConnectedClients;
use crate::transport::hub::RelayHub;
use crate::transport::tcp::TcpRelay;
use crate::transport::tls::{self, TlsRelay, TlsSetupError};
use crate::users::UserStore;

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
    /// Directory holding persistent state: `ca-cert.pem`/`ca-key.pem`, plus
    /// the append-only event logs `devices.log`/`missions.log` (see
    /// `src/eventlog.rs`). Created if it doesn't exist. Reused across
    /// restarts -- an existing CA here is loaded rather than regenerated,
    /// which matters because regenerating the CA invalidates every
    /// previously-issued client certificate.
    pub data_dir: PathBuf,
    /// Periodic backup of `data_dir` -- disabled by default. See
    /// `src/backup.rs` for the local-mirror + optional-offsite-command
    /// design.
    pub backup: BackupConfig,
    /// See `src/marti/admin.rs` -- `None` means the admin API
    /// (enrollment-token minting) is unreachable by anyone.
    pub admin_common_name: Option<String>,
    /// See `src/enrollment_tokens.rs` and [`EnrollmentMode`]'s own doc
    /// comment -- `Auto` by default: secure by default without requiring
    /// the operator to separately remember to lock enrollment down.
    pub enrollment_mode: EnrollmentMode,
}

/// Whether `/Marti/api/tls/signClient/v2` requires a valid enrollment
/// token. **Secure by default, without an insecure default**: `Auto`
/// (the default) requires a token *only once an admin device actually
/// exists* -- checked live against the device registry on every
/// enrollment attempt, not a static flag decided once at startup. A fresh
/// deployment with no `admin_common_name` configured yet (or one
/// configured but not yet enrolled) stays open, so bootstrap needs no
/// separate "temporarily open it, then lock it down and restart" dance --
/// enrolling the admin device is itself what flips enrollment locked,
/// live, no restart required. `Open` is an explicit, permanent override
/// for a deployment that wants enrollment open regardless (e.g. one
/// gating access at the network/firewall level instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentMode {
    #[default]
    Auto,
    Open,
}

/// See `src/backup.rs`'s doc comment for the design this configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupConfig {
    pub enabled: bool,
    /// A plain [`std::time::Duration`], not [`time::Duration`] like
    /// [`AppConfig::cert_validity`] -- this is what
    /// [`crate::backup::BackupRunner::run_periodic`] actually takes, and
    /// keeping it in that unit end-to-end avoids a lossy
    /// seconds-truncating conversion at the one call site that used to
    /// silently floor any sub-second interval up to a full second.
    pub interval: std::time::Duration,
    /// Where the local mirror is written. Relative paths are resolved
    /// against the current working directory, same as `data_dir`.
    pub backup_dir: PathBuf,
    /// An external command shipping `backup_dir` elsewhere, e.g.
    /// `["rsync", "-a", "{src}/", "user@host:/backups/microtak/"]`. Empty
    /// means offsite shipping is disabled -- local-only backup.
    pub offsite_command: Vec<String>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: std::time::Duration::from_secs(3600),
            backup_dir: PathBuf::from("./backup"),
            offsite_command: Vec::new(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            enrollment_addr: "0.0.0.0:8446".parse().unwrap(),
            marti_api_addr: "0.0.0.0:8443".parse().unwrap(),
            plain_tcp_addr: "0.0.0.0:8087".parse().unwrap(),
            mtls_addr: "0.0.0.0:8089".parse().unwrap(),
            ca_common_name: "MicroTAK CA".to_string(),
            server_common_name: "microtak-server".to_string(),
            cert_validity: Duration::days(365),
            backup: BackupConfig::default(),
            data_dir: PathBuf::from("./data"),
            admin_common_name: None,
            enrollment_mode: EnrollmentMode::default(),
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
    #[error("enrollment token store setup failed: {0}")]
    EnrollmentTokens(#[from] EnrollmentTokenError),
    #[error("user store setup failed: {0}")]
    Users(#[from] crate::users::UserError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A fully-bound (but not yet running) MicroTAK server: every listener has
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
    pub content_store: Arc<ContentStore>,
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
            config.data_dir.join("devices.log"),
        )?);
        let missions = Arc::new(MissionStore::load_or_create(
            config.data_dir.join("missions.log"),
        )?);
        let content_store = Arc::new(ContentStore::open(config.data_dir.join("content"))?);
        let enrollment_tokens = Arc::new(EnrollmentTokenStore::load_or_create(
            config.data_dir.join("enrollment_tokens.log"),
        )?);
        let users = Arc::new(UserStore::load_or_create(config.data_dir.join("users.log"))?);
        let hub = RelayHub::new();
        let clients = ConnectedClients::new();

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
            tokens: Arc::clone(&enrollment_tokens),
            enrollment_mode: config.enrollment_mode,
            admin_common_name: config.admin_common_name.clone(),
            users: Arc::clone(&users),
        });

        let plain_router = enrollment::router(enrollment_state).merge(oauth::router(Arc::clone(&users)));
        let enrollment = PlainHttpServer::bind(config.enrollment_addr, plain_router).await?;
        let admin_state = AdminState {
            tokens: enrollment_tokens,
            users,
            registry: Arc::clone(&registry),
            admin_common_name: config.admin_common_name.clone(),
        };
        let marti_router = missions_api::router(Arc::clone(&missions))
            .merge(client_endpoints::router(clients.clone()))
            .merge(content_api::router(Arc::clone(&content_store)))
            .merge(admin::router(admin_state))
            .merge(discovery::router())
            .merge(contacts::router(clients.clone()))
            .merge(groups::router());
        let marti_api =
            MtlsHttpServer::bind(config.marti_api_addr, Arc::clone(&tls_server_config), marti_router)
                .await?;
        let tcp = TcpRelay::bind(config.plain_tcp_addr, hub.clone(), clients.clone()).await?;
        let tls = TlsRelay::bind(
            config.mtls_addr,
            tls_server_config,
            hub,
            Arc::clone(&registry),
            clients,
        )
        .await?;

        if config.backup.enabled {
            let offsite = OffsiteTarget::new(config.backup.offsite_command.clone());
            let runner = BackupRunner::new(config.data_dir.clone(), config.backup.backup_dir.clone(), offsite);
            tokio::spawn(runner.run_periodic(config.backup.interval));
        }

        Ok(Self {
            ca_cert_pem,
            registry,
            missions,
            content_store,
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
        std::env::temp_dir().join(format!("microtak-app-{label}-{}-{n}", std::process::id()))
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
        let content_hash = first.content_store.put(b"persisted content", None).unwrap();
        drop(first); // never `.run()`, so nothing is actually listening to tear down

        let second = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert_eq!(
            second.ca_cert_pem, ca_cert_pem,
            "CA must survive a restart -- regenerating it would invalidate every issued cert"
        );
        assert!(second.registry.find("device-a").is_some());
        assert!(second.missions.get("m").is_some());
        assert_eq!(
            second.content_store.get(&content_hash).unwrap().as_deref(),
            Some(&b"persisted content"[..])
        );

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
