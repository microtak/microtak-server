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

use rustls::ServerConfig;
use time::Duration;
use tracing::{info, warn};

use crate::backup::{BackupRunner, OffsiteTarget};
use crate::bootstrap::{BOOTSTRAP_TOKEN_FILE, BootstrapToken};
use crate::certsource::{self, CertLoadError, CertSource, SwappableCert};
use crate::clientip::TrustedProxies;
use crate::content_store::ContentStore;
use crate::enrollment_tokens::{EnrollmentTokenError, EnrollmentTokenStore};
use crate::groups::GroupStore;
use crate::marti::admin::AdminState;
use crate::marti::enrollment::EnrollmentState;
use crate::marti::groups::GroupsState;
use crate::marti::{
    MtlsHttpServer, TlsHttpServer, admin, client_endpoints, contacts, content as content_api,
    discovery, enrollment, groups, missions as missions_api, oauth,
};
use crate::metrics;
use crate::missions::{MissionError, MissionStore};
use crate::pki::{self, CertificateAuthority, PkiError};
use crate::ratelimit::AuthLimiter;
use crate::registry::{DeviceRegistry, RegistryError};
use crate::servernames::{self, ServerCertError};
use crate::sync::{ResourceStore, SyncError};
use crate::transport::admission::{Admission, AdmissionLimits};
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
    /// Where the unauthenticated plain-TCP CoT relay listens, if enabled.
    pub plain_tcp_addr: SocketAddr,
    /// Whether to run the plain-TCP CoT relay at all. **Off by default**:
    /// it is cleartext and unauthenticated -- anyone who can reach it can
    /// read every position and inject arbitrary CoT. Enable it only for a
    /// trusted local bridge (e.g. an APRS or mesh gateway on the same host
    /// or an isolated network).
    pub plain_tcp_enabled: bool,
    /// Where the mTLS CoT relay listens.
    pub mtls_addr: SocketAddr,
    /// The official `validateClientUid` check: a device's SA must carry
    /// the `clientUid` its certificate was enrolled for, or the connection
    /// ends. **On by default** (officially off).
    pub validate_client_uid: bool,
    /// Only the admin may create, change or delete data feeds (a streaming
    /// feed opens a port). **On by default**; officially everyone may.
    pub datafeeds_admin_only: bool,
    /// Common Name for a freshly-generated CA (ignored if a CA already
    /// exists in `data_dir`).
    pub ca_common_name: String,
    /// Common Name (and DNS SAN) for the mTLS listener's own server
    /// certificate, freshly issued by the CA on every startup (the server's
    /// own leaf cert doesn't need continuity across restarts the way the CA
    /// itself does -- clients trust the CA and the SAN hostname, not a
    /// pinned exact server certificate).
    pub server_common_name: String,
    /// Extra names (IP addresses or DNS names) clients reach this server
    /// by, added as SANs to the server certificate alongside
    /// `server_common_name` -- e.g. the LAN IP devices enroll against.
    /// Clients that verify the enrollment endpoint's hostname (rather than
    /// trusting it on first contact) need their address listed here.
    pub server_names: Vec<String>,
    /// Also name every non-loopback interface address in the server
    /// certificate, re-checked every minute and re-issued live when the
    /// set changes (LAN, Starlink, Wi-Fi links coming and going). On by
    /// default. See `src/servernames.rs`.
    pub server_names_from_interfaces: bool,
    /// Reverse proxies (Traefik, Pangolin) in front of the enrollment
    /// listener, whose `X-Forwarded-For` is trusted for rate limiting --
    /// see `src/clientip.rs`. Empty (the default): the header is ignored.
    pub trusted_proxies: TrustedProxies,
    /// TCP proxies / load balancers whose PROXY protocol header is believed
    /// on every listener -- see [`crate::transport::proxy_protocol`].
    pub proxy_protocol_from: TrustedProxies,
    /// Where the enrollment listener's TLS certificate comes from -- see
    /// [`CertSource`]. The mTLS listeners always use the internal one.
    pub enrollment_cert: CertSource,
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
    /// The Common Name of the admin device -- the only identity allowed to
    /// use the admin API (`src/marti/admin.rs`), and reserved at
    /// enrollment: it can only be enrolled with the one-time bootstrap
    /// token (`src/bootstrap.rs`). Defaults to `"admin"`. `None` makes the
    /// admin API unreachable by anyone.
    pub admin_common_name: Option<String>,
    /// See `src/enrollment_tokens.rs` and [`EnrollmentMode`]'s own doc
    /// comment -- `Auto` by default: secure by default without requiring
    /// the operator to separately remember to lock enrollment down.
    pub enrollment_mode: EnrollmentMode,
    /// Connection limits and TLS/HTTP timeouts, shared by all listeners --
    /// see [`crate::transport::admission`].
    pub admission: AdmissionLimits,
    /// Largest DataSync upload accepted, in bytes (uploads are streamed to
    /// disk, never buffered whole).
    pub max_upload_bytes: u64,
    /// Where to serve Prometheus metrics (plain HTTP, unauthenticated --
    /// keep it on a private network). `None`: no metrics listener. See
    /// [`crate::metrics`].
    pub metrics_addr: Option<SocketAddr>,
}

/// Whether `/Marti/api/tls/signClient/v2` requires a valid enrollment
/// token from a client that presents no password credential.
///
/// - `Auto` (the default): **locked from the very first start**. A new
///   device needs an invite token minted by the admin (or a password
///   account). The admin device itself enrolls with the one-time bootstrap
///   token the server writes to `data_dir` on first start (see
///   `src/bootstrap.rs`) -- there is no open window in which whoever
///   arrives first can claim the admin identity. (Before 2026-09-28, `Auto`
///   stayed open until the admin enrolled; that window is closed.)
/// - `Open`: an explicit override for deployments gating access some other
///   way (e.g. network perimeter). Open for *new* identities only: an
///   already-enrolled identity can't be re-enrolled without its own
///   password credential, and the admin identity still needs the bootstrap
///   token.
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
            plain_tcp_enabled: false,
            mtls_addr: "0.0.0.0:8089".parse().unwrap(),
            validate_client_uid: true,
            datafeeds_admin_only: true,
            ca_common_name: "MicroTAK CA".to_string(),
            server_common_name: "microtak-server".to_string(),
            server_names: Vec::new(),
            server_names_from_interfaces: true,
            trusted_proxies: TrustedProxies::default(),
            proxy_protocol_from: TrustedProxies::default(),
            enrollment_cert: CertSource::Internal,
            cert_validity: Duration::days(365),
            backup: BackupConfig::default(),
            data_dir: PathBuf::from("./data"),
            admin_common_name: Some("admin".to_string()),
            enrollment_mode: EnrollmentMode::default(),
            admission: AdmissionLimits::default(),
            max_upload_bytes: content_api::DEFAULT_MAX_UPLOAD_BYTES,
            metrics_addr: None,
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
    #[error("server certificate: {0}")]
    ServerCert(#[from] ServerCertError),
    #[error("enrollment TLS certificate: {0}")]
    EnrollmentCert(#[from] CertLoadError),
    #[error("group store setup failed: {0}")]
    Groups(#[from] crate::groups::GroupError),
    #[error("OAuth signing key: {0}")]
    OAuthKey(#[from] oauth::JwtSignerError),
    #[error("resource store error: {0}")]
    Resources(#[from] SyncError),
    #[error("data feed store setup failed: {0}")]
    DataFeeds(#[from] crate::datafeeds::DataFeedError),
    #[error("device profile store setup failed: {0}")]
    Profiles(#[from] crate::profiles::ProfileError),
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
    pub groups: Arc<GroupStore>,
    enrollment: TlsHttpServer,
    marti_api: MtlsHttpServer,
    tcp: Option<TcpRelay>,
    tls: TlsRelay,
    bootstrap: Arc<BootstrapToken>,
    /// Set in [`CertSource::Files`] mode: the live enrollment certificate
    /// and the files to watch for replacements.
    enrollment_cert_watch: Option<(Arc<SwappableCert>, PathBuf, PathBuf)>,
    /// Set when `server_names_from_interfaces` is on.
    interface_watch: Option<InterfaceWatch>,
    /// Set when `metrics_addr` is.
    metrics: Option<(tokio::net::TcpListener, metrics::Sources)>,
    pub datafeeds: Arc<crate::datafeeds::DataFeedStore>,
    feed_inputs: crate::transport::feeds::FeedInputs,
}

/// What the background task re-issuing the server cert on address changes
/// needs -- see [`servernames::watch_interfaces`].
struct InterfaceWatch {
    ca: CertificateAuthority,
    target: Arc<SwappableCert>,
    common_name: String,
    configured: Vec<String>,
    validity: Duration,
    current: Vec<String>,
}

impl App {
    pub async fn bind(config: AppConfig) -> Result<Self, AppError> {
        std::fs::create_dir_all(&config.data_dir)?;

        // The official envelope's `nodeId`, stable per installation.
        crate::marti::envelope::load_or_create_server_id(&config.data_dir)?;
        let ca = load_or_generate_ca(&config.data_dir, &config.ca_common_name)?;
        let ca_cert_pem = ca.ca_cert_pem();
        let registry = Arc::new(DeviceRegistry::load_or_create(
            config.data_dir.join("devices.log"),
        )?);
        let groups = Arc::new(GroupStore::load_or_create(
            config.data_dir.join("groups.log"),
        )?);
        // Missions in the official model; MicroTAK ≤ 0.8's `missions.log`
        // (a different model) is left alone, not migrated.
        let missions = Arc::new(MissionStore::load_or_create(
            config.data_dir.join("official-missions.log"),
        )?);
        let latest_cot = Arc::new(crate::latest_cot::LatestCot::load(
            config.data_dir.join("latest-cot.json"),
        ));
        let mission_tokens = Arc::new(
            crate::marti::mission_token::MissionTokenSigner::load_or_create(&config.data_dir)?,
        );
        let content_store = Arc::new(ContentStore::open(config.data_dir.join("content"))?);
        let resources = Arc::new(ResourceStore::load_or_create(
            config.data_dir.join("resources.log"),
        )?);
        let enrollment_tokens = Arc::new(EnrollmentTokenStore::load_or_create(
            config.data_dir.join("enrollment_tokens.log"),
        )?);
        // The official `profiles/` folder: its subfolders are profile
        // directories.
        let profiles_dir = config.data_dir.join("profiles");
        std::fs::create_dir_all(&profiles_dir)?;
        let profiles_dir = std::fs::canonicalize(&profiles_dir)?;
        let profiles = Arc::new(crate::profiles::ProfileStore::load_or_create(
            config.data_dir.join("device-profiles.log"),
            config.data_dir.join("profile-content"),
        )?);
        let datafeeds = Arc::new(crate::datafeeds::DataFeedStore::load_or_create(
            config.data_dir.join("datafeeds.log"),
        )?);
        let users = Arc::new(UserStore::load_or_create(
            config.data_dir.join("users.log"),
        )?);
        let bootstrap = Arc::new(match &config.admin_common_name {
            Some(admin_cn) => {
                let token = BootstrapToken::load_or_create(
                    &config.data_dir.join(BOOTSTRAP_TOKEN_FILE),
                    registry.find(admin_cn).is_some(),
                )?;
                if let Some(path) = token.path() {
                    info!(
                        admin_common_name = %admin_cn,
                        path = %path.display(),
                        "admin device not enrolled yet -- enroll it with the one-time bootstrap token in this file"
                    );
                }
                token
            }
            None => BootstrapToken::none(),
        });
        let limiter = Arc::new(AuthLimiter::default());
        let hub = RelayHub::new();
        let clients = ConnectedClients::new();

        // The mTLS listener's own server identity, issued by the same CA a
        // client would enroll against.
        // The server's own identity, issued by the same CA clients enroll
        // against, naming every address it's reachable by (see
        // `src/servernames.rs`). One swappable cert shared by every listener
        // that uses the internal identity, so an address change is picked up
        // everywhere at once.
        let detected = if config.server_names_from_interfaces {
            servernames::interface_addresses()
        } else {
            Vec::new()
        };
        let server_names =
            servernames::collect(&config.server_common_name, &config.server_names, &detected);
        let (server_cert, _, _) = servernames::issue_server_cert(
            &ca,
            &config.server_common_name,
            &server_names,
            config.cert_validity,
        )?;
        info!(names = ?server_names, "server certificate issued");
        let internal_cert = Arc::new(SwappableCert::new(server_cert));
        let interface_watch = config.server_names_from_interfaces.then(|| InterfaceWatch {
            ca: CertificateAuthority::from_pem(&ca.ca_cert_pem(), &ca.ca_key_pem())
                .expect("the CA just loaded must reload from its own PEM"),
            target: Arc::clone(&internal_cert),
            common_name: config.server_common_name.clone(),
            configured: config.server_names.clone(),
            validity: config.cert_validity,
            current: server_names,
        });

        let ca_cert_der = pki::cert_pem_to_der(&ca_cert_pem)?;
        // Shared between the CoT mTLS relay and the Marti API's mTLS HTTP
        // listener -- same server identity, same CA-based client
        // verification policy.
        let tls_server_config: Arc<ServerConfig> = Arc::new(tls::server_config_with_resolver(
            ca_cert_der,
            Arc::clone(&internal_cert) as Arc<dyn rustls::server::ResolvesServerCert>,
        )?);

        // The enrollment listener: TLS only, no client cert. Internal mode
        // reuses the same server identity as the mTLS listeners.
        let (enrollment_cert, enrollment_cert_watch) = match &config.enrollment_cert {
            CertSource::Internal => (Arc::clone(&internal_cert), None),
            CertSource::Files {
                cert_file,
                key_file,
            } => {
                let cert = Arc::new(SwappableCert::new(certsource::load_files(
                    cert_file, key_file,
                )?));
                info!(cert_file = %cert_file.display(), "enrollment TLS certificate loaded from files");
                (
                    Arc::clone(&cert),
                    Some((cert, cert_file.clone(), key_file.clone())),
                )
            }
        };

        let enrollment_state = Arc::new(EnrollmentState {
            ca,
            registry: Arc::clone(&registry),
            cert_validity: config.cert_validity,
            tokens: Arc::clone(&enrollment_tokens),
            enrollment_mode: config.enrollment_mode,
            admin_common_name: config.admin_common_name.clone(),
            users: Arc::clone(&users),
            bootstrap: Arc::clone(&bootstrap),
            limiter: Arc::clone(&limiter),
            groups: Arc::clone(&groups),
        });

        let enrollment_profiles = crate::marti::profiles::EnrollmentProfilesState {
            store: Arc::clone(&profiles),
            groups: Arc::clone(&groups),
            users: Arc::clone(&users),
            tokens: Arc::clone(&enrollment_tokens),
            limiter: Arc::clone(&limiter),
            profiles_dir: profiles_dir.clone(),
            max_upload_bytes: config.max_upload_bytes,
        };
        let plain_router = enrollment::router(enrollment_state)
            .merge(crate::marti::profiles::enrollment_router(
                enrollment_profiles,
            ))
            .merge(oauth::router(
                Arc::clone(&users),
                limiter,
                Arc::new(oauth::JwtSigner::load_or_create(&config.data_dir)?),
            ))
            .layer(axum::Extension(Arc::new(config.trusted_proxies.clone())));
        // One instance for every listener, so the total cap is server-wide.
        let admission = Admission::new(config.admission)
            .with_proxy_protocol_from(config.proxy_protocol_from.clone());
        let enrollment = TlsHttpServer::bind(
            config.enrollment_addr,
            Arc::new(tls::server_auth_only_config(enrollment_cert)),
            plain_router,
        )
        .await?
        .with_admission(admission.clone());
        let metrics = match config.metrics_addr {
            Some(addr) => Some((
                metrics::bind(addr).await?,
                metrics::Sources {
                    registry: Arc::clone(&registry),
                    users: Arc::clone(&users),
                    missions: Arc::clone(&missions),
                    groups: Arc::clone(&groups),
                    tokens: Arc::clone(&enrollment_tokens),
                    clients: clients.clone(),
                    content: Arc::clone(&content_store),
                    admission: admission.clone(),
                    data_dir: config.data_dir.clone(),
                },
            )),
            None => None,
        };
        let admin_state = AdminState {
            tokens: enrollment_tokens,
            users,
            registry: Arc::clone(&registry),
            groups: Arc::clone(&groups),
            admin_common_name: config.admin_common_name.clone(),
        };
        Arc::clone(&latest_cot).spawn_feed(hub.subscribe());
        let mission_notifier = Arc::new(crate::marti::mission_notify::MissionNotifier::new(
            hub.sender(),
            Arc::clone(&missions),
            Arc::clone(&resources),
            Arc::clone(&latest_cot),
            Arc::clone(&groups),
        ));
        let marti_router = missions_api::router_with(missions_api::MissionsState {
            store: Arc::clone(&missions),
            groups: Arc::clone(&groups),
            admin_common_name: config.admin_common_name.clone(),
            tokens: mission_tokens,
            resources: Arc::clone(&resources),
            latest_cot: Arc::clone(&latest_cot),
            notifier: Arc::clone(&mission_notifier),
            clients: clients.clone(),
            content: Arc::clone(&content_store),
        })
        .merge(client_endpoints::router(clients.clone()))
        .merge(content_api::router(content_api::SyncState {
            content: Arc::clone(&content_store),
            resources: Arc::clone(&resources),
            groups: Arc::clone(&groups),
            admin_common_name: config.admin_common_name.clone(),
            max_upload_bytes: config.max_upload_bytes,
            missions: Arc::clone(&missions),
            latest_cot: Arc::clone(&latest_cot),
        }))
        .merge(admin::router(admin_state))
        .merge(crate::marti::datafeeds::router(
            crate::marti::datafeeds::DataFeedsState {
                store: Arc::clone(&datafeeds),
                groups: Arc::clone(&groups),
                admin_common_name: config.admin_common_name.clone(),
                admin_only: config.datafeeds_admin_only,
            },
        ))
        .merge(crate::marti::profiles::router(
            crate::marti::profiles::ProfilesState {
                store: profiles,
                groups: Arc::clone(&groups),
                notifier: Arc::clone(&mission_notifier),
                max_upload_bytes: config.max_upload_bytes,
                profiles_dir,
            },
        ))
        .merge(discovery::router())
        .merge(crate::marti::security::router(
            crate::marti::security::SecurityState {
                non_secure_ports: config
                    .plain_tcp_enabled
                    .then_some(config.plain_tcp_addr.port())
                    .into_iter()
                    .chain(config.metrics_addr.map(|a| a.port()))
                    .collect(),
            },
        ))
        .merge(contacts::router(contacts::ContactsState {
            clients: clients.clone(),
            latest_cot: Arc::clone(&latest_cot),
            groups: Arc::clone(&groups),
            admin_common_name: config.admin_common_name.clone(),
        }))
        .merge(crate::marti::subscriptions::router(
            contacts::ContactsState {
                clients: clients.clone(),
                latest_cot: Arc::clone(&latest_cot),
                groups: Arc::clone(&groups),
                admin_common_name: config.admin_common_name.clone(),
            },
        ))
        .merge(groups::router(GroupsState {
            groups: Arc::clone(&groups),
            admin_common_name: config.admin_common_name.clone(),
        }))
        // The official URL authorization table (security-context.xml).
        .layer(axum::middleware::from_fn({
            let admin = config.admin_common_name.clone();
            move |request, next| crate::marti::access::enforce(admin.clone(), request, next)
        }));
        let marti_api = MtlsHttpServer::bind(
            config.marti_api_addr,
            Arc::clone(&tls_server_config),
            marti_router,
        )
        .await?
        .with_admission(admission.clone())
        .with_registry(Arc::clone(&registry));
        let tcp = if config.plain_tcp_enabled {
            Some(
                TcpRelay::bind(config.plain_tcp_addr, hub.clone(), clients.clone())
                    .await?
                    .with_groups(Arc::clone(&groups))
                    .with_admission(admission.clone())
                    .with_latest_sa(),
            )
        } else {
            None
        };
        // Streaming data feeds' own listeners (`transport::feeds`).
        let feed_inputs = crate::transport::feeds::FeedInputs {
            bind_ip: config.mtls_addr.ip(),
            hub: hub.clone(),
            clients: clients.clone(),
            groups: Arc::clone(&groups),
            registry: Arc::clone(&registry),
            tls_config: Arc::clone(&tls_server_config),
            admission: admission.clone(),
        };
        let tls = TlsRelay::bind(
            config.mtls_addr,
            tls_server_config,
            hub,
            Arc::clone(&registry),
            clients,
        )
        .await?
        .with_groups(Arc::clone(&groups))
        .with_admission(admission)
        .with_missions(mission_notifier)
        // `<buffer><latestSA enable="true"/>`, the official default.
        .with_latest_sa()
        .with_validate_client_uid(config.validate_client_uid)
        // The official default input (`protocol="tls"`) negotiates TAK
        // Protocol.
        .with_tak_protocol(crate::transport::tls::TakProtocol {
            server_version: crate::marti::discovery::VERSION_STRING.to_string(),
            cot_url_base: Some(format!(
                "https://{}:{}",
                config.server_common_name,
                config.marti_api_addr.port()
            )),
        });

        if config.backup.enabled {
            let offsite = OffsiteTarget::new(config.backup.offsite_command.clone());
            let runner = BackupRunner::new(
                config.data_dir.clone(),
                config.backup.backup_dir.clone(),
                offsite,
            );
            tokio::spawn(runner.run_periodic(config.backup.interval));
        }

        Ok(Self {
            ca_cert_pem,
            registry,
            missions,
            content_store,
            groups,
            enrollment,
            marti_api,
            tcp,
            tls,
            bootstrap,
            enrollment_cert_watch,
            interface_watch,
            metrics,
            datafeeds,
            feed_inputs,
        })
    }

    pub fn enrollment_addr(&self) -> std::io::Result<SocketAddr> {
        self.enrollment.local_addr()
    }

    pub fn marti_api_addr(&self) -> std::io::Result<SocketAddr> {
        self.marti_api.local_addr()
    }

    /// Errors with [`std::io::ErrorKind::NotConnected`] if the plain-TCP
    /// relay is disabled (the default -- see [`AppConfig::plain_tcp_enabled`]).
    pub fn plain_tcp_addr(&self) -> std::io::Result<SocketAddr> {
        match &self.tcp {
            Some(tcp) => tcp.local_addr(),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "the plain-TCP relay is disabled",
            )),
        }
    }

    /// Where the admin's one-time bootstrap token is, while one is
    /// outstanding (admin configured but not yet enrolled).
    pub fn bootstrap_token_path(&self) -> Option<PathBuf> {
        self.bootstrap
            .is_outstanding()
            .then(|| self.bootstrap.path().map(PathBuf::from))
            .flatten()
    }

    pub fn mtls_addr(&self) -> std::io::Result<SocketAddr> {
        self.tls.local_addr()
    }

    /// The metrics listener's address, if one is configured.
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics
            .as_ref()
            .and_then(|(listener, _)| listener.local_addr().ok())
    }

    /// Run every listener concurrently until one of them hits a fatal
    /// error (a healthy server runs this forever).
    pub async fn run(self) -> std::io::Result<()> {
        let Self {
            enrollment,
            marti_api,
            tcp,
            tls,
            enrollment_cert_watch,
            interface_watch,
            metrics,
            datafeeds,
            feed_inputs,
            ..
        } = self;
        tokio::spawn(crate::transport::feeds::run(datafeeds, feed_inputs));
        if let Some((listener, sources)) = metrics {
            tokio::spawn(async move {
                if let Err(error) = metrics::serve(listener, sources).await {
                    tracing::warn!(%error, "metrics listener stopped");
                }
            });
        }
        if let Some(watch) = interface_watch {
            tokio::spawn(servernames::watch_interfaces(
                watch.ca,
                watch.target,
                watch.common_name,
                watch.configured,
                watch.validity,
                std::time::Duration::from_secs(60),
                watch.current,
            ));
        }
        if let Some((cert, cert_file, key_file)) = enrollment_cert_watch {
            tokio::spawn(certsource::watch_files(
                cert,
                cert_file,
                key_file,
                std::time::Duration::from_secs(60),
            ));
        }
        let tcp = async {
            match tcp {
                Some(tcp) => tcp.run().await,
                None => std::future::pending().await,
            }
        };
        tokio::try_join!(enrollment.run(), marti_api.run(), tcp, tls.run())?;
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
        #[cfg(unix)]
        if crate::bootstrap::tighten_to_owner_only(&key_path)? {
            warn!(path = %key_path.display(), "CA private key was readable by other users; restricted it to the owner");
        }
        return Ok(CertificateAuthority::from_pem(&cert_pem, &key_pem)?);
    }

    let ca = CertificateAuthority::generate(ca_common_name)?;
    std::fs::write(&cert_path, ca.ca_cert_pem())?;
    // The key signs every identity, the admin's included: owner-only.
    crate::bootstrap::write_private_file(&key_path, ca.ca_key_pem().as_bytes())?;
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
        let mission = first
            .missions
            .create(
                crate::missions::NewMission {
                    guid: crate::marti::envelope::random_uuid(),
                    name: "m".into(),
                    fields: Default::default(),
                    tool: "public".into(),
                    creator_uid: "user-1".into(),
                    groups: ["__ANON__".to_string()].into(),
                    password_hash: None,
                    default_role: None,
                    invite_only: false,
                },
                1_000,
            )
            .unwrap();
        let content_hash = first.content_store.put(b"persisted content", None).unwrap();
        drop(first); // never `.run()`, so nothing is actually listening to tear down

        let second = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert_eq!(
            second.ca_cert_pem, ca_cert_pem,
            "CA must survive a restart -- regenerating it would invalidate every issued cert"
        );
        assert!(second.registry.find("device-a").is_some());
        assert!(second.missions.by_guid(&mission.guid).is_some());
        assert_eq!(
            second.content_store.get(&content_hash).unwrap().as_deref(),
            Some(&b"persisted content"[..])
        );

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// TC-ENROLL-15, at the assembly level: a fresh server with an admin
    /// CN configured writes a bootstrap token file; once the admin has
    /// enrolled, a restart creates none and removes a stale one.
    #[tokio::test]
    async fn bootstrap_token_exists_until_the_admin_enrolls() {
        let data_dir = unique_temp_dir("bootstrap");
        let first = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        let path = first
            .bootstrap_token_path()
            .expect("admin not enrolled yet");
        assert_eq!(path, data_dir.join(BOOTSTRAP_TOKEN_FILE));
        let token = std::fs::read_to_string(&path).unwrap();
        first.registry.enroll("admin", "admin-cert-pem", 1).unwrap();
        drop(first);

        let second = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert!(second.bootstrap_token_path().is_none());
        assert!(!path.exists(), "the stale token file is removed");
        assert!(!token.is_empty());
        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// The plain-TCP relay is off unless explicitly enabled.
    #[tokio::test]
    async fn plain_tcp_relay_is_disabled_by_default() {
        assert!(!AppConfig::default().plain_tcp_enabled);
        let data_dir = unique_temp_dir("plain-tcp");
        let app = App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert_eq!(
            app.plain_tcp_addr().unwrap_err().kind(),
            std::io::ErrorKind::NotConnected
        );
        drop(app);

        let enabled = App::bind(AppConfig {
            plain_tcp_enabled: true,
            ..ephemeral_config(data_dir.clone())
        })
        .await
        .unwrap();
        assert!(enabled.plain_tcp_addr().is_ok());
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The CA key signs every identity, the admin's included -- readable by
    /// the server's own user only, like the bootstrap token.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_generated_ca_key_is_readable_by_the_owner_only() {
        let data_dir = unique_temp_dir("ca-key-mode");
        App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert_eq!(mode_of(&data_dir.join("ca-key.pem")), 0o600);
        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// Data dirs created before the key was written privately get fixed on
    /// the next start instead of staying world-readable.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_existing_world_readable_ca_key_is_tightened_on_start() {
        use std::os::unix::fs::PermissionsExt;
        let data_dir = unique_temp_dir("ca-key-tighten");
        App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        let key_path = data_dir.join("ca-key.pem");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        App::bind(ephemeral_config(data_dir.clone())).await.unwrap();
        assert_eq!(mode_of(&key_path), 0o600);
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
