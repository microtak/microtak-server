//! TOML configuration file, converted into an [`AppConfig`].
//!
//! Implements `docs/TEST-PLAN.md` §10: TC-CFG-01 (cheap-to-check invalid
//! values rejected at startup, not deferred to first use) and TC-CFG-02
//! (adjacent — see [`Config::load_or_default`]'s doc comment on the
//! missing-vs-invalid-file distinction).
//!
//! Every field is optional in the file itself (`#[serde(default)]`, backed
//! by [`Config::default`] mirroring [`AppConfig::default`]) — a config file
//! only needs to name the fields it wants to override.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use time::Duration;
use thiserror::Error;

use crate::app::{AppConfig, BackupConfig, EnrollmentMode};
use crate::certsource::CertSource;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind_host: String,
    pub enrollment_port: u16,
    pub marti_api_port: u16,
    pub plain_tcp_port: u16,
    /// Off by default -- see `AppConfig::plain_tcp_enabled`.
    pub plain_tcp_enabled: bool,
    pub mtls_port: u16,
    pub ca_common_name: String,
    pub server_common_name: String,
    /// Extra IPs/DNS names for the server certificate -- see
    /// `AppConfig::server_names`.
    pub server_names: Vec<String>,
    /// See `AppConfig::server_names_from_interfaces` -- on by default.
    pub server_names_from_interfaces: bool,
    /// Reverse proxies whose `X-Forwarded-For` is trusted, as IPs or CIDR
    /// networks -- see `AppConfig::trusted_proxies`.
    pub trusted_proxies: Vec<String>,
    /// Optional PEM certificate chain + key for the enrollment listener
    /// (e.g. Let's Encrypt). Set both or neither; unset means a
    /// certificate from MicroTAK's own CA. See `src/certsource.rs`.
    pub enrollment_cert_file: Option<PathBuf>,
    pub enrollment_key_file: Option<PathBuf>,
    pub cert_validity_days: i64,
    pub data_dir: PathBuf,
    /// Whether periodic backup of `data_dir` runs at all -- disabled by
    /// default. See `src/backup.rs`.
    pub backup_enabled: bool,
    pub backup_interval_seconds: u64,
    pub backup_dir: PathBuf,
    /// An external command shipping the local backup elsewhere, e.g.
    /// `["rsync", "-a", "{src}/", "user@host:/backups/microtak/"]`. Empty
    /// means local-only backup, no offsite shipping.
    pub backup_offsite_command: Vec<String>,
    /// The Common Name of the admin device -- the only identity allowed to
    /// call the admin endpoints (`/Marti/api/admin/*`), and reserved at
    /// enrollment: it can only be enrolled with the one-time bootstrap
    /// token written to `data_dir/bootstrap-token` on first start. Defaults
    /// to `"admin"`. See `src/marti/admin.rs` and `src/bootstrap.rs`.
    pub admin_common_name: Option<String>,
    /// `"auto"` (the default) or `"open"` -- see [`EnrollmentMode`]'s own
    /// doc comment. `"auto"` requires a valid enrollment token (`?token=...`)
    /// or a password account on `/Marti/api/tls/signClient/v2` from the
    /// very first start; `"open"` lets any *new* identity enroll without
    /// one.
    pub enrollment_mode: EnrollmentMode,
}

impl Default for Config {
    fn default() -> Self {
        let defaults = AppConfig::default();
        Self {
            bind_host: "0.0.0.0".to_string(),
            enrollment_port: defaults.enrollment_addr.port(),
            marti_api_port: defaults.marti_api_addr.port(),
            plain_tcp_port: defaults.plain_tcp_addr.port(),
            plain_tcp_enabled: defaults.plain_tcp_enabled,
            mtls_port: defaults.mtls_addr.port(),
            ca_common_name: defaults.ca_common_name,
            server_common_name: defaults.server_common_name,
            server_names: defaults.server_names,
            server_names_from_interfaces: defaults.server_names_from_interfaces,
            trusted_proxies: Vec::new(),
            enrollment_cert_file: None,
            enrollment_key_file: None,
            cert_validity_days: defaults.cert_validity.whole_days(),
            data_dir: defaults.data_dir,
            backup_enabled: defaults.backup.enabled,
            backup_interval_seconds: defaults.backup.interval.as_secs().max(1),
            backup_dir: defaults.backup.backup_dir,
            backup_offsite_command: defaults.backup.offsite_command,
            admin_common_name: defaults.admin_common_name,
            enrollment_mode: defaults.enrollment_mode,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid bind_host '{0}': not a valid IP address")]
    InvalidBindHost(String),
    #[error("invalid cert_validity_days {0}: must be positive")]
    InvalidCertValidity(i64),
    #[error("enrollment_cert_file and enrollment_key_file must be set together")]
    IncompleteEnrollmentCert,
    #[error(transparent)]
    InvalidTrustedProxy(#[from] crate::clientip::InvalidTrustedProxy),
}

impl Config {
    /// Load from `path`. A *missing* file is not an error — it falls back
    /// to [`Config::default`] (TC-CFG-02's spirit applied the other way:
    /// absence is fine, presence-but-broken is not). A file that exists but
    /// fails to parse, or fails validation in [`Config::to_app_config`], is
    /// a hard startup error either way.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };
        toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// TC-CFG-01: `bind_host`/`cert_validity_days` are validated here,
    /// eagerly, rather than left to fail confusingly wherever they're first
    /// used (a `SocketAddr` bind failure, or a `time::Duration` that's
    /// silently negative). Out-of-range ports are already rejected by
    /// `u16`'s own deserialization in [`Config::load_or_default`].
    pub fn to_app_config(&self) -> Result<AppConfig, ConfigError> {
        let bind_ip: IpAddr = self
            .bind_host
            .parse()
            .map_err(|_| ConfigError::InvalidBindHost(self.bind_host.clone()))?;
        if self.cert_validity_days <= 0 {
            return Err(ConfigError::InvalidCertValidity(self.cert_validity_days));
        }
        let enrollment_cert = match (&self.enrollment_cert_file, &self.enrollment_key_file) {
            (None, None) => CertSource::Internal,
            (Some(cert_file), Some(key_file)) => CertSource::Files {
                cert_file: cert_file.clone(),
                key_file: key_file.clone(),
            },
            _ => return Err(ConfigError::IncompleteEnrollmentCert),
        };

        Ok(AppConfig {
            enrollment_addr: SocketAddr::new(bind_ip, self.enrollment_port),
            marti_api_addr: SocketAddr::new(bind_ip, self.marti_api_port),
            plain_tcp_addr: SocketAddr::new(bind_ip, self.plain_tcp_port),
            plain_tcp_enabled: self.plain_tcp_enabled,
            mtls_addr: SocketAddr::new(bind_ip, self.mtls_port),
            ca_common_name: self.ca_common_name.clone(),
            server_common_name: self.server_common_name.clone(),
            server_names: self.server_names.clone(),
            server_names_from_interfaces: self.server_names_from_interfaces,
            trusted_proxies: crate::clientip::TrustedProxies::parse(&self.trusted_proxies)?,
            enrollment_cert,
            cert_validity: Duration::days(self.cert_validity_days),
            data_dir: self.data_dir.clone(),
            backup: BackupConfig {
                enabled: self.backup_enabled,
                interval: std::time::Duration::from_secs(self.backup_interval_seconds.max(1)),
                backup_dir: self.backup_dir.clone(),
                offsite_command: self.backup_offsite_command.clone(),
            },
            admin_common_name: self.admin_common_name.clone(),
            enrollment_mode: self.enrollment_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_falls_back_to_defaults() {
        let path = std::env::temp_dir().join(format!(
            "microtak-config-test-missing-{}.toml",
            std::process::id()
        ));
        let config = Config::load_or_default(&path).unwrap();
        assert_eq!(config.bind_host, "0.0.0.0");
        assert_eq!(config.enrollment_port, 8446);
    }

    #[test]
    fn partial_toml_overrides_only_named_fields() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-config-test-partial-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("microtak.toml");
        std::fs::write(&path, "data_dir = \"/var/lib/microtak\"\nmtls_port = 9999\n").unwrap();

        let config = Config::load_or_default(&path).unwrap();
        assert_eq!(config.data_dir, PathBuf::from("/var/lib/microtak"));
        assert_eq!(config.mtls_port, 9999);
        // Untouched fields keep their defaults.
        assert_eq!(config.bind_host, "0.0.0.0");
        assert_eq!(config.enrollment_port, 8446);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invalid_toml_syntax_is_a_hard_error() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-config-test-badsyntax-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("microtak.toml");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        let result = Config::load_or_default(&path);
        assert!(matches!(result, Err(ConfigError::Parse { .. })));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// TC-CFG-01.
    #[test]
    fn out_of_range_port_is_rejected_at_parse_time() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-config-test-badport-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("microtak.toml");
        std::fs::write(&path, "mtls_port = 99999\n").unwrap(); // > u16::MAX

        let result = Config::load_or_default(&path);
        assert!(matches!(result, Err(ConfigError::Parse { .. })));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// TC-CFG-01.
    #[test]
    fn invalid_bind_host_is_rejected_eagerly() {
        let config = Config {
            bind_host: "not-an-ip".to_string(),
            ..Config::default()
        };
        assert!(matches!(
            config.to_app_config(),
            Err(ConfigError::InvalidBindHost(_))
        ));
    }

    /// TC-CFG-01.
    #[test]
    fn non_positive_cert_validity_is_rejected_eagerly() {
        let config = Config {
            cert_validity_days: 0,
            ..Config::default()
        };
        assert!(matches!(
            config.to_app_config(),
            Err(ConfigError::InvalidCertValidity(0))
        ));
    }

    #[test]
    fn valid_config_converts_cleanly() {
        let config = Config::default();
        let app_config = config.to_app_config().unwrap();
        assert_eq!(app_config.enrollment_addr.port(), 8446);
        assert_eq!(app_config.cert_validity, Duration::days(365));
        assert!(!app_config.backup.enabled, "backup is off by default");
    }

    #[test]
    fn backup_settings_round_trip_from_toml() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-config-test-backup-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("microtak.toml");
        std::fs::write(
            &path,
            r#"
            backup_enabled = true
            backup_interval_seconds = 900
            backup_dir = "/var/backups/microtak"
            backup_offsite_command = ["rsync", "-a", "{src}/", "user@host:/backups/"]
            "#,
        )
        .unwrap();

        let config = Config::load_or_default(&path).unwrap();
        let app_config = config.to_app_config().unwrap();
        assert!(app_config.backup.enabled);
        assert_eq!(app_config.backup.interval, std::time::Duration::from_secs(900));
        assert_eq!(
            app_config.backup.backup_dir,
            PathBuf::from("/var/backups/microtak")
        );
        assert_eq!(
            app_config.backup.offsite_command,
            vec!["rsync", "-a", "{src}/", "user@host:/backups/"]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enrollment_gating_settings_round_trip_from_toml() {
        let dir = std::env::temp_dir().join(format!(
            "microtak-config-test-enroll-gate-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("microtak.toml");
        std::fs::write(
            &path,
            r#"
            admin_common_name = "jz-admin"
            enrollment_mode = "open"
            "#,
        )
        .unwrap();

        let config = Config::load_or_default(&path).unwrap();
        let app_config = config.to_app_config().unwrap();
        assert_eq!(app_config.admin_common_name.as_deref(), Some("jz-admin"));
        assert_eq!(app_config.enrollment_mode, EnrollmentMode::Open);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Enrollment cert files are all-or-nothing, and parse into
    /// `CertSource::Files`; `server_names` passes through.
    #[test]
    fn enrollment_cert_files_and_server_names_parse() {
        let both: Config = toml::from_str(
            "server_names = [\"192.168.1.10\", \"tak.example.com\"]\nenrollment_cert_file = \"/c.pem\"\nenrollment_key_file = \"/k.pem\"\n",
        )
        .unwrap();
        let app_config = both.to_app_config().unwrap();
        assert_eq!(app_config.server_names, vec!["192.168.1.10", "tak.example.com"]);
        assert_eq!(
            app_config.enrollment_cert,
            CertSource::Files {
                cert_file: PathBuf::from("/c.pem"),
                key_file: PathBuf::from("/k.pem"),
            }
        );

        let only_cert: Config = toml::from_str("enrollment_cert_file = \"/c.pem\"\n").unwrap();
        assert!(matches!(
            only_cert.to_app_config(),
            Err(ConfigError::IncompleteEnrollmentCert)
        ));

        assert_eq!(
            Config::default().to_app_config().unwrap().enrollment_cert,
            CertSource::Internal
        );
    }

    /// Secure by default: with no config at all, mode is `Auto` (locked
    /// from the first start), an admin CN is reserved for the bootstrap
    /// token, and the unauthenticated plain-TCP relay is off.
    #[test]
    fn enrollment_mode_defaults_to_auto_not_open() {
        let app_config = Config::default().to_app_config().unwrap();
        assert_eq!(app_config.admin_common_name.as_deref(), Some("admin"));
        assert_eq!(app_config.enrollment_mode, EnrollmentMode::Auto);
        assert!(!app_config.plain_tcp_enabled, "plain TCP must be opt-in");
    }
}
