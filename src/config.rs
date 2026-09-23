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

use crate::app::{AppConfig, BackupConfig};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind_host: String,
    pub enrollment_port: u16,
    pub marti_api_port: u16,
    pub plain_tcp_port: u16,
    pub mtls_port: u16,
    pub ca_common_name: String,
    pub server_common_name: String,
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
}

impl Default for Config {
    fn default() -> Self {
        let defaults = AppConfig::default();
        Self {
            bind_host: "0.0.0.0".to_string(),
            enrollment_port: defaults.enrollment_addr.port(),
            marti_api_port: defaults.marti_api_addr.port(),
            plain_tcp_port: defaults.plain_tcp_addr.port(),
            mtls_port: defaults.mtls_addr.port(),
            ca_common_name: defaults.ca_common_name,
            server_common_name: defaults.server_common_name,
            cert_validity_days: defaults.cert_validity.whole_days(),
            data_dir: defaults.data_dir,
            backup_enabled: defaults.backup.enabled,
            backup_interval_seconds: defaults.backup.interval.as_secs().max(1),
            backup_dir: defaults.backup.backup_dir,
            backup_offsite_command: defaults.backup.offsite_command,
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

        Ok(AppConfig {
            enrollment_addr: SocketAddr::new(bind_ip, self.enrollment_port),
            marti_api_addr: SocketAddr::new(bind_ip, self.marti_api_port),
            plain_tcp_addr: SocketAddr::new(bind_ip, self.plain_tcp_port),
            mtls_addr: SocketAddr::new(bind_ip, self.mtls_port),
            ca_common_name: self.ca_common_name.clone(),
            server_common_name: self.server_common_name.clone(),
            cert_validity: Duration::days(self.cert_validity_days),
            data_dir: self.data_dir.clone(),
            backup: BackupConfig {
                enabled: self.backup_enabled,
                interval: std::time::Duration::from_secs(self.backup_interval_seconds.max(1)),
                backup_dir: self.backup_dir.clone(),
                offsite_command: self.backup_offsite_command.clone(),
            },
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
}
