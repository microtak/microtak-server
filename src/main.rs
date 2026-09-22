//! EdgeTAK daemon entrypoint.
//!
//! Config file path: `$EDGETAK_CONFIG`, or `./edgetak.toml` if unset — see
//! [`edgetak::config::Config`]. A missing file falls back to
//! [`edgetak::app::AppConfig::default`]'s ports; a present-but-invalid one
//! is a fatal startup error. CA, device registry, mission store, and
//! uploaded DataSync content persist to `data_dir` (default `./data`) and
//! reload across restarts. Periodic backup of `data_dir` (local mirror plus
//! an optional offsite command) is off by default -- see
//! [`edgetak::app::BackupConfig`] and `src/backup.rs`. No mesh sync yet; see
//! `docs/ARCHITECTURE.md` for the remaining open questions.

use std::path::PathBuf;

use edgetak::app::App;
use edgetak::config::Config;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::var("EDGETAK_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./edgetak.toml"));
    let config = Config::load_or_default(&config_path)
        .and_then(|c| c.to_app_config())
        .unwrap_or_else(|error| {
            panic!("failed to load config from {}: {error}", config_path.display())
        });

    let backup_enabled = config.backup.enabled;
    let backup_dir = config.backup.backup_dir.clone();

    let app = App::bind(config)
        .await
        .unwrap_or_else(|error| panic!("failed to start EdgeTAK: {error}"));

    tracing::info!(
        enrollment = %app.enrollment_addr()?,
        marti_api = %app.marti_api_addr()?,
        plain_tcp = %app.plain_tcp_addr()?,
        mtls = %app.mtls_addr()?,
        backup_enabled,
        backup_dir = %backup_dir.display(),
        "edgetakd starting"
    );

    app.run().await
}
