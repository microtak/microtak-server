//! MicroTAK daemon entrypoint.
//!
//! Config file path: `$MICROTAK_CONFIG`, or `./microtak.toml` if unset — see
//! [`microtak_server::config::Config`]. A missing file falls back to
//! [`microtak_server::app::AppConfig::default`]'s ports; a present-but-invalid one
//! is a fatal startup error. CA, device registry, mission store, and
//! uploaded DataSync content persist to `data_dir` (default `./data`) and
//! reload across restarts. Periodic backup of `data_dir` (local mirror plus
//! an optional offsite command) is off by default -- see
//! [`microtak_server::app::BackupConfig`] and `src/backup.rs`. No mesh sync yet; see
//! `docs/ARCHITECTURE.md` for the remaining open questions.

use std::path::PathBuf;

use microtak_server::app::App;
use microtak_server::config::Config;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::var("MICROTAK_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./microtak.toml"));
    let config = Config::load_or_default(&config_path)
        .and_then(|c| c.to_app_config())
        .unwrap_or_else(|error| {
            panic!("failed to load config from {}: {error}", config_path.display())
        });

    let backup_enabled = config.backup.enabled;
    let backup_dir = config.backup.backup_dir.clone();

    let app = App::bind(config)
        .await
        .unwrap_or_else(|error| panic!("failed to start MicroTAK: {error}"));

    tracing::info!(
        enrollment = %app.enrollment_addr()?,
        marti_api = %app.marti_api_addr()?,
        plain_tcp = %app.plain_tcp_addr()?,
        mtls = %app.mtls_addr()?,
        backup_enabled,
        backup_dir = %backup_dir.display(),
        "microtakd starting"
    );

    app.run().await
}
