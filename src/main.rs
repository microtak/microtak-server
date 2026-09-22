//! EdgeTAK daemon entrypoint.
//!
//! No configuration file yet (see `docs/TEST-PLAN.md` §10 TC-CFG-*) —
//! listens on the hardcoded default ports from [`edgetak::app::AppConfig`],
//! generates a fresh in-memory CA, device registry, and mission store on
//! every startup (no persistence across restarts yet). Suitable for local
//! testing only; see `docs/ARCHITECTURE.md` for the open questions blocking
//! a real deployment (config surface, persistence, mesh sync).

use edgetak::app::{App, AppConfig};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let config = AppConfig::default();
    let app = App::bind(config)
        .await
        .unwrap_or_else(|error| panic!("failed to start EdgeTAK: {error}"));

    tracing::info!(
        enrollment = %app.enrollment_addr()?,
        marti_api = %app.marti_api_addr()?,
        plain_tcp = %app.plain_tcp_addr()?,
        mtls = %app.mtls_addr()?,
        "edgetakd starting"
    );
    tracing::warn!("CA, device registry, and mission store are in-memory only -- nothing persists across a restart yet");

    app.run().await
}
