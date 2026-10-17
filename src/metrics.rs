//! Prometheus metrics (`GET /metrics`, text exposition format) on a
//! separate, plain-HTTP listener (`metrics_addr`, off by default) -- meant
//! for a scraper on a private network, never for the internet: it reveals
//! counts, not content, but has no authentication.
//!
//! Two kinds of numbers:
//! - **Counters** for things that happen (CoT events, enrollments, refused
//!   connections): process-wide atomics in [`COUNTERS`], incremented where
//!   it happens. They reset on restart, as Prometheus counters may.
//! - **Gauges** for what the server holds (devices, missions, files,
//!   connected clients, ...): read from the live stores at scrape time, so
//!   they can't drift.
//!
//! Hand-written exposition rather than a metrics crate: a few dozen lines,
//! no dependency, and the format is simple and stable.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;

use crate::content_store::ContentStore;
use crate::enrollment_tokens::EnrollmentTokenStore;
use crate::groups::GroupStore;
use crate::missions::MissionStore;
use crate::registry::DeviceRegistry;
use crate::transport::admission::Admission;
use crate::transport::connections::{ConnectedClients, Transport};
use crate::users::UserStore;

/// Process-wide event counters.
#[derive(Default)]
pub struct Counters {
    pub cot_events_tls: AtomicU64,
    pub cot_events_tcp: AtomicU64,
    /// Events dropped for impersonating another device (TC-TLS-04).
    pub cot_events_dropped: AtomicU64,
    pub enrollments: AtomicU64,
    /// Connections refused by the connection limits.
    pub connections_refused: AtomicU64,
}

pub static COUNTERS: Counters = Counters {
    cot_events_tls: AtomicU64::new(0),
    cot_events_tcp: AtomicU64::new(0),
    cot_events_dropped: AtomicU64::new(0),
    enrollments: AtomicU64::new(0),
    connections_refused: AtomicU64::new(0),
};

pub fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// Everything the gauges are read from.
#[derive(Clone)]
pub struct Sources {
    pub registry: Arc<DeviceRegistry>,
    pub users: Arc<UserStore>,
    pub missions: Arc<MissionStore>,
    pub groups: Arc<GroupStore>,
    pub tokens: Arc<EnrollmentTokenStore>,
    pub clients: ConnectedClients,
    pub content: Arc<ContentStore>,
    pub admission: Admission,
    pub data_dir: PathBuf,
}

pub fn router(sources: Sources) -> Router {
    Router::new().route("/metrics", get(metrics)).with_state(sources)
}

async fn metrics(State(sources): State<Sources>) -> impl IntoResponse {
    // Directory scans and /proc reads: keep them off the async workers.
    let body = tokio::task::spawn_blocking(move || render(&sources))
        .await
        .unwrap_or_default();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], body)
}

/// Serve [`router`] on `listener` forever.
pub async fn serve(listener: tokio::net::TcpListener, sources: Sources) -> std::io::Result<()> {
    axum::serve(listener, router(sources)).await
}

struct Exposition(String);

impl Exposition {
    fn metric(&mut self, name: &str, kind: &str, help: &str, samples: &[(&str, f64)]) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
        for (labels, value) in samples {
            let _ = writeln!(self.0, "{name}{labels} {value}");
        }
    }

    fn gauge(&mut self, name: &str, help: &str, value: f64) {
        self.metric(name, "gauge", help, &[("", value)]);
    }

    fn counter(&mut self, name: &str, help: &str, value: &AtomicU64) {
        self.metric(name, "counter", help, &[("", value.load(Ordering::Relaxed) as f64)]);
    }
}

pub fn render(sources: &Sources) -> String {
    let mut out = Exposition(String::new());
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    out.metric(
        "microtak_build_info",
        "gauge",
        "Server version.",
        &[(&format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")), 1.0)],
    );

    let devices = sources.registry.all();
    out.gauge("microtak_devices", "Enrolled device identities.", devices.len() as f64);
    out.gauge(
        "microtak_devices_blocked",
        "Blocked identities.",
        devices.iter().filter(|d| d.revoked).count() as f64,
    );
    out.gauge(
        "microtak_certificates_revoked",
        "Individually revoked certificates.",
        sources.registry.revoked_cert_count() as f64,
    );

    let users = sources.users.list();
    out.gauge(
        "microtak_password_accounts",
        "Password accounts that can log in.",
        users.iter().filter(|u| !u.revoked).count() as f64,
    );
    out.gauge(
        "microtak_enrollment_tokens_active",
        "Invite tokens not used, revoked or expired.",
        sources
            .tokens
            .list()
            .iter()
            .filter(|t| !t.used && !t.revoked && t.expires_at_unix.is_none_or(|at| at > now))
            .count() as f64,
    );
    out.gauge("microtak_missions", "Missions (Data Sync).", sources.missions.list().len() as f64);
    out.gauge("microtak_groups", "Groups (channels).", sources.groups.list().len() as f64);

    let clients = sources.clients.list();
    let count = |transport: Transport| clients.iter().filter(|c| c.transport == transport).count() as f64;
    out.metric(
        "microtak_connected_clients",
        "gauge",
        "Clients connected to the CoT relay.",
        &[
            ("{transport=\"tls\"}", count(Transport::Tls)),
            ("{transport=\"tcp\"}", count(Transport::Tcp)),
        ],
    );
    out.gauge(
        "microtak_open_connections",
        "Open connections on all listeners (what the connection limits count).",
        sources.admission.open_connections() as f64,
    );

    out.metric(
        "microtak_cot_events_received_total",
        "counter",
        "CoT events received from clients and relayed.",
        &[
            ("{transport=\"tls\"}", COUNTERS.cot_events_tls.load(Ordering::Relaxed) as f64),
            ("{transport=\"tcp\"}", COUNTERS.cot_events_tcp.load(Ordering::Relaxed) as f64),
        ],
    );
    out.counter(
        "microtak_cot_events_dropped_total",
        "CoT events dropped for impersonating another device.",
        &COUNTERS.cot_events_dropped,
    );
    out.counter("microtak_enrollments_total", "Certificates issued.", &COUNTERS.enrollments);
    out.counter(
        "microtak_connections_refused_total",
        "Connections refused by the connection limits.",
        &COUNTERS.connections_refused,
    );

    let content = sources.content.stats();
    out.metric(
        "microtak_content_files",
        "gauge",
        "Files stored via Data Sync (pictures recognized by their content).",
        &[("{kind=\"image\"}", content.images as f64), ("{kind=\"other\"}", content.others as f64)],
    );
    out.gauge("microtak_content_bytes", "Bytes stored via Data Sync.", content.bytes as f64);
    out.gauge(
        "microtak_data_dir_bytes",
        "Bytes in the data directory (state, content, logs).",
        dir_size(&sources.data_dir) as f64,
    );

    if let Some(process) = process_stats() {
        out.counter_value("process_cpu_seconds_total", "CPU time used by the server.", process.cpu_seconds);
        out.gauge("process_resident_memory_bytes", "Resident memory of the server.", process.resident_bytes);
    }
    out.0
}

impl Exposition {
    fn counter_value(&mut self, name: &str, help: &str, value: f64) {
        self.metric(name, "counter", help, &[("", value)]);
    }
}

fn dir_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else { return 0 };
    entries
        .flatten()
        .map(|entry| match entry.metadata() {
            Ok(m) if m.is_dir() => dir_size(&entry.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

struct ProcessStats {
    cpu_seconds: f64,
    resident_bytes: f64,
}

/// From `/proc/self` (Linux; `None` elsewhere).
fn process_stats() -> Option<ProcessStats> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the parenthesized command name; utime and stime are the
    // 14th and 15th fields overall, in clock ticks (USER_HZ, 100 on Linux).
    let after_comm = stat.rsplit_once(") ")?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let ticks: f64 = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss_kb: f64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(ProcessStats {
        cpu_seconds: ticks / 100.0,
        resident_bytes: rss_kb * 1024.0,
    })
}

/// Bind the metrics listener (see `AppConfig::metrics_addr`).
pub async fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_has_help_type_and_labelled_samples() {
        let mut out = Exposition(String::new());
        out.metric("x_total", "counter", "Things.", &[("{a=\"b\"}", 3.0)]);
        assert_eq!(out.0, "# HELP x_total Things.\n# TYPE x_total counter\nx_total{a=\"b\"} 3\n");
    }

    #[test]
    fn process_stats_are_read_on_linux() {
        if cfg!(target_os = "linux") {
            let stats = process_stats().expect("/proc/self is readable");
            assert!(stats.resident_bytes > 0.0);
        }
    }
}
