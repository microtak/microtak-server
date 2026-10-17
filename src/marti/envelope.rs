//! The official TAK Server's response conventions, shared by every Marti
//! endpoint that has an official counterpart:
//!
//! - **Envelope** (`com.bbn.marti.cot.search.model.ApiResponse`,
//!   `@JsonInclude(NON_NULL)`): `{"version": "3", "type": <Java class
//!   name>, "data": ..., "nodeId": <server id>}`.
//! - **Dates** (`tak.server.Constants.COT_DATE_FORMAT`,
//!   `yyyy-MM-dd'T'HH:mm:ss.S'Z'`): UTC, milliseconds *unpadded* -- Java's
//!   `SimpleDateFormat` writes `S` as the plain number (`.5`, `.42`, `.689`).
//! - **Server id**: the official `serverInfo().getServerId()` is a random
//!   32-hex-digit id generated once per installation; ours is persisted in
//!   `data_dir/server-id` ([`load_or_create_server_id`]).

use std::path::Path;
use std::sync::OnceLock;

use axum::Json;
use serde::Serialize;

/// `tak.server.Constants.API_VERSION`.
pub const API_VERSION: &str = "3";

static SERVER_ID: OnceLock<String> = OnceLock::new();

/// This installation's id (the envelope's `nodeId`). Set by `App::bind`
/// from `data_dir`; a process that never binds an `App` (unit tests) gets a
/// random one.
pub fn server_id() -> &'static str {
    SERVER_ID.get_or_init(random_id)
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read `data_dir/server-id`, creating it on first start, and make it this
/// process's [`server_id`].
pub fn load_or_create_server_id(data_dir: &Path) -> std::io::Result<String> {
    let path = data_dir.join("server-id");
    let id = match std::fs::read_to_string(&path) {
        Ok(existing) if !existing.trim().is_empty() => existing.trim().to_string(),
        _ => {
            let id = random_id();
            std::fs::write(&path, format!("{id}\n"))?;
            id
        }
    };
    // A second App in the same process (tests) keeps the first id.
    let _ = SERVER_ID.set(id.clone());
    Ok(id)
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    version: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    data: T,
    #[serde(rename = "nodeId")]
    node_id: &'static str,
}

/// The official envelope around `data`, `kind` being the official model's
/// Java class name (`Mission`, `TakCert`, `MissionSubscription`, ...).
pub fn api_response<T: Serialize>(kind: &'static str, data: T) -> Json<serde_json::Value> {
    Json(
        serde_json::to_value(ApiResponse {
            version: API_VERSION,
            kind,
            data,
            node_id: server_id(),
        })
        .unwrap_or(serde_json::Value::Null),
    )
}

/// A Unix timestamp (seconds) in the official COT date format.
pub fn cot_date(unix_seconds: i64) -> String {
    cot_date_millis(unix_seconds.saturating_mul(1000))
}

/// A Unix timestamp in milliseconds in the official COT date format.
pub fn cot_date_millis(unix_millis: i64) -> String {
    let nanos = (unix_millis as i128) * 1_000_000;
    let dt = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{}Z",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.millisecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cot_dates_have_unpadded_milliseconds_like_java() {
        assert_eq!(cot_date_millis(1_760_716_800_005), "2025-10-17T16:00:00.5Z");
        assert_eq!(cot_date_millis(1_760_716_800_042), "2025-10-17T16:00:00.42Z");
        assert_eq!(cot_date_millis(1_760_716_800_689), "2025-10-17T16:00:00.689Z");
        assert_eq!(cot_date(0), "1970-01-01T00:00:00.0Z");
    }

    #[test]
    fn envelope_has_version_type_data_and_node_id() {
        let Json(value) = api_response("TakCert", vec![1, 2]);
        assert_eq!(value["version"], "3");
        assert_eq!(value["type"], "TakCert");
        assert_eq!(value["data"], serde_json::json!([1, 2]));
        assert_eq!(value["nodeId"].as_str().unwrap().len(), 32);
    }

    #[test]
    fn the_server_id_is_persisted() {
        let dir = std::env::temp_dir().join(format!("microtak-server-id-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_or_create_server_id(&dir).unwrap();
        assert_eq!(load_or_create_server_id(&dir).unwrap(), first);
        std::fs::remove_dir_all(&dir).ok();
    }
}
