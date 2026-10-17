//! `GET /Marti/api/subscriptions/all` (`SubscriptionApi.getAllSubscriptions`):
//! one `SubscriptionInfo` per connected client -- the admin sees all, others
//! those their groups reach.
//!
//! The values follow how the official server fills them: the subscription
//! uid is `tls:<n>` / `tcp:<n>`; protocol, ip and port come from parsing the
//! Netty handler's `toString` ("Netty Dummy TCP Channel server on local port
//! … client: /1.2.3.4:5678" split on `:`), hence protocol `Netty` and the
//! address with a leading space; callsign falls back to the subscription
//! uid; `takClient:takVersion` from the report's `platform:version`; the
//! metrics fields (`t-x-c-m`) stay empty. The result is a set ordered by
//! `SubscriptionInfo.hashCode` (the official `ConcurrentSkipListSet`).

use axum::extract::{RawQuery, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde_json::{json, Value};

use super::contacts::ContactsState;
use super::PeerIdentity;
use crate::transport::connections::{ClientEndpoint, Transport};

pub fn router(state: ContactsState) -> Router {
    Router::new().route("/Marti/api/subscriptions/all", get(all_subscriptions)).with_state(state)
}

/// Java's `String.hashCode`.
fn java_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32))
}

/// `SubscriptionInfo.hashCode` over its eight fields, in order.
fn info_hash(fields: [&str; 8]) -> i32 {
    fields.iter().fold(1i32, |h, f| h.wrapping_mul(31).wrapping_add(java_hash(f)))
}

fn info(state: &ContactsState, endpoint: &ClientEndpoint, now_ms: i64) -> (i32, Value) {
    let contact = super::contacts::remote_subscription(endpoint, &state.latest_cot);
    let s = |k: &str| contact[k].as_str().unwrap_or("").to_string();
    let subscription_uid = state.clients.subscription_uid(endpoint);
    let callsign = if s("callsign").is_empty() { subscription_uid.clone() } else { s("callsign") };
    let takv = s("takv");
    let (tak_client, tak_version) = match takv.split_once(':') {
        Some((client, version)) => (client.to_string(), version.split(':').next().unwrap_or("").to_string()),
        None => (takv.clone(), String::new()),
    };
    let ip = match endpoint.remote_addr {
        std::net::SocketAddr::V4(a) => a.ip().to_string(),
        std::net::SocketAddr::V6(a) => a.ip().to_string(),
    };
    let ip_address = format!(" {ip}");
    let port = endpoint.remote_addr.port().to_string();
    let username = endpoint.common_name.clone().unwrap_or_default();
    let dn = endpoint.common_name.as_ref().map(|cn| format!("CN={cn}")).unwrap_or_default();
    let last_report = endpoint.uid.as_deref().and_then(|u| state.latest_cot.get(u)).map(|e| e.server_time_ms).unwrap_or(0);
    let groups: Vec<Value> = match (&endpoint.common_name, endpoint.transport) {
        (Some(cn), Transport::Tls) => state
            .groups
            .memberships(cn)
            .into_iter()
            .map(|g| serde_json::to_value(super::groups::GroupJson::from(g)).unwrap_or(Value::Null))
            .collect(),
        _ => Vec::new(),
    };
    let client_uid = s("uid");
    let protocol = "Netty".to_string();
    let hash = info_hash([&client_uid, &dn, &ip_address, &port, &protocol, &s("role"), &subscription_uid, &username]);
    let value = json!({
        "dn": dn,
        "callsign": callsign,
        "clientUid": client_uid,
        "lastReportMilliseconds": last_report,
        "lastReportDiffMilliseconds": now_ms - last_report,
        "takClient": tak_client,
        "takVersion": tak_version,
        "username": username,
        "groups": groups,
        "role": s("role"),
        "ipAddress": ip_address,
        "port": port,
        "pendingWrites": 0,
        "team": s("team"),
        "protocol": protocol,
        "xpath": null,
        "subscriptionUid": subscription_uid,
        "numProcessed": 0,
        "appFramerate": "",
        "battery": "",
        "batteryStatus": "",
        "batteryTemp": "",
        "deviceDataRx": "",
        "deviceDataTx": "",
        "heapCurrentSize": "",
        "heapFreeSize": "",
        "heapMaxSize": "",
        "deviceIPAddress": "",
        "storageAvailable": "",
        "storageTotal": "",
        "incognito": false,
        "handlerType": "",
    });
    (hash, value)
}

async fn all_subscriptions(
    State(state): State<ContactsState>,
    Extension(identity): Extension<PeerIdentity>,
    _headers: HeaderMap,
    RawQuery(_query): RawQuery,
) -> Response {
    let admin = state.admin_common_name.as_deref() == Some(identity.0.as_str());
    let groups = state.groups.all_group_names(&identity.0);
    let clients = super::contacts::reachable(&state.clients, &state.groups, (!admin).then_some(&groups));
    let now = crate::cot::now_unix_millis();
    let mut set: std::collections::BTreeMap<i32, Value> = std::collections::BTreeMap::new();
    for client in &clients {
        let (hash, value) = info(&state, client, now);
        set.entry(hash).or_insert(value);
    }
    super::envelope::api_response("SubscriptionInfo", Value::Array(set.into_values().collect())).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn java_string_hashes() {
        assert_eq!(java_hash(""), 0);
        assert_eq!(java_hash("a"), 97);
        assert_eq!(java_hash("hello"), 99_162_322);
        assert_eq!(java_hash("tls:1"), "tls:1".encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32)));
    }

    #[tokio::test]
    async fn subscription_info_follows_the_official_values() {
        let state = ContactsState {
            clients: crate::transport::connections::ConnectedClients::new(),
            latest_cot: Arc::new(crate::latest_cot::LatestCot::in_memory()),
            groups: Arc::new(crate::groups::GroupStore::in_memory()),
            admin_common_name: None,
        };
        let endpoint = ClientEndpoint {
            remote_addr: "10.1.2.3:55555".parse().unwrap(),
            transport: Transport::Tls,
            common_name: Some("jz".into()),
            uid: Some("ANDROID-1".into()),
            connected_at_unix: 0,
        };
        state.clients.register(endpoint.clone());
        state.latest_cot.record("ANDROID-1", r#"<event version="2.0" uid="ANDROID-1" type="a-f-G-U-C" how="h-e" time="t" start="t" stale="t"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail><contact callsign="JZ" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Lead"/><takv platform="ATAK-CIV" version="5.6.0.1" device="d" os="34"/></detail></event>"#, 1_000);
        let (_, v) = info(&state, &endpoint, 5_000);
        assert_eq!(v["subscriptionUid"], "tls:1");
        assert_eq!(v["callsign"], "JZ");
        assert_eq!((v["takClient"].as_str(), v["takVersion"].as_str()), (Some("ATAK-CIV"), Some("5.6.0.1")));
        assert_eq!((v["protocol"].as_str(), v["ipAddress"].as_str(), v["port"].as_str()), (Some("Netty"), Some(" 10.1.2.3"), Some("55555")));
        assert_eq!(v["lastReportDiffMilliseconds"], 4_000);
        assert_eq!(v["dn"], "CN=jz");
        assert_eq!(v["xpath"], Value::Null);
    }
}
