//! Contacts: the official `ContactsApi` (`GET /Marti/api/contacts/all`,
//! `RemoteSubscriptionLite`) and the shape mission contacts share
//! (`RemoteSubscription`, `GET /Marti/api/missions/{name}/contacts`).
//!
//! Each connected client is one entry: `uid` is its client uid (empty until
//! its first position report), `callsign` from that report's contact,
//! `team` / `role` from `__group@name|role` and `takv` as
//! `platform:version` (all three `unknown` if any is missing --
//! `Subscription.setLatestSA`), `notes` its user, `filterGroups` null (no
//! filter groups configured). The list holds the clients the caller's OUT
//! groups can reach (`getSubscriptionsWithGroupAccess`).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde_json::{json, Value};

use super::PeerIdentity;
use crate::groups::{Direction, GroupStore};
use crate::latest_cot::LatestCot;
use crate::transport::connections::{ClientEndpoint, ConnectedClients};

#[derive(Clone)]
pub struct ContactsState {
    pub clients: ConnectedClients,
    pub latest_cot: Arc<LatestCot>,
    pub groups: Arc<GroupStore>,
    pub admin_common_name: Option<String>,
}

pub fn router(state: ContactsState) -> Router {
    Router::new().route("/Marti/api/contacts/all", get(list_contacts)).with_state(state)
}

/// team, role, takv from the latest report (`Subscription.setLatestSA`).
fn sa_fields(xml: &str) -> (String, String, String, String) {
    use quick_xml::events::Event as X;
    let mut reader = quick_xml::Reader::from_str(xml);
    let (mut team, mut role, mut platform, mut version, mut callsign) = (None, None, None, None, None);
    let mut path: Vec<Vec<u8>> = Vec::new();
    loop {
        let (e, empty) = match reader.read_event() {
            Ok(X::Start(e)) => (e.into_owned(), false),
            Ok(X::Empty(e)) => (e.into_owned(), true),
            Ok(X::End(_)) => {
                path.pop();
                continue;
            }
            Ok(X::Eof) | Err(_) => break,
            Ok(_) => continue,
        };
        let name = e.name().as_ref().to_vec();
        if path == [b"event".to_vec(), b"detail".to_vec()] {
            let get = |k: &str| {
                e.attributes()
                    .flatten()
                    .find(|a| a.key.as_ref() == k.as_bytes())
                    .and_then(|a| a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()))
            };
            match name.as_slice() {
                b"__group" => {
                    team = get("name");
                    role = get("role");
                }
                b"takv" => {
                    platform = get("platform");
                    version = get("version");
                }
                b"contact" => callsign = get("callsign"),
                _ => {}
            }
        }
        if !empty {
            path.push(name);
        }
    }
    let callsign = callsign.unwrap_or_default();
    match (team, role, platform, version) {
        (Some(t), Some(r), Some(p), Some(v)) => (callsign, t, r, format!("{p}:{v}")),
        _ => (callsign, "unknown".into(), "unknown".into(), "unknown".into()),
    }
}

/// The `contact` callsign of a CoT event ("" without one).
pub fn callsign(xml: &str) -> String {
    sa_fields(xml).0
}

/// `RemoteSubscription` / `RemoteSubscriptionLite` JSON for a connection.
pub fn remote_subscription(endpoint: &ClientEndpoint, latest_cot: &LatestCot) -> Value {
    let uid = endpoint.uid.clone().unwrap_or_default();
    let (callsign, team, role, takv) = match endpoint.uid.as_deref().and_then(|u| latest_cot.get(u)) {
        Some(event) => sa_fields(&event.xml),
        None => (String::new(), String::new(), String::new(), String::new()),
    };
    json!({
        "filterGroups": null,
        "notes": endpoint.common_name.clone().unwrap_or_default(),
        "callsign": callsign,
        "team": team,
        "role": role,
        "takv": takv,
        "uid": uid,
    })
}

/// The connections whose groups meet `groups` (all of them for the admin).
pub fn reachable(state_clients: &ConnectedClients, groups_store: &GroupStore, groups: Option<&std::collections::BTreeSet<String>>) -> Vec<ClientEndpoint> {
    state_clients
        .list()
        .into_iter()
        .filter(|c| match (groups, &c.common_name) {
            (None, _) => true,
            (Some(groups), Some(cn)) => groups_store.all_group_names(cn).iter().any(|g| groups.contains(g)),
            (Some(groups), None) => groups.contains(crate::groups::ANON_GROUP),
        })
        .collect()
}

async fn list_contacts(State(state): State<ContactsState>, Extension(identity): Extension<PeerIdentity>) -> Json<Vec<Value>> {
    let admin = state.admin_common_name.as_deref() == Some(identity.0.as_str());
    let out = state.groups.active_groups(Some(&identity.0), Direction::Out);
    let reachable = reachable(&state.clients, &state.groups, (!admin).then_some(&out));
    Json(reachable.iter().map(|c| remote_subscription(c, &state.latest_cot)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::connections::Transport;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn state() -> ContactsState {
        ContactsState {
            clients: ConnectedClients::new(),
            latest_cot: Arc::new(LatestCot::in_memory()),
            groups: Arc::new(GroupStore::in_memory()),
            admin_common_name: None,
        }
    }

    async fn contacts(state: &ContactsState, cn: &str) -> Vec<Value> {
        let mut request = Request::builder().uri("/Marti/api/contacts/all").body(Body::empty()).unwrap();
        request.extensions_mut().insert(PeerIdentity(cn.into()));
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    fn connect(state: &ContactsState, port: u16, cn: &str, uid: Option<&str>) {
        state.clients.register(ClientEndpoint {
            remote_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            transport: Transport::Tls,
            common_name: Some(cn.into()),
            uid: uid.map(String::from),
            connected_at_unix: 1_000,
        });
    }

    /// `RemoteSubscriptionLite` from the latest report: callsign, team,
    /// role, `platform:version`; `unknown` if the report lacks any of them.
    #[tokio::test]
    async fn contacts_carry_the_official_fields() {
        let s = state();
        assert!(contacts(&s, "me").await.is_empty());
        connect(&s, 1, "device-a", Some("UID-A"));
        s.latest_cot.record("UID-A", r#"<event version="2.0" uid="UID-A" type="a-f-G-U-C" how="h-e" time="t" start="t" stale="t"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail><contact callsign="ALPHA" endpoint="*:-1:stcp"/><__group name="Cyan" role="Team Member"/><takv platform="ATAK-CIV" version="5.6.0" device="d" os="34"/></detail></event>"#, 1);
        connect(&s, 2, "device-b", Some("UID-B"));
        s.latest_cot.record("UID-B", r#"<event version="2.0" uid="UID-B" type="a-f-G-U-C" how="h-e" time="t" start="t" stale="t"><point lat="0" lon="0" hae="0" ce="0" le="0"/><detail><contact callsign="BRAVO" endpoint="*:-1:stcp"/></detail></event>"#, 1);
        connect(&s, 3, "device-c", None);
        let mut list = contacts(&s, "me").await;
        list.sort_by_key(|c| c["notes"].as_str().unwrap().to_string());
        assert_eq!(
            list[0],
            json!({ "filterGroups": null, "notes": "device-a", "callsign": "ALPHA", "team": "Cyan", "role": "Team Member", "takv": "ATAK-CIV:5.6.0", "uid": "UID-A" })
        );
        assert_eq!((list[1]["team"].as_str(), list[1]["takv"].as_str()), (Some("unknown"), Some("unknown")));
        assert_eq!(list[2]["uid"], "", "listed before its first report, without a uid");
    }

    #[tokio::test]
    async fn contacts_are_limited_to_reachable_groups() {
        let s = state();
        s.groups.create("Red", None, 0).unwrap();
        s.groups.set_member("Red", "red-1", Some(crate::groups::Membership::Both)).unwrap();
        s.groups.set_member("Red", "red-2", Some(crate::groups::Membership::Both)).unwrap();
        connect(&s, 1, "red-1", Some("R1"));
        connect(&s, 2, "anon", Some("A1"));
        let red: Vec<String> = contacts(&s, "red-2").await.iter().map(|c| c["uid"].as_str().unwrap().to_string()).collect();
        assert_eq!(red, ["R1"]);
        let anon: Vec<String> = contacts(&s, "other").await.iter().map(|c| c["uid"].as_str().unwrap().to_string()).collect();
        assert_eq!(anon, ["A1"]);
    }
}
