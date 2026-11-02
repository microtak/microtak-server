//! Live connected-client tracker, shared across [`super::tcp::TcpRelay`]
//! and [`super::tls::TlsRelay`] the same way [`super::hub::RelayHub`] is —
//! one registry of "who's actually connected right now," not two.
//!
//! Backs `GET /Marti/api/clientEndPoints` (TC-MARTI-09): a real reference
//! implementation was found to return a static/hardcoded empty list for
//! this endpoint regardless of who was actually connected — this registry
//! exists specifically so MicroTAK's answer is never that.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::seen::SeenStore;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Unauthenticated plain-TCP CoT relay.
    Tcp,
    /// mTLS-authenticated CoT relay.
    Tls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEndpoint {
    pub remote_addr: SocketAddr,
    pub transport: Transport,
    /// The authenticated cert Common Name — always `Some` for
    /// [`Transport::Tls`], always `None` for [`Transport::Tcp`] (which has
    /// no identity, see `transport::tcp`'s own doc comment).
    pub common_name: Option<String>,
    /// The CoT `uid` this connection has bound (see TC-TLS-04) — `None`
    /// until (and unless) it does, even for an mTLS connection.
    pub uid: Option<String>,
    pub connected_at_unix: i64,
}

/// One row of `GET /Marti/api/clientEndPoints`: a currently-connected client,
/// or a previously-seen identity that is offline now. Extends the live
/// [`ClientEndpoint`] shape with `last_status` + `last_seen_unix`; the
/// live-only fields are omitted for an offline entry.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    pub common_name: Option<String>,
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at_unix: Option<i64>,
    /// `"connected"` or `"disconnected"`.
    pub last_status: &'static str,
    pub last_seen_unix: i64,
}

#[derive(Clone, Default)]
pub struct ConnectedClients {
    clients: Arc<RwLock<HashMap<SocketAddr, ClientEndpoint>>>,
    /// Each connection's subscription number, `streamingUidGen` style
    /// (from 1, per process).
    numbers: Arc<RwLock<HashMap<SocketAddr, u64>>>,
    next_number: Arc<std::sync::atomic::AtomicU64>,
    /// Each connection's latest SA, as relayed (the official
    /// `Subscription.latestSA`): gone with the connection.
    latest_sa: Arc<RwLock<HashMap<SocketAddr, Arc<str>>>>,
    /// Durable last-seen (per identity), surviving disconnect and restart.
    seen: Arc<SeenStore>,
}

impl ConnectedClients {
    pub fn new() -> Self {
        Self::default()
    }

    /// With a persistent last-seen store (see [`SeenStore::load`]).
    pub fn with_seen(seen: Arc<SeenStore>) -> Self {
        Self {
            seen,
            ..Self::default()
        }
    }

    pub fn register(&self, endpoint: ClientEndpoint) {
        let number = self
            .next_number
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if let Some(cn) = &endpoint.common_name {
            self.seen
                .mark_connected(cn, endpoint.uid.clone(), endpoint.transport, now_unix());
        }
        self.numbers
            .write()
            .unwrap()
            .insert(endpoint.remote_addr, number);
        self.clients
            .write()
            .unwrap()
            .insert(endpoint.remote_addr, endpoint);
    }

    pub fn unregister(&self, remote_addr: SocketAddr) {
        let removed = self.clients.write().unwrap().remove(&remote_addr);
        self.numbers.write().unwrap().remove(&remote_addr);
        self.latest_sa.write().unwrap().remove(&remote_addr);
        if let Some(cn) = removed.and_then(|endpoint| endpoint.common_name) {
            self.seen.mark_disconnected(&cn, now_unix());
        }
    }

    /// All known identities with their last-seen time and whether connected
    /// right now (the historical view behind `GET /Marti/api/clientEndPoints`):
    /// currently-connected clients (from the live registry) plus every
    /// previously-seen identity that is offline now.
    pub fn endpoint_views(&self) -> Vec<EndpointView> {
        let now = now_unix();
        let clients = self.clients.read().unwrap();
        let mut connected_cns = HashSet::new();
        let mut views: Vec<EndpointView> = clients
            .values()
            .map(|endpoint| {
                if let Some(cn) = &endpoint.common_name {
                    connected_cns.insert(cn.clone());
                }
                EndpointView {
                    remote_addr: Some(endpoint.remote_addr),
                    transport: Some(endpoint.transport),
                    common_name: endpoint.common_name.clone(),
                    uid: endpoint.uid.clone(),
                    connected_at_unix: Some(endpoint.connected_at_unix),
                    last_status: "connected",
                    last_seen_unix: now,
                }
            })
            .collect();
        drop(clients);
        for record in self.seen.all() {
            if connected_cns.contains(&record.common_name) {
                continue;
            }
            views.push(EndpointView {
                remote_addr: None,
                transport: Some(record.transport),
                common_name: Some(record.common_name),
                uid: record.uid,
                connected_at_unix: None,
                last_status: "disconnected",
                last_seen_unix: record.last_seen_unix,
            });
        }
        views
    }

    /// Record a connection's own SA (`trackLatestSA`). A no-op if
    /// `remote_addr` isn't registered.
    pub fn set_latest_sa(&self, remote_addr: SocketAddr, xml: Arc<str>) {
        if self.clients.read().unwrap().contains_key(&remote_addr) {
            self.latest_sa.write().unwrap().insert(remote_addr, xml);
        }
    }

    /// Every other connected client's latest SA, oldest connection first.
    pub fn latest_sas_except(&self, remote_addr: SocketAddr) -> Vec<(ClientEndpoint, Arc<str>)> {
        let clients = self.clients.read().unwrap();
        let numbers = self.numbers.read().unwrap();
        let mut sas: Vec<_> = self
            .latest_sa
            .read()
            .unwrap()
            .iter()
            .filter(|(addr, _)| **addr != remote_addr)
            .filter_map(|(addr, xml)| {
                Some((
                    numbers.get(addr).copied().unwrap_or(0),
                    clients.get(addr)?.clone(),
                    Arc::clone(xml),
                ))
            })
            .collect();
        sas.sort_by_key(|(number, _, _)| *number);
        sas.into_iter()
            .map(|(_, endpoint, xml)| (endpoint, xml))
            .collect()
    }

    /// The official subscription uid of a connection: `tls:<n>` / `tcp:<n>`.
    pub fn subscription_uid(&self, endpoint: &ClientEndpoint) -> String {
        let number = self
            .numbers
            .read()
            .unwrap()
            .get(&endpoint.remote_addr)
            .copied()
            .unwrap_or(0);
        let protocol = match endpoint.transport {
            Transport::Tls => "tls",
            Transport::Tcp => "tcp",
        };
        format!("{protocol}:{number}")
    }

    /// Update the bound `uid` for an already-registered connection (e.g.
    /// once TC-TLS-04's binding succeeds, sometime after connect). A no-op
    /// if `remote_addr` isn't registered (e.g. the connection already
    /// closed) — nothing to update, not an error.
    pub fn set_uid(&self, remote_addr: SocketAddr, uid: String) {
        let common_name = {
            let mut clients = self.clients.write().unwrap();
            match clients.get_mut(&remote_addr) {
                Some(endpoint) => {
                    endpoint.uid = Some(uid.clone());
                    endpoint.common_name.clone()
                }
                None => None,
            }
        };
        if let Some(cn) = common_name {
            self.seen.set_uid(&cn, uid);
        }
    }

    pub fn list(&self) -> Vec<ClientEndpoint> {
        self.clients.read().unwrap().values().cloned().collect()
    }
}

/// Guarantees [`ConnectedClients::unregister`] runs on every exit path out of
/// a connection-handling task (early `return`s included), without repeating
/// the call at each one. Shared by [`super::tcp`] and [`super::tls`].
pub struct UnregisterOnDrop<'a> {
    pub clients: &'a ConnectedClients,
    pub peer: SocketAddr,
}

impl Drop for UnregisterOnDrop<'_> {
    fn drop(&mut self) {
        self.clients.unregister(self.peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(addr: &str, transport: Transport) -> ClientEndpoint {
        ClientEndpoint {
            remote_addr: addr.parse().unwrap(),
            transport,
            common_name: None,
            uid: None,
            connected_at_unix: 1_000,
        }
    }

    #[test]
    fn registers_and_lists_connections() {
        let clients = ConnectedClients::new();
        assert!(clients.list().is_empty());

        clients.register(endpoint("127.0.0.1:1", Transport::Tcp));
        clients.register(endpoint("127.0.0.1:2", Transport::Tls));
        assert_eq!(clients.list().len(), 2);
    }

    #[test]
    fn unregister_removes_a_connection() {
        let clients = ConnectedClients::new();
        let addr = "127.0.0.1:1".parse().unwrap();
        clients.register(endpoint("127.0.0.1:1", Transport::Tcp));
        clients.unregister(addr);
        assert!(clients.list().is_empty());
    }

    #[test]
    fn set_uid_updates_a_live_registration() {
        let clients = ConnectedClients::new();
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        clients.register(endpoint("127.0.0.1:1", Transport::Tls));
        clients.set_uid(addr, "UID-A".to_string());

        let found = clients.list().into_iter().find(|c| c.remote_addr == addr);
        assert_eq!(found.unwrap().uid.as_deref(), Some("UID-A"));
    }

    #[test]
    fn set_uid_on_unregistered_connection_is_a_harmless_no_op() {
        let clients = ConnectedClients::new();
        clients.set_uid("127.0.0.1:9".parse().unwrap(), "UID-X".to_string());
        assert!(clients.list().is_empty());
    }

    #[test]
    fn latest_sas_are_per_connection_and_leave_with_it() {
        let clients = ConnectedClients::new();
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        clients.register(endpoint("127.0.0.1:1", Transport::Tls));
        clients.register(endpoint("127.0.0.1:2", Transport::Tls));
        clients.set_latest_sa(a, "old".into());
        clients.set_latest_sa(a, "new".into());
        clients.set_latest_sa(b, "b".into());
        clients.set_latest_sa("127.0.0.1:9".parse().unwrap(), "gone".into());

        let others: Vec<String> = clients
            .latest_sas_except(b)
            .into_iter()
            .map(|(_, xml)| xml.to_string())
            .collect();
        assert_eq!(others, vec!["new"]);
        assert_eq!(
            clients
                .latest_sas_except("127.0.0.1:3".parse().unwrap())
                .len(),
            2
        );
        clients.unregister(a);
        assert!(clients.latest_sas_except(b).is_empty());
    }
}
