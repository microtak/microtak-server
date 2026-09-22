//! Live connected-client tracker, shared across [`super::tcp::TcpRelay`]
//! and [`super::tls::TlsRelay`] the same way [`super::hub::RelayHub`] is —
//! one registry of "who's actually connected right now," not two.
//!
//! Backs `GET /Marti/api/clientEndPoints` (TC-MARTI-09): a real reference
//! implementation was found to return a static/hardcoded empty list for
//! this endpoint regardless of who was actually connected — this registry
//! exists specifically so EdgeTAK's answer is never that.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

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

#[derive(Clone, Default)]
pub struct ConnectedClients {
    clients: Arc<RwLock<HashMap<SocketAddr, ClientEndpoint>>>,
}

impl ConnectedClients {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, endpoint: ClientEndpoint) {
        self.clients
            .write()
            .unwrap()
            .insert(endpoint.remote_addr, endpoint);
    }

    pub fn unregister(&self, remote_addr: SocketAddr) {
        self.clients.write().unwrap().remove(&remote_addr);
    }

    /// Update the bound `uid` for an already-registered connection (e.g.
    /// once TC-TLS-04's binding succeeds, sometime after connect). A no-op
    /// if `remote_addr` isn't registered (e.g. the connection already
    /// closed) — nothing to update, not an error.
    pub fn set_uid(&self, remote_addr: SocketAddr, uid: String) {
        if let Some(endpoint) = self.clients.write().unwrap().get_mut(&remote_addr) {
            endpoint.uid = Some(uid);
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
}
