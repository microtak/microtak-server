//! Shared CoT relay hub: the single broadcast bus every transport listener
//! ([`super::tcp`], [`super::tls`]) publishes into and reads from, so a CoT
//! event ingested on *any* transport is relayed to clients connected via
//! *any other* transport too.
//!
//! Before this existed, [`super::tcp::TcpRelay`] and [`super::tls::TlsRelay`]
//! each created their own independent broadcast channel — a real
//! architectural gap found while building the end-to-end test suite: a CoT
//! event sent by a plain-TCP client (e.g. a trusted local bridge like an
//! APRS-IS gateway) would never reach an mTLS-authenticated client, and
//! vice versa, even though both are meant to be one shared tactical picture
//! on one server. A real deployment expects exactly one routing domain
//! regardless of which port a given client happened to connect through.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::broadcast;

/// How many not-yet-delivered events a slow client can lag behind before it
/// starts missing messages (see [`broadcast`]'s lagged-receiver semantics).
pub const DEFAULT_CAPACITY: usize = 1024;

/// A CoT event read off the wire by one connection, queued for delivery to
/// every *other* connection on *any* transport sharing this hub.
#[derive(Clone)]
pub struct Outbound {
    /// The originating connection's address, so its own transport listener
    /// can skip re-delivering an event back to its own sender.
    pub sender: SocketAddr,
    pub xml: Arc<str>,
}

#[derive(Clone)]
pub struct RelayHub {
    tx: broadcast::Sender<Outbound>,
}

impl RelayHub {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn sender(&self) -> broadcast::Sender<Outbound> {
        self.tx.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Outbound> {
        self.tx.subscribe()
    }
}

impl Default for RelayHub {
    fn default() -> Self {
        Self::new()
    }
}
