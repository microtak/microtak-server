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
    /// `None` — broadcast to every other connection (the default, e.g. an
    /// ordinary PLI/position report). `Some(uids)` — GeoChat individual
    /// (`<marti><dest uid=.../></marti>`) or team (`chatgrp`) addressing
    /// (see `cot::Event::addressed_uids`): deliver only to a connection
    /// whose own identity is in this list, per
    /// `docs/TEST-PLAN.md` §7 (TC-CHAT-01/02).
    ///
    /// **Scope note**: only mTLS connections have a registry-bound identity
    /// to match against (see `transport::tls`) — plain-TCP connections have
    /// no reliable identity, so they never receive a directed message,
    /// only broadcasts. Documented, not silent: see `transport::tcp`'s
    /// delivery loop.
    pub dest_uids: Option<Arc<[String]>>,
}

impl Outbound {
    /// Whether a connection whose own identity is `my_uid` should receive
    /// this message: always true for a broadcast, otherwise only if
    /// `my_uid` is one of the addressed recipients.
    pub fn is_deliverable_to(&self, my_uid: Option<&str>) -> bool {
        match &self.dest_uids {
            None => true,
            Some(uids) => my_uid.is_some_and(|uid| uids.iter().any(|u| u == uid)),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(dest_uids: Option<Vec<&str>>) -> Outbound {
        Outbound {
            sender: "127.0.0.1:1".parse().unwrap(),
            xml: "<event/>".into(),
            dest_uids: dest_uids
                .map(|uids| uids.into_iter().map(String::from).collect::<Vec<_>>().into()),
        }
    }

    #[test]
    fn broadcast_is_deliverable_to_anyone() {
        let msg = outbound(None);
        assert!(msg.is_deliverable_to(Some("UID-A")));
        assert!(msg.is_deliverable_to(None)); // even a connection with no known identity
    }

    #[test]
    fn directed_message_only_deliverable_to_addressed_uid() {
        let msg = outbound(Some(vec!["UID-A", "UID-B"]));
        assert!(msg.is_deliverable_to(Some("UID-A")));
        assert!(msg.is_deliverable_to(Some("UID-B")));
        assert!(!msg.is_deliverable_to(Some("UID-C")));
    }

    #[test]
    fn directed_message_never_deliverable_to_unknown_identity() {
        let msg = outbound(Some(vec!["UID-A"]));
        assert!(!msg.is_deliverable_to(None));
    }
}
