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
    /// The sender's active IN groups at send time (`crate::groups`): the
    /// message reaches a connection only if one of these is among that
    /// connection's active OUT groups -- the official TAK Server's
    /// reachability rule. Anonymous senders carry `__ANON__`.
    pub groups: Arc<std::collections::BTreeSet<String>>,
    /// Who produced it: a client's event, or the server's own message
    /// (mission notifications).
    pub origin: Origin,
    /// The TAK Protocol frame, encoded once by the first protobuf receiver
    /// and shared by the rest (`None` inside: it can't be sent as one).
    pub proto: Arc<std::sync::OnceLock<Option<Arc<[u8]>>>>,
}

/// Where an [`Outbound`] came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Client,
    /// A server message. Addressed (`dest_uids`) ones go straight to those
    /// connections, as the official server submits to a subscription
    /// directly; broadcast ones reach connections sharing one of `groups`
    /// (always, if `groups` has `__ANON__`, which every official user
    /// holds), except `skip_uid` -- `submitBroadcastMissionAnnouncementCot`.
    Server {
        skip_uid: Option<Arc<str>>,
    },
}

/// The address server-originated messages carry as their sender.
pub const SERVER_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

impl Outbound {
    /// A server message for exactly these client uids.
    pub fn server_to(uids: Vec<String>, xml: String) -> Self {
        Outbound {
            sender: SERVER_ADDR,
            xml: xml.into(),
            dest_uids: Some(uids.into()),
            groups: Arc::new(Default::default()),
            origin: Origin::Server { skip_uid: None },
            proto: Default::default(),
        }
    }

    /// A server broadcast to everyone sharing one of `groups`, but `skip_uid`.
    pub fn server_broadcast(
        groups: std::collections::BTreeSet<String>,
        skip_uid: Option<String>,
        xml: String,
    ) -> Self {
        Outbound {
            sender: SERVER_ADDR,
            xml: xml.into(),
            dest_uids: None,
            groups: Arc::new(groups),
            origin: Origin::Server {
                skip_uid: skip_uid.map(Into::into),
            },
            proto: Default::default(),
        }
    }

    /// Whether a connection receiving from `receiver_out_groups` (its
    /// active OUT groups) may see this message at all.
    pub fn reaches(&self, receiver_out_groups: &std::collections::BTreeSet<String>) -> bool {
        match self.origin {
            Origin::Server { .. } if self.dest_uids.is_some() => true,
            Origin::Server { .. } if self.groups.contains(crate::groups::ANON_GROUP) => true,
            _ => self
                .groups
                .iter()
                .any(|group| receiver_out_groups.contains(group)),
        }
    }

    /// Whether a connection whose own identity is `my_uid` should receive
    /// this message: always true for a broadcast, otherwise only if
    /// `my_uid` is one of the addressed recipients.
    pub fn is_deliverable_to(&self, my_uid: Option<&str>) -> bool {
        if let Origin::Server {
            skip_uid: Some(skip),
        } = &self.origin
            && my_uid == Some(skip.as_ref())
        {
            return false;
        }
        match &self.dest_uids {
            None => true,
            Some(uids) => my_uid.is_some_and(|uid| uids.iter().any(|u| u == uid)),
        }
    }
}

/// Streaming mission content (`<marti><dest mission=…>`), implemented by
/// the mission side ([`crate::marti::mission_notify`]) so the transports
/// don't depend on it.
pub trait StreamingMissions: Send + Sync {
    /// The event `event_uid` from `client_uid` / `username` is addressed to
    /// these missions: record it where the client may write, and return the
    /// live subscribers it goes to.
    fn route(
        &self,
        client_uid: Option<&str>,
        username: &str,
        names: &[String],
        guids: &[String],
        event_uid: &str,
    ) -> Vec<String>;
    /// The client is gone: it stops receiving mission changes.
    fn client_disconnected(&self, client_uid: &str);
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
            dest_uids: dest_uids.map(|uids| {
                uids.into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>()
                    .into()
            }),
            groups: Arc::new(std::collections::BTreeSet::from(["__ANON__".to_string()])),
            origin: Origin::Client,
            proto: Default::default(),
        }
    }

    /// Official reachability: delivered iff the sender's IN groups and the
    /// receiver's OUT groups share a group.
    #[test]
    fn reaches_requires_a_shared_group() {
        let mut msg = outbound(None);
        msg.groups = Arc::new(["Red".to_string(), "Blue".to_string()].into());
        assert!(msg.reaches(&["Blue".to_string()].into()));
        assert!(!msg.reaches(&["Green".to_string()].into()));
        assert!(!msg.reaches(&std::collections::BTreeSet::new()));
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
