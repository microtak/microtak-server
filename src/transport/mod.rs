//! Transport layer: turns raw byte streams into decoded CoT events and back.
//!
//! - [`admission`]: connection limits and the TLS handshake timeout every
//!   listener applies.
//! - [`codec`]: transport-agnostic incremental CoT XML stream decoder.
//! - [`hub`]: the shared broadcast bus [`tcp`] and [`tls`] both relay
//!   through, so a CoT event is delivered across transports, not just to
//!   other clients on the same one.
//! - [`connections`]: the shared live connected-client registry [`tcp`]
//!   and [`tls`] both register/unregister with, backing `clientEndPoints`
//!   (TC-MARTI-09).
//! - [`identity`]: what an mTLS connection may send, and as whom.
//! - [`proxy_protocol`]: real client addresses from a trusted TCP proxy.
//! - [`tcp`]: plain-TCP relay listener built on the decoder (no auth).
//! - [`tls`]: mTLS-authenticated relay built on the same decoder, requiring
//!   a client cert signed by a configured CA (`docs/TEST-PLAN.md` §3).
//!
//! Not yet implemented: TAK Protocol Version 1 binary framing (§2
//! TC-STREAM-06..08).

pub mod admission;
pub mod codec;
pub mod connections;
pub mod feeds;
pub mod hub;
pub mod identity;
pub mod proxy_protocol;
pub mod takproto;
pub mod tcp;
pub mod tls;
