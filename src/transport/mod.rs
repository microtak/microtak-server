//! Transport layer: turns raw byte streams into decoded CoT events and back.
//!
//! - [`codec`]: transport-agnostic incremental CoT XML stream decoder.
//! - [`hub`]: the shared broadcast bus [`tcp`] and [`tls`] both relay
//!   through, so a CoT event is delivered across transports, not just to
//!   other clients on the same one.
//! - [`tcp`]: plain-TCP relay listener built on the decoder (no auth).
//! - [`tls`]: mTLS-authenticated relay built on the same decoder, requiring
//!   a client cert signed by a configured CA (`docs/TEST-PLAN.md` §3).
//!
//! Not yet implemented: TAK Protocol Version 1 binary framing (§2
//! TC-STREAM-06..08).

pub mod codec;
pub mod hub;
pub mod tcp;
pub mod tls;
