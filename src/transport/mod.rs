//! Transport layer: turns raw byte streams into decoded CoT events and back.
//!
//! - [`codec`]: transport-agnostic incremental CoT XML stream decoder.
//! - [`tcp`]: plain-TCP relay listener built on the decoder (no auth).
//! - [`tls`]: mTLS-authenticated relay built on the same decoder, requiring
//!   a client cert signed by a configured CA (`docs/TEST-PLAN.md` §3).
//!
//! Not yet implemented: TAK Protocol Version 1 binary framing (§2
//! TC-STREAM-06..08), cert-CN↔uid identity binding (§3 TC-TLS-04).

pub mod codec;
pub mod tcp;
pub mod tls;
