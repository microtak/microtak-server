//! Transport layer: turns raw byte streams into decoded CoT events and back.
//!
//! - [`codec`]: transport-agnostic incremental CoT XML stream decoder.
//! - [`tcp`]: plain-TCP relay listener built on the decoder (no TLS yet).
//!
//! Not yet implemented: mTLS-authenticated streaming (`docs/TEST-PLAN.md`
//! §3 TC-TLS-*), TAK Protocol Version 1 binary framing (§2 TC-STREAM-06..08).

pub mod codec;
pub mod tcp;
