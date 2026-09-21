//! Marti-compatible REST API surface.
//!
//! - [`enrollment`]: certificate enrollment (`/Marti/api/tls/*`).
//!
//! Not yet implemented: missions/DataSync, groups, device profiles (see
//! `docs/TEST-PLAN.md` §5).

pub mod enrollment;
