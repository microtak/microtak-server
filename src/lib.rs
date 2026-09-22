//! EdgeTAK core library.
//!
//! Architecture, design decisions, and the full test-case catalog live in
//! this monorepo's wiki: `wiki/EdgeTAK.md` and `wiki/EdgeTAK-Test-Plan.md`.
//! Read those before extending this crate — this is a from-scratch,
//! compatibility-minded reimplementation of TAK server behavior, and the
//! wiki documents which behaviors are confirmed-compatible targets vs.
//! EdgeTAK's own design decisions where no authoritative spec exists.

pub mod app;
pub mod cot;
pub mod marti;
pub mod missions;
pub mod pki;
pub mod registry;
pub mod transport;

// Planned modules, not yet implemented (see docs/TEST-PLAN.md for the test
// cases each will need to satisfy before being considered done):
//
// - `mesh`: cross-instance island sync over Reticulum/LXMF, spanning
//   MeshCore, packet radio, and Starlink/IP transports -- see
//   docs/TEST-PLAN.md §9.
//
// Current state of the implemented modules:
// - `app`: wires everything below into one runnable server (`App`) --
//   `src/main.rs` and `tests/e2e.rs` are its two consumers.
// - `transport`: plain-TCP relay (no auth) and mTLS relay, sharing one
//   `transport::hub::RelayHub` so a CoT event crosses transports. The mTLS
//   relay enforces `registry`-based identity binding (TC-TLS-04) and
//   connect-time revocation (TC-TLS-05) -- see `transport::tls`'s own doc
//   comment for exactly what's and isn't covered.
// - `pki`: CA generation and CSR signing. No persistence of the CA itself
//   yet (only the device registry persists).
// - `registry`: JSON-file-backed device registry, binds cert Common Name
//   to CoT `uid` (TC-TLS-04) and tracks revocation. Re-enrolling a revoked
//   device does not clear its revocation (no separate `unrevoke` exists).
// - `missions`: JSON-file-backed mission (Data Sync) metadata store --
//   create/update/delete, change log, subscriptions. No DataSync file
//   *content* storage yet (TC-MARTI-07/08) -- see its own doc comment.
// - `marti::enrollment` + `marti::missions`: the HTTP `/Marti/api/*`
//   contract on top of `pki`/`registry`/`missions`. No groups/device
//   profiles yet. Enrollment is deliberately plain HTTP (unauthenticated by
//   design); missions is mTLS-authenticated via `marti::MtlsHttpServer`
//   (TC-MARTI-10) -- request handlers don't yet cross-check a claimed
//   creatorUid/actorUid against the connecting cert's identity, though; see
//   `marti`'s own doc comment.
