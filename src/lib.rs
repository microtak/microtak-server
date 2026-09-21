//! EdgeTAK core library.
//!
//! Architecture, design decisions, and the full test-case catalog live in
//! this monorepo's wiki: `wiki/EdgeTAK.md` and `wiki/EdgeTAK-Test-Plan.md`.
//! Read those before extending this crate — this is a from-scratch,
//! compatibility-minded reimplementation of TAK server behavior, and the
//! wiki documents which behaviors are confirmed-compatible targets vs.
//! EdgeTAK's own design decisions where no authoritative spec exists.

pub mod cot;
pub mod pki;
pub mod transport;

// Planned modules, not yet implemented (see docs/TEST-PLAN.md for the test
// cases each will need to satisfy before being considered done):
//
// - `users`: user/device (EUD) identity, groups, and profile management,
//   bound to issued certificates -- see docs/TEST-PLAN.md §3 TC-TLS-04.
//   `pki::SignedCertificate::common_name` is the hook this will consume.
// - `marti`: Marti-compatible REST API (missions/DataSync, groups, device
//   profiles, and the HTTP `/Marti/api/tls/*` enrollment contract on top of
//   `pki::CertificateAuthority`) -- see docs/TEST-PLAN.md §4-5.
// - `mesh`: cross-instance island sync over Reticulum/LXMF, spanning
//   MeshCore, packet radio, and Starlink/IP transports -- see
//   docs/TEST-PLAN.md §9.
//
// `transport` currently implements only the plain-TCP CoT relay (no TLS);
// mTLS wiring on top of `pki::CertificateAuthority` is next -- see
// `transport`'s own module docs.
// `pki` implements CA generation and CSR signing only; no persistence, no
// revocation, no HTTP enrollment endpoint yet.
