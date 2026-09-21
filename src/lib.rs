//! EdgeTAK core library.
//!
//! Architecture, design decisions, and the full test-case catalog live in
//! this monorepo's wiki: `wiki/EdgeTAK.md` and `wiki/EdgeTAK-Test-Plan.md`.
//! Read those before extending this crate — this is a from-scratch,
//! compatibility-minded reimplementation of TAK server behavior, and the
//! wiki documents which behaviors are confirmed-compatible targets vs.
//! EdgeTAK's own design decisions where no authoritative spec exists.

pub mod cot;

// Planned modules, not yet implemented (scaffold phase only — see
// wiki/EdgeTAK-Test-Plan.md for the test cases each will need to satisfy
// before being considered done):
//
// - `transport`: plain-TCP and mTLS CoT streaming listeners (TAK XML +
//   TAK Protocol Version 1 framing).
// - `marti`: Marti-compatible REST API (missions/DataSync, certificate
//   enrollment, groups, device profiles).
// - `mesh`: cross-instance island sync over Reticulum/LXMF, spanning
//   MeshCore, packet radio, and Starlink/IP transports.
