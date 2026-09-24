//! MicroTAK core library.
//!
//! Architecture, design decisions, and the full test-case catalog live in
//! this monorepo's wiki: `wiki/MicroTAK.md` and `wiki/MicroTAK-Test-Plan.md`.
//! Read those before extending this crate — this is a from-scratch,
//! compatibility-minded reimplementation of TAK server behavior, and the
//! wiki documents which behaviors are confirmed-compatible targets vs.
//! MicroTAK's own design decisions where no authoritative spec exists.

pub mod app;
pub mod backup;
pub mod config;
pub mod content_store;
pub mod cot;
pub mod enrollment_tokens;
pub mod eventlog;
pub mod marti;
pub mod missions;
pub mod pki;
pub mod registry;
pub mod transport;
pub mod users;

// Planned modules, not yet implemented (see docs/TEST-PLAN.md for the test
// cases each will need to satisfy before being considered done):
//
// - `mesh`: cross-instance island sync over Reticulum/LXMF, spanning
//   MeshCore, packet radio, and Starlink/IP transports -- see
//   docs/TEST-PLAN.md §9.
//
// Current state of the implemented modules:
// - `app`: wires everything below into one runnable server (`App`) --
//   `src/main.rs` and `tests/e2e.rs` are its two consumers. CA, device
//   registry, and mission store all persist to `AppConfig::data_dir` and
//   reload across restarts.
// - `config`: optional TOML config file, converted into `AppConfig`. A
//   missing file falls back to defaults; a present-but-invalid one is a
//   hard startup error (TC-CFG-01/02).
// - `transport`: plain-TCP relay (no auth) and mTLS relay, sharing one
//   `transport::hub::RelayHub` so a CoT event crosses transports. The mTLS
//   relay enforces `registry`-based identity binding (TC-TLS-04) and
//   connect-time revocation (TC-TLS-05) -- see `transport::tls`'s own doc
//   comment for exactly what's and isn't covered.
// - `pki`: CA generation and CSR signing.
// - `eventlog`: generic append-only, replayable event log -- the shared
//   persistence/audit/backup engine both `registry` and `missions` are
//   built on. See its own doc comment for the design rationale.
// - `registry`: event-log-backed device registry, binds cert Common Name
//   to CoT `uid` (TC-TLS-04) and tracks revocation. Re-enrolling a revoked
//   device does not clear its revocation (no separate `unrevoke` exists).
// - `missions`: event-log-backed mission (Data Sync) metadata store --
//   create/update/delete, change log, subscriptions. Tracks content
//   *references* only (hash + filename) -- see `content_store` for the
//   actual bytes.
// - `content_store`: hash-addressed DataSync file content storage
//   (TC-MARTI-07/08) -- atomic upload (temp file + fsync + rename),
//   caller-claimed hashes always re-verified against the real SHA-256, and
//   a validated-hex-hash guard against path traversal on lookup.
// - `backup`: periodic local mirror of `AppConfig::data_dir` plus an
//   optional offsite shipping command (rsync/scp/aws s3 sync/...), built on
//   the append-only event-log design so a pass only copies newly-appended
//   bytes, not the whole directory every time. Off by default
//   (`AppConfig::backup`).
// - `marti::enrollment` + `marti::missions` + `marti::client_endpoints` +
//   `marti::content`: the HTTP `/Marti/api/*` contract on top of
//   `pki`/`registry`/`missions`/`content_store`. No groups/device profiles
//   yet. Enrollment is deliberately plain HTTP (unauthenticated by design);
//   everything else is mTLS-authenticated via `marti::MtlsHttpServer`
//   (TC-MARTI-10), and `missions` additionally cross-checks a claimed
//   creatorUid/actorUid/uid against the connecting cert's identity -- see
//   `marti`'s own doc comment.
