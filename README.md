# EdgeTAK

A lightweight TAK (Team Awareness Kit) server, written in Rust, designed to
run on modest/edge infrastructure and to **federate with other EdgeTAK
instances over heterogeneous, often low-bandwidth transports** (MeshCore LoRa
mesh, Reticulum/LXMF, Starlink, potentially AX.25 packet radio) — built for
grid-down "island" scenarios where instances may be cut off from each other
for extended periods and need to resync opportunistically once a link
reappears.

**Status: early but functional.** `edgetakd` runs a real server today: CoT
parsing, a plain-TCP and an mTLS CoT relay sharing one cross-transport
broadcast bus, a certificate authority with CSR signing, a device registry
with identity binding and revocation, a certificate enrollment HTTP
endpoint, an mTLS-authenticated mission (Data Sync) metadata API — CRUD,
change log, subscriptions — an optional TOML config file, and persistence
(CA, device registry, and mission store all survive a restart). No DataSync
file content storage and no mesh-sync layer yet — see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for exactly what's built vs.
still design-stage.

This is a from-scratch implementation, not a fork of any existing TAK
server. Its design draws on source-level research into the official TAK
Server, `tkuester/taky`, and `brian7704/OpenTAKServer` — both for protocol
compatibility targets and as a "don't repeat this bug" checklist. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for what was found.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design decisions, protocol
  notes, and how EdgeTAK relates to existing TAK servers.
- [docs/TEST-PLAN.md](docs/TEST-PLAN.md) — the full test-case catalog every
  feature is expected to satisfy before being considered done.

Every feature is expected to be backed by tests (API-level integration tests
and/or unit tests) before being considered complete — see the test plan for
what "tested" means for each area. `tests/e2e.rs` drives the fully-assembled
server (real HTTP enrollment, then real mTLS/plain-TCP connections against
the same running instance); everything else is tested at the module level.

## Building and running

```sh
cargo build
cargo test               # unit + module-level integration tests
cargo test --test e2e    # end-to-end suite against the assembled server
cargo run --bin edgetakd # starts a real server on the default ports
```

Config is optional: `$EDGETAK_CONFIG`, or `./edgetak.toml` if unset (see
[docs/TEST-PLAN.md](docs/TEST-PLAN.md) §10). A missing file falls back to
defaults. CA, device registry, and mission store persist under `data_dir`
(default `./data`) and reload on the next start.

## Project layout

```
src/
  lib.rs                — crate root, module map
  app.rs                — assembles every component into one runnable server
  config.rs              — optional TOML config file, converted into AppConfig
  cot.rs                — CoT <event>/<point> XML parsing and serialization
  pki.rs                — certificate authority: CA generation, CSR signing
  registry.rs            — device registry: cert CN <-> CoT uid binding, revocation
  missions.rs             — mission (Data Sync) metadata store: CRUD, change log, subscriptions
  marti/mod.rs            — shared plain-HTTP and mTLS HTTP server plumbing
  marti/enrollment.rs    — Marti-compatible certificate enrollment HTTP endpoint (plain HTTP)
  marti/missions.rs       — Marti missions HTTP API (mTLS-authenticated)
  transport/codec.rs     — incremental CoT XML stream decoder
  transport/hub.rs       — shared cross-transport broadcast bus
  transport/tcp.rs       — plain-TCP CoT relay
  transport/tls.rs       — mTLS-authenticated CoT relay
  main.rs                — edgetakd entrypoint
tests/
  e2e.rs                 — end-to-end suite against the assembled server
```

## License

MIT — see [LICENSE](LICENSE).
