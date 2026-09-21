# EdgeTAK

A lightweight TAK (Team Awareness Kit) server, written in Rust, designed to
run on modest/edge infrastructure and to **federate with other EdgeTAK
instances over heterogeneous, often low-bandwidth transports** (MeshCore LoRa
mesh, Reticulum/LXMF, Starlink, potentially AX.25 packet radio) — built for
grid-down "island" scenarios where instances may be cut off from each other
for extended periods and need to resync opportunistically once a link
reappears.

**Status: early scaffold.** Only the CoT `<event>`/`<point>` XML model
(`src/cot.rs`) is implemented and tested. CoT streaming transport, the Marti
REST API, certificate enrollment, and the mesh-sync layer are all
design-stage — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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
what "tested" means for each area.

## Building

```sh
cargo build
cargo test
```

## Project layout

```
src/
  lib.rs   — crate root, module map (most modules are planned, not yet implemented)
  cot.rs   — CoT <event>/<point> XML parsing and serialization (implemented + tested)
  main.rs  — daemon entrypoint (currently a stub)
```

## License

MIT — see [LICENSE](LICENSE).
