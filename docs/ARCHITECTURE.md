# EdgeTAK Architecture

**Status: early but functional.** `edgetakd` runs a real server: CoT parsing (`src/cot.rs`), a plain-TCP and an mTLS CoT relay sharing one cross-transport broadcast bus (`src/transport/`), a certificate authority with CSR signing (`src/pki.rs`), a device registry with cert-CN↔uid identity binding and revocation (`src/registry.rs`), a certificate enrollment HTTP endpoint (`src/marti/enrollment.rs`), and an mTLS-authenticated mission (Data Sync) metadata API — CRUD, change log, subscriptions (`src/missions.rs` + `src/marti/missions.rs`) — all assembled by `src/app.rs`. Covered end-to-end by `tests/e2e.rs` in addition to each module's own tests. No config file, no persistence across restarts, and no DataSync file content storage or mesh sync yet — everything below past this point describes target design, not all of it built. The missions API validates the *connection's* client cert but doesn't yet cross-check a request body's claimed `creatorUid`/`actorUid` against that identity — see `marti`'s doc comment.

## What this is

EdgeTAK is a lightweight TAK (Team Awareness Kit) server, written in Rust, with two goals that existing options (the official TAK Server, FreeTAKServer, taky, OpenTAKServer) don't combine:

1. **Small footprint, single static binary** — no JVM, no Postgres, no message broker required to run a basic instance, suited to modest/edge hardware (SBCs, potentially battery-powered mesh nodes).
2. **Mesh-federated, grid-down resilient.** Multiple EdgeTAK instances should be able to run as fully standalone "islands" and **opportunistically sync** with each other once connectivity reappears, over heterogeneous and often severely bandwidth-constrained transports: MeshCore (LoRa mesh), Reticulum (RNS), Starlink, and potentially AX.25 packet radio.

This is a from-scratch implementation, not a fork. Research on the official TAK Server, taky, and OpenTAKServer informs protocol-compatibility targets and a "don't repeat this bug" checklist — see [TEST-PLAN.md](./TEST-PLAN.md) for the full, cited catalog this project is built against.

## Scope

**In scope (eventually):**

1. CoT ingestion/relay over plain TCP and mTLS-authenticated TCP (TAK CoT XML; TAK Protocol Version 1 binary framing as a secondary target).
2. A Marti-API-compatible REST surface sufficient for real ATAK/WinTAK/iTAK/WebTAK clients to enroll, stream, and use Data Sync/missions.
3. Certificate enrollment (CSR submission + signing), matching the real Marti `/Marti/api/tls/*` contract closely enough for stock clients to work unmodified.
4. **Mesh sync**: EdgeTAK-to-EdgeTAK synchronization of CoT state across islanded deployments (see below).

5. **User/device (EUD) management**: identity, groups, and profiles, bound to issued certificates. Depends on PKI existing first.
6. **Backup**: periodic backup-to-disk (interval configurable), plus optional S3/SCP/rsync offsite backup when internet access is available. Not meaningful to implement until there's persistent state (CA/keys, device records, config) worth backing up.
7. **Deployment packaging**: container image (Docker/Podman-compatible), a Helm chart, and install instructions. The Helm chart is deferred until the config surface (TLS certs, persistence, mesh-sync settings) is stable enough to be worth expressing as chart values.

**Deferred to a later phase, and possibly unneeded:** a full TAK web client — live map, video feed playback, geolocated images, a live event stream, chat, and team status visualization. Put on the backburner in favor of a full end-to-end test suite first; an existing web TAK client (CloudTAK) may be reused instead of building a bespoke one, once the Marti API surface is compatible enough. Not started.

**Explicitly out of scope for now:**

- Official-TAK-Server-style federation (gRPC-over-HTTP/2 on a dedicated port) — insufficiently documented from authoritative public sources to build a compatible peer, and not the sync model this project actually needs.
- Video/VCM streaming.
- LDAP/AD auth, device profiles/groups/channels beyond a minimal viable set.
- ExCheck.

## CoT protocol notes

- **CoT XML streaming has no message-boundary framing** beyond well-formed `<event>...</event>` documents concatenated with no delimiter — a receiver must behave like a streaming XML parser, not assume one socket read equals one message. Confirmed from the official `takproto` README in `deptofdefense/AndroidTacticalAssaultKit-CIV`.
- **Real ATAK clients send every CoT event on a persistent stream as its own complete XML document**, each with its own leading `<?xml version='1.0'...?>` declaration. Most streaming XML parsers choke on more than one declaration/root element per stream — a CoT parser has to specifically tolerate this, including a declaration split across TCP reads. (Confirmed from `tkuester/taky`'s source, which works around exactly this with a hand-rolled byte-level scanner.)
- **TAK Protocol Version 1 (binary/protobuf) framing**: `0xbf <varint version> <protobuf payload>` for mesh/UDP, `0xbf <varint payload-length> <protobuf payload>` for TCP streaming. The varint is a standard Protocol Buffers base-128 varint — an off-the-shelf Rust protobuf/varint implementation (e.g. `prost`) is safe to reuse. Negotiation is a hard, one-way cutover (`<TakProtocolSupport>` → `<TakRequest>` → `<TakResponse status="true">`), after which mixed framing is not supported.
- **Marti API certificate enrollment (`signClient/v2`) requires a raw-body CSR with PEM headers/footers stripped and `Content-Type: application/octet-stream`.** A form-encoded POST silently misparses on at least one real, deployed community TAK server implementation — this is a confirmed, high-value interoperability gotcha, not a hypothetical.
- **`stale` is a client-side display/trust-window hint, not a server-enforced rule.** No evidence any reference server drops/rejects events whose `stale` has already elapsed at receipt time.
- **No explicit CoT "disconnect"/"logout" event type is part of the base spec** — but at least one real, deployed community TAK server implementation synthesizes one on disconnect (a `t-x-d-d` event, `how="h-g-i-g-o"`). EdgeTAK adopts this convention.
- **GeoChat team/group routing depends on a `chatgrp` element's `uid2` attribute and a `hierarchy` sub-tag inside `__chat`**, not just `chatroom`/`groupOwner`. Omitting these has caused *silent partial delivery* (some recipients get a message, others don't) in at least one real server implementation — a failure mode worse than an outright error because it's easy to miss with too few test clients.

## Security/robustness lessons from existing implementations

Two independent, real community TAK server implementations were read at the source level as part of this project's research. Recurring findings worth designing against from day one:

- **No max CoT event size enforced** in at least one reference implementation (explicitly acknowledged as an open TODO in its own source) — an unbounded single event can exhaust memory. EdgeTAK enforces a configurable cap.
- **XXE/entity-resolution hardening must be applied consistently across every XML entry point**, not just the primary CoT parser — a real implementation's own documented "never resolve entities" policy was found contradicted in a secondary (video-registry) endpoint.
- **No binding between a connection's authenticated TLS client-cert identity and the CoT-level `uid`/callsign it's allowed to assert.** In both implementations studied, a connection authenticated as cert CN=A can send CoT events claiming to be a completely different, known device's `uid`, with no cross-check. One implementation's own source comments this is a *deliberate* tradeoff to support legitimate mesh/RF-relay gateways (a bridge relaying CoT on behalf of an off-grid device under that device's own identity). EdgeTAK's own mesh-relay design faces the identical tension — a mesh gateway legitimately needs to forward CoT under another device's identity — so this needs an explicit, documented authorization model (e.g. a "trusted relay" grant per connection), not a silent default in either direction.
- **Certificate verification must check the full validity window and reject cleanly on failure**, not just check the CA signature. A confirmed bug in one implementation used an invalid Python exception-matching construct (`except A | B` on two exception classes) that raised an unrelated crash at exactly the moment a certificate legitimately failed verification, and separately never checked cert expiration at all.
- **Every rejection path should produce a specific, logged, human-readable reason server-side**, even where the wire protocol has no room for rich error detail in the client-facing response. A recurring pattern in both implementations studied is a low-level internal error (a stack trace, a broker-routing failure, a form-encoding mismatch) leaking to the client or logs untranslated, instead of a clean, typed rejection.
- **A failure in one part of per-event processing should not silently cancel unrelated processing for the same event.** One implementation runs a long, unguarded sequential chain of processing steps per CoT event (position → chat → alert → casevac → marker → mission routing) — a single bad sub-block early in the chain silently cancels everything after it.

## Mesh sync architecture — the core design problem

The grid-down/island requirement is fundamentally a **delay-tolerant networking (DTN) / store-and-forward** problem, not the official TAK Server's federation model (always-on mutual TLS between two well-connected servers). Islands may be cut off for hours, reconnect unpredictably, and the available link on reconnect may be extremely low-bandwidth (LoRa, AX.25 packet radio) as often as it's fast (Starlink).

Current design direction:

1. **Reticulum (RNS)** — `markqvist/Reticulum` — as the single addressing/routing layer spanning all target transports. It's designed to work over any half-duplex channel ≥5bps with MTU ≥500 bytes, natively supports LoRa, AX.25 TNCs, serial, and IP/TCP interfaces, and its wire protocol was dedicated to the public domain. This avoids building separate transport-specific sync paths for each medium.
2. **LXMF**, built on Reticulum by the same team, already implements the needed store-and-forward behavior: "Propagation Nodes" cache messages for currently-unreachable destinations and automatically peer/sync their stores with each other when they can see each other. This is treated as a maintained, purpose-built component rather than something to reimplement from a DTN textbook.
3. **Caveat, not yet validated**: LXMF is designed for human-rate messaging, not high-frequency position (PLI) telemetry. CoT position updates at native ATAK update rates would need batching/coalescing before riding LXMF, or risk flooding propagation nodes — this needs hands-on prototyping/measurement.
4. **Wire payload over slow links must be TAK Protobuf, not XML** — a full XML CoT event is several complete packets' worth of airtime on 1200-baud AX.25 or slow LoRa configs. This is close to a hard requirement for the packet-radio/LoRa tiers, not an optimization.
5. **Conflict resolution**: a hand-rolled per-`uid`, last-writer-wins-by-`time` merge is judged sufficient — CoT's semantics (independent per-uid entities, newer `time` supersedes, expiry via `stale`) don't need a general-purpose CRDT library.
6. **Integration path**: prototype against the Python reference `rnsd` daemon (as a sidecar process) before committing to a native-Rust RNS implementation. Several exist, but their wire-compatibility claims against the Python reference implementation are largely self-reported and unverified as of this writing.
7. **Open items**: an authoritative MeshCore throughput figure, and measured LXMF per-message overhead against CoT's native update frequency — both needed before this moves from design to implementation.

## Open questions

- Async runtime and HTTP framework choice for the Marti API surface (`tokio` + `axum` are the likely default, not yet decided in code).
- TLS library choice for mTLS CoT streaming (`rustls` is the likely default for a pure-Rust stack, avoiding an OpenSSL system dependency).
- Whether to shell out to `rnsd` (Python sidecar) or adopt a native Rust Reticulum crate for the mesh-sync layer.
- Exact v1 scope of the Marti API surface (which endpoints are must-have for real client compatibility vs. deferred).
- Whether EdgeTAK issues its own PKI (own CA) or expects to be paired with an existing TAK CA.

## Sources

Key public references used during research: `deptofdefense/AndroidTacticalAssaultKit-CIV` (`takproto/README.md`), `tkuester/taky` (source + issue tracker), `brian7704/OpenTAKServer` (source), `markqvist/Reticulum` and `markqvist/LXMF`, `Cloud-RF/tak-server` (`CoreConfig.xml`), and third-party Marti API documentation at `docs.magktech.com`.
