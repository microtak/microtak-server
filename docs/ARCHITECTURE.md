# MicroTAK Architecture

**Status: early but functional.** `microtakd` runs a real server: CoT parsing (`src/cot.rs`), a plain-TCP and an mTLS CoT relay sharing one cross-transport broadcast bus and one live connected-client registry (`src/transport/`), a certificate authority with CSR signing (`src/pki.rs`), a device registry with cert-CN↔uid identity binding and revocation (`src/registry.rs`), a certificate enrollment HTTP endpoint (`src/marti/enrollment.rs`), an mTLS-authenticated mission (Data Sync) metadata API — CRUD, change log, subscriptions, per-request identity-claim enforcement (`src/missions.rs` + `src/marti/missions.rs`) — a `GET /Marti/api/clientEndPoints` endpoint backed by that live registry rather than a static stub (`src/transport/connections.rs` + `src/marti/client_endpoints.rs`), hash-addressed DataSync file content storage with server-verified hashes and atomic writes (`src/content_store.rs` + `src/marti/content.rs`), periodic local + optional-offsite backup of persistent state, built on the append-only design so a pass only copies newly-appended bytes (`src/backup.rs`, off by default), opt-in enrollment invite tokens plus a minimal mTLS-authenticated admin API to mint/list/revoke them (`src/enrollment_tokens.rs` + `src/marti/admin.rs`, off by default), an optional TOML config file, and persistence: the CA, device registry, mission store, and uploaded content all survive a restart (`src/config.rs`, `src/app.rs`) — verified against the real binary, not just the test suite (a CA's fingerprint confirmed identical across two actual runs). All assembled by `src/app.rs`, covered end-to-end by `tests/e2e.rs` in addition to each module's own tests. No mesh sync yet — everything below past this point describes target design, not all of it built.

## What this is

MicroTAK is a lightweight TAK (Team Awareness Kit) server, written in Rust, with two goals that existing options (the official TAK Server, FreeTAKServer, taky, OpenTAKServer) don't combine:

1. **Small footprint, single static binary** — no JVM, no Postgres, no message broker required to run a basic instance, suited to modest/edge hardware (SBCs, potentially battery-powered mesh nodes).
2. **Mesh-federated, grid-down resilient.** Multiple MicroTAK instances should be able to run as fully standalone "islands" and **opportunistically sync** with each other once connectivity reappears, over heterogeneous and often severely bandwidth-constrained transports: MeshCore (LoRa mesh), Reticulum (RNS), Starlink, and potentially AX.25 packet radio. As of 2026-09-23 this sync/dedup logic is planned to live in a separate `microtak-sync` connector, not in this repo — see "Project split" below.

This is a from-scratch implementation, not a fork. Research on the official TAK Server, taky, and OpenTAKServer informs protocol-compatibility targets and a "don't repeat this bug" checklist — see [TEST-PLAN.md](./TEST-PLAN.md) for the full, cited catalog this project is built against.

## Scope

**In scope (eventually):**

1. CoT ingestion/relay over plain TCP and mTLS-authenticated TCP (TAK CoT XML; TAK Protocol Version 1 binary framing as a secondary target).
2. A Marti-API-compatible REST surface sufficient for real ATAK/WinTAK/iTAK/WebTAK clients to enroll, stream, and use Data Sync/missions.
3. Certificate enrollment (CSR submission + signing), matching the real Marti `/Marti/api/tls/*` contract closely enough for stock clients to work unmodified.
4. **Mesh sync**: MicroTAK-to-MicroTAK synchronization of CoT state across islanded deployments (see below).

5. **User/device (EUD) management**: identity, groups, and profiles, bound to issued certificates. Depends on PKI existing first.
6. **Backup**: periodic backup-to-disk (interval configurable), plus optional S3/SCP/rsync offsite backup when internet access is available. **Implemented** (`src/backup.rs`) — see "Implemented" line above.
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
- **No explicit CoT "disconnect"/"logout" event type is part of the base spec** — but at least one real, deployed community TAK server implementation synthesizes one on disconnect (a `t-x-d-d` event, `how="h-g-i-g-o"`). MicroTAK adopts this convention.
- **GeoChat team/group routing depends on a `chatgrp` element's `uid2` attribute and a `hierarchy` sub-tag inside `__chat`**, not just `chatroom`/`groupOwner`. Omitting these has caused *silent partial delivery* (some recipients get a message, others don't) in at least one real server implementation — a failure mode worse than an outright error because it's easy to miss with too few test clients.

## Security/robustness lessons from existing implementations

Two independent, real community TAK server implementations were read at the source level as part of this project's research. Recurring findings worth designing against from day one:

- **No max CoT event size enforced** in at least one reference implementation (explicitly acknowledged as an open TODO in its own source) — an unbounded single event can exhaust memory. MicroTAK enforces a configurable cap.
- **XXE/entity-resolution hardening must be applied consistently across every XML entry point**, not just the primary CoT parser — a real implementation's own documented "never resolve entities" policy was found contradicted in a secondary (video-registry) endpoint.
- **No binding between a connection's authenticated TLS client-cert identity and the CoT-level `uid`/callsign it's allowed to assert.** In both implementations studied, a connection authenticated as cert CN=A can send CoT events claiming to be a completely different, known device's `uid`, with no cross-check. One implementation's own source comments this is a *deliberate* tradeoff to support legitimate mesh/RF-relay gateways (a bridge relaying CoT on behalf of an off-grid device under that device's own identity). MicroTAK's own mesh-relay design faces the identical tension — a mesh gateway legitimately needs to forward CoT under another device's identity — so this needs an explicit, documented authorization model (e.g. a "trusted relay" grant per connection), not a silent default in either direction.
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
6. **Integration path, resolved 2026-09-23**: build against `BeechatNetworkSystemsLtd/Reticulum-rs` (crate `reticulum`), a native async-Rust implementation, rather than shelling out to the Python reference `rnsd`. Hands-on evaluation of every candidate found: Beechat's crate has real, current adoption (339★, pushed within the last month as of this writing), a plain, permissive MIT license — freely includable in MicroTAK's own AGPL-3.0 codebase (permissive-into-copyleft is a one-way-compatible direction; see "Licensing" below for why MicroTAK itself is AGPL, not MIT) — tokio-native (no FFI/subprocess), and implements exactly the primitives this design needs (Destination, Link, Channel, Resource, and a real multi-hop-routing Transport). No LXMF support, which is fine — MicroTAK's own settled design (point 5 below) builds its own uid-keyed merge/store-and-forward logic regardless, so LXMF was never going to be used as-is. Other candidates checked and rejected for now: `lelloman/rns-rs` (most feature-complete, but under a non-OSI "ethical use" license variant and very new, worth re-checking in 6-12 months as it may overtake Beechat's crate); `merely-made/retinue`+`outrider` (best-tested, does have real LXMF support, but single-maintainer v0.0.x with real bus-factor risk); `jrl290/Reticulum-rust` (no LICENSE file at all — legally unusable, disqualified outright). The Reticulum "shared instance" local-socket protocol (port 37428, HDLC-framed — how Sideband/Nomad Network/MeshChat already interoperate with a shared `rnsd`) remains a documented, real fallback if the chosen crate stalls, but isn't needed given the above.
7. **Open items**: an authoritative MeshCore throughput figure, and measured LXMF-equivalent per-message overhead against CoT's native update frequency (now to be measured against `reticulum`'s own Resource/Link overhead directly, having dropped LXMF) — both needed before this moves from design to implementation.

**"Can this whole layer just be handed off to Reticulum?" — checked directly, answer: transport yes, sync semantics no.** Reticulum's own primitives (Destination, Link, Channel, Resource, Packet) are point-to-point transport — addressing, encrypted links, reliable transfer. LXMF adds a discrete message unit with no supersession/versioning concept anywhere in its spec: two updates to the same logical entity are just two unrelated messages with different content hashes. Propagation Node "sync" replicates a *message log*, not a *current-state table* — no merge/conflict-resolution semantics are documented anywhere, and no project in the Reticulum ecosystem (Sideband, Nomad Network, MeshChat — all messaging/chat-shaped) does structured-record sync either; a real builder asking this exact question in Reticulum's own GitHub discussions got help with an integer-parsing bug, not merge semantics. So concretely: encryption, identity, multi-hop routing, and store-and-forward delivery are genuinely Reticulum/LXMF's job — but treating a CoT `uid` as a logical key, resolving out-of-order arrivals by `time`, deduplicating by that key, and deciding whether a newly-reachable island needs a re-send are unavoidably MicroTAK's own code, no matter what. Point 5 above isn't optional scope to trim later — it's the minimum viable application layer LXMF leaves for any structured-data use case, confirmed by checking rather than assumed.

## Project split: microtak-server / microtak-sync / microtak-node — decided 2026-09-23

EdgeTAK was renamed **MicroTAK** and split into separate repos/crates rather than staying one monolithic binary, generalizing the bridge-pattern decision below into the project's actual top-level shape:

- **`microtak-server`** — this repo. The TAK server itself: CoT relay, mTLS/PKI, missions/DataSync, `clientEndPoints`, content storage, event-log persistence/audit trail, backup. Stays a lightweight, single static binary with **no radio- or mesh-protocol code linked into it at all** — every integration below talks to it only through its existing plain-TCP/mTLS CoT ports and Marti HTTP API, never as a compiled-in dependency.
- **`microtak-sync`** — the mesh-federation connector. Owns the actual synchronization/deduplication logic: the per-`uid`, last-write-wins merge that the Reticulum research below concluded is unavoidably this project's own code, not something Reticulum/LXMF provides. It subscribes to `microtak-server`'s plain-TCP feed to build its own "last known state per uid" cache, does the mesh-side merge/resend decision-making there (not in `microtak-server`), and re-injects synced CoT back through the same port. This is the same integration point and trust model as any other connector (see below) — `microtak-server` has no special knowledge of mesh sync.
- **`microtak-node`** — a new, **not yet started** component: embedded client firmware for LoRa/Bluetooth/WiFi hardware (ESP32/nRF52-class), targeting specific real devices — Heltec V2/V3/V4, LilyGO T-Echo, Seeed Wio Tracker L1 (nRF52840 + LR1110) — so trackers/radios can participate directly rather than needing a host-PC bridge. **Open, explicitly undecided question**: whether `microtak-node`'s link to the server (via `microtak-sync`) should be strictly Reticulum-based, or something else — likely constrained by real embedded flash/RAM/power budgets vs. running a full Reticulum stack on a microcontroller. This needs dedicated research, peer review, and red-teaming before committing, not a default assumption carried over from the server-side decision above.

## Radio/protocol bridge integration pattern — resolved 2026-09-23

Raised concretely by a future-scope note to integrate DMR and analog radio (both carry APRS, producing GPS position events; DMR also carries its own SMS-like text messaging) — but the same question applies to any radio/protocol/connector `microtak-server` doesn't natively speak, `microtak-sync` included (see split above). **Decision: bridge as a separate, optional service/connector that speaks CoT into the server over its existing transport, not code integrated into the core.**

Reasoning:

1. **MicroTAK's own design already anticipates exactly this.** The plain-TCP CoT relay (`src/transport/tcp.rs`) is explicitly documented and tested as accepting CoT from "a trusted local bridge like an APRS-IS gateway" (`src/transport/hub.rs`'s doc comment; exercised in `tests/e2e.rs`'s `e2e_fanout_to_multiple_clients_across_mixed_transports`, where the sender "doesn't need to be enrolled/authenticated -- it connects over the plain-TCP transport, like a trusted local bridge would"). No new API surface is needed for this pattern — it already exists and is already covered by tests.
2. **Real precedent in this monorepo**: `opentakserver/aprscot/` is already exactly this shape — a standalone APRS-IS-to-CoT bridge, not code merged into OpenTAKServer itself.
3. **Keeps the core lightweight**, per this doc's own "small footprint, single static binary" goal (see "What this is" above). Radio-protocol dependencies (KISS/AX.25 framing, DMR parsing, serial/hamlib bindings, a full Reticulum stack) are exactly the kind of thing that would bloat every build for deployments that don't need that particular connector, and connector-specific code tends to be more experimental/unstable than the core — a crash or hang in a DMR driver, or in `microtak-sync`'s mesh logic, shouldn't be able to take down the CoT relay.
4. **True optionality**: a deployment without DMR/analog radio hardware, or without mesh federation at all, simply doesn't run that connector process. A Cargo feature flag would still ship the dependency in the binary even when unused; a separate process doesn't.

**Connector-to-server trust model, by deployment shape**: a same-host/trusted-LAN connector (the common case — a connector process and the server on the same box or a trusted local network) should use the unauthenticated plain-TCP port, no cert management needed, matching the APRS-IS-gateway pattern already documented. A connector crossing an untrusted network boundary should instead enroll via the normal mTLS enrollment flow, so its CoT carries a real, revocable device identity rather than anonymous trust.

This pattern is the default for every connector — `microtak-sync`, DMR, analog-radio APRS, and anything else not natively spoken by the core — not just the DMR/analog-radio case that originally prompted deciding it.

## Licensing — decided 2026-09-23

MicroTAK is licensed **AGPL-3.0-or-later**, not the MIT license it started under. Deliberate choice, not a default: the concern was a for-profit fork running a modified version as a closed, hosted service with no obligation to give anything back. Plain GPL wouldn't actually close that gap — it only requires sharing source on *distribution*, and running a modified server as a service never distributes a binary to anyone. AGPL's Section 13 specifically extends the sharing requirement to network use: if you run a modified MicroTAK as a network service at all, you have to offer users of that service the modified source. This doesn't *prevent* a for-profit fork — nothing except a non-OSI, source-available restriction (Business Source License, SSPL, etc.) actually does that, and those come at the cost of not being recognized as open source at all (rejected by Debian/Fedora, generally distrusted by contributors) — it just guarantees any such fork stays open, which was the actual goal. Dual-licensing (AGPL publicly, a separate commercial license without the AGPL obligations sold to companies that want one) remains an open option for later if it's ever worth pursuing, but requires owning 100% of the copyright — meaning outside contributions would need a CLA from that point on, not a decision to make casually.

Practical consequence: any dependency pulled into `microtak-server` must be permissively licensed (MIT/Apache-2.0/BSD) or itself AGPL/GPL-compatible — permissive-into-copyleft is fine (see the Reticulum crate license note above), the reverse is not.

## Resource requirements — measured 2026-09-23, not estimated

Actually load-tested against the real published `ghcr.io/microtak/microtak-server:latest` image (Docker, `docker stats`), not benchmarked-by-arithmetic. Methodology: N concurrent real client connections (plain-TCP or mTLS, each enrolling for real over HTTP for the mTLS cases), each sending a realistic ~250-300 byte PLI-style CoT event (position + contact + status + group) at a configurable interval, relayed by the real broadcast fan-out to every other connection — the O(N²)-ish cost this architecture's whole design is actually exercising.

| Scenario | Server CPU | Memory (RSS) | Notes |
|---|---|---|---|
| Idle, 0 clients | ~0% | 6.7 MiB | baseline |
| 100 clients, plain-TCP, realistic rate (avg ~8s/update) | 4.7–5.7% of 1 core | 6.8–7.2 MiB | ~13.5 events/s ingress, ~1,336 deliveries/s fan-out |
| 100 clients, plain-TCP, aggressive rate (avg ~2s/update) | 10.5–14% of 1 core | 6.6–6.9 MiB | scales sublinearly with event rate, not the bottleneck at this N |
| 100 simultaneous mTLS handshakes (reconnect-storm simulation) | 34.6% spike, gone within ~1s | 9.4–9.7 MiB | real but brief; ECDSA handshake cost, not sustained load |
| 100 mTLS clients, sustained relay (same rate as plain-TCP case) | ~0.01% | 9.4–9.7 MiB | identical relay code path to plain-TCP once connected — mTLS's only added cost is the one-time handshake |

Caveat on the mTLS handshake numbers: a client-side per-handshake latency figure (~400ms average) was also measured but discarded as unreliable — it's an artifact of the single-threaded Python test client doing 100 real OpenSSL handshakes itself, not a server-side signal. The server-side CPU spike (34.6%, resolving within ~1s) is the trustworthy number.

**Headroom conclusion**: at 100 clients, even the worst-case mixed scenario tested (mass mTLS reconnect immediately followed by aggressive-rate updates) doesn't come close to stressing a modern single core, and memory stays under 10MB total. **1 vCPU / 256MB RAM is comfortable for 100 clients** with real headroom to spare — the limiting factor at higher N would be aggregate bandwidth from the broadcast fan-out (O(N²) in client count × update rate), not CPU or memory.

### Raspberry Pi Zero estimate

No physical unit was available to test against directly, so this combines one real empirical technique (Docker `--cpus`/`--memory` cgroup constraints against the actual image, which exactly replicates the 512MB RAM ceiling both Pi Zero variants share) with published single-core benchmark ratios (necessarily lower-confidence than the table above):

- Constraining the container to a 5%-of-this-test-host's-core CPU quota **saturated** under the aggressive-rate 100-client workload (pinned at the quota ceiling).
- Constraining to 15% left comfortable headroom (~3.3% actual use) under the realistic-rate workload.
- Memory never exceeded ~10MB even at 100 mTLS clients — the 512MB ceiling on either Pi Zero variant is not a constraint at this scale.

Extrapolating from there using published Geekbench single-core figures (Pi Zero's ARM11 core scores roughly 30-50 vs. a typical modern server/desktop core's 1500-2500+, i.e. very roughly 1.5-3% of one modern core; Pi Zero 2 W's Cortex-A53 cores score roughly 130-180, i.e. very roughly 6-12% each, ×4 cores):

- **Original Pi Zero** (single ARM11 core @ 1GHz, ARMv6, no NEON): roughly **30-60 clients at realistic update rates**, **15-30 clients** if most are updating aggressively. Real open question, not verified: whether the `ring` crypto backend has an optimized path for ARMv6 at all, or falls back to a slower generic implementation, which would specifically hurt mTLS handshake cost (not steady-state relay throughput).
- **Pi Zero 2 W** (quad-core Cortex-A53 @ 1GHz, ARMv8): roughly **100-300 clients at realistic rates**, likely still fine at 100+ under aggressive rates given 4 available cores against a workload that barely stresses one. Lower-confidence than the original-Pi-Zero estimate since multi-core scaling wasn't specifically emulated.

Both estimates should be treated as informed extrapolation, not measurement — re-verify on real hardware before using either number for a real deployment decision.

## Enrollment lockdown / admin API — decided 2026-09-23

Enrollment (`POST /Marti/api/tls/signClient/v2`) is wide open by design, matching the real Marti contract -- fine on a trusted network, a real gap otherwise. Rather than requiring auth on enrollment itself (which has no cert yet to authenticate with), added an opt-in invite-token gate: `AppConfig::enrollment_requires_token` (off by default) requires a valid, single-use, optionally-expiring token alongside the CSR. Tokens are minted/listed/revoked through a small new admin API on the existing mTLS Marti listener, gated by a configured `admin_common_name` -- fails closed if unset, not open by default.

This has a real, unavoidable bootstrap-order implication: the admin's own device has to be enrolled while enrollment is still open (the admin endpoints are only reachable over mTLS using a cert enrollment already issued), *then* `enrollment_requires_token` gets turned on and the server restarted. It's a two-phase, restart-based flow, not a live toggle -- config is loaded once at startup, matching every other config value in this project. Documented and tested as exactly that two-phase sequence, not glossed over as a single-step "just turn it on."

## Mission roles — decided 2026-09-23

The other half of the permissions discussion above: missions previously had zero authorization beyond identity-claim matching (a caller could only ever act *as itself*, but any authenticated device could delete or rewrite *any* mission's metadata, not just its own). Added `MissionRole` (`Owner`, `Subscriber`) to `src/missions.rs`'s data model — `Owner` assigned automatically to a mission's creator, `Subscriber` assigned automatically on subscribing and removed on unsubscribing (an `Owner` who subscribes/unsubscribes from their own mission keeps `Owner` regardless — subscription state never demotes an owner).

**A genuinely nice consequence of the event-sourcing design**: role state isn't a new field written into the event log — it's deterministically re-derived by the reducer from the exact same `Created`/`Subscribed`/`Unsubscribed` events that already existed for unrelated reasons. Replaying an *existing*, pre-roles `missions.log` with the new code correctly reconstructs every mission's Owner/Subscriber roles with zero migration code, zero schema versioning, zero backfill script — the append-only, replay-everything design pays for itself again here, the same way it already did for backup and audit trail.

**Enforcement** (`src/marti/missions.rs`): `delete`/`update` require `Owner`; `add_content` requires *any* role — real collaborative Data Sync usage (multiple devices contributing pins/files to one mission), not locked to the creator alone. `list`/`get`/`changes` stay deliberately unrestricted regardless of role, matching real collaborative situational-awareness use (discovering/previewing a mission before joining it) — only mutating actions are role-gated, a scope boundary chosen deliberately rather than gating everything by default. New `PUT`/`DELETE /missions/:name/role(/:uid)` endpoints let an `Owner` assign or revoke another identity's role, with a last-owner protection (a mission can never end up with zero owners — a permanent lockout) enforced at the store level, surfaced as a real `409` through the HTTP layer, not just checked ad hoc per caller.

This closes the first half of a two-part permissions/enrollment discussion; the second half -- real roles/permissions on missions (MISSION_OWNER/SUBSCRIBER-style) -- needs a data-model change to `missions.rs` and is deliberately deferred as separate, larger work, not bundled into this change.

## Open questions

- Async runtime and HTTP framework choice for the Marti API surface (`tokio` + `axum` are the likely default, not yet decided in code).
- TLS library choice for mTLS CoT streaming (`rustls` is the likely default for a pure-Rust stack, avoiding an OpenSSL system dependency).
- ~~Whether to shell out to `rnsd` (Python sidecar) or adopt a native Rust Reticulum crate for the mesh-sync layer.~~ Resolved 2026-09-23: native crate, `BeechatNetworkSystemsLtd/Reticulum-rs` (see point 6 above).
- Exact v1 scope of the Marti API surface (which endpoints are must-have for real client compatibility vs. deferred).
- Whether MicroTAK issues its own PKI (own CA) or expects to be paired with an existing TAK CA.

## Sources

Key public references used during research: `deptofdefense/AndroidTacticalAssaultKit-CIV` (`takproto/README.md`), `tkuester/taky` (source + issue tracker), `brian7704/OpenTAKServer` (source), `markqvist/Reticulum` and `markqvist/LXMF`, `Cloud-RF/tak-server` (`CoreConfig.xml`), and third-party Marti API documentation at `docs.magktech.com`.
