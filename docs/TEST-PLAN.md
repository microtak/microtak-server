# EdgeTAK Test Plan

Test-case catalog for EdgeTAK, derived from source-level research on the official TAK Server, `tkuester/taky`, and `brian7704/OpenTAKServer`, plus this project's own design decisions for the mesh-sync layer. Every feature is expected to be backed by a test (unit and/or API-level integration test) before being considered done — this document is the checklist that's measured against.

**Status**: research/planning phase. Only the "CoT Event Model" section below has implemented tests (`src/cot.rs`). Everything else is planned.

## How to read this catalog

Each test case is tagged with why it exists:

- **[COMPAT]** — a confirmed real-server/real-client behavior EdgeTAK must match for interoperability. Cited to a primary or strongly-corroborated source.
- **[DESIGN]** — a behavior with no authoritative spec found; EdgeTAK is making its own decision and the test verifies *that decision*, not compatibility with anything external.
- **[HARDEN]** — a defensive/security test targeting a known weakness or bug class found in an existing implementation, which EdgeTAK should deliberately avoid repeating.

---

## 1. CoT Event Model (`src/cot.rs`) — implemented

| ID | Case | Type | Status |
|---|---|---|---|
| TC-COT-01 | Parse a minimal well-formed `<event>` with all required attributes and a `<point>` | [COMPAT] | ✅ implemented |
| TC-COT-02 | Round-trip parse→serialize→parse produces an equal `Event` | [DESIGN] | ✅ implemented |
| TC-COT-03 | Parse an event with a `<detail>` block; detail is preserved (currently as opaque raw passthrough) | [COMPAT] | ✅ implemented |
| TC-COT-04 | Reject an event missing a required attribute (`uid`) | [COMPAT] | ✅ implemented |
| TC-COT-05 | Reject malformed/unclosed XML | [COMPAT] | ✅ implemented |
| TC-COT-06 | Accept an event whose `stale` predates `time`/`start` — parsing must not reject this; `stale` is a client-side display hint, not a server-enforced ordering rule | [DESIGN] | ✅ implemented |
| TC-COT-07 | Round-trip an event carrying unknown/extra root-level attributes (e.g. `opex`, `qos`, `access` — real clients send these) without silently corrupting known fields. Open design question: preserve unknown attributes round-trip-safe, or document dropping them? | [DESIGN] | ❌ not implemented |
| TC-COT-08 | Reject (or gracefully handle, per a documented policy) non-numeric point/detail fields seen in real-world non-ATAK CoT producers, e.g. `hae="NaN"`, `course="unknown"`, `speed="unknown"` (a confirmed real payload shape from an ADS-B bridge integration) | [HARDEN] | ❌ not implemented |
| TC-COT-09 | Enforce a configurable maximum single-event size and reject (not silently OOM) an oversized `<event>`. At least one reference implementation has **no such limit** (an explicit open TODO in its own source) — this is a deliberate EdgeTAK improvement, not a compatibility requirement. | [HARDEN] | ❌ not implemented |
| TC-COT-10 | Model at least the `<contact>`, `<__chat>`, `<__group>`/`chatgrp`, `<status>`, and `<precisionlocation>` detail sub-elements structurally, rather than opaque passthrough — needed before chat/group routing tests (§7) can be meaningful | [COMPAT] | ❌ not implemented (currently opaque `RawDetail`) |
| TC-COT-11 | Parsing/serialization never resolves external XML entities (XXE hardening), verified as a property test across **every** XML entry point in the codebase, not just the primary CoT parser | [HARDEN] | ❌ not implemented |

## 2. CoT Transport / Stream Framing

The single most important interoperability risk identified during research.

**Implemented** (`src/transport/codec.rs`, `src/transport/tcp.rs`): TC-STREAM-01 through 05, plus TC-ROUTE-01 (baseline broadcast relay) — TC-STREAM-01/02/03/05 as fast unit tests directly against `StreamDecoder`, TC-STREAM-04/05/TC-ROUTE-01 as real socket-level integration tests against an actual `TcpListener`. TC-STREAM-06 through 11 (TAK Protocol binary framing, TLS handshake timeout, idle-client tolerance, startup timeout) are not yet implemented.

| ID | Case | Type |
|---|---|---|
| TC-STREAM-01 | Correctly parse a persistent TCP stream where **every** CoT event carries its own leading `<?xml version="1.0" ...?>` declaration (confirmed real ATAK behavior) | [COMPAT] |
| TC-STREAM-02 | Correctly parse the above when an XML declaration is split across multiple TCP reads/packets | [COMPAT] |
| TC-STREAM-03 | Correctly parse a single `<event>` split across multiple TCP reads at an arbitrary byte boundary (not just at the declaration) | [COMPAT] |
| TC-STREAM-04 | On a stream-level XML syntax error (malformed markup, not just a bad CoT field), disconnect the client — do not attempt to resync mid-stream | [DESIGN] |
| TC-STREAM-05 | On a semantically-invalid-but-well-formed single event (e.g. bad date field, missing optional attribute), log and skip that event — keep the connection open, process subsequent events normally | [DESIGN] |
| TC-STREAM-06 | Detect and correctly handle the TAK Protocol Version 1 binary framing cutover: `<TakProtocolSupport version="N"/>` advertisement → client `<TakRequest version="N"/>` → server `<TakResponse status="true"/>` → both sides switch to `0xbf`-prefixed protobuf framing and never send CoT XML again on that connection | [COMPAT] |
| TC-STREAM-07 | Correctly decode the TAK Protocol stream variant's length-prefix as a standard protobuf base-128 varint (not a fixed-width integer) | [COMPAT] |
| TC-STREAM-08 | Correctly decode the TAK Protocol mesh variant (`0xbf <varint version> <payload>`, no length prefix) | [COMPAT] |
| TC-STREAM-09 | A stalled/incomplete TLS handshake is force-disconnected after a bounded timeout rather than holding a connection slot indefinitely | [HARDEN] |
| TC-STREAM-10 | An idle, fully-connected client (no CoT sent, no ping) is **not** disconnected by the server — TAK keepalive is client-initiated | [COMPAT] |
| TC-STREAM-11 | Reject (with a clear log message, not a silent hang or crash) a connection that never completes a valid handshake/first-message within a bounded startup window | [HARDEN] |

## 3. TLS / mTLS & Certificate Identity

**Implemented** (`src/transport/tls.rs` + `src/registry.rs`): TC-TLS-01, TC-TLS-02, TC-TLS-04, and TC-TLS-05 (connect-time only), each as a real `rustls`/`tokio-rustls` mTLS handshake over an actual TCP socket, using certs issued by `src/pki.rs` and identities tracked in the device registry. TC-TLS-02/04/05's rejection tests all account for the same TLS 1.3 subtlety: a client can consider its handshake/read "succeeded" locally before the server's rejection (a TLS close_notify, sent explicitly on every disconnect path) actually arrives, so each test treats a failed handshake, a failed write, or a failed/EOF read as a pass. TC-TLS-03 is implemented as "require a client cert" only (not the "or allow anonymous" branch). TC-TLS-06/07 are not yet implemented.

| ID | Case | Type |
|---|---|---|
| TC-TLS-01 | Accept a valid client cert signed by EdgeTAK's own CA over the mTLS CoT port | [COMPAT] |
| TC-TLS-02 | Reject a client cert not signed by EdgeTAK's CA (untrusted issuer) at the TLS layer | [COMPAT] |
| TC-TLS-03 | Reject a client with no cert at all when client-cert-required mode is on; decide deliberately whether EdgeTAK offers an unauthenticated mode at all | [DESIGN] |
| TC-TLS-04 | **Bind CoT-level session identity to the authenticated cert's CN.** Reject (or clearly flag) a self-identifying CoT atom whose claimed `uid`/callsign is inconsistent with the connecting cert's identity. This is a deliberate divergence from at least one reference implementation, which has no such binding by its own documented admission and allows uid/callsign spoofing and silent mid-session re-identification. | [HARDEN] |
| TC-TLS-05 | A revoked certificate is rejected. Decide and test explicitly **when**: at TLS handshake time vs. app-level check after handshake vs. continuous re-checking of already-open sessions | [DESIGN] |
| TC-TLS-06 | Certificate enrollment issues certs usable immediately over the mTLS CoT port with no server restart/reload required | [COMPAT] |
| TC-TLS-07 | Client cert bundle format (PKCS12) is importable by a real ATAK/WinTAK client, not just OpenSSL-verifiable — test against a live client, not just cryptographic correctness (real ATAK-specific import failures have been reported against at least one reference implementation's bundles, root cause unconfirmed) | [COMPAT] |

## 4. Certificate Enrollment / Marti PKI API

**Implemented** (`src/pki.rs` + `src/marti/enrollment.rs` + `src/registry.rs`): CA generation and CSR signing (`pki.rs`), the HTTP `/Marti/api/tls/config` and `/Marti/api/tls/signClient/v2` endpoints (`marti/enrollment.rs`), and device recording on successful enrollment (`registry.rs`). Covers TC-ENROLL-01, 02, 03, 06, and 07 — each as a real HTTP integration test against a bound `axum` server using `reqwest`, including one that cryptographically re-verifies the returned certificate against the CA. TC-ENROLL-04 (re-enrollment policy) has a partial, tested answer: re-enrolling preserves both the `uid` binding and revocation status rather than resetting either — but no endpoint-level test of *re-enrollment via HTTP* exists yet, only at the registry level. `v1` (`signClient/` with no suffix) is deliberately not implemented (see the module's doc comment for why). TC-ENROLL-05 (enrollment Data Package / "quick connect") is not yet implemented.

| ID | Case | Type |
|---|---|---|
| TC-ENROLL-01 | `GET /Marti/api/tls/config` reachable with no client cert, returns CA config info | [COMPAT] |
| TC-ENROLL-02 | CSR submission to the v2 signing endpoint **succeeds** when sent as raw-body `application/octet-stream` with PEM headers/footers stripped | [COMPAT] |
| TC-ENROLL-03 | CSR submission sent as `application/x-www-form-urlencoded` (or otherwise not raw-body octet-stream) is **rejected with a clear, specific error** — not silently misparsed into an opaque 500. Confirmed as a real bug in at least one deployed reference implementation. | [HARDEN] |
| TC-ENROLL-04 | Re-enrollment of an already-enrolled CN (same identity requests a new cert) is handled per a documented policy — no authoritative source found for official-server behavior here, so this is EdgeTAK's own decision | [DESIGN] |
| TC-ENROLL-05 | An enrollment-package endpoint (equivalent to `GET /Marti/api/tls/profile/enrollment`) returns a full enrollment Data Package (connection settings + client cert bundle) usable by ATAK's "quick connect" flow, as a distinct code path from raw CSR signing | [COMPAT] |
| TC-ENROLL-06 | A malformed/truncated/non-CSR payload to the signing endpoint is rejected with a clear error, not a crash or hang | [HARDEN] |
| TC-ENROLL-07 | Enrollment success responses adapt their exact shape (body format and `Content-Type` header) to which client is asking, if broad out-of-the-box compatibility with ATAK/WinTAK/iTAK matters — at least one reference implementation deliberately serves a JSON body under `Content-Type: text/plain` specifically for one client, by explicit design choice (not a bug) | [COMPAT] |
| TC-ENROLL-08 | Certificate verification checks the full validity window (`notBefore`/`notAfter`), not just CA signature validity — a confirmed gap in at least one reference implementation would accept an expired-but-correctly-signed cert | [HARDEN] |
| TC-ENROLL-09 | Certificate verification cleanly rejects a syntactically-valid-but-signature-invalid client certificate with a typed error — it must not crash. (A confirmed real bug in one reference implementation used an invalid exception-matching construct that crashed instead of rejecting cleanly, at exactly the moment a cert legitimately failed verification.) | [HARDEN] |
| TC-ENROLL-10 | `uid` and the CSR's `common_name` are cross-validated against each other on enrollment/re-enrollment, rather than accepted as independent, uncorrelated client-supplied values — a confirmed gap in at least one reference implementation that also enables uid-spoofing (see TC-TLS-04) | [HARDEN] |

## 5. Marti REST API — Missions / DataSync

Real official-server error-status contracts for this area are undocumented by any authoritative public source found. Test cases marked [DESIGN] here are EdgeTAK's own contract, not verified compatibility targets.

| ID | Case | Type |
|---|---|---|
| TC-MARTI-01 | `PUT /Marti/api/missions/<name>` creates a mission; `GET` retrieves it; `DELETE` removes it | [COMPAT] (endpoint shape) |
| TC-MARTI-02 | Creating a mission with a name that already exists returns a clear, documented error (e.g. `409 Conflict`) — EdgeTAK's own contract | [DESIGN] |
| TC-MARTI-03 | Mission names containing URL-reserved characters (spaces, `%`, `/`) round-trip correctly through the REST path segment | [HARDEN] |
| TC-MARTI-04 | `PUT/DELETE /Marti/api/missions/<name>/subscription` correctly adds/removes a client's subscription and only that client's future fan-out changes | [COMPAT] |
| TC-MARTI-05 | `GET /Marti/api/missions/<name>/changes` returns an accurate change log/diff since a given point, not just current full state | [COMPAT] |
| TC-MARTI-06 | Concurrent edits to the same mission from two clients don't corrupt state or silently drop one edit — pick and document a concurrency policy | [DESIGN] |
| TC-MARTI-07 | `GET /Marti/api/sync/content?hash=<h>` — returned file's actual content hash matches the requested hash (a reference implementation does **not** verify this, trusting stored metadata blindly — an integrity gap worth deliberately avoiding) | [HARDEN] |
| TC-MARTI-08 | Data package upload + metadata-sidecar write is atomic (or safely resumable) — a crash mid-upload must not leave orphaned symlinks/partial files that later 500 or serve corrupt content | [HARDEN] |
| TC-MARTI-09 | `GET /Marti/api/clientEndPoints` reflects **actual** currently-connected clients, not a static/hardcoded stub (a confirmed real gap in at least one reference implementation) | [HARDEN] |
| TC-MARTI-10 | Requests to `/Marti/*` correctly require and validate the mTLS client cert per-request, avoiding the class of bug where a reverse-proxy fails to forward cert info to the app layer (a confirmed real deployment trap in more than one reference implementation) | [HARDEN] |
| TC-MARTI-11 | Mission-name sanitization (if any, e.g. HTML/script stripping) is applied **consistently** between the create path and every subsequent lookup/update path for that same mission — a confirmed real gap in one reference implementation, which sanitizes on create but looks up unsanitized, orphaning any mission whose name contains sanitizable characters | [HARDEN] |
| TC-MARTI-12 | Decide and test explicitly whether re-`PUT`ing an already-existing mission name is an update that merges in only provided fields (inheriting the rest from the existing record, with success returned either way — a confirmed reference behavior that gives callers no way to distinguish "created" from "updated into existing"), or something stricter | [DESIGN] |

## 6. Session / Routing / Fan-out

| ID | Case | Type |
|---|---|---|
| TC-ROUTE-01 | An ordinary (non-chat) CoT event from one connected client is broadcast to all other connected clients (baseline relay behavior) | [COMPAT] |
| TC-ROUTE-02 | An event whose `stale` has already elapsed by the time a **new** client connects is not replayed to that new client | [DESIGN] |
| TC-ROUTE-03 | On client disconnect, synthesize and broadcast a `t-x-d-d` CoT event (`how="h-g-i-g-o"`) announcing that uid's departure, rather than relying purely on `stale` expiry — no *base-spec* disconnect event type is documented anywhere, but at least one real deployed reference server actively does this, and EdgeTAK adopts the same convention | [COMPAT] |
| TC-ROUTE-04 | The server enforces a maximum persistable TTL, clamping an event's effective `stale` even if the event itself claims a longer one | [DESIGN] |
| TC-ROUTE-05 | Late-joining clients receive a snapshot of current (non-stale) persisted state at connect time, not just future live traffic | [COMPAT] |
| TC-ROUTE-06 | Access control / group-based filtering of fan-out (if implemented) is enforced consistently for **all** traffic types, not just chat — at least one reference implementation's group filtering is chat-only, leaving ordinary PLI/marker traffic completely unfiltered even when groups exist | [DESIGN] |
| TC-ROUTE-07 | Directed/private CoT messages (`<dest callsign="X"/>` or `<dest uid="X"/>`) are only delivered to a recipient the sender is actually authorized to message, if any access-control model is implemented at all — a confirmed gap in at least one reference implementation, which routes any directed CoT with no authorization check | [DESIGN] |

## 7. GeoChat

| ID | Case | Type |
|---|---|---|
| TC-CHAT-01 | A `t-x-c-t` (GeoChat) event addressed to a specific individual is delivered only to that recipient, not broadcast | [COMPAT] |
| TC-CHAT-02 | A team/group-addressed chat message is delivered to **all** members of that team — tested with **at least 3 simulated clients**, not 1-2, specifically because a real confirmed bug in a well-known TAK server implementation manifests as silent *partial* delivery (some recipients get it, others don't) rather than an outright failure | [COMPAT] |
| TC-CHAT-03 | Team-chat routing correctly parses and uses `chatgrp`'s `uid2` attribute and `__chat`'s `hierarchy` sub-tag — the exact fields a confirmed real bug traced to a missing model | [COMPAT] |
| TC-CHAT-04 | A destination client that hasn't yet self-identified does not silently swallow a chat addressed to it — either it's queued until identity arrives, or the sender gets a clear delivery-failure signal | [DESIGN] |
| TC-CHAT-05 | GeoChat events missing an expected-but-technically-optional sub-element (e.g. `<remarks>`) are handled gracefully — at least one real client is known to omit it | [COMPAT] |

## 8. Resource Limits & DoS Hardening

| ID | Case | Type |
|---|---|---|
| TC-LIMIT-01 | Maximum single CoT event size enforced (see also TC-COT-09) | [HARDEN] |
| TC-LIMIT-02 | Maximum concurrent connections enforced with a clear rejection (not resource exhaustion) past the limit | [HARDEN] |
| TC-LIMIT-03 | A client flooding events at high rate is rate-limited or backpressured rather than allowed to starve other clients' fan-out. At least one reference implementation has no per-connection rate limit or event-size cap anywhere in its CoT ingestion path. | [HARDEN] |
| TC-LIMIT-04 | Every rejection path (malformed input, auth failure, size limit, rate limit) produces a specific, logged, human-readable server-side reason — even where the wire protocol itself has no room for rich error detail in the response to the client | [HARDEN] |
| TC-LIMIT-05 | A failure in one part of per-event processing (e.g. malformed point data) does not silently cancel unrelated processing for the same event (e.g. a valid embedded GeoChat message riding the same CoT). A confirmed gap in at least one reference implementation, which runs all per-event processing steps as one unguarded sequential chain. | [HARDEN] |
| TC-LIMIT-06 | Structured detail sub-blocks with free-form attributes (e.g. CASEVAC-style medical evacuation requests) are validated/allowlisted before being persisted, not blindly passed through into a storage call — a confirmed gap in at least one reference implementation where one unexpected attribute name can crash processing of the entire event | [HARDEN] |
| TC-LIMIT-07 | Rejecting or skipping an event's position data (e.g. `(0,0)` coordinates, or an out-of-range sentinel value) does not leave orphaned related-table rows — a confirmed gap in at least one reference implementation | [HARDEN] |

## 9. Mesh Sync (island federation) — design-stage, tests speculative

This entire section is speculative and will change once Reticulum/LXMF prototyping happens (see [ARCHITECTURE.md](./ARCHITECTURE.md)) — these are the test cases implied by the current design direction, not a locked spec.

| ID | Case | Type |
|---|---|---|
| TC-MESH-01 | Two EdgeTAK instances with no direct connectivity, each holding independent CoT state, converge to the same merged state once a sync opportunity (any transport) becomes available | [DESIGN] |
| TC-MESH-02 | Conflicting updates to the same `uid` from two islands resolve deterministically via last-writer-wins-by-`time` | [DESIGN] |
| TC-MESH-03 | Sync payloads sent over a simulated low-bandwidth transport (throttled to ~1200bps, modeling AX.25) use TAK Protobuf encoding, not XML, and complete within a bounded time/byte budget for a representative batch of events | [DESIGN] |
| TC-MESH-04 | An island that has been disconnected for an extended period (hours) and reconnects successfully catches up without requiring a full state dump every time — incremental/delta sync, not full resync, once any state has previously been exchanged | [DESIGN] |
| TC-MESH-05 | High-frequency PLI (position) updates are batched/coalesced before being placed on a mesh-sync payload, rather than forwarded 1:1 at native ATAK update rates — needs a concrete coalescing policy once real throughput numbers are available (currently unmeasured) | [DESIGN], pending measurement |
| TC-MESH-06 | Reticulum/LXMF integration (whichever form it takes) survives the sidecar/dependency being temporarily unavailable without crashing the local (non-mesh) CoT relay functionality — mesh sync is additive, not a single point of failure for local operation | [DESIGN] |

## 10. Configuration

| ID | Case | Type |
|---|---|---|
| TC-CFG-01 | Invalid config values that are cheap to check (out-of-range ports, non-integer TTLs) are rejected at startup, not deferred to first use | [DESIGN] |
| TC-CFG-02 | A config-referenced file that doesn't exist (TLS cert/key path) produces a clear fatal startup error, not a silent skip or a confusing later failure | [DESIGN] |
| TC-CFG-03 | No hardcoded, widely-known default secret ships in EdgeTAK's default config — at least one reference implementation's default PKCS12 export password is a literal, widely-known-in-community string. EdgeTAK should generate a random one or refuse to start without an explicit one set. | [HARDEN] |
| TC-CFG-04 | No secret (passwords, private key material) is ever logged, at any log level — motivated by a real, confirmed bug in a reference implementation that logged plaintext passwords at WARNING level on every login | [HARDEN] |

## 11. WebSocket / live-update payloads (deferred, not in current scope)

If EdgeTAK ever implements Socket.IO/WebSocket-compatible live updates for browser-based clients, the following event names/payload/gating conventions are confirmed from a real deployed reference server and worth matching for client compatibility: `"point"` (gated on the CoT having a `<takv>`, `<__video>`, or `<contact>` element — a bare position update with none of these never reaches a live map), `"alert"`, `"casevac"`, `"marker"` (gated on CoT `type` matching known atom/marker prefixes), `"rb_line"`, and `"eud"` (emitted specifically on the `t-x-d-d` disconnect convention from TC-ROUTE-03). All confirmed emitted under a **named** Socket.IO namespace, not the default root namespace.

## 12. Device Registry (new module, not part of the original catalog)

Added alongside the enrollment endpoint (§4) — tracks enrolled devices by certificate Common Name, implements TC-TLS-04's binding policy, and tracks revocation. Not part of the original research-derived catalog above (there's no external reference implementation to compare against here — this is EdgeTAK's own design), so tracked with plain descriptions rather than TC-IDs.

**Implemented** (`src/registry.rs`), each with a passing unit test: enroll and find a device; re-enrollment (cert rotation) preserves an existing `uid` binding; re-enrollment preserves an existing revocation (does **not** silently un-revoke — a real bug caught by the mTLS integration tests during development, see TC-TLS-05 above); bind a `uid` on first use; idempotent re-assertion of an already-owned `uid`; reject binding a `uid` already owned by a different device; reject a device rebinding to a *different* `uid` than the one it already owns; revoke a device; revoking an unknown device errors; the registry persists across a reload from its JSON file; loading a nonexistent path starts empty rather than erroring.

**Not yet implemented**: an explicit `unrevoke` action (revocation is currently one-way); any capacity/pagination concerns (irrelevant at this project's target scale, see `docs/ARCHITECTURE.md`).

## Pending research

- MeshCore throughput figures — needed to finalize TC-MESH-03/05's concrete bandwidth budget.
- Native Rust Reticulum (RNS) crate maturity/interoperability — needs hands-on verification before TC-MESH-06 can specify which integration path to actually build against.
