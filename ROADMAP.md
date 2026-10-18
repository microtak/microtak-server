# Roadmap

MicroTAK's first rule is compatibility with the official TAK Server and its
clients: every API follows the official server's source, currently
**TAK Server 5.7-RELEASE-14** (`TAK-Product-Center/Server` @ `5187abd`,
2026-04-03). Anything not listed as done below either isn't implemented
yet or answers as the official server would without the feature.

This file lists direction, not dates.

## Done

- TAK Protocol (streaming protobuf) on the TLS port, negotiated as on the
  official default input; messages over 64 KiB become file transfers to
  `/Marti/api/cot/xml/{uid}`.
- CoT over TLS (mTLS) and an optional plain-TCP relay; ping/pong, GeoChat,
  direct messages, `<marti><dest>` routing, groups ("channels").
- Certificate enrollment (`/Marti/api/tls`), OAuth login for CloudTAK,
  locked-down enrollment (bootstrap token, invite tokens, password
  accounts), revocation, the official URL authorization table.
- Enterprise Sync: the official servlets (`/Marti/sync/*`), `MetadataApi`,
  `FileManagerApi` (list, get, HEAD, metadata, delete, count).
- The official Mission API: roles and mission tokens, password-protected
  and invite-only missions, change notifications on the CoT stream,
  layers, logs, invitations, subscriptions, contacts, mission packages
  (export and import of plain data packages), streamed mission content,
  `pagedmissions` / `missioncount`, external mission data, map layers,
  mission copy and send, offline change sets (`changes.json`) on package
  import.
- `/Marti/api/contacts/all`, `/Marti/api/subscriptions/all`,
  `/Marti/api/security/isSecure`.
- The latest situational awareness of every reachable client, sent to a
  client right after it connects (`latestSA`, on by default as
  officially), on mTLS and plain TCP.
- Persistence and backups, Docker images and Helm chart (amd64 and arm64),
  release binaries.
- CI: unit, end-to-end and black-box suites (the black-box suite drives the
  real Docker image over the network), `cargo fmt`, clippy, coverage,
  OSV-Scanner.

## Next: the rest of the official Mission API

- Mission KML (`/missions/{name}/kml`): the official server's KML builder,
  icon styles and HAE-to-MSL conversion (geoid data).
- Mission feeds, together with the data feed API they depend on
  (`/Marti/api/datafeeds`).

Not planned: the official server's own configuration endpoints
(`/Marti/api/config`, `security/config`, `authentication/config`). They
describe its JKS stores, LDAP and CoreConfig, which MicroTAK doesn't have.
All three are admin-only on the official server too.

## Then

- Device profiles and the WebSocket API web clients use.
- Load testing: a simulator that keeps a configurable number of TAK
  clients (100 by default) connected and active against a deployment, to
  see how MicroTAK holds up under constant use.

## Later

- Federation between MicroTAK instances over low-bandwidth or intermittent
  links (LoRa mesh, Reticulum/LXMF, satellite, packet radio) for "island"
  deployments that resync when a link comes back: `microtak-sync`, starting
  with a design document. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- `microtak-node`, an embedded client for small devices.
- Radio bridges (MeshCore, APRS) as separate connectors.

## Contributing

Pick anything above; please follow the official server's behavior (cite the
source file you followed) and add tests. See [README.md](README.md).
