# MicroTAK

A lightweight TAK (Team Awareness Kit) server, written in Rust, for running
your own ATAK/iTAK/WinTAK infrastructure on modest hardware — a Raspberry Pi,
a small VPS, a laptop in a go-bag.

MicroTAK speaks the same protocols as the official TAK Server (CoT over
TLS/TCP, certificate enrollment, the Marti mission/Data Sync API), so
existing ATAK, iTAK, and WinTAK clients connect to it without modification.
It's a from-scratch implementation, not a fork — built after studying the
official TAK Server, [taky](https://github.com/tkuester/taky), and
[OpenTAKServer](https://github.com/brian7704/OpenTAKServer) for protocol
compatibility and to avoid their known rough edges.

The longer-term goal is federation between MicroTAK instances over
low-bandwidth or intermittent links (LoRa mesh, Reticulum/LXMF, satellite,
packet radio) for "island" deployments that lose connectivity to each other
and need to resync once a link comes back. That part isn't built yet — see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for what's running today versus
still on the drawing board.

## What it does today

- Real-time CoT relay over mutual-TLS, so ATAK/iTAK/WinTAK clients see each
  other's positions and markers live (plus an opt-in plain-TCP relay for
  trusted local bridges).
- Certificate-based device enrollment — a client requests a cert, the server
  signs it with its own CA, done. Enrollment is **secure by default**: locked
  from the first start, with the admin device enrolling via a one-time
  bootstrap token and every other device via an invite token or a password
  account. See "Enrollment & access control" below.
- Missions (Data Sync) — shared folders of markers and files that sync
  across devices, with Owner/Subscriber permissions so not everyone can
  delete or rewrite someone else's mission.
- Everything persists to disk and survives a restart, with optional
  periodic backups (local or offsite via a command you control, e.g.
  `rsync`).

## Enrollment & access control

By default (`enrollment_mode = "auto"`), enrollment is **locked from the
very first start**. On first start the server writes a one-time
**bootstrap token** to `data_dir/bootstrap-token` (readable by the server's
own user only) and logs where it is. Enroll your admin device — the Common
Name configured as `admin_common_name`, `"admin"` by default — with that
token:

```sh
# Docker: read the token and the CA certificate from the data volume
docker compose exec microtak-server cat data/bootstrap-token
docker compose exec microtak-server cat data/ca-cert.pem > ca.pem

microtak-admin-cli enroll --enrollment-url https://<server>:8446 --ca ca.pem \
  --cn admin --token <bootstrap token>
```

The token works once, only for the admin identity, and the file is deleted
after use. Invite tokens can be bound to one device name (`commonName` when
minting; the CLI's `token mint --cn`), which is what an enrollment QR code
for that device carries: TAK clients scanning
`tak://com.atakmap.app/enroll?host=…&username=…&token=…` enroll over HTTPS
presenting the token as the password for that username. From then on, new devices need a one-time invite token (or a
password account, below) minted by the admin through the mTLS-authenticated
admin API, or more conveniently with the companion CLI,
[microtak-admin-cli](https://github.com/microtak/microtak-admin-cli), which
also prints enrollment QR codes for handing a device its token.

Identity rules, enforced in every mode:

- The admin identity can only ever be enrolled with the bootstrap token.
- An invite token (or `Open` mode) can only create a **new** identity — it
  can never re-enroll a device that already exists. Re-enrolling (rotating)
  an existing identity requires that identity's own password account.
- Issued client certificates always carry a fixed profile (client-auth
  only, never a CA, no alternative names), whatever the device's CSR asks
  for.
- Repeated failed password/token attempts are rate-limited (HTTP 429).

If you'd rather manage access some other way (e.g. a firewall/VPN
perimeter), set `enrollment_mode = "open"` to let any *new* identity
enroll without a token (the identity rules above still apply) — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
reasoning behind the two modes.

For clients that expect real TAK-Server-style username/password login
(e.g. [CloudTAK](https://github.com/dfpc-coe/CloudTAK)) rather than a bare
invite token, mint a password account the same way — `POST
/Marti/api/admin/users` (or the CLI's `user mint` command) — and that
account can log in via `POST /oauth/token` and self-enroll a device cert
via `Authorization: Basic` on the enrollment endpoint, bypassing the
invite-token gate entirely.

## System requirements

MicroTAK is deliberately lightweight — it's built to run on the kind of
hardware other TAK servers can't touch.

- **CPU / RAM**: 1 vCPU and 256MB RAM is comfortable for 100 connected
  clients with real headroom to spare, per actual load testing (not just
  estimation) — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
  numbers. Idle memory use is under 10MB. A Raspberry Pi Zero 2 W should
  handle 100+ clients; the original single-core Pi Zero is good for roughly
  15–60 depending on how chatty your clients are (that estimate hasn't been
  verified on real hardware yet — see the same doc for caveats).
- **Disk**: minimal. State (CA, device registry, missions, uploaded mission
  content) is stored under `data_dir`; size scales with how much mission
  content you upload, not with client count. Add extra headroom if you
  enable periodic backups.
- **OS / architecture**: Linux, x86_64. The Docker image and prebuilt
  release binaries currently target `x86_64-linux` (glibc). ARM builds (for
  a Pi) aren't packaged yet — see
  [docs/PACKAGING.md](docs/PACKAGING.md) — so an ARM device today means
  building from source with a stable Rust toolchain (edition 2024).
- **Network**: MicroTAK needs four ports reachable by your clients (see the
  table below) — no other services or databases required. It has no
  external runtime dependencies beyond what's in the Docker image.

## Running it

The quickest way to try MicroTAK is Docker:

```sh
docker compose up
```

This builds the image and exposes the four ports MicroTAK listens on:

| Port | Purpose |
|------|---------|
| 8446 | Certificate enrollment + OAuth login (**HTTPS only**, no client cert) |
| 8443 | Marti API — missions, admin (mTLS) |
| 8087 | CoT relay (plain TCP) — **off by default**, see below |
| 8089 | CoT relay (mTLS) |

MicroTAK serves **no plain HTTP**. The enrollment port presents a
certificate from MicroTAK's own CA by default — nothing to set up, works
fully offline, and TAK clients trust it on first contact (OmniTAK does by
default) and then pin the CA they receive during enrollment, so nothing has
to be installed on devices. See "TLS certificates" below for naming the
server's addresses, using Let's Encrypt, and running behind a reverse proxy.

The plain-TCP relay on 8087 is unauthenticated and unencrypted — anyone who
can reach it can read every position and inject events — so it only runs
with `plain_tcp_enabled = true`. Enable it only for a trusted local bridge
(e.g. an APRS or mesh gateway on the same host).

Data and backups live in Docker volumes so they survive container restarts.
To customize settings, drop a `microtak.toml` next to `docker-compose.yml`
and uncomment the volume mount for it.

Deploying alongside other services on a shared host? Host-side ports are
overridable via a `.env` file (copy `.env.example`), and
`docker-compose.proxy.yml` is an optional overlay that fronts the
certificate-enrollment endpoint with an existing Traefik reverse proxy for a
real TLS certificate (e.g. via Let's Encrypt) instead of raw HTTP:

```sh
cp .env.example .env   # fill in your real domain/ports; .env is gitignored
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d
```

The Marti API and both CoT relay ports are deliberately left out of that
overlay — they do their own TLS (and, for the mTLS ones, client-cert
authentication) at the application layer, so they're published directly to
the host rather than routed through a reverse proxy that would just add a
redundant (or actively broken) second TLS layer in front.

A [Helm chart](charts/microtak-server) is also available for Kubernetes
deployments. See [docs/PACKAGING.md](docs/PACKAGING.md) for the plan to add
apt, Nix, and AUR packages on top of these.

### Groups ("channels")

MicroTAK mirrors the official TAK Server's groups. An identity (a device's
certificate name) is a member of groups with a direction: **IN** — it may
send into the group — and/or **OUT** — it receives from the group. A
message reaches a device only if the sender's active IN groups and the
device's active OUT groups share a group. An identity without groups is in
`__ANON__` both ways, so a server without groups behaves as before:
everyone sees everyone.

- The admin creates groups and sets memberships
  (`/Marti/api/admin/groups…`, or `microtak-admin-cli group …`).
- Invite tokens and password accounts can carry groups (`groups` for both
  directions, `groupsIn`, `groupsOut`), applied when the device enrolls — so
  a QR code can put a phone straight into its team.
- Devices switch their groups on and off themselves (ATAK's channel
  selector: `GET /Marti/api/groups/all`, `PUT /Marti/api/groups/active` /
  `activebits`), effective immediately.
- Missions are visible only within their groups (default: the creator's),
  and support the official read-only subscriber role
  (`defaultRole: "MISSION_READONLY_SUBSCRIBER"`).

### TLS certificates

- **Server names**: the server certificate names `server_common_name`
  (`microtak-server`) plus every non-loopback address of the host's network
  interfaces — LAN, Wi-Fi, Starlink, … — re-checked every minute and
  re-issued live when addresses come and go (`server_names_from_interfaces`,
  on by default). Add DNS names, or the host's addresses when MicroTAK runs
  in a container on a bridge network (where it only sees its own container
  address), with `server_names = ["192.168.1.10", "tak.example.com"]`.
  Enrolled devices pin MicroTAK's CA, not a particular server certificate,
  so re-issuing never affects them.
- **Let's Encrypt** (server has internet and a DNS name): point
  `enrollment_cert_file` / `enrollment_key_file` at the PEM files your ACME
  client (certbot, lego, …) maintains. They're re-read automatically after
  renewal; a broken renewal is logged and the previous certificate keeps
  serving. MicroTAK has no built-in ACME client on purpose — the ACME
  challenges need plain HTTP on port 80 or port 443. The mTLS ports (8443,
  8089) always use MicroTAK's own CA.
- **Reverse proxy** (Traefik, Pangolin): see
  [docs/proxy/README.md](docs/proxy/README.md) — the proxy re-encrypts to
  MicroTAK (never plain HTTP to the backend), the mTLS ports stay TCP
  passthrough, and `trusted_proxies` keeps rate limiting per real client.

### Building from source

```sh
cargo build --release
cargo run --release --bin microtakd
```

Config is optional — MicroTAK reads `$MICROTAK_CONFIG`, or `./microtak.toml`
if that's unset, and falls back to sensible defaults if neither exists.

`scripts/build.sh` runs the same build/test/clippy steps CI does (add
`--nix` for `nix flake check`, `--docker` to build the image locally); see
`scripts/build.sh --help`.

## The MicroTAK ecosystem

- **microtak-server** (this repo) — the server itself.
- [microtak-admin-cli](https://github.com/microtak/microtak-admin-cli) — a
  command-line tool for enrolling devices, minting/managing invite tokens,
  and managing mission roles, with terminal QR codes for handoff.
- microtak-admin-web — a web-based admin UI, in progress.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design decisions, protocol
  notes, and how MicroTAK relates to existing TAK servers.
- [docs/TEST-PLAN.md](docs/TEST-PLAN.md) — the test-case catalog every
  feature is expected to satisfy before being considered done.
- [docs/PACKAGING.md](docs/PACKAGING.md) — the plan for making the whole
  ecosystem installable via apt, Nix, and the AUR.

## Contributing

Every feature is expected to come with tests before it's considered done —
see the test plan for what "tested" means for a given area.

```sh
cargo test               # unit + module-level integration tests
cargo test --test e2e    # end-to-end suite against a fully assembled server
```

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE). Chosen so that anyone running a
modified version of this server as a network service, not just distributing
a binary, has to share their modifications too. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the reasoning.
