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

- Real-time CoT relay over plain TCP and mutual-TLS, so ATAK/iTAK/WinTAK
  clients see each other's positions and markers live.
- Certificate-based device enrollment — a client requests a cert, the server
  signs it with its own CA, done. Enrollment is **secure by default**: once
  you've enrolled your own admin device, the server automatically locks
  further enrollment behind one-time invite tokens. See "Enrollment &
  access control" below.
- Missions (Data Sync) — shared folders of markers and files that sync
  across devices, with Owner/Subscriber permissions so not everyone can
  delete or rewrite someone else's mission.
- Everything persists to disk and survives a restart, with optional
  periodic backups (local or offsite via a command you control, e.g.
  `rsync`).

## Enrollment & access control

By default (`enrollment_mode = "auto"`), a brand-new MicroTAK server accepts
any enrollment — there's no admin yet, so there's nothing to protect. The
moment your configured admin device (`admin_common_name` in the config)
actually enrolls, the server locks down live, no restart required: from then
on, new devices need a one-time invite token to enroll. Mint, list, and
revoke those tokens through the mTLS-authenticated admin API, or more
conveniently with the companion CLI,
[microtak-admin-cli](https://github.com/microtak/microtak-admin-cli), which
also prints enrollment QR codes for handing a device its token.

If you'd rather manage access some other way (e.g. a firewall/VPN
perimeter), set `enrollment_mode = "open"` to disable the lockdown
permanently — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
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
| 8446 | Certificate enrollment (plain HTTP) |
| 8443 | Marti API — missions, admin (mTLS) |
| 8087 | CoT relay (plain TCP) |
| 8089 | CoT relay (mTLS) |

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
