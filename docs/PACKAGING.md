# MicroTAK Packaging Plan

**Status: plan, not yet executed** — this document lays out how to get `microtak-server`, `microtak-admin-cli`, and (once built) `microtak-admin-web` installable via `apt`, Nix, and the AUR, in addition to the Docker image + Helm chart that already exist. Written 2026-09-23; treat line items as a checklist to work through, not a finished state.

## What exists today

- `microtak-server`: Docker image (`ghcr.io/microtak/microtak-server`), a Helm chart (`charts/microtak-server`), source-only (no standalone binary release).
- `microtak-admin-cli`: source-only plus one pre-built Linux x86_64 binary attached to each GitHub Release.
- `microtak-admin-web`: in progress, not yet released.
- Both existing repos already have `release-please`-driven semantic versioning and real GitHub Releases — every packaging path below builds on that, not a separate versioning scheme.

## Why this needs real groundwork first, not just a PKGBUILD

`apt` and the AUR both fundamentally build from source (Debian's infra compiles `.deb`s itself; a typical AUR `PKGBUILD` runs `cargo build --release` against a fetched source tarball) — they don't just wrap a Docker image. That means, before any of the three ecosystems below can meaningfully package `microtak-server` as a proper system service, it needs the groundwork a real system daemon package expects and doesn't have yet:

- A **systemd unit file** (`microtak-server.service`) with sensible restart/hardening settings.
- A **dedicated system user** (matching the Docker image's own non-root `microtak` user, uid, and `/var/lib/microtak-server` layout) and a packaging-side postinstall step to create it.
- A **packaged default config** (`/etc/microtak/microtak.toml`) and documented `MICROTAK_CONFIG` env var override, matching what the Docker image and Helm chart already assume.
- **Standalone release binaries** for `microtak-server` itself (currently Docker-only) — `microtak-admin-cli` already has this pattern (`.github/workflows/publish-binaries.yml`); `microtak-server` needs the same.

None of the three packaging targets below are meaningfully startable until this exists, so it's Phase 0, not optional polish.

## Phase 0 — shared groundwork (do this first, in `microtak-server`)

1. Add `packaging/systemd/microtak-server.service` (a real, testable unit — `Type=simple`, `User=microtak`, `Restart=on-failure`, `ProtectSystem=strict`/`ProtectHome=true` and similar hardening directives, `ReadWritePaths=/var/lib/microtak-server`).
2. Add `packaging/microtak.toml.example` — the same shape the Helm chart's ConfigMap already renders, as a real starting file for a bare-metal install.
3. Add a `publish-binaries.yml` workflow to `microtak-server` mirroring `microtak-admin-cli`'s own (x86_64-linux to start), chained the same way from `release-please.yml`.
4. Decide and document the on-disk layout once, so every packaging format agrees: binary at `/usr/bin/microtakd`, config at `/etc/microtak/microtak.toml`, data at `/var/lib/microtak-server` (already the Docker image's own path — reuse it, don't invent a second convention), running as system user `microtak`.

## Phase 1 — self-serve installability (low effort, no external gatekeepers)

These don't require anyone else's approval and can ship as soon as Phase 0 lands.

### Nix (flakes) — done, 2026-09-23

Added `flake.nix` to both `microtak-server` and `microtak-admin-cli`, built with `crane` + `rust-overlay` — `nix run github:microtak/microtak-server` and `nix run github:microtak/microtak-admin-cli` work with no PR review needed. `microtak-server` also exposes `nixosModules.default`, wrapping a real `systemd.services.microtak-server` unit behind `services.microtak-server.enable`/`.configFile` options — the idiomatic way a NixOS user actually wants to run a server daemon, not just a plain package.

Both flakes' outputs (`packages`, `apps`, `checks`) are defined for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, and `aarch64-darwin` — pulled forward from the Phase 3 "multi-arch" item below, since with Nix this is nearly free: each system builds *natively* on its own architecture (a Mac builds the `aarch64-darwin` output locally; an ARM board running NixOS, e.g. a Pi Zero 2 W, builds `aarch64-linux` locally), not through cross-compilation from x86_64 CI. `nix build`/`nix flake check` were run for real (not just written on faith) against `x86_64-linux` in development, including running the full test suite and clippy as flake checks (`checks.test`, `checks.clippy`), matching the CI pipeline's own gate. The `aarch64-linux`/`darwin` outputs are structurally identical and use the same cross-platform-safe dependency set (`rustls`, no `openssl-sys`) but haven't been built on real ARM/Apple hardware yet — flag that as the one remaining gap before calling multi-arch Nix support fully verified.

Actual `nixpkgs` inclusion (a PR to `NixOS/nixpkgs` adding `pkgs/by-name/mi/microtak-server/package.nix`) is a separate, slower, community-reviewed step — worth doing eventually for discoverability (`nix-env -iA nixpkgs.microtak-server`), but the flake alone already gets Nix users a working install path without waiting on that.

### GitHub Releases as a stopgap "package manager"

Already partly done for `microtak-admin-cli`. Extend to `microtak-server` (Phase 0, item 3). This isn't a real package manager, but it's the immediate, zero-infrastructure fallback every other path builds on top of (both `apt` and AUR packaging below literally point at these release tarballs as their source).

## Phase 2 — real distro-level packages

### `.deb` / apt

1. Add [`cargo-deb`](https://github.com/kornelski/cargo-deb) metadata (`[package.metadata.deb]` in `Cargo.toml`) to `microtak-server` and `microtak-admin-cli` — it builds a real `.deb` directly from Cargo project metadata, including the systemd unit and postinst script from Phase 0, with no separate packaging-repo maintenance burden.
2. Add a CI job (chained the same way as Docker/binary publishing) that runs `cargo deb` on release and attaches the `.deb` to the GitHub Release — this alone lets anyone `dpkg -i` a downloaded file, no repository needed yet.
3. **Real `apt install` support** (`sudo apt install microtak-server`) needs a hosted, signed apt repository — realistically a self-hosted one first (a GPG-signed repo built with `aptly` or `reprepro`, served as static files from GitHub Pages or a small VPS, with a one-line `curl | apt-key add` + `add-apt-repository` setup step in the README), *not* waiting on Debian/Ubuntu's own archive. Actual inclusion in the official Debian/Ubuntu archives is a much longer, bureaucratic process (an ITP bug, a sponsor, full Debian Policy compliance) — worth pursuing only once the project has enough real users to justify the overhead; track as a Phase 3 stretch goal, not a near-term target.

### AUR (Arch Linux)

1. Requires an AUR account (`aur.archlinux.org`) and an SSH key registered with it.
2. Each AUR package is its own tiny git repo with a `PKGBUILD` + `.SRCINFO`. Write two: `microtak-server` and `microtak-admin-cli` (a `-bin` variant per package, e.g. `microtak-server-bin`, is also common practice on AUR for projects that also want a prebuilt-binary-only variant alongside the build-from-source one — optional, not required for v1).
3. `PKGBUILD` for each: `source=("https://github.com/microtak/<repo>/archive/refs/tags/v${pkgver}.tar.gz")`, `build()` runs `cargo build --release --locked`, `package()` installs the binary, the systemd unit, and the license file to the standard Arch paths.
4. Push each `PKGBUILD` to its AUR git repo on every release (can be scripted/automated via CI once the pattern is proven manually once or twice first).

## Phase 3 — longer-term, bigger lift, pursue only if there's real demand

- Actual `nixpkgs` inclusion (upstream PR).
- Actual Debian/Ubuntu official archive inclusion (ITP process).
- Multi-arch **release binaries and Docker images** (`aarch64-unknown-linux-gnu` for Raspberry Pi — directly relevant given this project's own measured Pi Zero resource-requirements research in this same doc — plus macOS targets) via `cross` in CI, feeding the GitHub Releases / `.deb` / AUR paths with more than just x86_64-linux artifacts. Nix users already get native ARM/Apple Silicon builds today (see the Nix section above) — this item is specifically about the *non-Nix* packaging paths catching up.
- A Homebrew tap for macOS users, the natural sibling to AUR/apt for that platform (not explicitly requested, but cheap once cross-compiled macOS binaries exist).

## What this deliberately does *not* attempt

- One unified "MicroTAK ecosystem version" — `microtak-server`, `microtak-admin-cli`, and `microtak-admin-web` each version independently via their own `release-please` pipeline, same as any other multi-repo ecosystem (Kubernetes' own `kubectl`/`kubeadm`/`kubelet` version independently too). Packaging metadata for each tracks its own repo's tags, not a shared number.
- Packaging `microtak-admin-web` is deliberately left out of this plan until it actually exists and its own deployment shape (likely another systemd service, or container-only) is settled.
