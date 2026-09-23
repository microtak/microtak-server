# syntax=docker/dockerfile:1

# ---- Build stage --------------------------------------------------------
FROM rust:1-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from source changes: build a
# throwaway binary against just the manifest first, so `cargo build` only
# recompiles microtak-server's own code (not its whole dependency tree) on a
# source-only change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --bin microtakd

# ---- Runtime stage --------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# rsync/openssh-client cover the two most common `backup_offsite_command`
# targets (rsync-over-ssh, scp) out of the box -- see src/backup.rs. Heavier
# tools (awscli for S3) are deliberately left out of the default image,
# consistent with this project's lightweight-footprint goal; build a custom
# image on top of this one if S3 offsite backup is needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    rsync \
    openssh-client \
    tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/microtak-server --uid 10001 --shell /usr/sbin/nologin microtak

COPY --from=builder /build/target/release/microtakd /usr/local/bin/microtakd

WORKDIR /var/lib/microtak-server
# data_dir/backup_dir default to relative paths ("./data", "./backup"),
# resolved against this working directory -- so they land here, under the
# two volumes below, without needing a microtak.toml at all.
RUN mkdir -p data backup && chown -R microtak:microtak /var/lib/microtak-server

ENV MICROTAK_CONFIG=/etc/microtak/microtak.toml
VOLUME ["/var/lib/microtak-server/data", "/var/lib/microtak-server/backup"]

# enrollment (plain HTTP), marti_api (mTLS), plain_tcp (unauthenticated CoT),
# mtls (mTLS CoT) -- see src/app.rs::AppConfig::default.
EXPOSE 8446 8443 8087 8089

USER microtak
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/microtakd"]
