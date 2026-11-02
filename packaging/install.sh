#!/bin/sh
# Install microtakd from the GitHub release binaries as a systemd service, with
# a daily timer that keeps it on the latest release. For a plain Debian-family
# host -- Raspberry Pi OS Lite (32- or 64-bit), Debian, Ubuntu.
#
#   curl -fsSLO https://raw.githubusercontent.com/microtak/microtak-server/main/packaging/install.sh
#   sudo sh install.sh                        # install the latest release
#   sudo sh install.sh --from-file ./microtakd  # install a local build instead
#
# Re-running it is safe: it never overwrites an existing config. It installs
# itself as /usr/local/sbin/microtak-update, which the timer runs as
# `microtak-update update`: download the newest release if it differs from the
# installed one, verify its checksum, swap the binary, restart, and roll back
# to the previous binary if the service doesn't come back up.
#
# Layout (docs/PACKAGING.md): binary /usr/local/bin/microtakd, config
# /etc/microtak/microtak.toml, state /var/lib/microtak-server (data/ and
# backup/ below it), system user `microtak`.
set -eu

REPO=microtak/microtak-server
BIN=/usr/local/bin/microtakd
SELF=/usr/local/sbin/microtak-update
CONF=/etc/microtak/microtak.toml
STATE=/var/lib/microtak-server
RELEASE_FILE=/usr/local/share/microtak/installed-release
UNIT_DIR=/etc/systemd/system

die() { echo "microtak: $*" >&2; exit 1; }
log() { echo "microtak: $*"; }

# Which release asset runs here. 32-bit Raspberry Pi OS on a 64-bit Pi runs an
# aarch64 kernel with an armhf userland, so ask dpkg before trusting uname.
target() {
	arch=$(dpkg --print-architecture 2>/dev/null || true)
	case "$arch" in
	amd64) echo x86_64-unknown-linux-gnu; return ;;
	arm64) echo aarch64-unknown-linux-gnu; return ;;
	armhf) echo armv7-unknown-linux-musleabihf; return ;;
	esac
	case "$(uname -m)" in
	x86_64) echo x86_64-unknown-linux-gnu ;;
	aarch64 | arm64) echo aarch64-unknown-linux-gnu ;;
	armv7l | armv8l) echo armv7-unknown-linux-musleabihf ;;
	*) die "no release binary for $(uname -m) (ARMv6 boards like the Pi Zero/1 aren't supported)" ;;
	esac
}

latest_tag() {
	curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

installed_tag() { cat "$RELEASE_FILE" 2>/dev/null || true; }

# Download and verify the release archive for $1 (tag); leaves the binary at
# $tmp/microtakd.
fetch() {
	asset="microtakd-$(target).tar.gz"
	base="https://github.com/$REPO/releases/download/$1"
	log "downloading $asset ($1)"
	curl -fsSL -o "$tmp/$asset" "$base/$asset" || die "download failed: $base/$asset"
	curl -fsSL -o "$tmp/$asset.sha256" "$base/$asset.sha256" || die "no checksum for $asset in $1"
	(cd "$tmp" && sha256sum -c --quiet "$asset.sha256") || die "checksum mismatch for $asset"
	tar xzf "$tmp/$asset" -C "$tmp" microtakd
}

# Put $1 in place as the binary, keeping the old one as $BIN.prev.
swap_in() {
	install -m 0755 "$1" "$BIN.new"
	[ -e "$BIN" ] && cp -p "$BIN" "$BIN.prev"
	mv -f "$BIN.new" "$BIN"
}

write_units() {
	cat >"$UNIT_DIR/microtak-server.service" <<EOF
[Unit]
Description=MicroTAK server
Documentation=https://github.com/$REPO
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=microtak
Group=microtak
Environment=MICROTAK_CONFIG=$CONF
ExecStart=$BIN
WorkingDirectory=$STATE
StateDirectory=microtak-server
StateDirectoryMode=0750
Restart=on-failure
RestartSec=5
LimitNOFILE=4096
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

	cat >"$UNIT_DIR/microtak-update.service" <<EOF
[Unit]
Description=Update microtakd to the latest MicroTAK release
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SELF update
EOF

	cat >"$UNIT_DIR/microtak-update.timer" <<EOF
[Unit]
Description=Daily MicroTAK release check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

write_config() {
	[ -e "$CONF" ] && { log "keeping existing $CONF"; return; }
	host=$(hostname)
	mkdir -p "$(dirname "$CONF")"
	cat >"$CONF" <<EOF
# MicroTAK server config -- all keys in the README. Restart after editing:
#   sudo systemctl restart microtak-server
# Names clients use to reach this server; they go into the server cert (the
# live interface IPs are added automatically).
server_common_name = "$host.local"
server_names = ["$host.local", "$host"]
admin_common_name = "admin"
EOF
	chmod 0644 "$CONF"
	log "wrote $CONF"
}

cmd_install() {
	from_file=
	if [ "${1:-}" = "--from-file" ]; then
		from_file=${2:-}
		[ -f "$from_file" ] || die "--from-file needs a path to a microtakd binary"
	fi

	for tool in curl tar sha256sum systemctl; do
		command -v "$tool" >/dev/null || die "$tool is required"
	done

	id microtak >/dev/null 2>&1 ||
		useradd --system --home-dir "$STATE" --no-create-home \
			--shell /usr/sbin/nologin microtak

	if [ -n "$from_file" ]; then
		swap_in "$from_file"
		tag=local
	else
		tag=$(latest_tag)
		[ -n "$tag" ] || die "couldn't read the latest release tag"
		fetch "$tag"
		swap_in "$tmp/microtakd"
	fi
	mkdir -p "$(dirname "$RELEASE_FILE")"
	echo "$tag" >"$RELEASE_FILE"

	if [ "$(realpath "$0")" != "$SELF" ]; then
		install -m 0755 "$0" "$SELF"
	fi
	write_config
	write_units
	systemctl daemon-reload
	systemctl enable --now microtak-update.timer
	systemctl enable microtak-server.service
	systemctl restart microtak-server.service
	rm -f "$BIN.prev"

	log "installed $tag ($(target)); auto-update: microtak-update.timer"
	log "first start writes the admin bootstrap token to $STATE/data/bootstrap-token"
	log "ports: 8446 enrollment, 8443 Marti API, 8089 CoT (mTLS)"
}

cmd_update() {
	tag=$(latest_tag)
	[ -n "$tag" ] || die "couldn't read the latest release tag"
	current=$(installed_tag)
	if [ "$tag" = "$current" ]; then
		log "already on $tag"
		return
	fi
	log "updating ${current:-unknown} -> $tag"
	fetch "$tag"
	swap_in "$tmp/microtakd"

	systemctl restart microtak-server.service || true
	sleep 10
	if systemctl is-active --quiet microtak-server.service; then
		echo "$tag" >"$RELEASE_FILE"
		rm -f "$BIN.prev"
		log "now on $tag"
	else
		log "$tag didn't start, rolling back to ${current:-the previous binary}"
		[ -e "$BIN.prev" ] && mv -f "$BIN.prev" "$BIN"
		systemctl restart microtak-server.service || true
		die "update to $tag failed (journalctl -u microtak-server)"
	fi
}

[ "$(id -u)" -eq 0 ] || die "run as root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

case "${1:-install}" in
# dash aborts the script on `shift` with no arguments, even behind `|| true`.
install)
	[ $# -eq 0 ] || shift
	cmd_install "$@"
	;;
--from-file) cmd_install "$@" ;;
update) cmd_update ;;
*) die "usage: $0 [install [--from-file PATH] | update]" ;;
esac
