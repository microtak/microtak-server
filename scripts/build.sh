#!/usr/bin/env bash
# Local build + test, mirroring .github/workflows/ci.yml.
#
# With no options, runs everything CI runs (minus the Docker image build,
# which is opt-in via --docker since it's slow and most edits don't touch
# the Dockerfile).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
  cat <<'EOF'
Usage: scripts/build.sh [options]

  -b, --build     Build only: cargo build --tests --locked
  -t, --test      Test only: cargo test --locked (unit tests + tests/e2e.rs)
  -c, --clippy    Clippy only: cargo clippy --all-targets --locked -- -D warnings
      --nix       Also run `nix flake check` (builds the package, runs
                  tests and clippy again, hermetically via the flake)
      --docker    Also build the Docker image locally (no push), like the
                  CI docker-build job
      --release   Build/test in release mode instead of debug
  -h, --help      Show this help

With no -b/-t/-c given, all three run (this is the default: same coverage
as CI's "Build, test, and lint" job).
EOF
}

do_build=0
do_test=0
do_clippy=0
do_nix=0
do_docker=0
release=0

if [ $# -eq 0 ]; then
  do_build=1; do_test=1; do_clippy=1
fi

while [ $# -gt 0 ]; do
  case "$1" in
    -b|--build) do_build=1 ;;
    -t|--test) do_test=1 ;;
    -c|--clippy) do_clippy=1 ;;
    --nix) do_nix=1 ;;
    --docker) do_docker=1 ;;
    --release) release=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

# Any of -b/-t/-c given alone means "just that one" -- only default to all
# three when none of them were explicitly requested.
if [ "$do_build" -eq 0 ] && [ "$do_test" -eq 0 ] && [ "$do_clippy" -eq 0 ]; then
  do_build=1; do_test=1; do_clippy=1
fi

release_flag=()
[ "$release" -eq 1 ] && release_flag=(--release)

if [ "$do_build" -eq 1 ]; then
  echo "==> cargo build --tests --locked ${release_flag[*]}"
  cargo build --tests --locked "${release_flag[@]}"
fi

if [ "$do_test" -eq 1 ]; then
  echo "==> cargo test --locked ${release_flag[*]}"
  cargo test --locked "${release_flag[@]}"
fi

if [ "$do_clippy" -eq 1 ]; then
  echo "==> cargo clippy --all-targets --locked -- -D warnings"
  cargo clippy --all-targets --locked -- -D warnings
fi

if [ "$do_nix" -eq 1 ]; then
  echo "==> nix flake check"
  nix flake check
fi

if [ "$do_docker" -eq 1 ]; then
  echo "==> docker build -t microtak-server:local ."
  docker build -t microtak-server:local .
fi

echo "==> done"
