#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${CLIPROXY_REPO_ROOT:-$SCRIPT_DIR}"
BIN_PATH="${CLIPROXY_BIN:-$REPO_ROOT/cli-proxy-api}"
PLIST_PATH="${CLIPROXY_PLIST:-$HOME/Library/LaunchAgents/com.router-for-me.cliproxyapi.source.plist}"
HEALTH_URL="${CLIPROXY_HEALTH_URL:-http://127.0.0.1:8317/healthz}"
BUILD=1
CHECK_HEALTH=1

usage() {
  cat <<EOF
Usage: ./restart-launchd-source.sh [options]

Options:
  --no-build       Restart launchd without rebuilding the binary.
  --no-health      Skip the health check after restart.
  --help           Show this help.

Environment overrides:
  CLIPROXY_REPO_ROOT    Repository root. Default: script directory.
  CLIPROXY_BIN          Binary path. Default: \$CLIPROXY_REPO_ROOT/cli-proxy-api.
  CLIPROXY_PLIST        LaunchAgent plist path. Default: ~/Library/LaunchAgents/com.router-for-me.cliproxyapi.source.plist.
  CLIPROXY_HEALTH_URL   Health check URL. Default: http://127.0.0.1:8317/healthz.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      BUILD=0
      ;;
    --no-health)
      CHECK_HEALTH=0
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option '$1'." >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ ! -d "$REPO_ROOT" ]]; then
  echo "Error: repository root does not exist: $REPO_ROOT" >&2
  exit 1
fi

if [[ ! -f "$PLIST_PATH" ]]; then
  echo "Error: LaunchAgent plist does not exist: $PLIST_PATH" >&2
  exit 1
fi

cd "$REPO_ROOT"

if [[ "$BUILD" -eq 1 ]]; then
  export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/cliproxy-go-build-cache}"
  mkdir -p "$GOCACHE"
  echo "Building $BIN_PATH ..."
  go build -o "$BIN_PATH" ./cmd/server
fi

echo "Unloading $PLIST_PATH ..."
if ! launchctl unload "$PLIST_PATH"; then
  echo "Warning: launchctl unload failed; continuing with load." >&2
fi

echo "Loading $PLIST_PATH ..."
launchctl load "$PLIST_PATH"

if [[ "$CHECK_HEALTH" -eq 0 ]]; then
  echo "Restart requested. Health check skipped."
  exit 0
fi

echo "Waiting for health check: $HEALTH_URL"
for _ in {1..30}; do
  if response="$(curl -fsS "$HEALTH_URL" 2>/dev/null)"; then
    echo "Health check OK: $response"
    exit 0
  fi
  sleep 1
done

echo "Error: health check failed after 30 seconds: $HEALTH_URL" >&2
exit 1
