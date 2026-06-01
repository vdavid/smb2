#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROFILE="${1:-internal}"

# Internal fixtures are dev-only and live under tests/. Consumer fixtures are
# embedded into the published crate (the `testing` feature `include_str!`s
# them), so they live next to that code under src/testing/fixtures/.
case "$PROFILE" in
    internal)
        echo "[*] Starting internal test containers..."
        docker compose -f "$SCRIPT_DIR/internal/docker-compose.yml" up -d --build --wait
        echo "[+] Internal containers ready"
        ;;
    consumer)
        echo "[*] Starting consumer test containers..."
        docker compose -f "$REPO_ROOT/src/testing/fixtures/consumer/docker-compose.yml" up -d --build --wait
        echo "[+] Consumer containers ready"
        ;;
    *)
        echo "Usage: $0 {internal|consumer}"
        exit 1
        ;;
esac
