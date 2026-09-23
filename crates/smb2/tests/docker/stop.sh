#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRATE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The internal fixtures live under tests/docker/, the consumer ones next to the
# `testing` feature that embeds them (see start.sh).
for compose_file in "$SCRIPT_DIR"/*/docker-compose.yml "$CRATE_ROOT/src/testing/fixtures/consumer/docker-compose.yml"; do
    if [ -f "$compose_file" ]; then
        echo "[*] Stopping $(dirname "$compose_file" | xargs basename)..."
        docker compose -f "$compose_file" down
    fi
done

echo "[+] All containers stopped"
