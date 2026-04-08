#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

for compose_file in "$SCRIPT_DIR"/*/docker-compose.yml; do
    if [ -f "$compose_file" ]; then
        echo "[*] Stopping $(dirname "$compose_file" | xargs basename)..."
        docker compose -f "$compose_file" down
    fi
done

echo "[+] All containers stopped"
