#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-internal}"

case "$PROFILE" in
    internal)
        echo "[*] Starting internal test containers..."
        docker compose -f "$SCRIPT_DIR/internal/docker-compose.yml" up -d --build --wait
        echo "[+] Internal containers ready"
        ;;
    consumer)
        echo "[*] Starting consumer test containers..."
        docker compose -f "$SCRIPT_DIR/consumer/docker-compose.yml" up -d --build --wait
        echo "[+] Consumer containers ready"
        ;;
    *)
        echo "Usage: $0 {internal|consumer}"
        exit 1
        ;;
esac
