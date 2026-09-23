#!/usr/bin/env bash
# Drives the read-ahead matrix: RTT × load, each running every size × variant.
# Usage: ./run.sh OUT.csv [runs] [rtts] [writers]
# DIRECTION=up measures uploads instead, shaping the client-to-server direction.
set -euo pipefail
cd "$(dirname "$0")"
OUT="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
RUNS="${2:-5}"
RTTS="${3:-0 5 60}"
WRITERS="${4:-2}"
PROJECT=smb2-read-ahead-bench
export SMB_BENCH_PORT="${SMB_BENCH_PORT:-17445}"
COMPOSE=(docker compose -p "$PROJECT" -f docker/docker-compose.yml)

cleanup() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

"${COMPOSE[@]}" up -d --build --wait
C="$("${COMPOSE[@]}" ps -q smb-bench)"
# The default sizes, plus any in SIZES; the `stat` probe reads f_65536.bin.
EXTRA="${SIZES:-}"
FILE_SIZES="65536 386048 1048576 8388608 104857600 ${EXTRA//,/ }"
docker exec -e FILE_SIZES="$FILE_SIZES" "$C" sh -c '
  mkdir -p /shares/public/bench /shares/public/load /shares/public/up
  chmod 777 /shares/public/bench /shares/public/load /shares/public/up
  for s in $FILE_SIZES; do
    head -c $s /dev/urandom > /shares/public/bench/f_$s.bin
  done
  chmod 666 /shares/public/bench/*'

# BIN runs a prebuilt binary instead, for example one built against an older
# smb2 to measure the "before".
if [ -z "${BIN:-}" ]; then
  cargo build --release --quiet
  BIN=./target/release/read-ahead-bench
fi

# Downloads shape the container's egress, since the responses carry the
# payload. Uploads shape its ingress instead, redirected through an ifb device
# because netem only shapes what leaves an interface.
MODE=run
DEV=eth0
LIMIT=""
if [ "${DIRECTION:-down}" = up ]; then
  MODE=upload
  DEV=ifb0
  # A deep queue, so the shaped uplink queues the way a slow one does instead
  # of dropping (netem's default limit is 1,000 packets, 1.5 MB).
  LIMIT="limit 100000"
  docker exec "$C" sh -c '
    ip link add ifb0 type ifb 2>/dev/null || true
    ip link set ifb0 up
    tc qdisc replace dev eth0 handle ffff: ingress
    tc filter replace dev eth0 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev ifb0'
fi

# Each link is "<delay ms>" or "<delay ms>@<rate>", e.g. "60@3mbit".
for rtt in $RTTS; do
  delay="${rtt%%@*}"
  rate=""
  [ "$rtt" != "$delay" ] && rate="rate ${rtt#*@}"
  if [ "$rtt" = 0 ]; then
    docker exec "$C" tc qdisc del dev "$DEV" root 2>/dev/null || true
  else
    # shellcheck disable=SC2086
    docker exec "$C" tc qdisc replace dev "$DEV" root netem delay "${delay}ms" $rate $LIMIT
  fi
  for load in ${LOADS:-0 $WRITERS}; do
    "$BIN" "$MODE" --addr "127.0.0.1:$SMB_BENCH_PORT" --rtt-ms "$rtt" --load-writers "$load" --runs "$RUNS" --out "$OUT" ${VARIANTS:+--variants "$VARIANTS"} ${SIZES:+--sizes "$SIZES"}
    docker exec "$C" sh -c 'rm -f /shares/public/load/* /shares/public/up/*'
  done
done
