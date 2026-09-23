#!/usr/bin/env bash
# The tuning grid behind results/self-tuning.md: every candidate in TUNINGS as
# `auto:<tuning>` on every link of a group, appended to OUT_DIR/down.csv or
# OUT_DIR/up.csv. Each group runs in under ten minutes on the reference rig.
# Usage: ./grid.sh OUT_DIR GROUP...
# Then: ./target/release/read-ahead-bench score --detail OUT_DIR/*.csv
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
shift
export BENCH_PROJECT="${BENCH_PROJECT:-smb2-ra-grid}"
export SMB_BENCH_PORT="${SMB_BENCH_PORT:-17545}"
# Each candidate's connection idles while the others run; see docker-compose.yml.
export BENCH_SLOW_START_AFTER_IDLE=0
TUNINGS="${TUNINGS:-ref fixed250 fixed100 wmax16 wmax16-del wmax8 meandev4 wmax16-n25 wmax16-n50 meandev4-n25}"
RUNS="${RUNS:-3}"
VARIANTS=""
for t in $TUNINGS; do VARIANTS="${VARIANTS:+$VARIANTS,}auto:$t"; done
export VARIANTS
# The largest file measures throughput; the others are what a file manager
# waits for per file. 3 MB/s links stop at 8 MiB to fit the time budget.
FAST=1048576,4194304,8388608,33554432
SLOW=1048576,4194304,8388608

down() { SIZES="$1" LOADS="${3:-0}" ./run.sh "$OUT/down.csv" "$RUNS" "$2"; }
up() { DIRECTION=up SIZES="$1" LOADS=0 ./run.sh "$OUT/up.csv" "$RUNS" "$2"; }

for group in "$@"; do
  case "$group" in
    d30) down $FAST "1@240mbit 5@240mbit 20@240mbit 60@240mbit 200@240mbit" ;;
    d3) down $SLOW "5@24mbit 60@24mbit 200@24mbit" ;;
    d300) down $FAST "1@2400mbit 5@2400mbit" ;;
    dfree) down $FAST "1 20 60 200" ;;
    djitter) down $FAST "5~5 20@240mbit~10 20@240mbit~40" ;;
    djitter3) down $SLOW "60@24mbit~30" ;;
    dstall) down $FAST "1+stall 5@240mbit+stall" ;;
    dstall3) down $SLOW "60@24mbit+stall" ;;
    dload) down $FAST "1 5@240mbit" 2 ;;
    up30) up $FAST "5@240mbit 60@240mbit 20@240mbit~40 5@240mbit+stall" ;;
    up3) up $SLOW "60@24mbit" ;;
    *) echo "unknown group $group (d30 d3 d300 dfree djitter djitter3 dstall dstall3 dload up30 up3)" >&2; exit 1 ;;
  esac
done
