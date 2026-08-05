#!/usr/bin/env bash
# Compares removing empty directories through a mounted SMB share against
# smb2-cli talking to the server directly.
#
# Each arm gets its own disjoint slice of the input list, so nothing is
# measured twice and the directories really do get removed.
#
# Usage:
#   rmdir-bench.sh <dir-list> <mount-path> <target> <sample-size> [concurrency...]
#
# Example:
#   SMB2_USER=david SMB2_PASS_COMMAND='secret RASPI_SMB_PASSWORD' \
#     ./rmdir-bench.sh dirs.txt \
#       /Volumes/PiHDD/xiaomi_camera_videos/788b2a1989e9 \
#       //192.168.1.150/PiHDD/xiaomi_camera_videos/788b2a1989e9 \
#       300 1 8 16 32

set -euo pipefail

if [ $# -lt 4 ]; then
    sed -n '2,14p' "$0"
    exit 1
fi

list=$1
mount_path=$2
target=$3
sample=$4
shift 4
concurrencies=("$@")
if [ ${#concurrencies[@]} -eq 0 ]; then
    concurrencies=(1 8 16 32)
fi

binary=$(dirname "$0")/../target/release/smb2
if [ ! -x "$binary" ]; then
    echo "Build the release binary first: cargo build --release" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
total_needed=$((sample * (1 + ${#concurrencies[@]})))
if [ "$(wc -l <"$list")" -lt "$total_needed" ]; then
    echo "Need at least $total_needed directories in $list for these arms" >&2
    exit 1
fi
split -l "$sample" -a 3 "$list" "$work/slice."
slices=("$work"/slice.*)

# Seconds with fractions, portable enough for macOS and Linux.
now() { python3 -c 'import time; print(time.time())'; }
elapsed() { python3 -c "print(f'{$2 - $1:.1f}')"; }

report() {
    local label=$1 seconds=$2 count=$3
    local rate
    rate=$(python3 -c "print(f'{$count / max($seconds, 0.001):.1f}')")
    printf '%-28s %8ss  %8s dirs/s\n' "$label" "$seconds" "$rate"
}

echo "Removing $sample directories per arm, $((${#concurrencies[@]} + 1)) arms."
echo

index=0
start=$(now)
while read -r dir; do
    rmdir "$mount_path/$dir" 2>/dev/null || true
done <"${slices[$index]}"
finish=$(now)
report "mounted share (rmdir)" "$(elapsed "$start" "$finish")" "$sample"

for concurrency in "${concurrencies[@]}"; do
    index=$((index + 1))
    start=$(now)
    "$binary" rmdir --from-file "${slices[$index]}" -j "$concurrency" "$target" >/dev/null
    finish=$(now)
    report "smb2-cli -j $concurrency" "$(elapsed "$start" "$finish")" "$sample"
done
