#!/usr/bin/env bash
# Compares ways of doing many small metadata operations on a remote server:
# through a mounted SMB share, over SSH, and with smb2-cli talking SMB
# directly at several concurrency levels.
#
# Each arm gets its own disjoint slice of the input list, so nothing is
# measured twice and the operations really do happen.
#
# Usage:
#   bulk-bench.sh <rm|rmdir> <path-list> <mount-path> <target> <sample-size> [concurrency...]
#
# Set SSH_HOST and SSH_PATH to add an SSH arm, which runs one process on the
# server doing plain local syscalls.
#
# Example:
#   SMB2_USER=david SMB2_PASS_COMMAND='secret RASPI_SMB_PASSWORD' \
#   SSH_HOST=raspi SSH_PATH=/mnt/hdd/xiaomi_camera_videos/788b2a1989e9 \
#     ./bulk-bench.sh rm junk.txt \
#       /Volumes/PiHDD/xiaomi_camera_videos/788b2a1989e9 \
#       //192.168.1.150/PiHDD/xiaomi_camera_videos/788b2a1989e9 \
#       500 1 8 16 32

set -euo pipefail

if [ $# -lt 5 ]; then
    sed -n '2,21p' "$0"
    exit 1
fi

operation=$1
list=$2
mount_path=$3
target=$4
sample=$5
shift 5
concurrencies=("$@")
if [ ${#concurrencies[@]} -eq 0 ]; then
    concurrencies=(1 8 16 32)
fi

case "$operation" in
rm)
    local_command=rm
    remote_call=os.remove
    ;;
rmdir)
    local_command=rmdir
    remote_call=os.rmdir
    ;;
*)
    echo "Operation must be rm or rmdir, got $operation" >&2
    exit 1
    ;;
esac

binary=$(dirname "$0")/../../target/release/smb2
if [ ! -x "$binary" ]; then
    echo "Build the release binary first: cargo build --release" >&2
    exit 1
fi

arms=$((1 + ${#concurrencies[@]}))
if [ -n "${SSH_HOST:-}" ]; then
    arms=$((arms + 1))
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ "$(wc -l <"$list")" -lt "$((sample * arms))" ]; then
    echo "Need at least $((sample * arms)) paths in $list for $arms arms" >&2
    exit 1
fi
split -l "$sample" -a 4 "$list" "$work/slice."
slices=("$work"/slice.*)

# Seconds with fractions, portable enough for macOS and Linux.
now() { python3 -c 'import time; print(time.time())'; }
elapsed() { python3 -c "print(f'{$2 - $1:.1f}')"; }

report() {
    local label=$1 seconds=$2 count=$3
    local rate
    rate=$(python3 -c "print(f'{$count / max($seconds, 0.001):.1f}')")
    printf '%-28s %8ss  %9s ops/s\n' "$label" "$seconds" "$rate"
}

echo "$operation on $sample paths per arm, $arms arms."
echo

index=0
start=$(now)
while read -r path; do
    "$local_command" "$mount_path/$path" 2>/dev/null || true
done <"${slices[$index]}"
finish=$(now)
report "mounted share" "$(elapsed "$start" "$finish")" "$sample"

if [ -n "${SSH_HOST:-}" ]; then
    index=$((index + 1))
    start=$(now)
    # One process doing the syscall per line. A shell loop calling `rm` would
    # fork per path and measure process spawn instead of the filesystem.
    ssh "$SSH_HOST" "cd '${SSH_PATH:?set SSH_PATH too}' && python3 -c '
import os, sys
for line in sys.stdin:
    try:
        $remote_call(line.strip())
    except OSError:
        pass
'" <"${slices[$index]}"
    finish=$(now)
    report "ssh (local syscalls)" "$(elapsed "$start" "$finish")" "$sample"
fi

for concurrency in "${concurrencies[@]}"; do
    index=$((index + 1))
    start=$(now)
    "$binary" "$operation" --from-file "${slices[$index]}" -j "$concurrency" "$target" >/dev/null
    finish=$(now)
    report "smb2-cli -j $concurrency" "$(elapsed "$start" "$finish")" "$sample"
done
