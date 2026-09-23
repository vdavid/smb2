#!/bin/sh
# Server stalls: freezes every smbd process for STALL_MS, every STALL_EVERY_MS,
# the way a disk seek or a busy NAS CPU holds every answer at once. `run.sh`
# starts it for a `+stall` link and stops it (and thaws smbd) afterwards.
on=$(awk "BEGIN { print ${STALL_MS:-150} / 1000 }")
off=$(awk "BEGIN { print (${STALL_EVERY_MS:-1000} - ${STALL_MS:-150}) / 1000 }")
while :; do
  sleep "$off"
  pkill -STOP smbd
  sleep "$on"
  pkill -CONT smbd
done
