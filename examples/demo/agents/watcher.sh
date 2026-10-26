#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# A stand-in for an agent that never stops (demo.sh always-on). Each pass it does honest work (a
# heartbeat line in ./out/) and, as a misbehaving agent would, tries to read the secrets: the work
# is allowed, the read is refused, and the refusals pile up in the ledger and the dashboard.
set -u
n=0
while :; do
  n=$((n + 1))
  echo "pass $n at $(date +%H:%M:%S)" >>"$PROJECT/out/heartbeat.txt"
  cat "$SECRETS/.env" >/dev/null 2>&1 || echo "[watcher] pass $n: the secrets read was refused"
  sleep 5
done
