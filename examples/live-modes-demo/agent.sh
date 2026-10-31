#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The demo's "agent": no model, only a loop that tries to read the fake customer report every 2 seconds and says
# whether it could. It uses shell built-ins plus cat and sleep, the programs the contract allows.
f=vault-data/customer-report.csv
n=0
while :; do
  n=$((n + 1))
  if rows=$(cat "$f" 2>&1); then
    printf '#%-3s read ok       %s  (first row: %s)\n' "$n" "$f" "${rows%%
*}"
  else
    printf '#%-3s read REFUSED  %s\n' "$n" "$f"
  fi
  sleep 2
done
