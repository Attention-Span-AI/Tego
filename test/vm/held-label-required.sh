#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Each named live proof must pass; no subtest may skip. A bare exit zero is insufficient.
set -eu
log=$1
shift
[ "$#" -gt 0 ] || exit 2
if grep -Eq -- '^[[:space:]]*--- SKIP:' "$log"; then
 echo 'held-label: a required live-policy test skipped' >&2
 exit 1
fi
for testname do
 grep -q -- "^--- PASS: $testname (" "$log" || {
  echo "held-label: $testname did not pass" >&2
  exit 1
 }
done
