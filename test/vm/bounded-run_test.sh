#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests bounded-run.sh, the bound the KVM harness puts on qemu, the suite binaries and the matrix's kill tests,
# against the defect the harness review found: they were bounded with `timeout -k 10`, which uutils' timeout
# (Ubuntu 25.10's) never escalates, so a command that ignores SIGTERM ran on past its bound. Each case runs
# bounded-run.sh with BOUNDED_RUN_GRACE=2 on a stand-in command; the kill cases fail with `timeout -k` alone.
#
# Usage: test/vm/bounded-run_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-bounded-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
ms() { echo $(($(date +%s%N) / 1000000)); }
export BOUNDED_RUN_GRACE=2

# 1. Status and stdin reach the caller.
out="$(echo through | "$here/bounded-run.sh" 30 cat)"
[ "$out" = through ] || fail "stdin did not reach the command: got \"$out\""
"$here/bounded-run.sh" 30 sh -c 'exit 3'
[ "$?" = 3 ] || fail "the command's status 3 did not reach the caller"

# 2. A command that ends on SIGTERM is ended at the bound.
t0="$(ms)"
"$here/bounded-run.sh" 1 sleep 30
t="$(($(ms) - t0))"
[ "$t" -lt 2500 ] || fail "sleep 30 under a 1 s bound took ${t}ms"

# 3. A command that ignores SIGTERM is killed GRACE seconds past the bound, with its child.
t0="$(ms)"
# shellcheck disable=SC2016 # the inner bash expands it
"$here/bounded-run.sh" 1 bash -c 'trap "" TERM; sleep 30 & echo $! >"$1"; wait' ignores "$tmp/child"
t="$(($(ms) - t0))"
[ "$t" -lt 6000 ] || fail "a command ignoring SIGTERM under a 1 s bound took ${t}ms; it should be killed at about 3 s"
[ "$t" -ge 2500 ] || fail "a command ignoring SIGTERM was killed after ${t}ms, before the grace had passed"
child="$(cat "$tmp/child")"
for _ in $(seq 20); do
	state="$(awk '{print $3}' "/proc/$child/stat" 2>/dev/null)"
	[ -n "$state" ] && [ "$state" != Z ] || break
	sleep 0.1
done
[ -z "$state" ] || [ "$state" = Z ] || fail "the command's child $child survived the kill"

# 4. A TERM to the script is passed on and, for a command that ignores it, escalates the same way.
"$here/bounded-run.sh" 60 bash -c 'trap "" TERM; sleep 30 & wait' &
pid=$!
sleep 1
t0="$(ms)"
kill -TERM "$pid"
wait "$pid"
t="$(($(ms) - t0))"
[ "$t" -lt 6000 ] || fail "a TERM to the script took ${t}ms to end a command that ignores it"
# 5. The harness bounds its commands with bounded-run.sh, not `timeout -k`.
if grep -n 'timeout -k' "$here/kvm-run.sh" "$here/root-suites.sh" "$here/run-matrix-row.sh"; then
	fail "a harness script bounds a command with timeout -k, which uutils' timeout never escalates"
fi
echo "bounded-run_test: ok"
