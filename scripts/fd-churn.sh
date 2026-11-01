#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# fd-churn.sh — a package's tests raced and repeated beside a descriptor and filesystem churn in another
# process: the gate each ADR 0023 package migration runs (the 2026-10-05 note, C4 and "Each package migration
# also"), and the TMPDIR churn script the fd closer was proved under.
#
# Why it exists: a number closed twice, or closed under a borrower, fails only when something else has taken
# the number in between, which takes load: it reproduced only under `go test -p 6 -race -count=500` with
# files being created and removed beside it. The churn runs in its own process, so it adds kernel and
# filesystem pressure (dentry and inode allocation, the page cache, the scheduler); it does not recycle numbers
# inside the test process, which is the tests' own job (sys.FD's race tests, a package's unwind tests).
#
# What proves the harness is its negative control, scripts/fd-churn_test.sh: a fixture that double-closes
# while another goroutine opens fails under it.
#
# Usage: scripts/fd-churn.sh [-count N] [-p P] [-run REGEXP] [-tags TAGS] PKG...
#   -count N   go test -count (default 500)
#   -p P       go test -p (default 6)
#   -run, -tags  passed to go test
#   PKG        packages as go test takes them (./internal/ledger)
# Run it under a memory limit on a small development box: the churn keeps several test binaries running at once.
# Environment: GO (go).
# Exit: 0 when go test passed and the churn ran until it was stopped; 1 when either failed; 2 on a usage error.
set -euo pipefail

usage() {
	sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" >&2
	exit 2
}

GO=${GO:-go}
count=500
procs=6
run=
tags=
while [ $# -gt 0 ]; do
	case $1 in
	-count) [ $# -ge 2 ] || usage; count=$2; shift 2 ;;
	-p) [ $# -ge 2 ] || usage; procs=$2; shift 2 ;;
	-run) [ $# -ge 2 ] || usage; run=$2; shift 2 ;;
	-tags) [ $# -ge 2 ] || usage; tags=$2; shift 2 ;;
	-h | --help) usage ;;
	-*) echo "fd-churn: unknown option $1" >&2; usage ;;
	*) break ;;
	esac
done
[ $# -ge 1 ] || usage
case $count in '' | *[!0-9]*) echo "fd-churn: -count $count is not a number" >&2; usage ;; esac
case $procs in '' | *[!0-9]*) echo "fd-churn: -p $procs is not a number" >&2; usage ;; esac

churn_dir=$(mktemp -d "${TMPDIR:-/tmp}/tego-fd-churn.XXXXXX")
churn_pid=
cleanup() {
	[ -z "$churn_pid" ] || kill "$churn_pid" 2>/dev/null || true
	[ -z "$churn_pid" ] || wait "$churn_pid" 2>/dev/null || true
	rm -rf "$churn_dir"
}
trap cleanup EXIT INT TERM

# The churn: create, open, close and unlink in a tight loop over a rotating set of names, until it is killed.
# Each round's count goes to a file, so the report says how much churn the run actually had. Any failure ends
# the loop with status 1, which the check after go test reads as a churn that did not run to the end.
churn() {
	local i=0 f fd
	while :; do
		f="$churn_dir/c$((i % 64))"
		: >"$f" || exit 1
		exec {fd}<"$f" || exit 1
		exec {fd}<&-
		rm -f -- "$f" || exit 1
		i=$((i + 1))
		[ $((i % 1000)) -ne 0 ] || echo "$i" >"$churn_dir/rounds"
	done
}
churn &
churn_pid=$!

args=(test -race -p "$procs" -count "$count")
[ -z "$run" ] || args+=(-run "$run")
[ -z "$tags" ] || args+=(-tags "$tags")
echo "fd-churn: $GO ${args[*]} $* beside a churn in $churn_dir"
status=0
# The race detector needs cgo, whatever the environment says for the product's static builds.
CGO_ENABLED=1 "$GO" "${args[@]}" "$@" || status=$?

churn_ok=1
if ! kill -0 "$churn_pid" 2>/dev/null; then
	churn_ok=0 # it ended on its own: a failed create, open or unlink
fi
rounds=$(cat "$churn_dir/rounds" 2>/dev/null || echo "under 1000")
echo "fd-churn: go test exit $status; churn $([ "$churn_ok" = 1 ] && echo "running" || echo "DIED") after $rounds rounds"
[ "$status" -eq 0 ] && [ "$churn_ok" = 1 ] || exit 1
