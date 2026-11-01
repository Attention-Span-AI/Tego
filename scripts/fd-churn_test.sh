#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests fd-churn.sh with its fixture, scripts/testdata/fdchurn: the negative control, a test that closes a
# number twice while another goroutine opens files, fails under the harness within -count=50 (a hard gate: a
# harness that cannot fail it proves nothing about the packages it is run on); the same test closing once
# passes; a go test that fails fails the script; and its usage errors exit 2.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$here/.."
GO=${GO:-go}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-fd-churn-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
fixture=./scripts/testdata/fdchurn
fail=0

# run MODE COUNT: the fixture under the harness in MODE; prints the harness's exit status.
run() {
	local st=0
	TEGO_FDCHURN_FIXTURE=$1 GO=$GO "$here/fd-churn.sh" -count "$2" -p 2 "$fixture" >"$tmp/out" 2>&1 || st=$?
	echo "$st"
}

st=$(run bug 50)
if [ "$st" = 1 ] && grep -q 'closed under it' "$tmp/out" && grep -q 'go test exit 1' "$tmp/out"; then
	echo "ok   a double close under the harness fails within -count=50"
else
	echo "FAIL: the negative control (a double close) exited $st under the harness, want 1 naming the lost descriptor:"
	sed 's/^/    /' "$tmp/out"
	fail=1
fi

st=$(run fixed 20)
if [ "$st" = 0 ] && grep -q 'churn running' "$tmp/out"; then
	echo "ok   the same test closing once passes, with the churn running to the end"
else
	echo "FAIL: the fixed fixture exited $st under the harness, want 0:"
	sed 's/^/    /' "$tmp/out"
	fail=1
fi

# A package that does not build is go test's failure, and the harness's.
st=0
GO=$GO "$here/fd-churn.sh" -count 1 ./scripts/testdata/fdchurn/missing >"$tmp/out" 2>&1 || st=$?
if [ "$st" = 1 ]; then
	echo "ok   a go test that fails fails the harness"
else
	echo "FAIL: a missing package exited $st, want 1"
	fail=1
fi

for args in "" "-count" "-count x ./x" "-p 0x ./x" "-bogus ./x"; do
	st=0
	# shellcheck disable=SC2086 # the arguments are split on purpose
	"$here/fd-churn.sh" $args >/dev/null 2>&1 || st=$?
	if [ "$st" = 2 ]; then
		echo "ok   usage: '$args'"
	else
		echo "FAIL: '$args' exited $st, want 2"
		fail=1
	fi
done
exit "$fail"
