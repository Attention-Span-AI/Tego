#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests skipgate.sh over canned `go test -json` streams: a skip the list allows passes and one it does not
# fails and is named with its reason; a list entry without a reason, and a stream with no test in it, are
# usage errors rather than passes; a repeated subtest's '#' is part of its name, not the start of a reason;
# a package is matched by its import path or its path in the module; lines that are not JSON, or not JSON objects, are passed
# over; the stream can come on stdin. With --must-pass, a listed test that passed passes, and one that
# skipped, failed or never ran fails; over several streams, one that some stream passed and none failed passes. A failed test's own output is printed either way, since the job's log
# is JSON otherwise. A test binary that ended while tests of it ran (go test's -timeout panic, an exit) has each of
# them named as unfinished, with its panic, the panic's list of running tests and the goroutine dump, or with its last
# lines where nothing panicked; a test that ended is never named so, and one another stream (another build of the
# package) passed is named where it was left unfinished. The dump starts at the binary's own panic, past one a child
# process printed before it.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
gate="${here}/skipgate.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-skipgate-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

m=github.com/attention-span-ai/tego
ev() { # ev ACTION PACKAGE TEST [OUTPUT]: one go test -json event
	if [ -n "${4:-}" ]; then
		printf '{"Action":"%s","Package":"%s/%s","Test":"%s","Output":"%s\\n"}\n' "$1" "$m" "$2" "$3" "$4"
	else
		printf '{"Action":"%s","Package":"%s/%s","Test":"%s"}\n' "$1" "$m" "$2" "$3"
	fi
}
{
	ev run internal/cli TestA
	ev pass internal/cli TestA
	ev run internal/cli TestRootOnly
	ev output internal/cli TestRootOnly "    ownlog_test.go:1: needs root"
	ev skip internal/cli TestRootOnly
	ev run internal/doctor "TestT/case#01"
	ev skip internal/doctor "TestT/case#01"
	echo 'not json: a line go printed itself'
	printf '{"Action":"output","Package":"%s/internal/cli","Output":"ok  \\t%s/internal/cli\\t0.1s\\n"}\n' "$m" "$m"
} >"$tmp/listed.json"
{
	cat "$tmp/listed.json"
	ev output internal/ledger TestNew "    new_test.go:9: this host has no such file"
	ev skip internal/ledger TestNew
} >"$tmp/unlisted.json"
{
	ev output internal/cli TestA "    a_test.go:3: got 1, want 2"
	ev fail internal/cli TestA
	ev skip internal/cli TestRootOnly
} >"$tmp/failed.json"
{ # the tagged build of a package whose plain build skipped TestRootOnly
	ev run internal/cli TestRootOnly
	ev pass internal/cli TestRootOnly
} >"$tmp/tagged.json"
printf '# comment\n\ninternal/cli TestRootOnly # needs root\n%s/internal/doctor TestT/case#01 # a repeated subtest\n' "$m" >"$tmp/allow"
printf 'internal/cli TestA # always runs\n' >"$tmp/must"
printf 'internal/cli TestRootOnly # root only\n' >"$tmp/mustskip"
printf 'internal/cli TestNever # never in the stream\n' >"$tmp/mustabsent"
printf 'internal/cli TestRootOnly\n' >"$tmp/noreason"
printf 'internal/cli TestRootOnly #   \n' >"$tmp/blankreason"
: >"$tmp/empty.json"

fail=0
# run NAME WANT_EXIT ARGS...: skipgate.sh's output is in $tmp/out.
run() {
	name=$1
	want=$2
	shift 2
	set +e
	bash "$gate" "$@" >"$tmp/out" 2>&1
	got=$?
	set -e
	if [ "$got" = "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $got, want $want" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}
has() { # has NAME PATTERN: the last run's output has a line matching PATTERN
	if ! grep -q -- "$2" "$tmp/out"; then
		echo "FAIL $1: no line matching \"$2\"" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}

run "every skip is listed" 0 "$tmp/allow" "$tmp/listed.json"
has "every skip is listed" "^allowed    internal/cli TestRootOnly"
has "every skip is listed" "^allowed    internal/doctor TestT/case#01"
has "the packages' result lines are printed" "^ok  .*internal/cli"

# a line that is valid JSON but not an object, last, once made jq exit 5 and kill the gate before its report
{ cat "$tmp/listed.json"; echo 42; echo '"x"'; echo '[1]'; } >"$tmp/scalar.json"
run "a JSON line that is not an object is passed over" 0 "$tmp/allow" "$tmp/scalar.json"
has "a JSON line that is not an object is passed over" "^allowed    internal/cli TestRootOnly"

run "an unlisted skip fails" 1 "$tmp/allow" "$tmp/unlisted.json"
has "an unlisted skip fails" "^UNLISTED   internal/ledger TestNew"
has "an unlisted skip names its reason" "this host has no such file"

set +e
bash "$gate" "$tmp/allow" <"$tmp/unlisted.json" >"$tmp/out" 2>&1
got=$?
set -e
if [ "$got" = 1 ] && grep -q "^UNLISTED   internal/ledger TestNew" "$tmp/out"; then
	echo "ok   the stream on stdin"
else
	echo "FAIL the stream on stdin: exit $got" >&2
	fail=1
fi

{
	ev skip internal/cgroup "TestTable/fatal/deep"
	ev skip internal/cgroup "TestTableX/fatal"
} >"$tmp/sub.json"
printf 'internal/cgroup TestTable/* # every case needs the same host budget\n' >"$tmp/suballow"
run "a parent's /* allows its subtests at any depth, and only its own" 1 "$tmp/suballow" "$tmp/sub.json"
has "a parent's /* allows its subtests" "^allowed    internal/cgroup TestTable/fatal/deep"
has "a parent's /* allows only its own subtests" "^UNLISTED   internal/cgroup TestTableX/fatal"

run "an entry without a reason is a usage error" 2 "$tmp/noreason" "$tmp/listed.json"
has "an entry without a reason is a usage error" "has no reason"
run "a blank reason is no reason" 2 "$tmp/blankreason" "$tmp/listed.json"
run "a stream with no test is a usage error" 2 "$tmp/allow" "$tmp/empty.json"
run "a missing list is a usage error" 2 "$tmp/nosuchlist" "$tmp/listed.json"

# A row-scoped entry is never a global allowance, including when the caller did not name a row.
printf 'internal/cli TestRootOnly row=rhel-9 # the row has no driver\n' >"$tmp/rowallow"
ev skip internal/cli TestRootOnly >"$tmp/row.json"
run "a scoped skip is allowed on its own row" 0 --row rhel-9 "$tmp/rowallow" "$tmp/row.json"
has "the row's skip is accepted" '^allowed    internal/cli TestRootOnly'
run "a scoped skip is rejected on another row" 1 --row fedora-7.2 "$tmp/rowallow" "$tmp/row.json"
has "another row's skip is rejected" '^UNLISTED   internal/cli TestRootOnly'
run "a scoped skip is rejected without a row" 1 "$tmp/rowallow" "$tmp/row.json"
run "a scoped skip is rejected with an empty row" 1 --row "" "$tmp/rowallow" "$tmp/row.json"
run "global skips still apply with a row" 0 --row fedora-7.2 "$tmp/allow" "$tmp/listed.json"
printf 'internal/cli TestRootOnly row= # missing row\n' >"$tmp/badrow"
run "an empty scope is a usage error" 2 "$tmp/badrow" "$tmp/row.json"
printf 'internal/cli TestRootOnly row=fedora-* # no wildcard scopes\n' >"$tmp/badrow"
run "a wildcard scope is a usage error" 2 "$tmp/badrow" "$tmp/row.json"
printf 'internal/cli TestRootOnly rows=rhel-9 # misspelled metadata\n' >"$tmp/badrow"
run "unknown scope metadata is a usage error" 2 "$tmp/badrow" "$tmp/row.json"
run "a malformed row argument is a usage error" 2 --row 'rhel-9 fedora-7.2' "$tmp/allow" "$tmp/listed.json"
run "a missing row argument is a usage error" 2 --row
run "must-pass accepts row before the mode" 0 --row rhel-9 --must-pass "$tmp/must" "$tmp/listed.json"
run "must-pass accepts row after the mode" 0 --must-pass --row rhel-9 "$tmp/must" "$tmp/listed.json"

run "a failed test is printed with its output, and failures are go test's to judge" 0 "$tmp/allow" "$tmp/failed.json"
has "a failed test is printed" "^--- FAIL: TestA (internal/cli)"
has "a failed test's output is printed" "got 1, want 2"

# go test's -timeout panic: test2json gives the tests that were running no result, only the package's fail, so the log
# said FAIL for internal/runtime and nothing more (CI, 2026-11-02)
pkgline() { # pkgline PACKAGE OUTPUT: a package's own output line
	printf '{"Action":"output","Package":"%s/%s","Output":"%s\\n"}\n' "$m" "$1" "$2"
}
{
	ev run internal/runtime TestFast
	ev pass internal/runtime TestFast
	ev run internal/runtime TestHang
	ev output internal/runtime TestHang "=== RUN   TestHang"
	ev run internal/runtime TestWaiting
	ev output internal/runtime TestHang "panic: test timed out after 10m0s"
	ev output internal/runtime TestHang '\trunning tests:'
	ev output internal/runtime TestHang '\t\tTestHang (9m59s)'
	ev output internal/runtime TestHang ""
	ev output internal/runtime TestHang "goroutine 7 [chan receive, 9 minutes]:"
	ev output internal/runtime TestHang "runtime.waitForTheRun(0x1)"
	pkgline internal/runtime "FAIL\\t$m/internal/runtime\\t600.127s"
	printf '{"Action":"fail","Package":"%s/internal/runtime"}\n' "$m"
	ev run internal/cli TestExits
	ev output internal/cli TestExits "    the last thing it said"
	pkgline internal/cli "FAIL\\t$m/internal/cli\\t1.0s"
	printf '{"Action":"fail","Package":"%s/internal/cli"}\n' "$m"
} >"$tmp/timeout.json"
run "a test binary that timed out names the tests it left unfinished" 0 "$tmp/allow" "$tmp/timeout.json"
has "a timed-out test is named" "^--- UNFINISHED: TestHang (internal/runtime)"
has "a test waiting to run when the binary ended is named" "^--- UNFINISHED: TestWaiting (internal/runtime)"
has "the timeout's panic is printed" "^    panic: test timed out after 10m0s"
has "the panic's list of running tests is printed" "TestHang (9m59s)"
has "the goroutine dump is printed" "runtime.waitForTheRun"
has "a binary that ended with no panic: its last lines are printed" "the last thing it said"
has "a binary that ended with no panic: its test is named" "^--- UNFINISHED: TestExits (internal/cli)"
if grep -q "UNFINISHED: TestFast" "$tmp/out"; then
	echo "FAIL a test that passed is named unfinished" >&2
	fail=1
fi
run "a stream whose every test ended names none unfinished" 0 "$tmp/allow" "$tmp/failed.json"
if grep -q "UNFINISHED" "$tmp/out"; then
	echo "FAIL a stream whose every test ended names a test unfinished" >&2
	fail=1
fi

# root-suites.sh gives skipgate.sh a package's plain and tagged builds as two streams: a test one of them left
# unfinished is named, with its stream, though the other passed it.
{
	ev run internal/runtime TestHang
	ev pass internal/runtime TestHang
	pkgline internal/runtime "ok  \\t$m/internal/runtime\\t1.0s"
} >"$tmp/plain.json"
cp "$tmp/timeout.json" "$tmp/tagged-timeout.json"
run "a test one build passed and another left unfinished" 0 "$tmp/allow" "$tmp/plain.json" "$tmp/tagged-timeout.json"
has "a test another build passed is still named where it was left unfinished" \
	"^--- UNFINISHED: TestHang (internal/runtime, in tagged-timeout.json)"
has "how that build's binary ended is printed, with its stream" \
	"^--- how the test binary of internal/runtime, in tagged-timeout.json ended:"
has "that build's timeout panic is printed" "^    panic: test timed out after 10m0s"

# A child process that shares the test binary's output can print a panic of its own before the binary's: the dump
# starts at go test's timeout panic, or, with none, at the last panic the binary printed.
{
	ev run internal/runtime TestChild
	ev output internal/runtime TestChild "panic: a child process's own panic"
	ev output internal/runtime TestChild "main.child()"
	ev pass internal/runtime TestChild
	ev run internal/runtime TestHang
	ev output internal/runtime TestHang "panic: test timed out after 10m0s"
	ev output internal/runtime TestHang '\trunning tests:'
	ev output internal/runtime TestHang '\t\tTestHang (9m59s)'
	pkgline internal/runtime "FAIL\\t$m/internal/runtime\\t600.1s"
	printf '{"Action":"fail","Package":"%s/internal/runtime"}\n' "$m"
	ev run internal/cli TestChild
	ev output internal/cli TestChild "panic: a child process's own panic"
	ev pass internal/cli TestChild
	ev run internal/cli TestCrash
	ev output internal/cli TestCrash "panic: the binary's own crash"
	ev output internal/cli TestCrash "internal/cli.TestCrash()"
	pkgline internal/cli "FAIL\\t$m/internal/cli\\t1.0s"
	printf '{"Action":"fail","Package":"%s/internal/cli"}\n' "$m"
} >"$tmp/childpanic.json"
run "a child's panic before the binary's own" 0 "$tmp/allow" "$tmp/childpanic.json"
has "the timeout's panic is printed past a child's" "^    panic: test timed out after 10m0s"
has "the binary's own crash is printed past a child's" "^    panic: the binary's own crash"
if grep -q "a child process's own panic" "$tmp/out"; then
	echo "FAIL the dump of how a binary ended starts at a child's panic, not the binary's own" >&2
	fail=1
fi

run "--must-pass: a listed test that passed" 0 --must-pass "$tmp/must" "$tmp/listed.json"
has "--must-pass: a listed test that passed" "^ok   internal/cli TestA"
run "--must-pass: a listed test that skipped" 1 --must-pass "$tmp/mustskip" "$tmp/listed.json"
has "--must-pass: a listed test that skipped" "^FAIL internal/cli TestRootOnly: skip"
run "--must-pass: a listed test that failed" 1 --must-pass "$tmp/must" "$tmp/failed.json"
run "--must-pass: a listed test that never ran" 1 --must-pass "$tmp/mustabsent" "$tmp/listed.json"
has "--must-pass: a listed test that never ran" "never ran"
run "--must-pass: skipped by one build, passed by the other" 0 --must-pass "$tmp/mustskip" "$tmp/listed.json" "$tmp/tagged.json"
run "--must-pass: passed by one build, skipped by the other (either order)" 0 --must-pass "$tmp/mustskip" "$tmp/tagged.json" "$tmp/listed.json"
run "--must-pass: failed by one build, passed by the other" 1 --must-pass "$tmp/must" "$tmp/listed.json" "$tmp/failed.json"

exit "$fail"
