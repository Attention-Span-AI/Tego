#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# skipgate.sh — reads `go test -json` streams and fails on a skip nobody decided to allow, or, with
# --must-pass, on a test that was expected to run and did not pass.
#
# Why it exists: a skipped test exits 0 exactly like a passed one, so a suite whose tests stop running (a
# probe that answers differently on a new runner image, a helper that is no longer built, a gate on root
# that nothing runs as root) stays green while it tests nothing. The allowlist names
# every skip that is expected and why, so a new one fails the job and has to be either fixed or listed with
# its reason. The must-pass list is the other half, for a job whose point is that certain tests run: CI's
# root-suites job gives it the root-only tests (test/vm/root-must-pass.txt), each of which skips wherever
# it is not root, and a skip there means the job lost what it exists for.
#
# It also prints the run the way a reader of a CI log needs it, since the job's own output is JSON: each
# package's result line, the build errors and each failed test's own output, and every skip with its reason
# and whether the list allows it. A test's failure is reported, not judged: the exit status of `go test` is
# the verdict on failures, and this script's is the verdict on skips.
#
# Usage: scripts/skipgate.sh [--must-pass] LIST [JSON...]   (the streams are read from stdin when no JSON is
#   named). LIST holds one test per line, "<package> <test> # <reason>", where the package is the import
#   path or its path within the module, and the test is its full name as `go test -json` reports it, a
#   subtest's included (TestX/case); in an allowlist, TestX/* allows every subtest of TestX. Blank lines and
#   lines starting with # are comments. Every entry must carry its reason: an entry without one is a usage
#   error.
# Exit: 0 when every skip is listed (with --must-pass: when every listed test passed); 1 when one is not;
#   2 on a usage error, an entry with no reason included, or a stream that holds no test at all.
# Needs: jq.
set -euo pipefail

usage() {
	sed -n '/^# Usage:/,/^# Needs:/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//' >&2
	exit 2
}
must=0
if [ "${1:-}" = --must-pass ]; then
	must=1
	shift
fi
[ $# -ge 1 ] || usage
list=$1
shift
[ -f "$list" ] || { echo "skipgate: $list: no such list" >&2; exit 2; }
command -v jq >/dev/null || { echo "skipgate: needs jq" >&2; exit 2; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
module="$(sed -n 's/^module //p' "$here/../go.mod")"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-skipgate.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# The list, normalized to "<import path> <test>" per line in $tmp/list; an entry without a reason stops here.
bad=0
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
	lineno=$((lineno + 1))
	case "$line" in "" | "#"*) continue ;; esac
	# The reason starts at the first " #": a test name has no space in it, but it may hold a '#', which
	# go test adds to a repeated subtest name (TestX/case#01).
	entry="${line%%[[:space:]]#*}"
	reason="${line#"$entry"}"
	reason="${reason#*#}"
	read -r pkg test extra <<<"$entry" || true
	if [ -z "${pkg:-}" ] || [ -z "${test:-}" ] || [ -n "${extra:-}" ]; then
		echo "skipgate: $list:$lineno: want \"<package> <test> # <reason>\", got: $line" >&2
		bad=1
		continue
	fi
	if [ -z "${reason// /}" ]; then
		echo "skipgate: $list:$lineno: $pkg $test has no reason; say why it may skip (or must pass)" >&2
		bad=1
		continue
	fi
	case "$pkg" in "$module" | "$module"/*) ;; *) pkg="$module/$pkg" ;; esac
	printf '%s %s\n' "$pkg" "$test" >>"$tmp/list"
done <"$list"
[ "$bad" = 0 ] || exit 2
touch "$tmp/list"
if [ "$must" = 1 ] && [ ! -s "$tmp/list" ]; then
	echo "skipgate: $list names no test, so --must-pass would hold nothing to account" >&2
	exit 2
fi

if [ $# -gt 0 ]; then
	cat -- "$@" >"$tmp/events"
else
	cat >"$tmp/events"
fi

# One line per test result, "<action> <package> <test>", and the packages' own result lines. A stream line
# that is not JSON (a panic that tore the stream, or go's own messages on a mixed stream) is passed over.
jq -Rr 'fromjson? | objects | select(.Test != null and (.Action == "pass" or .Action == "fail" or .Action == "skip"))
	| "\(.Action) \(.Package) \(.Test)"' "$tmp/events" >"$tmp/results"
if [ ! -s "$tmp/results" ]; then
	echo "skipgate: no test result in the stream: a gate that read nothing would pass vacuously" >&2
	exit 2
fi

# output PACKAGE TEST: what the test printed, indented, without go's own RUN/PAUSE/CONT lines.
output() {
	jq -Rrj --arg p "$1" --arg t "$2" 'fromjson? | objects | select(.Action == "output" and .Package == $p and .Test == $t)
		| .Output | select(test("^=== (RUN|PAUSE|CONT|NAME)") | not)' "$tmp/events" | sed 's/^/    /'
}

echo "== packages"
jq -Rrj 'fromjson? | objects | select((.Action == "output" and .Test == null and (.Output | test("^(ok|FAIL|\\?|---)")))
	or .Action == "build-output") | .Output' "$tmp/events"

failed=$(awk '$1 == "fail"' "$tmp/results")
if [ -n "$failed" ]; then
	echo
	echo "== failed tests"
	while read -r _ pkg test; do
		echo "--- FAIL: $test (${pkg#"$module"/})"
		output "$pkg" "$test"
	done <<<"$failed"
fi

status=0
echo
if [ "$must" = 1 ]; then
	echo "== must pass ($list)"
	while read -r pkg test; do
		# Over several streams (root-suites runs a package's plain and tegobpf builds), a test passed when some
		# stream passed it and none failed it: a plain build's skip of a test its tagged build ran is not a miss.
		got=$(awk -v p="$pkg" -v t="$test" '$2 == p && $3 == t { r[$1] = 1 }
			END { if ("fail" in r) print "fail"; else if ("pass" in r) print "pass"; else if ("skip" in r) print "skip" }' "$tmp/results")
		case "$got" in
		pass) echo "ok   ${pkg#"$module"/} $test" ;;
		"")
			echo "FAIL ${pkg#"$module"/} $test: never ran"
			status=1
			;;
		*)
			echo "FAIL ${pkg#"$module"/} $test: $got"
			output "$pkg" "$test"
			status=1
			;;
		esac
	done <"$tmp/list"
else
	echo "== skipped tests (allowed by $list or not)"
	# allowed PACKAGE TEST: the list names TEST, or one of its parents with "/*", which stands for all of that
	# test's subtests (a table test whose every case can skip for the same reason).
	allowed() {
		local t="$2"
		grep -qxF -- "$1 $t" "$tmp/list" && return 0
		while [ "${t%/*}" != "$t" ]; do
			t="${t%/*}"
			grep -qxF -- "$1 $t/*" "$tmp/list" && return 0
		done
		return 1
	}
	while read -r _ pkg test; do
		if allowed "$pkg" "$test"; then
			echo "allowed    ${pkg#"$module"/} $test"
		else
			echo "UNLISTED   ${pkg#"$module"/} $test"
			output "$pkg" "$test"
			status=1
		fi
	done < <(awk '$1 == "skip"' "$tmp/results")
	if [ "$status" = 1 ]; then
		echo "skipgate: a test skipped that $list does not allow: fix what made it skip, or list it with the reason" >&2
	fi
fi
exit "$status"
