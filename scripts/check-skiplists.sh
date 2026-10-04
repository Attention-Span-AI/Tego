#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-skiplists.sh — the lists scripts/skipgate.sh reads name tests that exist, once each, and every root-only
# skip the unprivileged integration step allows is accounted for as root.
#
# Why it exists: an allowlist entry for a test that was renamed or deleted allows nothing and says nothing, and a
# must-pass entry for one fails only on the one runner that reads it; a skip the integration step allows because
# it needs root is allowed there on the promise that the root run holds it, which is true only when the root
# run's must-pass or skip list names it too.
#
# It checks, for test/unit-skips.txt, test/integration-skips.txt, test/vm/root-skips.txt and
# test/vm/root-must-pass.txt:
#   - every entry is "<package> <test> # <reason>", the package a directory of this module and the test's top-level
#     name a `func TestX(` in one of that directory's _test.go files (TestX/* and TestX/case name its subtests);
#   - no list names one test twice, and no test is both in root-skips.txt and root-must-pass.txt;
#   - every integration-skips.txt entry whose reason says root is in root-must-pass.txt or root-skips.txt;
#   - every root-skips.txt and root-must-pass.txt entry's package is in test/vm/suites.sh's PKGS, the packages a root
#     run starts: an entry for another package allows a skip, or requires a pass, that no root run reaches.
#
# It also checks the tests the workflows name: every alternative of a `-test.run '...'` pattern, or of a
# `VM_RUN='...'` assignment (test/vm/root-suites.sh's narrowing, which it hands go test as -test.run), in
# .github/workflows/*.yml must match a `func` in some _test.go file, and so must every name a `for t in ...; do`
# loop there greps for as `--- PASS: $t`. A pattern that matches nothing is not an error to go test, and the
# loop then fails the job on every run (or a renamed test leaves a gate that checks nothing).
#
# Usage: scripts/check-skiplists.sh   (from anywhere in the checkout)
# Exit: 0 when every list holds; 1 when one does not; 2 when a list is missing.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
module="$(sed -n 's/^module //p' go.mod)"
lists=(test/unit-skips.txt test/integration-skips.txt test/vm/root-skips.txt test/vm/root-must-pass.txt)
suites=test/vm/suites.sh
for l in "${lists[@]}" "$suites"; do
	[ -f "$l" ] || { echo "check-skiplists: $l: no such list" >&2; exit 2; }
done
# PKGS: the packages root-suites.sh, CI's root-suites job and the nightly's guests run as root.
# shellcheck source=test/vm/suites.sh
. "$suites"

status=0
fail() {
	echo "check-skiplists: $*"
	status=1
}

# entries LIST: "<lineno> <package> <test> <reason...>" per entry, the package without the module prefix.
entries() {
	local n=0 line entry reason pkg test extra
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		case "$line" in "" | "#"*) continue ;; esac
		entry="${line%%[[:space:]]#*}"
		reason="${line#"$entry"}"
		reason="${reason#*#}"
		read -r pkg test extra <<<"$entry" || true
		if [ -z "${pkg:-}" ] || [ -z "${test:-}" ] || [ -n "${extra:-}" ] || [ -z "${reason// /}" ]; then
			echo "$n - - malformed: $line"
			continue
		fi
		pkg="${pkg#"$module"/}"
		echo "$n $pkg $test $reason"
	done <"$1"
}

for l in "${lists[@]}"; do
	declare -A seen=()
	while read -r n pkg test reason; do
		if [ "$pkg" = - ]; then
			fail "$l:$n: want \"<package> <test> # <reason>\", got: ${reason#malformed: }"
			continue
		fi
		top="${test%%/*}"
		if ! [[ "$top" =~ ^Test[A-Za-z0-9_]*$ ]]; then
			fail "$l:$n: $pkg $test: not a test name"
			continue
		fi
		if [ -n "${seen["$pkg $test"]:-}" ]; then
			fail "$l:$n: $pkg $test is listed twice (first at line ${seen["$pkg $test"]})"
		fi
		seen["$pkg $test"]=$n
		if [ ! -d "$pkg" ]; then
			fail "$l:$n: $pkg: no such package directory"
			continue
		fi
		shopt -s nullglob
		files=("$pkg"/*_test.go)
		shopt -u nullglob
		if [ "${#files[@]}" -eq 0 ] || ! grep -q -- "^func $top(" "${files[@]}"; then
			fail "$l:$n: $pkg $test: no func $top( in $pkg/*_test.go"
		fi
	done < <(entries "$l")
	unset seen
done

# A test the root run both requires to pass and allows to skip is one of the two by mistake, but for an untagged:
# skip: that allows the skip in the plain build of a package whose tests load the objects only, and the must-pass
# list then holds the tagged build to running it (root-suites.sh: passed in some build, failed in none).
# The two sorted lists go through files: fed through two process substitutions, comm failed now and then with
# "file 1 is not in sorted order" on lists that sort -c accepts, and set -e ended the script with no finding.
skips=$(mktemp) musts=$(mktemp)
entries test/vm/root-skips.txt | awk '$2 != "-" && $4 != "untagged:" {print $2, $3}' | LC_ALL=C sort -u >"$skips"
entries test/vm/root-must-pass.txt | awk '$2 != "-" {print $2, $3}' | LC_ALL=C sort -u >"$musts"
both=$(LC_ALL=C comm -12 "$skips" "$musts")
rm -f "$skips" "$musts"
while read -r pkg test; do
	[ -n "$pkg" ] || continue
	fail "$pkg $test is in both test/vm/root-skips.txt and test/vm/root-must-pass.txt"
done <<<"$both"

# The unprivileged step's root-only skips: each must be held by the root run's must-pass list or named, with
# its reason, among the skips a root run allows. An allowed subtest pattern is held by its test's entry too.
rooted=$( { entries test/vm/root-skips.txt; entries test/vm/root-must-pass.txt; } | awk '$2 != "-" {print $2, $3}' | sort -u)
while read -r n pkg test reason; do
	[ "$pkg" != - ] || continue
	shopt -s nocasematch
	if [[ " $reason " =~ [^A-Za-z]root[^A-Za-z] ]]; then
		shopt -u nocasematch
		if ! grep -qxF -- "$pkg $test" <<<"$rooted" && ! grep -qxF -- "$pkg ${test%%/*}" <<<"$rooted" &&
			! grep -qxF -- "$pkg ${test%%/*}/*" <<<"$rooted"; then
			fail "test/integration-skips.txt:$n: $pkg $test skips for root (\"${reason# }\"), but neither test/vm/root-must-pass.txt nor test/vm/root-skips.txt names it"
		fi
	fi
	shopt -u nocasematch
done < <(entries test/integration-skips.txt)

# The root lists' packages are ones the root run starts. ADR 0100's Tests section named a KVM gate for the peer
# check while internal/platform/peer was in no suite; an entry for such a package
# is the same promise in a list.
for l in test/vm/root-skips.txt test/vm/root-must-pass.txt; do
	while read -r n pkg test reason; do
		[ "$pkg" != - ] || continue
		started=no
		for p in "${PKGS[@]}"; do
			if [ "$p" = "$pkg" ]; then
				started=yes
				break
			fi
		done
		[ "$started" = yes ] || fail "$l:$n: $pkg $test: $pkg is not in $suites's PKGS, so no root run starts it"
	done < <(entries "$l")
done

# The tests the workflows run and require. CHECK_WORKFLOWS names another directory (the script's own test).
wfdir="${CHECK_WORKFLOWS:-.github/workflows}"
shopt -s nullglob
wfs=("$wfdir"/*.yml)
shopt -u nullglob
# The repository's own test files (tracked, or new and not ignored), never a nested checkout under .claude/worktrees,
# and only their func lines: the concatenation of every worktree's tests made grep's regex overflow its stack.
tests_tree=$(./scripts/tree-files.sh | while IFS= read -r -d '' test_file; do
	case "$test_file" in
		*_test.go) printf '%s\0' "$test_file" ;;
	esac
done | xargs -0 -r grep -h '^func ' --)
for wf in "${wfs[@]}"; do
	while IFS= read -r pat; do
		IFS='|' read -ra alts <<<"$pat"
		for alt in "${alts[@]}"; do
			grep -Eq -- "^func [A-Za-z0-9_]*(${alt})[A-Za-z0-9_]*\(" <<<"$tests_tree" ||
				fail "$wf: -test.run (or VM_RUN) names $alt, which matches no func in any _test.go file"
		done
	done < <(grep -v '^[[:space:]]*#' "$wf" | grep -oE -- "(-test\.run |VM_RUN=)'[^']*'" | sed -E "s/^(-test\.run |VM_RUN=)'(.*)'\$/\2/")
	while read -r name; do
		[ -n "$name" ] || continue
		grep -q -- "^func ${name}(" <<<"$tests_tree" ||
			fail "$wf: a --- PASS loop requires $name, which is no func in any _test.go file"
	done < <(awk '/^[[:space:]]*#/ { next }
		/for t in / { on = 1 }
		on { line = $0; if (sub(/.*for t in /, "", line) == 0) {} sub(/;[[:space:]]*do.*/, "", line); n = split(line, w, /[[:space:]\\]+/)
			for (i = 1; i <= n; i++) if (w[i] ~ /^Test/) print w[i]
			if ($0 ~ /;[[:space:]]*do/) on = 0 }' "$wf")
done

if [ "$status" = 0 ]; then
	echo "check-skiplists: ${lists[*]} hold"
fi
exit "$status"
