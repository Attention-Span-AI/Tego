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
#   - every entry is "<package> <test> [row=ROW] # <reason>", the package a directory of this module and the test's top-level
#     name a `func TestX(` in one of that directory's _test.go files (TestX/* and TestX/case name its subtests);
#   - no list names one test twice, and no test is both in root-skips.txt and root-must-pass.txt;
#   - every integration-skips.txt entry whose reason says root is in root-must-pass.txt or root-skips.txt;
#   - every root-skips.txt and root-must-pass.txt entry's package is in test/vm/suites.sh's PKGS, the packages a root
#     run starts: an entry for another package allows a skip, or requires a pass, that no root run reaches.
#   - every scoped row exists in fetch-kernel.py's inventory, and a row-scoped must-pass entry has a direct,
#     full-package root-suites dispatch on that row in .github/workflows/vm-matrix.yml.
#
# It reads the test files too, for the skips no list names yet (tools/rootskips: a test that skips, or may skip, for
# want of root, in the unprivileged unit build and in the integration build). Each must be allowed by the step's list,
# by scripts/skipgate.sh's own rule (the candidates go to it as a stream of skip results); an entry's reason that says
# root is held by the root lists as above. Without it a new needs-root test that skips and is listed nowhere passed
# this check and failed only the full gate, half an hour later (gates 23 and 28). It needs go and jq.
# A pass is not "no unlisted needs-root skip exists": the tool's doc comment (tools/rootskips/main.go) says which
# shapes it reads, which it reads loosely (a candidate where it cannot tell) and which it cannot see at all.
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
	local n=0 line entry reason pkg test scope extra
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		case "$line" in "" | "#"*) continue ;; esac
		entry="${line%%[[:space:]]#*}"
		reason="${line#"$entry"}"
		reason="${reason#*#}"
		read -r pkg test scope extra <<<"$entry" || true
		if [ -z "${pkg:-}" ] || [ -z "${test:-}" ] || [ -n "${extra:-}" ] || [ -z "${reason// /}" ] ||
			{ [ -n "${scope:-}" ] && ! [[ "$scope" =~ ^row=[a-z0-9][a-z0-9.-]*$ ]]; }; then
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
			fail "$l:$n: malformed entry: want \"<package> <test> [row=ROW] # <reason>\", got: ${reason#malformed: }"
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

# Syntax alone cannot establish a row obligation: a typo or an unscheduled package would leave the global skip
# allowance active everywhere. The offline checker reads the inventory and the workflow's direct dispatches.
python3 scripts/check-skiprows.py || status=1

# A test the root run both requires to pass and allows to skip is one of the two by mistake, but for an untagged:
# skip: that allows the skip in the plain build of a package whose tests load the objects only, and the must-pass
# list then holds the tagged build to running it (root-suites.sh: passed in some build, failed in none).
# The two sorted lists go through files: fed through two process substitutions, comm failed now and then with
# "file 1 is not in sorted order" on lists that sort -c accepts, and set -e ended the script with no finding.
skips=$(mktemp) musts=$(mktemp)
entries test/vm/root-skips.txt | awk '$2 != "-" && $4 != "untagged:" {print $2, $3}' | LC_ALL=C sort -u >"$skips"
# A row-scoped must-pass entry beside an unscoped skip is the other pairing on purpose: the test may skip where
# root-skips.txt says, and must pass on that one row. Only unscoped must-pass entries take part in this check.
entries <(grep -Ev '^[^#]*[[:space:]]row=[a-z0-9][a-z0-9.-]*[[:space:]]+#' test/vm/root-must-pass.txt) |
	awk '$2 != "-" {print $2, $3}' | LC_ALL=C sort -u >"$musts"
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

# The skips nobody listed yet: the tests that skip, or may skip, for want of root (tools/rootskips reads the syntax
# tree), in the two unprivileged builds the CI steps run. A "test" candidate (its own statements skip for a process
# that is not root, directly or through a helper) becomes a skip result in a go test -json stream and goes through
# scripts/skipgate.sh with the step's list, so the rule that allows a skip is that script's, the one the step itself
# applies; a "sub" candidate (the skip is somewhere the tool cannot name: a subtest's closure, a branch, a loop, or
# under a condition that also holds another term) needs an entry for its test or one of its subtests. Whether the
# root run holds a listed entry is the loop above's rule (a reason that says root), unchanged: an entry that says
# only "needs CAP_SYS_ADMIN" is not asked for. A skip that is no needs-root skip is cleared in the test file by a
# `// rootskips:ignore <reason>` comment on its line or the line before; nothing here lists a test on its own.
rootskips_check() { # LABEL LIST TOOLFLAGS...
	local label=$1 list=$2 pkg_path dir test kind pos events cand gate_out rc unlisted
	shift 2
	cand=$(mktemp) events=$(mktemp)
	if ! "$tool" "$@" . >"$cand"; then
		fail "$label: tools/rootskips could not read the test files"
		rm -f "$cand" "$events"
		return
	fi
	while IFS=$'\t' read -r dir test kind pos; do
		[ -n "$test" ] || continue
		if [ "$dir" = . ]; then pkg_path=$module; else pkg_path=$module/$dir; fi
		if [ "$kind" = test ]; then
			printf '{"Action":"skip","Package":"%s","Test":"%s"}\n' "$pkg_path" "$test" >>"$events"
		elif ! entries "$list" | awk -v p="$dir" -v t="$test" '$2 == p && ($3 == t || index($3, t "/") == 1) { ok = 1 } END { exit !ok }'; then
			fail "$label: $dir $test ($pos) may skip for want of root (in a branch, a closure or a subtest), and $list names neither it nor one of its subtests"
		fi
	done <"$cand"
	if [ -s "$events" ]; then
		rc=0
		gate_out=$(./scripts/skipgate.sh "$list" "$events" 2>&1) || rc=$?
		if [ "$rc" != 0 ]; then
			unlisted=0
			while read -r _ dir test; do
				unlisted=1
				fail "$label: $dir $test skips for want of root and $list does not allow it (list it with its reason, and in the root lists)"
			done < <(grep '^UNLISTED' <<<"$gate_out" || true)
			[ "$unlisted" = 1 ] || fail "$label: scripts/skipgate.sh gave no verdict (exit $rc): $gate_out"
		fi
	fi
	rm -f "$cand" "$events"
}
command -v jq >/dev/null || { echo "check-skiplists: needs jq (scripts/skipgate.sh judges the root-gated tests)" >&2; exit 2; }
tool_dir=$(mktemp -d)
trap 'rm -rf "$tool_dir"' EXIT
tool=$tool_dir/rootskips
if "${GO:-go}" build -o "$tool" ./tools/rootskips; then
	rootskips_check "unit build" test/unit-skips.txt -cgo
	rootskips_check "integration build" test/integration-skips.txt -tags integration
else
	fail "tools/rootskips does not build"
fi

# The skips of the root run itself: a test that skips when the process IS root (`if os.Geteuid() == 0 { t.Skip(...) }`,
# the usual shape of a test that makes its failure with a mode bit, which root passes) is no candidate in the two builds
# above, which are not root, and was found only by a root run: the strict skip gate printed UNLISTED five of them after a
# three-hour guest run. tools/rootskips -asroot reads them from the syntax tree, in the builds the root run makes
# (-tags integration, and with tegobpf), and each one in a package the root run starts must be named, with its reason, in
# test/vm/root-skips.txt (or held by test/vm/root-must-pass.txt, for a skip that is conditional and never taken there): as
# the test, as an ancestor of the subtest ("TestX", "TestX/*", or its full name), or, where
# the tool cannot name the subtest (a name that is no literal, shown as "*"), as any entry of that test. The tool's doc
# comment says which shapes it reads. A skip that is no root skip is cleared in the test file with `// rootskips:ignore`.
asroot_check() {
	local dir test kind pos p in_pkgs found
	found=$({ "$tool" -asroot -tags integration . && "$tool" -asroot -tags integration,tegobpf .; } | LC_ALL=C sort -u) || {
		fail "tools/rootskips -asroot could not read the test files"
		return
	}
	while IFS=$'\t' read -r dir test kind pos; do
		[ -n "$test" ] || continue
		in_pkgs=no
		for p in "${PKGS[@]}"; do
			[ "$p" = "$dir" ] && in_pkgs=yes
		done
		[ "$in_pkgs" = yes ] || continue
		{ entries test/vm/root-skips.txt; entries test/vm/root-must-pass.txt; } | awk -v p="$dir" -v r="$test" '
			function top(x) { i = index(x, "/"); return i ? substr(x, 1, i - 1) : x }
			$2 == p {
				e = $3
				if (e == r || e == top(r) || index(r, e "/") == 1) ok = 1
				if (e ~ /\/\*$/ && index(r, substr(e, 1, length(e) - 1)) == 1) ok = 1
				if (r ~ /\/\*/ && top(e) == top(r)) ok = 1
			}
			END { exit !ok }' ||
			fail "root run: $dir $test ($pos) skips when the process is root and test/vm/root-skips.txt names neither it nor its test (make it run as root, e.g. testutil.RerunAsOrdinaryUser, or list it with the true reason)"
	done <<<"$found"
}
if [ -x "$tool" ]; then
	asroot_check
fi

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
