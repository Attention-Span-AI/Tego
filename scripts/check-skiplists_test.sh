#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests the half of check-skiplists.sh that reads the workflows (CHECK_WORKFLOWS names a fixture directory): a
# test named in a `-test.run` pattern or in a `for t in ...` loop must be a func in the tree, so a gate that
# names a deleted test (it once left bpf-load red on every push) fails here instead. A pattern is unanchored
# as go test's is, comments are not read, and a loop's names may continue over lines. In a fixture tree it also tests
# that the root lists name only packages test/vm/suites.sh's PKGS starts as root.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-skiplists-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

fail=0
# try NAME WANT_EXIT WORKFLOW_BODY
try() {
	rm -rf "$tmp/wf" && mkdir "$tmp/wf"
	printf '%s\n' "$3" >"$tmp/wf/w.yml"
	set +e
	CHECK_WORKFLOWS="$tmp/wf" "$here/check-skiplists.sh" >"$tmp/out" 2>&1
	got=$?
	set -e
	if [ "$got" = "$2" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: exit $got, want $2" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}

try "tests that exist pass" 0 "run: t -test.run 'TestObjectsLoadOnThisKernel|TestNet.*OnRealKernel|TestFanotify'
  for t in TestObjectsLoadOnThisKernel TestNetVerdictOnRealKernel \\
           TestFanotifyRefusesDeniedRead; do"
try "a -test.run alternative with no func fails" 1 "run: t -test.run 'TestObjectsLoadOnThisKernel|TestGoneForGood'"
grep -q "TestGoneForGood" "$tmp/out" || { echo "FAIL the alternative is named" >&2; fail=1; }
try "a loop name with no func fails" 1 "  for t in TestObjectsLoadOnThisKernel TestGoneForGood; do"
grep -q "requires TestGoneForGood" "$tmp/out" || { echo "FAIL the loop name is named" >&2; fail=1; }
try "a name on a loop's continuation line is read" 1 "  for t in TestObjectsLoadOnThisKernel \\
           TestGoneForGood; do"
try "comments are not read" 0 "# -test.run 'TestGoneForGood'
      # for t in TestGoneForGood; do"
# root-suites.sh narrows a run with VM_RUN, which it hands go test as -test.run: the same pattern, the same check.
try "VM_RUN alternatives that exist pass" 0 "run: VM_HOST=sudo VM_RUN='TestObjectsLoadOnThisKernel|TestNet.*OnRealKernel' test/vm/root-suites.sh x"
try "a VM_RUN alternative with no func fails" 1 "run: VM_HOST=sudo VM_RUN='TestObjectsLoadOnThisKernel|TestGoneForGood' test/vm/root-suites.sh x"
grep -q "TestGoneForGood" "$tmp/out" || { echo "FAIL the VM_RUN alternative is named" >&2; fail=1; }
try "a commented VM_RUN is not read" 0 "# VM_RUN='TestGoneForGood' test/vm/root-suites.sh"
# Use an isolated index so this test never stages or deletes a caller's source file. A deleted
# tracked file must disappear from discovery while an untracked file with spaces remains visible.
fixture="$tmp/repo"
mkdir -p "$fixture/scripts" "$fixture/p" "$fixture/test/vm" "$fixture/.github/workflows"
cp "$here/check-skiplists.sh" "$here/tree-files.sh" "$fixture/scripts/"
printf 'module example.test/skiplists\n' >"$fixture/go.mod"
for list in test/unit-skips.txt test/integration-skips.txt test/vm/root-skips.txt test/vm/root-must-pass.txt; do
	printf '# empty fixture list\n' >"$fixture/$list"
done
printf 'PKGS=(\n\tp\n)\nHELPERS=()\n' >"$fixture/test/vm/suites.sh"
printf 'func TestRemoved(t *testing.T) {}\n' >"$fixture/p/removed_test.go"
printf 'func TestNewWithSpaces(t *testing.T) {}\n' >"$fixture/p/new with spaces_test.go"
git -C "$fixture" init -q
git -C "$fixture" add p/removed_test.go
rm "$fixture/p/removed_test.go"
printf "run: go test -test.run 'TestNewWithSpaces'\n" >"$fixture/.github/workflows/w.yml"
if "$fixture/scripts/check-skiplists.sh" >"$tmp/tree.out" 2>&1; then
	echo 'ok   deleted tracked and untracked spaced files use the current tree'
else
	echo 'FAIL current tree discovery' >&2
	sed 's/^/     /' "$tmp/tree.out" >&2
	fail=1
fi
printf "run: go test -test.run 'TestRemoved'\n" >"$fixture/.github/workflows/w.yml"
set +e
"$fixture/scripts/check-skiplists.sh" >"$tmp/tree.out" 2>&1
got=$?
set -e
if [ "$got" = 1 ] && grep -q 'TestRemoved, which matches no func' "$tmp/tree.out"; then
	echo 'ok   workflow referencing a deleted test still fails with its name'
else
	echo "FAIL removed test diagnostic: exit $got, want 1" >&2
	sed 's/^/     /' "$tmp/tree.out" >&2
	fail=1
fi
# A test root-skips.txt lets skip in the plain build only (an untagged: entry) may also be one the root run must see
# pass, which its tagged build does; any other entry in both lists is a mistake.
printf 'func TestBoth(t *testing.T) {}\n' >"$fixture/p/both_test.go"
printf "run: go test -test.run 'TestNewWithSpaces'\n" >"$fixture/.github/workflows/w.yml"
printf 'p TestBoth # must pass as root\n' >"$fixture/test/vm/root-must-pass.txt"
for c in "untagged: the plain build has no objects|0" "the kernel lacks it|1"; do
	printf 'p TestBoth # %s\n' "${c%|*}" >"$fixture/test/vm/root-skips.txt"
	set +e
	"$fixture/scripts/check-skiplists.sh" >"$tmp/both.out" 2>&1
	got=$?
	set -e
	if [ "$got" = "${c#*|}" ] && { [ "$got" = 0 ] || grep -q 'TestBoth is in both' "$tmp/both.out"; }; then
		echo "ok   a must-pass test with the skip \"${c%|*}\" exits $got"
	else
		echo "FAIL a must-pass test with the skip \"${c%|*}\": exit $got, want ${c#*|}" >&2
		sed 's/^/     /' "$tmp/both.out" >&2
		fail=1
	fi
done
# Row scoping adds metadata, never a bypass of the root registry's validation. A scoped test still has to exist,
# remain unique, belong to a root package, and stay disjoint from must-pass (apart from untagged: as before).
printf '# empty fixture list\n' >"$fixture/test/vm/root-must-pass.txt"
for c in 'p TestBoth row=rhel-9 # the driver is absent|0|' \
	'p TestBoth row= # missing row|1|malformed' \
	'p TestBoth row=fedora-* # no wildcard|1|malformed' \
	'p TestBoth rows=rhel-9 # unknown metadata|1|malformed' \
	'p TestGone row=rhel-9 # a deleted test|1|no func TestGone'; do
	rest=${c#*|} want=${rest%%|*} message=${rest#*|}
	printf '%s\n' "${c%%|*}" >"$fixture/test/vm/root-skips.txt"
	got=0
	"$fixture/scripts/check-skiplists.sh" >"$tmp/scoped.out" 2>&1 || got=$?
	if [ "$got" = "$want" ] && { [ -z "$message" ] || grep -qF "$message" "$tmp/scoped.out"; }; then
		echo "ok   scoped registry validation: ${c%%|*}"
	else
		echo "FAIL scoped registry validation: exit $got, want $want: ${c%%|*}" >&2
		sed 's/^/     /' "$tmp/scoped.out" >&2
		fail=1
	fi
done
printf 'p TestBoth row=rhel-9 # driver absent\np TestBoth row=fedora-7.2 # duplicate\n' >"$fixture/test/vm/root-skips.txt"
got=0
"$fixture/scripts/check-skiplists.sh" >"$tmp/scoped.out" 2>&1 || got=$?
if [ "$got" = 1 ] && grep -q 'is listed twice' "$tmp/scoped.out"; then
	echo 'ok   row metadata does not hide a duplicate registry entry'
else
	echo "FAIL scoped duplicate validation: exit $got" >&2
	fail=1
fi
printf 'p TestBoth row=rhel-9 # driver absent\n' >"$fixture/test/vm/root-skips.txt"
printf 'p TestBoth # must pass\n' >"$fixture/test/vm/root-must-pass.txt"
got=0
"$fixture/scripts/check-skiplists.sh" >"$tmp/scoped.out" 2>&1 || got=$?
if [ "$got" = 1 ] && grep -q 'TestBoth is in both' "$tmp/scoped.out"; then
	echo 'ok   row metadata does not hide a must-pass contradiction'
else
	echo "FAIL scoped must-pass validation: exit $got" >&2
	fail=1
fi
printf '# empty fixture list\n' >"$fixture/test/vm/root-must-pass.txt"
# The root lists name tests of the packages the root run starts (test/vm/suites.sh's PKGS): an entry for a package
# outside it allows a skip, or requires a pass, that no root run reaches (ADR 0100 named a KVM gate for the peer
# check while its package was missing from PKGS).
mkdir -p "$fixture/q"
printf 'func TestOutside(t *testing.T) {}\n' >"$fixture/q/outside_test.go"
printf '# empty fixture list\n' >"$fixture/test/vm/root-skips.txt"
for l in test/vm/root-skips.txt test/vm/root-must-pass.txt; do
	cp "$fixture/$l" "$tmp/saved"
	printf 'q TestOutside # a root-only test\n' >>"$fixture/$l"
	set +e
	"$fixture/scripts/check-skiplists.sh" >"$tmp/pkgs.out" 2>&1
	got=$?
	set -e
	if [ "$got" = 1 ] && grep -q "q TestOutside: q is not in test/vm/suites.sh's PKGS" "$tmp/pkgs.out"; then
		echo "ok   a $l entry for a package outside PKGS fails"
	else
		echo "FAIL a $l entry for a package outside PKGS: exit $got, want 1 naming it" >&2
		sed 's/^/     /' "$tmp/pkgs.out" >&2
		fail=1
	fi
	cp "$tmp/saved" "$fixture/$l"
done
if "$fixture/scripts/check-skiplists.sh" >"$tmp/pkgs.out" 2>&1; then
	echo "ok   entries for packages in PKGS pass"
else
	echo "FAIL entries for packages in PKGS:" >&2
	sed 's/^/     /' "$tmp/pkgs.out" >&2
	fail=1
fi
rm "$fixture/test/vm/suites.sh"
set +e
"$fixture/scripts/check-skiplists.sh" >"$tmp/pkgs.out" 2>&1
got=$?
set -e
if [ "$got" = 2 ] && grep -q "test/vm/suites.sh: no such list" "$tmp/pkgs.out"; then
	echo "ok   a missing test/vm/suites.sh exits 2"
else
	echo "FAIL a missing test/vm/suites.sh: exit $got, want 2" >&2
	sed 's/^/     /' "$tmp/pkgs.out" >&2
	fail=1
fi
exit "$fail"
