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
# The workflow cases run in a small tree of their own, not this checkout's: they hold only the test names the
# workflows below name, so they do not depend on the real tree's lists (a needs-root test that skips and is listed
# nowhere would otherwise fail four unrelated-looking cases) and do not read the whole tree for each case.
wfx="$tmp/wfx"
mkdir -p "$wfx/scripts" "$wfx/p" "$wfx/tools" "$wfx/test/vm" "$wfx/.github/workflows"
cp "$here/check-skiplists.sh" "$here/tree-files.sh" "$here/check-skiprows.py" "$here/skipgate.sh" "$wfx/scripts/"
cp -r "$here/../tools/rootskips" "$wfx/tools/"
rm -f "$wfx/tools/rootskips/"*_test.go
printf 'module example.test/wfx\n' >"$wfx/go.mod"
for list in test/unit-skips.txt test/integration-skips.txt test/vm/root-skips.txt test/vm/root-must-pass.txt; do
	printf '# empty fixture list\n' >"$wfx/$list"
done
printf 'PKGS=(\n\tp\n)\nHELPERS=()\n' >"$wfx/test/vm/suites.sh"
printf 'print("rhel-9 5.14 rpm full RHEL")\n' >"$wfx/test/vm/fetch-kernel.py"
printf '# no scoped must-pass obligation in this fixture\n' >"$wfx/.github/workflows/vm-matrix.yml"
printf 'package p\n\nimport "testing"\n\nfunc TestObjectsLoadOnThisKernel(t *testing.T) {}\n\nfunc TestNetVerdictOnRealKernel(t *testing.T) {}\n\nfunc TestFanotifyRefusesDeniedRead(t *testing.T) {}\n' >"$wfx/p/names_test.go"
git -C "$wfx" init -q
# try NAME WANT_EXIT WORKFLOW_BODY
try() {
	rm -rf "$tmp/wf" && mkdir "$tmp/wf"
	printf '%s\n' "$3" >"$tmp/wf/w.yml"
	set +e
	CHECK_WORKFLOWS="$tmp/wf" "$wfx/scripts/check-skiplists.sh" >"$tmp/out" 2>&1
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
# check-skiprows.py reads the last line of every step's run block (a continued call at a step's end used to reach
# shlex with a lone backslash and fail the whole check).
if python3 "$here/check-skiprows_test.py" >"$tmp/skiprows.out" 2>&1; then
	echo 'ok   check-skiprows.py reads the last line of a run block'
else
	echo 'FAIL check-skiprows.py unit tests:' >&2
	sed 's/^/     /' "$tmp/skiprows.out" >&2
	fail=1
fi
# Use an isolated index so this test never stages or deletes a caller's source file. A deleted
# tracked file must disappear from discovery while an untracked file with spaces remains visible.
fixture="$tmp/repo"
mkdir -p "$fixture/scripts" "$fixture/p" "$fixture/test/vm" "$fixture/.github/workflows"
cp "$here/check-skiplists.sh" "$here/tree-files.sh" "$here/check-skiprows.py" "$here/skipgate.sh" "$fixture/scripts/"
# tools/rootskips is stdlib-only, so it builds in the fixture's own module.
mkdir -p "$fixture/tools"
cp -r "$here/../tools/rootskips" "$fixture/tools/"
rm -f "$fixture/tools/rootskips/"*_test.go
printf 'module example.test/skiplists\n' >"$fixture/go.mod"
for list in test/unit-skips.txt test/integration-skips.txt test/vm/root-skips.txt test/vm/root-must-pass.txt; do
	printf '# empty fixture list\n' >"$fixture/$list"
done
printf 'PKGS=(\n\tp\n)\nHELPERS=()\n' >"$fixture/test/vm/suites.sh"
printf 'print("rhel-9 5.14 rpm full RHEL")\nprint("fedora-7.2 7.2 koji full Fedora")\n' >"$fixture/test/vm/fetch-kernel.py"
printf '# no scoped must-pass obligation in this fixture\n' >"$fixture/.github/workflows/vm-matrix.yml"
printf 'package p\n\nfunc TestRemoved(t *testing.T) {}\n' >"$fixture/p/removed_test.go"
printf 'package p\n\nfunc TestNewWithSpaces(t *testing.T) {}\n' >"$fixture/p/new with spaces_test.go"
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
printf 'package p\n\nfunc TestBoth(t *testing.T) {}\n' >"$fixture/p/both_test.go"
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
	'p TestBoth row=rhel-90 # misspelled row|1|unknown matrix row rhel-90' \
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
printf 'package q\n\nfunc TestOutside(t *testing.T) {}\n' >"$fixture/q/outside_test.go"
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
# The skips no list names yet (tools/rootskips reads the test files; scripts/skipgate.sh's rule judges them): a test
# that skips for want of root, itself or through a helper of its package, must be allowed by the step's list, in the
# plain build (test/unit-skips.txt) and the integration build (test/integration-skips.txt). Gates 23 and 28 found two
# only when the whole integration step ran.
printf '# empty fixture list\n' >"$fixture/test/vm/root-skips.txt"
printf '# empty fixture list\n' >"$fixture/test/vm/root-must-pass.txt"
printf "run: go test -test.run 'TestNewWithSpaces'\n" >"$fixture/.github/workflows/w.yml"
rm -f "$fixture/p/both_test.go"
cat >"$fixture/p/needsroot_test.go" <<'GO'
package p

import (
	"os"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestDirectGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestViaHelper(t *testing.T) {
	requireRoot(t)
}

func TestRootRunSkip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the dashboard refuses to run as root")
	}
}
GO
cat >"$fixture/p/integ_integration_test.go" <<'GO'
//go:build integration

package p

import (
	"os"
	"testing"
)

func TestIntegrationRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestIntegrationSub(t *testing.T) {
	t.Run("x", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root")
		}
	})
}
GO
cat >"$fixture/p/bpf_bpf_test.go" <<'GO'
//go:build tegobpf

package p

import (
	"os"
	"testing"
)

func TestOnlyWithObjects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}
GO
cat >"$fixture/p/plain_test.go" <<'GO'
package p

import "testing"

func TestPlain(t *testing.T) {}
GO
# rootskips NAME WANT_EXIT MESSAGE...: the script's exit status, and each MESSAGE somewhere in its output.
rootskips() {
	rs_name=$1 rs_want=$2 rs_got=0
	shift 2
	"$fixture/scripts/check-skiplists.sh" >"$tmp/rs.out" 2>&1 || rs_got=$?
	if [ "$rs_got" = "$rs_want" ]; then
		for rs_m in "$@"; do
			grep -qF -- "$rs_m" "$tmp/rs.out" || rs_got="no \"$rs_m\""
		done
	fi
	if [ "$rs_got" = "$rs_want" ]; then
		echo "ok   $rs_name"
	else
		echo "FAIL $rs_name: $rs_got, want exit $rs_want with the messages" >&2
		sed 's/^/     /' "$tmp/rs.out" >&2
		fail=1
	fi
}
rootskips "unlisted needs-root skips fail, a direct gate and a helper's alike, in the plain build" 1 \
	'unit build: p TestDirectGate' 'unit build: p TestViaHelper'
if grep -qE 'TestOnlyWithObjects|TestPlain' "$tmp/rs.out"; then
	echo "FAIL a tegobpf-only file and a plain test are named" >&2
	fail=1
else
	echo "ok   a tegobpf-only file and a plain test are not candidates"
fi
# A test that skips when the process is root is named (check-skiplists.sh, the root run's lists): the unprivileged
# scan reads the skips of a process that is not root, which this one is none of.
if grep -qF 'root run: p TestRootRunSkip' "$tmp/rs.out"; then
	echo "ok   a skip under euid == 0 is named for the root run's lists"
else
	echo "FAIL a skip under euid == 0 is not named for the root run's lists" >&2
	sed 's/^/     /' "$tmp/rs.out" >&2
	fail=1
fi
printf 'p TestDirectGate # needs root\np TestViaHelper # needs root\n' >>"$fixture/test/unit-skips.txt"
printf 'p TestDirectGate # needs root\np TestViaHelper # needs root\n' >>"$fixture/test/integration-skips.txt"
printf 'p TestDirectGate # root only\np TestViaHelper # root only\np TestRootRunSkip # root only\n' >"$fixture/test/vm/root-skips.txt"
rootskips "the plain build's tests pass once listed; the integration build's file is still unlisted" 1 \
	'integration build: p TestIntegrationRoot'
if grep -q 'unit build' "$tmp/rs.out"; then
	echo "FAIL the listed plain-build tests are named again" >&2
	fail=1
fi
printf 'p TestIntegrationRoot # needs root\n' >>"$fixture/test/integration-skips.txt"
printf 'p TestIntegrationRoot # root only\n' >>"$fixture/test/vm/root-skips.txt"
rootskips "a skip in a subtest's closure needs an entry for its test or one of its subtests" 1 \
	'p TestIntegrationSub' 'may skip for want of root'
printf 'p TestIntegrationSub/x # needs root\n' >>"$fixture/test/integration-skips.txt"
printf 'p TestIntegrationSub # root only\n' >>"$fixture/test/vm/root-skips.txt"
rootskips "with every needs-root skip listed the lists hold" 0 'hold'
# Five shapes the first version of the tool missed (review finding F1; the script exited 0 on a tree holding
# all of them): a skip in an if-else, a method as the helper, a helper in another package, a switch case, and a subtest
# function kept in a variable. None has a message that says root, so the message rule cannot rescue them. Each must fail
# the check, and the controls beside them (a skip for a tool, a skip in the root run) must not.
mkdir -p "$fixture/zzhelp" "$fixture/zzprobe"
cat >"$fixture/zzhelp/help.go" <<'GO'
package zzhelp

import (
	"os"
	"testing"
)

func RequireRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	}
}
GO
cat >"$fixture/zzprobe/probe_test.go" <<'GO'
package zzprobe

import (
	"os"
	"testing"

	"example.test/skiplists/zzhelp"
)

type env struct{}

func (env) requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	}
}

func TestElseBranch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	} else {
		t.Log("root")
	}
}

func TestViaMethod(t *testing.T) { env{}.requireRoot(t) }

func TestCrossPkg(t *testing.T) { zzhelp.RequireRoot(t) }

func TestInSwitch(t *testing.T) {
	switch {
	case os.Geteuid() != 0:
		t.Skip("skipping")
	}
}

func TestSubtestVar(t *testing.T) {
	f := func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("skipping")
		}
	}
	t.Run("a", f)
}

func TestControlTool(t *testing.T) {
	if os.Getenv("NO_TOOL") != "" {
		t.Skip("no tool")
	}
}

func TestControlRootRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the dashboard refuses to run as root")
	}
}
GO
rootskips "the five shapes of the first version's blind spot fail the check, in each build" 1 \
	'unit build: zzprobe TestElseBranch' 'unit build: zzprobe TestViaMethod' 'unit build: zzprobe TestCrossPkg' \
	'unit build: zzprobe TestInSwitch' 'unit build: zzprobe TestSubtestVar' 'integration build: zzprobe TestInSwitch'
if grep -qE 'TestControl' "$tmp/rs.out"; then
	echo "FAIL a skip for a tool, or in the root run, is named" >&2
	fail=1
else
	echo "ok   the controls beside the five shapes are not candidates"
fi
rm -r "$fixture/zzhelp" "$fixture/zzprobe"
rm "$fixture/p/needsroot_test.go" "$fixture/p/integ_integration_test.go" "$fixture/p/bpf_bpf_test.go" "$fixture/p/plain_test.go"
for l in test/unit-skips.txt test/integration-skips.txt test/vm/root-skips.txt; do printf '# empty fixture list\n' >"$fixture/$l"; done

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
