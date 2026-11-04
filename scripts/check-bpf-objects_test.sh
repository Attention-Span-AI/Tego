#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# check-bpf-objects_test.sh — check-bpf-objects.sh's detection, in a throwaway repository with a stand-in `make`
# (no clang, nothing fetched): a `make gen` that reproduces the committed files passes; one that changes an object,
# drops a file or adds one is refused (exit 1) with the file named and the fix command printed.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-check-bpf-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

repo="$tmp/repo"
mkdir -p "$repo/internal/bpf" "$tmp/bin"
printf 'object-a\n' >"$repo/internal/bpf/a_bpfel.o"
printf 'package bpf\n' >"$repo/internal/bpf/a_bpfel.go"
printf 'object-b\n' >"$repo/internal/bpf/b_bpfeb.o"
printf 'package bpf\n' >"$repo/internal/bpf/adoption_specs_gen.go"
git -C "$repo" init -q
git -C "$repo" add -- internal
git -C "$repo" -c user.name=t -c user.email=t@t commit -q -m init
# The stand-in make: `make -C DIR gen` runs $FAKE_GEN in DIR/internal/bpf.
cat >"$tmp/bin/make" <<'MK'
#!/bin/sh
cd "$2/internal/bpf" && eval "$FAKE_GEN"
MK
chmod +x "$tmp/bin/make"

fail=0
# run NAME WANT_EXIT WANT_TEXT FAKE_GEN
run() {
	local name=$1 want=$2 text=$3 rc=0
	FAKE_GEN=$4 PATH="$tmp/bin:$PATH" BPF_CHECK_REPO="$repo" BPF_CHECK_TMP="$tmp/scratch" \
		"$here/check-bpf-objects.sh" >"$tmp/out" 2>&1 || rc=$?
	if [ "$rc" -ne "$want" ] || ! grep -q -- "$text" "$tmp/out"; then
		echo "FAIL: $name: exit $rc (want $want, output with '$text')"
		sed 's/^/    /' "$tmp/out"
		fail=1
	else
		echo "ok   $name"
	fi
}
run "identical output passes" 0 "ok (4 files identical)" ":"
run "a tampered object is named" 1 "a_bpfel.o" "printf tampered >>a_bpfel.o"
run "stale adoption metadata is named" 1 "adoption_specs_gen.go" "printf tampered >>adoption_specs_gen.go"
run "dropped adoption metadata is named" 1 "adoption_specs_gen.go (committed" "rm -f adoption_specs_gen.go"
run "the fix command is printed" 1 "make gen" "printf x >>b_bpfeb.o"
run "a file make gen drops is named" 1 "b_bpfeb.o (committed" "rm -f b_bpfeb.o"
run "a file make gen adds is named" 1 "c_bpfel.o (made by make gen" "printf c >c_bpfel.o"
run "a failing make gen is a setup failure" 2 "make gen failed" "exit 1"
# A scratch path that is a symlink (or otherwise not ours) is refused before make gen runs.
rm -rf "$tmp/scratch"; mkdir "$tmp/elsewhere"; ln -s "$tmp/elsewhere" "$tmp/scratch"
run "a symlinked scratch path is refused" 2 "not a directory owned by you" ":"
rm -f "$tmp/scratch"
mkdir -m 777 "$tmp/scratch"
run "a pre-created loose-mode scratch dir is tightened" 0 "ok (4 files identical)" ":"
[ "$(stat -c %a "$tmp/scratch")" = 700 ] || { echo "FAIL: scratch mode not 0700"; fail=1; }
# The pre-marker tool leaves only its empty lock after a successful run. NET09's
# object changes make the full gate meet the demo cleanup guard on that state.
rm -f "$tmp/scratch/.tego-bpf-check"
run "a legacy empty lock can be migrated" 0 "ok (4 files identical)" ":"
[ -f "$tmp/scratch/.tego-bpf-check" ] || { echo "FAIL: legacy scratch was not marked"; fail=1; }

# This exception must never claim unmarked data, aliases or a failed listing.
rm -f "$tmp/scratch/.tego-bpf-check"
printf valuable >"$tmp/scratch/lock"
run "a nonempty legacy lock is refused" 2 "refusing nonempty" ":"
[ "$(cat "$tmp/scratch/lock")" = valuable ] && [ ! -e "$tmp/scratch/.tego-bpf-check" ] || {
	echo "FAIL: nonempty legacy lock changed or was claimed"; fail=1;
}
rm -f "$tmp/scratch/lock"
: >"$tmp/empty-lock"
ln "$tmp/empty-lock" "$tmp/scratch/lock"
run "a hard-linked legacy lock is refused" 2 "refusing nonempty" ":"
[ ! -e "$tmp/scratch/.tego-bpf-check" ] || { echo "FAIL: hard-linked lock was claimed"; fail=1; }
rm -f "$tmp/scratch/lock"
ln -s "$tmp/empty-lock" "$tmp/scratch/lock"
run "a symlinked legacy lock is refused" 2 "refusing nonempty" ":"
[ ! -e "$tmp/scratch/.tego-bpf-check" ] || { echo "FAIL: symlinked lock was claimed"; fail=1; }
rm -f "$tmp/scratch/lock"
: >"$tmp/scratch/lock"
entry=$'\n\n'
mkdir "$tmp/scratch/$entry"
printf valuable >"$tmp/scratch/$entry/keep"
run "legacy lock with newline-only state is refused" 2 "refusing nonempty" ":"
[ -f "$tmp/scratch/$entry/keep" ] && [ ! -e "$tmp/scratch/.tego-bpf-check" ] || {
	echo "FAIL: legacy state changed or was claimed"; fail=1;
}
rm -rf "$tmp/scratch/$entry"
printf '#!/bin/sh\necho "listing failed" >&2\nexit 71\n' >"$tmp/bin/find"
chmod +x "$tmp/bin/find"
run "failed legacy enumeration refuses migration" 2 "listing failed" ":"
[ ! -e "$tmp/scratch/.tego-bpf-check" ] || { echo "FAIL: failed listing claimed legacy scratch"; fail=1; }
rm -f "$tmp/bin/find"
run "legacy scratch recovers after a listing failure" 0 "ok (4 files identical)" ":"
# Generated scratch children are removed on exit; the lock and ownership marker stay.
shopt -s nullglob dotglob
for remaining in "$tmp/scratch"/*; do
	case ${remaining##*/} in lock|.tego-bpf-check) ;; *) echo "FAIL: scratch directory left behind: $remaining"; fail=1 ;; esac
done
[ "$fail" -eq 0 ] && echo "check-bpf-objects_test: ok"
exit "$fail"
