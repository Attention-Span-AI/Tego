#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests what measure-plane-verifier.sh decides around its guests: the table it prints from a console log (the largest
# count per plane build and the budget the test held it to), the exit code for a program over its budget (1), a guest
# that could not boot (97), a kernel that is not cached or a test binary that does not build (2), and that a queue lock
# is taken around every boot. The script runs as written from a copy in a tree of stand-ins: a go that "builds" by
# writing the -o file, and a kvm-run.sh that writes the console log a case gives it and exits with the code it gives.
# Nothing boots.
#
# Usage: test/vm/measure-plane-verifier_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-plane-verifier-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

repo="$tmp/repo"
mkdir -p "$repo/test/vm" "$tmp/cache/kernel" "$tmp/bin" "$tmp/consoles"
cp "$here/measure-plane-verifier.sh" "$repo/test/vm/"
for k in k-ok k-over k-noboot; do
	mkdir -p "$tmp/cache/kernel/$k"
	: >"$tmp/cache/kernel/$k/vmlinuz"
done

cat >"$tmp/bin/go" <<'STUB_GO'
#!/usr/bin/env bash
[ -z "${STUB_BUILD_FAIL:-}" ] || { echo "build failed" >&2; exit 1; }
while [ $# -gt 0 ]; do
	if [ "$1" = -o ]; then : >"$2"; fi
	shift
done
STUB_GO
cat >"$repo/test/vm/kvm-run.sh" <<'STUB_KVM'
#!/usr/bin/env bash
log=""
while [ $# -gt 0 ]; do
	case "$1" in
	--log) log="$2"; shift 2 ;;
	--) break ;;
	*) shift ;;
	esac
done
echo "$TEGO_VM_KERNEL" >>"$STUB_BOOTS"
cp "$STUB_CONSOLES/$TEGO_VM_KERNEL.console" "$log"
exit "$(cat "$STUB_CONSOLES/$TEGO_VM_KERNEL.rc")"
STUB_KVM
chmod +x "$tmp/bin/go" "$repo/test/vm/kvm-run.sh"

console() { # console KERNEL RD PR RDBUDGET PRBUDGET [over]
	cat >"$tmp/consoles/$1.console" <<CONSOLE
[    0.000000] Linux version 6.19.4-test (build@host)
=== RUN   TestPlaneLoadsAndAttaches/decide_rd
=== RUN   TestPlaneLoadsAndAttaches/decide_rd/lsm
    plane_load_integration_test.go:122: lsm_path_rename: $2 instructions verified
    plane_load_integration_test.go:122: lsm_path_mknod: 1000 instructions verified
    plane_budget_integration_test.go:1: decide_rd on 6.19.4-test: a plane program's budget is $4
=== RUN   TestPlaneLoadsAndAttaches/decide_pr
=== RUN   TestPlaneLoadsAndAttaches/decide_pr/lsm
    plane_load_integration_test.go:122: lsm_path_rename: $3 instructions verified
    plane_budget_integration_test.go:1: decide_pr on 6.19.4-test: a plane program's budget is $5
CONSOLE
	if [ -n "${6:-}" ]; then
		echo "    plane_load_integration_test.go:123: lsm_x: $3 instructions verified, over the budget of $5" >>"$tmp/consoles/$1.console"
	fi
}
run() { # run COMMAND...: sets out (stdout) and rc; stderr is kept in $tmp/err
	: >"$tmp/boots"
	out="$(env TEGO_VM_CACHE="$tmp/cache" GO="$tmp/bin/go" STUB_BOOTS="$tmp/boots" STUB_CONSOLES="$tmp/consoles" "$@" 2>"$tmp/err")"
	rc=$?
}
script="$repo/test/vm/measure-plane-verifier.sh"

# a kernel inside its budgets: the table has the largest counts and budgets, the exit is 0
console k-ok 100417 59387 110459 65326
echo 0 >"$tmp/consoles/k-ok.rc"
run "$script" -o "$tmp/out1" k-ok
[ "$rc" -eq 0 ] || fail "ok kernel: exit $rc, want 0: $out $(cat "$tmp/err")"
echo "$out" | grep -qE '^k-ok +6\.19\.4-test +100417 +59387 +110459 +65326 +PASS$' || fail "ok kernel: table row: $out"
[ -f "$tmp/out1/k-ok.console" ] && [ -f "$tmp/out1/table.txt" ] || fail "ok kernel: logs kept in the output folder"

# a program over its budget fails the run with exit 1 and says so
console k-over 111463 59387 110459 65326 over
echo 1 >"$tmp/consoles/k-over.rc"
run "$script" -o "$tmp/out2" k-ok k-over
[ "$rc" -eq 1 ] || fail "over budget: exit $rc, want 1: $out"
echo "$out" | grep -qE '^k-over .* FAIL\(rc=1,over=1\)$' || fail "over budget: table row: $out"
echo "$out" | grep -qE '^k-ok .* PASS$' || fail "over budget: the passing kernel is still listed: $out"

# a guest that cannot boot (97) is not a pass and ends the exit code at 97 even beside a failure
console k-noboot 0 0 0 0
echo 97 >"$tmp/consoles/k-noboot.rc"
run "$script" -o "$tmp/out3" k-over k-noboot
[ "$rc" -eq 97 ] || fail "no boot: exit $rc, want 97: $out"
echo "$out" | grep -q 'NOT-BOOTED(97)' || fail "no boot: table row: $out"

# a kernel that is not cached is a usage error before anything is built or booted
run "$script" -o "$tmp/out4" k-ok no-such-kernel
[ "$rc" -eq 2 ] || fail "missing kernel: exit $rc, want 2"
[ ! -s "$tmp/boots" ] || fail "missing kernel: a guest booted"
grep -q 'no-such-kernel/vmlinuz' "$tmp/err" || fail "missing kernel: message names it: $(cat "$tmp/err")"

# a test binary that does not build stops before any boot
run env STUB_BUILD_FAIL=1 "$script" -o "$tmp/out5" k-ok
[ "$rc" -eq 2 ] || fail "build failure: exit $rc, want 2"
[ ! -s "$tmp/boots" ] || fail "build failure: a guest booted"

# a queue lock is taken around the boot: with it free the run goes on, with it held elsewhere the boot waits
lock="$tmp/queue.lock"
: >"$lock"
run env TEGO_VM_QUEUE_LOCK="$lock" "$script" -o "$tmp/out6" k-ok
[ "$rc" -eq 0 ] || fail "queue lock free: exit $rc, want 0: $(cat "$tmp/err")"
(
	exec 9>"$lock"
	flock 9
	: >"$tmp/held"
	sleep 3
) &
holder=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[ -f "$tmp/held" ] && break
	sleep 0.2
done
start=$SECONDS
run env TEGO_VM_QUEUE_LOCK="$lock" "$script" -o "$tmp/out7" k-ok
wait "$holder"
[ "$rc" -eq 0 ] || fail "queue lock held: exit $rc, want 0"
[ $((SECONDS - start)) -ge 2 ] || fail "queue lock held: the boot did not wait ($((SECONDS - start)) s)"

echo "ok measure-plane-verifier_test"
