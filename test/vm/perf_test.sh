#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests what perf.sh decides before and around its one guest: which kernel the suite measures. `make vm-perf` boots
# this host's own kernel, and PERF_KERNEL=<row> boots a kernel-matrix row's instead (fetch-kernel.py fetches it, as
# matrix.sh does), which is how the cold-start campaign reads the rows beside 6.17 (the budgets are the 6.17 guest's;
# another row's figures are numbers to record, since a limit set on one kernel is not a verdict on another). A row that
# is not one, a doctor-only row (no tier is offered there, so there is nothing to measure), a kernel set by hand for
# another row and a kernel that cannot be fetched stop before anything is built; and a guest that did run is booted on
# the row's kernel, with its console log named for the row, so rows do not overwrite one another.
#
# perf.sh runs as written, from a copy of test/vm in a tree of stand-ins: a go that "builds" by writing a file, a
# fetch-kernel.py that names rows and fails on request, and a kvm-run.sh that records the kernel and the LSM it was given
# and the arguments of the boot, then reports the exit code it is told. Nothing boots and no network is used.
#
# Usage: test/vm/perf_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-perf-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

repo="$tmp/repo"
mkdir -p "$repo/test/vm" "$repo/cmd/tego" "$repo/test/perf/cmd/openbench" "$repo/test/perf/cmd/execbench" "$repo/test/perf/cmd/perfsuite" "$tmp/bin"
cp "$here/perf.sh" "$repo/test/vm/"

# fetch-kernel.py: STUB_ROWS is "name:body ..." (default row-a:full row-d:doctor-only); a fetch of the row named by
# STUB_FETCH_FAIL exits 97, as the real one does when the box cannot get the kernel; every fetch is logged.
cat >"$repo/test/vm/fetch-kernel.py" <<'EOF'
import os, sys
rows = dict(r.split(":") for r in os.environ.get("STUB_ROWS", "row-a:full row-d:doctor-only").split())
a = sys.argv[1:]
if a[:1] == ["--name"] and len(a) == 2 and a[1] in rows:
    print("matrix-" + a[1])
elif a[:1] == ["--body"] and len(a) == 2 and a[1] in rows:
    print(rows[a[1]])
elif len(a) == 1 and a[0] in rows:
    with open(os.environ["STUB_FETCHES"], "a") as f:
        f.write(a[0] + "\n")
    if a[0] == os.environ.get("STUB_FETCH_FAIL"):
        print("fetch-kernel: " + a[0] + ": the mirror no longer carries the package", file=sys.stderr)
        sys.exit(97)
    print("/stub/" + a[0] + "/vmlinuz")
else:
    sys.exit(2)
EOF

# kvm-run.sh: one line per boot with the kernel and LSM it was given, the memory, the log it was told and the command.
cat >"$repo/test/vm/kvm-run.sh" <<'EOF'
#!/usr/bin/env bash
log=""
args=("$@")
while [ $# -gt 0 ]; do
	case "$1" in
	--log) log="$2"; shift 2 ;;
	--) shift; break ;;
	*) shift ;;
	esac
done
echo "kernel=${TEGO_VM_KERNEL-unset} lsm=${TEGO_VM_LSM-unset} mem=${TEGO_VM_MEM-unset} log=$(basename "$log") cmd=$*" >>"$STUB_BOOTS"
[ -z "$log" ] || echo "guest console" >"$log"
exit "${STUB_GUEST_RC:-0}"
EOF
chmod +x "$repo/test/vm/kvm-run.sh"

# go: build writes the file it is asked for with -o, and every call is logged.
cat >"$tmp/bin/go" <<EOF
#!/usr/bin/env bash
echo "\$*" >>"$tmp/go.log"
out=""
while [ \$# -gt 0 ]; do [ "\$1" != -o ] || out="\$2"; shift; done
[ -z "\$out" ] || { printf '#!/bin/sh\nexit 0\n' >"\$out"; chmod +x "\$out"; }
EOF
chmod +x "$tmp/bin/go"

# run_perf runs the copy of perf.sh with the given variables and arguments after --; its status is in $rc, its stderr in
# $tmp/err, and the guest boots (one line each) in $tmp/boots.
run_perf() {
	local vars=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
	[ "${1:-}" != -- ] || shift
	rm -f "$tmp/boots" "$tmp/fetches" "$tmp/go.log"
	: >"$tmp/boots"
	: >"$tmp/fetches"
	rc=0
	env -i PATH="$tmp/bin:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/bin/go" PERF_OUT="$tmp/perf-out" \
		STUB_BOOTS="$tmp/boots" STUB_FETCHES="$tmp/fetches" "${vars[@]+"${vars[@]}"}" \
		bash "$repo/test/vm/perf.sh" "$@" >"$tmp/out" 2>"$tmp/err" || rc=$?
}

# 1. With no PERF_KERNEL the guest boots this host's kernel, as it always did: the kernel is not set, the log is
# perf-<boot>.console, nothing is fetched, and the suite's own arguments reach the guest.
run_perf -- -checks start
[ "$rc" = 0 ] || fail "no PERF_KERNEL: exited $rc: $(cat "$tmp/err")"
[ "$(wc -l <"$tmp/boots")" -eq 1 ] || fail "no PERF_KERNEL: $(wc -l <"$tmp/boots") boots, want 1"
grep -q 'kernel=unset lsm=unset ' "$tmp/boots" || fail "no PERF_KERNEL: the guest was handed a kernel or an LSM: $(cat "$tmp/boots")"
grep -q 'log=perf-bpf.console cmd=/usr/local/bin/perfsuite -checks start$' "$tmp/boots" || fail "no PERF_KERNEL: log or command wrong: $(cat "$tmp/boots")"
[ ! -s "$tmp/fetches" ] || fail "no PERF_KERNEL: a kernel was fetched: $(cat "$tmp/fetches")"

# 2. PERF_KERNEL=<row>: the row is fetched once, before anything is built, the guest boots its kernel, and its console
# log carries the row so another row's run does not replace it. PERF_BOOT is as it was: default boots the kernel's own LSM list.
run_perf PERF_KERNEL=row-a -- -checks cold
[ "$rc" = 0 ] || fail "PERF_KERNEL=row-a: exited $rc: $(cat "$tmp/err")"
[ "$(cat "$tmp/fetches")" = row-a ] || fail "PERF_KERNEL=row-a fetched \"$(cat "$tmp/fetches")\", want row-a once"
grep -q 'kernel=matrix-row-a lsm=unset .*log=perf-row-a-bpf.console cmd=/usr/local/bin/perfsuite -checks cold$' "$tmp/boots" ||
	fail "PERF_KERNEL=row-a: the guest was not booted on the row's kernel with the row's log: $(cat "$tmp/boots")"
grep -q 'row-a' "$tmp/err" || fail "PERF_KERNEL=row-a: stderr does not name the row: $(cat "$tmp/err")"
run_perf PERF_KERNEL=row-a PERF_BOOT=default --
grep -q 'kernel=matrix-row-a lsm=kernel .*log=perf-row-a-default.console' "$tmp/boots" ||
	fail "PERF_KERNEL=row-a PERF_BOOT=default: $(cat "$tmp/boots")"
run_perf PERF_BOOT=default --
grep -q 'kernel=unset lsm=kernel .*log=perf-default.console' "$tmp/boots" || fail "PERF_BOOT=default alone: $(cat "$tmp/boots")"

# 3. The row `host` is this box's own kernel, named: nothing is fetched, and the guest is handed uname -r.
run_perf PERF_KERNEL=host --
[ "$rc" = 0 ] || fail "PERF_KERNEL=host: exited $rc: $(cat "$tmp/err")"
[ ! -s "$tmp/fetches" ] || fail "PERF_KERNEL=host fetched: $(cat "$tmp/fetches")"
grep -q "kernel=$(uname -r) " "$tmp/boots" || fail "PERF_KERNEL=host: the guest was not handed uname -r: $(cat "$tmp/boots")"

# 4. What perf.sh refuses stops it before anything is built or booted, with 2 for a usage error and the fetch's own 97
# for a kernel the box cannot get: a name that is not a row, a doctor-only row, a kernel set by hand for another row, a
# PERF_BOOT that is not one.
refused() {
	local name="$1" want_rc="$2" want_text="$3"
	shift 3
	run_perf "$@" --
	[ "$rc" = "$want_rc" ] || fail "$name: exited $rc, want $want_rc: $(cat "$tmp/err")"
	grep -qF -- "$want_text" "$tmp/err" || fail "$name: stderr lacks \"$want_text\": $(cat "$tmp/err")"
	[ ! -s "$tmp/boots" ] || fail "$name: a guest booted: $(cat "$tmp/boots")"
	[ ! -s "$tmp/go.log" ] || fail "$name: something was built before the refusal: $(cat "$tmp/go.log")"
}
refused "a name that is not a row" 2 "is not a kernel-matrix row" PERF_KERNEL=no-such-row
refused "a doctor-only row" 2 "doctor-only" PERF_KERNEL=row-d
refused "a kernel set by hand for another row" 2 "says another kernel" PERF_KERNEL=row-a TEGO_VM_KERNEL=matrix-row-d
refused "a kernel that cannot be fetched" 97 "the mirror no longer carries the package" PERF_KERNEL=row-a STUB_FETCH_FAIL=row-a
refused "a PERF_BOOT that is not one" 2 "PERF_BOOT must be bpf or default" PERF_BOOT=weird

# 5. The suite's exit status is perf.sh's: a budget failed in the guest (1) is 1 here, and the line on stderr says which row's guest.
run_perf PERF_KERNEL=row-a STUB_GUEST_RC=1 --
[ "$rc" = 1 ] || fail "a guest that exited 1: perf.sh exited $rc, want 1"
grep -q 'row-a' "$tmp/err" || fail "a failed row's stderr does not name it: $(cat "$tmp/err")"

echo "ok perf_test.sh"
