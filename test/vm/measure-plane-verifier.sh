#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# measure-plane-verifier.sh — what the decision plane costs the verifier on each kernel under $TEGO_VM_CACHE/kernel.
#
# It builds internal/bpf's test binary (-tags 'integration tegobpf'), boots every kernel named on the command line (or,
# with none, the default list below) in a throwaway KVM guest with test/vm/kvm-run.sh, runs TestPlaneLoadsAndAttaches
# in it as root, and prints one table: per kernel, the largest verified-instruction count of each plane build (rd =
# decide_rd, pr = decide_pr), the budget the test held it to, and whether the test passed. The test fails, in the
# guest, a program over internal/bpf's planeBudgetFor (ADR 0024: 20,000 plus the block walk's 8,000, or on Linux
# 6.19.4 to 6.19.y the count measured on Fedora's 6.19.10 plus 10 %), and logs the counts either way, so a kernel
# that no row of plane_budget_integration_test.go covers shows its count here before anyone sets a budget for it.
#
# What it proves: the verifier cost of the plane's own objects on those kernels. It proves nothing about what a program
# decides (the root tests do: internal/runtime's TestRootLiveBlock* for the live blocks' paths), and arm64 has no guest.
#
# socket_listen, the plane's largest program (it walks no path), has a budget of its own per kernel family (internal/bpf
# plane_budget_integration_test.go's planeListenFamilies): its counts are in listen.txt, not in the table's rd and pr
# columns, which are the largest path-walking program of each build against the budget those programs are held to.
#
# Usage: test/vm/measure-plane-verifier.sh [-o OUTDIR] [KERNEL...]
#   KERNEL    a directory name under $TEGO_VM_CACHE/kernel that holds a vmlinuz (what kvm-run.sh calls
#             TEGO_VM_KERNEL); default: fedorabudget-mainline-6.18 fedorabudget-mainline-6.19.3
#             fedorabudget-mainline-6.19.4 fedorabudget-mainline-6.19.10 fedorabudget-mainline-6.19.14
#             matrix-fedora-7.0 matrix-fedora-7.2
#   -o OUTDIR where the test binary, each kernel's console log and the table go (default: a new directory under
#             $TEGO_VM_SCRATCH, else under $HOME/.cache/tego-vm/out)
# Environment: TEGO_VM_CACHE (default ~/.cache/tego-vm), GO (go), TEGO_VM_QUEUE_LOCK (a file to hold with flock(1)
# around every boot: a one-guest-at-a-time queue; unset takes no lock), TEGO_VM_TIMEOUT (seconds
# per guest, default 900), TEGO_VM_MEM, TEGO_VM_SMP and the rest of kvm-run.sh's variables. TEGO_TEST_PLANE_PREEMPT=waive
# is set for the guest: a kernel that preempts kernel code (Fedora 7.x) refuses fmod_ret mode in a product build.
# Exit code: 0 when every kernel booted, ran the test and the test passed; 1 when a kernel's test failed (a program over
# its budget, the plane not loading); 97 when a guest could not be booted at all; 2 on a usage error.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cache="${TEGO_VM_CACHE:-$HOME/.cache/tego-vm}"
timeout_s="${TEGO_VM_TIMEOUT:-900}"
go="${GO:-go}"
out=""

while getopts 'o:' opt; do
	case "$opt" in
	o) out="$OPTARG" ;;
	*) echo "usage: $0 [-o OUTDIR] [KERNEL...]" >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

kernels=("$@")
if [ ${#kernels[@]} -eq 0 ]; then
	kernels=(fedorabudget-mainline-6.18 fedorabudget-mainline-6.19.3 fedorabudget-mainline-6.19.4
		fedorabudget-mainline-6.19.10 fedorabudget-mainline-6.19.14 matrix-fedora-7.0 matrix-fedora-7.2)
fi
for k in "${kernels[@]}"; do
	if [ ! -f "$cache/kernel/$k/vmlinuz" ]; then
		echo "measure-plane-verifier: no $cache/kernel/$k/vmlinuz (kernels here: $(find "$cache/kernel" -mindepth 1 -maxdepth 1 -printf '%f ' 2>/dev/null))" >&2
		exit 2
	fi
done
if [ -z "$out" ]; then
	out="$(mktemp -d "${TEGO_VM_SCRATCH:-$cache/out}/plane-verifier.XXXXXX")" || exit 2
else
	mkdir -p "$out" || exit 2
fi

bin="$out/bpf.test"
echo "measure-plane-verifier: building $bin" >&2
(cd "$root" && CGO_ENABLED=0 "$go" test -c -count=1 -tags 'integration tegobpf' -o "$bin" ./internal/bpf) >"$out/build.log" 2>&1 || {
	echo "measure-plane-verifier: FAIL: the test binary did not build (see $out/build.log)" >&2
	exit 2
}

# summarize LOG: "<rd largest> <pr largest> <rd budget> <pr budget> <over-budget lines> <rd listen> <pr listen> <rd listen
# budget> <pr listen budget>" for the table and listen.txt. The largest counts leave out socket_listen's, which have their own.
summarize() {
	awk '
		/=== RUN +TestPlaneLoadsAndAttaches\// {
			split($0, a, "/"); cur = a[2]; sub(/[ \t].*$/, "", cur)
		}
		/[0-9]+ instructions verified/ {
			match($0, /[0-9]+ instructions verified/)
			n = substr($0, RSTART, RLENGTH) + 0
			if ($0 ~ /socket_listen: [0-9]+ instructions verified/) {
				if (n > lmax[cur]) lmax[cur] = n
			} else if (n > max[cur]) max[cur] = n
		}
		/socket_listen.s budget is [0-9]+/ {
			match($0, /socket_listen.s budget is [0-9]+/); lb[cur] = substr($0, RSTART, RLENGTH); sub(/^.*budget is /, "", lb[cur]); lb[cur] += 0
		}
		/a plane program.s budget is [0-9]+/ {
			match($0, /budget is [0-9]+/); b[cur] = substr($0, RSTART + 10, RLENGTH - 10) + 0
		}
		/over the budget of/ { over++ }
		END {
			printf "%d %d %d %d %d %d %d %d %d\n", max["decide_rd"], max["decide_pr"], b["decide_rd"], b["decide_pr"], over,
				lmax["decide_rd"], lmax["decide_pr"], lb["decide_rd"], lb["decide_pr"]
		}' "$1"
}

table="$out/table.txt"
printf '%-34s %-26s %10s %10s %10s %10s %s\n' kernel uname rd-largest pr-largest rd-budget pr-budget result >"$table"
listen="$out/listen.txt"
printf '%-34s %-26s %12s %12s %12s %12s\n' kernel uname rd-listen pr-listen rd-budget pr-budget >"$listen"
worst=0
for k in "${kernels[@]}"; do
	log="$out/$k.console"
	run=("$here/kvm-run.sh" --timeout "$timeout_s" --log "$log" --env TEGO_TEST_PLANE_PREEMPT=waive --
		"$bin" -test.v -test.count=1 -test.timeout=14m -test.run '^TestPlaneLoadsAndAttaches$')
	echo "measure-plane-verifier: booting $k" >&2
	if [ -n "${TEGO_VM_QUEUE_LOCK:-}" ]; then
		TEGO_VM_KERNEL="$k" flock "$TEGO_VM_QUEUE_LOCK" "${run[@]}" >"$out/$k.stdout" 2>"$out/$k.stderr"
	else
		TEGO_VM_KERNEL="$k" "${run[@]}" >"$out/$k.stdout" 2>"$out/$k.stderr"
	fi
	rc=$?
	echo "$rc" >"$out/$k.rc"
	uname_line="$(grep -m1 -oE 'Linux version [^ ]+' "$log" 2>/dev/null | sed 's/Linux version //')"
	read -r rd pr rdb prb over lrd lpr lrdb lprb < <(summarize "$log")
	result=PASS
	if [ "$rc" -eq 97 ]; then
		result="NOT-BOOTED(97)"
		worst=97
	elif [ "$rc" -ne 0 ] || [ "${over:-0}" -ne 0 ] || [ $((rd + pr)) -eq 0 ] || [ $((lrd + lpr)) -eq 0 ]; then
		result="FAIL(rc=$rc,over=${over:-0})"
		[ "$worst" -eq 97 ] || worst=1
	fi
	printf '%-34s %-26s %10s %10s %10s %10s %s\n' "$k" "${uname_line:-?}" "$rd" "$pr" "${rdb:-0}" "${prb:-0}" "$result" >>"$table"
	printf '%-34s %-26s %12s %12s %12s %12s\n' "$k" "${uname_line:-?}" "${lrd:-0}" "${lpr:-0}" "${lrdb:-0}" "${lprb:-0}" >>"$listen"
done

cat "$table"
echo "socket_listen (its own budget per kernel family):"
cat "$listen"
echo "measure-plane-verifier: logs and table in $out" >&2
exit "$worst"
