#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# perf.sh — the tier-3 guest perf suite (`make vm-perf`): builds tego with the BPF objects and the test hooks,
# the openbench loop and the suite driver (test/perf), boots one KVM guest with test/vm/kvm-run.sh and runs
# perfsuite in it as root. The suite measures, in one boot, the cold start per mode, the warm start with Prepare's
# phase breakdown, Prepare's fill at 1, 1000 and cap-1 rows, a raw open+close loop per mode (200k opens, one pinned
# CPU, modes alternated), the name entries' figures per plane mode (ADR 0043 C10: an open with and without the
# header's name flag, a refusal by name over one by the file's own row at 3 and 32 levels, a directory rename, the
# warm start and Prepare's fill with 64 name rows; only with -checks name, ADR 0043's notes say why), a raw
# socket+close loop and a setsockopt loop at landlock and
# on tier cgroup's fanotify
# fallback (cgroup/sock_create's and cgroup/setsockopt's cost, ADR 0018 PR 2 and (7)), an exec loop per mode with and
# without command rules (test/perf/cmd/execbench: the exec pins' cost, ADR 0048 P2's K7) and 2, 8 and 32 concurrent
# runs with landlock alone as the control. It fails when a
# budget of test/perf is over its limit, and prints TARGET-MISS for a figure over the spec's own target
# (docs/p0/enforce-plane.md §10 records both, with the kernel and mode).
#
# Usage: test/vm/perf.sh [perfsuite flags]      e.g.  test/vm/perf.sh -checks start,fill
#                                                     test/vm/perf.sh -budget start.warm.landlock.p50_ms=1   (must fail)
# Environment:
#   PERF_BOOT     bpf (default): the host's lsm= list plus bpf, so tier bpflsm and the plane's LSM mode exist;
#                 default: no lsm= at all, the kernel's own CONFIG_LSM (Ubuntu's has no bpf), the plane in fmod_ret mode
#   PERF_KERNEL   a kernel-matrix row (test/vm/fetch-kernel.py --list; host is this box's own kernel, the default): the
#                 guest boots that row's kernel, fetched and signature-checked as matrix.sh fetches it, and its console
#                 log is perf-<row>-<boot>.console. PERF_BOOT keeps its meaning on a row: bpf is the host's lsm= list
#                 plus bpf (what root-suites.sh boots on every row), default the row kernel's own CONFIG_LSM. The
#                 budgets are the 6.17 guest's: on another row the suite still fails over a limit, and an exit of 1
#                 there is a figure to record, not a gate (perf-cold: matrix rows are informational). A doctor-only
#                 row is refused (exit 2): no tier is offered there.
#   PERF_OUT      where the binaries and the console log go (default bin/perf)
#   PERF_TIMEOUT  seconds the guest may run (default 3000)
#   GO            the go command (default go); TEGO_VM_MEM (default 3G: 32 launchers), TEGO_VM_SMP (default 4)
# Exit code: the suite's (0 pass, 1 a budget failed, 2 usage) when the guest ran it; kvm-run.sh's otherwise.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
GO="${GO:-go}"
OUT="${PERF_OUT:-$repo/bin/perf}"
case "$OUT" in /*) ;; *) OUT="$repo/$OUT" ;; esac
BOOT="${PERF_BOOT:-bpf}"
case "$BOOT" in bpf | default) ;; *) echo "perf.sh: PERF_BOOT must be bpf or default, not $BOOT" >&2; exit 2 ;; esac

# PERF_KERNEL=<row> measures a kernel-matrix row's own kernel, the way matrix.sh boots one: the row is fetched
# (fetch-kernel.py: signature-checked, cached) and TEGO_VM_KERNEL names it. Everything that can be wrong with the row is
# found here, before the suite is built: a name that is not a row, a doctor-only row (no tier is offered, so there is
# nothing to measure), a kernel set by hand for another row, a kernel the box cannot fetch (97, as for matrix.sh).
KERNEL_ROW="${PERF_KERNEL:-}"
KERNEL_TAG=""
if [ -n "$KERNEL_ROW" ]; then
	if [ "$KERNEL_ROW" = host ]; then
		row_kernel="$(uname -r)"
	else
		row_kernel="$(python3 "$here/fetch-kernel.py" --name "$KERNEL_ROW" 2>/dev/null)" ||
			{ echo "perf.sh: PERF_KERNEL=$KERNEL_ROW is not a kernel-matrix row (python3 $here/fetch-kernel.py --list; host is this box's own kernel)" >&2; exit 2; }
		if [ "$(python3 "$here/fetch-kernel.py" --body "$KERNEL_ROW")" = doctor-only ]; then
			echo "perf.sh: PERF_KERNEL=$KERNEL_ROW is a doctor-only row: no tier is offered there, so the suite has nothing to measure" >&2
			exit 2
		fi
	fi
	if [ -n "${TEGO_VM_KERNEL:-}" ] && [ "$TEGO_VM_KERNEL" != "$row_kernel" ]; then
		echo "perf.sh: PERF_KERNEL=$KERNEL_ROW boots $row_kernel, but TEGO_VM_KERNEL=$TEGO_VM_KERNEL says another kernel" >&2
		exit 2
	fi
	if [ "$KERNEL_ROW" != host ]; then
		python3 "$here/fetch-kernel.py" "$KERNEL_ROW" >/dev/null || exit $?
	fi
	export TEGO_VM_KERNEL="$row_kernel"
	KERNEL_TAG="$KERNEL_ROW-"
fi

mkdir -p "$OUT" || exit 1
cd "$repo" || exit 1
export CGO_ENABLED=0
if ! "$GO" build -buildmode=exe -tags tegobpf,tegotesthooks -trimpath -o "$OUT/tego" ./cmd/tego ||
	! "$GO" build -trimpath -o "$OUT/openbench" ./test/perf/cmd/openbench ||
	! "$GO" build -trimpath -o "$OUT/execbench" ./test/perf/cmd/execbench ||
	! "$GO" build -trimpath -o "$OUT/perfsuite" ./test/perf/cmd/perfsuite; then
	echo "perf.sh: build failed" >&2
	exit 1
fi

if [ "$BOOT" = default ]; then
	export TEGO_VM_LSM=kernel
fi
export TEGO_VM_MEM="${TEGO_VM_MEM:-3G}"
log="$OUT/perf-$KERNEL_TAG$BOOT.console"
"$here/kvm-run.sh" --sudo --timeout "${PERF_TIMEOUT:-3000}" --log "$log" \
	--file "$OUT/tego:/usr/local/bin/tego" \
	--file "$OUT/openbench:/usr/local/bin/openbench" \
	--file "$OUT/execbench:/usr/local/bin/execbench" \
	--file "$OUT/perfsuite:/usr/local/bin/perfsuite" \
	-- /usr/local/bin/perfsuite "$@"
rc=$?
echo "perf.sh: guest ${KERNEL_ROW:+kernel=$KERNEL_ROW }boot=$BOOT exit $rc; console log $log" >&2
exit "$rc"
