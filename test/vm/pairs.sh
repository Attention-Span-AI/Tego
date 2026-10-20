#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# pairs.sh — ADR 0021's pairs runs from the host (`make vm-pairs`): it builds the binaries, boots one KVM guest per
# variant with test/vm/kvm-run.sh --sudo (a freeze then loses one variant, not the night), runs tier2-pairs.sh in it
# once per phase, and reads each console into $VM_OUT/pairs/<row>/<boot>/<variant>/summary.json.
#
# The builds, all CGO-free: tego (static, -buildmode=exe) and tego-pie (-buildmode=pie), both
# -tags tegobpf,tegotesthooks so tier2-pairs.sh can pin the decision plane (TEGO_TEST_PLANE); permlistener, the
# third-party listener; and elfinterp, run here on the host, which must find a PT_INTERP and ET_DYN in tego-pie and
# no PT_INTERP in tego, or nothing boots: a PIE run recorded for a build that came out static would prove nothing.
#
# The variants (ADR 0021's conditions, enforce-cgroup-observe §6 E39), each a list of phases PLANE:MODE:PAIRS:
#
#   two-inodes     fanotify:plain:400 fanotify:timeout:300 fanotify:kill:300  COPY_B=1, AGENT_SLEEP 0.05
#   third-party    the same phases                                            permlistener beside the runs
#   guest-freeze   fanotify:plain:200 fanotify:timeout:300                    AGENT_SLEEP 1 (a reported whole-guest freeze)
#   pie            fanotify:plain:50 auto:plain:50                            tego-pie against the static tego (two
#                                                                             inodes), SELF_DENY: a deny_read over the
#                                                                             PIE's own file (ADR 0021 (4))
#   plane-control  auto:plain:200                                             COPY_B=1 and permlistener: the harness
#                                                                             works with a plane too (not a condition)
#
# A kill phase SIGKILLs one launcher per pair at a point drawn from the previous pair's length, so the kills land at
# any AGENT_SLEEP; each phase's summary counts the kills that landed and those that hit a started run, and
# tier2-pairs.sh fails a kill phase where fewer than half the pairs lost a launcher (PAIRS-KILLS-SHORT). On the
# fallback, a killed launcher's agent that read the secret after the kill, in a run that never refused it and that
# its reaper closed, is E15's stated window (tier2-pairs.sh's judge, killed-read): the summary counts those pairs
# (killed_reads) and warns, and any other read fails the variant.
#
# A variant passes when every phase printed PAIRS-DONE n/n and exited 0, no "=== WATCHDOG" line appeared, nothing
# printed PAIRS-ASSERT-FAIL, PAIRS-SETUP-FAIL, PAIRS-LISTENER-FAIL, PAIRS-CLEANUP-FAIL or PAIRS-KILLS-SHORT, the pie variant's
# PAIRS-SELF-DENY came in every phase, and a listener phase's stats count events from tego (the group saw the
# launchers' and stages' opens). A listener event answered at its deadline (late>0) is a warning in the summary.
# A PLANE=auto phase that ran the fanotify fallback fails plane-control (it then controls nothing) and is a warning
# for pie (a row with no plane mode, such as AL2023 6.1 under lockdown; its pinned fallback phase is the proof).
#
# Usage: test/vm/pairs.sh
#        test/vm/pairs.sh --summarize CONSOLE STATUS VARIANT ROW BOOT PHASES  (the console reader; prints the JSON)
# Environment:
#   VARIANTS       the variants to run, in order (default: two-inodes third-party guest-freeze pie plane-control)
#   PAIRS_KERNEL   a kernel-matrix row (test/vm/fetch-kernel.py --list), fetched as matrix.sh fetches it; host (the
#                  default) is this box's own kernel. A doctor-only row is refused: no tier is offered there.
#   PAIRS_BOOT     bpf (default): the host's lsm= list plus bpf; default: the kernel's own CONFIG_LSM; both: each
#   PAIRS_N        replaces every phase's pair count (PAIRS_N=50 is a smoke; a kill phase under 20 pairs can miss
#                  KILL_MIN's share by chance, tier2-pairs.sh's KILL_MIN says how often)
#   PAIRS_TIMEOUT  seconds one guest may run (default: 300, plus 120 per phase and 5 per pair)
#   VM_OUT         where the binaries and results go (default bin/vm)
#   GO             the go command (default go); TEGO_VM_MEM (default 1536M), TEGO_VM_SMP (default 2)
# Exit code: 0 when every variant passed on every boot, 1 when one did not, 2 on a usage error; 97 when a kernel
# cannot be fetched (fetch-kernel.py's).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# summarize reads one guest's console ($1) and kvm-run.sh's status line ($2) for variant $3 on row $4, boot $5,
# whose phases are $6 (PLANE:MODE:PAIRS, space-separated), and prints its summary.json; "pass" is the verdict.
summarize() {
	python3 - "$@" <<'PY'
import json, re, sys

console, status_file, variant, row, boot, phases_arg = sys.argv[1:7]
want = []
for p in phases_arg.split():
    plane, mode, n = p.split(':')
    want.append({'plane_pin': plane, 'mode': mode, 'pairs': int(n)})
try:
    with open(status_file, errors='replace') as f:
        status = f.read().strip()
except OSError:
    status = ''
with open(console, 'rb') as f:
    lines = [l.decode('utf-8', 'replace').rstrip('\r\n').replace('\r', '') for l in f]

phases = [dict(w, done=None, ok=0, plane=None, rc=None, listener=None, inodes=None, self_deny=False, kills=None,
               kills_started=None, killed_reads=None) for w in want]
cur = None
watchdog, asserts, failures, warnings = [], [], [], []
retries = 0
for line in lines:
    m = re.search(r'PAIRS-PHASE (\d+) ', line)
    if m and line.startswith('PAIRS-PHASE '):
        k = int(m.group(1)) - 1
        cur = phases[k] if 0 <= k < len(phases) else None
        continue
    m = re.match(r'PAIRS-PHASE-END (\d+) rc=(\d+)', line)
    if m:
        k = int(m.group(1)) - 1
        if 0 <= k < len(phases):
            phases[k]['rc'] = int(m.group(2))
        cur = None
        continue
    if '=== WATCHDOG' in line:
        watchdog.append(line[line.index('=== WATCHDOG'):])
        continue
    if 'status=retry' in line and line.startswith('PAIR-CLEANUP '):
        retries += 1
    for tag in ('PAIRS-ASSERT-FAIL', 'PAIRS-SETUP-FAIL', 'PAIRS-LISTENER-FAIL', 'PAIRS-CLEANUP-FAIL', 'PAIRS-KILLS-SHORT'):
        if line.startswith(tag):
            (asserts if tag == 'PAIRS-ASSERT-FAIL' else failures).append(line)
    if cur is None:
        continue
    m = re.match(r'PAIRS-DONE (\d+)/(\d+) plane=(\S+)', line)
    if m:
        cur['done'] = m.group(1) + '/' + m.group(2)
        cur['ok'] = int(m.group(1))
        cur['plane'] = m.group(3)
        m = re.search(r' kills=(\d+) kills_started=(\d+)', line)
        if m:
            cur['kills'], cur['kills_started'] = int(m.group(1)), int(m.group(2))
        m = re.search(r' killed_reads=(\d+)', line)
        if m:
            cur['killed_reads'] = int(m.group(1))
    m = re.match(r'PAIRS-INODES (.*)', line)
    if m:
        cur['inodes'] = m.group(1)
    if line.startswith('PAIRS-SELF-DENY ok'):
        cur['self_deny'] = True
    m = re.match(r'PAIRS-LISTENER rc=\d+ PERMLISTENER-STATS (.*)', line)
    if m:
        cur['listener'] = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', m.group(1))}

listener_variant = variant in ('third-party', 'plane-control')
copy_b = variant in ('two-inodes', 'pie', 'plane-control')
reasons = []
if watchdog:
    reasons.append('a watchdog report (stall)')
if asserts:
    reasons.append('%d ledger assertion(s) failed' % len(asserts))
if failures:
    reasons.append('; '.join(failures))
for i, p in enumerate(phases, 1):
    if p['done'] != '%d/%d' % (p['pairs'], p['pairs']):
        reasons.append('phase %d: PAIRS-DONE %s, want %d/%d' % (i, p['done'] or 'missing', p['pairs'], p['pairs']))
    if p['rc'] != 0:
        reasons.append('phase %d: exit %s' % (i, 'missing' if p['rc'] is None else p['rc']))
    if p['mode'] == 'kill' and p['done'] and p['kills'] is None:
        reasons.append('phase %d: kill mode with no count of the kills that landed' % i)
    if p['killed_reads']:
        warnings.append("phase %d: in %d pair(s) the killed launcher's agent read SECRET in E15's window (the "
                        "fallback's stated limit until the reaper kills the run)" % (i, p['killed_reads']))
    if p['plane_pin'] != 'auto' and p['done'] and p['plane'] != p['plane_pin']:
        reasons.append('phase %d: plane %s, pinned %s' % (i, p['plane'], p['plane_pin']))
    if p['plane_pin'] == 'auto' and p['done'] and p['plane'] == 'fanotify':
        if variant == 'plane-control':
            reasons.append('phase %d: PLANE=auto ran the fanotify fallback, and the plane control needs a plane mode' % i)
        else:
            warnings.append('phase %d: PLANE=auto ran the fanotify fallback (no plane mode on this boot)' % i)
    if copy_b and not p['inodes']:
        reasons.append('phase %d: no PAIRS-INODES' % i)
    if variant == 'pie' and not p['self_deny']:
        reasons.append('phase %d: no PAIRS-SELF-DENY' % i)
    if listener_variant:
        st = p['listener']
        if not st:
            reasons.append('phase %d: no listener stats' % i)
        elif st.get('tego', 0) == 0:
            reasons.append('phase %d: the listener saw no tego event' % i)
        elif st.get('late', 0) > 0:
            warnings.append('phase %d: the listener answered %d event(s) at its deadline' % (i, st['late']))
if status and status != 'guest 0':
    reasons.append('guest: ' + status)

listener = None
stats = [p['listener'] for p in phases if p['listener']]
if stats:
    listener = {k: sum(s.get(k, 0) for s in stats) for k in ('events', 'tego', 'late')}
summary = {
    'row': row, 'boot': boot, 'variant': variant,
    'pairs': sum(p['pairs'] for p in phases), 'ok': sum(p['ok'] for p in phases),
    'stall': bool(watchdog), 'plane': sorted({p['plane'] for p in phases if p['plane']}),
    'inodes': [p['inodes'] for p in phases if p['inodes']], 'listener': listener,
    'cleanup_retries': retries, 'phases': phases,
    'kills': sum(p['kills'] or 0 for p in phases), 'kills_started': sum(p['kills_started'] or 0 for p in phases),
    'killed_reads': sum(p['killed_reads'] or 0 for p in phases), 'watchdog': watchdog[:20], 'asserts': asserts[:20],
    'guest': status, 'pass': not reasons, 'reasons': reasons, 'warnings': warnings,
}
json.dump(summary, sys.stdout, indent=1, sort_keys=True)
print()
PY
}

if [ "${1:-}" = --summarize ]; then
	shift
	[ $# = 6 ] || { echo "pairs.sh: --summarize CONSOLE STATUS VARIANT ROW BOOT PHASES" >&2; exit 2; }
	summarize "$@"
	exit $?
fi
[ $# = 0 ] || { echo "pairs.sh: no arguments (the environment says what to run; see the header)" >&2; exit 2; }

GO="${GO:-go}"
OUT="${VM_OUT:-bin/vm}"
case "$OUT" in /*) ;; *) OUT="$repo/$OUT" ;; esac
VARIANTS="${VARIANTS:-two-inodes third-party guest-freeze pie plane-control}"
case "${PAIRS_BOOT:-bpf}" in
bpf) boots=(bpf) ;;
default) boots=(default) ;;
both) boots=(bpf default) ;;
*) echo "pairs.sh: PAIRS_BOOT must be bpf, default or both, not ${PAIRS_BOOT}" >&2; exit 2 ;;
esac
case "${PAIRS_N:-}" in *[!0-9]* | 0*) echo "pairs.sh: PAIRS_N must be a positive count, not $PAIRS_N" >&2; exit 2 ;; esac
case "${PAIRS_TIMEOUT:-}" in *[!0-9]* | 0*) echo "pairs.sh: PAIRS_TIMEOUT must be a count of seconds, not $PAIRS_TIMEOUT" >&2; exit 2 ;; esac

# variant sets, for variant $1: phases (PLANE:MODE:PAIRS ...) and the guest's environment (genv). It fails on a
# name that is not a variant.
variant() {
	local p q
	genv=(TEGO=/usr/local/bin/tego AGENT_SLEEP=0.05)
	case "$1" in
	two-inodes) phases="fanotify:plain:400 fanotify:timeout:300 fanotify:kill:300"; genv+=(COPY_B=1) ;;
	third-party) phases="fanotify:plain:400 fanotify:timeout:300 fanotify:kill:300"; genv+=(LISTENER=/vm/permlistener) ;;
	guest-freeze) phases="fanotify:plain:200 fanotify:timeout:300"; genv=(TEGO=/usr/local/bin/tego AGENT_SLEEP=1 CAPTURE=uprobe) ;;
	pie)
		phases="fanotify:plain:50 auto:plain:50"
		genv=(TEGO=/usr/local/bin/tego-pie TEGO_B=/usr/local/bin/tego COPY_B=1 SELF_DENY=1 AGENT_SLEEP=0.05)
		;;
	plane-control) phases="auto:plain:200"; genv+=(COPY_B=1 LISTENER=/vm/permlistener) ;;
	*) return 1 ;;
	esac
	if [ -n "${PAIRS_N:-}" ]; then
		q=""
		for p in $phases; do q+="${q:+ }${p%:*}:$PAIRS_N"; done
		phases=$q
	fi
}
for v in $VARIANTS; do
	variant "$v" || { echo "pairs.sh: $v is not a variant (two-inodes third-party guest-freeze pie plane-control)" >&2; exit 2; }
done

# PAIRS_KERNEL=<row> runs on a kernel-matrix row's own kernel, as perf.sh and matrix.sh boot one; everything that can
# be wrong with the row is found before anything is built.
ROW="${PAIRS_KERNEL:-host}"
if [ "$ROW" != host ]; then
	row_kernel="$(python3 "$here/fetch-kernel.py" --name "$ROW" 2>/dev/null)" ||
		{ echo "pairs.sh: PAIRS_KERNEL=$ROW is not a kernel-matrix row (python3 $here/fetch-kernel.py --list; host is this box's own kernel)" >&2; exit 2; }
	if [ "$(python3 "$here/fetch-kernel.py" --body "$ROW")" = doctor-only ]; then
		echo "pairs.sh: PAIRS_KERNEL=$ROW is a doctor-only row: no tier is offered there, so there is no pair to run" >&2
		exit 2
	fi
	if [ -n "${TEGO_VM_KERNEL:-}" ] && [ "$TEGO_VM_KERNEL" != "$row_kernel" ]; then
		echo "pairs.sh: PAIRS_KERNEL=$ROW boots $row_kernel, but TEGO_VM_KERNEL=$TEGO_VM_KERNEL says another kernel" >&2
		exit 2
	fi
	python3 "$here/fetch-kernel.py" "$ROW" >/dev/null || exit $?
	export TEGO_VM_KERNEL="$row_kernel"
fi

bin="$OUT/pairs/bin"
mkdir -p "$bin" || exit 1
cd "$repo" || exit 1
if ! CGO_ENABLED=0 "$GO" build -buildmode=exe -tags tegobpf,tegotesthooks -trimpath -o "$bin/tego" ./cmd/tego ||
	! CGO_ENABLED=0 "$GO" build -buildmode=pie -tags tegobpf,tegotesthooks -trimpath -o "$bin/tego-pie" ./cmd/tego ||
	! CGO_ENABLED=0 "$GO" build -trimpath -o "$bin/permlistener" ./test/vm/cmd/permlistener ||
	! CGO_ENABLED=0 "$GO" build -trimpath -o "$bin/elfinterp" ./test/vm/cmd/elfinterp; then
	echo "pairs.sh: build failed" >&2
	exit 1
fi
# The PIE must be one (a loader and ET_DYN), and the static build must not name a loader: the pie variant pairs them.
if ! "$bin/elfinterp" -want pie "$bin/tego-pie" || ! "$bin/elfinterp" -want static "$bin/tego"; then
	echo "pairs.sh: the builds are not linked as the pie variant needs (elfinterp above)" >&2
	exit 1
fi

export TEGO_VM_MEM="${TEGO_VM_MEM:-1536M}" TEGO_VM_SMP="${TEGO_VM_SMP:-2}"
fail=0
for boot in "${boots[@]}"; do
	for v in $VARIANTS; do
		variant "$v"
		dir="$OUT/pairs/$ROW/$boot/$v"
		if ! { rm -rf "$dir" && mkdir -p "$dir"; }; then exit 1; fi
		# The guest's script: one tier2-pairs.sh per phase, each in a work directory of its own, framed by lines the
		# summary reads. A phase that fails does not stop the next; a stall powers the guest off.
		{
			echo '#!/bin/bash'
			echo '# Written by test/vm/pairs.sh: one tier2-pairs.sh per phase.'
			k=0
			pairs=0
			for p in $phases; do
				k=$((k + 1))
				IFS=: read -r plane mode n <<<"$p"
				pairs=$((pairs + n))
				echo "echo 'PAIRS-PHASE $k plane=$plane mode=$mode pairs=$n'"
				echo "PAIRS_DIR=/tmp/pairs-$k PLANE=$plane MODE=$mode PAIRS=$n /bin/bash /vm/tier2-pairs.sh"
				echo "echo \"PAIRS-PHASE-END $k rc=\$?\""
			done
			echo 'exit 0'
		} >"$dir/guest.sh"
		timeout="${PAIRS_TIMEOUT:-$((300 + 120 * k + 5 * pairs))}"
		envs=()
		for e in "${genv[@]}"; do envs+=(--env "$e"); done
		if [ "$boot" = default ]; then lsm=kernel; else lsm="${TEGO_VM_LSM:-}"; fi
		echo "pairs.sh: $ROW $boot $v: $phases (timeout ${timeout}s)" >&2
		TEGO_VM_LSM="$lsm" "$here/kvm-run.sh" --sudo --timeout "$timeout" --log "$dir/console" --status "$dir/status" \
			--file "$bin/tego:/usr/local/bin/tego" --file "$bin/tego-pie:/usr/local/bin/tego-pie" \
			--file "$bin/permlistener:/vm/permlistener" --file "$here/tier2-pairs.sh:/vm/tier2-pairs.sh" \
			--file "$dir/guest.sh:/vm/pairs-guest.sh" "${envs[@]}" -- /bin/bash /vm/pairs-guest.sh >"$dir/kvm-run.log" 2>&1
		rc=$?
		[ -f "$dir/console" ] || : >"$dir/console"
		if ! summarize "$dir/console" "$dir/status" "$v" "$ROW" "$boot" "$phases" >"$dir/summary.json"; then
			echo "pairs.sh: $ROW $boot $v: the console could not be read (kvm-run.sh exit $rc)" >&2
			fail=1
			continue
		fi
		verdict="$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(("PASS" if s["pass"] else "FAIL") + " %d/%d stall=%s %s%s" % (s["ok"], s["pairs"], str(s["stall"]).lower(), "; ".join(s["reasons"]), (" WARN " + "; ".join(s["warnings"])) if s["warnings"] else ""))' "$dir/summary.json")"
		echo "pairs: $ROW $boot $v $verdict ($dir/summary.json)"
		case "$verdict" in PASS*) ;; *) fail=1 ;; esac
	done
done
exit "$fail"
