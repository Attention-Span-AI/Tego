#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run-matrix-row.sh — one kernel-matrix row's body, run as root inside the row's guest (P0-DESIGN §10 "Kernel
# matrix", §12 "P0 is complete when, on the kernel matrix: ..."). test/vm/matrix.sh
# boots the row's own kernel with test/vm/kvm-run.sh --sudo --delegate-user, so this script is root the way `sudo` makes
# a user root: SUDO_UID names the user, and a root `tego run` drops the agent to that user.
#
# What it runs, in this order, each with its own result line:
#   doctor-user  `tego doctor` as the user: §12.2 wants tier landlock;
#   doctor-root  `tego doctor` as root: §12.2 wants tier cgroup "with sudo" and no boot change (bpflsm where bpf
#                is an active LSM already);
#   kt1 as the user at tier landlock and as root at tier cgroup; kt2 as the user (the forwarder half at
#   landlock) and as root (the forwarder half at cgroup, and the uprobe half); kt4 as root (every tier
#   the machine allows, its agent dropped to the user); kt5 as root (the same tiers: the cost of an untouched
#   fs.ask and net.ask entry, the 20-step agent and the pip build, each with and without them, FEATURES R7);
#   kt6 as root (half (a) as the user, (b), (c));
#   kt7 as root (half (a) as the user at tier landlock, when matrix.sh carried the Claude Agent SDK, and
#   half (b) at tier cgroup); smoke-exec-rules (ADR 0048 C6: exec.deny refuses rm -r and git push at their
#   execve) as the user at tier landlock and as root at tier cgroup; where bpf is an active LSM, doctor-bpflsm and kill tests 1 and 7 (b) at tier
#   bpflsm (kt4 and kt5 include it among their tiers; TIER3-PLAN T11); kt3 only when VM_KT3=1, since a two-vCPU guest shared with other guests is
#   not the quiet machine §9's budgets are measured on (matrix.sh then carries its noop and cpu workloads
#   prebuilt, as TEGO_BENCH_BIN, because the guest has no go to build them; without them it is a named skip).
# `--only doctor-refusal` is the whole body of a doctor-only row (fetch-kernel.py's DOCTOR_ONLY: Ubuntu 22.04's 5.15,
# Landlock ABI 1, where no tier is offered): test/vm/doctor-refusal.sh as the user and as root, which holds doctor and
# `tego run` to refusing the machine with the fix, and fails when the machine offers a tier at all.
# `--only kt6c` runs kill test 6's half (c), then kill tests 1, 4, 5 and 7 (b) at bpflsm: matrix.sh reboots the row with the lsm= line doctor
# printed and calls this again, which is R16's "after adding bpf to lsm= exactly as printed and one reboot".
# `--only kt4` and `--only kt5` run that kill test alone, as root, on the one boot matrix.sh gives them (VM_ONLY).
# `--only smoke` runs the smoke-exec-rules cell alone, as the user and as root (matrix.sh's VM_ONLY=smoke).
#
# Every result is one line, "MATRIX-RESULT <check> <as> <PASS|FAIL|SKIP> <exit> <detail>", after the kill
# test's own output with its KT-HALF lines, so matrix.sh can tabulate a row from the console alone. Each boot also
# prints "MATRIX-FACTS landlock_abi=<n> cgroup_mode=<mode>" from root's doctor (doctor-facts.sh), for the report. When
# KT_FIXTURE_DIR is set, the fixtures the kill tests saved are printed last as a base64 tar between
# MATRIX-FIXTURES-BEGIN and MATRIX-FIXTURES-END: the console is the only thing that leaves the guest.
#
# With VM_COVER=1 (matrix.sh's switch for scripts/coverage.sh --kill-tests) the tego given is a -cover
# build: every check runs with GOCOVERDIR naming /tmp/tego-covdata, a directory every uid can write since the
# user halves run tego as the user and a root run drops its agent to that user, and after everything else
# each data file there is printed as one "TEGO-COVFILE <name> <base64>" line, the format coverage.sh decodes
# from its own suites' consoles.
#
# Usage: run-matrix-row.sh <tego-binary> [--only kt6c|kt4|kt5|smoke|doctor-refusal]
# Exit 0 when every check passed, 1 when any failed or a kill test skipped (kill test 3, named, is the one
# allowed skip), 2 on a usage error.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
e2e="$here/../e2e"
# shellcheck source=test/e2e/kt-exit.sh
. "$e2e/kt-exit.sh"
usage() { echo "usage: run-matrix-row.sh <tego-binary> [--only kt6c|kt4|kt5|smoke|doctor-refusal]" >&2; exit 2; }
[ $# -ge 1 ] || usage
tego="$1"
shift
only=""
while [ $# -gt 0 ]; do
	case "$1" in
	--only)
		[ $# -ge 2 ] || usage
		only="$2"
		shift 2
		;;
	*) usage ;;
	esac
done
# kt6c is the one check a second boot runs alone, kt4 and kt5 the ones a boot runs alone to measure kill test 4
# or 5 as root (matrix.sh's VM_ONLY=kt4 and VM_ONLY=kt5), smoke the exec-rules smoke cell alone (VM_ONLY=smoke), and
# doctor-refusal the one a doctor-only row runs; any other name would run nothing and report nothing.
case "$only" in "" | kt6c | kt4 | kt5 | smoke | doctor-refusal) ;; *) usage ;; esac
[ -x "$tego" ] || { echo "run-matrix-row: $tego is not an executable file" >&2; exit 1; }
export TEGO_BIN="$tego"
# This runs in a guest, a disposable machine, whose home is its own: the kill tests may use the product binary the row
# was given, which test/e2e/lib.sh's kt_require_testhooks refuses anywhere else (identity-config.md R27).
export TEGO_DISPOSABLE_HOST="${TEGO_DISPOSABLE_HOST:-kvm}"
TEST_TIMEOUT="${VM_TEST_TIMEOUT:-1500}"

user_home="$(getent passwd "${SUDO_UID:-0}" | cut -d: -f6)"
# as_user runs a command as the user sudo names, the way that user's own shell would.
as_user() {
	setpriv --reuid="$SUDO_UID" --regid="${SUDO_GID:-$SUDO_UID}" --clear-groups \
		env -u SUDO_UID -u SUDO_GID -u SUDO_USER -u SUDO_COMMAND HOME="${user_home:-/}" USER="${SUDO_USER:-}" "$@"
}

# The doctor and compile calls this script makes itself run with an isolation of their own, and so does every kill test (each
# sources test/e2e/lib.sh, which gives its run one): a binary built with -tags tegotesthooks (VM_TESTHOOKS=1) refuses a
# machine config whose ledger_root is the built-in ~/.tego/runs, which is what no TEGO_CONFIG gives it, and a product
# build would anchor in the guest user's ~/.tego (identity-config.md R27). iso_make DIR UID writes a machine config naming
# a ledger_root of its own in DIR, handed to UID; with_iso <user|root> CMD... runs CMD as that identity with the
# variables.
iso_make() {
	local d="$1" uid="$2"
	mkdir -p "$d/log-home"
	chmod 755 "$d"
	printf 'version: 0\nledger_root: %s/runs\nstop_grace: 3s\n' "$d" >"$d/config.yaml"
	chmod 600 "$d/config.yaml"
	[ "$uid" = 0 ] || chown -R "$uid:${SUDO_GID:-$uid}" "$d"
}
iso_dir_root=""
iso_dir_user=""
with_iso() {
	local who="$1" d
	shift
	d="$iso_dir_root"
	[ "$who" != user ] || d="$iso_dir_user"
	if [ "$who" = user ]; then
		as_user env TEGO_CONFIG="$d/config.yaml" TEGO_TEST_CHAIN_ANCHOR="$d/chain.log" TEGO_TEST_OWN_LOG_HOME="$d/log-home" HISTFILE=/dev/null "$@"
	else
		env TEGO_CONFIG="$d/config.yaml" TEGO_TEST_CHAIN_ANCHOR="$d/chain.log" TEGO_TEST_OWN_LOG_HOME="$d/log-home" HISTFILE=/dev/null "$@"
	fi
}

failed=0
say() { echo "MATRIX-RESULT $*"; }
# Kill test 5's knobs the guest was given (matrix.sh's VM_KT5_RUNS and VM_KT5_PLANES; its tiers are named where used),
# as the VAR=value words `kt` hands the script. Empty: the ten runs of R7's median, and the plane the boot selects.
kt5_opts=()
[ -z "${VM_KT5_RUNS:-}" ] || kt5_opts+=("KT5_RUNS=$VM_KT5_RUNS")
[ -z "${VM_KT5_PLANES:-}" ] || kt5_opts+=("KT5_PLANES=$VM_KT5_PLANES")
# note_facts prints this boot's facts line from the text of a root `tego doctor` (doctor-facts.sh): the Landlock ABI and
# the decision plane tier cgroup decides opens by. matrix.sh keeps the first one a boot prints in summary.json, per row
# and boot. A text it cannot read prints no line, and says so on stderr.
note_facts() {
	local facts
	if facts="$("$here/doctor-facts.sh" <<<"$1" 2>&1)"; then
		echo "MATRIX-FACTS $facts"
	else
		echo "run-matrix-row: no facts from doctor's text: $facts" >&2
	fi
}

echo "MATRIX-KERNEL $(uname -r) lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"
if [ "$(id -u)" != 0 ] || [ -z "${SUDO_UID:-}" ]; then
	echo "run-matrix-row: must run as root with SUDO_UID set (kvm-run.sh --sudo)" >&2
	exit 1
fi
iso_dir_root="$(mktemp -d /tmp/matrix-iso-root-XXXXXX)"
iso_dir_user="$(mktemp -d /tmp/matrix-iso-user-XXXXXX)"
trap 'rm -rf "$iso_dir_root" "$iso_dir_user"' EXIT
iso_make "$iso_dir_root" 0
iso_make "$iso_dir_user" "$SUDO_UID"
# The guest's python3 runs the fixture dump and kill tests 4 and 7; a guest built from a host whose interpreter's
# stdlib was not staged (kvm-run.sh names the host's own version) dies at startup with "No module named
# encodings". Say so here, by name, rather than in each of those steps.
if py_err="$(python3 -c 'import encodings, tarfile, base64' 2>&1)"; then
	say "guest-python root PASS 0"
else
	echo "$py_err"
	say "guest-python root FAIL 1 the guest's python3 cannot import its stdlib: ${py_err##*$'\n'}"
	failed=1
fi
covdir=""
if [ "${VM_COVER:-0}" = 1 ]; then
	covdir=/tmp/tego-covdata
	mkdir -p "$covdir" && chmod 1777 "$covdir"
	export GOCOVERDIR="$covdir"
fi

# doctor_check runs doctor as one identity and judges its tier against what §12.2 expects of it.
doctor_check() {
	local name="$1" want="$2" who="$3" out rc tier
	echo "== $name"
	out="$(with_iso "$who" "$tego" doctor 2>&1)"
	rc=$?
	echo "$out"
	[ "$name" != doctor-root ] || note_facts "$out"
	tier="$(sed -n 's/^tier: //p' <<<"$out" | head -1)"
	if [ "$rc" = 0 ] && [ "$tier" = "$want" ]; then
		say "$name ${name#doctor-} PASS $rc tier=$tier"
	else
		say "$name ${name#doctor-} FAIL $rc tier=${tier:-none}, want $want: $(grep -E '^missing for '"$want"':' <<<"$out" | head -1)"
		failed=1
	fi
}

# kt runs one kill test as one identity, prints its output (its KT-HALF lines among it), then one result
# line for its exit.
# Usage: kt <script> <user|root> [VAR=value...] [-- script arguments...]
kt() {
	local script="$1" who="$2" log rc verdict detail vars=() args=()
	shift 2
	while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
	[ "${1:-}" != -- ] || { shift; args=("$@"); }
	log="$(mktemp /tmp/matrix-kt-XXXXXX)"
	chmod 644 "$log"
	echo "== $script as $who ${vars[*]} ${args[*]}"
	local start=$SECONDS
	if [ "$who" = user ]; then
		(cd /tmp && as_user env "${vars[@]}" "$here/bounded-run.sh" "$TEST_TIMEOUT" "$e2e/$script.sh" "${args[@]}") >"$log" 2>&1
	else
		(cd /tmp && env "${vars[@]}" "$here/bounded-run.sh" "$TEST_TIMEOUT" "$e2e/$script.sh" "${args[@]}") >"$log" 2>&1
	fi
	rc=$?
	cat "$log"
	verdict="$(kt_verdict "$rc")"
	# A skip here is a failure: every kill test this row runs is one the row exists for, and a skip (no jq,
	# no sudo user) means enforcement was not exercised on this kernel. matrix.sh's report says the same.
	[ "$verdict" = PASS ] || failed=1
	detail="$(grep -E '^(PASS|FAIL|SKIP):' "$log" | tail -1 | cut -c1-300)"
	# timeout(1)'s own code is 124, or 125 from uutils' timeout when the killed command then exits; the
	# elapsed time is what says the kill test was stopped rather than failing on its own.
	[ $((SECONDS - start)) -lt "$TEST_TIMEOUT" ] || detail="ran past VM_TEST_TIMEOUT=${TEST_TIMEOUT}s and was stopped"
	say "$script${args[*]:+[${args[*]}]}${vars[*]:+[${vars[*]}]} $who $verdict $rc $detail"
	rm -f "$log"
}

# tier3 runs kill tests 1, 4, 5 and 7 (b) at tier bpflsm (TIER3-PLAN T11, enforce-plane R28) where bpf is an active LSM:
# first doctor as root must offer the tier (R28's "bpflsm yes"), then each kill test at it, whose skip fails the row as
# any kill test's does. Kill tests 4 and 5 run here only when asked (their full runs already add bpflsm to their
# default tiers).
# Where bpf is not active, the one line says so and is not a failure: the row's second boot, with the lsm= line
# doctor printed, runs them.
tier3() {
	local with_kt45="$1" lsm out rc
	lsm="$(cat /sys/kernel/security/lsm 2>/dev/null)"
	case ",$lsm," in
	*,bpf,*) ;;
	*)
		say "tier3 - SKIP - bpf is not an active LSM on this boot (lsm=$lsm): kill tests 1, 4, 5 and 7 at bpflsm run after the lsm= fix"
		return
		;;
	esac
	echo "== doctor-bpflsm"
	out="$(with_iso root "$tego" doctor --require bpflsm 2>&1)"
	rc=$?
	echo "$out"
	note_facts "$out"
	if [ "$rc" = 0 ]; then
		say "doctor-bpflsm root PASS 0 bpf is an active LSM and doctor offers tier bpflsm"
	else
		say "doctor-bpflsm root FAIL $rc bpf is an active LSM and doctor refuses tier bpflsm: $(grep -E 'bpflsm' <<<"$out" | head -1)"
		failed=1
	fi
	kt kt1-identity root KT_TIER=bpflsm
	[ "$with_kt45" != yes ] || kt kt4-ordinary root KT4_TIERS=bpflsm
	[ "$with_kt45" != yes ] || kt kt5-ask root KT5_TIERS=bpflsm "${kt5_opts[@]+"${kt5_opts[@]}"}"
	kt kt7-two-agents root KT7_TIER=bpflsm -- b
}

# doctor_refusal runs doctor-refusal.sh as one identity and turns its verdict into one result line: the body of a
# doctor-only row, where doctor offers no tier and no kill test has one to run at. The script's own last line (PASS:
# or FAIL: and the parts that were wrong) is the detail.
doctor_refusal() {
	local who="$1" log rc verdict detail
	log="$(mktemp /tmp/matrix-dr-XXXXXX)"
	chmod 644 "$log"
	echo "== doctor-refusal.sh as $who"
	if [ "$who" = user ]; then
		(cd /tmp && as_user "$here/bounded-run.sh" "$TEST_TIMEOUT" "$here/doctor-refusal.sh" "$tego") >"$log" 2>&1
	else
		(cd /tmp && "$here/bounded-run.sh" "$TEST_TIMEOUT" "$here/doctor-refusal.sh" "$tego") >"$log" 2>&1
	fi
	rc=$?
	cat "$log"
	[ "$who" != root ] || note_facts "$(with_iso root "$tego" doctor 2>&1)"
	detail="$(grep -E '^(PASS|FAIL):' "$log" | tail -1 | cut -c1-300)"
	verdict=PASS
	[ "$rc" = 0 ] || { verdict=FAIL; failed=1; }
	say "doctor-refusal $who $verdict $rc ${detail#*: }"
	rm -f "$log"
}

if [ "$only" = doctor-refusal ]; then
	doctor_refusal user
	doctor_refusal root
elif [ "$only" = kt6c ]; then
	kt kt6-fresh-vm root -- c
	tier3 yes
elif [ "$only" = kt4 ]; then
	kt kt4-ordinary root ${VM_KT4_TIERS:+"KT4_TIERS=$VM_KT4_TIERS"}
elif [ "$only" = kt5 ]; then
	kt kt5-ask root ${VM_KT5_TIERS:+"KT5_TIERS=$VM_KT5_TIERS"} "${kt5_opts[@]+"${kt5_opts[@]}"}"
elif [ "$only" = smoke ]; then
	kt smoke-exec-rules user KT_TIER=landlock
	kt smoke-exec-rules root KT_TIER=cgroup
else
	doctor_check doctor-user landlock user
	# §12.2 wants tier cgroup "with sudo" and no boot change; where bpf is already an active LSM, tier bpflsm is
	# the highest tier doctor reaches as root with the objects (T7), so that is the tier it must report.
	root_want=cgroup
	case ",$(cat /sys/kernel/security/lsm 2>/dev/null)," in *,bpf,*) root_want=bpflsm ;; esac
	doctor_check doctor-root "$root_want" root
	kt kt1-identity user KT_TIER=landlock
	kt kt1-identity root KT_TIER=cgroup
	kt smoke-exec-rules user KT_TIER=landlock
	kt smoke-exec-rules root KT_TIER=cgroup
	kt kt2-capture user
	kt kt2-capture root
	kt kt4-ordinary root ${VM_KT4_TIERS:+"KT4_TIERS=$VM_KT4_TIERS"}
	kt kt5-ask root ${VM_KT5_TIERS:+"KT5_TIERS=$VM_KT5_TIERS"} "${kt5_opts[@]+"${kt5_opts[@]}"}"
	kt kt6-fresh-vm root
	kt kt7-two-agents root
	tier3 no
	if [ "${VM_KT3:-0}" = 1 ]; then
		kt kt3-overhead root
	else
		say "kt3-overhead root SKIP - not run: §9's budgets need a quiet dedicated machine, not a shared two-vCPU guest (VM_KT3=1 runs it anyway)"
	fi
fi

if [ -n "${KT_FIXTURE_DIR:-}" ] && [ -d "$KT_FIXTURE_DIR" ] && [ -n "$(ls -A "$KT_FIXTURE_DIR" 2>/dev/null)" ]; then
	# python3 rather than tar: the guest carries this host's python3 and not its tar.
	echo "MATRIX-FIXTURES-BEGIN"
	python3 - "$KT_FIXTURE_DIR" <<-'PY'
	import base64, io, sys, tarfile
	buf = io.BytesIO()
	with tarfile.open(fileobj=buf, mode="w:gz") as t:
	    t.add(sys.argv[1], arcname=".")
	data = base64.b64encode(buf.getvalue()).decode()
	for i in range(0, len(data), 120):
	    print(data[i:i + 120])
	PY
	echo "MATRIX-FIXTURES-END"
fi
if [ -n "$covdir" ]; then
	for f in "$covdir"/*; do
		[ -f "$f" ] && echo "TEGO-COVFILE ${f##*/} $(base64 -w0 "$f")"
	done
fi
exit "$failed"
