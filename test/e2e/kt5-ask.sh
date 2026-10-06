#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt5-ask.sh — kill test 5 (docs/FEATURES.md "Kill test 5 (R7)": "the contract declares one `fs.ask` and one
# `net.ask` entry the workload never touches; compared with the same contract without them, the run is slower by
# under 1% of wall time or 1 s, whichever is larger, on the 20-step agent and on the build workload, in every tier;
# `run_end` carries `supervisor{notifications, held_ms}`"; docs/p0/supervisor.md §10 "E2E").
#
# What it attacks: that an approval nobody asks for is free. An ask entry is answered by the supervisor, so a
# contract that declares one keeps the supervisor in the loop for what the kernel would otherwise decide alone: at
# tiers cgroup and bpflsm the seccomp filter stops notifying fs mutations, write-opens and truncate only while the
# contract has no fs.ask entry (enforce/landlock planeSkips, ADR 0024 (14), enforce-plane R27), so with one every such
# syscall of the workload is a notification again. Whether that costs under a second a run is a measurement and not a
# given (FEATURES E13: "kill test 5 is a per-tier measurement, not a given"), and this is the measurement, in every
# tier the machine allows.
#
# The two workloads R7 names, each under one contract with and without the two entries:
#   agent20  the 20-step agent of kill test 2 (test/workloads/python-steps) through the forwarder, against the local
#            model stand-in (test/workloads/model-stub): twenty model calls and a handful of syscalls, the cost of
#            the run is the run's own fixed cost and the notifications it keeps;
#   pip      the build workload of kill test 4 (test/workloads/build/python): `pip install` of the pinned wheels from
#            the local wheelhouse and `pytest` over them, thousands of file creations, the write-heavy case the
#            plane's skips exist for.
# Both are exact and repeatable on any box with python3, openssl (agent20) and the wheelhouse test/e2e/pydeps.sh
# caches (pip). A workload this box lacks is a named skip, never a pass.
#
# "The same contract without them": the two contracts of a cell are one text, and differ in the two ask lines and in
# nothing else. Both carry a net: section, with one allow entry nobody connects to, because net.ask cannot be
# declared without one and the network policy a net: section brings is what kill tests 3 and 4 measure; the delta
# here is the entries'. The fs.ask entry is a directory the run never opens (R22: a literal path, no grant), the
# net.ask entry a documentation address nothing answers on (RFC 5737). Each run's ledger must show them untouched
# (no ask or answer line), the supervisor in the loop (run_end.supervisor.notifications above zero) and the approval
# machinery live for the run that declared the entries and not for the other (run_start.capabilities.ask), or the cell
# fails: a run that never asked, in a tier whose supervisor saw nothing, or two contracts tego took for one,
# measured nothing.
#
# What a cell measures: one run of each contract that is not counted (it primes the page cache and the plane's
# build, and proves both contracts run), then KT5_RUNS (10: "the median of ten") pairs, the two contracts back to
# back, base first on the odd pairs and ask first on the even ones, so a host whose load drifts, or whose build
# lingers or does not, falls on both alike. A cell passes when the median wall time under the ask contract is under
# the base contract's by 1% or 1 s, the larger (kt5_budget_ms), and is a FAIL printed as TARGET-MISS with the figure
# when it is not: the budget is fixed, and a miss is the condition reported, not a number to move.
# The wall time is taken inside the bound that stops a hung launcher, as kill test 4's is (test/e2e/kt4-ordinary.sh,
# kt5_timer): timeout(1) notices its command's exit up to 100 ms late where it is uutils', the same on both contracts,
# but then the medians printed are not the runs' own, and the 1% is taken of them.
#
# Tiers: $KT5_TIERS, default "landlock", plus "cgroup" and "bpflsm" as root under sudo where doctor offers them. Tier
# cgroup is a cell per decision plane its run was decided by (run_start.decision_plane: lsm, fmod_ret, or fanotify
# where the listener fell back), named in the cell: pinning one needs a binary built with -tags tegotesthooks, whose
# TEGO_TEST_PLANE $KT5_PLANES names (auto, lsm, fmod_ret, fanotify, space-separated; default auto), and a pin the run
# did not get (the mode is unavailable here, or the binary ignores the variable) is a named skip, not a pass under a
# label the run did not have. Tier bpflsm is the plane in LSM mode.
#
# Other knobs: KT5_KINDS (default "agent20 pip"), KT5_RUNS (10), KT5_RECORDS (record modes, default "summary"; a
# mode other than summary is named in the cell: FEATURES asks for the figure per tier and mode).
#
# Exit 0 when every cell that ran passed, 1 when one failed, 77 when none could run; one KT-HALF line per cell,
# with the medians, the figure and run_end.supervisor's medians — see test/e2e/lib.sh.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

KT5_RUNS="${KT5_RUNS:-10}" # R7's acceptance: the median of ten runs of each contract
case "$KT5_RUNS" in
'' | *[!0-9]* | 0)
	echo "kt5-ask.sh: KT5_RUNS must be a positive integer, not \"$KT5_RUNS\"" >&2
	exit 2
	;;
esac
kinds="${KT5_KINDS:-agent20 pip}"
records="${KT5_RECORDS:-summary}"
planes="${KT5_PLANES:-auto}"
ALLOW_NET="tcp://192.0.2.1:443" # the net: section both contracts carry; RFC 5737 TEST-NET-1, never routed
ASK_NET="tcp://192.0.2.2:443"   # the net.ask entry: the next address of it, which nothing in either workload connects to

tego="$(kt_ensure_tego)"
repo="$(kt_repo_root)"
if kt_am_root && ! kt_sudo_user; then
	kt_skip "running as root without SUDO_UID: a root tego run drops the agent to the sudo user and has none here"
fi

tiers="${KT5_TIERS:-landlock}"
if [ -z "${KT5_TIERS:-}" ] && kt_sudo_user && kt_tier_available "$tego" cgroup >/dev/null; then
	tiers="landlock cgroup"
	# Tier bpflsm, the decision plane in LSM mode, where the boot allows it.
	if kt_tier_available "$tego" bpflsm >/dev/null; then
		tiers="$tiers bpflsm"
	fi
fi

# A log of tego's own beside the machine config, not the invoking user's ~/.tego/tego.log (a binary built with
# -tags tegotesthooks honours this, as it honours the chain anchor kt_config points into the work directory; a
# product binary ignores it).
export TEGO_TEST_OWN_LOG_HOME="$KT_ROOT/own-log-home"
mkdir -p "$TEGO_TEST_OWN_LOG_HOME"

failed=0
ran=0
result() { # cell verdict text
	kt_half kt5 "$1" "$2" "${*:3}"
	case "$2" in
	PASS) ran=1 ;;
	FAIL) ran=1; failed=1 ;;
	esac
}

# kt5_budget_ms BASE_MS prints what R7 lets the ask contract's run cost over the base contract's, whose median wall
# time is BASE_MS: the larger of 1% of it, rounded up, and one second. A run is within it when it is slower by less.
kt5_budget_ms() {
	local one_percent=$((($1 + 99) / 100))
	echo $((one_percent > 1000 ? one_percent : 1000))
}

# kt5_over_one_percent BASE_MS DELTA_MS succeeds when a run slower by DELTA_MS than one of BASE_MS is slower by 1% of it
# or more (rounded up, as kt5_budget_ms is), so that it can only be inside R7's allowance by the 1 s.
kt5_over_one_percent() {
	[ "$2" -ge $((($1 + 99) / 100)) ]
}

median() {
	# stdin: one integer per line.
	sort -n | awk '{a[NR]=$1} END {if (NR==0) {print 0} else if (NR%2==1) {print a[(NR+1)/2]} else {print int((a[NR/2]+a[NR/2+1])/2)}}'
}

# kt5_timer is the shell that times one run: `bash -c "$kt5_timer" <file> <command...>` runs the command and writes
# its wall time in ms to <file>, taken around the command inside whatever bounds it (kt4-ordinary.sh's kt4_timer says
# why: uutils' timeout notices its command's exit only on a 100 ms poll). The shell traps SIGTERM instead of dying of
# it, so when the bound signals the run's process group it goes on waiting for tego, and the bound still returns when
# tego does.
# shellcheck disable=SC2016 # the timing shell expands it, with the output file as $0
kt5_timer='trap : TERM; t0=$(date +%s%N); "$@"; rc=$?; t1=$(date +%s%N); echo $(((t1 - t0) / 1000000)) >"$0"; exit "$rc"'

# The model stand-in, started once, outside every run (kt_model_stub says why): agent20 talks to it through the
# forwarder, which trusts its certificate through SSL_CERT_FILE.
stub_dir=""
stub_why=""
# shellcheck disable=SC2329 # prepare_agent20 calls it, and run_cell calls prepare_agent20 by name
ensure_stub() {
	[ -z "$stub_why" ] || return 1
	[ -z "$stub_dir" ] || return 0
	command -v python3 >/dev/null 2>&1 || { stub_why="python3 is not on PATH: the 20-step agent is a system-Python agent"; return 1; }
	local d
	d="$(kt_workdir)"
	kt_tls_cert "$d" || { stub_why="openssl could not make a certificate for the local model stand-in"; return 1; }
	kt_model_stub "$d" || { stub_why="the local model stand-in did not start: $(cat "$d/stub.err" 2>/dev/null)"; return 1; }
	stub_dir="$d"
}

# prepare_<kind> sets up one cell's work directory and sets: cmd (the argv, run from cwd), cwd, reset (a command that
# returns the tree to its state before one run), extends, contract_head (contract lines after command:), execs (the
# exec.allow entries), env_lines and limit_lines (the contract's env: and limits: bodies), ok (an extended regular
# expression the run's output must match) and ssl_cert (SSL_CERT_FILE for the launcher, or empty). It prints a reason
# and returns 2 when the kind cannot run here. run_cell calls them by name ("prepare_$kind"), which shellcheck cannot
# follow.
# shellcheck disable=SC2329
prepare_agent20() {
	local agent="$repo/test/workloads/python-steps/agent.py"
	# The stand-in's background process must not hold this function's redirected output.
	ensure_stub >/dev/null || { echo "$stub_why"; return 2; }
	cmd=(python3 "$agent" - 20)
	cwd="$W"
	reset=":"
	extends=""
	# kill test 2's forwarder half: the agent reads ANTHROPIC_BASE_URL, the forwarder's loopback listener ("-"), and
	# the forwarder reaches the stand-in over TLS.
	contract_head=("models:" "  - { provider: anthropic, host: \"127.0.0.1\", port: $KT_STUB_PORT }" "capture: forwarder")
	execs='"python3"'
	env_lines=('  pass: ["PATH", "HOME"]')
	limit_lines=("  pids: 64" "  wall: 120s")
	ok="steps=20 ok=20"
	ssl_cert="$stub_dir/cert.pem"
}

# shellcheck disable=SC2329
prepare_pip() {
	local py
	# shellcheck disable=SC2119 # pydeps.sh's default cache, not this function's arguments
	py="$(kt_pydeps)" || { echo "the pip bootstrap and wheelhouse are not cached and cannot be fetched (test/e2e/pydeps.sh)"; return 2; }
	cp -r "$py/pip-bootstrap" "$py/wheelhouse" "$work/"
	chmod -R go+rX "$work/pip-bootstrap" "$work/wheelhouse"
	cmd=(bash "$repo/test/workloads/build/python/run.sh" "$work/wheelhouse" "$work/pip-bootstrap" "$W/target" "$W/tmp")
	cwd="$W"
	# kill test 4's pip kind (kt4-ordinary.sh prepare_pip says why each entry is there): the install target is kept
	# between runs and only emptied, so the exec entry names a path that exists when the contract compiles.
	mkdir -p "$W/target"
	reset="find '$W/target' -mindepth 1 -delete; rm -rf '$W/tmp'"
	extends="base/python-dev"
	# No capture: this is the cost of an ask entry, and the uprobe source's own cost is kill test 4's.
	contract_head=("capture: off")
	execs="\"bash\", \"dirname\", \"mkdir\", \"$W/target/\""
	env_lines=("  set: { HOME: \"$W/agent-home\", TMPDIR: \"$W/tmp\" }")
	limit_lines=("  wall: 300s")
	ok="[0-9]+ passed"
	ssl_cert=""
}

# write_contract FILE VARIANT writes the cell's contract. The variants are one text: only the two ask lines differ.
write_contract() {
	local file="$1" variant="$2" l
	{
		echo "version: 0"
		echo "name: kt5-$kind"
		[ -z "$extends" ] || echo "extends: $extends"
		echo "command: [$(printf '"%s", ' "${cmd[@]}" | sed 's/, $//')]"
		for l in "${contract_head[@]}"; do echo "$l"; done
		echo "fs:"
		echo "  write: [\"$W/\"]"
		[ "$variant" != ask ] || echo "  ask: [\"$never/\"]"
		echo "net:"
		echo "  allow: [\"$ALLOW_NET\"]"
		[ "$variant" != ask ] || echo "  ask: [\"$ASK_NET\"]"
		echo "exec:"
		echo "  allow: [$execs]"
		echo "env:"
		for l in "${env_lines[@]}"; do echo "$l"; done
		echo "limits:"
		for l in "${limit_lines[@]}"; do echo "$l"; done
		echo "record: $record"
	} >"$file"
}

# ledger_facts DIR prints what the verdict rests on, from the run directory DIR's ledger, as one line "<tier>
# <decision plane or -> <notifications> <held_ms> <ask and answer lines> <run_start's capability ask>", and nothing when
# the ledger has no run_start or no run_end with a supervisor block of numbers (run_end carries
# supervisor{notifications, held_ms}, FEATURES R7). The capability is the run's own statement that its approval
# machinery was compiled and started (runstart.go: an AskConfig, a live broker, a started supervisor): true for a run
# that declared the entries and false for one that did not, or the two contracts of a cell are one contract to tego.
ledger_facts() {
	jq -rs '
		([.[] | select(.kind == "run_start")] | first) as $s |
		([.[] | select(.kind == "run_end")] | first) as $e |
		if $s == null or $e == null or ($e.supervisor | type) != "object"
			or ($e.supervisor.notifications | type) != "number" or ($e.supervisor.held_ms | type) != "number" then empty
		else [$s.tier, ($s.decision_plane // "-"), $e.supervisor.notifications, $e.supervisor.held_ms,
			([.[] | select(.kind == "ask" or .kind == "answer")] | length), ($s.capabilities.ask | tostring)] | join(" ") end' "$1/events.jsonl" 2>/dev/null
}

# one_run VARIANT runs the cell's workload once under that variant's contract, timed, and reads what it left. It sets
# wall (ms), and tier_seen, plane_seen, notif, held and asks from the ledger. It returns 1 with why set when the run
# cannot be judged: it broke, its output is not the workload's, or its ledger lacks what the verdict rests on.
one_run() {
	local v="$1" rc rundir facts want_ask cap_ask
	rm -rf "${cfg:?}/runs"
	eval "$reset"
	rm -f "$work/wall"
	(
		cd "$cwd" || exit 1
		[ "$pin" = auto ] || export TEGO_TEST_PLANE="$pin"
		[ -z "$ssl_cert" ] || export SSL_CERT_FILE="$ssl_cert"
		kt_run bash -c "$kt5_timer" "$work/wall" "$tego" run "$work/$v.yaml" --tier "$tier" --offline -- "${cmd[@]}"
	) >"$work/run.log" 2>&1
	rc=$?
	# No time written means kt_run's SIGKILL, ten seconds past the bound, killed the timing shell with tego.
	wall="$(cat "$work/wall" 2>/dev/null || echo $((${KT_RUN_TIMEOUT:-300} * 1000)))"
	if [ "$rc" -ne 0 ]; then
		why="the $v contract's run exited $rc ($(kt_err_line "$work/run.log"))"
		return 1
	fi
	if ! grep -Eq "$ok" "$work/run.log"; then
		why="the $v contract's run exited 0 but its output is not the workload's (no \"$ok\"): $(tail -1 "$work/run.log" | cut -c1-200)"
		return 1
	fi
	rundir="$(kt_rundir "$cfg")"
	if [ -z "$rundir" ]; then
		why="the $v contract's run exited 0 but left no run directory"
		return 1
	fi
	if ! kt_ledger_valid "$rundir/events.jsonl"; then
		why="the $v contract's ledger has a line that is not JSON"
		return 1
	fi
	facts="$(ledger_facts "$rundir")"
	if [ -z "$facts" ]; then
		why="the $v contract's ledger has no run_end carrying a supervisor block of notifications and held_ms (FEATURES R7), so the run cannot be attributed"
		return 1
	fi
	read -r tier_seen plane_seen notif held asks cap_ask <<<"$facts"
	if [ "$tier_seen" != "$tier" ]; then
		why="the $v contract's run was asked for tier $tier and ran at tier $tier_seen"
		return 1
	fi
	want_ask=false
	[ "$v" != ask ] || want_ask=true
	if [ "$cap_ask" != "$want_ask" ]; then
		why="the $v contract's run_start says capabilities.ask is $cap_ask, want $want_ask: its approval machinery is not what its entries say, so the pair does not compare a contract with entries to one without"
		return 1
	fi
	if [ "$asks" != 0 ]; then
		why="the $v contract's run touched an ask entry ($asks ask or answer lines): the entries are to be ones the workload never touches"
		return 1
	fi
}

# run_cell KIND TIER PIN RECORD sets up one cell, measures it and reports it.
run_cell() {
	local kind="$1" tier="$2" pin="$3" record="$4"
	# A cell is named by its workload and tier, then the plane that decided it at tier cgroup, then a record mode
	# other than summary: agent20-landlock, pip-cgroup@fmod_ret, pip-bpflsm+off.
	local cell="$kind-$tier" suffix="" work cfg W never why wall tier_seen plane_seen notif held asks
	local cmd=() cwd reset extends contract_head=() execs env_lines=() limit_lines=() ok ssl_cert
	[ "$record" = summary ] || suffix="+$record"
	work="$(kt_workdir)"
	cfg="$(kt_workdir)"
	# The machine config, ledger root, profiles and chain anchor sit in a directory of their own: tego's own
	# directory may hold nothing a write entry reaches (agent-contract R10), and the work directory holds those.
	kt_config "$cfg" >/dev/null
	W="$work/write"
	never="$work/never"
	mkdir -p "$W/agent-home" "$W/tmp" "$never"
	# Called in this shell, not in a $(...), so the variables it sets survive; a skip's reason goes to a file.
	if "prepare_$kind" >"$work/why"; then
		kt_agent_owns "$W"
		write_contract "$work/base.yaml" base
		write_contract "$work/ask.yaml" ask
		measure_cell
	else
		result "$cell$suffix" SKIP "$(cat "$work/why")"
	fi
	rm -rf "${work:?}" "${cfg:?}"
}

# med prints the median of its arguments.
med() { printf '%s\n' "$@" | median; }

# measure_cell runs and judges the cell run_cell set up (and reports it, or the reason it could not be judged).
measure_cell() {
	local plane="" i v order base_walls=() ask_walls=() base_notif=() ask_notif=() base_held=() ask_held=()
	local base_med ask_med delta budget warm_ms sup timing figure

	# Warm-up: one run of each contract that is not counted. It also names the plane that decided the cell.
	for v in base ask; do
		if ! one_run "$v"; then
			result "$cell$suffix" FAIL "warm-up: $why"
			return
		fi
		[ "$v" != base ] || warm_ms="$wall"
		plane="$plane_seen"
	done
	if [ "$tier" = cgroup ]; then
		if [ "$pin" != auto ] && [ "$plane" != "$pin" ]; then
			result "$cell@$pin$suffix" SKIP "TEGO_TEST_PLANE=$pin was asked for and the run was decided by $plane: the mode is not available on this boot, or this tego is not a -tags tegotesthooks build"
			return
		fi
		cell="$cell@$plane"
	fi
	cell="$cell$suffix"
	# A run ten times the warm-up is broken whatever it does next; bounding it there keeps a launcher that hangs from
	# holding the kill test for kt_run's default bound twenty times over.
	local KT_RUN_TIMEOUT=$((warm_ms * 10 / 1000 + 60))

	for i in $(seq 1 "$KT5_RUNS"); do
		if [ $((i % 2)) = 1 ]; then order="base ask"; else order="ask base"; fi
		for v in $order; do
			if ! one_run "$v"; then
				result "$cell" FAIL "run $i: $why"
				return
			fi
			if [ "$plane_seen" != "$plane" ]; then
				result "$cell" FAIL "run $i: the $v contract's run was decided by $plane_seen, the warm-up's by $plane"
				return
			fi
			if [ "$v" = base ]; then
				base_walls+=("$wall") base_notif+=("$notif") base_held+=("$held")
				continue
			fi
			if [ "$notif" -lt 1 ]; then
				result "$cell" FAIL "run $i: run_end.supervisor.notifications is 0 for the ask contract's run: the supervisor saw nothing of it, so this tier measured nothing"
				return
			fi
			ask_walls+=("$wall") ask_notif+=("$notif") ask_held+=("$held")
		done
	done

	base_med="$(med "${base_walls[@]}")"
	ask_med="$(med "${ask_walls[@]}")"
	delta=$((ask_med - base_med))
	budget="$(kt5_budget_ms "$base_med")"
	kt_note "$cell base wall ms: ${base_walls[*]}; notifications: ${base_notif[*]}; held_ms: ${base_held[*]}"
	kt_note "$cell ask  wall ms: ${ask_walls[*]}; notifications: ${ask_notif[*]}; held_ms: ${ask_held[*]}"
	sup="supervisor notifications $(med "${base_notif[@]}") -> $(med "${ask_notif[@]}"), held_ms $(med "${base_held[@]}") -> $(med "${ask_held[@]}") (base -> ask, medians)"
	timing="base $base_med ms, ask $ask_med ms (medians of $KT5_RUNS runs) against a budget of $budget ms, the larger of 1% of $base_med ms and 1000 ms"
	figure="$(printf '%+d' "$delta") ms ($(awk -v d="$delta" -v b="$base_med" 'BEGIN { printf "%+.1f%%", (b > 0) ? d * 100 / b : 0 }'))"
	if [ "$delta" -ge "$budget" ]; then
		result "$cell" FAIL "TARGET-MISS $figure is not under the budget of $budget ms: $timing; $sup"
	elif kt5_over_one_percent "$base_med" "$delta"; then
		# R7's "1% or 1 s, whichever is larger" is passed here by the second half alone, which a reader should see.
		result "$cell" PASS "$figure, over 1% of the run and inside the allowance by its 1 s: $timing; $sup"
	else
		result "$cell" PASS "$figure: $timing; $sup"
	fi
}

# A workload no prepare_ function names would be a skip with no reason: a usage error instead, as a bad KT5_RUNS is.
for kind in $kinds; do
	if ! declare -F "prepare_$kind" >/dev/null; then
		echo "kt5-ask.sh: KT5_KINDS names \"$kind\", which is not a workload (agent20, pip)" >&2
		exit 2
	fi
done

for tier in $tiers; do
	if ! reason="$(kt_tier_available "$tego" "$tier")"; then
		for kind in $kinds; do result "$kind-$tier" SKIP "tier $tier unavailable: $reason"; done
		continue
	fi
	tier_planes="auto"
	[ "$tier" != cgroup ] || tier_planes="$planes"
	for kind in $kinds; do
		for record in $records; do
			for pin in $tier_planes; do
				run_cell "$kind" "$tier" "$pin" "$record"
			done
		done
	done
done

[ "$failed" = 0 ] || kt_fail "the ask entries cost a run more than R7 allows, or a cell could not be judged (KT-HALF lines above)"
[ "$ran" = 1 ] || kt_skip "none of kill test 5's cells could run here (KT-HALF lines above)"
kt_pass "an untouched fs.ask and net.ask entry cost every cell that could run here under 1% of wall time or 1 s (KT-HALF lines above)"
