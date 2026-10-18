#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# soak.sh -- a long unattended run of the custom agent under tego, sampled every minute (README.md). It
# answers: over hours, does tego leak memory or descriptors, burn cpu, slow the agent, fill a disk, or fail the run for
# ledger reasons? Each ARM is one run at one record level (full, summary or off); two arms can run side by side.
#
#   soak.sh start  ARM [SECONDS]   start the arm in a transient user service, or under nohup where there is no systemd --user
#                                  (SOAK_NOHUP=1 forces it); default 7200 s = 2 hours; ARM is a record level,
#                                  full, summary or off, optionally with a label (full-fast): one service and one directory each
#   soak.sh resume ARM             carry on an arm whose service stopped (a reboot, a kill): a new run, a new segment
#   soak.sh status [ARM]           state, the last sample, the segments
#   soak.sh analyze [ARM...]       the CSV's analysis and the 20-hour extrapolation (soak_analyze.py)
#   soak.sh stop   ARM             stop the arm now
#   soak.sh selftest               a minute-long arm that is stopped half way and resumed: two segments, the whole target
#
# Environment: TEGO_BIN=<tego built with -tags tegotesthooks> (required by start; it is copied into the arm, so a later
# rebuild changes nothing), SOAK_DIR=<where the arms live; default $TMPDIR/tego-custom-soak>, SOAK_INTERVAL=<seconds
# between samples, 60>, SOAK_AGENT_ARGS=<agent.py's arguments; the chatter>, SOAK_TOKENS and SOAK_COST_USD=<the limits.tokens
# and limits.cost_usd the contract carries: 5000000 and 5, far above what the default chatter spends; raise them with it>.
# The last three are kept with the arm, so that resume runs the same soak. Each arm is a directory with its own tego
# (config, ledger, chain anchor, log), workspace and stand-in model: the real ~/.tego is never touched. Results:
# $SOAK_DIR/ARM/samples.csv, one row per sample, and analyze's text.
# shellcheck disable=SC2154,SC2034 # state, bin, ws, outside, stub_pid, listener_port and repo are lib.sh's, which is sourced
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
soak=${SOAK_DIR:-${TMPDIR:-/tmp}/tego-custom-soak}
cmd=${1:-}
arm=${2:-}

usage() {
	cat >&2 <<'USAGE'
usage: soak.sh start ARM [SECONDS] | resume ARM | status [ARM] | analyze [ARM...] | stop ARM | selftest
       ARM is a record level, full, summary or off, with an optional label (full-fast). See the header of soak.sh.
USAGE
	exit 2
}

# segments_done_s: the seconds the arm's finished segments ran (each segment-N.start has a segment-N.end)
segments_done_s() {
	local f n=0 s e
	for f in "$1"/segment-*.end; do
		[ -e "$f" ] || continue
		s=$(cat "${f%.end}.start")
		e=$(cat "$f")
		n=$((n + e - s))
	done
	echo "$n"
}

# close_interrupted DIR: a segment with a start and no end ran until its service was stopped or killed; its end is its
# last sample, and the arm's remaining time counts it
close_interrupted() {
	local f n s last
	for f in "$1"/segment-*.start; do
		[ -e "$f" ] || continue
		n=${f##*/segment-}
		n=${n%.start}
		[ -e "$1/segment-$n.end" ] && continue
		s=$(cat "$f")
		last=$(awk -F, -v seg="$n" 'NR > 1 && $3 == seg {e = $2} END {print e + 0}' "$1/samples.csv" 2>/dev/null)
		echo $((s + last)) >"$1/segment-$n.end"
		echo interrupted >"$1/segment-$n.exit"
	done
}

have_systemd_user() { command -v systemd-run >/dev/null && systemctl --user show --property=Version >/dev/null 2>&1; }

# is_running ARM: its service is active, or its nohup process is alive
is_running() {
	{ [ -f "$soak/$1/unit.pid" ] && kill -0 "$(cat "$soak/$1/unit.pid")" 2>/dev/null; } ||
		systemctl --user is-active --quiet "tego-soak-$1.service" 2>/dev/null
}

launch() { # launch ARM: the arm's main process, in a transient user service, or under nohup where there is none
	if [ "${SOAK_NOHUP:-0}" != 1 ] && have_systemd_user; then
		systemd-run --user --unit="tego-soak-$1" --collect --quiet \
			--setenv=SOAK_DIR="$soak" --setenv=SOAK_INTERVAL="${SOAK_INTERVAL:-60}" \
			-- bash "$here/soak.sh" run "$1" &&
			echo "soak.sh: arm $1 running as tego-soak-$1.service; results in $soak/$1/samples.csv"
	else
		rm -f "$soak/$1/unit.pid"
		SOAK_DIR="$soak" SOAK_INTERVAL="${SOAK_INTERVAL:-60}" setsid nohup bash "$here/soak.sh" run "$1" \
			>"$soak/$1/unit.log" 2>&1 </dev/null &
		echo $! >"$soak/$1/unit.pid"
		echo "soak.sh: arm $1 running under nohup (pid $!); results in $soak/$1/samples.csv"
	fi
}

case $cmd in
start)
	[ -n "$arm" ] || usage
	case $arm in full | summary | off | full-* | summary-* | off-*) ;; *) echo "soak.sh: ARM is a record level, full, summary or off, with an optional -label" >&2; exit 2 ;; esac
	[ -x "${TEGO_BIN:-}" ] || { echo "soak.sh: set TEGO_BIN to a tego built with -tags tegotesthooks" >&2; exit 2; }
	# A product build ignores the anchor and own-log variables and would anchor the soak's runs in the invoking user's
	# own ~/.tego/chain.log (identity-config.md R27; tools/isocheck SH-6). Only the test build contains the name.
	grep -aq TEGO_TEST_CHAIN_ANCHOR "$TEGO_BIN" 2>/dev/null || {
		echo "soak.sh: $TEGO_BIN is not built with -tags tegotesthooks; it would write the real ~/.tego/chain.log" >&2
		exit 2
	}
	if [ -e "$soak/$arm" ]; then
		echo "soak.sh: $soak/$arm exists; 'resume $arm' carries it on" >&2
		exit 2
	fi
	mkdir -p "$soak/$arm/bin"
	chmod 755 "$soak" "$soak/$arm" "$soak/$arm/bin"
	cp "$TEGO_BIN" "$soak/$arm/bin/tego"
	echo "${3:-7200}" >"$soak/$arm/seconds"
	[ -z "${SOAK_AGENT_ARGS:-}" ] || echo "$SOAK_AGENT_ARGS" >"$soak/$arm/agent-args"
	echo "${SOAK_TOKENS:-5000000} ${SOAK_COST_USD:-5}" >"$soak/$arm/budgets"
	launch "$arm"
	;;
resume)
	[ -d "$soak/${arm:-?}" ] || { echo "soak.sh: no arm $arm under $soak" >&2; exit 2; }
	if is_running "$arm"; then
		echo "soak.sh: arm $arm is still running" >&2
		exit 0
	fi
	close_interrupted "$soak/$arm"
	launch "$arm"
	;;
stop)
	if [ -f "$soak/${arm:?}/unit.pid" ] && kill -0 "$(cat "$soak/$arm/unit.pid")" 2>/dev/null; then
		kill -- "-$(cat "$soak/$arm/unit.pid")" # the arm's process group: setsid made it a leader
	else
		systemctl --user stop "tego-soak-$arm.service"
	fi
	;;
status)
	if [ -n "$arm" ]; then dirs=("$soak/$arm"); else dirs=("$soak"/*/); fi
	for d in "${dirs[@]}"; do
		[ -f "$d/seconds" ] || continue
		a=$(basename "$d")
		echo "== $a: $(is_running "$a" && echo running || echo stopped); target $(cat "$d/seconds") s;" \
			"finished segments ran $(segments_done_s "$d") s"
		for f in "$d"/segment-*.exit; do [ -e "$f" ] && echo "   $(basename "${f%.exit}") ended: exit $(cat "$f")"; done
		[ -f "$d/samples.csv" ] && {
			head -1 "$d/samples.csv"
			tail -1 "$d/samples.csv"
		}
	done
	;;
analyze)
	shift
	exec python3 "$here/soak_analyze.py" "$soak" "$@"
	;;
selftest)
	[ -x "${TEGO_BIN:-}" ] || { echo "soak.sh: set TEGO_BIN to a tego built with -tags tegotesthooks" >&2; exit 2; }
	# A product build ignores the anchor and own-log variables and would anchor the soak's runs in the invoking user's
	# own ~/.tego/chain.log (identity-config.md R27; tools/isocheck SH-6). Only the test build contains the name.
	grep -aq TEGO_TEST_CHAIN_ANCHOR "$TEGO_BIN" 2>/dev/null || {
		echo "soak.sh: $TEGO_BIN is not built with -tags tegotesthooks; it would write the real ~/.tego/chain.log" >&2
		exit 2
	}
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-soak-selftest-XXXXXX") || exit 1
	chmod 755 "$tmp"
	export SOAK_DIR=$tmp SOAK_INTERVAL=5
	soak=$tmp # this process's own view of it, for is_running and segments_done_s
	unset SOAK_AGENT_ARGS
	t=off-selftest
	"$0" start "$t" 60 >/dev/null || exit 1
	sleep 25
	"$0" stop "$t"
	sleep 3
	"$0" resume "$t" >/dev/null || exit 1
	while is_running "$t"; do sleep 2; done
	segs=$(find "$tmp/$t" -maxdepth 1 -name 'segment-*.start' | wc -l)
	ran=$(segments_done_s "$tmp/$t")
	rows=$(($(wc -l <"$tmp/$t/samples.csv") - 1))
	ok=0
	[ "$segs" = 2 ] && [ "$ran" -ge 58 ] && [ "$ran" -le 75 ] && [ "$rows" -ge 10 ] && python3 "$here/soak_analyze.py" "$tmp" "$t" >"$tmp/analysis.out" || ok=1
	# the last sample is taken after tego ended (counters -1): its cpu must still be counted, from the last live row
	grep -Eq '; [0-9.]+ cpu-seconds in all' "$tmp/analysis.out" && ! grep -Eq '; 0(\.0)? cpu-seconds in all' "$tmp/analysis.out" || ok=1
	echo "$([ "$ok" = 0 ] && echo PASS || echo FAIL)  soak selftest: $segs segments, $ran s of a 60 s target, $rows samples, the analysis reads them and counts tego's cpu"
	rm -rf "$tmp"
	exit "$ok"
	;;
run) # the arm's main process, started by launch
	[ -d "$soak/${arm:-?}" ] || exit 2
	dir=$soak/$arm
	seconds=$(cat "$dir/seconds")
	interval=${SOAK_INTERVAL:-60}
	record=${arm%%-*}
	read -r tokens cost_usd <"$dir/budgets" 2>/dev/null || { tokens=5000000 cost_usd=5; }
	close_interrupted "$dir"
	done_s=$(segments_done_s "$dir")
	remaining=$((seconds - done_s))
	if [ "$remaining" -le 5 ]; then
		echo "soak.sh: arm $arm has already run its $seconds s"
		exit 0
	fi
	helpers=()
	cleanup() {
		local p
		for p in "${helpers[@]}"; do kill "$p" 2>/dev/null; done
	}
	trap cleanup EXIT
	export TEGO_BIN=$dir/bin/tego
	# shellcheck source=lib.sh
	. "$here/lib.sh"
	lib_init "$dir" || exit 1
	seg=$(($(find "$dir" -maxdepth 1 -name 'segment-*.start' | wc -l) + 1))
	python3 "$here/model_script.py" task >"$dir/script.json"
	lib_stub "$dir/script.json" || exit 1
	lib_listener
	[ "$seg" = 1 ] && lib_workspace soak
	ws=$dir/ws-soak
	outside=$dir/outside-soak
	# The contract is the one a long unattended run should carry: every limit the engine has, set far above what a healthy
	# loop reaches, so that the soak also shows they raise no false alarm over hours.
	lib_contract "$dir/contract/soak.yaml" "$record" "${SOAK_ASK_TIMEOUT:-5s}" "wall: $((remaining + 900))s" \
		"stall_after: 5m" "repeats: 8" "tokens: $tokens" "cost_usd: $cost_usd" "memory: 1GiB" "pids: 64" "cpu: 2"
	args_text="--sleep 0.5 --read-files 25 --bad-every 40 --bad cred,push,connect,outside,ask-a --report-every 300"
	[ ! -s "$dir/agent-args" ] || args_text=$(cat "$dir/agent-args")
	read -r -a args <<<"$args_text"
	start=$(date +%s)
	echo "$start" >"$dir/segment-$seg.start"
	earlier=$(find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%f\n')
	(
		cd "$ws" || exit 1
		PATH="$ws/bin:$PATH" exec "$bin" watch --boundary "$dir/contract/soak.yaml" -- python3 agent.py "${args[@]}" \
			--bad-port "$listener_port" --outside "$outside" --max-seconds "$remaining"
	) >"$dir/agent-$seg.out" 2>"$dir/watch-$seg.err" </dev/null &
	ev_pid=$!
	for _ in $(seq 1 100); do # this segment's run is the one that was not there before it started
		run=$(find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%f\n' | grep -vxF -f <(echo "$earlier") | head -1)
		[ -n "$run" ] && break
		sleep 0.1
	done
	[ -n "${run:-}" ] || { echo "soak.sh: tego started no run" >&2; exit 1; }
	echo "$run" >"$dir/segment-$seg.run"
	python3 "$here/soak_sample.py" "$dir" "$run" "$ev_pid" "$seg" "$((start + remaining + 120))" "$interval" &
	sampler=$!
	wait "$ev_pid"
	rc=$?
	echo "$rc" >"$dir/segment-$seg.exit"
	date +%s >"$dir/segment-$seg.end"
	wait "$sampler"
	# the whole ledger read back once the run is over: how long each view takes on a ledger this size is the figure for a
	# 20-hour one (the verify line first, then the time of each command)
	{
		"$bin" events "$run" --verify
		TIMEFORMAT="%R s"
		for c in "status $run" "measure $run" "drift $run" "events $run --last" "events $run --kind refused --limit 20" \
			"events $run --verify"; do
			# shellcheck disable=SC2086 # $c is a command line with arguments, split on purpose
			echo "$c: $({ time "$bin" $c >/dev/null 2>&1; } 2>&1)"
		done
	} >"$dir/segment-$seg.verify" 2>&1
	;;
*)
	usage
	;;
esac
