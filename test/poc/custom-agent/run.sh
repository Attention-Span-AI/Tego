#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh -- a custom agent under tego, unattended, in COMPRESSED TIME: seconds stand for hours (README.md). The agent
# (agent.py, runaway.py) is a black box to tego; each scenario holds it to a contract and then reads the ledger back
# (report.py) and checks what happened against it. Everything happens under $DEMO_ROOT, with a machine config, ledger,
# price table, chain anchor and log of its own (the tegotesthooks build): the real ~/.tego is never touched, and the
# only network is a stand-in model and a throwaway listener on 127.0.0.1.
#
#   a  a normal unattended loop, with refusals recorded            h  reading the full log afterwards
#   b  nobody answers an ask: refused at ask.timeout, the agent goes on
#   c  a person answers once with approve --always / deny --always; the repeats are answered without holding
#   d  limits.wall ends the run                      e  stall_after and repeats end a hang and a runaway loop
#   f  limits.tokens and limits.cost_usd end a run that spends too much; a budget nothing can count is refused; going round the forwarder
#   g  limits.memory, limits.pids and limits.cpu
#   i  onboarding: the README's checklist on this agent (watch record-only, tego learn, compile --test, a run)
#   j  the ledger cannot grow          k  the model endpoint goes away          l  the launcher is killed
#   m  what recording costs: one file opened 20000 times, unconfined, under summary and under full (FLOOD_COUNT=200000: the most)
#
# Usage: run.sh [all|a|b|c|d|e|f|g|i|j|k|l|m|negative]    (default all; negative: every scenario again with one rule or limit
#                                               removed, which must make the check for it FAIL)
#        DEMO_ROOT=<dir>  keep everything there: it must not exist or must be empty, and its mode is set to 755
#        TEGO_BIN=<tego built with -tags tegotesthooks> to skip the build;  KEEP=1 to keep the scratch directory
# shellcheck disable=SC2154,SC2034 # state, bin, ws, outside, stub_pid, listener_port and repo are lib.sh's, which is sourced
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
what=${1:-all}
if [ -n "${DEMO_ROOT:-}" ]; then
	root=$DEMO_ROOT
	# The demo changes its root's mode and writes and removes files under it, so it takes only a directory that is
	# new or empty: never one that holds anything of anyone's (DEMO_ROOT=$HOME, say).
	if [ -n "$(ls -A -- "$root" 2>/dev/null)" ]; then
		echo "run.sh: DEMO_ROOT=$root is not empty; give a new or empty directory" >&2
		exit 2
	fi
	mkdir -p -- "$root" || exit 1
else
	root=$(mktemp -d "${TMPDIR:-/tmp}/tego-custom-agent-XXXXXX") || exit 1
fi
chmod 755 -- "$root" || exit 1
helpers=()
cleanup() {
	local p
	for p in "${helpers[@]}"; do kill "$p" 2>/dev/null; done
	[ "${KEEP:-0}" = 1 ] || [ -n "${DEMO_ROOT:-}" ] || rm -rf "$root"
}
trap cleanup EXIT
for t in python3 openssl; do command -v "$t" >/dev/null || { echo "run.sh: needs $t" >&2; exit 2; }; done

# shellcheck source=lib.sh
. "$here/lib.sh"
real_home=$(getent passwd "$(id -u)" | cut -d: -f6)
# The real ~/.tego is listed before and after, apart from chain.log: another process of the same account that does not
# redirect its anchor appends to it whenever it ends a run, whatever this script does. For chain.log the check is that
# none of THIS script's runs was anchored there.
tego_home_listing() { [ -d "$real_home/.tego" ] && find "$real_home/.tego" -not -name chain.log -printf '%p %s %T@\n' 2>/dev/null | sort; }
real_chain=$real_home/.tego/chain.log
chain_lines() { if [ -f "$real_chain" ]; then wc -l <"$real_chain"; else echo 0; fi; }
tego_home_listing >"$root/tego-home-before.txt"
chain_before=$(chain_lines)
lib_init "$root" || exit 1
echo "demo directory: $root   (source $state/env.sh to use tego by hand)"
lib_listener

section() { printf '\n==== %s\n' "$1"; }
fail=0
mut=${MUT:-} # the rule or limit negative mode removes (apply_mutation, drop)
quiet=${QUIET:-0}
say() { [ "$quiet" = 1 ] || printf '%s\n' "$@"; }
check() { # check <ok 0|1> <what>
	if [ "$1" = 0 ]; then say "PASS  $2"; else say "FAIL  $2"; fail=1; fi
}
runs_now() { find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%f\n' | sort; }
# run_since <runs_now output from before the watch>: sets $run to the one run the watch created, or to nothing when it
# created none (a run refused before run_start leaves no directory) or several. A scenario never reads the newest run
# instead: after a refusal that is the previous scenario's, whose checks would then pass or fail for the wrong run.
run_since() {
	local new
	new=$(comm -13 <(printf '%s\n' "$1") <(runs_now) | grep .)
	if [ "$(grep -c . <<<"$new")" = 1 ]; then run=$new; else run=; fi
}
cut190() { cut -c1-190 | sed "s#$root#\$ROOT#g"; }

# apply_mutation <contract>: the contract with ONE rule removed, for the negative controls
apply_mutation() {
	case $mut in
	no-forwarder) sed -i '/^models:/,/^capture: forwarder$/d' "$1" ;;
	no-deny-read) sed -i '/deny_read: \["\.\/fake-home\/\.ssh"\]/d' "$1" ;;
	git-allowed) sed -i 's#allow: \["python3", "bash"\]#allow: ["python3", "bash", "git", "/bin/sh"]#' "$1" ;; # the stand-in is a #!/bin/sh script
	connect-allowed) sed -i "s#allow: \[\"unix:/var/run/nscd/socket\"\]#allow: [\"unix:/var/run/nscd/socket\", \"127.0.0.1:$listener_port\"]#" "$1" ;;
	outside-writable) sed -i "s#^    - \"./work/\"#    - \"./work/\"\n    - \"$outside/\"#" "$1" ;;
	ask-writable) sed -i 's#^  ask: \["./held/"\]#  ask: []#; s#^    - "./work/"#    - "./work/"\n    - "./held/"#' "$1" ;;
	esac
}

# run_agent <name> <record> <ask timeout> <model script> <limit>... -- <command...>: one run of the command under the
# contract, in the workspace lib_workspace made. Leaves the run id in $run, tego's exit status in $rc and the output
# (the agent's, then tego's notices) in $root/out-<name>.txt.
run_agent() {
	local name=$1 record=$2 timeout=$3 script=$4 lim=() l before
	shift 4
	while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
		case $mut:${1%%:*} in
		no-"${1%%:*}":*) ;; # a negative control drops the limit it is named for
		# Without the forwarder nothing counts the model budgets, and a contract that declares one is refused at launch,
		# 125 [budget-unmetered] (limits-check-doctor-cli.md R32): the control drops them too, so its run starts.
		no-forwarder:tokens | no-forwarder:cost_usd | no-forwarder:repeats) ;;
		*) lim+=("$1") ;;
		esac
		shift
	done
	shift
	# shellcheck disable=SC2086 # the profile and its argument ("loop 60") are split on purpose
	python3 "$here/model_script.py" $script >"$root/script-$name.json"
	lib_stub "$root/script-$name.json" || return 1
	lib_contract "$root/contract/$name.yaml" "$record" "$timeout" "${lim[@]}"
	l=$root/contract/$name.yaml
	[ -z "${edit:-}" ] || sed -i "${edit//@STUB_PORT@/$stub_port}" "$l" # a scenario's own change to the contract
	apply_mutation "$l"
	set -- "${@//@STUB_PORT@/$stub_port}"
	before=$(runs_now)
	(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch --boundary "$l" -- "$@") >"$root/out-$name.txt" 2>"$root/err-$name.txt" </dev/null
	rc=$?
	run_since "$before"
}

# show_out <name> [lines]: the agent's own output, trimmed; tego's notices are not repeated
show_out() {
	[ "$quiet" = 1 ] && return
	echo "-- the agent's own output (its exit status as tego returned it: $rc):"
	grep -E '^(custom-agent|runaway):' "$root/out-$1.txt" | cut -c1-150 | awk -v n="${2:-12}" 'NR<=n{print "   "$0; next} {last=$0; k++} END{if(k){print "   ... ("k" more lines) ..."; print "   "last}}'
	grep -E '^tego: ' "$root/out-$1.txt" "$root/err-$1.txt" | sed 's#^[^:]*:##' | cut -c1-150 | sed 's/^/   /'
}

# ledger <filter-args...>: tego events, the lines that matter
ledger() {
	[ "$quiet" = 1 ] && return
	"$bin" events "$run" "$@" 2>&1 | cut190
}

# verdict <report scenario> [key=value ...]: report.py's checks against the ledger
verdict() {
	local s=$1 out
	shift
	if [ -n "$run" ]; then
		out=$(python3 "$here/report.py" "$s" "$state" "$run" "$@" 2>&1) || fail=1
	else
		out="FAIL  norun      the watch created no run for the check $s to read (tego exited $rc)"
		fail=1
	fi
	if [ "$quiet" = 1 ]; then
		printf '%s\n' "$out" >>"$root/verdict.txt"
	else
		printf '%s\n' "$out" | sed "s#$root#\$ROOT#g"
	fi
}
exit_is() { check "$([ "$rc" = "$1" ] && echo 0 || echo 1)" "tego watch exited $1 ($2)"; }
verify_ledger() { "$bin" events "$run" --verify >"$root/verify.txt" 2>&1; check "$?" "the ledger verifies: $(sed 's#, anchored in .*##; s#^[^:]*: ##' "$root/verify.txt")"; }

# --- a: a normal unattended loop with refusals recorded --------------------------------------------------------------
s_a() {
	section "a. a normal unattended loop: work, and four things the contract must stop (record: full, 20 s)"
	lib_workspace a
	run_agent a full 3s task "wall: 5m" "stall_after: 10s" "repeats: 8" "pids: 64" "memory: 512MiB" -- python3 agent.py \
		--sleep 0.15 --bad-every 4 --bad cred,push,connect,outside --bad-port "$listener_port" --outside "$outside" \
		--max-seconds 20 --report-every 10
	show_out a 9
	say "-- the ledger (tego events $run), one line per kind of refusal:"
	ledger --kind refused | awk 'NR==1 || !seen[$5" "$6]++' | grep -v '/dev/tty'
	say "-- ... and the model's calls, recorded and counted (ssl_request, ssl_response, decision):"
	ledger --kind ssl_request --kind ssl_response --kind decision --limit 6
	exit_is 0 "the agent's own end"
	verdict normal "ws=$ws" "outside=$outside" "port=$listener_port" "stub_log=$root/stub/requests.log"
	verify_ledger
}

# --- h: reading the full log afterwards -------------------------------------------------------------------------------
s_h() {
	section "h. after the run: what tego status, events, measure, drift and --verify show (run $run, scenario a)"
	[ "$quiet" = 1 ] && return
	echo "-- tego status $run     (state, how long idle, model steps, events, how it ended, gaps, the run's resources):"
	"$bin" status "$run" 2>&1 | cut -c1-200 | sed 's/^/   /'
	echo "-- tego measure $run    (the budget's view: model steps, refusals, tokens and estimated cost, wall):"
	"$bin" measure "$run" 2>&1 | sed -n '3,16p' | sed 's/^/   /'
	echo "-- tego drift $run      (declared against observed, per rule: what was allowed, refused, and never used):"
	"$bin" drift "$run" 2>&1 | sed -n '1,22p' | cut -c1-120 | sed 's/^/   /'
	echo "   (an exec by name is one event per directory of PATH the agent's own search tried: the misses are the observed ones)"
	echo "-- tego events $run --last     (the last refusal, gap or limit: what went wrong last):"
	"$bin" events "$run" --last 2>&1 | cut190 | sed 's/^/   /'
	echo "-- tego events $run --kind exec --rule 'exec[bash]' --limit 3     (any slice of the full record, by kind, rule, verdict, source or step):"
	"$bin" events "$run" --kind exec --rule 'exec[bash]' --limit 3 2>&1 | cut190 | sed 's/^/   /'
	echo "-- tego events $run --verify   (the hash chain, and the anchor kept outside the ledger):"
	"$bin" events "$run" --verify 2>&1 | sed "s#$root#\$ROOT#g" | sed 's/^/   /'
}

# --- b: nobody answers -------------------------------------------------------------------------------------------------
s_b() {
	section "b. nobody answers an ask: the held write is refused at ask.timeout (3 s here; 5 minutes by default, 1 hour at most)"
	lib_workspace b
	run_agent b full 3s task "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 agent.py --sleep 0.1 --bad-every 3 --bad ask-a \
		--max-seconds 16 --report-every 8
	show_out b 8
	say "-- the ledger: each try is its own ask, held the whole timeout, answered by the timeout, refused (ask-timeout):"
	ledger --kind ask --kind answer --kind refused --limit 12
	exit_is 0 "the agent's own end: held, refused and carried on"
	verdict ask-timeout "ws=$ws" ask_timeout=3
}

# answerer <log>: a person at a second terminal. It answers each held write as a person would, after a moment's
# thought, and says what it did: held/report.md is approved for the rest of the run, anything else is denied for it.
answerer() { # answerer <log> <runs_now output from before the run>: answers only the run started since
	local r id op target verdict seen=" " always=(--always)
	[ "$mut" != no-always ] || always=() # the negative control: a person who answers each request and never says "always"
	while :; do
		r=$(comm -13 <(printf '%s\n' "$2") <(runs_now) | grep -m1 .)
		if [ -n "$r" ]; then
			while read -r id _ op target; do
				case "$seen" in *" $id "*) continue ;; esac
				seen="$seen$id "
				case "$target" in */held/report.md) verdict=approve ;; *) verdict=deny ;; esac
				sleep 1
				"$bin" "$verdict" "$r" "$id" "${always[@]}" >/dev/null 2>&1 &&
					echo "[person] tego $verdict ${always[*]}   ($op ${target#"$ws"/})" >>"$1"
			done < <("$bin" ask "$r" 2>/dev/null | grep '^q-')
		fi
		sleep 0.2
	done
}

# --- c: a person answers once -----------------------------------------------------------------------------------------
s_c() {
	section "c. a person answers once, --always: the repeats are answered without holding the agent (ask.timeout 30 s)"
	lib_workspace c
	: >"$root/answers.log"
	answerer "$root/answers.log" "$(runs_now)" &
	local person=$!
	helpers+=("$person")
	run_agent c full 30s task "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 agent.py --sleep 0.1 --bad-every 3 \
		--bad ask-a,ask-b --max-seconds 14 --report-every 7
	kill "$person" 2>/dev/null
	show_out c 6
	say "-- the person's answers (from a second terminal):"
	[ "$quiet" = 1 ] || sed 's/^/   /' "$root/answers.log"
	say "-- the ledger: two human answers, then every repeat answered by standing:<ask id> after 0 s, each its own ask and answer:"
	ledger --kind ask --kind answer --limit 9
	exit_is 0 "the agent's own end"
	verdict ask-person "ws=$ws"
}

# --- d: limits.wall -----------------------------------------------------------------------------------------------------
s_d() {
	section "d. limits.wall ends the run (12 s here stands for the 20 hours of a night; the agent would run 20 s)"
	lib_workspace d
	run_agent d full 3s task "wall: 12s" "pids: 64" "memory: 512MiB" -- python3 agent.py --sleep 0.2 --max-seconds 20 \
		--bad-every 5 --bad cred,push --report-every 5
	show_out d 4
	say "-- the ledger: a limit event names it, run_end says why, and the exit status is 124:"
	ledger --kind limit --kind run_end
	say "-- tego status:"
	[ "$quiet" = 1 ] || "$bin" status "$run" 2>&1 | sed -n 1,2p | sed 's/^/   /'
	exit_is 124 "limit"
	verdict wall ceiling=12 "out=$root/out-d.txt"
}

# --- e: stall_after and repeats -----------------------------------------------------------------------------------------
s_e1() {
	section "e1. limits.repeats ends a runaway loop: the model asks for the same tool call again and again (repeats: 6)"
	lib_workspace e1
	run_agent e1 full 3s "loop 60" "repeats: 6" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py loop --max-steps 60
	show_out e1 4
	ledger --kind limit --kind run_end
	exit_is 124 "limit"
	verdict repeats ceiling=6 "out=$root/out-e1.txt"
}
s_e2() {
	section "e2. limits.stall_after ends a hung agent: nothing at all happens for 5 s (stall_after: 5s)"
	lib_workspace e2
	run_agent e2 full 3s task "stall_after: 5s" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py hang --seconds 15
	show_out e2 4
	ledger --kind limit --kind run_end
	exit_is 124 "limit"
	verdict stall ceiling=5 "out=$root/out-e2.txt"
}
s_e3() {
	section "e3. the limit of stall_after: an agent busy READING is silent under record: summary, and is ended as stalled"
	lib_workspace e3
	run_agent e3 summary 3s task "stall_after: 5s" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py read --seconds 14
	show_out e3 3
	ledger --kind limit --kind run_end --kind gap
	exit_is 124 "limit: a false stall, the reader was busy"
	verdict stall-quiet-summary ceiling=5
	say "-- the same reader under record: full:"
	lib_workspace e3f
	run_agent e3f full 3s task "stall_after: 5s" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py read --seconds 14
	show_out e3f 3
	exit_is 0 "the reader's own end: every read is an event, so it is never silent"
	verdict stall-quiet-full
}
s_e() { s_e1; s_e2; s_e3; }

# --- f: tokens and cost ---------------------------------------------------------------------------------------------------
s_f1() {
	section "f1. limits.tokens ends a run that spends too much: 300 tokens (the stand-in model's calls cost about 22 each)"
	lib_workspace f1
	run_agent f1 full 3s task "tokens: 300" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 agent.py --sleep 0.05 --max-seconds 8
	show_out f1 3
	ledger --kind limit --kind run_end
	exit_is 124 "limit"
	verdict tokens ceiling=300
}
s_f2() {
	section "f2. limits.cost_usd: the price table (\$3 and \$15 per million tokens, a stand-in for the real one) turns tokens into an estimate"
	lib_workspace f2
	run_agent f2 full 3s task "cost_usd: 0.002" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 agent.py --sleep 0.05 --max-seconds 8
	show_out f2 3
	ledger --kind limit --kind run_end
	exit_is 124 "limit"
	verdict cost ceiling=0.002
}
s_f3() {
	section "f3. a budget nothing can count is refused: a tokens budget on an agent whose model traffic tego cannot count (no models: entry)"
	local before
	lib_workspace f3
	python3 "$here/model_script.py" task >"$root/script-f3.json"
	lib_stub "$root/script-f3.json"
	lib_contract "$root/contract/f3.yaml" full 3s "tokens: 300" "wall: 5m" "pids: 64" "memory: 512MiB"
	sed -i '/^models:/,/^capture: forwarder$/d' "$root/contract/f3.yaml"
	(cd "$ws" && "$bin" compile "$root/contract/f3.yaml" --offline) >"$root/compile-f3.txt" 2>&1
	say "-- tego compile says every run of it is refused, and how to fix it:"
	[ "$quiet" = 1 ] || grep -A1 'budget-unmetered' "$root/compile-f3.txt" | cut190 | sed 's/^/   /'
	grep -q 'limits.tokens budget never trips.*refused \[budget-unmetered\]' "$root/compile-f3.txt"
	check "$?" "tego compile reports the tokens budget [budget-unmetered]"
	# The refusal comes before run_start, so the run leaves no directory (run_since, not the newest run, which is the
	# previous scenario's).
	before=$(runs_now)
	(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch --boundary "$root/contract/f3.yaml" -- python3 runaway.py cpu --seconds 2) \
		>"$root/out-f3.txt" 2>"$root/err-f3.txt" </dev/null
	rc=$?
	run_since "$before"
	say "-- the run is refused before the agent starts:"
	[ "$quiet" = 1 ] || grep '^tego run: ' "$root/err-f3.txt" | cut190 | sed 's/^/   /'
	exit_is 125 "refused: a limit that never trips is no limit"
	grep -q 'the tokens budget cannot be counted.*\[budget-unmetered\]$' "$root/err-f3.txt"
	check "$?" "the refusal names the tokens budget and [budget-unmetered]"
	grep -q 'Fix: declare the model endpoint under models:' "$root/err-f3.txt"
	check "$?" "the refusal gives the fix: declare the model endpoint under models:"
	check "$(grep -q '^runaway:' "$root/out-f3.txt" && echo 1 || echo 0)" "the agent never ran (no output of its own)"
	check "$([ -z "$run" ] && [ "$(runs_now)" = "$before" ] && echo 0 || echo 1)" "the refused run left no run directory"
}
s_f4() {
	section "f4. an agent that goes round the forwarder: a connection straight to the model's own address is refused, though net.allow names it"
	lib_workspace f4
	edit='s#allow: \["unix:/var/run/nscd/socket"\]#allow: ["unix:/var/run/nscd/socket", "127.0.0.1:@STUB_PORT@"]#' \
		run_agent f4 full 3s task "tokens: 300" "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py direct --port @STUB_PORT@
	show_out f4 3
	ledger --kind refused
	exit_is 0 "the agent's own end"
	verdict direct
}
s_f() { s_f1; s_f2; s_f3; s_f4; }

# --- g: memory, pids, cpu -------------------------------------------------------------------------------------------------
s_g1() {
	section "g1. limits.memory: a memory hog allocates 8 MiB at a time, to its own cap of 96 MiB; the limit is 40 MiB"
	lib_workspace g1
	run_agent g1 full 3s task "memory: 40MiB" "wall: 5m" "pids: 64" -- python3 runaway.py memhog --cap-mib 96 --hold 1
	show_out g1 6
	ledger --kind run_end
	[ "$quiet" = 1 ] || "$bin" status "$run" 2>&1 | grep '^resources' | sed 's/^/   /'
	exit_is 137 "oom"
	verdict memory ceiling=40
}
s_g2() {
	section "g2. limits.pids: a fork stand-in starts children that only sleep, to its own cap of 60; the limit is 16 tasks"
	lib_workspace g2
	run_agent g2 full 3s task "pids: 16" "memory: 256MiB" "wall: 5m" -- python3 runaway.py forkbomb --cap 60 --hold 3
	show_out g2 4
	ledger --kind run_end
	[ "$quiet" = 1 ] || "$bin" status "$run" 2>&1 | grep '^resources' | sed 's/^/   /'
	exit_is 137 "pids"
	verdict pids ceiling=16
}
s_g3() {
	section "g3. limits.cpu: a busy loop for 6 s of wall time under cpu: 0.25 (a quarter of one core)"
	lib_workspace g3
	run_agent g3 full 3s task "cpu: 0.25" "memory: 256MiB" "pids: 64" "wall: 5m" -- python3 runaway.py cpu --seconds 6
	show_out g3 3
	[ "$quiet" = 1 ] || "$bin" status "$run" 2>&1 | grep '^resources' | sed 's/^/   /'
	exit_is 0 "the loop's own end: throttled, not killed"
	verdict cpu ceiling=0.25 seconds=6
}
s_g() { s_g1; s_g2; s_g3; }

# --- i: onboarding -------------------------------------------------------------------------------------------------------
s_i() {
	section "i. onboarding, the checklist of README.md on the custom agent: record-only run, tego learn, the contract's own test, a run"
	lib_workspace i
	python3 "$here/model_script.py" task >"$root/script-i.json"
	lib_stub "$root/script-i.json"
	local before cmd=(python3 agent.py --sleep 0.15 --bad-every 4 --bad "cred,push,connect,outside" --bad-port "$listener_port"
		--outside "$outside" --max-seconds 8 --report-every 8)
	say "-- 1. tego watch -- python3 agent.py ...   (no boundary: it only records; the agent reaches the stand-in model directly)"
	before=$(runs_now)
	(cd "$ws" && ANTHROPIC_BASE_URL="https://127.0.0.1:$stub_port" PATH="$ws/bin:$PATH" "$bin" watch -- "${cmd[@]}") \
		>"$root/out-i1.txt" 2>"$root/err-i1.txt" </dev/null
	rc=$?
	run_since "$before"
	local observed=$run proposal=$root/contract/proposal-i.yaml
	show_out i1 3
	say "   every forbidden action went through, and is in the record: $("$bin" status "$run" | sed -n 2p | awk '{print $6, "events"}')"
	say "-- 2. tego learn $run --out proposal.yaml   (the lines that matter; read every entry of the real file)"
	"$bin" learn "$run" --out "$proposal" >"$root/learn-i.txt" 2>&1
	[ "$quiet" = 1 ] || { sed -n '/^fs:/,/^# limits/p' "$proposal" | grep -vE '^\s*#( tego records| are addresses| place of| Reads)|^$' | sed "s#$root#\$ROOT#g" | cut -c1-150 | sed 's/^/   /'; }
	sed "s#@PORT@#$listener_port#; s#@NAME@#i#" "$here/verdicts.yaml" >"$root/contract/verdicts-i.yaml"
	say "-- 3. tego compile proposal.yaml   (what it says about the proposal; the fixes it names are made, and nothing else is)"
	[ "$quiet" = 1 ] || (cd "$ws" && "$bin" compile "$proposal" --offline 2>&1 | grep -E '^(error|warning)' | sed "s#$root#\$ROOT#g" | cut -c1-210 | sed 's/^/   /')
	# the fixes it names: delete each exec.allow entry it says does not exist (a PATH-search miss learn took for a program
	# that ran; it varies from run to run), and allow the interpreter of the stand-in git script
	(cd "$ws" && "$bin" compile "$proposal" --offline 2>&1) | sed -n 's/^error: [^ ]* exec.allow "\([^"]*\)": .*\[path-missing\].*/\1/p' |
		while read -r missing; do sed -i "\#\"$missing\"#d" "$proposal"; done
	sed -i '/^exec:/,/^net:/ s#^  allow:$#&\n    - "/bin/sh"#' "$proposal"
	say "-- 3b. tego compile proposal.yaml --test verdicts.yaml   (the contract's own test; nothing runs)"
	[ "$quiet" = 1 ] || (cd "$ws" && "$bin" compile "$proposal" --offline --test "$root/contract/verdicts-i.yaml" 2>&1 | grep -E '^(FAIL|[0-9]+ rows)' | sed "s#$root#\$ROOT#g" | cut -c1-190 | sed 's/^/   /')
	say "-- 4. tego watch --boundary proposal.yaml --record full -- python3 agent.py ...   (the proposal as written; full so reads are seen)"
	before=$(runs_now)
	(cd "$ws" && ANTHROPIC_BASE_URL="https://127.0.0.1:$stub_port" PATH="$ws/bin:$PATH" "$bin" watch --boundary "$proposal" --record full -- "${cmd[@]}") \
		>"$root/out-i2.txt" 2>"$root/err-i2.txt" </dev/null
	rc=$?
	run_since "$before"
	show_out i2 3
	verdict onboard "observe=$observed" "proposal=$proposal" "port=$listener_port"
	say "-- 5. the trimmed contract (contract.yaml, as scenario a ran it) against the same test:"
	lib_contract "$root/contract/i.yaml" full 3s "wall: 5m"
	[ "$quiet" = 1 ] || (cd "$ws" && "$bin" compile "$root/contract/i.yaml" --offline --test "$root/contract/verdicts-i.yaml" 2>&1 | grep -E '^(FAIL|[0-9]+ rows)' | sed 's/^/   /')
	(cd "$ws" && "$bin" compile "$root/contract/i.yaml" --offline --test "$root/contract/verdicts-i.yaml" >/dev/null 2>&1)
	check "$?" "the trimmed contract passes its own test table (8 rows)"
}

# --- j, k, l: what can go wrong at night, for tego itself --------------------------------------------------------------------
s_j() {
	section "j. the ledger cannot grow (a file size limit of 2 MiB on tego stands for a full disk): the run is stopped, not left unrecorded"
	lib_workspace j
	python3 "$here/model_script.py" task >"$root/script-j.json"
	lib_stub "$root/script-j.json"
	lib_contract "$root/contract/j.yaml" full 3s "wall: 5m" "pids: 64" "memory: 512MiB"
	local before
	before=$(runs_now)
	(
		ulimit -f 2048
		cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch --boundary "$root/contract/j.yaml" -- python3 agent.py --sleep 0.05 --max-seconds 40 \
			--report-every 4
	) >"$root/out-j.txt" 2>"$root/err-j.txt" </dev/null
	rc=$?
	run_since "$before"
	show_out j 6
	say "-- tego's own words, and the ledger as it stands:"
	[ "$quiet" = 1 ] || { grep -E '^tego run: ' "$root/err-j.txt" | sed "s#$root#\$ROOT#g" | cut -c1-230 | sed 's/^/   /'; "$bin" status "$run" 2>&1 | sed -n 1,2p | sed 's/^/   /'; find "$state/runs/$run" -name events.jsonl -printf '   events.jsonl: %s bytes (the limit is 2097152)\n'; }
	exit_is 125 "the run's record is incomplete"
	"$bin" events "$run" --verify >"$root/verify.txt" 2>&1
	say "-- tego events --verify: $(sed 's#, head.*##; s#^[^:]*: ##' "$root/verify.txt")"
	left=0
	for p in /proc/[0-9]*; do [ "$(readlink "$p/cwd" 2>/dev/null)" = "$ws" ] && left=$((left + 1)); done
	verdict ledger-full "out=$root/out-j.txt" "stderr=$root/err-j.txt" "verify=$root/verify.txt" "left=$left" limit=2097152
}

s_k() {
	section "k. the model endpoint goes away in the middle of the run and does not come back (a provider's outage)"
	lib_workspace k
	python3 "$here/model_script.py" task >"$root/script-k.json"
	lib_stub "$root/script-k.json"
	lib_contract "$root/contract/k.yaml" full 3s "wall: 5m" "stall_after: 8s" "pids: 64" "memory: 512MiB"
	local down=$stub_pid before
	before=$(runs_now)
	(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch --boundary "$root/contract/k.yaml" -- python3 agent.py --sleep 0.1 --max-seconds 30 --report-every 5) \
		>"$root/out-k.txt" 2>"$root/err-k.txt" </dev/null &
	local w=$!
	sleep 6
	kill "$down"
	wait "$down" 2>/dev/null
	wait "$w"
	rc=$?
	run_since "$before"
	show_out k 6
	say "-- the ledger: each failed call is a gap, the agent's retries keep the run alive (stall_after is 8 s), nothing else changes:"
	ledger --kind gap --limit 5
	exit_is 0 "the agent's own end"
	verdict model-down
}

s_l() {
	section "l. the launcher itself is killed (kill -9) mid-run: the agent must not outlive it, and the ledger must still be readable"
	lib_workspace l
	python3 "$here/model_script.py" task >"$root/script-l.json"
	lib_stub "$root/script-l.json"
	lib_contract "$root/contract/l.yaml" full 3s "wall: 5m" "pids: 64" "memory: 512MiB"
	local before
	before=$(runs_now)
	(cd "$ws" && PATH="$ws/bin:$PATH" exec "$bin" watch --boundary "$root/contract/l.yaml" -- python3 agent.py --sleep 0.1 --max-seconds 30 --report-every 5) \
		>"$root/out-l.txt" 2>"$root/err-l.txt" </dev/null &
	local w=$!
	sleep 5
	kill -9 "$w"
	wait "$w" 2>/dev/null
	sleep 2
	run_since "$before"
	local left=0 p
	for p in /proc/[0-9]*; do [ "$(readlink "$p/cwd" 2>/dev/null)" = "$ws" ] && left=$((left + 1)); done
	check "$([ "$left" = 0 ] && echo 0 || echo 1)" "no process of the run is left ($left): the agent died with its launcher (PR_SET_PDEATHSIG)"
	say "-- tego status right after the kill, and after the next tego gc (which any later run or stop also does):"
	[ "$quiet" = 1 ] || "$bin" status "$run" 2>&1 | sed -n 1,2p | sed 's/^/   /'
	[ "$quiet" = 1 ] || "$bin" gc 2>&1 | sed 's/^/   /'
	[ "$quiet" = 1 ] || "$bin" status "$run" 2>&1 | sed -n 1,2p | sed 's/^/   /'
	rc=125
	verdict orphaned
	verify_ledger
}

# --- m: what recording costs --------------------------------------------------------------------------------------------------
s_m() {
	local flood_n=${FLOOD_COUNT:-20000} # FLOOD_COUNT=200000 is the most runaway.py flood does
	section "m. what recording costs the agent: one file opened and read $flood_n times, unconfined, then under record: summary, then full"
	lib_workspace m
	# Three runs of each, the least of the three taken: a microbenchmark on a shared machine is its fastest run, and what
	# else the box was doing shows in the others.
	local i out us0=999999 us1=999999 us2=999999 us summary
	for _ in 1 2 3; do
		out=$(cd "$ws" && python3 runaway.py flood --count "$flood_n")
		us=${out##*= } us0=$(awk -v a="$us0" -v b="${us% us*}" 'BEGIN{print (b < a) ? b : a}')
		run_agent m1 summary 3s task "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py flood --count "$flood_n"
		summary=$run
		out=$(grep -h '^runaway:' "$root/out-m1.txt")
		us=${out##*= } us1=$(awk -v a="$us1" -v b="${us% us*}" 'BEGIN{print (b < a) ? b : a}')
		run_agent m2 full 3s task "wall: 5m" "pids: 64" "memory: 512MiB" -- python3 runaway.py flood --count "$flood_n"
		out=$(grep -h '^runaway:' "$root/out-m2.txt")
		us=${out##*= } us2=$(awk -v a="$us2" -v b="${us% us*}" 'BEGIN{print (b < a) ? b : a}')
	done
	say "-- least of three, per open: unconfined ${us0} us, tego record: summary ${us1} us, tego record: full ${us2} us"
	say "-- what a recorded open costs on top of an unrecorded one: $(awk -v a="$us0" -v b="$us1" 'BEGIN{printf "%.1f", b - a}') us under summary (reads are not notified), $(awk -v a="$us0" -v b="$us2" 'BEGIN{printf "%.1f", b - a}') us under full"
	verdict flood "opens=$flood_n" mode=full
	run=$summary
	verdict flood "opens=$flood_n" mode=summary
}

# --- negative controls ----------------------------------------------------------------------------------------------------
# neg <scenario function> <mutation> <check id> <what was removed>: run the scenario with one rule or limit removed; the
# check for it must FAIL
neg() {
	local fn=$1 m=$2 id=$3 label=$4 saved=$fail
	case " ${NEG_ONLY:-$m} " in *" $m "*) ;; *) return 0 ;; esac # NEG_ONLY="<mutation> ..." runs only those controls
	: >"$root/verdict.txt"
	mut=$m quiet=1 "$fn" >/dev/null 2>&1
	fail=$saved # the mutated run's own failing checks are the point, not a failure of this script
	if grep -q "^FAIL  norun " "$root/verdict.txt"; then
		echo "FAIL  without $label the mutated run never started, so $id tested nothing: $(grep -m1 "^FAIL  norun " "$root/verdict.txt" | sed 's/^FAIL  norun *//')"
		fail=1
	elif grep -q "^FAIL  $id " "$root/verdict.txt"; then
		echo "PASS  without $label the check $id fails: $(grep "^FAIL  $id " "$root/verdict.txt" | cut -c1-160 | sed 's/^FAIL  [^ ]* *//')"
	else
		echo "FAIL  without $label the check $id still passes"
		fail=1
	fi
}
negative() {
	section "negative controls: the same scenarios with one rule or limit removed; each named check must FAIL"
	neg s_a no-deny-read a.cred "fs.deny_read for the credential"
	neg s_a git-allowed a.push "the refusal of git (exec.allow lists it)"
	neg s_a connect-allowed a.connect "the refusal of the port (net.allow lists it)"
	neg s_a outside-writable a.outside "the refusal of the outside write (fs.write lists it)"
	neg s_b ask-writable b.timeout "fs.ask for held/ (it is plainly writable)"
	neg s_c ask-writable c.human "fs.ask for held/ (nothing is held, so nobody is asked)"
	neg s_c no-always c.standing "the person's --always (every repeat is held and answered again)"
	neg s_d no-wall d.end "limits.wall"
	neg s_e1 no-repeats e1.end "limits.repeats"
	neg s_e2 no-stall_after e2.end "limits.stall_after"
	neg s_f1 no-tokens f1.end "limits.tokens"
	neg s_f2 no-cost_usd f2.end "limits.cost_usd"
	neg s_f4 no-forwarder f4.refused "the forwarder (models: and capture:), so that net.allow's entry for the model's address grants it"
	neg s_g1 no-memory g1.oom "limits.memory"
	neg s_g2 no-pids g2.pids "limits.pids"
	neg s_g3 no-cpu g3.cpu "limits.cpu"
	echo "(a mutated run shows no output of its own; the verdicts above are what counts)"
}

case $what in
all) s_i; s_a; s_h; s_b; s_c; s_d; s_e; s_f; s_g; s_j; s_k; s_l; s_m ;;
a) s_a; s_h ;;
b | c | d | e | f | g | i | j | k | l | m) "s_$what" ;;
negative) negative ;;
*) echo "usage: run.sh [all|a|b|c|d|e|f|g|i|j|k|l|m|negative]" >&2; exit 2 ;;
esac

tego_home_listing >"$root/tego-home-after.txt"
cmp -s "$root/tego-home-before.txt" "$root/tego-home-after.txt"
check "$?" "the real ~/.tego is unchanged (listing before and after, chain.log apart)"
new_anchors=$(tail -n +$((chain_before + 1)) "$real_chain" 2>/dev/null | awk '{print $1}')
ours=0
while read -r r_id; do
	grep -qx "$r_id" <<<"$new_anchors" && ours=$((ours + 1))
done < <(find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%f\n')
check "$([ "$ours" = 0 ] && echo 0 || echo 1)" "none of this script's runs was anchored in the real ~/.tego/chain.log ($ours of $(grep -c . <<<"$new_anchors") lines added meanwhile are ours)"
echo "directory: $root"
[ "$fail" = 0 ] # the script ends here, with the checks' verdict as its status
