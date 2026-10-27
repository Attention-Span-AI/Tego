#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ADR 0077's measurement: what notifying every read open for the reason channel (reason.reads: on) costs, against the
# same run with reason.reads: off, at tier landlock under record: summary, no root.
#
#   test/bench/read-notify/run.sh opens     # per-open cost: REPEATS runs of each, alternated, the opener pinned
#   test/bench/read-notify/run.sh claude    # wall time of the offline Claude Code workload (model stand-in)
#   test/bench/read-notify/run.sh           # both
#
# opens: each run is `tego run` of the opener, test/workloads/read-opener (N opens of one file from one thread pinned
# to CPU), with tego and its supervisor confined to CPUS (taskset); the opener prints the median and p99 of its own
# opens. The figures are the medians over REPEATS runs. claude: the interactive-claude POC's contract
# (test/poc/interactive-claude) under record: summary, run as `claude -p` with the stand-in answering: one Bash tool
# call that reads FILES small files with the shell's own read builtin, then a closing text; the figure is the median
# wall time of CLAUDE_REPEATS runs of each, with the median count of notifications the supervisor answered (run_end),
# the opens it was told of among them.
# Every run records the 1-minute load average first; a run that started at load LOAD_MAX or above is labelled LOADED,
# and the script ends with status 3 so it is rerun on a quiet box. A median over 25 µs an open, or a workload more
# than 5 % slower, prints TARGET-MISS with its number (ADR 0077's rule for the default).
#
# Everything is under ROOT (a new directory under TMPDIR by default): tego's machine config, ledger, chain anchor and
# own log (the tegotesthooks build redirects them), the workspace, the stand-in and its certificate.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
what=${1:-all}
REPEATS=${REPEATS:-20}
N=${N:-20000}
CPU=${CPU:-1}
CPUS=${CPUS:-0-3}
LOAD_MAX=${LOAD_MAX:-2}
CLAUDE_REPEATS=${CLAUDE_REPEATS:-10}
FILES=${FILES:-2000}
root=${ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/read-notify.XXXXXX")}
mkdir -p "$root" && chmod 755 "$root"
status=0

case "$what" in opens | claude | all) ;; *) echo "run.sh: opens, claude or all" >&2; exit 2 ;; esac

# --- tego and the opener, isolated -------------------------------------------------------------------------------
mkdir -p "$root/bin" && chmod 755 "$root/bin"
bin=$root/bin/tego
(cd "$repo" && CGO_ENABLED=0 go build -tags=tegotesthooks -o "$bin" ./cmd/tego) || exit 1
(cd "$repo" && CGO_ENABLED=0 go build -o "$root/bin/opener" ./test/workloads/read-opener) || exit 1
# Only the test build honours the anchor and own-log variables below (identity-config.md R27).
grep -aq TEGO_TEST_CHAIN_ANCHOR "$bin" || { echo "run.sh: $bin is not a tegotesthooks build" >&2; exit 2; }
state=$root/state
mkdir -p "$state/runs" "$state/ownlog" "$state/run" && chmod 755 "$state" && chmod 700 "$state/run"
printf 'version: 0\nledger_root: %s\nstop_grace: 3s\n' "$state/runs" >"$state/config.yaml"
chmod 600 "$state/config.yaml"
export TEGO_CONFIG=$state/config.yaml TEGO_TEST_CHAIN_ANCHOR=$state/chain.log TEGO_TEST_OWN_LOG_HOME=$state/ownlog
export XDG_RUNTIME_DIR=$state/run HISTFILE=/dev/null

# load1 prints the 1-minute load average, labelled LOADED at LOAD_MAX or above (the tables keep the label).
load1() {
	local l
	l=$(cut -d' ' -f1 /proc/loadavg)
	if awk -v l="$l" -v m="$LOAD_MAX" 'BEGIN { exit !(l >= m) }'; then
		echo "$l LOADED"
	else
		echo "$l"
	fi
}

# median reads numbers, one a line, and prints their median.
median() { sort -n | awk '{ v[NR] = $1 } END { if (NR == 0) print 0; else if (NR % 2) print v[(NR + 1) / 2]; else print (v[NR / 2] + v[NR / 2 + 1]) / 2 }'; }

# --- opens -------------------------------------------------------------------------------------------------------
opens() {
	local ws=$root/opens mode i order line l
	mkdir -p "$ws/out" "$ws/secret" "$ws/contract" && chmod 755 "$ws" "$ws/out" "$ws/contract"
	echo benign >"$ws/data.txt"
	echo key >"$ws/secret/key"
	for mode in on off; do
		cat >"$ws/contract/$mode.yaml" <<YAML
version: 0
name: read-notify-$mode
command: ["$root/bin/opener"]
tier: landlock
record: summary
fs:
  write: ["./out/"]
  deny_read: ["./secret/"]
exec:
  allow: ["$root/bin/opener"]
reason:
  reads: $mode
YAML
	done
	: >"$root/opens.tsv"
	for i in $(seq 1 "$REPEATS"); do
		order="on off"
		[ $((i % 2)) = 0 ] && order="off on"
		for mode in $order; do
			l=$(load1)
			line=$(cd "$ws" && taskset -c "$CPUS" "$bin" run "$ws/contract/$mode.yaml" -- "$root/bin/opener" -n "$N" -cpu "$CPU" -path data.txt 2>"$root/opens-$mode-$i.err" | grep '^RESULT')
			[ -n "$line" ] || { echo "run.sh: run $i ($mode) printed no RESULT:" >&2; tail -5 "$root/opens-$mode-$i.err" >&2; exit 1; }
			# RESULT median_ns M p99_ns P fails F
			printf '%s\t%s\t%s\t%s\t%s\n' "$mode" "$(echo "$line" | cut -d' ' -f3)" "$(echo "$line" | cut -d' ' -f5)" "$(echo "$line" | cut -d' ' -f7)" "$l" >>"$root/opens.tsv"
		done
	done
	local on_med on_p99 off_med off_p99 fails delta
	on_med=$(awk -F'\t' '$1 == "on" { print $2 }' "$root/opens.tsv" | median)
	on_p99=$(awk -F'\t' '$1 == "on" { print $3 }' "$root/opens.tsv" | median)
	off_med=$(awk -F'\t' '$1 == "off" { print $2 }' "$root/opens.tsv" | median)
	off_p99=$(awk -F'\t' '$1 == "off" { print $3 }' "$root/opens.tsv" | median)
	fails=$(awk -F'\t' '{ s += $4 } END { print s + 0 }' "$root/opens.tsv")
	delta=$(awk -v a="$on_med" -v b="$off_med" 'BEGIN { printf "%.0f", a - b }')
	echo "RESULT opens repeats=$REPEATS n=$N cpu=$CPU cpus=$CPUS on_median_ns=$on_med on_p99_ns=$on_p99 off_median_ns=$off_med off_p99_ns=$off_p99 delta_median_ns=$delta fails=$fails"
	echo "loads: $(cut -f5 "$root/opens.tsv" | tr '\n' ' ')"
	[ "$fails" = 0 ] || { echo "run.sh: $fails opens failed" >&2; status=1; }
	if [ "$delta" -gt 25000 ]; then
		echo "TARGET-MISS read-notify opens: +$delta ns an open with reason reads (ADR 0077's rule: at most 25000)"
	fi
}

# --- claude --------------------------------------------------------------------------------------------------------
claude_workload() {
	local claude=${CLAUDE:-$(command -v claude)} poc=$repo/test/poc/interactive-claude ws home port entries p mode i order l t0 t1
	[ -n "$claude" ] && [ -x "$claude" ] || { echo "run.sh: no claude on PATH (CLAUDE=<path>)" >&2; exit 2; }
	for t in python3 openssl; do command -v "$t" >/dev/null || { echo "run.sh: needs $t" >&2; exit 2; }; done
	mkdir -p "$root/stub" && chmod 755 "$root/stub"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
		-keyout "$root/stub/key.pem" -out "$root/stub/cert.pem" -subj /CN=127.0.0.1 \
		-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" -addext "keyUsage=critical,digitalSignature,keyCertSign" \
		-addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || { echo "run.sh: openssl could not make a certificate" >&2; exit 2; }
	chmod 644 "$root/stub/cert.pem"
	# The account's own home, as the passwd database names it: the POC denies its agent configuration to the run, and
	# these scripts never read it.
	local real_home
	real_home=$(getent passwd "$(id -u)" | cut -d: -f6)
	# The stand-in's two turns; $f and $n are the Bash tool's, expanded by the agent's shell.
	# shellcheck disable=SC2016
	printf '[[{"type": "tool_use", "name": "Bash", "input": {"command": "n=0; for f in data/*; do read -r l < \\"$f\\" && n=$((n+1)); done; echo read $n", "description": "Read the data files"}}], [{"type": "text", "text": "READ-DONE"}]]\n' >"$root/stub/script.json"
	: >"$root/claude.tsv"
	for i in $(seq 1 "$CLAUDE_REPEATS"); do
		order="on off"
		[ $((i % 2)) = 0 ] && order="off on"
		for mode in $order; do
			ws=$root/ws home=$root/home
			rm -rf "$ws" "$home" "$root/contract" "$root/xdg" "$state/runs"
			mkdir -p "$ws/work" "$ws/data" "$ws/.claude-state/tmp" "$home" "$root/contract" "$state/runs" "$root/xdg"
			chmod 755 "$ws" "$home" "$root/contract" && chmod 700 "$root/xdg"
			for p in $(seq 1 "$FILES"); do echo "line $p" >"$ws/data/f$p"; done
			echo '{"hasCompletedOnboarding": true, "theme": "dark"}' >"$ws/.claude-state/.claude.json"
			rm -f "$root/stub/stub.port"
			python3 "$repo/test/workloads/model-stub/server.py" --cert "$root/stub/cert.pem" --key "$root/stub/key.pem" \
				--ready "$root/stub/stub.port" --log "$root/stub/requests.log" --script "$root/stub/script.json" 2>"$root/stub/stub.err" &
			local stub=$!
			for _ in $(seq 1 100); do [ -s "$root/stub/stub.port" ] && break; sleep 0.1; done
			port=$(cat "$root/stub/stub.port")
			entries=""
			for p in .claude .claude.json .codex .config/anthropic .tego; do
				[ -e "$real_home/$p" ] && entries="$entries\"$real_home/$p\", "
			done
			# The POC's contract, under record: summary, with no held directory (-p answers no approval), and the
			# reason.reads value this run measures.
			sed "s#@STUB_PORT@#$port#; s#@ROOT@#$root#g; s#^@DENY_READ@\$#  deny_read: [${entries%, }]#; s#^record: full\$#record: summary#; /^  ask: \\[\"\\.\\/held\\/\"\\]\$/d" \
				"$poc/claude-interactive-offline.yaml" >"$root/contract/agent.yaml"
			printf 'reason:\n  reads: %s\n' "$mode" >>"$root/contract/agent.yaml"
			chmod 644 "$root/contract/agent.yaml"
			l=$(load1)
			t0=$(date +%s%N)
			(cd "$ws" && SSL_CERT_FILE=$root/stub/cert.pem HOME=$home ANTHROPIC_API_KEY=sk-ant-api03-NOT-A-REAL-KEY-0000000000000000000000000000 \
				taskset -c "$CPUS" "$bin" run "$root/contract/agent.yaml" -- "$claude" -p "Read the data files." --allowedTools Bash \
				>"$root/claude-$mode-$i.out" 2>"$root/claude-$mode-$i.err" </dev/null)
			local rc=$?
			t1=$(date +%s%N)
			kill "$stub" 2>/dev/null
			wait "$stub" 2>/dev/null
			grep -q "READ-DONE" "$root/claude-$mode-$i.out" || {
				echo "run.sh: claude run $i ($mode) did not finish its script (rc $rc):" >&2
				tail -5 "$root/claude-$mode-$i.out" "$root/claude-$mode-$i.err" >&2
				exit 1
			}
			# The notifications the run's supervisor answered (run_end), which is how many opens it was told of.
			local notes
			notes=$(grep -ho '"notifications":[0-9]*' "$state"/runs/r-*/events.jsonl | tail -1 | cut -d: -f2)
			printf '%s\t%s\t%s\t%s\n' "$mode" "$(((t1 - t0) / 1000000))" "$l" "${notes:-0}" >>"$root/claude.tsv"
		done
	done
	local on off pct
	on=$(awk -F'\t' '$1 == "on" { print $2 }' "$root/claude.tsv" | median)
	off=$(awk -F'\t' '$1 == "off" { print $2 }' "$root/claude.tsv" | median)
	pct=$(awk -v a="$on" -v b="$off" 'BEGIN { printf "%.1f", 100 * (a - b) / b }')
	local on_notes off_notes
	on_notes=$(awk -F'\t' '$1 == "on" { print $4 }' "$root/claude.tsv" | median)
	off_notes=$(awk -F'\t' '$1 == "off" { print $4 }' "$root/claude.tsv" | median)
	echo "RESULT claude repeats=$CLAUDE_REPEATS files=$FILES on_median_ms=$on off_median_ms=$off change_pct=$pct on_notifications=$on_notes off_notifications=$off_notes"
	echo "walls: $(cut -f1,2 "$root/claude.tsv" | tr '\t\n' ': ')"
	echo "loads: $(cut -f3 "$root/claude.tsv" | tr '\n' ' ')"
	if awk -v p="$pct" 'BEGIN { exit !(p > 5) }'; then
		echo "TARGET-MISS read-notify claude: +$pct % wall time with reason reads (ADR 0077's rule: at most 5 %)"
	fi
}

[ "$what" = claude ] || opens
[ "$what" = opens ] || claude_workload
echo "directory: $root"
if cat "$root"/opens.tsv "$root"/claude.tsv 2>/dev/null | grep -q LOADED; then
	echo "LOADED: a run started at load $LOAD_MAX or above; rerun on a quiet box"
	exit 3
fi
exit "$status"
