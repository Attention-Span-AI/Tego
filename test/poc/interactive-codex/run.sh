#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — the offline interactive Codex session under an enforcing tego contract (README.md). It builds an isolated
# tego, starts the local model stand-in, lays out a workspace, and runs
#   U   the stand-in's own self-test,
#   P0  the login screen's other ways in (a ChatGPT account),
#   P1  Codex as it ships (default settings, its background server) under the contract: what its start does,
#   P2  the same with --no-daemon, and P2b with the machine's resolver reachable, so that the names Codex looks up show
#       as the connections that are refused,
#   P3  Codex's own sandbox left on, and then turned off by a flag: what a command does,
#   P4  what `net.dns.mode: off` does at tier landlock, for a program of its own and for Codex,
#   S   the whole session, driven on a pty (drive.py), and a control with an invented ledger,
#   L   the same session with no boundary, recorded, `tego learn` over it, and what its `/proc/self/exe` entry grants,
#   C   the two contracts for a real key (codex-real-*.yaml): they compile, and their rule tables refuse what they must,
# and then reads the ledger back and checks it: no connection to any address but the forwarder's loopback listener was
# allowed, every model request the stand-in answered is an ssl_request source=forwarder, and what each step did.
#
# Everything lives under $ROOT; the real ~/.tego, ~/.codex, ~/.claude, ~/.claude.json and ~/.config/anthropic are
# neither read nor written (the contract denies the agent the files of them that exist, `tego watch` is built with the
# tegotesthooks tag so its chain anchor and log live in $ROOT, and ~/.tego is listed before and after). Codex's own
# installation is under ~/.codex/packages: it is run, and read for that, and nothing else of ~/.codex is touched.
#
# Usage: run.sh [unit|startup|session|learn|contracts|all|negative]     default all (about 6 minutes)
#        negative: four runs of the session with one rule of the contract removed each (MUTATE=ask-to-write, git-allowed,
#        secret-readable, net-allowed); each must FAIL the check that rule is there for, and a PASS here says it did. A
#        check that cannot fail proves nothing.
#        ROUTE=a|b    how Codex is pointed at the forwarder in the session and the negative controls. a (default): tego
#                     writes the run's CODEX_HOME with `openai_base_url` (capture-derive.md R19b), and Codex's login screen
#                     takes the dummy key. b: a custom provider in config.toml whose base_url is the forwarder's port,
#                     pinned in the machine config (`forwarder.listen`), and the key read from the environment (`env_key`):
#                     no login screen, and no WebSocket offers.
#        ROOT=<dir>   keep everything there (default: a temporary directory, removed at the end unless KEEP=1)
#        TEGO_BIN=<tego built with -tags tegotesthooks> skips the build;  CODEX=<path to codex>
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
what=${1:-all}
root=${ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/tego-interactive-codex-XXXXXX")}
mkdir -p "$root" && chmod 755 "$root"
root=$(cd "$root" && pwd)
codex=${CODEX:-$(command -v codex || true)}
stub=$repo/test/workloads/model-stub/openai_responses.py
stub_pid=
cur=run
route=${ROUTE:-a}
[ "$route" = a ] || [ "$route" = b ] || { echo "run.sh: ROUTE is a or b" >&2; exit 2; }
layout_route=a
cleanup() {
	[ -z "$stub_pid" ] || kill "$stub_pid" 2>/dev/null
	[ "${KEEP:-0}" = 1 ] || [ -n "${ROOT:-}" ] || rm -rf "$root"
}
trap cleanup EXIT
section() { printf '\n==== %s\n' "$1"; }
fail=0
check() { # check <ok 0|1> <what>
	if [ "$1" = 0 ]; then echo "PASS  $2"; else echo "FAIL  $2"; fail=1; fi
}

for t in python3 openssl jq; do command -v "$t" >/dev/null || { echo "run.sh: needs $t" >&2; exit 2; }; done
if [ "$what" = unit ]; then
	# the stand-in's self-test needs no Codex (CI has none)
	section "U. the stand-in's self-test (test/workloads/model-stub/openai_responses.py --selftest)"
	python3 "$stub" --selftest
	exit $?
fi
[ -n "$codex" ] && [ -x "$codex" ] || { echo "run.sh: no codex on PATH (CODEX=<path>)" >&2; exit 2; }
codex_version=$("$codex" --version 2>/dev/null | head -1)
echo "codex: $codex ($codex_version)"
[ "$codex_version" = "codex-cli 0.159.2" ] || echo "note: measured against codex-cli 0.159.2; other versions may differ in the switches this uses"

# --- tego --------------------------------------------------------------------------------------------------------
bin=${TEGO_BIN:-$root/bin/tego}
if [ -z "${TEGO_BIN:-}" ]; then
	mkdir -p "$root/bin" && chmod 755 "$root/bin"
	(cd "$repo" && CGO_ENABLED=0 go build -tags=tegotesthooks -o "$bin" ./cmd/tego) || exit 1
fi
# A binary handed in as TEGO_BIN must be the test build: a product build ignores the anchor and own-log variables set
# below and would anchor this session's runs in the invoking user's own ~/.tego/chain.log (identity-config.md R27;
# tools/isocheck SH-6). Only the test build contains the variable's name.
grep -aq TEGO_TEST_CHAIN_ANCHOR "$bin" 2>/dev/null || {
	echo "run.sh: $bin is not built with -tags tegotesthooks; it would write the real ~/.tego/chain.log" >&2
	exit 2
}
[ "$bin" = "$root/bin/tego" ] || { mkdir -p "$root/bin" && chmod 755 "$root/bin" && cp "$bin" "$root/bin/tego"; }

# tego's own files (machine config, ledger, chain anchor, log), the contract, the stand-in's files, Codex's configuration
# and the agent's workspace are separate directories: tego refuses a contract that lets the agent write its own state or
# the contract file's directory.
state=$root/state
mkdir -p "$state/runs" "$state/ownlog" && chmod 755 "$state"
write_machine_config() { # write_machine_config [forwarder port to pin]
	{
		printf 'version: 0\nledger_root: %s/runs\nstop_grace: 3s\n' "$state"
		[ -z "${1:-}" ] || printf 'forwarder:\n  listen: 127.0.0.1:%s\n' "$1"
	} >"$state/config.yaml"
	chmod 600 "$state/config.yaml"
}
write_machine_config
cat >"$state/env.sh" <<ENVS
# source this in a second terminal to use tego ask / approve / deny / events against this run
export TEGO_CONFIG=$state/config.yaml
export TEGO_TEST_CHAIN_ANCHOR=$state/chain.log
export TEGO_TEST_OWN_LOG_HOME=$state/ownlog
export XDG_RUNTIME_DIR=$root/xdg-tego
ENVS
# The runs' runtime directory, here for the commands run by hand too (layout() empties it before each part): a launch
# makes <XDG_RUNTIME_DIR>/tego and sweeps the directories the invoking user's crashed runs left there
# (identity-config.md R27 clause b4), so it is never theirs.
mkdir -p "$root/xdg-tego" && chmod 700 "$root/xdg-tego"
# shellcheck disable=SC1091 # written just above
. "$state/env.sh"

# the account's own home, as the passwd database names it
real_home=$(getent passwd "$(id -u)" | cut -d: -f6)
tego_home_listing() { [ -d "$real_home/.tego" ] && find "$real_home/.tego" -printf '%p %s %T@\n' 2>/dev/null | sort; }
tego_home_listing >"$root/tego-home-before.txt"

# --- the model stand-in -------------------------------------------------------------------------------------------
mkdir -p "$root/stub" && chmod 755 "$root/stub"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	-keyout "$root/stub/key.pem" -out "$root/stub/cert.pem" -subj /CN=127.0.0.1 \
	-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" -addext "keyUsage=critical,digitalSignature,keyCertSign" \
	-addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || { echo "run.sh: openssl could not make a certificate" >&2; exit 2; }
chmod 644 "$root/stub/cert.pem"

# Codex's model catalog for this run: its bundled `gpt-5.5` entry under a name of its own (see codex-config.toml). Made by
# `codex debug models`, which renders the bundled catalog and does nothing else (no connection: measured).
make_catalog() {
	mkdir -p "$root/scratch-home" "$root/scratch-codex"
	env -i PATH="$PATH" HOME="$root/scratch-home" CODEX_HOME="$root/scratch-codex" "$codex" debug models 2>/dev/null |
		python3 -c '
import json, sys
m = dict(next(x for x in json.load(sys.stdin)["models"] if x["slug"] == "gpt-5.5"))
m.update(slug="gpt-stub", display_name="Stand-in", description="the offline stand-in model", upgrade=None, availability_nux=None, visibility="list", priority=1)
json.dump({"models": [m]}, sys.stdout)' >"$root/models.json" || { echo "run.sh: could not make the model catalog" >&2; exit 2; }
}
make_catalog

# layout <variant> [tls|plain]: a fresh workspace, Codex configuration, stand-in and contract for one run.
#   variant session  the hardened configuration (codex-config.toml) and the contract
#   variant default  Codex's own defaults (only the model, and the folder trusted)
#   variant record   the hardened configuration, the stand-in on plain HTTP and Codex's state in the workspace: no contract
layout() {
	local variant=$1 mode=${2:-tls} port entries p secret
	ws=$root/ws home=$root/home
	if [ -n "${stub_pid:-}" ]; then kill "$stub_pid" 2>/dev/null; wait "$stub_pid" 2>/dev/null; stub_pid=; fi
	find "$ws" "$home" "$root/xdg-tego" "$root/tmp" "$root/codex-user" "$root/secrets" "$root/contract" "$root/stub/dump" "$state/runs" \
		-mindepth 1 -delete 2>/dev/null
	# $root/xdg-tego is the run's XDG_RUNTIME_DIR. The launcher makes tego/ under it, 0700: one made here under umask
	# 002 would be group-writable, and a run that routes Codex refuses such a runtime directory (agent-contract.md R10a).
	mkdir -p "$ws/work" "$ws/held" "$ws/bin" "$home" "$root/xdg-tego" "$root/tmp" "$root/codex-user" "$root/secrets" \
		"$root/contract" "$state/runs" "$root/stub/dump"
	chmod 755 "$ws" "$home" "$root/codex-user" "$root/secrets" "$root/contract"
	chmod 700 "$root/xdg-tego" "$root/tmp"
	cp "$here/git" "$ws/bin/git"
	secret=$root/secrets/api-token.txt
	echo "TOP-SECRET-DECOY-TOKEN-0123456789" >"$secret"
	chmod 644 "$secret"
	: >"$root/stub/requests.log"
	sed "s#@SECRET@#$secret#g" "$here/stub-script.json" >"$root/stub/script.json"
	rm -f "$root/stub/stub.port"
	local tlsargs=()
	[ "$mode" = tls ] && tlsargs=(--cert "$root/stub/cert.pem" --key "$root/stub/key.pem")
	python3 "$stub" "${tlsargs[@]}" --ready "$root/stub/stub.port" --log "$root/stub/requests.log" --dump "$root/stub/dump" \
		--script "$root/stub/script.json" 2>"$root/stub/stub.err" &
	stub_pid=$!
	for _ in $(seq 1 100); do [ -s "$root/stub/stub.port" ] && break; sleep 0.1; done
	port=$(cat "$root/stub/stub.port")
	layout_route=a
	write_machine_config
	pass_extra=
	route_top="# (route a) the built-in openai provider: tego writes openai_base_url into the run's own CODEX_HOME"
	route_table=
	if [ "$variant" = session ] && [ "$route" = b ]; then
		# a custom provider whose base_url is the forwarder's listener: its port has to be known now, so it is pinned in the
		# machine config; and its key is read from the environment, so Codex asks for no login
		layout_route=b
		fwd_port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
		write_machine_config "$fwd_port"
		pass_extra=', "STAND_IN_API_KEY"'
		route_top='# (route b) a custom provider, below; the key comes from the environment, so there is no login screen
model_provider = "stand-in"'
		route_table="# The forwarder's listener, whose port the machine config pins (forwarder.listen), is this provider's base_url;
# supports_websockets = false spares the WebSocket offers the built-in provider makes before each request.
[model_providers.stand-in]
name = \"Stand-in\"
base_url = \"http://127.0.0.1:$fwd_port/v1\"
wire_api = \"responses\"
env_key = \"STAND_IN_API_KEY\"
supports_websockets = false"
	fi
	case "$variant" in
	session | record)
		ROOT_=$root WS_=$ws TOP_=$route_top TABLE_=$route_table python3 -c '
import os, sys
s = open(sys.argv[1]).read()
for k, v in (("@ROOT@", os.environ["ROOT_"]), ("@WS@", os.environ["WS_"]), ("@ROUTE_TOP@", os.environ["TOP_"]), ("@ROUTE_TABLE@", os.environ["TABLE_"])):
    s = s.replace(k, v)
sys.stdout.write(s)' "$here/codex-config.toml" >"$root/codex-user/config.toml" ;;
	default)
		cat >"$root/codex-user/config.toml" <<TOML
# Codex's own defaults, except: the model (a name of the run's own catalog), the trusted folder, and what P6 adds
model = "gpt-stub"
model_catalog_json = "$root/codex-user/models.json"
${extra_config:-}
[projects."$ws"]
trust_level = "trusted"
TOML
		;;
	esac
	cp "$root/models.json" "$root/codex-user/models.json"
	if [ "$variant" = record ]; then
		# no forwarder: Codex talks to the plain stand-in itself, and keeps its state in the workspace, where `tego learn`
		# can see it (a write outside the workspace is listed, not allowed)
		mkdir -p "$ws/.codex-state"
		cp "$root/codex-user/config.toml" "$ws/.codex-state/config.toml"
		cp "$root/models.json" "$ws/.codex-state/models.json"
		sed -i "s#^model_catalog_json = .*#model_catalog_json = \"$ws/.codex-state/models.json\"#; 1i openai_base_url = \"http://127.0.0.1:$port/v1\"" \
			"$ws/.codex-state/config.toml"
		return
	fi
	entries="\"$secret\""
	# Codex keeps its login, history and sessions in ~/.codex, next to its own installation (~/.codex/packages), so the
	# directory as a whole cannot be denied: the files of it that exist are, by name (a stat, never a read or a listing).
	for p in .codex/auth.json .codex/config.toml .codex/history.jsonl .codex/sessions .codex/memories .codex/log .codex/skills \
		.codex/rules .codex/AGENTS.md .codex/installation_id .codex/state_5.sqlite .codex/logs_2.sqlite .codex/goals_1.sqlite \
		.codex/memories_1.sqlite .codex/queue_1.sqlite .codex/thread_history_1.sqlite .claude .claude.json .config/anthropic .tego; do
		[ -e "$real_home/$p" ] && entries="$entries, \"$real_home/$p\""
	done
	sed "s#@STUB_PORT@#$port#; s#@ROOT@#$root#g; s#@PASS_EXTRA@#$pass_extra#; s#^@DENY_READ@\$#  deny_read: [$entries]#" \
		"$here/codex-interactive-offline.yaml" >"$root/contract/agent.yaml"
	case "${MUTATE:-}" in
	ask-to-write) # held/ is plainly writable: nothing is held
		sed -i 's#^  ask: \["./held/"\]#  ask: []#; s#^    - "./work/"#    - "./work/"\n    - "./held/"#' "$root/contract/agent.yaml" ;;
	git-allowed) # git may run: the push is not refused
		sed -i 's#^  allow: \["bash", "cat"\]#  allow: ["bash", "cat", "git"]#' "$root/contract/agent.yaml" ;;
	secret-readable) # the decoy secret is not denied
		sed -i "s#^  deny_read: \[\"$secret\"#  deny_read: [#; s#^  deny_read: \[, #  deny_read: [#" "$root/contract/agent.yaml" ;;
	dns-system) # the machine's resolver is reachable again: the names resolve, and the connections are what is refused
		sed -i 's#^    mode: "off"#    mode: "system"#' "$root/contract/agent.yaml" ;;
	net-allowed) # the connection the model asks for is allowed
		sed -i 's#^  allow: \["unix:/var/run/nscd/socket"\]#  allow: ["unix:/var/run/nscd/socket", "tcp://127.0.0.1:9"]#' "$root/contract/agent.yaml" ;;
	"") ;;
	*) echo "run.sh: unknown MUTATE=$MUTATE" >&2; exit 2 ;;
	esac
	chmod 644 "$root/contract/agent.yaml"
}

newest_run() { find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%T@ %f\n' | sort -rn | head -1 | cut -d' ' -f2; }
run_driver() { (cd "$ws" && DRIVE_ROUTE=$layout_route python3 "$here/drive.py" "$root" "$@"); }
report() { keep_events "$(newest_run)"; python3 "$here/report.py" "$root" "$(newest_run)" "$real_home" "$@"; }
# keep_events <run>: the run's whole ledger, as it was when the report read it (the next layout empties the ledger root)
keep_events() { mkdir -p "$root/evidence/ledgers" && cp "$state/runs/$1/events.jsonl" "$root/evidence/ledgers/${DRIVE_LABEL:-$cur}-$1.jsonl"; }

# compile_contract: the contract as tego loads and compiles it, from the workspace as the run will
compile_contract() {
	echo "-- tego compile agent.yaml (the contract as loaded; first lines of the rule table):"
	(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" compile "$root/contract/agent.yaml" --offline 2>&1 | sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" | cut -c1-170 | head -34)
}

# run_exec: a non-interactive `tego watch` (drive.py has its own environment for the pty runs)
run_exec() { # run_exec <label> <codex args...>: one `codex exec` under the contract, no terminal
	local label=$1
	shift
	(cd "$ws" && env -i PATH="$ws/bin:$PATH" HOME="$home" LANG=C.UTF-8 TERM=xterm-256color HISTFILE=/dev/null \
		XDG_RUNTIME_DIR="$root/xdg-tego" SSL_CERT_FILE="$root/stub/cert.pem" \
		TEGO_CONFIG="$TEGO_CONFIG" TEGO_TEST_CHAIN_ANCHOR="$TEGO_TEST_CHAIN_ANCHOR" TEGO_TEST_OWN_LOG_HOME="$TEGO_TEST_OWN_LOG_HOME" \
		timeout 120 "$bin" watch --boundary "$root/contract/agent.yaml" --offline -- "$@" </dev/null >"$root/$label.out" 2>"$root/$label.err")
	echo "codex exited $?"
	sed -n '/^approval:/,/^sandbox:/p' "$root/$label.err" | sed 's/^/   /'
}

# switch_run <tui|exec> <label> <config lines>: Codex's defaults plus the given lines, the resolver reachable, and where its
# direct connections went (a TUI run sits 12 s at its prompt; an exec run answers one prompt)
switch_run() {
	local kind=$1 label=$2 extra=$3
	MUTATE=dns-system
	extra_config=$extra layout default
	MUTATE=
	if [ "$kind" = tui ]; then
		DRIVE_LABEL=$label DRIVE_ARGS="--no-daemon" DRIVE_WAIT=12 run_driver probe >/dev/null 2>&1 || true
	else
		run_exec "$label" codex exec --skip-git-repo-check "hi" >/dev/null
	fi
	printf '   %-6s %-26s ' "$kind" "$label:"
	cur=$label report groups
}

rm -rf "$root/evidence"

if [ "$what" = all ]; then
	section "U. the stand-in's self-test (test/workloads/model-stub/openai_responses.py --selftest)"
	python3 "$stub" --selftest
	check "$?" "the stand-in's self-test passes"
fi

if [ "$what" = startup ] || [ "$what" = all ]; then
	section "P0. the login screen's other two ways in (ChatGPT account), under the contract"
	layout default
	DRIVE_LABEL=p0 run_driver probe-login 2>&1 | grep -v '^\[' | grep -E '^(screen reached|-- option|tego watch exited)' || true
	cur=p0 report startup | grep -E 'auth.openai.com|name lookup|D-Bus'

	section "P1. Codex as it ships, under the contract: its own settings, its background server (no --no-daemon)"
	layout default
	DRIVE_LABEL=p1 DRIVE_ARGS="" DRIVE_NO_LOGIN=1 DRIVE_FIRST_TIMEOUT=30 DRIVE_WAIT=6 \
		run_driver probe 2>&1 | grep -v '^\[' || true
	cur=p1 report startup
	left=$(ps -eo args | awk -v p="$root/xdg-tego" 'index($0, p) && $1 != "awk" {n++} END {print n + 0}')
	check "$([ "$left" = 0 ] && echo 0 || echo 1)" "no process of the run survived it ($left left; the daemon it started was in the run's cgroup)"

	section "P2. the same with --no-daemon"
	layout default
	DRIVE_LABEL=p2 DRIVE_ARGS="--no-daemon" DRIVE_WAIT=15 DRIVE_PROMPT="hello" DRIVE_WAIT_AFTER=6 run_driver probe 2>&1 | grep -v '^\[' || true
	cur=p2 report startup

	section "P2b. the same with net.dns.mode: system: the names resolve, and the connections are what is refused"
	MUTATE=dns-system
	layout default
	MUTATE=
	DRIVE_LABEL=p2b DRIVE_ARGS="--no-daemon" DRIVE_WAIT=15 DRIVE_PROMPT="hello" DRIVE_WAIT_AFTER=6 run_driver probe 2>&1 | grep -v '^\[' || true
	cur=p2b report startup

	section "P2c. a stored login in a CODEX_HOME inside the project (the shape of codex-real-direct.yaml, offline): with and without --no-daemon"
	layout default plain
	mkdir -p "$ws/.codex-state"
	cat >"$ws/.codex-state/config.toml" <<TOML
openai_base_url = "http://127.0.0.1:$(cat "$root/stub/stub.port")/v1"
model = "gpt-stub"
model_catalog_json = "$ws/.codex-state/models.json"
sandbox_mode = "danger-full-access"
approval_policy = "never"
check_for_update_on_startup = false
[features]
plugins = false
shell_snapshot = false
daemon_auto_start = false
[projects."$ws"]
trust_level = "trusted"
TOML
	cp "$root/models.json" "$ws/.codex-state/models.json"
	printf '{\n  "auth_mode": "apikey",\n  "OPENAI_API_KEY": "sk-offline-DUMMY-not-a-real-key-0000000000000000"\n}\n' >"$ws/.codex-state/auth.json"
	chmod 600 "$ws/.codex-state/auth.json"
	cat >"$root/contract/agent.yaml" <<DIRECT
version: 0
name: codex-direct-offline
command: ["codex"]
capture: "off"
record: full
fs:
  write: ["./.codex-state/", "./work/", "/dev/null", "/dev/tty"]
exec:
  allow: ["bash", "cat"]
net:
  allow: ["tcp://127.0.0.1:$(cat "$root/stub/stub.port")", "unix:/var/run/nscd/socket"]
  dns:
    mode: "off"
env:
  pass: ["PATH", "HOME", "LANG", "TERM", "COLORTERM"]
  set:
    CODEX_HOME: "./.codex-state"
    HISTFILE: "/dev/null"
DIRECT
	chmod 644 "$root/contract/agent.yaml"
	for flags in "" "--no-daemon"; do
		echo "-- codex $flags   (daemon_auto_start = false in its config either way)"
		DRIVE_LABEL=p2c DRIVE_ARGS="$flags" DRIVE_NO_LOGIN=1 DRIVE_WAIT=5 DRIVE_PROMPT="hello" DRIVE_WAIT_AFTER=5 run_driver probe 2>&1 | grep -E '^(screen reached|tego watch exited)' || true
		cur=p2c report startup | grep -E "control socket|managed app-server|lock"
	done

	section "P6. what each switch of codex-config.toml stops: Codex's defaults, one switch group at a time, the resolver reachable"
	switch_run tui t0-defaults ""
	switch_run tui t1-update-check-off "check_for_update_on_startup = false"
	switch_run tui t2-plugins-off $'[features]\nplugins = false'
	switch_run tui t3-all-switches $'check_for_update_on_startup = false\n[analytics]\nenabled = false\n[feedback]\nenabled = false\n[features]\nplugins = false\nremote_plugin = false\napps = false\nshell_snapshot = false\ndaemon_auto_start = false'
	switch_run exec e0-defaults "check_for_update_on_startup = false"
	switch_run exec e1-plugins-off $'check_for_update_on_startup = false\n[features]\nplugins = false'
	switch_run exec e2-analytics-feedback-off $'check_for_update_on_startup = false\n[analytics]\nenabled = false\n[feedback]\nenabled = false'
	switch_run exec e3-both-off $'check_for_update_on_startup = false\n[analytics]\nenabled = false\n[feedback]\nenabled = false\n[features]\nplugins = false'

	section "P3. Codex's own sandbox left on, and then turned off by a flag: a command the model asks for (codex exec)"
	layout default
	echo "-- Codex's defaults: its sandbox (bubblewrap) is on"
	run_exec p3a codex exec --skip-git-repo-check "run the demo"
	cur=p3a report exec
	layout default
	echo "-- the same with --dangerously-bypass-approvals-and-sandbox"
	run_exec p3b codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox "run the demo"
	cur=p3b report exec

	section "P4. what net.dns.mode: off does at tier landlock (a program of its own, not Codex)"
	cat >"$root/contract/dns.yaml" <<DNS
version: 0
name: dns-probe
command: ["python3"]
record: full
capture: "off"
fs:
  write: ["$ws/work/"]
net:
  allow: ["tcp://127.0.0.1:1"]
  dns:
    mode: "off"
DNS
	chmod 644 "$root/contract/dns.yaml"
	cp "$here/dns_probe.py" "$ws/work/dns_probe.py"
	(cd "$ws" && env -i PATH="$PATH" HOME="$home" TEGO_CONFIG="$TEGO_CONFIG" TEGO_TEST_CHAIN_ANCHOR="$TEGO_TEST_CHAIN_ANCHOR" \
		TEGO_TEST_OWN_LOG_HOME="$TEGO_TEST_OWN_LOG_HOME" timeout 60 "$bin" watch --boundary "$root/contract/dns.yaml" --offline -- \
		python3 work/dns_probe.py 2>&1 </dev/null | grep -v '^tego\|^warning\|^  tego\|^  fix')
	"$bin" events "$(newest_run)" --json | jq -r 'select(.kind=="net") | "   ledger: net \(.verdict) \(.reason // "") \(.proto) \(.dst)\(if .best_effort then "  best_effort: true" else "" end)"'

	section "P4b. Codex's own name lookup under net.dns.mode: off (it is told to use http://example.com/v1; nothing is allowed)"
	mkdir -p "$root/dns-codex" && chmod 755 "$root/dns-codex"
	cat >"$root/dns-codex/config.toml" <<TOML
model = "gpt-probe"
openai_base_url = "http://example.com/v1"
check_for_update_on_startup = false
sandbox_mode = "danger-full-access"
approval_policy = "never"
[analytics]
enabled = false
[features]
plugins = false
shell_snapshot = false
daemon_auto_start = false
TOML
	cat >"$root/contract/dns-codex.yaml" <<DNS
version: 0
name: codex-dns-probe
command: ["codex"]
record: full
capture: "off"
fs:
  write: ["$root/dns-codex/", "$ws/work/"]
net:
  allow: ["tcp://127.0.0.1:1"]
  dns:
    mode: "off"
env:
  pass: ["PATH", "HOME", "LANG", "TERM", "CODEX_HOME"]
DNS
	chmod 644 "$root/contract/dns-codex.yaml"
	(cd "$ws" && env -i PATH="$PATH" HOME="$home" LANG=C.UTF-8 CODEX_HOME="$root/dns-codex" \
		TEGO_CONFIG="$TEGO_CONFIG" TEGO_TEST_CHAIN_ANCHOR="$TEGO_TEST_CHAIN_ANCHOR" TEGO_TEST_OWN_LOG_HOME="$TEGO_TEST_OWN_LOG_HOME" \
		timeout 60 "$bin" watch --boundary "$root/contract/dns-codex.yaml" --offline -- codex exec --skip-git-repo-check "hi" \
		</dev/null >"$root/p4b.out" 2>"$root/p4b.err")
	grep -m1 'failed to lookup' "$root/p4b.err" | sed 's/^[0-9TZ:.-]* //' | cut -c1-220
	cur=p4b report exec
fi

if [ "$what" = session ] || [ "$what" = all ]; then
	section "S. the whole interactive session"
	layout session
	compile_contract
	run_driver session
	check "$?" "the driver's own checks (above)"
	run=$(newest_run)
	echo "run: $run"
	"$bin" status "$run" 2>&1 | sed -n '1,2p'
	cur=session report session || fail=1
	echo "-- what is on disk afterwards:"
	(cd "$root" && find ws/work ws/held -type f -printf '   %p  %s bytes\n' | sort)
	check "$([ -z "$(find "$home" "$root/codex-user" "$ws" -iname 'auth.json' -o -iname '*credential*' -o -iname '*oauth*' 2>/dev/null)" ] && echo 0 || echo 1)" \
		"no credential file is left anywhere ($([ "$layout_route" = a ] && echo "the dummy key's auth.json went with the run's private CODEX_HOME" || echo "the dummy key was only ever in the environment"))"
	check "$([ -z "$(ls -A "$root/xdg-tego/tego" 2>/dev/null)" ] && echo 0 || echo 1)" "tego removed the run's private CODEX_HOME at the end of the run"

	echo "-- control, an invented ledger: one allowed connection to a chatgpt.com address appended to a copy of this run's ledger"
	fake=$root/invented
	rm -rf "$fake" && mkdir -p "$fake/state/runs/$run"
	cp "$state/runs/$run/events.jsonl" "$fake/state/runs/$run/events.jsonl"
	echo '{"v":1,"seq":99999,"kind":"net","verdict":"allow","rule":"net[tcp://chatgpt.com:443]","dst":"104.18.32.47:443","proto":"tcp","host":"chatgpt.com","ts":"2026-10-06T00:00:00Z"}' >>"$fake/state/runs/$run/events.jsonl"
	for d in stub ws secrets bin; do ln -s "$root/$d" "$fake/$d"; done
	caught=$(python3 "$here/report.py" "$fake" "$run" "$real_home" session | grep -cE '^FAIL +(the only network allowed|no connection to any other address was allowed)')
	check "$([ "$caught" = 2 ] && echo 0 || echo 1)" "the invented connection made the two network checks fail ($caught of 2; nothing was connected)"
fi

if [ "$what" = learn ] || [ "$what" = all ]; then
	section "L. the same session recorded with no boundary, and the contract tego learn proposes from it"
	layout record plain
	(cd "$ws" && DRIVE_LABEL=record DRIVE_BOUNDARY=none python3 "$here/drive.py" "$root" session)
	run=$(newest_run)
	echo "run: $run"
	cur=record report record
	rm -rf "$root/proposal" && mkdir -p "$root/proposal" && chmod 755 "$root/proposal"  # learn never replaces a file
	"$bin" learn "$run" --workspace "$ws" --out "$root/proposal/proposed.yaml" 2>&1 | sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" | head -20
	echo "-- the proposal (paths relative to the scratch directory shown as \$ROOT):"
	sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" "$root/proposal/proposed.yaml" | cut -c1-190
	echo "-- tego compile of the proposal:"
	(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" compile "$root/proposal/proposed.yaml" --offline 2>&1 | sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" | cut -c1-170 | head -12)

	# When this POC was recorded, learn proposed this entry and it compiled to the tego binary, which the probe then
	# ran. Since 2026-10-16 compile refuses it (agent-contract.md R8a), so the section checks that.
	section "L2. exec.allow \"/proc/self/exe\", which that proposal held when this POC was recorded: compile refuses it"
	cat >"$root/contract/procself.yaml" <<PS
version: 0
name: procself
command: ["bash"]
record: full
capture: "off"
fs:
  write: ["$ws/work/"]
exec:
  allow: ["/proc/self/exe"]
net:
  allow: ["tcp://127.0.0.1:1"]
PS
	chmod 644 "$root/contract/procself.yaml"
	procself_out=$(cd "$ws" && "$bin" compile "$root/contract/procself.yaml" --offline 2>&1)
	procself_rc=$?
	printf '%s\n' "$procself_out" | grep -m1 'exec-proc' | sed "s#$root#\$ROOT#g" | cut -c1-200
	check "$([ "$procself_rc" != 0 ] && printf '%s' "$procself_out" | grep -q 'exec-proc' && echo 0 || echo 1)" \
		"compile refuses the /proc/self/exe entry (exec-proc, exit $procself_rc), so no run of it starts"
fi

if [ "$what" = contracts ] || [ "$what" = all ]; then
	section "C. the contracts for a real key (codex-real-forwarder.yaml, codex-real-direct.yaml): they compile, and their rule tables say what they are for"
	# Templates, with the paths of a real account marked CHANGE: they get a scratch account's here, so that tego can load
	# them. Nothing is run. `compile` only stats the files of the real ~/.codex that the deny_read entries name, as `layout`
	# does.
	ws=$root/ws
	mkdir -p "$ws" "$root/contract" "$root/real-codex-home"
	chmod 755 "$ws" "$root/contract" "$root/real-codex-home"
	: >"$root/real-codex-home/config.toml"
	entries=
	for p in .codex/auth.json .codex/config.toml .codex/history.jsonl .codex/sessions; do
		[ -e "$real_home/$p" ] && entries="${entries:+$entries, }\"$real_home/$p\""
	done
	fill_real() { # fill_real <name>: the template with the scratch account's paths, as $root/contract/<name>.yaml
		sed "s#\"/home/USER/.config/tego/codex\"#\"$root/real-codex-home\"#; s#^  deny_read: .*#  deny_read: [$entries]#" \
			"$here/$1.yaml" >"$root/contract/$1.yaml"
		chmod 644 "$root/contract/$1.yaml"
	}
	rule_table() { # rule_table <contract name> <rows>: tego compile --test, run from the workspace
		(cd "$ws" && "$bin" compile "$root/contract/$1.yaml" --offline --test "$root/contract/$2.yaml" 2>&1)
	}
	for c in codex-real-forwarder codex-real-direct; do
		fill_real "$c"
		out=$(cd "$ws" && "$bin" compile "$root/contract/$c.yaml" --offline 2>&1)
		rc=$?
		echo "-- tego compile $c.yaml (the first lines):"
		echo "$out" | grep -E '^(warning|  fix|contract|tier|capture|fs |exec |net )' | sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" | cut -c1-170
		check "$([ "$rc" = 0 ] && echo 0 || echo 1)" "$c.yaml compiles offline (exit $rc)"
	done
	# what each contract is for, asked of its compiled rule table (the rows are indented so that they are not counted as checks)
	cat >"$root/contract/rows-forwarder.yaml" <<'ROWS'
version: 0
tests:
  - name: a direct connect to the model host, in the contract's own tier
    action: net.connect
    host_port: api.openai.com:443
    expect: refused
  - name: the same in tier landlock
    action: net.connect
    host_port: api.openai.com:443
    tier: landlock
    expect: refused
  - name: the same in tier cgroup
    action: net.connect
    host_port: api.openai.com:443
    tier: cgroup
    expect: refused
  - name: the same in tier bpflsm
    action: net.connect
    host_port: api.openai.com:443
    tier: bpflsm
    expect: refused
  - name: a connect to chatgpt.com, where Codex's plugin sync goes
    action: net.connect
    host_port: chatgpt.com:443
    expect: refused
ROWS
	cat >"$root/contract/rows-direct.yaml" <<'ROWS'
version: 0
tests:
  - name: the model's endpoint
    action: net.connect
    host_port: api.openai.com:443
    expect: allow
  - name: chatgpt.com, where Codex's plugin sync and a ChatGPT login go, is refused
    action: net.connect
    host_port: chatgpt.com:443
    expect: refused
  - name: raw.githubusercontent.com, where its announcement file is, is refused
    action: net.connect
    host_port: raw.githubusercontent.com:443
    expect: refused
ROWS
	chmod 644 "$root/contract/rows-forwarder.yaml" "$root/contract/rows-direct.yaml"
	out=$(rule_table codex-real-forwarder rows-forwarder)
	rc=$?
	echo "-- tego compile codex-real-forwarder.yaml --test (a direct connect around the forwarder):"
	echo "$out" | grep -E '^(PASS|FAIL|[0-9]+ rows)' | sed "s#$root#\$ROOT#g; s#^#   #" | cut -c1-200
	check "$([ "$rc" = 0 ] && echo 0 || echo 1)" "codex-real-forwarder.yaml refuses a direct connect to api.openai.com:443 in every tier, and one to chatgpt.com"
	out=$(rule_table codex-real-direct rows-direct)
	rc=$?
	echo "-- tego compile codex-real-direct.yaml --test (only the model's endpoint):"
	echo "$out" | grep -E '^(PASS|FAIL|[0-9]+ rows)' | sed "s#$root#\$ROOT#g; s#^#   #" | cut -c1-200
	check "$([ "$rc" = 0 ] && echo 0 || echo 1)" "codex-real-direct.yaml allows api.openai.com:443 and refuses chatgpt.com and raw.githubusercontent.com"
	# controls: the same rows against a contract with one rule changed must fail
	sed 's#^    - "tcp://api.openai.com:443"#    - "tcp://api.openai.com:443"\n    - "tcp://chatgpt.com:443"#' "$root/contract/codex-real-direct.yaml" >"$root/contract/codex-real-direct-mutated.yaml"
	sed 's#^  allow: \["unix:/var/run/nscd/socket"\]#  allow: ["unix:/var/run/nscd/socket", "tcp://api.openai.com:443"]#; s#^capture: forwarder#capture: "off"#' \
		"$root/contract/codex-real-forwarder.yaml" >"$root/contract/codex-real-forwarder-mutated.yaml"
	chmod 644 "$root/contract/codex-real-direct-mutated.yaml" "$root/contract/codex-real-forwarder-mutated.yaml"
	out=$(rule_table codex-real-direct-mutated rows-direct)
	echo "-- control: chatgpt.com added to codex-real-direct.yaml's net.allow:"
	echo "$out" | grep -E '^(FAIL|[0-9]+ rows)' | sed "s#$root#\$ROOT#g; s#^#   #; s# (\$ROOT/contract/[^)]*)##" | cut -c1-200
	check "$(echo "$out" | grep -q '^FAIL chatgpt.com' && echo 0 || echo 1)" "with chatgpt.com allowed, the rows of codex-real-direct.yaml fail on it"
	out=$(rule_table codex-real-forwarder-mutated rows-forwarder)
	echo "-- control: the forwarder off and api.openai.com:443 allowed in codex-real-forwarder.yaml:"
	echo "$out" | grep -E '^(FAIL|[0-9]+ rows)' | sed "s#$root#\$ROOT#g; s#^#   #; s# (\$ROOT/contract/[^)]*)##" | cut -c1-200
	check "$(echo "$out" | grep -q '^FAIL a direct connect to the model host' && echo 0 || echo 1)" "with the direct connect allowed and no forwarder, the rows of codex-real-forwarder.yaml fail on it"
fi

if [ "$what" = negative ]; then
	# each mutation: the contract with one rule removed, the check that rule is there for, which must fail
	declare -A must=(
		[ask-to-write]='tego held the agent and a person answered'
		[git-allowed]='git push was refused'
		[secret-readable]='the decoy secret never reached the model'
		[net-allowed]='a connection to an address the contract does not allow'
	)
	for m in ask-to-write git-allowed secret-readable net-allowed; do
		section "N. the session with the rule removed: MUTATE=$m (the check for that rule must FAIL)"
		MUTATE=$m
		layout session
		grep -nE "ask:|allow: \[\"(bash|unix)|deny_read" "$root/contract/agent.yaml" | sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" | cut -c1-200
		out=$(run_driver session 2>&1 | grep -E "^(PASS|FAIL)"; cur=neg-$m report session 2>&1 | grep -E "^(PASS|FAIL)")
		echo "$out" | grep -E "^FAIL" | sed 's/^/   (failed) /'
		echo "   $(echo "$out" | grep -c '^PASS') checks still pass, $(echo "$out" | grep -c '^FAIL') fail"
		check "$(echo "$out" | grep -E '^FAIL' | grep -qF "${must[$m]}" && echo 0 || echo 1)" "with the rule removed, the check '${must[$m]}' fails"
	done
	MUTATE=
fi

tego_home_listing >"$root/tego-home-after.txt"
# Every run here anchors its chain in $ROOT/state/chain.log (report.py checks `events --verify` says so). The real
# ~/.tego/chain.log is the one file of ~/.tego another process on a shared machine may append to meanwhile (it did, while
# nothing of this script ran: sampled every 12 s), so it is compared apart: everything else in ~/.tego must be unchanged.
if ! cmp -s <(grep -v '/chain.log ' "$root/tego-home-before.txt") <(grep -v '/chain.log ' "$root/tego-home-after.txt"); then
	diff <(grep -v '/chain.log ' "$root/tego-home-before.txt") <(grep -v '/chain.log ' "$root/tego-home-after.txt") | head -5
	check 1 "the real ~/.tego is unchanged (listing before and after, chain.log apart)"
else
	check 0 "the real ~/.tego is unchanged (listing before and after, chain.log apart)"
fi
if ! cmp -s <(grep '/chain.log ' "$root/tego-home-before.txt") <(grep '/chain.log ' "$root/tego-home-after.txt"); then
	echo "note: the real ~/.tego/chain.log grew while this ran ($(grep '/chain.log ' "$root/tego-home-before.txt" | cut -d' ' -f2) -> $(grep '/chain.log ' "$root/tego-home-after.txt" | cut -d' ' -f2) bytes); every run here is anchored in \$ROOT/state/chain.log, so it was another process"
fi
echo "directory: $root"
[ "$fail" = 0 ] # the script ends here, with the checks' verdict as its status
