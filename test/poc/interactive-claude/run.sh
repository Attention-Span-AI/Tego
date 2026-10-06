#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — the offline interactive Claude Code session under an enforcing tego contract (README.md). It builds an
# isolated tego, starts the local model stand-in, lays out a workspace, runs
#   P1  Claude Code with a dummy key and NO completed first run  (what the startup check does),
#   P2  Claude Code with a completed first run and NO key       (what the login screen does),
#   S   the whole session: dummy key + completed first run, driven on a pty (drive.py),
# and then reads the ledger back and checks it: no connection to an Anthropic address was ever allowed, every model
# request the stand-in answered is an ssl_request source=forwarder, and what each step did.
#
# Everything lives under $ROOT; the real ~/.tego, ~/.claude, ~/.claude.json, ~/.codex and ~/.config/anthropic are
# neither read nor written (the contract denies the agent the last four, `tego watch` is built with the
# tegotesthooks tag so its chain anchor and log live in $ROOT, and ~/.tego is listed before and after).
#
# Usage: run.sh [probe|session|all|negative]     default all
#        negative: three runs of the session with one rule of the contract removed each (MUTATE=ask-to-write,
#        git-allowed, outside-writable); each must FAIL the check that rule is there for. A check that cannot fail
#        proves nothing.
#        ROOT=<dir>   keep everything there (default: a temporary directory, removed at the end unless KEEP=1)
#        TEGO_BIN=<tego built with -tags tegotesthooks> skips the build;  CLAUDE=<path to claude>
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
what=${1:-all}
root=${ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/tego-interactive-claude-XXXXXX")}
mkdir -p "$root" && chmod 755 "$root"
root=$(cd "$root" && pwd)
claude=${CLAUDE:-$(command -v claude || true)}
helpers=()
cleanup() {
	local p
	for p in "${helpers[@]}"; do kill "$p" 2>/dev/null; done
	[ "${KEEP:-0}" = 1 ] || [ -n "${ROOT:-}" ] || rm -rf "$root"
}
trap cleanup EXIT
section() { printf '\n==== %s\n' "$1"; }
fail=0
check() { # check <ok 0|1> <what>
	if [ "$1" = 0 ]; then echo "PASS  $2"; else echo "FAIL  $2"; fail=1; fi
}

[ -n "$claude" ] && [ -x "$claude" ] || { echo "run.sh: no claude on PATH (CLAUDE=<path>)" >&2; exit 2; }
for t in python3 openssl jq; do command -v "$t" >/dev/null || { echo "run.sh: needs $t" >&2; exit 2; }; done

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

# tego's own files (machine config, ledger, chain anchor, log), the contract, the stand-in's files and the agent's
# workspace are four separate directories: tego refuses a contract that lets the agent write its own state or the
# contract file's directory.
state=$root/state
mkdir -p "$state/runs" "$state/ownlog" && chmod 755 "$state"
cat >"$state/config.yaml" <<CFG
version: 0
ledger_root: $state/runs
stop_grace: 3s
CFG
chmod 600 "$state/config.yaml"
# The run's runtime directory (drive.py names the same one): a launch makes <XDG_RUNTIME_DIR>/tego and sweeps the
# directories the invoking user's crashed runs left there, so it is this POC's own, 0700 as tego requires
# (identity-config.md R27 clause b4). It is not under $state: tego denies the agent its own state directory, and the
# Claude Code settings file a run provisions lives in the runtime directory, where the agent must read it.
mkdir -p "$root/run" && chmod 700 "$root/run"
cat >"$state/env.sh" <<ENVS
# source this in a second terminal to use tego ask / approve / deny / events against this run
export TEGO_CONFIG=$state/config.yaml
export TEGO_TEST_CHAIN_ANCHOR=$state/chain.log
export TEGO_TEST_OWN_LOG_HOME=$state/ownlog
export XDG_RUNTIME_DIR=$root/run
ENVS
# shellcheck disable=SC1091 # written just above
. "$state/env.sh"

# the account's own home, as the passwd database names it: what Claude Code reads whatever HOME says
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

# layout <name> <seed>: a fresh workspace and contract for one run. seed=onboarded writes Claude Code's first-run
# flag into CLAUDE_CONFIG_DIR; seed=none leaves the directory empty.
layout() {
	local seed=$1 port entries p
	ws=$root/ws home=$root/home
	rm -rf "$ws" "$home" "$root/outside" "$root/contract" "$root/xdg" "$state/runs"
	mkdir -p "$ws/work" "$ws/held" "$ws/bin" "$ws/.claude-state" "$home" "$root/outside" "$root/contract" "$state/runs"
	chmod 755 "$ws" "$home" "$root/outside" "$root/contract"
	mkdir -p "$root/xdg" && chmod 700 "$root/xdg"
	cp "$here/git" "$ws/bin/git"
	if [ "$seed" = onboarded ]; then
		# Claude Code's own first-run record: "the first-run steps are done". It holds no credential. Without it, its
		# first act is a connectivity check against api.anthropic.com (P1), which this contract refuses.
		echo '{"hasCompletedOnboarding": true, "theme": "dark"}' >"$ws/.claude-state/.claude.json"
	fi
	: >"$root/stub/requests.log"
	sed "s#@W@#$ws#g; s#@OUT@#$root/outside#g" "$here/stub-script.json" >"$root/stub/script.json"
	if [ -n "${stub_pid:-}" ]; then kill "$stub_pid" 2>/dev/null; wait "$stub_pid" 2>/dev/null; fi
	rm -f "$root/stub/stub.port"
	python3 "$repo/test/workloads/model-stub/server.py" --cert "$root/stub/cert.pem" --key "$root/stub/key.pem" \
		--ready "$root/stub/stub.port" --log "$root/stub/requests.log" --script "$root/stub/script.json" 2>"$root/stub/stub.err" &
	stub_pid=$!
	helpers+=("$stub_pid")
	for _ in $(seq 1 100); do [ -s "$root/stub/stub.port" ] && break; sleep 0.1; done
	port=$(cat "$root/stub/stub.port")
	entries=""
	for p in .claude .claude.json .codex .config/anthropic .tego; do
		[ -e "$real_home/$p" ] && entries="$entries\"$real_home/$p\", "
	done
	sed "s#@STUB_PORT@#$port#; s#@ROOT@#$root#g; s#^@DENY_READ@\$#  deny_read: [${entries%, }]#" \
		"$here/claude-interactive-offline.yaml" >"$root/contract/agent.yaml"
	case "${MUTATE:-}" in
	ask-to-write) # held/ is plainly writable: nothing is held
		sed -i 's#^  ask: \["./held/"\]#  ask: []#; s#^    - "./work/"#    - "./work/"\n    - "./held/"#' "$root/contract/agent.yaml" ;;
	git-allowed) # git may run: the push is not refused
		sed -i 's#^  allow: \["bash"\]#  allow: ["bash", "git"]#' "$root/contract/agent.yaml" ;;
	outside-writable) # the directory the agent must not write is writable
		sed -i "s#^    - \"./work/\"#    - \"./work/\"\n    - \"$root/outside/\"#" "$root/contract/agent.yaml" ;;
	dns-system) # the machine's resolver is reachable again
		sed -i 's#^    mode: "off"#    mode: "system"#' "$root/contract/agent.yaml" ;;
	"") ;;
	*) echo "run.sh: unknown MUTATE=$MUTATE" >&2; exit 2 ;;
	esac
	chmod 644 "$root/contract/agent.yaml"
}

# ledger helpers ------------------------------------------------------------------------------------------------------
newest_run() { find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%T@ %f\n' | sort -rn | head -1 | cut -d' ' -f2; }

run_driver() { # run_driver <mode>
	(cd "$ws" && python3 "$here/drive.py" "$root" "$1")
}

# compile_contract: the contract as tego loads and compiles it, from the workspace as the run will
compile_contract() {
	echo "-- tego compile agent.yaml (the contract as loaded; first lines of the rule table):"
	(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" compile "$root/contract/agent.yaml" --offline 2>&1 | sed "s#$root#\$ROOT#g; s#$real_home#\$HOME#g" | cut -c1-170 | head -40)
}

rm -rf "$root/evidence"

if [ "$what" = probe ] || [ "$what" = all ]; then
	section "P1. dummy key, first run NOT completed: what the startup check does (contract as shipped: no name lookup)"
	layout none
	run_driver probe-nokey-unseeded 2>&1 | grep -v '^\[' || true
	run=$(newest_run)
	python3 "$here/report.py" "$root" "$run" "$real_home" probe || fail=1

	section "P1b. the same with net.dns.mode: system: the name resolves, the connection is what is refused"
	MUTATE=dns-system
	layout none
	run_driver probe-nokey-unseeded-dns-system 2>&1 | grep -v '^\[' || true
	MUTATE=
	run=$(newest_run)
	python3 "$here/report.py" "$root" "$run" "$real_home" probe-attempts || fail=1

	section "P2. first run completed, NO key: what Claude Code shows"
	layout onboarded
	export DRIVE_NO_KEY=1
	run_driver probe-nokey 2>&1 | grep -v '^\[' || true
	unset DRIVE_NO_KEY
fi

if [ "$what" = session ] || [ "$what" = all ]; then
	section "S. the whole interactive session"
	layout onboarded
	compile_contract
	run_driver session
	check "$?" "the driver's own checks (above)"
	run=$(newest_run)
	echo "run: $run"
	"$bin" status "$run" 2>&1 | sed -n '1,2p'
	python3 "$here/report.py" "$root" "$run" "$real_home" || fail=1
	echo "-- what is on disk afterwards:"
	(cd "$root" && find ws/work ws/held outside -type f -printf '   %p  %s bytes\n' | sort)
	check "$([ -z "$(find "$ws/.claude-state" "$home" -iname '*credential*' -o -iname '*.api_key' -o -iname '*oauth*' 2>/dev/null)" ] && echo 0 || echo 1)" \
		"no credential file exists anywhere the session could have written one (CLAUDE_CONFIG_DIR, HOME)"
fi

if [ "$what" = negative ]; then
	for m in ask-to-write git-allowed outside-writable; do
		section "N. the session with the rule removed: MUTATE=$m (the checks below must FAIL)"
		MUTATE=$m
		layout onboarded
		grep -nE "ask:|allow: \[\"bash|outside/|held/" "$root/contract/agent.yaml" | sed "s#$root#\$ROOT#g"
		run_driver session 2>&1 | grep -E "^(PASS|FAIL)"
		run=$(newest_run)
		python3 "$here/report.py" "$root" "$run" "$real_home" | grep -E "^(PASS|FAIL)"
	done
	MUTATE=
	echo "(every FAIL above is the check that the removed rule makes fail; this mode's exit status is not a verdict)"
	fail=0
fi

tego_home_listing >"$root/tego-home-after.txt"
cmp -s "$root/tego-home-before.txt" "$root/tego-home-after.txt"
check "$?" "the real ~/.tego is unchanged (listing before and after)"
echo "directory: $root"
[ "$fail" = 0 ] # the script ends here, with the checks' verdict as its status
