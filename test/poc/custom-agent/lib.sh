#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# lib.sh -- the setup run.sh and soak.sh share (README.md). It is sourced, never run. Everything it makes lives under
# $root, and nothing it starts touches the real ~/.tego, ~/.claude, ~/.codex or ~/.ssh.
#
#   lib_init <root>                  an isolated tego: its own machine config, ledger root, price table, chain anchor and
#                                    log (the tegotesthooks build redirects the last two); sets bin, state
#   lib_stub <script.json>           the stand-in model on a fresh port, serving that script; sets stub_port
#   lib_listener                     a throwaway listener on 127.0.0.1, "the port nobody allowed"; sets listener_port
#   lib_workspace <name>             a fresh workspace: the repo, a fake credential, a stand-in git, the agent's files;
#                                    sets ws and outside
#   lib_contract <out> <record> <ask timeout> <limit>...   contract.yaml filled in, each limit as "name: value"
#
# The caller sets here (this directory), repo (the checkout) and helpers=() (pids its cleanup kills).
# shellcheck disable=SC2154 # here and repo are the caller's

lib_init() {
	# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the root is made absolute.
	root=$(cd "$1" && pwd) || return 1
	bin=${TEGO_BIN:-$root/bin/tego}
	if [ -z "${TEGO_BIN:-}" ]; then
		mkdir -p "$root/bin"
		(cd "$repo" && CGO_ENABLED=0 go build -tags=tegotesthooks -o "$bin" ./cmd/tego) || return 1
	fi
	# tego's own files (machine config, ledger, chain anchor, log), the contract and the agent's workspace are three
	# separate directories: tego refuses a contract that lets the agent write its own state or the contract's directory.
	state=$root/tego
	mkdir -p "$state/runs" "$state/ownlog" "$root/home" "$root/contract"
	chmod 755 "$state" "$root/home" "$root/contract" # tego refuses a machine config in a directory others can write
	cat >"$state/prices.yaml" <<'PRICES'
version: 1
updated: 2026-10-06
models:
  claude-stub-1:
    input_per_mtok: 3.00
    output_per_mtok: 15.00
PRICES
	cat >"$state/config.yaml" <<CFG
version: 0
ledger_root: $state/runs
stop_grace: 3s
prices: $state/prices.yaml
CFG
	chmod 600 "$state/config.yaml" "$state/prices.yaml"
	# The runs' runtime directory: a launch makes <XDG_RUNTIME_DIR>/tego and sweeps the directories the invoking user's
	# crashed runs left there, so it is the demo's own, 0700 as tego requires (identity-config.md R27 clause b4).
	mkdir -p "$state/run" && chmod 700 "$state/run"
	cat >"$state/env.sh" <<ENVS
# source this in a second terminal to use tego ask / approve / deny / status / events against these runs
export TEGO_CONFIG=$state/config.yaml
export TEGO_TEST_CHAIN_ANCHOR=$state/chain.log
export TEGO_TEST_OWN_LOG_HOME=$state/ownlog
export XDG_RUNTIME_DIR=$state/run
ENVS
	# shellcheck disable=SC1091 # written just above
	. "$state/env.sh"
	export HOME=$root/home HISTFILE=/dev/null
}

lib_stub() {
	if [ -n "${stub_pid:-}" ]; then
		kill "$stub_pid" 2>/dev/null
		wait "$stub_pid" 2>/dev/null
	fi
	mkdir -p "$root/stub"
	chmod 755 "$root/stub"
	if [ ! -s "$root/stub/cert.pem" ]; then
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
			-keyout "$root/stub/key.pem" -out "$root/stub/cert.pem" -subj /CN=127.0.0.1 \
			-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" -addext "keyUsage=critical,digitalSignature,keyCertSign" \
			-addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || return 1
		chmod 644 "$root/stub/cert.pem"
	fi
	# the forwarder speaks TLS to the stand-in and trusts its certificate through tego's OWN environment; the contract's
	# env.pass leaves SSL_CERT_FILE out, so the agent never sees it
	export SSL_CERT_FILE=$root/stub/cert.pem
	rm -f "$root/stub/port"
	: >"$root/stub/requests.log"
	python3 "$repo/test/workloads/model-stub/server.py" --cert "$root/stub/cert.pem" --key "$root/stub/key.pem" \
		--ready "$root/stub/port" --log "$root/stub/requests.log" --script "$1" 2>"$root/stub/err" &
	stub_pid=$!
	helpers+=("$stub_pid")
	local _
	for _ in $(seq 1 100); do [ -s "$root/stub/port" ] && break; sleep 0.1; done
	stub_port=$(cat "$root/stub/port")
}

lib_listener() {
	[ -n "${listener_port:-}" ] && return 0
	python3 - "$root/listener-port" <<'PY' &
import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept()
    c.close()
PY
	helpers+=("$!")
	local _
	for _ in $(seq 1 50); do [ -s "$root/listener-port" ] && break; sleep 0.1; done
	listener_port=$(cat "$root/listener-port")
}

lib_workspace() {
	ws=$root/ws-$1
	outside=$root/outside-$1
	rm -rf "$ws" "$outside"
	mkdir -p "$ws/work/repo/src" "$ws/work/repo/tests" "$ws/held" "$ws/fake-home/.ssh" "$ws/bin" "$outside"
	chmod 755 "$ws" "$outside"
	local i j
	for i in $(seq -w 1 "${SRC_FILES:-40}"); do
		{
			echo "\"\"\"mod_$i: part of the toy project the agent maintains.\"\"\""
			for j in $(seq 1 12); do
				printf '\n\ndef f_%s_%s(x):\n    """Return x plus %s."""\n    return x + %s\n' "$i" "$j" "$j" "$j"
			done
		} >"$ws/work/repo/src/mod_$i.py"
	done
	cp "$here/project/run_tests.sh" "$ws/work/repo/tests/run_tests.sh"
	echo "-----BEGIN FAKE KEY, NOT A SECRET-----" >"$ws/fake-home/.ssh/id_ed25519"
	cp "$here/project/git" "$ws/bin/git"
	cp "$here/agent.py" "$here/runaway.py" "$ws/"
}

lib_contract() {
	local out=$1 record=$2 timeout=$3 line l
	shift 3
	while IFS= read -r line; do
		case $line in
		@LIMITS@) for l in "$@"; do printf '  %s\n' "$l"; done ;;
		*)
			line=${line//@STUB_PORT@/$stub_port}
			line=${line//@RECORD@/$record}
			printf '%s\n' "${line//@ASK_TIMEOUT@/$timeout}"
			;;
		esac
	done <"$here/contract.yaml" >"$out"
	chmod 644 "$out"
}
