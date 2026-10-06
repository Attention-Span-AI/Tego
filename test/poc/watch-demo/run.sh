#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — a safe, self-contained demonstration of 'tego watch' (README.md). It runs one stand-in agent three ways:
#   A  no boundary: everything is recorded and no rule refuses anything;
#   B  a boundary, with a person answering the approvals the agent triggers (approve --always, deny --always);
#   C  the same boundary with nobody there: the held write is refused when its timeout ends;
# and then proves an interactive program works (D). Everything happens under $DEMO_ROOT, with a machine config of its
# own and tego's chain anchor and log redirected there (the tegotesthooks build): the real ~/.tego is never
# touched. The agent is a script; the only network it sees is one throwaway listener on 127.0.0.1.
#
# Usage: run.sh            (DEMO_ROOT=<dir> to keep the output somewhere: it must not exist or must be empty, and
#                           its mode is set to 755; TEGO_BIN=<tego built with -tags tegotesthooks> to skip the
#                           build; KEEP=1 to keep the scratch directory)
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
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
	root=$(mktemp -d "${TMPDIR:-/tmp}/tego-watch-demo-XXXXXX") || exit 1
fi
# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the root is made absolute.
root=$(cd "$root" && pwd) || exit 1
chmod 755 -- "$root" || exit 1
helpers=()
cleanup() {
	local p
	for p in "${helpers[@]}"; do kill "$p" 2>/dev/null; done
	[ "${KEEP:-0}" = 1 ] || [ -n "${DEMO_ROOT:-}" ] || rm -rf "$root"
}
trap cleanup EXIT

section() { printf '\n==== %s\n' "$1"; }

# --- an isolated tego -------------------------------------------------------------------------------------------
bin=${TEGO_BIN:-$root/bin/tego}
if [ -z "${TEGO_BIN:-}" ]; then
	mkdir -p "$root/bin"
	(cd "$repo" && CGO_ENABLED=0 go build -tags=tegotesthooks -o "$bin" ./cmd/tego) || exit 1
fi
# A binary handed in as TEGO_BIN must be the test build: a product build ignores the anchor and own-log variables set
# below and would anchor this demo's runs in the invoking user's own ~/.tego/chain.log (identity-config.md R27;
# tools/isocheck SH-6). Only the test build contains the variable's name.
grep -aq TEGO_TEST_CHAIN_ANCHOR "$bin" 2>/dev/null || {
	echo "run.sh: $bin is not built with -tags tegotesthooks; it would write the real ~/.tego/chain.log" >&2
	exit 2
}
# tego's own files (machine config, ledger, chain anchor, log) live in $state; the agents' workspaces are beside
# it, never inside it: a contract that lets the agent write tego's own directory is refused.
state=$root/tego
mkdir -p "$state/runs" "$state/ownlog"
chmod 755 "$state" # tego refuses a machine config in a directory others can write, whatever the umask
cat >"$state/config.yaml" <<CFG
version: 0
ledger_root: $state/runs
stop_grace: 3s
CFG
chmod 600 "$state/config.yaml"
# The runs' runtime directory: a launch makes <XDG_RUNTIME_DIR>/tego and sweeps the directories the invoking user's
# crashed runs left there, so it is the demo's own, 0700 as tego requires (identity-config.md R27 clause b4).
mkdir -p "$state/run" && chmod 700 "$state/run"
cat >"$state/env.sh" <<ENVS
# source this in a second terminal to use tego ask / approve / deny / events against this demo
export TEGO_CONFIG=$state/config.yaml
export TEGO_TEST_CHAIN_ANCHOR=$state/chain.log
export TEGO_TEST_OWN_LOG_HOME=$state/ownlog
export XDG_RUNTIME_DIR=$state/run
ENVS
# shellcheck disable=SC1091 # written just above
. "$state/env.sh"
echo "demo directory: $root   (source $state/env.sh to use tego by hand)"

# --- a throwaway listener: the "network" the agent may not reach ---------------------------------------------------
python3 - "$root/port" <<'PY' &
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
for _ in $(seq 1 50); do [ -s "$root/port" ] && break; sleep 0.1; done
port=$(cat "$root/port")

# fresh_ws <name>: a workspace with a project file, a fake credential, a stand-in git and the agent itself.
fresh_ws() {
	ws=$root/ws-$1
	rm -rf "$ws"
	mkdir -p "$ws/work" "$ws/held" "$ws/project" "$ws/fake-home/.ssh" "$ws/bin"
	chmod 755 "$ws"
	echo "an ordinary project file" >"$ws/project/readme.txt"
	echo "-----BEGIN FAKE KEY, NOT A SECRET-----" >"$ws/fake-home/.ssh/id_ed25519"
	printf '#!/bin/sh\necho "pretend: pushed to origin"\n' >"$ws/bin/git"
	chmod +x "$ws/bin/git"
	cp "$here/agent.sh" "$here/unattended.sh" "$ws/"
}

# newest_run prints the id of the most recent run in the demo's ledger.
newest_run() {
	find "$state/runs" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%T@ %f\n' | sort -rn | head -1 | cut -d' ' -f2
}

# show_ledger <run>: the ledger lines that tell the story, not every library the shell opened.
show_ledger() {
	echo "-- the ledger (tego events $1), the lines that matter:"
	"$bin" events "$1" 2>&1 | grep -E ' (refused|ask|answer) |127\.0\.0\.1|project/readme|work/note|held/|fake-home|exec .*(git|cat)' | cut -c1-190
	echo "-- tego status:"
	"$bin" status "$1" 2>&1 | sed -n '1,2p'
}

# answerer <log>: a person at a second terminal. It answers each held write as a person would, after a moment's
# thought, and says what it did: held/a.txt is approved for the rest of the run, anything else is denied for it.
answerer() {
	local run id op target verdict seen=" "
	while :; do
		run=$(newest_run)
		if [ -n "$run" ]; then
			while read -r id _ op target; do
				case "$seen" in *" $id "*) continue ;; esac
				seen="$seen$id "
				case "$target" in */held/a.txt) verdict=approve ;; *) verdict=deny ;; esac
				sleep 1
				"$bin" "$verdict" "$run" "$id" --always >/dev/null 2>&1 &&
					echo "[person] tego $verdict --always   ($op $target)" >>"$1"
			done < <("$bin" ask "$run" 2>/dev/null | grep '^q-')
		fi
		sleep 0.2
	done
}

# --- A: no boundary ----------------------------------------------------------------------------------------------
section "A. tego watch -- bash agent.sh     (no boundary: everything is recorded, no rule refuses anything)"
fresh_ws a
(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch -- bash agent.sh "$port") 2>"$root/a.err"
run_a=$(newest_run)
grep -vE '^(warning|  fix|tego run:)' "$root/a.err"
show_ledger "$run_a"

# --- B: a boundary and a person ------------------------------------------------------------------------------------
section "B. tego watch --boundary boundary.yaml -- bash agent.sh     (a person answers what it asks)"
fresh_ws b
sed 's/@TIMEOUT@/2m/' "$here/boundary.yaml" >"$ws/boundary.yaml"
: >"$root/answers.log"
answerer "$root/answers.log" &
helpers+=("$!")
(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch --boundary boundary.yaml -- bash agent.sh "$port") 2>"$root/b.err"
grep -vE '^(warning|  fix|tego run:)' "$root/b.err"
run_b=$(newest_run)
sleep 1
kill "${helpers[-1]}" 2>/dev/null
echo "-- the person's answers (from a second terminal):"
cat "$root/answers.log"
show_ledger "$run_b"

# --- C: nobody answers ---------------------------------------------------------------------------------------------
section "C. the same boundary with nobody to answer: an unattended run (ask.timeout 5s)"
fresh_ws c
sed 's/@TIMEOUT@/5s/' "$here/boundary.yaml" >"$ws/boundary.yaml"
(cd "$ws" && PATH="$ws/bin:$PATH" "$bin" watch --boundary boundary.yaml -- bash unattended.sh) 2>"$root/c.err"
run_c=$(newest_run)
show_ledger "$run_c"

# --- D: an interactive program -------------------------------------------------------------------------------------
section "D. an interactive program under tego watch (a shell on a real pseudo-terminal)"
fresh_ws d
(cd "$ws" && TEGO_BIN="$bin" python3 "$here/interactive_pty.py")
