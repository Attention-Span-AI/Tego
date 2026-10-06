#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# agent.sh — a stand-in for ANY agent, for the 'tego watch' demo (README.md). It is not an AI: it is a script that
# tries, in order, the things a boundary should allow, hold for a person, or refuse, and prints what each attempt
# saw. Tego treats it as a black box, exactly as it would Claude Code or Codex. It touches only the demo's own
# scratch directory and one throwaway listener on 127.0.0.1, and its "git" is a harmless stand-in on PATH.
set -u

port=${1:?usage: agent.sh <listener port>}

# elapsed_ms prints the milliseconds since $1, a value of $EPOCHREALTIME with its decimal point removed.
elapsed_ms() { echo $((("${EPOCHREALTIME/./}" - $1) / 1000)); }

# try <label> <function>: run one attempt, say what it saw and how long it took. A long wait is the agent held at
# an approval; DENIED is a refusal, and tego's ledger says which rule refused it.
try() {
	local label=$1 start out rc verdict=allowed reason=
	start=${EPOCHREALTIME/./}
	out=$("$2" 2>&1)
	rc=$?
	if [ "$rc" -ne 0 ]; then
		verdict=DENIED
		reason=${out##*: }
		reason=${reason%% (os error*}
	fi
	printf '%-47s %-8s %-18s %5s ms\n' "$label" "$verdict" "$reason" "$(elapsed_ms "$start")"
}

read_project() { cat project/readme.txt >/dev/null; }
write_inside() { echo "the agent was here" >work/note.txt; }
read_secret() { cat fake-home/.ssh/id_ed25519 >/dev/null; }
run_git_push() { git push; }
connect_out() { exec 3<>"/dev/tcp/127.0.0.1/$port"; }
held_first() { echo one >held/a.txt; }
held_again() { echo two >>held/a.txt; }
held_other() { echo x >held/b.txt; }
held_other_again() { echo y >held/b.txt; }

printf '%-47s %-8s %-18s %8s\n' "step" "outcome" "why" "time"
try "read a project file" read_project
try "write inside the workspace (work/)" write_inside
try "read a credential (fake-home/.ssh/id_ed25519)" read_secret
try "run 'git push'" run_git_push
try "connect to 127.0.0.1:$port" connect_out
try "write held/a.txt (asks a person)" held_first
try "write held/a.txt again (the same ask)" held_again
try "write held/b.txt (asks a person)" held_other
try "write held/b.txt again (the same ask)" held_other_again
echo "the agent finished"
