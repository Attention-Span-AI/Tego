# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# Sourced by kvm-run.sh: run the guest under a bound that a signal to the script also reaches.
#
# GNU and uutils timeout(1) both move themselves into a process group of their own, so a Ctrl-C or a TERM to
# kvm-run.sh (or to root-suites.sh, matrix.sh or the session that launched them) never reached timeout or
# qemu: the guest was orphaned, kept its RAM until --timeout (25 to 60 minutes) and, under matrix.sh, held the
# flock the orphan inherited, so the next boot waited for it. guarded_run starts the pipeline in the
# background, records the pid of the process it runs, and forwards INT, TERM and HUP to it. The callers run
# bounded-run.sh there, which passes TERM to timeout and escalates to SIGKILL itself (timeout -k never does on
# uutils').

guarded_pidf=""
guarded_bg=""

# guarded_kill sends TERM to the guarded command, waiting briefly for its pid file when a signal arrives
# before the background pipeline has written it. It does nothing when no guarded run is in progress.
guarded_kill() {
	local i pid
	[ -n "$guarded_pidf" ] && [ -n "$guarded_bg" ] || return 0
	for ((i = 0; i < 30; i++)); do
		pid="$(cat "$guarded_pidf" 2>/dev/null || true)"
		if [ -n "$pid" ]; then
			kill -TERM "$pid" 2>/dev/null || true
			return 0
		fi
		kill -0 "$guarded_bg" 2>/dev/null || return 0
		sleep 0.1
	done
}

# guarded_run CONSOLE STATUSFILE COMMAND [ARG...] runs COMMAND with its output copied to CONSOLE and to stdout
# (stderr and stdin are the caller's), and leaves COMMAND's exit status in STATUSFILE. It returns 0 once the
# command has ended, and exits 143 after a signal, once the command has been told to stop and has ended.
guarded_run() {
	local console="$1" statusf="$2"
	shift 2
	guarded_pidf="$statusf.pid"
	rm -f "$guarded_pidf" "$statusf"
	# fd 9 is the build lock: the guest must not hold it.
	(
		exec 9>&-
		bash -c 'echo $$ >"$1"; shift; exec "$@"' guarded "$guarded_pidf" "$@" | tee "$console"
		echo "${PIPESTATUS[0]}" >"$statusf"
	) &
	guarded_bg=$!
	trap 'guarded_kill; wait "$guarded_bg" 2>/dev/null; exit 143' INT TERM HUP
	wait "$guarded_bg" || true
	trap - INT TERM HUP
	guarded_bg=""
	return 0
}
