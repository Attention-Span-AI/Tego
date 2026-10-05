# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# Sourced by root-suites.sh and matrix.sh: run a guest step so that a signal to the script alone reaches it.
#
# guarded-run.sh keeps a TERM to kvm-run.sh from orphaning qemu, but a `kill <pid>` of root-suites.sh or matrix.sh
# killed only that shell: kvm-run.sh (and, under matrix.sh, the flock that holds guest.lock for it) ran on until
# --timeout. fwd_run starts the step in the background, forwards INT, TERM and HUP to it, waits for it to wind
# down and exits 143.
#
#   fwd_run CMD [ARG...]     CMD is kvm-run.sh, which has its own trap and stops its guest on TERM.
#   fwd_run -L CMD [ARG...]  CMD is `flock -o LOCK kvm-run.sh ...`: flock does not forward a signal, so the TERM goes
#                            to its child (kvm-run.sh) and flock, and the lock, end with it.
# It returns CMD's status.

fwd_pid=""
fwd_lock=0

# fwd_kill sends TERM to the running step (for -L, to the child of the flock), waiting briefly for that child to
# exist when a signal arrives before flock has started it. It does nothing when no step is running.
fwd_kill() {
	local kids i
	[ -n "$fwd_pid" ] || return 0
	if [ "$fwd_lock" = 1 ]; then
		for ((i = 0; i < 30; i++)); do
			kids="$(pgrep -P "$fwd_pid" 2>/dev/null || true)"
			[ -z "$kids" ] || break
			kill -0 "$fwd_pid" 2>/dev/null || return 0
			sleep 0.1
		done
		# shellcheck disable=SC2086 # a list of pids
		[ -z "$kids" ] || kill -TERM $kids 2>/dev/null || true
	else
		kill -TERM "$fwd_pid" 2>/dev/null || true
	fi
}

fwd_run() {
	local rc
	fwd_lock=0
	if [ "${1:-}" = -L ]; then
		fwd_lock=1
		shift
	fi
	"$@" <&0 &
	fwd_pid=$!
	trap 'fwd_kill; wait "$fwd_pid" 2>/dev/null; exit 143' INT TERM HUP
	wait "$fwd_pid"
	rc=$?
	trap - INT TERM HUP
	fwd_pid=""
	return "$rc"
}
