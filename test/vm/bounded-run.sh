#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bounded-run.sh BOUND COMMAND [ARG...] — timeout(1) BOUND COMMAND with a SIGKILL the host's timeout may not send.
#
# `timeout -k N` is not an escalation on every host: uutils' timeout (coreutils 0.2.2, Ubuntu 25.10's) takes -k
# and never sends the SIGKILL, and goes on waiting for a command that ignores SIGTERM (`timeout -k 2 1 sh -c
# 'trap "" TERM; sleep 8'` returned after 8 s, GNU's after 3 s). A qemu or test launcher that survived SIGTERM
# then kept its RAM and, under matrix.sh, its flock. This script is the escalation with either timeout, as
# kt_run's watchdog is for the kill tests (test/e2e/lib.sh): SIGTERM at BOUND from timeout, SIGKILL to timeout's
# whole process group GRACE seconds later (BOUNDED_RUN_GRACE, default 10). A TERM, INT or HUP to this script is
# passed to timeout and starts the same grace, so guarded_run's signal handling ends a command that ignores it.
#
# Exit status: timeout's, or 137 for a command that had to be killed. Stdin is the command's.
set -uo pipefail

bound="${1:?usage: bounded-run.sh BOUND COMMAND [ARG...]}"
shift
grace="${BOUNDED_RUN_GRACE:-10}"
exec 3<&0
wd=""
tpid=""

# arm (re)starts the watchdog: after $1 seconds it kills timeout's process group. timeout leads a group of its
# own and is the subshell that became it, so the group id is $tpid. The watchdog is stopped the moment timeout
# returns, so it never signals a group id reused since.
arm() {
	[ -z "$wd" ] || { kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null; }
	(
		s=
		trap 'kill $s 2>/dev/null; exit 0' TERM
		sleep "$1" &
		s=$!
		wait "$s" && kill -KILL -- "-$tpid" 2>/dev/null
	) </dev/null >/dev/null 2>&1 &
	wd=$!
}

# shellcheck disable=SC2329 # Called by the INT/TERM/HUP trap below.
on_signal() {
	kill -TERM "$tpid" 2>/dev/null
	arm "$grace"
}

trap 'on_signal' INT TERM HUP
(exec timeout "$bound" "$@") <&3 &
tpid=$!
arm $((bound + grace))
rc=0
while :; do
	wait "$tpid"
	rc=$?
	# A trapped signal makes wait return early with 128+n; the command has ended only when the pid is gone.
	kill -0 "$tpid" 2>/dev/null || break
done
kill "$wd" 2>/dev/null
wait "$wd" 2>/dev/null
exit "$rc"
