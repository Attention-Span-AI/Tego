#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# ssh-suite.sh: run one long command (a root suite) in a full-distribution KVM guest reached over SSH, detached from
# the SSH session that starts it, and tell apart the ways it can end: the command finished (its own exit code), it ran
# past its bound, or the guest was lost (qemu ended, the guest stopped answering, or the run's supervisor is gone without
# a result) before the command's end was recorded.
#
# Why it exists: test/vm/kvm-run.sh's initramfs guests run their command under the guest's own /init and report over
# the serial console, so no connection can cut a suite short. A full distribution (AlmaLinux 9.8 with SELinux, a
# release kit's cloud image, test/vm/service-install.py's guests) is driven over SSH instead, and a suite run inside an
# SSH session ends when the session does. On 2026-11-11 the host's memory guard SIGKILLed such a guest's qemu during a
# root suite; the driver read "Connection to 127.0.0.1 closed by remote host" as the suite's end, and the lost guest was
# taken for hours for a product failure in the test that happened to be running.
#
# How: the start writes the run's files into a state directory, DIR/NAME (mode 0700), each read back and compared
# (cksum) before anything runs, and starts a supervisor (setsid, nohup) that records who it is (the guest's boot id, its
# pid and the pid's start time), runs COMMAND in a process group of its own from another directory, DIR/NAME.work,
# with its output in the state's log, ends that group past --timeout (SIGTERM, then SIGKILL --grace seconds later, until
# no process of it is left), and last writes its result, with the run's nonce, through a rename. A poll is a fresh SSH
# call (each one ended by bounded-run.sh at --call-timeout: SIGTERM, then SIGKILL) that fetches the log's new bytes and
# asks whether the supervisor, by boot id, pid and start time, still runs. The run is over only when the supervisor is
# gone and its result is there with the nonce; neither a file COMMAND writes in its own directory nor a result without
# the nonce ends it. When a poll fails, qemu is asked (--qemu-pid, and --qemu-status, the line its starter writes when
# it ends). A start whose answer was lost is found again by its nonce and polled, never started twice.
#
# Usage: test/vm/ssh-suite.sh --ssh SSH --qemu-pid PID [options] -- COMMAND [ARG...]
#   --ssh SSH           an executable that runs its one argument as a shell command line on the guest, as `ssh HOST CMD`
#                       does (a wrapper with the port, key and user); each call is a new connection
#   --qemu-pid PID      the pid of the guest's qemu on this host
#   --qemu-status FILE  where the guest's starter writes qemu's end once qemu has ended: "signal <n>" or "exit <n>"
#   --sudo              run the supervisor (and so COMMAND) as root through `sudo -n`, so that it can end every
#                       process of the command's group; the state is then root's
#   --name NAME         the run's name in the guest (default suite; letters, digits, '.', '_', '-'; not . or ..)
#   --dir DIR           the guest directory the runs live in (default /var/tmp/tego-ssh-suite: on the guest's disk)
#   --log FILE          keep everything the command printed in FILE (it is also copied to stdout as it comes)
#   --status FILE       write one line saying where the exit code came from: "guest <code>", "timeout",
#                       "lost signal <n>", "lost exit <n>", "lost qemu-gone", "lost unreachable", "lost suite-gone",
#                       "lost rebooted", "short-log", "env" or "usage"
#   --poll SECS         seconds between polls (default 10)
#   --timeout SECS      the supervisor ends the command's group after SECS (default 3600)
#   --grace SECS        seconds between that SIGTERM and the SIGKILL (default 10)
#   --unreachable SECS  a guest that has answered no call for SECS while qemu runs is lost (default 300)
#   --call-timeout SECS end one SSH call that has not returned in SECS (default 120, at least 1): a frozen guest can hold
#                       a connection open without a word, and a call that never returned would never ask qemu
#
# Exit code: COMMAND's own when the supervisor recorded its end; 98 when the guest was lost first (a GUEST-LOST line
# says how: nothing it printed is a test result); 124 when the command ran past --timeout; 97 when it could not be
# started (DIR/NAME is another run's, or a setup file did not read back whole) or its log did not come back whole; 2 on a
# usage error. A command can exit 98, 124 or 97 itself: the --status word (guest 98 against lost ...) tells which.
set -u

EXIT_ENV=97
EXIT_LOST=98
EXIT_TIMEOUT=124
EXIT_USAGE=2

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ssh_cmd="" qemu_pid="" qemu_status="" as="" name=suite dir=/var/tmp/tego-ssh-suite logfile="" statusfile=""
poll=10 limit=3600 grace=10 unreachable=300 calltimeout=120

say() { echo "ssh-suite: $*" >&2; }
status() { [ -z "$statusfile" ] || echo "$*" >"$statusfile" || say "cannot write the status file $statusfile"; }
usage() {
	sed -n '/^# Usage:/,/^# Exit code:/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
	status usage
	exit "$EXIT_USAGE"
}
# sq quotes one word for a remote shell, whole: the x keeps the command substitution from trimming trailing newlines.
sq() {
	_sq=$(printf '%sx' "$1" | sed "s/'/'\\\\''/g")
	printf "'%s'" "${_sq%x}"
}
num() { case "$1" in "" | *[!0-9]*) return 1 ;; esac; }

while [ $# -gt 0 ]; do
	case "$1" in
	--sudo) as="sudo -n"; shift ;;
	--ssh | --qemu-pid | --qemu-status | --name | --dir | --log | --status | --poll | --timeout | --grace | --unreachable | --call-timeout)
		[ $# -ge 2 ] || usage
		case "$1" in
		--ssh) ssh_cmd=$2 ;;
		--qemu-pid) qemu_pid=$2 ;;
		--qemu-status) qemu_status=$2 ;;
		--name) name=$2 ;;
		--dir) dir=$2 ;;
		--log) logfile=$2 ;;
		--status) statusfile=$2; : >"$statusfile" || exit "$EXIT_USAGE" ;;
		--poll) poll=$2 ;;
		--timeout) limit=$2 ;;
		--grace) grace=$2 ;;
		--unreachable) unreachable=$2 ;;
		--call-timeout) calltimeout=$2 ;;
		esac
		shift 2
		;;
	-h | --help) usage ;;
	--) shift; break ;;
	*) say "unknown option $1"; usage ;;
	esac
done
[ -n "$ssh_cmd" ] && [ $# -ge 1 ] || usage
for n in "$qemu_pid" "$poll" "$limit" "$grace" "$unreachable" "$calltimeout"; do num "$n" || usage; done
[ "$calltimeout" -ge 1 ] || { say "--call-timeout must be at least 1"; usage; }
case "$name" in . | ..) say "--name cannot be . or .."; usage ;; "" | *[!A-Za-z0-9._-]*) say "--name is letters, digits, '.', '_' and '-'"; usage ;; esac
case "$dir" in /*) ;; *) say "--dir must be absolute"; usage ;; esac

state="$dir/$name"
work="$dir/$name.work"
[ -n "$logfile" ] || logfile="./ssh-suite-$name.log"
: >"$logfile" || { say "cannot write the log $logfile"; status env; exit "$EXIT_ENV"; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ssh-suite.XXXXXX") || { status env; exit "$EXIT_ENV"; }
trap 'rm -rf "$tmp"' EXIT
trap 'exit 143' INT TERM HUP
nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
[ -n "$nonce" ] || { say "no nonce"; status env; exit "$EXIT_ENV"; }

cmdline=""
for a in "$@"; do cmdline="$cmdline $(sq "$a")"; done
cmdtext="exec$cmdline
"

# st prints the start time of a pid (field 22 of /proc/<pid>/stat, read after the command name, which may hold spaces).
# shellcheck disable=SC2016 # the guest's sh expands it
remote_st='st() { _s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1; _s=${_s##*) }; set -- $_s; shift 19; echo "$1"; }'

# The supervisor, as the guest runs it: setsid nohup sh STATE/sup.sh STATE WORK LIMIT GRACE NONCE.
suptext="#!/bin/sh
# ssh-suite.sh's supervisor: runs STATE/cmd in a process group of its own from WORK, ends the group past LIMIT seconds,
# and writes \"NONCE exit|timeout|setup CODE ended|left\" to STATE/result last.
$remote_st
S=\$1 W=\$2 L=\$3 G=\$4 N=\$5
cd \"\$S\" || exit 1
b=\$(cat /proc/sys/kernel/random/boot_id) || exit 1
echo \"\$b \$\$ \$(st \$\$)\" >sup.part && mv sup.part sup || exit 1
result() { printf '%s %s %s %s\\n' \"\$N\" \"\$1\" \"\$2\" \"\$3\" >result.part && mv result.part result; }
cd \"\$W\" || { result setup 1 ended; exit 1; }
setsid sh \"\$S/cmd\" </dev/null >>\"\$S/log\" 2>&1 &
c=\$!
echo \"\$c \$(st \$c)\" >\"\$S/child.part\" && mv \"\$S/child.part\" \"\$S/child\"
(
	i=0
	while [ \$i -lt \"\$L\" ] && [ ! -e \"\$S/ended\" ]; do sleep 1; i=\$((i + 1)); done
	[ ! -e \"\$S/ended\" ] || exit 0
	: >\"\$S/timedout\"
	kill -s TERM -- \"-\$c\" 2>/dev/null
	i=0
	while [ \$i -lt \"\$G\" ] && kill -s 0 -- \"-\$c\" 2>/dev/null; do sleep 1; i=\$((i + 1)); done
	kill -s KILL -- \"-\$c\" 2>/dev/null
	exit 0
) </dev/null >/dev/null 2>&1 &
w=\$!
wait \"\$c\"
rc=\$?
: >\"\$S/ended\"
wait \"\$w\"
cd \"\$S\" || exit 1
kind=exit
[ ! -e timedout ] || kind=timeout
grp=ended
if [ \"\$kind\" = timeout ]; then
	i=0
	while [ \$i -lt 20 ] && kill -s 0 -- \"-\$c\" 2>/dev/null; do kill -s KILL -- \"-\$c\" 2>/dev/null; sleep 1; i=\$((i + 1)); done
fi
! kill -s 0 -- \"-\$c\" 2>/dev/null || grp=left
result \"\$kind\" \"\$rc\" \"\$grp\"
"

sumof() { printf '%s' "$1" | cksum; }

# call SCRIPT: runs SCRIPT on the guest (through sudo -n with --sudo), its stdout in $tmp/out and stderr in $tmp/err;
# bounded-run.sh ends it at --call-timeout (SIGTERM to the call, SIGKILL to its process group 5 s later).
call() {
	BOUNDED_RUN_GRACE=5 "$here/bounded-run.sh" "$calltimeout" "$ssh_cmd" "${as:+$as }sh -c $(sq "$1")" </dev/null >"$tmp/out" 2>"$tmp/err"
}

# The start: idempotent by the nonce, so a start whose answer was lost is run again safely. It prints
# TEGO-SSH-SUITE-STARTED once the supervisor has recorded itself, or TEGO-SSH-SUITE-NOSTART with the reason (as data:
# the reason never holds a path).
start="set -u
d=$(sq "$dir") s=$(sq "$state") w=$(sq "$work") n=$(sq "$nonce")
no() { echo \"TEGO-SSH-SUITE-NOSTART \$1\"; exit 0; }
mkdir -p \"\$d\" || no 'the runs directory cannot be made'
if ! mkdir \"\$s\" 2>/dev/null; then
	[ \"\$(cat \"\$s/nonce\" 2>/dev/null)\" = \"\$n\" ] || no 'the run directory exists and is not this run'
	i=0
	while [ ! -s \"\$s/sup\" ] && [ ! -e \"\$s/setup-failed\" ] && [ \$i -lt 15 ]; do sleep 1; i=\$((i + 1)); done
	[ -s \"\$s/sup\" ] || no 'an earlier start of this run did not finish setting up'
	echo 'TEGO-SSH-SUITE-STARTED again'
	exit 0
fi
fail() { : >\"\$s/setup-failed\"; no \"\$1\"; }
chmod 700 \"\$s\" || fail 'the state directory mode cannot be set'
printf '%s\\n' \"\$n\" >\"\$s/nonce\" && [ \"\$(cat \"\$s/nonce\")\" = \"\$n\" ] || fail 'the nonce did not read back'
put() { printf '%s' \"\$2\" >\"\$s/\$1\" || fail \"\$1 was not written\"; [ \"\$(cksum <\"\$s/\$1\")\" = \"\$3\" ] || fail \"\$1 did not read back whole\"; }
put cmd $(sq "$cmdtext") $(sq "$(sumof "$cmdtext")")
put sup.sh $(sq "$suptext") $(sq "$(sumof "$suptext")")
: >\"\$s/log\" || fail 'the log cannot be made'
mkdir -p \"\$w\" || fail 'the working directory cannot be made'
setsid nohup sh \"\$s/sup.sh\" \"\$s\" \"\$w\" $limit $grace \"\$n\" </dev/null >/dev/null 2>&1 &
i=0
while [ ! -s \"\$s/sup\" ] && [ \$i -lt 15 ]; do sleep 1; i=\$((i + 1)); done
[ -s \"\$s/sup\" ] || fail 'the supervisor did not record itself in 15 s'
echo 'TEGO-SSH-SUITE-STARTED'"

# qemu_end prints how qemu ended ("signal <n>", "exit <n>"), "gone" when it has ended and nobody wrote how, or nothing
# while it runs. A starter notices qemu's end a moment after it, so a qemu found gone gets 10 s for its status line.
qemu_end() {
	kill -0 "$qemu_pid" 2>/dev/null && [ ! -s "${qemu_status:-/nonexistent}" ] && return 0
	i=0
	while [ -n "$qemu_status" ] && [ ! -s "$qemu_status" ] && [ "$i" -lt 10 ]; do
		sleep 1
		i=$((i + 1))
	done
	if [ -n "$qemu_status" ] && [ -s "$qemu_status" ]; then head -n 1 "$qemu_status"; else echo gone; fi
}

# lost STATUS-WORD TEXT: the guest is gone or silent before the supervisor's result.
lost() {
	line="GUEST-LOST: $2 before the suite $name finished; this is not a test result"
	echo "$line" >&2
	echo "$line" >>"$logfile" || say "cannot write the log $logfile"
	status "lost $1"
	exit "$EXIT_LOST"
}

# unanswered: a call failed; lost if qemu ended or the guest has been silent for --unreachable.
last_ok=$(date +%s)
unanswered() {
	end=$(qemu_end)
	case "$end" in
	"signal "[0-9]*) lost "$end" "qemu ended by $end" ;;
	"exit "[0-9]*) lost "$end" "qemu ended ($end)" ;;
	gone) lost qemu-gone "qemu (pid $qemu_pid) ended, how is not recorded," ;;
	esac
	now=$(date +%s)
	say "$1 ($(tail -n 1 "$tmp/err" 2>/dev/null)); qemu still runs; silent for $((now - last_ok))s"
	[ $((now - last_ok)) -lt "$unreachable" ] || lost unreachable "the guest answered no call for $((now - last_ok))s while qemu runs"
}

while :; do
	if call "$start" && grep -q '^TEGO-SSH-SUITE-STARTED' "$tmp/out"; then
		break
	fi
	if grep -q '^TEGO-SSH-SUITE-NOSTART' "$tmp/out"; then
		say "the command did not start in the guest: $(sed -n 's/^TEGO-SSH-SUITE-NOSTART //p' "$tmp/out" | head -n 1)"
		status env
		exit "$EXIT_ENV"
	fi
	unanswered "the start got no answer"
	sleep "$poll"
done
last_ok=$(date +%s)
say "started $name in the guest ($state, nonce $nonce); polling every ${poll}s"

off=0
stalled=0
started=$(date +%s)
# The host's own bound, past the supervisor's: its timeout, the grace, the group's end and a few calls.
deadline=$((started + limit + grace + 30 + 3 * calltimeout + 2 * poll))
while :; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		say "$name has no recorded end $((deadline - started))s after it started, past its --timeout ${limit}s and the grace"
		status "timeout unconfirmed"
		exit "$EXIT_TIMEOUT"
	fi
	# The result first, then the supervisor's liveness, then the log's size: a log read after the result is whole. A
	# supervisor found gone with no result read a moment before is asked again, as it writes its result before it ends.
	pollcmd="$remote_st
cd $(sq "$state") 2>/dev/null || { echo TEGO-SSH-SUITE-NODIR; exit 0; }
res=-; [ ! -f result ] || res=\$(cat result)
b=\$(cat /proc/sys/kernel/random/boot_id) || exit 3
alive=no reboot=no
if read -r sb sp sst <sup; then
	if [ \"\$sb\" != \"\$b\" ]; then reboot=yes; elif [ \"\$(st \"\$sp\")\" = \"\$sst\" ]; then alive=yes; fi
fi
if [ \"\$alive\" = no ] && [ \"\$res\" = - ] && [ -f result ]; then res=\$(cat result); fi
s=\$(wc -c <log) || exit 3
echo \"TEGO-SSH-SUITE \$s \$alive \$reboot \$res\"
exec tail -c +$((off + 1)) log"
	if call "$pollcmd" && hdr=$(head -n 1 "$tmp/out") && [ "${hdr%% *}" = TEGO-SSH-SUITE ]; then
		last_ok=$(date +%s)
		# shellcheck disable=SC2086 # the header's words
		set -- $hdr
		size=$2 alive=$3 reboot=$4 rnonce=${5:--} kind=${6:-} rc=${7:-} grp=${8:-}
		tail -n +2 "$tmp/out" >"$tmp/chunk"
		got=$(wc -c <"$tmp/chunk")
		if [ "$got" -gt 0 ]; then
			cat "$tmp/chunk" >>"$logfile" || { say "cannot write the log $logfile"; status env; exit "$EXIT_ENV"; }
			cat "$tmp/chunk"
			off=$((off + got))
		fi
		if [ "$alive" = no ] && [ "$rnonce" = "$nonce" ]; then
			if [ "$off" -lt "$size" ]; then
				stalled=$((stalled + 1))
				say "the log came back short ($off of $size bytes)"
				if [ "$stalled" -ge 3 ]; then
					say "the log of $name did not come back whole in 3 tries after its end; its exit was $kind $rc"
					status short-log
					exit "$EXIT_ENV"
				fi
				sleep 1
				continue
			fi
			[ "$grp" = ended ] || say "processes of $name's group still run in the guest after its end"
			case "$kind" in
			exit)
				num "$rc" || rc=1
				status "guest $rc"
				say "$name ended in the guest with exit $rc"
				exit "$rc"
				;;
			timeout)
				say "$name ran past ${limit}s; its group was ended (SIGTERM, then SIGKILL): $grp"
				if [ "$grp" = ended ]; then status timeout; else status "timeout group-left"; fi
				exit "$EXIT_TIMEOUT"
				;;
			*)
				say "the supervisor of $name could not start it ($kind)"
				status env
				exit "$EXIT_ENV"
				;;
			esac
		fi
		if [ "$alive" = no ]; then
			[ "$reboot" = no ] || lost rebooted "the guest booted again (another boot id)"
			lost suite-gone "the suite's supervisor in the guest is gone without its result (something killed it)"
		fi
	else
		[ "$(head -n 1 "$tmp/out" 2>/dev/null)" != TEGO-SSH-SUITE-NODIR ] ||
			lost suite-gone "the guest answered but has no $state (a fresh guest, or its disk was replaced)"
		unanswered "a poll failed"
	fi
	sleep "$poll"
done
