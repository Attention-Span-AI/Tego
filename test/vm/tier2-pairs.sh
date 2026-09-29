#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# tier2-pairs.sh — the guest half of the concurrent tier-2 freeze hunt and of ADR 0021's pairs conditions:
# PAIRS pairs of `tego run --tier cgroup` of one contract, the second started 0-20 ms after the first, under a
# watchdog that dumps every task's kernel stack and the fanotify groups each process holds once a pair stops making
# progress. test/vm/pairs.sh (`make vm-pairs`) boots the guests and runs it per variant.
#
# Why a watchdog of its own: each tier-2 run on the fanotify fallback marks the mount of `/` with FAN_OPEN_PERM and
# FAN_OPEN_EXEC_PERM (docs/p0/enforce-cgroup-observe.md §6 E34), so a group whose listener stops answering
# blocks every open and every execve on the guest's root, this script's included. The watchdog is a
# subshell forked before the first run, and from then on it uses bash builtins only: `read -t` on a fifo to
# sleep, `read` to print a file, `kill` to signal. It opens nothing on `/`: its fifo, the heartbeat and the
# launchers' output live on the tmpfs `/tmp`, and the stacks under procfs. Its report goes to the console
# (fd 1, opened by /init before any group existed), which kvm-run.sh captures with --log.
#
# What it proves per pair (ADR 0021, A-0021-1): PLANE is exported as TEGO_TEST_PLANE, the decision plane's pin
# of a tegobpf,tegotesthooks build (internal/cli/machine_testhook.go), so a host where a plane mode passes still
# runs the fallback when PLANE=fanotify. Nothing is taken on trust: each run's contract denies reading SECRET, a
# file on `/` (so the run's mark is on the root mount, as in the original report, not on the tmpfs /tmp), and its agent reads it
# once and says whether the read went through. The deny_read is nested in a write entry for SECRET's directory:
# Landlock grants reads beneath a write entry, so it is the plane, or the listener on the fallback, that refuses that
# read, never Landlock (whose EACCES would come first and leave the listener nothing to decide).
# Each pair is judged once, from all of its evidence together, before cleanup removes it (assert_pair, judge; ADR
# 0021's 2026-10-19 note holds the table): first it settles (a killed launcher's run is closed by its
# reaper after the launcher's wait returned, ADR 0020 (3)); then every run that started must report PLANE as its
# decision_plane, refuse SECRET at most once and only by that plane's mechanism (source fanotify on the fallback;
# mechanism plane with the mode as decision_plane otherwise), hold no other verdict on SECRET and no exec line of
# the stage (ADR 0021 (2)), and be one launcher's by run_start's launcher_pid; then each launcher gets one verdict
# from its exit status, whether kill mode's SIGKILL targeted it, its own run and its output, and no other
# combination than the table's passes: complete (exited 0, the run whole with one refusal and run_end reason exit,
# the agent saying its read was refused), killed-early, killed-in-run or killed-read (the target, exited 137), or
# failed (any other exit, which fails the pair). killed-read is E15's window (enforce-cgroup-observe §6 E15, a
# stated P0 limit): on the fallback the agent of a SIGKILLed launcher runs undecided by fanotify until the reaper
# kills it, so its read may go through; it passes only where the run shows exactly that (no refusal of SECRET, a
# run_end reason orphaned) and is counted and printed as "PAIRS-KILLED-READ pair=<i> launcher=<a|b> plane=fanotify".
# A pair that fails the judgement prints "PAIRS-ASSERT-FAIL pair=<i> what=<item> ..." with the evidence it judged and
# ends the script with no PAIRS-DONE: 1, or 2 when the first pair ran on another plane than PLANE (the binary is not
# a test-hooks build, or the host lacks the mode).
#
# Run it from the host (test/vm/pairs.sh does this for each variant):
#
#   TEGO_VM_MEM=1536M TEGO_VM_SMP=2 test/vm/kvm-run.sh --sudo --timeout 900 --log pairs.console \
#     --file bin/tego:/usr/local/bin/tego --file test/vm/tier2-pairs.sh:/vm/tier2-pairs.sh \
#     --env PAIRS=100 --env MODE=plain -- /bin/bash /vm/tier2-pairs.sh
#
# It prints "PAIR <i> rc=<a>,<b>" per pair (with " kill=<a|b>", the launcher the SIGKILL targeted, in kill mode) and
# "PAIRS-DONE <ok>/<n> plane=<mode> copy_b=<0|1> listener=<0|1> mode=<MODE> kills=<k> kills_started=<s>
# killed_reads=<r>" at the end: in k pairs the targeted launcher's verdict was a killed one, in s of them its run
# had started, and in r of them its agent read SECRET in E15's window (all 0 outside kill mode). A stall prints a report
# between "=== WATCHDOG" lines: the stacks and marks, then SIGABRT to the launchers for their goroutines (a
# launcher stuck stopping the world prints none), then SIGKILL to them and whether the pair loop, which execs
# on the marked root, moves again, then the same for the third-party listener, so "Tego's group holds" and
# "the third party holds" are told apart. It then powers the guest off, so kvm-run.sh reports no-report (125) and
# the console log holds the report.
#
# Environment:
#   PAIRS        pairs to run (default 50)
#   STALL        seconds without progress that count as a stall (default 20)
#   COLD_STALL   the same for the invocation's first run (the self-deny run, else pair 1), at least STALL (default
#                120): the first run of each binary in a boot probes the plane modes cold (doctor's run-probe cache
#                is keyed by the binary, so COPY_B's copy and the PIE pay it too). A boot's first run measured
#                13.6-17.8 s on 6.17 (docs/p0/enforce-plane.md §10.1, cold.bootfirst.ms), and over 20 s in the
#                2-CPU pairs guests on a loaded host (2026-10-19), which STALL took for a freeze
#   MODE         plain: two launchers, each waited for;
#                timeout: each launcher under `timeout -s QUIT -k 5 40`, as the original report ran
#                (uutils coreutils 0.2.2's timeout, Ubuntu 25.10's, never sends the -k SIGKILL);
#                kill: as plain, and one launcher of each pair is SIGKILLed at a point drawn uniformly from the
#                previous pair's length after the second one started (0-900 ms for the first pair), so the kills
#                fall across a run's life, from its start to its teardown, at any AGENT_SLEEP: the case "a dead
#                listener's marks must not block the host" (§6 E15). Fewer than KILL_MIN percent of the pairs
#                losing a launcher fails the phase ("PAIRS-KILLS-SHORT", exit 1): a kill that lands after both
#                launchers exited tests nothing
#   KILL_MIN     MODE=kill's least share of pairs, in percent, whose kill must land (default 50). The share is a
#                sample: at the low end of the 70-96 % landing rate seen on 6.17 (2026-10-19), 50 pairs miss 50 % once
#                in about 1,000 phases, 20 pairs once in 60 and 10 pairs once in 20: a short kill phase can fail by
#                chance (the binomial tail), so a kill phase is meant to run 50 pairs or more
#   PLANE        fanotify (default), lsm, fmod_ret or auto: the decision plane every run must report (auto: the one
#                the first run reports, which every later run must match)
#   EXPECT_PLANE with PLANE=auto, the mode the probe must select (empty: any)
#   CAPTURE      the contract's capture: (default uprobe)
#   AGENT_SLEEP  seconds the agent sleeps after its read of SECRET (default 1)
#   SECRET       the file each run's contract denies and its agent reads (default /var/lib/tego-pairs/secret)
#   TEGO        the launcher binary (default /usr/local/bin/tego, a tegobpf,tegotesthooks build)
#   TEGO_B      the second launcher of each pair (default TEGO)
#   COPY_B       1: the two launchers of a pair run from two inodes. Without TEGO_B, TEGO is copied to
#                COPY_B_PATH (default /usr/local/bin/tego-b, renamed in over a copy an earlier invocation's linger
#                timer may still execute) before any group exists; with it, TEGO_B must be
#                another inode than TEGO. "PAIRS-INODES a=<dev:ino> b=<dev:ino>" names both.
#   LISTENER     a third-party permission listener (test/vm/cmd/permlistener), started in allow-touch mode with
#                LISTENER_ARGS before the watchdog, waited for LISTENER_READY seconds (default 10) to print
#                PERMLISTENER-READY, and stopped with SIGTERM at the end: its stats line is kept as PAIRS-LISTENER.
#                LISTENER_ARGS, when unset, is "-deadline <3 x COLD_STALL>s": the listener lets an unanswered event through
#                at its deadline, and a freeze its decisions are part of must reach the watchdog first
#   SELF_DENY    1: before the pairs, one run whose contract denies reading TEGO's own file and whose agent opens
#                it for reading must be complete, judged as a pair's launcher is: exit 0 with that open refused (the
#                agent says so, and the ledger by the plane's mechanism) and the stage's exec neither decided nor
#                recorded (ADR 0021 (4)); "PAIRS-SELF-DENY ok". The file is reached by a hard link beside SECRET,
#                so it needs TEGO and SECRET on one filesystem (setup_self_link)
#   SETTLE       seconds a pair waits for its started runs' run_end before it is judged (default 10, less than
#                STALL): a killed launcher's reaper writes it once the run's cgroup is empty
#   PAIRS_DIR    the work directory, on the tmpfs (default /tmp/pairs): one per invocation in a guest
# Exit code: 0 when every pair passed, 1 when one did not, 2 when the setup or the first pair says the run could not
# prove what it claims (a usage error, the plane, COPY_B's inodes, the listener's start).
set -u
N=${PAIRS:-50}
STALL=${STALL:-20}
COLD_STALL=${COLD_STALL:-120}
MODE=${MODE:-plain}
PLANE=${PLANE:-fanotify}
EXPECT_PLANE=${EXPECT_PLANE:-}
COPY_B=${COPY_B:-0}
COPY_B_PATH=${COPY_B_PATH:-/usr/local/bin/tego-b}
LISTENER=${LISTENER:-}
LISTENER_READY=${LISTENER_READY:-10}
SELF_DENY=${SELF_DENY:-0}
KILL_MIN=${KILL_MIN:-50}
SETTLE=${SETTLE:-10}
SECRET=${SECRET:-/var/lib/tego-pairs/secret}
SELF_LINK=${SECRET%/*}/tego-self
TEGO=${TEGO:-/usr/local/bin/tego}
b_given=${TEGO_B:+1}
TEGO_B=${TEGO_B:-$TEGO}
w=${PAIRS_DIR:-/tmp/pairs}
lpid=""

usage() {
	echo "tier2-pairs.sh: $*" >&2
	exit 2
}
case $MODE in plain | timeout | kill) ;; *) usage "MODE must be plain, timeout or kill, not $MODE" ;; esac
case $EXPECT_PLANE in "" | fanotify | lsm | fmod_ret) ;; *) usage "EXPECT_PLANE must be fanotify, lsm or fmod_ret, not $EXPECT_PLANE" ;; esac
# want_plane is the decision_plane every run must report; empty under PLANE=auto until the first run names it.
case $PLANE in
fanotify | lsm | fmod_ret)
	[ -z "$EXPECT_PLANE" ] || usage "EXPECT_PLANE goes with PLANE=auto"
	want_plane=$PLANE
	;;
auto) want_plane=$EXPECT_PLANE ;;
*) usage "PLANE must be fanotify, lsm, fmod_ret or auto, not $PLANE" ;;
esac
case $COPY_B in 0 | 1) ;; *) usage "COPY_B must be 0 or 1, not $COPY_B" ;; esac
case $SELF_DENY in 0 | 1) ;; *) usage "SELF_DENY must be 0 or 1, not $SELF_DENY" ;; esac
case $N in '' | *[!0-9]*) usage "PAIRS must be a count, not $N" ;; esac
case $KILL_MIN in '' | *[!0-9]*) usage "KILL_MIN must be a percentage, not $KILL_MIN" ;; esac
[ "$KILL_MIN" -le 100 ] || usage "KILL_MIN must be a percentage, not $KILL_MIN"
case $STALL in '' | *[!0-9]*) usage "STALL must be a count of seconds, not $STALL" ;; esac
case $COLD_STALL in '' | *[!0-9]*) usage "COLD_STALL must be a count of seconds, not $COLD_STALL" ;; esac
case $SETTLE in '' | *[!0-9]*) usage "SETTLE must be a count of seconds, not $SETTLE" ;; esac
[ "$SETTLE" -lt "$STALL" ] || usage "SETTLE must be less than STALL ($STALL), not $SETTLE"
[ "$COLD_STALL" -ge "$STALL" ] || COLD_STALL=$STALL
LISTENER_ARGS=${LISTENER_ARGS--deadline $((COLD_STALL * 3))s}
export TEGO_TEST_PLANE=$PLANE
# A launcher the watchdog ends with SIGABRT prints every goroutine.
export GOTRACEBACK=all

# The kernel's own detectors, before any group exists. A fanotify permission wait is TASK_KILLABLE, which
# the hung-task detector skips, so the watchdog below is what names those; the detector names the truly
# uninterruptible waits (a group's release waiting on its pinned marks, a mutex) on its own.
echo 8 >/proc/sys/kernel/printk 2>/dev/null
echo 10 >/proc/sys/kernel/hung_task_timeout_secs 2>/dev/null
echo 0 >/proc/sys/kernel/hung_task_panic 2>/dev/null
echo -1 >/proc/sys/kernel/hung_task_warnings 2>/dev/null
echo 1 >/proc/sys/kernel/hung_task_all_cpu_backtrace 2>/dev/null
echo 1 >/proc/sys/kernel/softlockup_all_cpu_backtrace 2>/dev/null
echo 1 >/proc/sys/kernel/sysrq 2>/dev/null

mkdir -p "$w"/runs "$w"/out || exit 2
# The machine config refuses a relative $TEGO_CONFIG layer (identity-config R14), so the directory is made absolute.
w="$(cd "$w" && pwd)" || exit 2
# The secret sits on `/`, not on the tmpfs /tmp: a run's deny_read marks the mount it is on, and the original report's shape is
# a mark on the root mount every open and exec of the guest goes through. Readable by the agent's own uid, so only
# Tego refuses it; its directory is root's, so the write entry over it lets the agent write nothing there.
# Its content is what a launcher's output must never hold: the agent's cat writes there.
secret_text="PAIRS-SECRET-CONTENT do-not-print"
if ! { mkdir -p "${SECRET%/*}" && echo "$secret_text" >"$SECRET" && chmod 644 "$SECRET"; }; then
	usage "cannot write SECRET $SECRET"
fi
cat >"$w"/config.yaml <<EOF
version: 0
ledger_root: $w/runs
stop_grace: 3s
EOF
chmod 600 "$w"/config.yaml
# The agents redirect nothing to a file: with no fs.write entry, Landlock does not let them open /dev/null for
# writing. Each agent says on its stdout, the launcher's output, whether its read went through ("PAIRS-READ opened"
# or "refused"), and the pairs agent's cat writes the secret there if it did: judge reads both (read_effect). The
# self-deny agent opens TEGO's file for reading with its shell's own redirection (no bytes of the binary are written
# anywhere); its run exits 0 either way (the ledger and that line say which).
cat >"$w"/agent.yaml <<EOF
version: 0
name: pair
command: ["sh", "-c", "if cat $SECRET; then echo 'PAIRS-READ opened'; else echo 'PAIRS-READ refused'; fi; sleep ${AGENT_SLEEP:-1}"]
models:
  - { provider: anthropic, host: api.anthropic.com, port: 443 }
capture: ${CAPTURE:-uprobe}
fs:
  write: ["${SECRET%/*}/"]
  deny_read: ["$SECRET"]
exec:
  allow: ["sh", "cat", "sleep"]
EOF
cat >"$w"/self.yaml <<EOF
version: 0
name: self-deny
command: ["sh", "-c", "if true <$SELF_LINK; then echo 'PAIRS-READ opened'; else echo 'PAIRS-READ refused'; fi"]
models:
  - { provider: anthropic, host: api.anthropic.com, port: 443 }
capture: ${CAPTURE:-uprobe}
fs:
  write: ["${SELF_LINK%/*}/"]
  deny_read: ["$SELF_LINK"]
exec:
  allow: ["sh"]
EOF
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$w"
export TEGO_CONFIG="$w"/config.yaml TEGO_TEST_CHAIN_ANCHOR="$w"/chain.log
mkfifo "$w"/fifo
exec 9<>"$w"/fifo
nap() { read -r -t "$1" -u 9 _ 2>/dev/null; }
echo "0-init" >"$w"/hb

# pcat prints a file with builtins only.
pcat() {
	local line
	while IFS= read -r line; do echo "    $line"; done 2>/dev/null <"$1"
}

# stacks prints every user task's state, wait channel and kernel stack, and for each process holding a
# fanotify group, that group's marks (its fdinfo), which is what says whose marks an opener waits on.
stacks() {
	local p c t line st wc fd fan stat
	for p in /proc/[0-9]*; do
		c=""
		read -r c <"$p/comm" 2>/dev/null || continue
		# Kernel threads (PF_KTHREAD in the ninth field of stat) say nothing about this hunt.
		stat=""
		read -r stat <"$p/stat" 2>/dev/null || continue
		# shellcheck disable=SC2086 # the fields after the comm, one argument each
		set -- ${stat##*) }
		[ $# -ge 7 ] && (($7 & 0x200000)) && continue
		st=""
		while read -r line; do case "$line" in State:*) st=${line#State:}; break ;; esac; done 2>/dev/null <"$p/status"
		wc=""
		read -r wc <"$p/wchan" 2>/dev/null
		echo "--- ${p#/proc/} $c state:$st wchan:$wc"
		for t in "$p"/task/*; do
			st=""
			while read -r line; do case "$line" in State:*) st=${line#State:}; break ;; esac; done 2>/dev/null <"$t/status"
			echo "  task ${t##*/} $st"
			pcat "$t/stack"
		done
		for fd in "$p"/fdinfo/*; do
			fan=0
			while IFS= read -r line; do case "$line" in fanotify*) fan=1; break ;; esac; done 2>/dev/null <"$fd"
			[ "$fan" = 1 ] || continue
			echo "  fanotify group on fd ${fd##*/}:"
			pcat "$fd"
		done
	done
}

# launcher_names sets lnames to the comm of TEGO's and TEGO_B's processes: each file's name, cut to the kernel's
# 15 bytes (TASK_COMM_LEN). COPY_B's copy and the PIE are launchers too, under names of their own.
launcher_names() {
	local n a=${TEGO##*/} b=${TEGO_B##*/}
	lnames=" ${a:0:15} "
	n=${b:0:15}
	case $lnames in *" $n "*) ;; *) lnames+="$n " ;; esac
}

# launchers prints the pids of every process named as a launcher (lnames) whose parent is not one: the launchers,
# not a process a launcher started under one of those names. (A stage execs /proc/self/exe, so its comm is "exe".)
# Under MODE=timeout the pids $! gives are timeout's, which is why this reads the process table instead.
launchers() {
	local p c stat pc
	for p in /proc/[0-9]*; do
		c=""
		read -r c <"$p/comm" 2>/dev/null || continue
		case $lnames in *" $c "*) ;; *) continue ;; esac
		read -r stat <"$p/stat" 2>/dev/null || continue
		# shellcheck disable=SC2086 # the fields after the comm, one argument each
		set -- ${stat##*) }
		pc=""
		read -r pc <"/proc/$2/comm" 2>/dev/null
		case $lnames in *" $pc "*) ;; *) echo "${p#/proc/}" ;; esac
	done
}

# recovery waits up to 15 s for the pair loop, which execs on the marked root, to move again after what $1 names,
# and says whether it did. Moving means a heartbeat other than $2, the one the stall was seen at: the loop may have
# moved on already while the report was being written. It returns 1, with every task's stack, when it did not.
recovery() {
	local cur=$2 f n up
	for ((n = 0; n < 15; n++)); do
		nap 1
		read -r f <"$w"/hb
		[ "$f" != "$cur" ] && break
	done
	read -r up _ </proc/uptime
	if [ "$f" != "$cur" ]; then
		echo "=== WATCHDOG: RECOVERED ${n}s after $1 (heartbeat $cur -> $f, uptime $up) ==="
		return 0
	fi
	echo "=== WATCHDOG: NOT RECOVERED 15s after $1 (uptime $up); task stacks follow ==="
	stacks
	echo t >/proc/sysrq-trigger
	return 1
}

# report is the stall report for pair $1, which has not moved for $2 seconds from heartbeat $3.
report() {
	local up="" pid f
	# The pair loop must not end the run, or print PAIRS-DONE, while the report is still being written.
	echo "$1" >"$w"/stalled
	read -r up _ </proc/uptime
	echo "=== WATCHDOG: pair $1 made no progress for ${2}s (uptime $up); task stacks follow ==="
	stacks
	echo w >/proc/sysrq-trigger
	echo l >/proc/sysrq-trigger
	# The pair's ledgers as they stand (on the tmpfs, read with builtins): how far each run got.
	for f in "$w"/runs/*/events.jsonl; do
		[ -f "$f" ] || continue
		echo "--- $f"
		pcat "$f"
	done
	# SIGABRT, not SIGQUIT: tego run forwards SIGQUIT to its agent (launch.HandledSignals) and lives on, while
	# SIGABRT is the Go runtime's own, which prints every goroutine (GOTRACEBACK=all) and ends the launcher.
	echo "=== WATCHDOG: SIGABRT to the launchers ($(launchers)) for their goroutines ==="
	for pid in $(launchers); do kill -ABRT "$pid" 2>/dev/null; done
	nap 5
	for f in "$w"/out/a.$1 "$w"/out/b.$1; do
		echo "--- $f"
		pcat "$f"
	done
	# A dead listener's marks must not block the host (§6 E15): SIGKILL every launcher still alive and see
	# whether the pair loop, which execs on the marked root, moves again. If it does not, the third party's
	# group, the same way, so a report says whose group held.
	# SIGABRT ends a Go launcher too, so the pair loop may have moved on already: the report says so as it is.
	read -r f <"$w"/hb
	read -r up _ </proc/uptime
	if [ "$f" != "$3" ]; then
		echo "=== WATCHDOG: RECOVERED after SIGABRT to the launchers (heartbeat $3 -> $f, uptime $up) ==="
	else
		echo "=== WATCHDOG: SIGKILL to the launchers ($(launchers)) ==="
		for pid in $(launchers); do kill -KILL "$pid" 2>/dev/null; done
		if recovery "SIGKILL to the launchers" "$3"; then
			[ -z "$lpid" ] || echo "=== WATCHDOG: the third-party listener ($lpid) was left running: Tego's group held ==="
		elif [ -n "$lpid" ] && kill -0 "$lpid" 2>/dev/null; then
			echo "=== WATCHDOG: SIGKILL to the third-party listener ($lpid) ==="
			kill -KILL "$lpid" 2>/dev/null
			recovery "SIGKILL to the third-party listener" "$3"
		fi
	fi
	echo "=== WATCHDOG: end of report; powering off ==="
	nap 2
	echo o >/proc/sysrq-trigger
}

# setup_copy_b gives COPY_B's second launcher an inode of its own, before any group exists: a copy of TEGO at
# COPY_B_PATH when TEGO_B was not given, else TEGO_B as given. Two names for one inode (TEGO_B equal to TEGO,
# or a hard link of it) would not be the condition ADR 0021 names, so that is refused (2).
setup_copy_b() {
	local a b
	[ "$COPY_B" = 1 ] || return 0
	if [ -z "$b_given" ]; then
		# By rename, not by writing over it: a phase before this one leaves its build's linger timer (ADR 0022)
		# executing COPY_B_PATH, and opening a busy executable for writing is ETXTBSY. The timer keeps its inode.
		if ! { cp -- "$TEGO" "$COPY_B_PATH.new" && chmod 755 "$COPY_B_PATH.new" &&
			mv -f -- "$COPY_B_PATH.new" "$COPY_B_PATH"; }; then
			echo "PAIRS-SETUP-FAIL what=copy_b-copy path=$COPY_B_PATH" >&2
			rm -f -- "$COPY_B_PATH.new"
			return 2
		fi
		TEGO_B=$COPY_B_PATH
	fi
	if ! { a=$(stat -L -c '%d:%i' -- "$TEGO") && b=$(stat -L -c '%d:%i' -- "$TEGO_B"); }; then
		echo "PAIRS-SETUP-FAIL what=copy_b-stat" >&2
		return 2
	fi
	echo "PAIRS-INODES a=$a b=$b"
	if [ "$a" = "$b" ]; then
		echo "PAIRS-SETUP-FAIL what=copy_b-same-inode a=$TEGO b=$TEGO_B inode=$a" >&2
		return 2
	fi
}

# setup_self_link gives SELF_DENY's run TEGO's file under a second name, SELF_LINK, before any group exists. The
# deny_read must be nested in a write entry, or Landlock's EACCES comes first and the plane decides nothing, and
# agent-contract R10 refuses a write entry at or over the file tego runs from: only another name of that inode can be
# both. A copy would be a file the launcher does not run from. A leftover link goes first: an earlier phase made it,
# and ln will not link a file onto itself. Across filesystems ln fails, and the setup with it (2).
setup_self_link() {
	[ "$SELF_DENY" = 1 ] || return 0
	if ! { rm -f -- "$SELF_LINK" && ln -- "$TEGO" "$SELF_LINK"; }; then
		echo "PAIRS-SETUP-FAIL what=self-link a=$TEGO link=$SELF_LINK" >&2
		return 2
	fi
}

# start_listener starts the third-party permission listener (LISTENER, test/vm/cmd/permlistener in allow-touch
# mode) before the watchdog and every run, and waits up to LISTENER_READY seconds for it to say its marks are
# placed. Its stdout is a fifo this shell holds open at both ends on fd 8, so the listener never blocks writing to
# it and its last line is still there to read at the stop. A listener that never says ready is killed (2).
start_listener() {
	local line
	[ -n "$LISTENER" ] || return 0
	mkfifo "$w/listener.fifo" || return 2
	exec 8<>"$w/listener.fifo"
	# shellcheck disable=SC2086 # LISTENER_ARGS is a list of flags
	"$LISTENER" -mode allow-touch $LISTENER_ARGS >&8 2>"$w/listener.err" 8>&- 9>&- &
	lpid=$!
	while read -r -t "$LISTENER_READY" -u 8 line; do
		if [ "$line" = PERMLISTENER-READY ]; then
			echo "PAIRS-LISTENER-READY pid=$lpid"
			return 0
		fi
	done
	echo "PAIRS-LISTENER-FAIL what=ready-timeout seconds=$LISTENER_READY" >&2
	pcat "$w/listener.err" >&2
	kill -KILL "$lpid" 2>/dev/null
	wait "$lpid" 2>/dev/null
	lpid=""
	return 2
}

# stop_listener stops the listener with SIGTERM: it removes its marks, answers what it still holds and prints its
# stats, kept as "PAIRS-LISTENER rc=<rc> PERMLISTENER-STATS ...". A listener that died before the stop, printed no
# stats or exited non-zero fails the run (1): the third party was not there for all of it.
stop_listener() {
	local line stats="" rc
	[ -n "$lpid" ] || return 0
	if ! kill -0 "$lpid" 2>/dev/null; then
		wait "$lpid" 2>/dev/null
		rc=$?
		lpid=""
		echo "PAIRS-LISTENER-FAIL what=died rc=$rc" >&2
		pcat "$w/listener.err" >&2
		return 1
	fi
	kill -TERM "$lpid" 2>/dev/null
	while read -r -t 15 -u 8 line; do
		case $line in PERMLISTENER-STATS*) stats=$line; break ;; esac
	done
	wait "$lpid"
	rc=$?
	lpid=""
	if [ -z "$stats" ] || [ "$rc" != 0 ]; then
		echo "PAIRS-LISTENER-FAIL what=exit rc=$rc ${stats:-no stats line}" >&2
		pcat "$w/listener.err" >&2
		return 1
	fi
	echo "PAIRS-LISTENER rc=$rc $stats"
}

setup_copy_b || exit $?
setup_self_link || exit $?
launcher_names
start_listener || exit $?

# watch is the watchdog: it reports once the heartbeat has not moved for STALL seconds, or COLD_STALL while the
# invocation's first run is under way (0-self, 1-start), which pays the boot's cold plane probe, and returns.
watch() {
	local last="" since=$SECONDS cur limit
	while :; do
		nap 2
		read -r cur <"$w"/hb
		[ "$cur" = "done" ] && return 0
		if [ "$cur" != "$last" ]; then
			last=$cur since=$SECONDS
			continue
		fi
		limit=$STALL
		case $cur in 0-self | 1-start) limit=$COLD_STALL ;; esac
		if [ $((SECONDS - since)) -ge "$limit" ]; then
			report "${cur%%-*}" $((SECONDS - since)) "$cur"
			return 0
		fi
	done
}

watch &
wd=$!

# launch starts launcher $1 (a or b) of pair $i from the binary $2, its output in out/$1.$i. Its pid is what ties its
# run to it (run_start's launcher_pid): $! for a plain launch. Under MODE=timeout $! is timeout's, so a shell between
# timeout and the launcher writes its own pid to pid.$1 and execs the launcher, which keeps that pid (timeout stays
# its parent, as in the original report).
launch() {
	case "$MODE" in
	timeout)
		: >"$w/pid.$1"
		# shellcheck disable=SC2016 # the inner shell expands $$, $1 and $2: its own pid and arguments
		timeout -s QUIT -k 5 40 /bin/sh -c 'echo "$$" >"$1" && exec "$2" run agent.yaml --tier cgroup --offline' \
			sh "$w/pid.$1" "$2" >"$w/out/$1.$i" 2>&1 &
		;;
	*) "$2" run agent.yaml --tier cgroup --offline >"$w/out/$1.$i" 2>&1 & ;;
	esac
}

# by_mechanism says whether the refused line $1 is the refusal of the plane every run must report: the listener's
# (source fanotify) on the fallback, the plane's (mechanism plane, the mode as its decision_plane) in a plane mode
# (pkg/spec/record/payload.go). A line from Landlock, the supervisor or another listener is none of them. Under
# PLANE=auto before the first run named the mode, the plane is the one this run's run_start reports, which
# assert_pair then holds every later run to.
by_mechanism() {
	local plane=${want_plane:-$f_plane}
	case $plane in
	fanotify)
		case $1 in *'"source":"fanotify"'*) return 0 ;; esac
		return 1
		;;
	esac
	case $1 in *'"mechanism":"plane"'*) ;; *) return 1 ;; esac
	[ -n "$plane" ] || return 1
	case $1 in *"\"decision_plane\":\"$plane\""*) return 0 ;; esac
	return 1
}

# ledger_facts reads one run's events.jsonl ($1, none when empty) with builtins and sets f_start (1 when run_start is
# there), f_plane (its decision_plane), f_lpid (its launcher_pid), f_end (1 when run_end is), f_reason (run_end's
# reason), f_refused (the refused fs lines that name $2), f_by (those by_mechanism admits), f_other (the fs lines that
# name $2 with any other verdict: a mechanism that let the read through or only saw it) and f_stage (exec lines for
# TEGO, TEGO_B or /proc/self/exe). A line is one event in canonical form (record-ledger R1): base fields first,
# then the payload's, so run_end's last "reason" is its payload's.
ledger_facts() {
	local line p
	f_start=0 f_plane="" f_lpid="" f_end=0 f_reason="" f_refused=0 f_by=0 f_other=0 f_stage=0
	[ -f "$1" ] || return 0
	while IFS= read -r line || [ -n "$line" ]; do
		case $line in
		*'"kind":"run_start"'*)
			f_start=1
			case $line in *'"launcher_pid":'*)
				p=${line#*\"launcher_pid\":}
				f_lpid=${p%%[!0-9]*}
				;;
			esac
			case $line in *'"decision_plane":"'*)
				p=${line#*\"decision_plane\":\"}
				f_plane=${p%%\"*}
				;;
			esac
			;;
		*'"kind":"run_end"'*)
			f_end=1
			case $line in *'"reason":"'*)
				p=${line##*\"reason\":\"}
				f_reason=${p%%\"*}
				;;
			esac
			;;
		*'"kind":"fs"'*)
			case $line in *"\"path\":\"$2\""*) ;; *) continue ;; esac
			case $line in
			*'"verdict":"refused"'*)
				f_refused=$((f_refused + 1))
				if by_mechanism "$line"; then f_by=$((f_by + 1)); fi
				;;
			*) f_other=$((f_other + 1)) ;;
			esac
			;;
		*'"kind":"exec"'*)
			case $line in
			*"\"path\":\"$TEGO\""* | *"\"path\":\"$TEGO_B\""* | *'"path":"/proc/self/exe"'*) f_stage=$((f_stage + 1)) ;;
			esac
			;;
		esac
	done <"$1"
}

# read_effect reads a launcher's output ($1) with builtins and sets f_read to what its agent's read did: "opened" when
# it went through (the secret's content is there, or the agent's own "PAIRS-READ opened"), else "refused" when the
# agent says its read failed ("PAIRS-READ refused"), else "none": the agent never ran its read, or was killed before
# it could say.
read_effect() {
	local line
	f_read=none
	while IFS= read -r line || [ -n "$line" ]; do
		case $line in
		*"$secret_text"* | 'PAIRS-READ opened') f_read=opened && return 0 ;;
		'PAIRS-READ refused') f_read=refused ;;
		esac
	done 2>/dev/null <"$1"
}

# settle waits, at most SETTLE seconds, until every started run in runs/ has its run_end. A launcher's wait returns
# before its run is final when the launcher died: the run's reaper then kills the run's cgroup, waits for it to empty
# and only then appends run_end reason=orphaned (ADR 0020 (3)). After that line the run's ledger is whole and no
# process of the run writes to its launcher's output any more, so what judge reads of either is final. A run still
# open at the bound is judged as it stands.
settle() {
	local path=$1 deadline=$((SECONDS + SETTLE)) d open
	while :; do
		open=0
		for d in "$w"/runs/*; do
			[ -d "$d" ] && [ ! -L "$d" ] || continue
			ledger_facts "$d/events.jsonl" "$path"
			if [ "$f_start" = 1 ] && [ "$f_end" = 0 ]; then
				open=1
				break
			fi
		done
		[ "$open" = 1 ] && [ "$SECONDS" -lt "$deadline" ] || return 0
		nap 0.1
	done
}

# judge gives one launcher of a pair its verdict from all of its evidence at once: whether kill mode's SIGKILL
# targeted it, its exit status, its own run (by run_start's launcher_pid) and its output (ADR 0021's 2026-10-19
# 2026-10-19 note holds the same table). $1 the pair, $2 the denied path, $3 the launcher's name, $4 its exit
# status, $5 its started run ("" for none), $6 its output. assert_pair has already held every started run to the
# plane, to at most one refusal of the path and that by the plane's mechanism, to no other verdict on the path and
# to no exec of the stage. It sets verdict to one of
#   complete       it exited 0: its run started, refused the path once, and ended with its agent's exit (run_end
#                  reason exit); its agent says its read was refused;
#   killed-early   kill mode's target, exited 137 with no run started; its agent never ran (run_start is written
#                  before the agent is let go, internal/runtime/run.go), so its output says no read;
#   killed-in-run  kill mode's target, exited 137 with its run started, and that run closed: by the launcher before
#                  the kill landed (reason exit), when it must be as whole as a complete one's, or by its reaper
#                  (reason orphaned); its agent's read went nowhere;
#   killed-read    as killed-in-run, but its agent's read went through: E15's window (enforce-cgroup-observe §6 E15,
#                  ADR 0020), which only the fallback has (a plane outlives its launcher), only a read the run never
#                  refused can be (the listener records a refusal after its FAN_DENY), and only in a run its reaper
#                  closed (reason orphaned: the launcher died with the run open);
#   failed         it exited any other way, a 137 of a launcher the kill did not target included (tego's own exit
#                  when its agent was cgroup-killed, pkg/spec/identity/exit.go), and its agent's read went nowhere:
#                  the pair fails;
# or prints PAIRS-ASSERT-FAIL with the evidence it judged and returns 1. No other combination passes.
judge() {
	local t=$3 r=$4 id=$5 tgt=0 whole=0 what=""
	verdict=""
	[ "$MODE" != kill ] || [ "$t" != "${kt:-}" ] || tgt=1
	read_effect "$6"
	ledger_facts "${id:+$w/runs/$id/events.jsonl}" "$2"
	# A run its launcher closed (reason exit) is whole whether or not the kill landed after that.
	[ "$r" != 0 ] || whole=1
	if [ "$tgt" = 1 ] && [ "$r" = 137 ] && [ "$f_end" = 1 ] && [ "$f_reason" = exit ]; then whole=1; fi
	if [ "$whole" = 1 ]; then
		if [ -z "$id" ]; then
			what=no-run
		elif [ "$f_refused" != 1 ]; then
			what=refusal
		elif [ "$f_end" != 1 ]; then
			what=run_end
		elif [ "$f_reason" != exit ]; then
			what=run_end-reason
		elif [ "$f_read" = opened ]; then
			what=secret-read
		elif [ "$f_read" != refused ]; then
			what=read-unseen
		elif [ "$r" = 0 ]; then
			verdict=complete
		else
			verdict=killed-in-run
		fi
	elif [ "$tgt" = 1 ] && [ "$r" = 137 ]; then
		if [ -z "$id" ]; then
			if [ "$f_read" = none ]; then verdict=killed-early; else what=read-without-run; fi
		elif [ "$f_end" != 1 ]; then
			what=run_end
		elif [ "$f_reason" != orphaned ]; then
			what=run_end-reason
		elif [ "$f_read" != opened ]; then
			verdict=killed-in-run
		elif [ "$want_plane" != fanotify ]; then
			what=secret-read
		elif [ "$f_refused" != 0 ]; then
			what=secret-read-after-refusal
		else
			verdict=killed-read
		fi
	elif [ "$f_read" = opened ]; then
		what=secret-read
	else
		verdict=failed
	fi
	[ -n "$what" ] || return 0
	echo "PAIRS-ASSERT-FAIL pair=$1 what=$what launcher=$t rc=$r target=$tgt run=${id:-none} read=$f_read" \
		"refused=$f_refused end=${f_reason:-none} plane=${want_plane:-none} out=$6" >&2
	pcat "$6" >&2
	return 1
}

# assert_pair judges pair $1 from its ledgers and its launchers' outputs before cleanup removes them. $2 is the path
# every run's contract denies; then four arguments per launcher: its name (a, b, self), its pid, its exit status and
# its output file. Once the pair has settled (settle):
#   - every started run (one with run_start) reports the plane (under PLANE=auto with no EXPECT_PLANE, the first
#     run's mode becomes the one every later run must report), refused the path at most once and only by the plane's
#     mechanism, holds no other verdict on the path and no exec line of the stage (ADR 0021 (2)), and is the run of
#     exactly one launcher of the pair by its launcher_pid;
#   - every launcher is judged (judge);
#   - a run directory with no run_start is what a launcher that died before writing one leaves: there are no more of
#     them than launchers that exited non-zero with no started run.
# It sets outcome[k] to launcher k's verdict and pair_ok to 0 when one of them is failed, else 1. It prints
# PAIRS-ASSERT-FAIL and returns 1, or 2 for the plane on the first pair (or the self-deny run, pair 0): that is the
# binary or the host.
assert_pair() {
	local pair=$1 path=$2 n=0 k owner unstarted=0 spare=0 d id what line
	local -a tag=() pid=() rc=() out=() run_of=()
	shift 2
	while [ $# -ge 4 ]; do
		tag[n]=$1 pid[n]=$2 rc[n]=$3 out[n]=$4 run_of[n]=""
		n=$((n + 1))
		shift 4
	done
	outcome=()
	pair_ok=1
	settle "$path"
	for d in "$w"/runs/*; do
		[ -d "$d" ] && [ ! -L "$d" ] || continue
		id=${d##*/}
		ledger_facts "$d/events.jsonl" "$path"
		if [ "$f_start" != 1 ]; then
			unstarted=$((unstarted + 1))
			continue
		fi
		if [ -z "$want_plane" ]; then
			case $f_plane in fanotify | lsm | fmod_ret)
				want_plane=$f_plane
				echo "PAIRS-PLANE $want_plane (from the first run, PLANE=auto)"
				;;
			esac
		fi
		if [ -z "$want_plane" ] || [ "$f_plane" != "$want_plane" ]; then
			echo "PAIRS-ASSERT-FAIL pair=$pair what=decision_plane want=${want_plane:-auto} got=${f_plane:-none} run=$id" >&2
			[ "$pair" -gt 1 ] || return 2
			return 1
		fi
		what=""
		if [ "$f_refused" -gt 1 ]; then
			what="refusals=$f_refused"
		elif [ "$f_by" != "$f_refused" ]; then
			what=refusal-mechanism
		elif [ "$f_other" != 0 ]; then
			what="unrefused-lines=$f_other"
		elif [ "$f_stage" != 0 ]; then
			what="stage-exec-recorded lines=$f_stage"
		fi
		if [ -n "$what" ]; then
			# The lines judged, for the reader: the ones that name the path, and the exec lines.
			echo "PAIRS-ASSERT-FAIL pair=$pair what=$what path=$path run=$id" >&2
			while IFS= read -r line; do
				case $line in *"\"path\":\"$path\""* | *'"kind":"exec"'*) echo "    $line" ;; esac
			done 2>/dev/null <"$d/events.jsonl" >&2
			return 1
		fi
		owner=""
		for ((k = 0; k < n; k++)); do
			[ -z "$f_lpid" ] || [ "${pid[k]}" != "$f_lpid" ] || owner=$k
		done
		if [ -z "$owner" ]; then
			echo "PAIRS-ASSERT-FAIL pair=$pair what=foreign-run launcher_pid=${f_lpid:-none} run=$id" >&2
			return 1
		fi
		if [ -n "${run_of[owner]}" ]; then
			echo "PAIRS-ASSERT-FAIL pair=$pair what=two-runs launcher=${tag[owner]} runs=${run_of[owner]},$id" >&2
			return 1
		fi
		run_of[owner]=$id
	done
	for ((k = 0; k < n; k++)); do
		judge "$pair" "$path" "${tag[k]}" "${rc[k]}" "${run_of[k]}" "${out[k]}" || return 1
		outcome[k]=$verdict
		[ "$verdict" != failed ] || pair_ok=0
		[ -n "${run_of[k]}" ] || [ "${rc[k]}" = 0 ] || spare=$((spare + 1))
	done
	if [ "$unstarted" -gt "$spare" ]; then
		echo "PAIRS-ASSERT-FAIL pair=$pair what=unstarted-runs runs=$unstarted launchers=$spare path=$path" >&2
		return 1
	fi
}

# abort ends the script with $1 and no PAIRS-DONE, keeping the pair's ledgers. After a stall report it waits for
# the watchdog, which powers the guest off: the report is the result. It moves the heartbeat only once an exec on
# the marked root went through, which is what the report's recovery check waits for.
abort() {
	if [ -e "$w/stalled" ]; then
		/bin/sh -c : && echo "abort" >"$w"/hb
		wait "$wd"
	fi
	stop_listener
	echo "done" >"$w"/hb
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null || :
	exit "$1"
}

# self_deny is ADR 0021 (4) for the binary the pairs run, a dynamically linked one included: one run of a contract
# that denies reading TEGO's file under SELF_LINK, whose agent opens it for reading, judged as one launcher of a pair
# is. It must be complete: the run exits 0, the open is refused by the plane's mechanism with one line and the agent
# saw it refused ("PAIRS-READ refused"), and no exec line names the stage, which exec'd TEGO before the run armed
# (ADR 0021 (2)).
self_deny() {
	local rc st sp
	echo "0-self" >"$w"/hb
	"$TEGO" run self.yaml --tier cgroup --offline >"$w"/out/self 2>&1 &
	sp=$!
	wait "$sp"
	rc=$?
	assert_pair 0 "$SELF_LINK" self "$sp" "$rc" "$w"/out/self
	st=$?
	if [ "$st" = 0 ] && [ "${outcome[0]}" != complete ]; then
		echo "PAIRS-ASSERT-FAIL pair=0 what=self-deny-exit rc=$rc" >&2
		st=1
	fi
	if [ "$st" != 0 ]; then
		pcat "$w"/out/self >&2
		return "$st"
	fi
	cleanup_pair 0 || return 1
	echo "PAIRS-SELF-DENY ok path=$SELF_LINK plane=$want_plane"
}

# kill_draw draws MODE=kill's kill point for a pair: kd, the delay after the second launch, uniform in [0, $1) ms
# ($1 the previous pair's length in ms; anything below 1 or not a number counts as 1) and written as seconds with
# three decimals for nap; and kt, the launcher the SIGKILL targets (a or b).
kill_draw() {
	local span=$1 ms
	[[ $span =~ ^[0-9]+$ ]] && [ "$span" -ge 1 ] || span=1
	ms=$(((RANDOM * 32768 + RANDOM) % span))
	printf -v kd '%d.%03d' $((ms / 1000)) $((ms % 1000))
	kt=a
	((RANDOM % 2)) || kt=b
}

# The launcher can exit before its reaper opens the held run directory (OpenAt creates lock/blobs
# before it reads run_end). Do not count cleanup as progress while that late creation defeats rm.
# Only rm's exact ENOTEMPTY for a selected run directory is retried: every other error, an empty
# diagnostic, or a successful rm that leaves a target is a failure. The watchdog still covers an
# external rm stuck opening/executing on the marked root. The retry budget is 5 integer SECONDS /
# 50 attempts for starting retries, excluding a blocked external rm, which remains under the original
# STALL watchdog. A command that started within that window still must succeed and leave no targets.
cleanup_pair() {
	local pair=$1 attempt=0 deadline=$((SECONDS + 5)) status path line matched retry
	local err="$w/cleanup.err"
	local -a runs=() targets=()
	while :; do
		if [ "$attempt" -gt 0 ] && [ "$SECONDS" -ge "$deadline" ]; then
			echo "PAIR-CLEANUP $pair attempt=$attempt status=failed reason=retry-bound rm_status=$status" >&2
			pcat "$err" >&2
			return 1
		fi
		runs=()
		for path in "$w"/runs/*; do
			[ -e "$path" ] || [ -L "$path" ] || continue
			runs+=("$path")
		done
		targets=("${runs[@]}" "$w/out/a.$((pair - 1))" "$w/out/b.$((pair - 1))")
		attempt=$((attempt + 1))
		LC_ALL=C command rm -rf -- "${targets[@]}" 2>"$err"
		status=$?
		if [ "$status" = 0 ]; then
			if [ -s "$err" ]; then
				echo "PAIR-CLEANUP $pair attempt=$attempt status=failed reason=rm rm_status=0" >&2
				pcat "$err" >&2
				return 1
			fi
			# Check the selected scope again, including newly created nonhidden entries. The ledger's
			# intentional .live index and the current pair's watchdog outputs stay in place.
			for path in "$w"/runs/* "${targets[@]}"; do
				if [ -e "$path" ] || [ -L "$path" ]; then
					echo "PAIR-CLEANUP $pair attempt=$attempt status=failed reason=retained" >&2
					echo "rm returned 0 but retained $path" >&2
					return 1
				fi
			done
			echo "PAIR-CLEANUP $pair attempts=$attempt status=removed"
			return 0
		fi
		retry=1
		[ "$status" = 1 ] && [ -s "$err" ] || retry=0
		while IFS= read -r line || [ -n "$line" ]; do
			matched=0
			for path in "${runs[@]}"; do
				if [ "$line" = "rm: cannot remove '$path': Directory not empty" ] &&
					[ -d "$path" ] && [ ! -L "$path" ]; then
					matched=1
					break
				fi
			done
			[ "$matched" = 1 ] || retry=0
		done <"$err"
		if [ "$retry" != 1 ]; then
			echo "PAIR-CLEANUP $pair attempt=$attempt status=failed reason=rm rm_status=$status" >&2
			pcat "$err" >&2
			return 1
		fi
		if [ "$attempt" -ge 50 ] || [ "$SECONDS" -ge "$deadline" ]; then
			echo "PAIR-CLEANUP $pair attempt=$attempt status=failed reason=retry-bound rm_status=$status" >&2
			pcat "$err" >&2
			return 1
		fi
		# Keep recovered failures visible in the captured console as well as the final failure.
		echo "PAIR-CLEANUP $pair attempt=$attempt status=retry reason=enotempty rm_status=$status" >&2
		pcat "$err" >&2
		nap 0.1
	done
}

cd "$w" || exit 1
if [ "$SELF_DENY" = 1 ]; then
	self_deny || abort $?
fi

ok=0
kills=0
kills_started=0
# killed_reads counts the pairs whose killed launcher's agent read SECRET in E15's window on the fallback (judge's
# killed-read).
killed_reads=0
# span_ms is the length of the previous pair, from its first launch to its last wait (EPOCHREALTIME, a builtin):
# kill mode draws its kill point from it. The first pair, cold and so longer, draws from 900 ms.
span_ms=900
# kt names the launcher kill mode's SIGKILL targets in the current pair (kill_draw); none outside kill mode.
kt=""
listening=0
[ -z "$LISTENER" ] || listening=1
for ((i = 1; i <= N; i++)); do
	[ ! -e "$w/stalled" ] || abort 1
	echo "$i-start" >"$w"/hb
	t0=${EPOCHREALTIME/[.,]/}
	launch a "$TEGO"
	pa=$!
	nap "0.0$((RANDOM % 3))"
	launch b "$TEGO_B"
	pb=$!
	if [ "$MODE" = kill ]; then
		kill_draw "$span_ms"
		nap "$kd"
		kp=$pa
		[ "$kt" = a ] || kp=$pb
		kill -KILL "$kp" 2>/dev/null
	fi
	wait "$pa"
	ra=$?
	wait "$pb"
	rb=$?
	t1=${EPOCHREALTIME/[.,]/}
	span_ms=$(((t1 - t0) / 1000))
	echo "PAIR $i rc=$ra,$rb${kt:+ kill=$kt}"
	# What the pair ran, on which plane, refusing what: judged from its ledgers and outputs before cleanup removes
	# them (assert_pair). A pair that fails the judgement fails like a cleanup failure, and its ledgers stay for the
	# reader. Under MODE=timeout the launchers' pids are the ones they wrote (launch), $! being timeout's.
	if [ "$MODE" = timeout ]; then
		pa="" pb=""
		read -r pa <"$w"/pid.a
		read -r pb <"$w"/pid.b
	fi
	assert_pair "$i" "$SECRET" a "$pa" "$ra" "$w"/out/a.$i b "$pb" "$rb" "$w"/out/b.$i
	st=$?
	[ "$st" = 0 ] || abort "$st"
	# The pair's verdict and its kill are the launchers' verdicts (judge): a failed launcher fails the pair, and the
	# kill landed when its target's verdict is a killed one (it hit a run when that run had started).
	if [ "$MODE" = kill ]; then
		kk=0
		[ "$kt" = a ] || kk=1
		case ${outcome[kk]} in killed-*) kills=$((kills + 1)) ;; esac
		case ${outcome[kk]} in killed-in-run | killed-read) kills_started=$((kills_started + 1)) ;; esac
		if [ "${outcome[kk]}" = killed-read ]; then
			killed_reads=$((killed_reads + 1))
			echo "PAIRS-KILLED-READ pair=$i launcher=$kt plane=$want_plane"
		fi
	fi
	# A pair counts as progress only once an exec on the marked root has gone through after it: a mark its
	# listener no longer answers shows up here, in the host's own execve, not in the launchers.
	if ! cleanup_pair "$i"; then
		# A cleanup error must not produce i-waited or PAIRS-DONE, even when both launchers exited 0.
		echo "PAIRS-CLEANUP-FAIL pair=$i" >&2
		abort 1
	fi
	echo "$i-waited" >"$w"/hb
	[ "$pair_ok" = 0 ] || ok=$((ok + 1))
done
[ ! -e "$w/stalled" ] || abort 1
# Under the watchdog still: a listener that does not stop is a stall like any other.
listener_rc=0
stop_listener || listener_rc=1
echo "done" >"$w"/hb
kill "$wd" 2>/dev/null
[ "$listener_rc" = 0 ] || exit 1
echo "PAIRS-DONE $ok/$N plane=${want_plane:-none} copy_b=$COPY_B listener=$listening mode=$MODE kills=$kills kills_started=$kills_started killed_reads=$killed_reads"
kills_ok=1
if [ "$MODE" = kill ] && [ $((kills * 100)) -lt $((N * KILL_MIN)) ]; then
	echo "PAIRS-KILLS-SHORT landed=$kills want=$(((N * KILL_MIN + 99) / 100)) pairs=$N kill_min=$KILL_MIN" >&2
	kills_ok=0
fi
[ "$ok" -eq "$N" ] && [ "$kills_ok" = 1 ]
