#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests ssh-suite.sh against stand-ins, with no guest: the "guest" is a directory on this host; the SSH wrapper runs its
# argument with sh in a session of its own and then sends that session SIGHUP, as sshd's end of a session does; marker
# files make it fail as a dropped connection does (exit 255), hang while ignoring SIGTERM, lose its answer after it ran,
# drop the payload of its answer, or find a cksum that disagrees; and qemu is a sleep this test kills. Every fault is
# synchronized with startup or held commands and acknowledged failed calls. Bounded waits observe those events;
# command release files keep a delayed host from injecting a fault after completion. What is held:
#   - output and exit code come back whole (98 too, as "guest 98": the status word, not the number, tells a command's
#     98 from a lost guest), and connections dropped mid-run, or the start's answer lost after it ran, end nothing;
#   - completion requires PID 1's retained normal wait status for the pinned service invocation to match the
#     supervisor's result. The real-nonce forgery plus supervisor death is refused. Root can still compromise
#     the guest's manager or SSH; these stand-ins do not prove a privilege boundary;
#   - a setup write that does not read back whole starts nothing; a name of . or .. and a directory with a quote in it
#     cannot run anything but the command;
#   - a qemu that ended, a guest silent past --unreachable (an SSH call that ignores SIGTERM included, which
#     --call-timeout ends with SIGKILL), a supervisor gone without its result, a reboot, and a pid now another process's
#     are each GUEST-LOST and exit 98;
#   - past --timeout it is 124 and the command's whole process group has ended, descendants ignoring SIGTERM included;
#   - a completed run whose log makes no progress ends in bounded time;
#   - a run still going when this script ends (a lost guest leaves its command alive) is gone, with its stand-in service
#     manager, before the scratch folder is removed: nothing is writing into it while it is removed.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-ssh-suite-test.XXXXXX")
qemu=""
# shellcheck disable=SC2329 # the EXIT trap calls it
cleanup() {
	[ -z "$qemu" ] || kill "$qemu" 2>/dev/null || true
	# The service-manager stand-in is a daemon of its own: it waits on the supervisor and, when that ends, writes the
	# end state into manager/. Ending the supervisor wakes it, so it is ended first (each stand-in names itself in
	# standin/ and is only taken for one while its command line is still the stand-in's), and waited for last.
	standins=""
	for f in "$tmp"/standin/*; do
		[ -e "$f" ] || continue
		p=${f##*/}
		[ -r "/proc/$p/cmdline" ] || continue
		case $(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null || true) in
		*"$tmp/bin/systemd-run"*)
			kill -s KILL "$p" 2>/dev/null || true
			standins="$standins $p"
			;;
		esac
	done
	for f in "$tmp"/guest*/*/child "$tmp"/guest*/*/sup; do
		[ -f "$f" ] || continue
		read -r a b _ <"$f" || continue
		case "$f" in */child) p=$a ;; *) p=$b ;; esac
		kill -s KILL -- "-$p" 2>/dev/null || kill -s KILL "$p" 2>/dev/null || true
	done
	# A killed process is gone once the kernel has reaped it; the bound only keeps a stuck one from hanging the script.
	for p in $standins; do
		i=0
		while [ -e "/proc/$p" ] && [ "$i" -lt 200 ]; do
			i=$((i + 1))
			sleep 0.05
		done
	done
	rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
fail() {
	echo "FAIL $*" >&2
	exit 1
}

mkdir "$tmp/bin" "$tmp/badsum" "$tmp/guest" "$tmp/manager" "$tmp/standin"
# The service-manager stand-in waits on the real supervisor child. Its retained status lives
# outside the simulated guest state. This exercises the protocol, not a host privilege boundary.
cat >"$tmp/bin/id" <<EOF
#!/bin/sh
if [ "\$*" = -u ]; then
	if [ -e "$tmp/nonroot" ]; then echo 1000; else echo 0; fi
else /usr/bin/id "\$@"; fi
EOF
cat >"$tmp/bin/systemd-run" <<'EOF'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

root = Path(__file__).resolve().parent.parent / "manager"
assert "--user" not in sys.argv
assert "--property=RemainAfterExit=yes" in sys.argv
assert "--property=KillMode=control-group" in sys.argv
unit = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--unit="))
state = root / unit
command = sys.argv[sys.argv.index("--") + 1:]
# Model the ExecStart syntax used by the path regression: $$ is literal $, whereas
# ${NAME} expands in the manager after the remote shell has removed its quotes.
# This is deliberately not a complete systemd command-line parser.
command = [re.sub(r"\$\$|\$\{([^}]+)\}",
                  lambda m: "$" if m.group() == "$$" else "", a) for a in command]
if os.fork():
    sys.exit(0)
os.setsid()
(root.parent / "standin" / str(os.getpid())).touch()
with open(os.devnull, "r+b", buffering=0) as null:
    for fd in (0, 1, 2):
        os.dup2(null.fileno(), fd)
    invocation = uuid.uuid4().hex
    def save(code, status, active, sub):
        part = state.with_suffix(".part")
        part.write_text(json.dumps(dict(InvocationID=invocation, ExecMainCode=code,
                                       ExecMainStatus=status, ActiveState=active, SubState=sub)))
        part.replace(state)
    save(0, 0, "active", "running")
    child = subprocess.Popen(command, start_new_session=True)
    rc = child.wait()
    save(1 if rc >= 0 else 2, abs(rc), "active" if rc == 0 else "failed",
         "exited" if rc == 0 else "failed")
EOF
cat >"$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env python3
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent / "manager"
state = root / sys.argv[2]
try:
    data = json.loads(state.read_text())
except (FileNotFoundError, ValueError):
    sys.exit(1)
if "--value" in sys.argv:
    print(data["InvocationID"])
else:
    for k, v in data.items():
        print(f"{k}={v}")
EOF
chmod +x "$tmp/bin/id" "$tmp/bin/systemd-run" "$tmp/bin/systemctl"
cat >"$tmp/badsum/cksum" <<'EOF'
#!/bin/sh
: >"$(dirname "$0")/../badsum-seen"
cat >/dev/null
echo "1 1"
EOF
chmod +x "$tmp/badsum/cksum"
cat >"$tmp/ssh" <<EOF
#!/bin/sh
if [ -e "$tmp/down" ]; then echo yes >"$tmp/down-seen"; echo "Connection to 127.0.0.1 closed by remote host." >&2; exit 255; fi
if [ -e "$tmp/hang" ]; then trap '' TERM; exec sleep 600; fi
p="$tmp/bin:\$PATH"
[ ! -e "$tmp/badsum-on" ] || p="$tmp/badsum:\$p"
if [ -e "$tmp/short" ]; then
	PATH=\$p setsid -w sh -c 'sh -c "\$1"; st=\$?; trap "" HUP; kill -HUP 0 2>/dev/null; exit \$st' ssh-stand-in "\$1" | head -n 1
	exit 0
fi
PATH=\$p setsid -w sh -c 'sh -c "\$1"
st=\$?
trap "" HUP
kill -HUP 0 2>/dev/null
exit \$st' ssh-stand-in "\$1"
st=\$?
if [ -e "$tmp/drop-after" ]; then rm -f "$tmp/drop-after"; echo "Connection to 127.0.0.1 closed by remote host." >&2; exit 255; fi
exit \$st
EOF
chmod +x "$tmp/ssh"

new_qemu() {
	[ -z "$qemu" ] || kill "$qemu" 2>/dev/null || true
	sleep 600 &
	qemu=$!
	rm -f "$tmp/qemu.status" "$tmp/down" "$tmp/hang" "$tmp/short" "$tmp/drop-after" "$tmp/badsum-on"
}

# wait_for FILE PATTERN SECS: until FILE holds PATTERN, at most SECS seconds.
wait_for() {
	i=0
	while ! grep -q -- "$2" "$1" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -le $(($3 * 10)) ] || fail "waited ${3}s for \"$2\" in $1: $(cat "$1" 2>/dev/null)"
		sleep 0.1
	done
}

# start NAME [ssh-suite options] -- COMMAND...: runs ssh-suite.sh in the background; finish checks it.
start() {
	n=$1
	shift
	t0=$(date +%s)
	"${SSH_SUITE_SCRIPT:-$here/ssh-suite.sh}" --ssh "$tmp/ssh" --qemu-pid "$qemu" --qemu-status "$tmp/qemu.status" --dir "${dir:-$tmp/guest}" \
		--name "$n" --log "$tmp/$n.log" --status "$tmp/$n.status" --poll 1 "$@" >"$tmp/$n.out" 2>"$tmp/$n.err" &
	pid=$!
}
started() { wait_for "$tmp/$n.err" "ssh-suite: started $n" 20; }
# Once the failed call is acknowledged, any earlier poll has returned to the driver.
pause_polling() {
	rm -f "$tmp/down-seen"
	touch "$tmp/down"
	wait_for "$tmp/down-seen" yes 10
}
# finish WANT-CODE WANT-STATUS [MAX-SECONDS]
finish() {
	rc=0
	wait "$pid" || rc=$?
	took=$(($(date +%s) - t0))
	[ "$rc" = "$1" ] || fail "$n: exit $rc, want $1: $(cat "$tmp/$n.err")"
	[ "$(cat "$tmp/$n.status")" = "$2" ] || fail "$n: status '$(cat "$tmp/$n.status")', want '$2': $(cat "$tmp/$n.err")"
	[ -z "${3:-}" ] || [ "$took" -le "$3" ] || fail "$n: took ${took}s, want at most $3"
	if [ "$1" = 98 ] && [ "$2" != "guest 98" ]; then
		grep -q "^GUEST-LOST: .* before the suite $n finished; this is not a test result" "$tmp/$n.err" ||
			fail "$n: no GUEST-LOST line on stderr: $(cat "$tmp/$n.err")"
		grep -q '^GUEST-LOST: ' "$tmp/$n.log" || fail "$n: the log does not say GUEST-LOST"
	elif grep -q GUEST-LOST "$tmp/$n.err"; then
		fail "$n: GUEST-LOST where the guest was not lost: $(cat "$tmp/$n.err")"
	fi
}
state() { echo "${dir:-$tmp/guest}/$1"; }

real_nonce_forgery() {
	# shellcheck disable=SC2016 # expanded by the command under test, using the REAL nonce
	start forged --timeout 5 --grace 1 -- sh -c '
read -r n <../forged/nonce
printf "%s exit 0 ended\n" "$n" >../forged/result
kill -KILL "$PPID"
sleep 30
exit 1'
	finish 98 "lost suite-gone" 40
}
manager_paths() {
	# shellcheck disable=SC2016 # literal manager expansion syntax in the directory name
	dir="$tmp/guest-"'${TEGO_UNSET}-$$'
	# shellcheck disable=SC2016 # the command under test expands PWD
	start dollars -- sh -c 'printf "%s\n" "$PWD"'
	finish 0 "guest 0"
	[ "$(cat "$tmp/dollars.log")" = "$dir/dollars.work" ] || fail "dollars: manager changed the working path"
	[ -s "$dir/dollars/sup" ] || fail "dollars: supervisor did not use the literal state path"
	dir=""
}
badsum_readback() {
	touch "$tmp/badsum-on"
	start badsum -- sh -c 'echo ran >'"$tmp"'/badsum.ran'
	finish 97 env 30
	rm -f "$tmp/badsum-on"
	[ -e "$tmp/badsum-seen" ] || fail "badsum: injected checksum command was not reached"
	grep -q 'cmd did not read back whole' "$tmp/badsum.err" || fail "badsum: no setup read-back refusal"
	[ ! -e "$tmp/badsum.ran" ] || fail "badsum: the command ran although its setup did not read back"
}
dropped_connection() {
	# shellcheck disable=SC2016 # the command under test waits on its release file
	start dropped -- sh -c 'echo before; while [ ! -e "$1" ]; do sleep 0.1; done; echo after' dropped "$tmp/dropped.release"
	started
	pause_polling
	wait_for "$tmp/dropped.err" 'a poll failed' 10
	rm -f "$tmp/down"
	touch "$tmp/dropped.release"
	finish 0 "guest 0"
	[ "$(cat "$tmp/dropped.log")" = "$(printf 'before\nafter')" ] || fail "dropped: log $(cat "$tmp/dropped.log")"
	grep -q "a poll failed" "$tmp/dropped.err" || fail "dropped: no poll failed while the connection was down"
}
shortlog_delivery() {
	# shellcheck disable=SC2016 # the command under test waits on its release file
	start shortlog -- sh -c 'while [ ! -e "$1" ]; do sleep 0.1; done; echo some output' shortlog "$tmp/shortlog.release"
	started
	pause_polling
	touch "$tmp/short"
	touch "$tmp/shortlog.release"
	rm -f "$tmp/down"
	finish 97 short-log 40
	rm -f "$tmp/short"
}
vanished_supervisor() {
	for how in killed reboot reuse; do
		start "vanish-$how" -- sleep 60
		started
		pause_polling
		s=$(state "vanish-$how")
		wait_for "$s/child" . 10
		read -r b p st <"$s/sup"
		read -r c _ <"$s/child"
		kill -s KILL -- "-$c" 2>/dev/null || true
		# End the watchdog group before replacing the record, so cleanup retains no orphan.
		kill -s KILL -- "-$p"
		case "$how" in
		reboot) echo "00000000-0000-0000-0000-000000000000 $p $st" >"$s/sup" ;;
		reuse) echo "$b $qemu 1" >"$s/sup" ;;
		esac
		rm -f "$tmp/down"
		if [ "$how" = reboot ]; then finish 98 "lost rebooted" 30; else finish 98 "lost suite-gone" 30; fi
	done
}
# A guest lost while its command runs leaves the command, its supervisor and the service manager's stand-in alive; the script
# ends in that state, and the cleanup trap must leave nothing writing into the folder it removes.
leftover_run() {
	start leftover -- sleep 60
	started
	kill "$pid"
	wait "$pid" || true
}
case "${SSH_SUITE_ONLY:-}" in
manager_paths | real_nonce_forgery | badsum_readback | dropped_connection | shortlog_delivery | vanished_supervisor | leftover_run)
	new_qemu
	"$SSH_SUITE_ONLY"
	echo "ok $SSH_SUITE_ONLY"
	exit 0
;;
"") ;;
*) fail "unknown SSH_SUITE_ONLY case: $SSH_SUITE_ONLY" ;;
esac

# 1. Output and exit code, stdout and stderr in order, a last line with no newline, a word with a quote in it.
new_qemu
start plain -- sh -c 'echo one; echo "it'"'"'s two" >&2; printf last; exit 3'
finish 3 "guest 3"
[ "$(cat "$tmp/plain.log")" = "$(printf "one\nit's two\nlast")" ] || fail "plain: log $(cat "$tmp/plain.log")"
[ "$(cat "$tmp/plain.out")" = "$(cat "$tmp/plain.log")" ] || fail "plain: stdout is not the log"

# 2. A command's own 98 is "guest 98", no GUEST-LOST: the status word says which 98 it is.
start ninetyeight -- sh -c 'exit 98'
finish 98 "guest 98"

# 3. Connections dropped mid-run: the command goes on, and the output comes back whole.
dropped_connection

# 4. The start ran in the guest and its answer was lost (exit 255 after it): the run is found by its state and polled,
# and the command ran once.
touch "$tmp/drop-after"
# shellcheck disable=SC2016 # the command under test waits on its release file
start startlost -- sh -c 'echo ran >>"$1"; while [ ! -e "$2" ]; do sleep 0.1; done; exit 4' startlost "$tmp/startlost.count" "$tmp/startlost.release"
started
touch "$tmp/startlost.release"
finish 4 "guest 4" 40
[ "$(wc -l <"$tmp/startlost.count")" = 1 ] || fail "startlost: the command ran $(wc -l <"$tmp/startlost.count") times"

# 5. The guest does not answer when the run starts: it is started once the guest answers, within --unreachable.
rm -f "$tmp/down-seen"
touch "$tmp/down"
start startdown --unreachable 20 -- sh -c 'echo ran >>'"$tmp"'/startdown.count; exit 0'
wait_for "$tmp/down-seen" yes 10
rm -f "$tmp/down"
finish 0 "guest 0" 40
[ "$(wc -l <"$tmp/startdown.count")" = 1 ] || fail "startdown: the command ran $(wc -l <"$tmp/startdown.count") times"

# 6. The real nonce plus supervisor death must not manufacture a successful completion.
real_nonce_forgery

# The earlier working-directory collision and wrong-nonce case still returns the real failure.
# shellcheck disable=SC2016 # the command under test writes the wrong nonce and waits on release
start collision -- sh -c 'echo 0 >rc; echo "0 exit 0 ended" >rc.part; printf "x exit 0 ended\n" >../collision/result; while [ ! -e "$1" ]; do sleep 0.1; done; exit 1' collision "$tmp/collision.release"
started
touch "$tmp/collision.release"
finish 1 "guest 1"

# 7. Names and directories as data: . and .. are refused; a directory with a quote and shell text in it runs the
# command there and nothing else, also on the path that reports a run that exists.
for bad in . ..; do
	rc=0
	"${SSH_SUITE_SCRIPT:-$here/ssh-suite.sh}" --ssh "$tmp/ssh" --qemu-pid "$qemu" --dir "$tmp/guest" --name "$bad" --log "$tmp/bad.log" -- true \
		>/dev/null 2>&1 || rc=$?
	[ "$rc" = 2 ] || fail "--name $bad: exit $rc, want 2"
done
dir="$tmp/guest'q; touch $tmp/pwned; echo '"
mkdir -p "$dir"
start quoted -- sh -c 'echo inside'
finish 0 "guest 0"
start quoted -- true
finish 97 env
[ ! -e "$tmp/pwned" ] || fail "a quote in --dir ran the text after it in the guest"
dir=""
manager_paths

# 8. A setup write that does not read back whole (a full disk, a short write) starts nothing.
badsum_readback

# 9. A call timeout of 0 is a usage error; an SSH call that ignores SIGTERM is ended (SIGKILL), and the guest is lost by
# --unreachable, in bounded time.
rc=0
"${SSH_SUITE_SCRIPT:-$here/ssh-suite.sh}" --ssh "$tmp/ssh" --qemu-pid "$qemu" --dir "$tmp/guest" --name zero --call-timeout 0 -- true >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "--call-timeout 0: exit $rc, want 2"
start frozen --call-timeout 2 --unreachable 6 -- sleep 60
started
touch "$tmp/hang"
finish 98 "lost unreachable" 40
rm -f "$tmp/hang"

# 10. qemu ended by a signal its starter recorded, and qemu gone with nothing recorded.
new_qemu
start killed -- sh -c 'echo working; sleep 30'
started
kill -KILL "$qemu"
echo "signal 9" >"$tmp/qemu.status"
touch "$tmp/down"
finish 98 "lost signal 9" 30
grep -q "qemu ended by signal 9" "$tmp/killed.err" || fail "killed: the line does not name the signal"
new_qemu
start gone -- sleep 30
started
kill -KILL "$qemu"
touch "$tmp/down"
finish 98 "lost qemu-gone" 40

# 11. The supervisor and its command gone with no result (a kill): lost; the same after a reboot (another boot id in the
# supervisor's record), and with the recorded pid now another process's (pid reuse): never taken for alive.
new_qemu
vanished_supervisor

# 12. Past --timeout: 124, and the command's whole group has ended, a child that ignores SIGTERM included.
start slow --timeout 3 --grace 2 -- sh -c 'trap "" TERM; (trap "" TERM; sleep 600) & while :; do sleep 1; done'
started
s=$(state slow)
wait_for "$s/child" . 10
read -r c _ <"$s/child"
finish 124 timeout 40
if pgrep -g "$c" >/dev/null; then fail "slow: processes of the command's group $c still run after the timeout: $(pgrep -a -g "$c")"; fi

# 13. A completed run whose log never comes back (every answer loses its payload) ends in bounded time.
shortlog_delivery

# 14. A run name another run has is not started again.
start plain -- true
finish 97 env

# 15. A normal supervisor exit of 1 cannot be replaced by a nonce-bearing file saying 0.
# Hold polling until the service manager has reaped the supervisor, then replace only the file.
# shellcheck disable=SC2016 # command under test expands its own argument
start waitstatus -- sh -c 'while [ ! -e "$1" ]; do sleep 0.1; done; exit 1' waitstatus "$tmp/waitstatus.release"
started
pause_polling
touch "$tmp/waitstatus.release"
s=$(state waitstatus)
wait_for "$s/result" 'exit 1 ended' 15
wait_for "$tmp/manager/tego-ssh-suite-$(cat "$s/nonce").service" '"SubState": "failed"' 15
printf '%s exit 0 ended\n' "$(cat "$s/nonce")" >"$s/result"
rm -f "$tmp/down"
finish 98 "lost suite-gone" 30

# 16. A completed service from another invocation cannot authorize this run's result.
# shellcheck disable=SC2016 # command under test expands its own argument
start invocation -- sh -c 'while [ ! -e "$1" ]; do sleep 0.1; done; exit 0' invocation "$tmp/invocation.release"
started
pause_polling
touch "$tmp/invocation.release"
s=$(state invocation)
wait_for "$s/result" 'exit 0 ended' 15
m="$tmp/manager/tego-ssh-suite-$(cat "$s/nonce").service"
wait_for "$m" '"SubState": "exited"' 15
python3 - "$m" <<'EOF'
import json
from pathlib import Path
import sys
p = Path(sys.argv[1])
data = json.loads(p.read_text())
data["InvocationID"] = "0" * 32
p.write_text(json.dumps(data))
EOF
rm -f "$tmp/down"
finish 98 "lost suite-gone" 30

# 17. A non-root SSH login without --sudo cannot fall back to file-only completion.
touch "$tmp/nonroot"
start nonroot -- sh -c 'echo ran >'"$tmp"'/nonroot.ran'
finish 97 env 20
[ ! -e "$tmp/nonroot.ran" ] || fail "nonroot: launched without access to the system manager"
rm -f "$tmp/nonroot"

# 18. A run still going when the script ends is ended with its stand-in before the folder is removed: the cleanup trap
# prints nothing and ends 0, every time (the removal used to race with the stand-in's last write).
for i in 1 2 3 4 5 6 7 8; do
	rc=0
	SSH_SUITE_ONLY=leftover_run sh "$0" >"$tmp/leftover.out" 2>&1 || rc=$?
	[ "$rc" = 0 ] && [ "$(cat "$tmp/leftover.out")" = "ok leftover_run" ] ||
		fail "leftover run $i: exit $rc: $(cat "$tmp/leftover.out")"
done

echo "ok ssh-suite_test.sh"
