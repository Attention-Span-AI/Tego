#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests ssh-suite.sh against stand-ins, with no guest: the "guest" is a directory on this host; the SSH wrapper runs its
# argument with sh in a session of its own and then sends that session SIGHUP, as sshd's end of a session does; marker
# files make it fail as a dropped connection does (exit 255), hang while ignoring SIGTERM, lose its answer after it ran,
# drop the payload of its answer, or find a cksum that disagrees; and qemu is a sleep this test kills. Every fault is
# injected only once the script says the run has started (a readiness line on its stderr, waited for with a bound), so
# a slow machine does not change what a case tests. What is held:
#   - output and exit code come back whole (98 too, as "guest 98": the status word, not the number, tells a command's
#     98 from a lost guest), and connections dropped mid-run, or the start's answer lost after it ran, end nothing;
#   - completion is the supervisor's own result, kept outside the command's working directory and carrying the run's
#     nonce: a command that writes an rc or a forged result does not end the run early;
#   - a setup write that does not read back whole starts nothing; a name of . or .. and a directory with a quote in it
#     cannot run anything but the command;
#   - a qemu that ended, a guest silent past --unreachable (an SSH call that ignores SIGTERM included, which
#     --call-timeout ends with SIGKILL), a supervisor gone without its result, a reboot, and a pid now another process's
#     are each GUEST-LOST and exit 98;
#   - past --timeout it is 124 and the command's whole process group has ended, descendants ignoring SIGTERM included;
#   - a completed run whose log makes no progress ends in bounded time.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-ssh-suite-test.XXXXXX")
qemu=""
# shellcheck disable=SC2329 # the EXIT trap calls it
cleanup() {
	[ -z "$qemu" ] || kill "$qemu" 2>/dev/null || true
	for f in "$tmp"/guest*/*/child "$tmp"/guest*/*/sup; do
		[ -f "$f" ] || continue
		read -r a b _ <"$f" || continue
		case "$f" in */child) p=$a ;; *) p=$b ;; esac
		kill -s KILL -- "-$p" 2>/dev/null || kill -s KILL "$p" 2>/dev/null || true
	done
	rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
fail() {
	echo "FAIL $*" >&2
	exit 1
}

mkdir "$tmp/bin" "$tmp/badsum" "$tmp/guest"
cat >"$tmp/badsum/cksum" <<'EOF'
#!/bin/sh
cat >/dev/null
echo "1 1"
EOF
chmod +x "$tmp/badsum/cksum"
cat >"$tmp/ssh" <<EOF
#!/bin/sh
if [ -e "$tmp/down" ]; then echo "Connection to 127.0.0.1 closed by remote host." >&2; exit 255; fi
if [ -e "$tmp/hang" ]; then trap '' TERM; exec sleep 600; fi
p=\$PATH
[ ! -e "$tmp/badsum-on" ] || p="$tmp/badsum:\$PATH"
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
	"$here/ssh-suite.sh" --ssh "$tmp/ssh" --qemu-pid "$qemu" --qemu-status "$tmp/qemu.status" --dir "${dir:-$tmp/guest}" \
		--name "$n" --log "$tmp/$n.log" --status "$tmp/$n.status" --poll 1 "$@" >"$tmp/$n.out" 2>"$tmp/$n.err" &
	pid=$!
}
started() { wait_for "$tmp/$n.err" "ssh-suite: started $n" 20; }
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

# 1. Output and exit code, stdout and stderr in order, a last line with no newline, a word with a quote in it.
new_qemu
start plain -- sh -c 'echo one; echo "it'"'"'s two" >&2; printf last; exit 3'
finish 3 "guest 3"
[ "$(cat "$tmp/plain.log")" = "$(printf "one\nit's two\nlast")" ] || fail "plain: log $(cat "$tmp/plain.log")"
[ "$(cat "$tmp/plain.out")" = "$(cat "$tmp/plain.log")" ] || fail "plain: stdout is not the log"

# 2. A command's own 98 is "guest 98", no GUEST-LOST: the status word says which 98 it is.
start ninetyeight -- sh -c 'exit 98'
finish 98 "guest 98"

# 3. Connections dropped for three seconds mid-run: the command goes on, and the output comes back whole.
start dropped -- sh -c 'echo before; sleep 5; echo after'
started
touch "$tmp/down"
sleep 3
rm -f "$tmp/down"
finish 0 "guest 0"
[ "$(cat "$tmp/dropped.log")" = "$(printf 'before\nafter')" ] || fail "dropped: log $(cat "$tmp/dropped.log")"
grep -q "a poll failed" "$tmp/dropped.err" || fail "dropped: no poll failed while the connection was down"

# 4. The start ran in the guest and its answer was lost (exit 255 after it): the run is found by its state and polled,
# and the command ran once.
touch "$tmp/drop-after"
start startlost -- sh -c 'echo ran >>'"$tmp"'/startlost.count; sleep 2; exit 4'
finish 4 "guest 4" 40
[ "$(wc -l <"$tmp/startlost.count")" = 1 ] || fail "startlost: the command ran $(wc -l <"$tmp/startlost.count") times"

# 5. The guest does not answer when the run starts: it is started once the guest answers, within --unreachable.
touch "$tmp/down"
start startdown --unreachable 20 -- sh -c 'echo ran >>'"$tmp"'/startdown.count; exit 0'
sleep 3
rm -f "$tmp/down"
finish 0 "guest 0" 40
[ "$(wc -l <"$tmp/startdown.count")" = 1 ] || fail "startdown: the command ran $(wc -l <"$tmp/startdown.count") times"

# 6. A command that writes rc in its working directory and a forged result into the run's state does not end the run:
# only the supervisor's result, with the run's nonce, once the supervisor is gone, does.
start forged -- sh -c 'echo 0 >rc; echo "0 exit 0 ended" >rc.part; printf "x exit 0 ended\n" >'"$tmp"'/guest/forged/result; sleep 4; exit 1'
finish 1 "guest 1"

# 7. Names and directories as data: . and .. are refused; a directory with a quote and shell text in it runs the
# command there and nothing else, also on the path that reports a run that exists.
for bad in . ..; do
	rc=0
	"$here/ssh-suite.sh" --ssh "$tmp/ssh" --qemu-pid "$qemu" --dir "$tmp/guest" --name "$bad" --log "$tmp/bad.log" -- true \
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

# 8. A setup write that does not read back whole (a full disk, a short write) starts nothing.
touch "$tmp/badsum-on"
start badsum -- sh -c 'echo ran >'"$tmp"'/badsum.ran'
finish 97 env 30
rm -f "$tmp/badsum-on"
[ ! -e "$tmp/badsum.ran" ] || fail "badsum: the command ran although its setup did not read back"

# 9. A call timeout of 0 is a usage error; an SSH call that ignores SIGTERM is ended (SIGKILL), and the guest is lost by
# --unreachable, in bounded time.
rc=0
"$here/ssh-suite.sh" --ssh "$tmp/ssh" --qemu-pid "$qemu" --dir "$tmp/guest" --name zero --call-timeout 0 -- true >/dev/null 2>&1 || rc=$?
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
for how in killed reboot reuse; do
	start "vanish-$how" -- sleep 60
	started
	s=$(state "vanish-$how")
	wait_for "$s/child" . 10
	read -r b p st <"$s/sup"
	read -r c _ <"$s/child"
	kill -s KILL -- "-$c" 2>/dev/null || true
	kill -s KILL "$p"
	case "$how" in
	reboot) echo "00000000-0000-0000-0000-000000000000 $p $st" >"$s/sup" ;;
	reuse) echo "$b $qemu 1" >"$s/sup" ;;
	esac
	if [ "$how" = reboot ]; then finish 98 "lost rebooted" 30; else finish 98 "lost suite-gone" 30; fi
done

# 12. Past --timeout: 124, and the command's whole group has ended, a child that ignores SIGTERM included.
start slow --timeout 3 --grace 2 -- sh -c 'trap "" TERM; (trap "" TERM; sleep 600) & while :; do sleep 1; done'
started
s=$(state slow)
wait_for "$s/child" . 10
read -r c _ <"$s/child"
finish 124 timeout 40
if pgrep -g "$c" >/dev/null; then fail "slow: processes of the command's group $c still run after the timeout: $(pgrep -a -g "$c")"; fi

# 13. A completed run whose log never comes back (every answer loses its payload) ends in bounded time.
start shortlog -- sh -c 'sleep 2; echo some output'
started
touch "$tmp/short"
finish 97 short-log 40
rm -f "$tmp/short"

# 14. A run name another run has is not started again.
start plain -- true
finish 97 env

echo "ok ssh-suite_test.sh"
