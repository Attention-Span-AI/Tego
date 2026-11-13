#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt-pause-orphan.sh: scope observations and record facts after a paused run loses its launcher
# (ADR 0124, amendment 2026-11-11 (second); GAPS C42).
#
# What it checks, at tier $KT_TIER (default landlock; the kernel's root half runs it under sudo at cgroup):
#   1. pause and resume with the launcher alive: `tego pause` freezes the run (its heartbeat file and its processes' CPU
#      time stop, cgroup.events says frozen 1), `tego resume` lets it carry on (both move again), and a second pause
#      freezes it again;
#   2. the launcher is then SIGKILLed while the run is paused. The sampled heartbeat files keep their sizes across
#      launcher death, a surviving child's sampled CPU time stays unchanged, and surviving processes keep their CPU
#      time across a later two-second sample;
#   3. what a person sees: `tego status` says the run is lost while paused (tier landlock, where nothing ends the frozen
#      tree until a sweep) or ended orphaned (the root tiers, whose reaper ends it at once); `tego resume` is refused;
#   4. tier landlock: after `tego stop`, the child is gone and the sampled heartbeat files have not grown; the record
#      ends with `gap launcher-lost` and `run_end orphaned` and verifies. Stop reports scope readings and record closure.
#
# The agent is two bash processes (the run's own top process and a child it starts), each appending
# $EPOCHREALTIME to its own beat file in a busy loop, with no exec after start: a beat file that keeps its size is a
# useful activity sample, checked alongside CPU time and the freezer state.
# Exit 0 pass, 1 fail, 77 skip (test/e2e/kt-exit.sh).
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
command -v python3 >/dev/null 2>&1 || kt_skip "python3 is required to read status and ledger JSON"
json_py="$repo_root/e2e/pausecompile-json.py"
pausecompile_json() { python3 "$json_py" "$@"; }
pausecompile_json check '{"ok":true}' <<<'{"ok":true}' || kt_fail "the JSON helper is not usable"
# A lost launcher is status's finding (exit 1); malformed output and command errors still fail the check.
status_json() {
	local rc=0
	"$tego" status "$1" --json || rc=$?
	[ "$rc" = 0 ] || [ "$rc" = 1 ]
}

tego="$(kt_ensure_tego)"
tier="${KT_TIER:-landlock}"
kt_note "checking the $tier tier is available"
if ! reason="$(kt_tier_available "$tego" "$tier")"; then
	kt_skip "$tier tier unavailable on this machine: $reason"
fi
if kt_am_root && ! kt_sudo_user; then
	kt_skip "running as root without SUDO_UID: a root tego run drops the agent to the sudo user and has none here"
fi

work="$(kt_workdir)"
out="$work/out"
mkdir -p "$out"
kt_config "$work" >/dev/null
# The chain anchor outside the work directory: R10 refuses a write entry inside the directory that holds the anchor,
# tego's own, and the out directory is in the work directory.
mkdir -p "$KT_ROOT/anchor"
export TEGO_TEST_CHAIN_ANCHOR="$KT_ROOT/anchor/chain.log"
cat >"$work/task.sh" <<'EOF'
#!/usr/bin/env bash
# $1: the out directory. The run's top process starts a child, and each appends a beat in a busy loop. Both ignore
# SIGTERM, so a stop's grace (part 5) leaves them running until its kill.
out="$1"
trap '' TERM
echo $$ >"$out/parent.pid"
bash -c 'trap "" TERM; echo $$ >"$1/child.pid"; while :; do echo "$EPOCHREALTIME" >>"$1/beat.child"; i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; done' child "$out" &
while :; do echo "$EPOCHREALTIME" >>"$out/beat.parent"; i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done; done
EOF
chmod 755 "$work/task.sh"
cat >"$work/agent.yaml" <<EOF
version: 0
name: kt-pause-orphan
command: ["bash", "task.sh", "$out"]
fs:
  write: ["$out/"]
exec:
  allow: ["bash"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 32
  wall: 600s
record: summary
EOF
kt_agent_owns "$out"

# cpu prints a process's utime+stime in clock ticks, or "gone".
cpu() {
	local stat
	stat="$(cat "/proc/$1/stat" 2>/dev/null)" || { echo gone; return; }
	stat="${stat##*) }"
	# shellcheck disable=SC2086 # the fields after the comm, split on purpose
	set -- $stat
	echo $((${12} + ${13}))
}
size() { stat -c %s "$1" 2>/dev/null || echo 0; }
# facts prints one line: both beat files' sizes and both processes' CPU time.
facts() { echo "beats=$(size "$out/beat.parent"),$(size "$out/beat.child") cpu=$(cpu "$ppid"),$(cpu "$cpid")"; }
frozen() { sed -n 's/^frozen //p' "$scope/cgroup.events" 2>/dev/null || echo gone; }

cd "$work" || kt_fail "cd $work"
kt_note "starting the run (tier $tier)"
"$tego" run agent.yaml --tier "$tier" --offline >"$work/run.out" 2>"$work/run.err" &
launcher=$!
for _ in $(seq 300); do
	[ -s "$out/beat.child" ] && [ -s "$out/beat.parent" ] && break
	sleep 0.1
done
if ! [ -s "$out/beat.child" ]; then
	cat "$work/run.err" >&2
	kt_fail "the agent never beat: $(kt_err_line "$work/run.err")"
fi
id="$(basename "$(kt_rundir "$work")")"
ppid="$(cat "$out/parent.pid")"
cpid="$(cat "$out/child.pid")"
scope="/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$cpid/cgroup")"
kt_note "run $id: launcher $launcher, agent $ppid, child $cpid, scope $scope"

kt_note "1. pause and resume with the launcher alive"
"$tego" pause "$id" || kt_fail "tego pause exited $?"
a="$(facts)"
sleep 3
b="$(facts)"
echo "paused: $a, 3 s later: $b, frozen $(frozen)"
[ "$a" = "$b" ] || kt_fail "the run moved while paused: $a then $b"
[ "$(frozen)" = 1 ] || kt_fail "cgroup.events says frozen $(frozen) while paused"
"$tego" resume "$id" || kt_fail "tego resume exited $?"
sleep 2
c="$(facts)"
echo "resumed: 2 s later: $c, frozen $(frozen)"
[ "$c" != "$b" ] || kt_fail "the run did not carry on after tego resume: $b then $c"
"$tego" pause "$id" || kt_fail "the second tego pause exited $?"
kt_half live-pause "$tier" PASS "pause froze the run, resume let it carry on, pause froze it again"

kt_note "2. kill -9 the launcher while the run is paused"
before="$(facts)"
child_before="$(cpu "$cpid")"
case "$child_before" in ""|*[!0-9]*) kt_fail "no numeric child CPU sample before launcher death: $child_before" ;; esac
cpu_scope="$(sed -n 's/^usage_usec //p' "$scope/cpu.stat")"
echo "before the kill: $before, scope usage_usec $cpu_scope"
kill -KILL "$launcher"
wait "$launcher"
echo "the launcher exited $?"
sleep 5
after="$(facts)"
child_after="$(cpu "$cpid")"
if [ "$child_after" != gone ] && [ "$child_after" != "$child_before" ]; then
	kt_fail "the child used CPU across launcher death: $child_before then $child_after"
fi
echo "5 s after the kill: $after, frozen $(frozen), scope usage_usec $(sed -n 's/^usage_usec //p' "$scope/cpu.stat" 2>/dev/null || echo gone)"
[ "${after%% *}" = "${before%% *}" ] || kt_fail "a beat file grew after the launcher died: $before then $after"
for p in "$ppid" "$cpid"; do
	was="$(cpu "$p")"
	[ "$was" = gone ] && continue
	sleep 2
	[ "$(cpu "$p")" = "$was" ] || kt_fail "process $p ran after the launcher died: CPU $was then $(cpu "$p")"
done

kt_note "3. what the person sees"
"$tego" status "$id"
echo "tego status exited $?"
status_json "$id" | pausecompile_json project state,paused,launcher_gone,scope_now,exit_reason ||
	kt_fail "could not read the orphan's status JSON"
"$tego" resume "$id"
rrc=$?
echo "tego resume exited $rrc"
[ "$rrc" = 1 ] || kt_fail "tego resume of the orphan exited $rrc, want 1"

if [ "$tier" = landlock ] || [ "$tier" = observe ]; then
	st="$(status_json "$id" | pausecompile_json join state,launcher_gone,scope_now)" ||
		kt_fail "could not read the orphan's status fields"
	[ "$st" = "lost true frozen" ] || kt_fail "tego status of the orphan: $st, want lost, last recorded paused, scope frozen"
	[ "$(cpu "$cpid")" != gone ] || kt_fail "the frozen child is gone before any sweep: the test proves nothing about it"
	[ "$(frozen)" = 1 ] || kt_fail "the orphan's scope says frozen $(frozen)"
	kt_note "4. tego stop ends it"
	"$tego" stop "$id" || kt_fail "tego stop exited $?"
	sleep 1
	end="$(facts)"
	echo "after the stop: $end, scope $( [ -d "$scope" ] && echo there || echo gone)"
	[ "$(cpu "$cpid")" = gone ] || kt_fail "the child is still there after tego stop"
	[ "${end%% *}" = "${before%% *}" ] || kt_fail "a beat file grew before the tree was killed: $before then $end"
else
	# The root tiers' reaper ended the orphan as soon as the launcher died.
	st="$(status_json "$id" | pausecompile_json field exit_reason)" ||
		kt_fail "could not read the reaped run's exit_reason"
	[ "$st" = orphaned ] || kt_fail "tego status of the reaped run: exit_reason $st, want orphaned"
	[ "$(cpu "$cpid")" = gone ] && [ "$(cpu "$ppid")" = gone ] || kt_fail "an agent process is still there after the reaper"
fi
rundir="$work/runs/$id"
tail -3 "$rundir/events.jsonl" | pausecompile_json project seq,kind,what,why,reason 2>/dev/null ||
	tail -3 "$rundir/events.jsonl" | cut -c1-300
last="$(tail -1 "$rundir/events.jsonl" | pausecompile_json field kind)" ||
	kt_fail "could not read the record's last JSON line"
[ "$last" = run_end ] || kt_fail "the record's last line is $last, want run_end"
tail -1 "$rundir/events.jsonl" | pausecompile_json check '{"kind":"run_end","reason":"orphaned"}' ||
	kt_fail "the record's last line must end the run with reason orphaned"
grep -q '"launcher-lost"' "$rundir/events.jsonl" || kt_fail "no launcher-lost gap before run_end"
"$tego" events "$id" --verify >/dev/null || kt_fail "tego events --verify failed on the ended orphan"
first="$before then $(facts)"

# 5. The last recorded state is not proof: pause, start a stop with a long grace (it thaws the run with no line and
# sends SIGTERM, which the agent ignores), then kill the launcher. The record still says paused; the scope runs.
kt_note "5. paused, a stop's grace, then the launcher killed"
rm -f "$out"/beat.* "$out"/*.pid
"$tego" run agent.yaml --tier "$tier" --offline >"$work/run2.out" 2>"$work/run2.err" &
launcher2=$!
for _ in $(seq 300); do
	[ -s "$out/beat.child" ] && break
	sleep 0.1
done
[ -s "$out/beat.child" ] || { cat "$work/run2.err" >&2; kt_fail "the second run never beat"; }
id2=
for run_dir in "$work/runs"/r-*; do
	[ -d "$run_dir" ] || continue
	candidate="${run_dir##*/}"
	if [ "$candidate" != "$id" ]; then id2="$candidate"; break; fi
done
[ -n "$id2" ] || kt_fail "the second run has no ledger directory"
cpid="$(cat "$out/child.pid")"
"$tego" pause "$id2" || kt_fail "tego pause of the second run exited $?"
scope2="/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$cpid/cgroup")"
[ "$(sed -n 's/^frozen //p' "$scope2/cgroup.events")" = 1 ] || kt_fail "the second run's scope is not frozen after tego pause"
"$tego" stop "$id2" --grace 120s >"$work/stop2.out" 2>&1 &
stopper=$!
# The stop thaws the run before it signals: wait until the scope says so, so the case is the one it names.
thawed=
for _ in $(seq 100); do
	if [ "$(sed -n 's/^frozen //p' "$scope2/cgroup.events")" = 0 ]; then thawed=1; break; fi
	sleep 0.1
done
[ -n "$thawed" ] || kt_fail "tego stop did not thaw the paused run within 10 s"
kill -KILL "$launcher2"
wait "$launcher2"
kill "$stopper" 2>/dev/null
wait "$stopper" 2>/dev/null
# The child's CPU time is what shows it runs: with no launcher, a syscall the supervisor decided fails ENOSYS (ADR 0013),
# so its beat file may not grow while its loop does.
a="$(cpu "$cpid")"
sleep 2
b="$(cpu "$cpid")"
echo "after the launcher's death: child CPU $a then $b ticks, beat $(size "$out/beat.child")"
"$tego" status "$id2"
st="$(status_json "$id2" | pausecompile_json project state,paused,launcher_gone,scope_now,exit_reason)" ||
	kt_fail "could not read the second run's status JSON"
echo "$st"
if [ "$tier" = landlock ] || [ "$tier" = observe ]; then
	case "$a$b" in *[!0-9]*) kt_fail "the thawed child's CPU time is not two numbers ($a then $b): it did not live through the check" ;; esac
	[ "$b" -gt "$a" ] || kt_fail "the thawed child did not run (CPU $a then $b): the case shows nothing"
	[ "$st" = '{"state":"lost","paused":true,"launcher_gone":true,"scope_now":"running","exit_reason":null}' ] ||
		kt_fail "tego status of a run a stop thawed before its launcher died: $st, want lost, recorded paused, scope running"
	"$tego" stop "$id2" || kt_fail "the second tego stop exited $?"
	[ "$(cpu "$cpid")" = gone ] || kt_fail "the child is still there after the second tego stop"
	thawed_result="a run thawed before launcher death read lost, last recorded paused, with scope running, then its child disappeared after stop"
else
	reason="$(pausecompile_json field exit_reason <<<"$st")" || kt_fail "could not read the second run's exit_reason"
	[ "$reason" = orphaned ] || kt_fail "the reaper did not end the second run: $st"
	thawed_result="the reaper ended the run thawed before launcher death with reason orphaned"
fi
kt_pass "tier $tier: beat sizes and surviving child CPU stayed unchanged across launcher death ($first); the child disappeared after cleanup, and the record ended orphaned and verified; $thawed_result"
