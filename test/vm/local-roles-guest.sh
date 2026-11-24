#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Disposable full-guest qualification. Never run on the development host.
set -euo pipefail
if [[ ${1:-} == --self-check ]]; then
  python3 "$(dirname "$0")/local-roles-assert.py" self-check
  python3 "$(dirname "$0")/local-roles-dashboard.py" --self-check
  python3 "$(dirname "$0")/local-roles-namespace.py" --self-check
  exit
fi
[[ ${TEGO_DISPOSABLE_HOST:-} == kvm && $EUID == 0 && -f /run/roles1-guest ]] || {
  echo 'requires explicit disposable guest root and /run/roles1-guest' >&2; exit 2;
}
umask 022
BASE=/var/tmp/roles1
BIN=/opt/roles1
LAUNCHER='' DASHBOARD='' DASHBOARD_SERVER='' ANSWER='' SECOND=''
assert() { python3 "$BIN/local-roles-assert.py" "$@"; }
answer_exec() { assert exec "$CASE/${ANSWER_LABEL:-answer}.identity.json" "$@"; }
cleanup() {
  local pid
  for pid in "$ANSWER" "$SECOND" "$DASHBOARD_SERVER" "$DASHBOARD" "$LAUNCHER"; do
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid"; fi
  done
}
trap cleanup EXIT
for command in jq python3 runuser sudo unshare timeout tail useradd loginctl systemctl systemd-run; do command -v "$command" >/dev/null; done
getent passwd roles-agent >/dev/null || useradd -m -u 21001 roles-agent
getent passwd roles-owner >/dev/null || useradd -m -u 21002 roles-owner
[[ $(id -u roles-agent) == 21001 && $(id -u roles-owner) == 21002 ]]
AGENT_GID=$(id -g roles-agent)
[[ ! -e /etc/tego/config.yaml && ! -e /etc/sudoers.d/roles1-proof ]] || {
  echo 'requires fresh disposable fixture: policy or sudo grant already exists' >&2; exit 2;
}
# The product names a program to run as root only when it can vouch for the path (selfbin.Named: root-owned, no group or
# other write along it), and refuses to print a command otherwise, which would change the refusals this script holds
# the product to. However the files got here (a tar extracted as the host's user is group-writable), make the install
# trusted before anything runs: root-owned, not writable by group or other, in a folder whose parents are root's.
chown -R root:root "$BIN"
chmod -R go-w "$BIN"
for dir in "$BIN" "$(dirname "$BIN")" /; do
  [[ $(stat -c %U "$dir") == root && -z $(find "$dir" -maxdepth 0 -perm /022 -print) ]] || {
    echo "$dir is not root-owned and closed to group and other writes" >&2; exit 2;
  }
done
install -d -m 0755 "$BASE/cases" /etc/tego
CASE_ROOT=$BASE/cases
BTRFS_LIMIT=0
# Where a file's st_dev is not the superblock's device that /proc/locks prints (a btrfs subvolume: Fedora's default root),
# a caller that is not the launcher's own uid cannot prove who holds a run's lock, so `tego approve` as roles-agent
# against the root launcher stops at that proof with "permission denied" on the launcher's descriptors, before the broker
# can refuse it (ADR 0126, "The superblock proof on a btrfs subvolume"; the refusal is right and is not weakened here).
# The rows that read the broker's own refusal need a place where the proof can be made, so the cases go on a tmpfs
# there. The probe is the kernel's own table: one held flock, its row in /proc/locks, the device it prints.
if mountpoint -q "$BASE/cases"; then umount "$BASE/cases"; fi
probe=$BASE/lockprobe
: > "$probe"
exec 9> "$probe"
flock -n 9
dev=$(stat -c %d "$probe") # glibc's major() and minor() of st_dev
printed=$(printf '%02x:%02x:%s' $(((dev >> 8) & 0xfff | (dev >> 32) & ~0xfff)) $((dev & 0xff | (dev >> 12) & ~0xff)) "$(stat -c %i "$probe")")
if ! grep -q " $printed " /proc/locks; then
  echo "roles1: /proc/locks does not print this filesystem's st_dev ($printed): the cases go on a tmpfs" >&2
  mount -t tmpfs -o size=512m,mode=0755 roles1-cases "$BASE/cases"
  # One row stays on the filesystem as it is, so the limit this probe finds is witnessed too, not only described.
  BTRFS_LIMIT=1
  install -d -m 0755 "$BASE/plain-cases"
fi
exec 9>&-
rm -f "$probe"
printf 'roles-owner ALL=(root) NOPASSWD: ALL\n' > /etc/sudoers.d/roles1-proof
chmod 0440 /etc/sudoers.d/roles1-proof
printf 'local_roles: owner_only\n' > /etc/tego/config.yaml
chmod 0644 /etc/tego/config.yaml
uname -a > "$BASE/kernel"
cat /sys/kernel/security/lsm > "$BASE/lsm"
sha256sum "$BIN"/tego{,-control,-fault,-negative-sync} > "$BASE/binaries"

wait_status() {
  local pid=$1 label=$2 rc=0
  timeout 20s tail --pid="$pid" -f /dev/null || {
    echo "FAIL: $label did not exit in 20 seconds" >&2; return 1;
  }
  wait "$pid" || rc=$?
  printf '%s\n' "$rc" > "$CASE/$label.status"
}
zero_effect() { test ! -e "$CASE/work/held/effect"; }
start_held() {
  local name=$1 binary=${2:-$BIN/tego} mode=${3:-} duration=${4:-10m} profile=${5:-managed}
  CASE=$CASE_ROOT/$name
  [[ ! -e $CASE ]] || { echo "case exists: $CASE" >&2; return 1; }
  install -d -m 0755 "$CASE"
  install -d -o roles-agent -g "$AGENT_GID" -m 0700 "$CASE/work" "$CASE/ledger" "$CASE/agent-log"
  install -d -o roles-agent -g "$AGENT_GID" -m 0700 "$CASE/work/held" "$CASE/work/out"
  install -d -m 0700 "$CASE/anchors" "$CASE/root-log" "$CASE/barrier"
  printf 'ledger_root: %s/ledger\n' "$CASE" > "$CASE/machine.yaml"
  chmod 0644 "$CASE/machine.yaml"
  cat > "$CASE/work/agent.yaml" <<YAML
version: 0
name: roles-proof
command: ["/bin/sh", "agent.sh"]
tier: landlock
fs:
  write: ["./out/"]
  ask: ["./held/"]
exec:
  allow: ["/bin/sh", "/bin/echo"]
net: {}
env:
  pass: ["PATH"]
ask:
  timeout: $duration
record: summary
YAML
  cat > "$CASE/work/agent.sh" <<'AGENT'
#!/bin/sh
# The result is the open's outcome: 0 when the held open was let through, 2 when it was refused. It does not read the
# shell's own status for a failed redirection, which is 2 in dash (Debian's and Ubuntu's sh) and 1 in bash (Fedora's).
if printf 'ONE-EFFECT\n' > held/effect; then printf '0\n' > out/result; else printf '2\n' > out/result; fi
AGENT
  chown -R roles-agent:"$AGENT_GID" "$CASE/work"
  export TEGO_CONFIG=$CASE/machine.yaml TEGO_TEST_CHAIN_ANCHOR=$CASE/anchors/chain.log
  export TEGO_TEST_OWN_LOG_HOME=$CASE/root-log
  export TEGO_ROLES_GUEST_MODE=$mode TEGO_ROLES_GUEST_DIR=$CASE/barrier TEGO_ROLES_GUEST_WITNESS=1
  (cd "$CASE/work"; SUDO_UID=21001 SUDO_GID="$AGENT_GID" exec "$binary" run agent.yaml) >"$CASE/launcher.out" 2>"$CASE/launcher.err" &
  LAUNCHER=$!
  local found=0 i
  for ((i=0;i<100;i++)); do
    if "$BIN/tego" ask --json > "$CASE/pending.json" 2> "$CASE/ask.err" &&
       jq -e '(.runs | length) == 1 and (.runs[0].pending | length) == 1' "$CASE/pending.json" >/dev/null; then found=1; break; fi
    kill -0 "$LAUNCHER" || { cat "$CASE/launcher.err"; return 1; }
    sleep .05
  done
  ((found)) || { cat "$CASE/launcher.err" "$CASE/ask.err"; return 1; }
  RUN=$(jq -er '.runs[0].run' "$CASE/pending.json")
  ASK=$(jq -er '.runs[0].pending[0].ask_id' "$CASE/pending.json")
  DIR=$CASE/ledger/$RUN
  AGENT=$(jq -er 'select(.kind == "ask") | .pid' "$DIR/events.jsonl" | tail -1)
  jq -c 'select(.kind == "run_start")' "$DIR/events.jsonl" > "$CASE/authority.json"
  if [[ $profile == managed ]]; then
    jq -e '.record_minor == 41 and .local_approval_authority.mode == "owner_only" and .local_approval_authority.agent_uid == 21001' "$CASE/authority.json" >/dev/null
    grep -F "$(sha256sum /etc/tego/config.yaml | cut -d' ' -f1)" "$CASE/authority.json"
  else
    jq -e '(.record_minor == 41) and (has("local_approval_authority") | not)' "$CASE/authority.json" >/dev/null
  fi
  cat "/proc/$AGENT/status" "/proc/$AGENT/cgroup" > "$CASE/agent-facts"
  zero_effect
}
still_pending() {
  "$BIN/tego" ask "$RUN" --json > "$CASE/still-pending.json"
  jq -e --arg ask "$ASK" '(.pending | length) == 1 and .pending[0].ask_id == $ask' "$CASE/still-pending.json" >/dev/null
  zero_effect
  test ! -e "$CASE/work/out/result"
}
refuse() {
  local label=$1 pattern=$2 rc=0; shift 2
  "$@" >"$CASE/$label.out" 2>"$CASE/$label.err" || rc=$?
  printf '%s\n' "$rc" > "$CASE/$label.status"
  assert status "$CASE/$label.status" 125
  grep -E "$pattern" "$CASE/$label.err"
  if [[ $label != private-* ]] && grep -Eiq 'permission denied|operation not permitted' "$CASE/$label.err"; then
    echo "FAIL: $label stopped at path access or local setup before broker proof" >&2
    return 1
  fi
  still_pending
}
as_agent() {
  runuser -u roles-agent -- env TEGO_CONFIG="$TEGO_CONFIG" TEGO_TEST_CHAIN_ANCHOR="$CASE/agent-log/chain.log" TEGO_TEST_OWN_LOG_HOME="$CASE/agent-log" "$@"
}
readable_fixture() {
  # Product handover.go leaves this live root directory 0700 until Close.
  # That prevents non-root O_RDONLY|O_DIRECTORY. A diagnostic 0755 is necessary
  # for this broker-admission row; record the original placement first.
  if [[ ! -e $CASE/product-placement ]]; then
    test "$(stat -c '%a %u' "$DIR")" = '700 0'
    stat -c '%a %u %n' "$DIR" > "$CASE/product-placement"
  fi
  chmod 0755 "$DIR"
  chmod 0644 "$DIR/events.jsonl"
  local paths=("$DIR" "$DIR/events.jsonl")
  if [[ -e $DIR/lock ]]; then chmod 0644 "$DIR/lock"; paths+=("$DIR/lock"); fi
  if [[ -S $DIR/ask.sock ]]; then paths+=("$DIR/ask.sock"); fi
  stat -c '%a %u %n' "${paths[@]}" > "$CASE/placement"
  assert placement "$DIR"
  as_agent python3 -c 'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY); os.close(fd)' "$DIR"
}
check_effect() {
  assert result "$CASE" 0
  assert operation "$DIR/events.jsonl" "$ASK" allow > "$CASE/operation-witness.json"
  assert actor "$DIR/events.jsonl" "$ASK" "$CASE/${ANSWER_LABEL:-answer}.identity.json"
  "$BIN/tego" events "$RUN" --verify > "$CASE/verify.out"
  "$BIN/tego" receipt "$RUN" > "$CASE/receipt.out"
}
once_effect() {
  answer_exec "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/root-answer.out" 2> "$CASE/root-answer.err"
  wait_status "$LAUNCHER" launcher
  LAUNCHER=
  test "$(cat "$CASE/launcher.status")" = 0
  check_effect
}
snapshot_dashboard() {
  local refused=${1:-}
  # Completed run ownership has been handed over; no live diagnostic needed.
  cp "$CASE/anchors/chain.log" "$CASE/agent-log/chain.log"
  chown roles-agent:"$AGENT_GID" "$CASE/agent-log/chain.log"
  install -o roles-agent -g "$AGENT_GID" -m 0600 /dev/null "$CASE/dashboard-ended.out"
  as_agent python3 "$BIN/local-roles-assert.py" exec "$CASE/agent-log/dashboard.identity.json" "$BIN/tego-control" serve --addr 127.0.0.1:8484 > "$CASE/dashboard-ended.out" 2> "$CASE/dashboard-ended.err" &
  DASHBOARD=$!
  chown roles-agent:"$AGENT_GID" "$CASE/dashboard-ended.out"
  chmod 0600 "$CASE/dashboard-ended.out"
  local args=(--ended --output-dir "$CASE/agent-log/pages")
  if [[ -n $refused ]]; then
    cp "$CASE/operation-witness.json" "$CASE/agent-log/operation-witness.json"
    args+=(--operation-witness "$CASE/agent-log/operation-witness.json")
  fi
  as_agent python3 "$BIN/local-roles-dashboard.py" "$CASE/dashboard-ended.out" "$RUN" "$ASK" "${args[@]}" > "$CASE/dashboard-ended-witness.json"
  DASHBOARD_SERVER=$(jq -er '.pid' "$CASE/agent-log/dashboard.identity.json")
  kill -TERM "$DASHBOARD_SERVER"
  wait_status "$DASHBOARD" dashboard-ended
  DASHBOARD='' DASHBOARD_SERVER=''
  sed -i -E 's/([?]t=)[^[:space:]]+/\1REDACTED/g' "$CASE/dashboard-ended.out"
}
barrier_entered() {
  local i
  for ((i=0;i<200;i++)); do
    if [[ -f $CASE/barrier/entered ]]; then zero_effect; return; fi
    sleep .05
  done
  echo 'FAIL: barrier was never entered' >&2; return 1
}
wait_caller_dead() {
  local i
  for ((i=0;i<200;i++)); do
    if [[ ! -r /proc/$AGENT/status ]] || grep -q '^State:.*Z' "/proc/$AGENT/status"; then printf '%s\n' "$AGENT dead before resume" > "$CASE/caller-dead"; return; fi
    sleep .05
  done
  echo 'FAIL: held caller did not die before resuming append' >&2; return 1
}
wait_broker_closed() {
  local i
  for ((i=0;i<200;i++)); do
    if [[ ! -S $DIR/ask.sock ]]; then printf '%s\n' "$RUN broker closed before resume" > "$CASE/broker-closed"; return; fi
    sleep .05
  done
  echo 'FAIL: shutdown did not close the broker before resuming append' >&2; return 1
}
finish_refused() {
  local event=$1 record_fault=${2:-no}
  wait_status "$ANSWER" answer
  ANSWER=
  assert status "$CASE/answer.status" 125
  wait_status "$LAUNCHER" launcher
  LAUNCHER=
  case $event in
    cancel)
      assert status "$CASE/launcher.status" 137
      assert result "$CASE" absent
      test -s "$CASE/caller-dead"
      ;;
    shutdown)
      assert status "$CASE/launcher.status" 143
      assert result "$CASE" absent
      test -s "$CASE/broker-closed"
      ;;
    policy|timeout)
      assert status "$CASE/launcher.status" 0
      assert result "$CASE" 2
      assert operation "$DIR/events.jsonl" "$ASK" refused > "$CASE/operation-witness.json"
      ;;
    record-fault)
      assert status "$CASE/launcher.status" 125
      assert result "$CASE" absent
      test ! -e "/proc/$AGENT/status"
      ;;
    *) echo "unknown refused row: $event" >&2; return 1 ;;
  esac
  local rc=0
  "$BIN/tego" ask "$RUN" "$ASK" > "$CASE/recorded-answer.out" 2> "$CASE/recorded-answer.err" || rc=$?
  printf '%s\n' "$rc" > "$CASE/recorded-answer.status"
  if [[ $record_fault == no ]]; then assert status "$CASE/recorded-answer.status" 0; fi
  rc=0
  "$BIN/tego" receipt "$RUN" > "$CASE/receipt.out" 2> "$CASE/receipt.err" || rc=$?
  printf '%s\n' "$rc" > "$CASE/receipt.status"
  if [[ $record_fault == no ]]; then assert status "$CASE/receipt.status" 0; fi
  rc=0
  "$BIN/tego" events "$RUN" --verify > "$CASE/verify.out" 2> "$CASE/verify.err" || rc=$?
  printf '%s\n' "$rc" > "$CASE/verify.status"
  if [[ $record_fault == no ]]; then
    assert status "$CASE/verify.status" 0
    assert actor "$DIR/events.jsonl" "$ASK" "$CASE/answer.identity.json"
  fi
}

# Same-user path access and actual broker authorization are distinct witnesses.
start_held same-user
for decision in approve deny; do
  refuse "private-$decision" 'permission denied|only root may answer once' as_agent "$BIN/tego" "$decision" "$RUN" "$ASK"
done
readable_fixture
for decision in approve deny; do
  refuse "readable-$decision" 'only root may answer once' as_agent "$BIN/tego" "$decision" "$RUN" "$ASK"
done
python3 "$BIN/local-roles-transfer.py" "$DIR" "$LAUNCHER" "$ASK" > "$CASE/transferred-writer.json"
still_pending
# The HTTP client has roles-agent's actual TCP credentials; token/cookie stay in memory.
install -o roles-agent -g "$AGENT_GID" -m 0600 /dev/null "$CASE/dashboard.out"
as_agent python3 "$BIN/local-roles-assert.py" exec "$CASE/agent-log/dashboard.identity.json" "$BIN/tego-control" serve --addr 127.0.0.1:8484 > "$CASE/dashboard.out" 2> "$CASE/dashboard.err" &
DASHBOARD=$!
chown roles-agent:"$AGENT_GID" "$CASE/dashboard.out"
chmod 0600 "$CASE/dashboard.out"
as_agent python3 "$BIN/local-roles-dashboard.py" "$CASE/dashboard.out" "$RUN" "$ASK" > "$CASE/dashboard-witness.json"
assert broker "$CASE/barrier/broker-replies.jsonl" "$CASE/agent-log/dashboard.identity.json" 2
# The specified 6.17 matrix row must exercise packet-delivered pidfds.
jq -se 'length > 0 and all(.[]; .packet_pidfd == true)' "$CASE/barrier/broker-replies.jsonl" >/dev/null
cp "$CASE/barrier/broker-replies.jsonl" "$BASE/kernel-pidfd-witness.jsonl"
still_pending
DASHBOARD_SERVER=$(jq -er '.pid' "$CASE/agent-log/dashboard.identity.json")
kill -TERM "$DASHBOARD_SERVER"
wait_status "$DASHBOARD" dashboard
DASHBOARD='' DASHBOARD_SERVER=''
sed -i -E 's/([?]t=)[^[:space:]]+/\1REDACTED/g' "$CASE/dashboard.out"
refuse root-always 'only root may answer once' "$BIN/tego" approve "$RUN" "$ASK" --always
printf 'ALTERNATE\n' > "$BASE/alternate"
refuse root-alternate 'only root may answer once' "$BIN/tego" alternate "$RUN" "$ASK" --file "$BASE/alternate"
once_effect
snapshot_dashboard
rc=0
"$BIN/tego" approve "$RUN" "$ASK" > "$CASE/repeat.out" 2> "$CASE/repeat.err" || rc=$?
printf '%s\n' "$rc" > "$CASE/repeat.status"
assert status "$CASE/repeat.status" 1
grep -F 'has ended; nothing waits for an answer' "$CASE/repeat.err"
# The ended-run CLI cannot reopen the held operation.
assert result "$CASE" 0

# Where the superblock proof cannot be made (the probe above found it so), the refusal ADR 0126 keeps stays witnessed: a
# caller that is not the launcher's uid, with the run's files readable to it, is still refused at the proof on the
# launcher's hidden descriptors, no answer is recorded, nothing takes effect, and the ask stays pending until root answers.
if ((BTRFS_LIMIT)); then
  CASE_ROOT=$BASE/plain-cases
  start_held btrfs-limit
  readable_fixture
  refuse private-btrfs-approve "launcher's descriptors are hidden from this user" as_agent "$BIN/tego" approve "$RUN" "$ASK"
  grep -F 'only root may answer once' "$CASE/private-btrfs-approve.err"
  test "$(jq -s '[.[] | select(.kind == "answer")] | length' "$DIR/events.jsonl")" = 0
  assert result "$CASE" absent
  once_effect
  CASE_ROOT=$BASE/cases
fi

start_held sudo-owner
runuser -u roles-owner -- sudo -n env TEGO_CONFIG="$TEGO_CONFIG" TEGO_TEST_CHAIN_ANCHOR="$TEGO_TEST_CHAIN_ANCHOR" TEGO_TEST_OWN_LOG_HOME="$CASE/root-log" python3 "$BIN/local-roles-assert.py" exec "$CASE/answer.identity.json" "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/sudo.out" 2> "$CASE/sudo.err"
wait_status "$LAUNCHER" launcher
LAUNCHER=
test "$(cat "$CASE/launcher.status")" = 0
check_effect

for who in root sudo; do
  start_held "$who-deny"
  if [[ $who == sudo ]]; then
    runuser -u roles-owner -- sudo -n env TEGO_CONFIG="$TEGO_CONFIG" TEGO_TEST_CHAIN_ANCHOR="$TEGO_TEST_CHAIN_ANCHOR" TEGO_TEST_OWN_LOG_HOME="$CASE/root-log" python3 "$BIN/local-roles-assert.py" exec "$CASE/answer.identity.json" "$BIN/tego" deny "$RUN" "$ASK" > "$CASE/deny.out" 2> "$CASE/deny.err"
  else
    answer_exec "$BIN/tego" deny "$RUN" "$ASK" > "$CASE/deny.out" 2> "$CASE/deny.err"
  fi
  wait_status "$LAUNCHER" launcher
  LAUNCHER=
  zero_effect
  assert status "$CASE/launcher.status" 0
  assert result "$CASE" 2
  assert operation "$DIR/events.jsonl" "$ASK" refused > "$CASE/operation-witness.json"
  assert actor "$DIR/events.jsonl" "$ASK" "$CASE/answer.identity.json" --deny
  jq -se '[.[] | select(.kind == "answer")] | length == 1 and .[0].approved == false and .[0].answer_reason == "ask-denied" and .[0].actor.uid == 0 and .[0].actor.role == "owner"' "$DIR/events.jsonl" >/dev/null
  "$BIN/tego" events "$RUN" --verify > "$CASE/verify.out"
done

namespace_answer() {
  local decision=$1 namespace=$2 mode=${3:-private}; shift 3
  python3 "$BIN/local-roles-namespace.py" "$DIR" "$LAUNCHER" "$ASK" "$decision" "$namespace" \
    --mode "$mode" --barrier "$CASE/barrier" --identity "$CASE/namespace.identity.json" "$@" \
    > "$CASE/namespace-witness.json" 2> "$CASE/namespace.err"
  if [[ $mode != send-restore ]]; then
    # Require the response from the broker as well as its independently captured reply.
    jq -e '.broker_response.code == "owner-only" and .connected_before_namespace == true' "$CASE/namespace-witness.json" >/dev/null
    jq -se --argjson pid "$(jq -er '.decision.pid' "$CASE/namespace-witness.json")" \
      '[.[] | select(.peer_pid == $pid and .peer_uid == 0 and .code == "owner-only" and .packet_pidfd == true)] | length == 1' \
      "$CASE/barrier/broker-replies.jsonl" >/dev/null
    still_pending
  fi
}
for namespace in user cgroup; do
  for decision in approve deny; do
    start_held "$namespace-ns-$decision"
    namespace_answer "$decision" "$namespace" private
    once_effect
  done
done
# Packet identity is fixed at send. Namespace and membership facts are judged
# after receipt. Hold the broker before its first post-packet authority read.
for decision in approve deny; do
  start_held "cgroup-send-restore-$decision" "$BIN/tego" after-packet
  namespace_answer "$decision" cgroup send-restore
  wait_status "$LAUNCHER" launcher
  LAUNCHER=
  assert status "$CASE/launcher.status" 0
  if [[ $decision == approve ]]; then
    assert result "$CASE" 0
    assert operation "$DIR/events.jsonl" "$ASK" allow > "$CASE/operation-witness.json"
    assert actor "$DIR/events.jsonl" "$ASK" "$CASE/namespace.identity.json"
  else
    assert result "$CASE" 2
    assert operation "$DIR/events.jsonl" "$ASK" refused > "$CASE/operation-witness.json"
    assert actor "$DIR/events.jsonl" "$ASK" "$CASE/namespace.identity.json" --deny
  fi
  "$BIN/tego" events "$RUN" --verify > "$CASE/verify.out"
done
for namespace in user cgroup governed; do
  for decision in approve deny; do
    start_held "send-enter-$namespace-$decision" "$BIN/tego" after-packet
    args=()
    if [[ $namespace == governed ]]; then
      CG=$(awk -F: '$1 == "0" {print $3}' "/proc/$AGENT/cgroup")
      CG_CHILD=/sys/fs/cgroup$CG/roles-answer
      mkdir "$CG_CHILD"
      args=(--governed "$CG_CHILD")
    fi
    namespace_answer "$decision" "$namespace" enter-after-send "${args[@]}"
    [[ $namespace != governed ]] || rmdir "$CG_CHILD"
    # Recovery must not pause at the already exercised diagnostic packet barrier.
    touch "$CASE/barrier/packet-resume"
    once_effect
  done
done
for decision in approve deny; do
  start_held "governed-$decision"
  CG=$(awk -F: '$1 == "0" {print $3}' "/proc/$AGENT/cgroup")
  CG_CHILD=/sys/fs/cgroup$CG/roles-answer
  mkdir "$CG_CHILD"
  # shellcheck disable=SC2016 # The child shell expands its positional arguments.
  refuse governed 'only root may answer once' sh -ec '
    echo $$ > "$1/cgroup.procs"
    cat /proc/self/cgroup
    shift; exec "$@"' sh "$CG_CHILD" "$BIN/tego" "$decision" "$RUN" "$ASK"
  rmdir "$CG_CHILD"
  once_effect
done

# Original source-loss rows: distinguish a local config refusal from a broker refusal.
for source in removed unreadable replaced off; do
  start_held "source-$source"
  cp /etc/tego/config.yaml "$CASE/policy.before"
  stat -c '%d %i %a %u %n' /etc/tego/config.yaml > "$CASE/policy-placement.before"
  case $source in
    removed) rm /etc/tego/config.yaml ;;
    unreadable) chmod 0600 /etc/tego/config.yaml ;;
    replaced) cp /etc/tego/config.yaml /etc/tego/config.next; mv /etc/tego/config.next /etc/tego/config.yaml ;;
    off) printf 'local_roles: off\n' > /etc/tego/config.yaml ;;
  esac
  for decision in approve deny; do
    rc=0
    "$BIN/tego" "$decision" "$RUN" "$ASK" > "$CASE/$decision.out" 2> "$CASE/$decision.err" || rc=$?
    printf '%s\n' "$rc" > "$CASE/$decision.status"
    ((rc != 0)) || { echo "FAIL: source-$source $decision succeeded" >&2; exit 1; }
    assert status "$CASE/$decision.status" 125
    if [[ $source == unreadable && $decision == approve ]]; then
      grep -F 'system layer must be readable' "$CASE/$decision.err"
      if [[ -e $CASE/barrier/broker-replies.jsonl ]]; then
        echo 'FAIL: unreadable strict approve contacted broker' >&2; exit 1
      fi
    else
      grep -F 'approval policy file changed since this run started' "$CASE/$decision.err"
    fi
    zero_effect
    test ! -e "$CASE/work/out/result"
  done
  cp "$CASE/policy.before" /etc/tego/config.yaml
  chmod 0644 /etc/tego/config.yaml
  still_pending
  if [[ $source == unreadable ]]; then
    # chmod repair retains the original trusted inode and bytes.
    once_effect
    start_held "source-$source-stop-relaunch"
  fi
  "$BIN/tego" stop "$RUN" > "$CASE/stop.out" 2> "$CASE/stop.err"
  wait_status "$LAUNCHER" launcher
  LAUNCHER=
  zero_effect
  assert status "$CASE/launcher.status" 143
  assert result "$CASE" absent
  "$BIN/tego" events "$RUN" --verify > "$CASE/verify.out"
  start_held "source-$source-relaunched"
  once_effect
done

start_held root-race
ANSWER_LABEL=first answer_exec "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/first.out" 2> "$CASE/first.err" &
ANSWER=$!
ANSWER_LABEL=second answer_exec "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/second.out" 2> "$CASE/second.err" &
SECOND=$!
wait_status "$ANSWER" first
ANSWER=
wait_status "$SECOND" second
SECOND=
if [[ $(cat "$CASE/first.status") == 0 ]]; then
  loser=second
  ANSWER_LABEL=first
else
  assert status "$CASE/second.status" 0
  loser=first
  ANSWER_LABEL=second
fi
assert race-loser "$CASE/$loser.status" "$CASE/$loser.err" "$RUN"
wait_status "$LAUNCHER" launcher
LAUNCHER=
test "$(cat "$CASE/launcher.status")" = 0
check_effect
unset ANSWER_LABEL

start_held late-answer "$BIN/tego" '' 1s
sleep 1.1
wait_status "$LAUNCHER" launcher
LAUNCHER=
rc=0
"$BIN/tego" approve "$RUN" "$ASK" > "$CASE/late.out" 2> "$CASE/late.err" || rc=$?
printf '%s\n' "$rc" > "$CASE/late.status"
assert status "$CASE/late.status" 1
grep -F 'has ended; nothing waits for an answer' "$CASE/late.err"
zero_effect
assert status "$CASE/launcher.status" 0
assert result "$CASE" 2
assert operation "$DIR/events.jsonl" "$ASK" refused > "$CASE/operation-witness.json"
jq -se '[.[] | select(.kind == "answer")] | length == 1 and .[0].approved == false and .[0].answer_reason == "ask-timeout" and .[0].system_cause == "timeout" and (.[0] | has("actor") | not)' "$DIR/events.jsonl" >/dev/null
"$BIN/tego" events "$RUN" --verify > "$CASE/verify.out"

# Every fault is a fresh held action. Only its answer append is instrumented.
for phase in before-append before-fsync; do
  for event in cancel shutdown policy timeout; do
    duration=10m
    [[ $event != timeout ]] || duration=1s
    start_held "$phase-$event" "$BIN/tego-fault" "$phase" "$duration"
    answer_exec "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/answer.out" 2> "$CASE/answer.err" &
    ANSWER=$!
    barrier_entered
    case $event in
      cancel) kill -KILL "$AGENT"; wait_caller_dead ;;
      shutdown) kill -TERM "$LAUNCHER"; wait_broker_closed ;;
      policy) cp /etc/tego/config.yaml /etc/tego/config.next; mv /etc/tego/config.next /etc/tego/config.yaml ;;
      timeout) sleep 1.1 ;;
    esac
    touch "$CASE/barrier/resume"
    finish_refused "$event"
    if [[ $event == policy ]]; then snapshot_dashboard refused; fi
    if [[ $event == timeout ]]; then
      grep -E 'timed out|ask-timeout' "$CASE/answer.out" "$CASE/answer.err" "$DIR/events.jsonl"
    fi
  done
done
for mode in short-write invalid-actor file-eio run-dir-eio parent-dir-eio dir-einval; do
  start_held "$mode" "$BIN/tego-fault" "$mode"
  answer_exec "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/answer.out" 2> "$CASE/answer.err" &
  ANSWER=$!
  finish_refused record-fault yes
  # Runtime shutdown attempts subsequent writes. Preserve all evidence of poison/refusal.
  case $mode in
    short-write) fault_pattern='short write' ;;
    invalid-actor) fault_pattern='actor|local approval|local-approval' ;;
    file-eio|run-dir-eio|parent-dir-eio) fault_pattern='input/output error' ;;
    dir-einval) fault_pattern='invalid argument|not supported' ;;
  esac
  assert fault-cause "$fault_pattern" "$DIR/events.jsonl" "$RUN" "$CASE/answer.err" "$CASE/launcher.err" > "$CASE/fault-errors"
done

# Negative control: skipping required sync must defeat the no-effect-before-sync assertion.
start_held negative-sync "$BIN/tego-negative-sync" before-fsync
answer_exec "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/answer.out" 2> "$CASE/answer.err" &
ANSWER=$!
wait_status "$ANSWER" answer
ANSWER=
wait_status "$LAUNCHER" launcher
LAUNCHER=
test ! -e "$CASE/barrier/entered"
if zero_effect; then echo 'FAIL: negative control did not expose the omitted sync' >&2; exit 1; fi
check_effect
printf 'EXPECTED-FAIL: no-effect-before-sync assertion rejected negative control\n' > "$CASE/negative-witness"
# Activation refusals use an action that would leave an effect immediately if released.
for activation in record-off observe setuid userns root-drop adopt; do
  CASE=$BASE/cases/activation-$activation
  install -d -m 0755 "$CASE"
  install -d -o roles-agent -g "$AGENT_GID" -m 0700 "$CASE/work" "$CASE/work/out" "$CASE/ledger"
  install -d -m 0700 "$CASE/anchors" "$CASE/root-log"
  printf 'ledger_root: %s/ledger\n' "$CASE" > "$CASE/machine.yaml"
  export TEGO_CONFIG=$CASE/machine.yaml TEGO_TEST_CHAIN_ANCHOR=$CASE/anchors/chain.log TEGO_TEST_OWN_LOG_HOME=$CASE/root-log
  cat > "$CASE/work/agent.sh" <<'AGENT'
#!/bin/sh
printf 'UNEXPECTED-RELEASE\n' > out/effect
AGENT
  cat > "$CASE/work/agent.yaml" <<'YAML'
version: 0
name: roles-activation
command: ["/bin/sh", "agent.sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh"]
net: {}
env:
  pass: ["PATH"]
record: summary
YAML
  chown -R roles-agent:"$AGENT_GID" "$CASE/work"
  args=(env SUDO_UID=21001 SUDO_GID="$AGENT_GID" "$BIN/tego" run agent.yaml)
  case $activation in
    record-off) args+=(--record off) ;;
    observe) args+=(--observe) ;;
    setuid) sed -i 's/tier: landlock/tier: cgroup/' "$CASE/work/agent.yaml"; printf 'setuid: true\n' >> "$CASE/work/agent.yaml" ;;
    userns)
      # Establish contract/path readability before entering a namespace which
      # maps host root alone and loses DAC override over the agent-owned work.
      chmod 0755 "$CASE/work"
      test -r "$CASE/work/agent.yaml"
      # Private namespace root takes the unprivileged backend path. Supply its
      # real delegated user-manager subtree before namespace entry, as the
      # matrix harness does for its unprivileged caller.
      loginctl enable-linger root
      systemctl start user@0.service
      args=(env XDG_RUNTIME_DIR=/run/user/0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus
        systemd-run --user --scope --quiet -p Delegate=yes
        unshare --user --map-root-user "${args[@]}") ;;
    root-drop) args=(env -u SUDO_UID -u SUDO_GID "$BIN/tego" run agent.yaml) ;;
    adopt)
      # shellcheck disable=SC2016 # The target shell expands its own PID and argument.
      runuser -u roles-agent -- sh -c 'echo $$ > "$1/out/adopt.pid"; exec /bin/sleep 60' sh "$CASE/work" &
      SECOND=$!
      found=0
      for ((i=0;i<100;i++)); do if [[ -s $CASE/work/out/adopt.pid ]]; then found=1; break; fi; sleep .05; done
      ((found)) || { echo 'FAIL: adoption target unavailable' >&2; exit 1; }
      ADOPT_PID=$(cat "$CASE/work/out/adopt.pid")
      args=(env SUDO_UID=21001 SUDO_GID="$AGENT_GID" "$BIN/tego" adopt --pid "$ADOPT_PID" --uid 21001 --record summary)
      ;;
  esac
  rc=0
  (cd "$CASE/work"; timeout 10s "${args[@]}") > "$CASE/refusal.out" 2> "$CASE/refusal.err" || rc=$?
  printf '%s\n' "$rc" > "$CASE/refusal.status"
  if [[ $activation == setuid ]]; then
    # Keep this row unchanged while the cold-probe product finding is open.
    assert status "$CASE/refusal.status" 125
    grep -E 'local root-only approvals|root-only approval' "$CASE/refusal.err"
  else
    assert activation-refusal "$activation" "$CASE/refusal.status" "$CASE/refusal.err"
  fi
  test ! -e "$CASE/work/out/effect"
  for events in "$CASE"/ledger/*/events.jsonl; do
    [[ -e $events ]] || continue
    if jq -se 'any(.[]; .kind == "run_start" and .local_approval_authority != null)' "$events"; then
      echo "FAIL: refused activation claimed managed run_start: $activation" >&2; exit 1
    fi
  done
  if [[ $activation == adopt ]]; then
    kill -TERM "$ADOPT_PID"
    wait_status "$SECOND" adopt-target
    SECOND=
  fi
done

# Both documented personal selectors restore same-user once approval without new attribution.
for personal in off unset; do
  if [[ $personal == off ]]; then printf 'local_roles: off\n' > /etc/tego/config.yaml; else printf '# personal host\n' > /etc/tego/config.yaml; fi
  start_held "personal-$personal" "$BIN/tego" '' 10m personal
  readable_fixture
  as_agent "$BIN/tego" approve "$RUN" "$ASK" > "$CASE/personal-answer.out" 2> "$CASE/personal-answer.err"
  wait_status "$LAUNCHER" launcher
  LAUNCHER=
  test "$(cat "$CASE/launcher.status")" = 0
  assert result "$CASE" 0
  assert operation "$DIR/events.jsonl" "$ASK" allow > "$CASE/operation-witness.json"
  jq -se 'all(.[]; (has("actor") | not) and (has("system_cause") | not) and (has("local_approval_authority") | not))' "$DIR/events.jsonl" >/dev/null
  "$BIN/tego" events "$RUN" --verify > "$CASE/verify.out"
done
rm /etc/sudoers.d/roles1-proof
printf 'ROLES-GUEST-DONE: all scripted qualification rows completed\n'
