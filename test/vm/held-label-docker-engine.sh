#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Runs only inside held-label-docker.sh's disposable container.
set -eu
mode=$1
cd /work
mkdir -p /work/out /tego-state/runs /tego-state/home
printf 'version: 0\nledger_root: /tego-state/runs\n' >/tego-state/config.yaml
chmod 600 /tego-state/config.yaml
assume=false
reads=held
[ "$mode" != assume ] || assume=true
[ "$mode" != direct ] || reads=direct
cat > /work/agent.yaml <<YAML
version: 0
name: docker-label
command: [/bin/actor, --held-label-agent, /work/out/secret]
tier: landlock
fs:
  reads: $reads
  apparmor_assume_root_namespace: $assume
  write: [/work/out/]
  deny_read: []
  deny_write: []
exec:
  allow: [/bin/actor]
env:
  pass: [PATH, HOME]
record: full
YAML
if [ "$mode" != direct ]; then
 cat >>/work/agent.yaml <<'YAML'
gate:
  completion: held
  rules:
    - 'fs.read matches "*.never"': 90
    - 'fs.write outside worktree': 90
YAML
fi
printf preserve >/work/out/secret
chown -R 1000:1000 /work /tego-state
export TEGO_CONFIG=/tego-state/config.yaml TEGO_TEST_CHAIN_ANCHOR=/tego-state/chain.log TEGO_TEST_OWN_LOG_HOME=/tego-state/home
/bin/tego run /work/agent.yaml >/work/output 2>&1
cat /work/output
ledger=$(find /tego-state/runs -name events.jsonl)
[ -n "$ledger" ] && [ -f "$ledger" ]
grep '"kind":"run_start"' "$ledger" >/work/start
if [ "$mode" = refuse ]; then
 grep -q 'LABEL-RESULT {"create":13,"read":13,"truncate":13}' /work/output
 [ "$(cat /work/out/secret)" = preserve ] && [ ! -e /work/out/secret.new ]
 grep -q 'AppArmor namespace depth is unreadable' /work/output
 grep -q 'held-label-unavailable' "$ledger"
 grep -q 'fs.apparmor_assume_root_namespace: true' /work/output
else
 grep -q 'LABEL-RESULT {"create":0,"read":0,"truncate":0}' /work/output
 [ -f /work/out/secret.new ] && [ ! -s /work/out/secret ]
fi
if [ "$mode" = assume ]; then
 grep -q '"best_effort":\["apparmor/assumed-root-namespace"' /work/start
else
 if grep -q 'apparmor/assumed-root-namespace' /work/start; then
  echo 'unexpected namespace assertion in run_start' >&2; exit 1
 fi
fi
echo "DOCKER-ENGINE-PASS $mode (read, truncate, create; run_start disclosure checked)"
