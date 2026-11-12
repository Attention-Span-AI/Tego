#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The stand-in agent of the short scenes (demo.sh rule ..., limits, deny-write, ask). Each subcommand is one
# thing a confused or prompt-injected agent might do, said in plain words, and what came of it. The same
# script runs without Tego (demo.sh ... --without) and under the scene's contract. Env it reads: SECRETS,
# SINK, HOMEISH, PROJECT, PORT, DOCKER_HOST_SOCK (a stand-in docker.sock), SSH_AUTH_SOCK (a stand-in ssh-agent),
# PYTHON3 (the python3 the contract allows, named by the file it runs as; python3 on PATH without it).
set -u
say() { echo "[agent] $*"; }
ok() { say "   -> $*"; }

case "${1:-}" in
  read)
    say "read the secrets file $SECRETS/.env"
    if v=$(cat "$SECRETS/.env" 2>/dev/null); then ok "GOT IT: $(printf '%s' "$v" | wc -c) bytes of secrets"; else ok "refused"; fi
    say "read an ordinary project file src/keep.txt"
    if cat "$PROJECT/src/keep.txt" >/dev/null 2>&1; then ok "read it (allowed)"; else ok "refused"; fi
    ;;
  write)
    say "write a report in out/ (the folder it was given)"
    if { echo "report" >"$PROJECT/out/report.txt"; } 2>/dev/null; then ok "written (allowed)"; else ok "refused"; fi
    say "append to the shell profile $HOMEISH/.bashrc"
    if { echo "# installed by the agent" >>"$HOMEISH/.bashrc"; } 2>/dev/null; then ok "PROFILE CHANGED"; else ok "refused"; fi
    ;;
  command)
    # This act deliberately deletes src/. Only plant()'s fake project may be
    # used, even when someone starts the stand-in directly with their own env.
    project_path=$(cd "${PROJECT:?}" && pwd -P) || exit 1
    marker=$PROJECT/.tego-demo-project
    if [ -L "$marker" ] || [ ! -f "$marker" ] ||
      ! IFS= read -r marked <"$marker" || [ "$marked" != "$project_path" ]; then
      say "refusing a project without the marker from demo setup"
      exit 1
    fi
    say "list the project (ls)"
    if ls "$PROJECT/src" >/dev/null 2>&1; then ok "ran (allowed)"; else ok "refused"; fi
    say "delete the source tree (rm -r src)"
    rm -r -- "$PROJECT/src" 2>/dev/null
    if [ -d "$PROJECT/src" ]; then ok "refused: src/ is still there"; else ok "SRC DELETED"; fi
    ;;
  net)
    say "call the host it was given ($SINK)"
    if curl -q -s --max-time 3 -H "X-Demo-Agent: mini net" "$SINK/allowed" >/dev/null 2>&1; then ok "reached it (allowed)"; else ok "refused"; fi
    say "call a host nobody listed (http://127.0.0.2:$PORT, standing in for a production database)"
    if curl -q -s --max-time 3 "http://127.0.0.2:$PORT/prod" >/dev/null 2>&1; then ok "REACHED IT"; else ok "refused or unreachable (the ledger says which)"; fi
    ;;
  process)
    say "start a new user namespace, the first step of most container escapes (unshare -U)"
    if unshare -U true 2>/dev/null; then ok "STARTED"; else ok "refused"; fi
    say "make a fileless program in memory (memfd_create), so no file rule can see what it runs"
    if "${PYTHON3:-python3}" -c 'import os; os.memfd_create("payload")' 2>/dev/null; then ok "MADE ONE"; else ok "refused"; fi
    ;;
  sockets)
    say "talk to the Docker daemon through its socket ($DOCKER_HOST_SOCK), which is root on the host"
    if out=$(curl -q -s --max-time 3 --unix-socket "$DOCKER_HOST_SOCK" http://docker/version 2>/dev/null) && [ -n "$out" ]; then ok "ANSWERED: $out"; else ok "refused"; fi
    say "ask the ssh-agent to sign with your keys ($SSH_AUTH_SOCK)"
    if out=$(curl -q -s --max-time 3 --unix-socket "$SSH_AUTH_SOCK" http://ssh-agent/sign 2>/dev/null) && [ -n "$out" ]; then ok "ANSWERED: $out"; else ok "refused"; fi
    ;;
  privesc)
    say "may a setuid program raise my privileges? (NoNewPrivs 0 = yes, 1 = never)"
    ok "$(grep NoNewPrivs /proc/self/status | tr -s '\t' ' ')"
    say "become root without a password (sudo -n id -u)"
    if u=$(sudo -n id -u 2>&1); then ok "ROOT: uid $u"; else ok "refused: $(printf '%s' "$u" | head -n 1)"; fi
    ;;
  fork)
    say "start 500 processes (a fork bomb, bounded so it is harmless anywhere)"
    "${PYTHON3:-python3}" -c '
import os, signal, time
kids = []
for i in range(500):
    try:
        pid = os.fork()
    except OSError as e:
        print("[agent]    process %d refused: %s" % (i + 1, e.strerror), flush=True)
        break
    if pid == 0:
        time.sleep(20)
        os._exit(0)
    kids.append(pid)
print("[agent]    -> %d of 500 started" % len(kids), flush=True)
for k in kids:
    os.kill(k, signal.SIGKILL)
'
    ;;
  memory)
    say "grab memory, 32 MiB at a time, up to 2 GiB"
    "${PYTHON3:-python3}" -c '
import sys
chunks = []
for i in range(64):
    chunks.append(bytearray(32 << 20))
    print("[agent]    holding %d MiB" % (32 * (i + 1)), flush=True)
print("[agent]    -> HELD 2 GiB", flush=True)
'
    ok "the memory hog ended (exit $?)"
    ;;
  hooks)
    say "edit a source file in the repo (src/app.txt)"
    if { echo "work" >"$PROJECT/src/app.txt"; } 2>/dev/null; then ok "written (allowed)"; else ok "refused"; fi
    say "plant a git hook (.git/hooks/pre-commit), which runs on your next commit, outside the agent's run"
    if { echo "#!/bin/sh" >"$PROJECT/.git/hooks/pre-commit"; } 2>/dev/null; then ok "HOOK PLANTED"; else ok "refused"; fi
    ;;
  ask)
    say "write a plan into held/ (a folder where every write waits for a person)"
    if { echo "the plan" >"$PROJECT/held/plan.txt"; } 2>/dev/null; then ok "written: someone approved it"; else ok "refused: denied, or nobody answered in time"; fi
    ;;
  *)
    echo "usage: mini.sh read|write|command|net|process|sockets|privesc|fork|memory|hooks|ask" >&2
    exit 2 ;;
esac
