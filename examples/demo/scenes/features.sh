#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The feature scenes (README.md, "Feature map"), sourced by demo.sh: they use its say, show, die, plant, sink_up,
# damage, last_run and need_tego. Each scene is short: the contract it runs under, the stand-in agent
# (agents/mini.sh) without Tego where that is harmless, then under Tego, then the ledger's refusals.
#   rules | rule read|write|command|net|process | always | limits | deny-write | ask | approve | deny
#   reason-hook | receipt | presets | selftest | identity | doctor | features

export PORT

MINI_ENV='["PATH", "HOME", "SECRETS", "SINK", "HOMEISH", "PROJECT", "PORT", "DOCKER_HOST_SOCK", "SSH_AUTH_SOCK"]'

# mini_plant lays out the fake world (plant) and adds the stand-in agent and the held/ folder of the ask scene.
mini_plant() {
  plant
  cp "$HERE/agents/mini.sh" "$PROJECT/mini.sh"
  mkdir -p "$PROJECT/held"
}

# mini_contract NAME TRICK: writes stdin, the scene's own lines, between the shared head and tail of a contract at
# $STAGE/c/NAME.yaml, outside the project, so the agent cannot rewrite its own rules.
mini_contract() {
  mkdir -p "$STAGE/c"
  body=$(cat)
  {
    printf 'version: 0\nname: demo-%s\ncommand: ["sh", "mini.sh", "%s"]\n%s\n' "$1" "$2" "$body"
    printf 'env:\n  pass: %s\nrecord: summary\ntier: landlock\ncapture: off\n' "$MINI_ENV"
    case "$body" in *limits:*) ;; *) printf 'limits:\n  pids: 64\n  memory: 512MiB\n  wall: 2m\n' ;; esac
  } >"$STAGE/c/$1.yaml"
}

# mini_without TRICK: the stand-in agent with no Tego around it.
mini_without() {
  say "Without Tego"
  show "cd '$PROJECT' && sh mini.sh $1"
}

# mini_with NAME [ask|end|none]: the stand-in agent under $STAGE/c/NAME.yaml, then what the ledger holds for it: the
# refusals, the held write and its answer (ask), the run's end and the limit that made it (end), or nothing (none,
# for a scene whose refusal the kernel makes without a ledger line). It leaves the run id in $run.
mini_with() {
  say "Under Tego. The rules:"
  show "grep -vE '^(version|env|  pass|record|tier|capture):' '$STAGE/c/$1.yaml'"
  say "Run it"
  show "cd '$PROJECT' && '$TEGO' run '$STAGE/c/$1.yaml' </dev/null 2>&1 | grep -v -E '^(warning|note|  fix:)|no price table'" || true
  run=$(last_run "demo-$1")
  [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
  case "${2:-}" in
    ask)
      say "What the ledger recorded: the held write and your answer"
      show "'$TEGO' events '$run' --kind ask --kind answer 2>&1 | cut -c1-200" ;;
    end)
      # run_end, not --last: --last shows the last refusal or gap, and a limit's end is neither.
      say "What the ledger recorded at the end (the limit that stopped it)"
      show "'$TEGO' events '$run' --kind run_end 2>&1 | cut -c1-200" ;;
    none) ;;
    *)
      say "What the ledger recorded as refused"
      show "'$TEGO' events '$run' --kind refused 2>&1 | cut -c1-200" ;;
  esac
}

rule_read() {
  say "Rule template 1, block read: the secrets folder is unreadable, the rest of the project is not"
  mini_without read
  mini_contract read read <<'EOF'
fs:
  write: ["/dev/null"]
  reads: held
  deny_read: ["../secrets/"]
exec:
  allow: ["sh", "cat", "wc"]
EOF
  mini_with read
}

rule_write() {
  say "Rule template 2, block write: writes only in out/; the shell profile is refused"
  mini_without write; mini_plant
  mini_contract write write <<'EOF'
fs:
  write: ["./out/", "/dev/null"]
exec:
  allow: ["sh"]
EOF
  mini_with write
  echo "shell profile now: $(tail -n 1 "$HOMEISH/.bashrc")"
}

rule_command() {
  say "Rule template 3, block command: 'rm -r' never runs, ls does (a command pattern, not a whole program)"
  mini_without command; mini_plant
  mini_contract command command <<'EOF'
fs:
  write: ["./src/", "/dev/null"]
exec:
  deny: ["rm -r"]
EOF
  mini_with command
}

rule_net() {
  sink_up
  say "Rule template 4, network host: only 127.0.0.1:$PORT (the sink); any other host is refused"
  mini_contract net net <<EOF
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "curl"]
net:
  allow: ["tcp://127.0.0.1:$PORT", "unix:/var/run/nscd/socket"]
EOF
  mini_with net
}

rule_process() {
  say "Rule template 5, process type: no new namespaces (container escapes), no fileless in-memory programs"
  echo "(the 'process type' template is not a contract word: these are the process kinds tiers 1 and 2 always refuse)"
  mini_without process
  mini_contract process process <<'EOF'
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "unshare", "true", "python3"]
EOF
  mini_with process
  echo "(the memfd refusal is made by the seccomp filter itself, before any supervisor sees it, so it has no ledger line)"
}

cmd_rule() {
  need_tego
  mini_plant
  case "${1:-}" in
    read) rule_read ;; write) rule_write ;; command) rule_command ;; net) rule_net ;; process) rule_process ;;
    *) die "usage: demo.sh rule read|write|command|net|process" ;;
  esac
}

cmd_rules() {
  for r in read write command net process; do cmd_rule "$r"; done
}

# sockd_up starts the stand-in docker.sock and ssh-agent socket (sockd.py) in the stage.
sockd_up() {
  mkdir -p "$STAGE/s"
  DOCKER_HOST_SOCK="$STAGE/s/docker.sock"; SSH_AUTH_SOCK="$STAGE/s/agent.sock"
  export DOCKER_HOST_SOCK SSH_AUTH_SOCK
  if [ -f "$STAGE/sockd.pid" ] && kill -0 "$(cat "$STAGE/sockd.pid")" 2>/dev/null; then return 0; fi
  python3 "$HERE/sockd.py" "$DOCKER_HOST_SOCK" "$SSH_AUTH_SOCK" >>"$STAGE/sockd.log" 2>&1 &
  echo $! >"$STAGE/sockd.pid"
  i=0
  while [ ! -S "$SSH_AUTH_SOCK" ]; do
    i=$((i + 1)); [ "$i" -lt 30 ] || die "the stand-in daemons did not start; see $STAGE/sockd.log"
    sleep 0.1
  done
}

cmd_always() {
  need_tego
  mini_plant; sockd_up
  say "Always on, in every contract: no local daemon sockets (stand-ins for docker.sock and the ssh-agent)"
  echo "docker.sock: $DOCKER_HOST_SOCK    ssh-agent: $SSH_AUTH_SOCK    (both fake, in the stage)"
  mini_without sockets
  mini_contract sockets sockets <<'EOF'
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "curl"]
EOF
  mini_with sockets
  say "Always on: no privilege escalation (no_new_privs: no setuid program, sudo included, can raise privileges)"
  mini_without privesc
  echo "(here sudo may ask for a password without Tego; with a cached sudo or a NOPASSWD rule the agent would be root)"
  mini_contract privesc privesc <<'EOF'
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "grep", "tr", "head", "sudo", "id"]
EOF
  mini_with privesc none
  echo "(no ledger line here: under no_new_privs the kernel ignores the setuid bit, so there is nothing left to refuse)"
}

cmd_limits() {
  need_tego
  mini_plant
  say "Limits: a fork bomb meets pids: 32 (only under Tego; the stand-in is bounded at 500 anyway)"
  mini_contract fork fork <<'EOF'
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "python3"]
limits:
  pids: 32
  memory: 256MiB
  wall: 2m
EOF
  mini_with fork end
  show "'$TEGO' status '$run' 2>&1 | grep -E '^(RUN|r-)|resources:'"
  say "Limits: a memory hog meets memory: 128MiB (the kernel stops it; the machine is untouched)"
  mini_contract memory memory <<'EOF'
fs:
  write: ["/dev/null"]
exec:
  allow: ["sh", "python3"]
limits:
  pids: 32
  memory: 128MiB
  wall: 2m
EOF
  mini_with memory end
  show "'$TEGO' status '$run' 2>&1 | grep -E '^(RUN|r-)|resources:'"
}

cmd_deny_write() {
  need_tego
  mini_plant
  say "Block write inside a write grant: the whole repo is writable, its .git/hooks/ is not (fs.deny_write)"
  mini_without hooks; mini_plant
  mini_contract hooks hooks <<'EOF'
fs:
  write: ["./", "/dev/null"]
  deny_write: ["./.git/hooks/"]
exec:
  allow: ["sh"]
EOF
  mini_with hooks
  if [ -e "$PROJECT/.git/hooks/pre-commit" ]; then echo "git hook: PLANTED"; else echo "git hook: none"; fi
  echo "(at tier landlock deny_write is best effort, and the run says so in its gaps; at the root tiers the kernel holds it)"
}

cmd_ask() {
  need_tego
  mini_plant
  say "Approvals: every write under held/ waits for a person (fs.ask). The agent pauses until you answer"
  echo "In a SECOND terminal:  ./demo.sh approve      (or ./demo.sh deny; or the dashboard's Approvals page)"
  mini_contract ask ask <<'EOF'
fs:
  write: ["./out/", "/dev/null"]
  ask: ["./held/"]
exec:
  allow: ["sh"]
ask:
  timeout: 3m
EOF
  mini_with ask ask
  if [ -e "$PROJECT/held/plan.txt" ]; then echo "held/plan.txt: written (approved)"; else echo "held/plan.txt: not written"; fi
}

# answer approve|deny answers the oldest pending ask of the newest ask-scene run, never another agent's ask.
answer() {
  need_tego
  run=$(last_run demo-ask)
  id=
  [ -n "$run" ] && id=$("$TEGO" ask "$run" 2>/dev/null | grep -oE 'q-[0-9a-f]{32}' | head -n 1 || true)
  [ -n "$id" ] || die "no pending ask: start './demo.sh ask' in the other terminal first"
  show "'$TEGO' ask '$run'"
  show "'$TEGO' $1 '$run' '$id'"
}

cmd_reason_hook() {
  need_tego
  repo=$(cd "$HERE/../.." && pwd)
  command -v go >/dev/null 2>&1 || die "the stand-in Claude Code is built from the repo: go must be on PATH"
  command -v openssl >/dev/null 2>&1 || die "openssl is needed for the model stub's certificate"
  mini_plant
  cc="$STAGE/cc"; ws="$cc/ws"
  rm -rf "$cc"; mkdir -p "$cc/bin" "$ws/work" "$ws/.claude-state/tmp" "$cc/home/.claude" "$cc/xdg" "$cc/stub"
  chmod 700 "$cc/xdg"
  say "Reason to the agent, the Claude Code way: tego's PostToolUse hook tells the model why, in the next request"
  echo "(a stand-in Claude Code, test/e2e/reason-claude/fakeclaude, and a local model stub: no login, no model, no network)"
  show "(cd '$repo' && CGO_ENABLED=0 go build -o '$cc/bin/claude' ./test/e2e/reason-claude/fakeclaude)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=127.0.0.1 \
    -addext subjectAltName=IP:127.0.0.1 -days 2 -keyout "$cc/stub/key.pem" -out "$cc/stub/cert.pem" >/dev/null 2>&1 \
    || die "openssl could not make the stub's certificate"
  printf '[\n [{"type": "tool_use", "name": "Write", "input": {"file_path": "%s/work/warmup.txt", "content": "warm-up\\n"}}],\n [{"type": "tool_use", "name": "Write", "input": {"file_path": "%s/.bashrc", "content": "# installed by the agent\\n"}}],\n [{"type": "text", "text": "DONE"}]\n]\n' "$ws" "$HOMEISH" >"$cc/stub-script.json"
  printf '{"prompt": "Tidy up my shell profile.", "turns": [\n {"calls": [{"write": "%s/work/warmup.txt", "content": "warm-up\\n"}]},\n {"calls": [{"write": "%s/.bashrc", "content": "# installed by the agent\\n"}]}\n]}\n' "$ws" "$HOMEISH" >"$cc/script.json"
  python3 -I "$repo/test/workloads/model-stub/server.py" --cert "$cc/stub/cert.pem" --key "$cc/stub/key.pem" \
    --ready "$cc/stub/port" --script "$cc/stub-script.json" --log "$cc/stub/stub.log" --log-content >"$cc/stub/stderr" 2>&1 &
  echo $! >"$STAGE/stub.pid"
  i=0
  while [ ! -s "$cc/stub/port" ]; do
    i=$((i + 1)); [ "$i" -lt 100 ] || die "the model stub did not start; see $cc/stub/stderr"
    sleep 0.1
  done
  sed -e "s|\"@@PORT@@\"|$(cat "$cc/stub/port")|" -e "s|@@CC@@|$cc|g" "$HERE/contracts/claude-standin.yaml" >"$cc/agent.yaml"
  say "The contract: writes only in ./work/; tego gives Claude Code its hook (harness: claude-code)"
  show "grep -E '^(name|harness|  write|    -)' '$cc/agent.yaml'"
  say "Run the stand-in Claude Code under Tego. Turn 2 writes ~/.bashrc, which the contract refuses"
  show "cd '$ws' && env -u CLAUDE_CODE_SIMPLE HOME='$cc/home' SSL_CERT_FILE='$cc/stub/cert.pem' ANTHROPIC_API_KEY=dummy-not-a-key PATH='$cc/bin:$PATH' \
    '$TEGO' run '$cc/agent.yaml' -- claude -p --permission-mode bypassPermissions --script '$cc/script.json' --result '$ws/work/result.json' 'Tidy up my shell profile.' 2>&1 | grep -v -E '^(warning|note|  fix:)|no price table'" || true
  run=$(last_run demo-claude-standin)
  [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
  say "What the model received in its next request, written by tego's hook (from the model stub's log)"
  show "python3 -I '$HERE/modelsaw.py' '$cc/stub/stub.log'" || true
  show "'$TEGO' events '$run' --kind refused 2>&1 | cut -c1-200"
  kill "$(cat "$STAGE/stub.pid")" 2>/dev/null || true
}

cmd_receipt() {
  need_tego
  say "The receipt: time taken, files written, each refusal with its rule, refusals over time, stall minutes, tests, asks"
  show "'$TEGO' receipt --last 2>&1 | grep -v 'no price table'"
  echo "In the dashboard: open the run (Overview, then the run's id) and its Receipt tab."
}

cmd_presets() {
  need_tego
  mini_plant; sink_up; : >"$STAGE/sink.log"
  # The presets name no folder of the kit's: no-secrets is the built-in deny_read list, whose .env scan covers the
  # project, so the fake secrets go in the project's own .env here (the stage's secrets/ folder is not a place
  # that list knows). The sink is not an allowed host: no-prod refuses every host the flags do not add.
  cp "$SECRETS/.env" "$PROJECT/.env"
  SECRETS=$PROJECT
  say "Rule setup from presets: no-secrets, no-prod, repo-only-writes, then adjust with flags"
  echo "(the project's own .env holds the fake secrets in this scene; the sink, 127.0.0.1:$PORT, is not an allowed host)"
  show "'$TEGO' init --preset no-secrets,no-prod,repo-only-writes --write ./src --write ./out --command 'sh rogue.sh' --name demo-preset --force '$PROJECT'"
  # no-secrets passes only its allow-list of variables; the stand-in agent reads where the fake world is from four
  # more, so the scene adds them where the generated file says to (an edit the presenter would make by hand).
  say "Adjust: the stand-in agent needs four variables of its own (no-secrets passes only an allow-list)"
  show "sed -i 's|^  # pass:\$|  pass: [SECRETS, SINK, HOMEISH, PROJECT]|' '$PROJECT/agent.yaml' && grep -A3 '^env:' '$PROJECT/agent.yaml' | grep -v '^ *#'"
  show "cd '$PROJECT' && '$TEGO' compile agent.yaml 2>&1 | grep -E '^(tier|record|fs|exec|net) ' | cut -c1-160"
  say "The rogue agent from Act 2, now under the preset rules"
  show "cd '$PROJECT' && '$TEGO' run agent.yaml </dev/null 2>&1 | grep -v -E '^(warning|note|  fix:)|no price table'" || true
  sleep 0.3
  damage
  run=$(last_run demo-preset); [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
  show "'$TEGO' events '$run' --kind refused 2>&1 | cut -c1-200"
}

cmd_selftest() {
  need_tego
  say "The escape self-test: each trick first without Tego (did it get through?), then under Tego (refused, and by which rule)"
  show "'$TEGO' test" || true
}

cmd_identity() {
  need_tego
  run=$(cat "$STAGE/last-run" 2>/dev/null || last_run)
  [ -n "$run" ] || die "no run yet: run './demo.sh with' first"
  say "Who started the run, where, from which contract (run_start, the chain's first line)"
  show "'$TEGO' events '$run' --kind run_start --json | grep -oE '\"(run|agent|launcher_user|launcher_uid|host|tier|contract_hash)\":(\"[^\"]*\"|[0-9]+)'"
  echo "In the dashboard: the top bar names the host; an approval's answer line names the uid that answered."
}

cmd_doctor() {
  need_tego
  say "Which tiers this machine has. Tier 1 (landlock) needs nothing; tiers 2 and 3 need root, tier 3 also the BPF LSM"
  show "'$TEGO' doctor 2>&1 | grep -E '^(ok|off|FAIL|skip) +(kernel|landlock|seccomp|cgroupv2|lsm|fanotify)' | fold -s -w 150 || true"
  echo "(a 'skip ... requires root' line is honest: run 'sudo tego doctor' to test the root tiers; this kit uses tier landlock)"
}

cmd_features() {
  sed -n '/^## Feature map/,/^## /p' "$HERE/README.md" | sed '$d'
}
