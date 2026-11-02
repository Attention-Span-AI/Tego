#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The Tego demo, one subcommand per act (see README.md):
#   setup | without | with | why | dashboard [serve args] | claude | codex | always-on | reset
#   the feature scenes (scenes/features.sh): rules | rule <t> | always | limits | deny-write | ask | approve | deny
#   | reason-hook | receipt | presets | selftest | identity | doctor | features
# Every command prints what it runs before it runs it. Nothing real is read or sent: the secrets are
# fake files under the stage, and the "internet" is sink.py on 127.0.0.1.
#   DEMO_STAGE  where the stage lives (default: ./stage next to this script, gitignored); a path holding one of
#               ' " \ | & or a line break is refused (plain, below), and so is a kit folder or a tego path that
#               holds a ' or a line break (quotable)
#   DEMO_PORT   the sink's port (default 8787)
#   TEGO_DEMO_UNIT  the always-on unit's name (default tego-demo-agent for the default stage; a stage chosen with
#               DEMO_STAGE gets tego-demo-agent-<cksum of its path>, so a reset there never stops another demo's unit)
#   TEGO, TEGO_CONTROL  the binaries (default: tego, tego-control on PATH)
set -eu

# printf, not echo: dash's echo reads a backslash in a path as an escape.
die() { printf 'demo.sh: %s\n' "$*" >&2; exit 1; }

# quotable NAME PATH refuses a path show() cannot put between single quotes, where it evaluates the commands it prints:
# one holding a ' or a line break. The kit's own folder and tego's path reach nothing else (they are otherwise quoted
# arguments), so this is all they are held to.
quotable() {
  case $2 in
    *\'* | *'
'*) die "$1 holds a ' or a line break, which the demo cannot quote: $2" ;;
  esac
}

# plain NAME PATH [HINT] refuses a path the kit cannot carry into a contract either: the claude, codex and reason-hook
# acts write the stage into contracts with sed, between YAML's double quotes, as plant() writes python3's interpreter
# (agent_python), and there a " \ | or & broke the replacement or the string. It is refused, as is a ' or a line break,
# before anything is made; HINT says what to do instead.
plain() {
  case $2 in
    *[\'\"\\\|\&]* | *'
'*) die "$1 holds one of ' \" \\ | & or a line break, which the demo cannot quote: $2${3:+ ($3)}" ;;
  esac
}

HERE=$(cd "$(dirname "$0")" && pwd)
quotable "the demo kit's folder" "$HERE"
STAGE=${DEMO_STAGE:-$HERE/stage}
case $STAGE in /*) ;; *) STAGE=$PWD/$STAGE ;; esac
plain "the stage" "$STAGE" "set DEMO_STAGE to a path without them"
mkdir -p "$STAGE"
STAGE=$(cd "$STAGE" && pwd)
PORT=${DEMO_PORT:-8787}
TEGO=${TEGO:-tego}
CONTROL=${TEGO_CONTROL:-tego-control}
if [ -n "${TEGO_DEMO_UNIT:-}" ]; then UNIT=$TEGO_DEMO_UNIT
elif [ -n "${DEMO_STAGE:-}" ]; then UNIT=tego-demo-agent-$(printf %s "$STAGE" | cksum | cut -d' ' -f1)
else UNIT=tego-demo-agent; fi
SINK="http://127.0.0.1:$PORT"
PROJECT="$STAGE/project"
SECRETS="$STAGE/secrets"
HOMEISH="$STAGE/home"
export SECRETS SINK HOMEISH PROJECT

say() { printf '\n== %s\n' "$*"; }
# show prints a command as the presenter would type it, then runs it.
show() { printf '$ %s\n' "$*"; eval "$*"; }

# piped CMD FILTER prints "CMD | FILTER" as show does and runs it, and returns CMD's exit status, not FILTER's: a
# pipeline's status is its last command's, so a CMD that failed behind tee and grep read as one that ran.
piped() {
  printf '$ %s | %s\n' "$1" "$2"
  rm -f "$STAGE/piped.status"
  { if eval "$1"; then s=0; else s=$?; fi; echo "$s" >"$STAGE/piped.status"; } | eval "$2" || :
  s=$(cat "$STAGE/piped.status" 2>/dev/null) || s=
  return "${s:-1}"
}

need_tego() {
  command -v "$TEGO" >/dev/null 2>&1 || die "tego is not on PATH. Build it (make build) and run: export PATH=\$PWD/bin:\$PATH"
  quotable "tego's path" "$(command -v "$TEGO")"
}

# PYTHON3 is the interpreter the guarded agent runs (agent_python), never one taken from the caller's environment.
unset PYTHON3

# agent_python sets and exports PYTHON3 to the file python3 runs as: the kernel's own name for it (/proc/self/exe),
# or python3's sys.executable where that is the same file by another name (/usr/bin/python3 for python3.13). plant()
# writes it into the guarded contract's exec.allow in place of python3, and the contract passes it to the agent, whose
# step 7 reads $TEGO_REASON (JSON) with it. Named python3, the grant took the python3 files on PATH, and under pyenv or
# asdf the first is a #! shim: tego refused to start the run, the shim's own interpreter (/usr/bin/env) on no list.
# A spelling with a space or a tab is passed over (an exec.allow entry reads one as a command and its words): a venv
# under "~/My Projects" names its python3 so, while the file it links to does not. When every spelling has one,
# python3 is named bare, as the kit did before, and tego resolves it on PATH (a #! shim there is then refused again).
agent_python() {
  [ -z "${PYTHON3:-}" ] || return 0
  PYTHON3=$(python3 -I -c 'import os, sys
exe = os.readlink("/proc/self/exe")
same = sys.executable if sys.executable and os.path.realpath(sys.executable) == exe else ""
print(next((c for c in (same, exe) if c and not any(ch.isspace() for ch in c)), "python3"))' 2>/dev/null) || PYTHON3=
  case $PYTHON3 in
    python3) ;;
    /*)
      [ -f "$PYTHON3" ] && [ -x "$PYTHON3" ] || die "python3 runs as $PYTHON3, which is not a program file the contract can name"
      plain "python3's interpreter" "$PYTHON3" ;;
    *) die "python3 is needed (the sink and the agent's step 7 run on it), and python3 on PATH did not say which file it runs as" ;;
  esac
  export PYTHON3
}

port_open() {
  python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(0.5)
sys.exit(s.connect_ex(("127.0.0.1", int(sys.argv[1]))))' "$PORT"
}

sink_up() {
  if [ -f "$STAGE/sink.pid" ] && kill -0 "$(cat "$STAGE/sink.pid")" 2>/dev/null; then return 0; fi
  if port_open; then die "port $PORT is busy and it is not this demo's sink; set DEMO_PORT to a free port"; fi
  command -v python3 >/dev/null 2>&1 || die "python3 is needed for the loopback sink"
  python3 "$HERE/sink.py" "$PORT" >>"$STAGE/sink.log" 2>&1 &
  echo $! >"$STAGE/sink.pid"
  i=0
  while ! port_open; do
    i=$((i + 1)); [ "$i" -lt 30 ] || die "the sink did not start; see $STAGE/sink.log"
    sleep 0.1
  done
}

# plant lays out the fake world afresh: fake secrets, a fake shell profile, a project with a git hooks
# dir and a file worth keeping. It is called before each act so each act starts from the same state.
# The project's agent.yaml is contracts/guarded.yaml with the file python3 runs as (agent_python) in exec.allow.
plant() {
  agent_python
  rm -rf "$SECRETS" "$HOMEISH" "$PROJECT"
  mkdir -p "$SECRETS" "$HOMEISH" "$PROJECT/src" "$PROJECT/out" "$PROJECT/.git/hooks"
  printf '# demo only, not a real credential\nTEGODEMO_AWS_SECRET=AKIA-FAKE-DEMO-0000-NOT-REAL\nTEGODEMO_DB_PASSWORD=hunter2-but-fake\n' >"$SECRETS/.env"
  printf 'TEGODEMO-this-is-not-a-real-key\n' >"$SECRETS/id_demo"
  chmod 600 "$SECRETS/.env" "$SECRETS/id_demo"
  printf '# my shell profile\n' >"$HOMEISH/.bashrc"
  printf 'important notes\n' >"$PROJECT/notes.txt"
  printf 'keep\n' >"$PROJECT/src/keep.txt"
  cp "$HERE/agents/rogue.sh" "$PROJECT/rogue.sh"
  sed "/^  allow:/s|\"python3\"|\"$PYTHON3\"|" "$HERE/contracts/guarded.yaml" >"$PROJECT/agent.yaml"
}

# damage prints what is left on the fake machine after an act.
damage() {
  say "What is left on the machine"
  hits=$(grep -c 'reached the sink' "$STAGE/sink.log" 2>/dev/null || true)
  echo "sink: ${hits:-0} request(s) arrived"
  grep 'reached the sink' "$STAGE/sink.log" 2>/dev/null | sed 's/^/  /' || true
  if [ "$(wc -l <"$HOMEISH/.bashrc")" -gt 1 ]; then echo "shell profile: TAMPERED ($(tail -n 1 "$HOMEISH/.bashrc"))"; else echo "shell profile: untouched"; fi
  if [ -e "$PROJECT/.git/hooks/pre-commit" ]; then echo "git hook: PLANTED (.git/hooks/pre-commit)"; else echo "git hook: none"; fi
  if [ -e "$PROJECT/notes.txt" ]; then echo "notes.txt: still there"; else echo "notes.txt: DELETED"; fi
}

# last_run [AGENT] prints the newest run of the contract named AGENT (status lists oldest first), so another demo's
# run, or the always-on agent's restarts, in the same ledger are never taken for this act's.
last_run() {
  "$TEGO" status --all 2>/dev/null | awk -v n="${1:-}" '$1 ~ /^r-/ && (n == "" || $2 == n) {r = $1} END {print r}'
}

# run_id_in FILE prints the run id the agent printed about itself ("[agent] run id: r-..."), from a run's output.
run_id_in() {
  sed -n 's/^\[agent\] *run id: *\(r-[A-Za-z0-9-]*\).*/\1/p' "$1" | tail -n 1
}

# q quotes one argument for the shell text show evaluates.
q() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }
# qargs quotes each of its arguments (q), each after a space: the words the presenter passes on to a program.
qargs() { for a in "$@"; do printf ' %s' "$(q "$a")"; done; }

cmd_setup() {
  need_tego
  say "Setup: fake secrets, a fake home, a project, and the loopback sink on 127.0.0.1:$PORT"
  plant
  sink_up
  echo "stage:   $STAGE"
  echo "secrets: $SECRETS (fake)"
  echo "project: $PROJECT"
  echo "sink:    $SINK  (log: $STAGE/sink.log)"
  echo "tego:    $("$TEGO" version 2>/dev/null | head -n 1)"
}

cmd_without() {
  need_tego
  plant; sink_up; : >"$STAGE/sink.log"
  say "Act 1: the agent WITHOUT Tego"
  echo "(the agent is a script that does what a confused or prompt-injected agent might do)"
  show "cd '$PROJECT' && sh rogue.sh"
  sleep 0.3
  damage
}

cmd_with() {
  need_tego
  plant; sink_up; : >"$STAGE/sink.log"
  say "Act 2: the SAME agent under Tego. The contract it runs under:"
  show "grep -v '^#' '$PROJECT/agent.yaml'"
  say "Run it"
  # Whether the run was made is tego's own exit status (piped), not grep's: a tego that refused to start the run was
  # followed by an untouched machine and the refusals of an earlier run, as if this one had made them. Act 3 reads
  # stage/last-run, so a run that failed leaves none.
  rm -f "$STAGE/last-run"
  piped "cd '$PROJECT' && '$TEGO' run agent.yaml </dev/null 2>&1" "tee '$STAGE/run.out' | grep -v -E '^(warning|note|  fix:)|no price table'" ||
    die "the run failed (tego run exited $?): see its message above"
  sleep 0.3
  damage
  # The run id comes from the run's own output (the agent prints it); the newest run of this contract is the fallback.
  run=$(run_id_in "$STAGE/run.out")
  [ -n "$run" ] || run=$(last_run demo-guarded)
  [ -n "$run" ] && echo "$run" >"$STAGE/last-run"
  say "Every refusal, with the rule that made it"
  show "'$TEGO' events '$run' --kind refused 2>&1 | cut -c1-200"
}

cmd_why() {
  need_tego
  run=$(cat "$STAGE/last-run" 2>/dev/null || true)
  [ -n "$run" ] || die "no run yet: run './demo.sh with' first"
  say "Act 3: why. The last refusal, as the agent itself reads it in \$TEGO_REASON"
  show "'$TEGO' events '$run' --last"
  say "The record is a hash chain, anchored outside the run's reach. Verify it"
  show "'$TEGO' events '$run' --verify"
  say "Now change one word in a COPY of the record and verify again (it must fail)"
  # The copy is the record as tego reads it (--json prints its lines byte for byte), from wherever the machine config
  # puts the ledger: a ledger_root read out of the config by hand missed one written in quotes or with a comment.
  copy=$STAGE/tampered/$run
  rm -rf "$STAGE/tampered"; mkdir -p "$copy"
  if show "'$TEGO' events '$run' --json >'$copy/events.jsonl'"; then
    show "sed -i '0,/refused/s//allowed-/' '$copy/events.jsonl'"
    show "'$TEGO' events '$copy' --verify || echo '(exit '\$?': the edit is detected)'"
  else
    echo "(no copy of the record of $run: skipping the tamper step)"
  fi
}

cmd_dashboard() {
  command -v "$CONTROL" >/dev/null 2>&1 || die "tego-control is not on PATH. Build it (go build -o bin/tego-control ./cmd/tego-control) and put bin/ on PATH"
  say "Act 4: the dashboard. It prints its URL and opens it signed in (no browser opener: open the URL). Ctrl-C stops it"
  # Extra arguments go to the dashboard: with port 8484 busy, ./demo.sh dashboard --addr 127.0.0.1:8585
  show "$(q "$CONTROL") serve --open$(qargs "$@")"
}

# agent_dir makes stage/<name>/ (the project the real agent works in) and stage/<name>.yaml (its
# contract, outside the project: tego refuses a contract the agent could rewrite).
agent_contract() {
  name=$1; deny=$2
  mkdir -p "$STAGE/$name"
  xdg=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
  # Codex runs its tools through codex-code-mode-host, which sits next to the real codex binary.
  codexhost=
  if command -v codex >/dev/null 2>&1; then
    codexhost=$(dirname "$(readlink -f "$(command -v codex)")")
  fi
  sed -e "s|@@STAGE@@|$STAGE|g" -e "s|@@XDG@@|$xdg|g" -e "s|@@CODEXHOST@@|$codexhost|g" -e "s|# @@DENY_READ@@|$deny|" \
    "$HERE/contracts/$name.yaml" >"$STAGE/$name.yaml"
}

cmd_claude() {
  need_tego
  command -v claude >/dev/null 2>&1 || die "claude (Claude Code) is not on PATH"
  agent_contract claude-code '# no extra deny_read'
  mkdir -p "$STAGE/claude-code/.claude-state/tmp"
  if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ] && [ "$#" -eq 0 ]; then
    echo "demo.sh: Claude Code needs your login in the environment. With your subscription, run once (outside Tego):" >&2
    echo "    claude setup-token        # then: export CLAUDE_CODE_OAUTH_TOKEN=<the token it prints>" >&2
    echo "or export ANTHROPIC_API_KEY=<your key>. Without either, Claude Code shows its login screen and cannot log in." >&2
  fi
  say "Act 5a: Claude Code under Tego (your login from CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY)"
  show "cd '$STAGE/claude-code' && '$TEGO' compile '$STAGE/claude-code.yaml' 2>&1 | grep -E '^(warning|error)' || true"
  if [ "$#" -gt 0 ]; then
    show "cd '$STAGE/claude-code' && '$TEGO' run '$STAGE/claude-code.yaml' -- claude$(qargs "$@")"
  else
    show "cd '$STAGE/claude-code' && '$TEGO' run '$STAGE/claude-code.yaml'"
  fi
}

cmd_codex() {
  need_tego
  command -v codex >/dev/null 2>&1 || die "codex is not on PATH"
  deny=
  for f in auth.json config.toml history.jsonl sessions; do
    [ -e "$HOME/.codex/$f" ] && deny="$deny\"~/.codex/$f\", "
  done
  agent_contract codex "${deny:+deny_read: [${deny%, }]}"
  mkdir -p "$STAGE/codex/work/tmp" "$STAGE/codex-home"
  # Codex's own sandbox is off because Tego is the cage (docs/OPERATIONS.md, interactive Codex).
  cat >"$STAGE/codex-home/config.toml" <<'TOML'
model = "gpt-5"
sandbox_mode = "danger-full-access"
approval_policy = "never"
check_for_update_on_startup = false
[analytics]
enabled = false
[feedback]
enabled = false
[features]
plugins = false
remote_plugin = false
apps = false
shell_snapshot = false
TOML
  say "Act 5b: Codex under Tego (sign in with 'Provide your own API key' on its login screen)"
  show "cd '$STAGE/codex' && '$TEGO' compile '$STAGE/codex.yaml' 2>&1 | grep -E '^(warning|error)' || true"
  if [ "$#" -gt 0 ]; then
    show "cd '$STAGE/codex' && '$TEGO' run '$STAGE/codex.yaml' -- codex --no-daemon$(qargs "$@")"
  else
    show "cd '$STAGE/codex' && '$TEGO' run '$STAGE/codex.yaml'"
  fi
}

# always-on runs a small agent as a systemd --user service, restarted if it dies. Every pass it does a
# little work and tries a secret: the refusals pile up in the dashboard. The unit ends a run as
# examples/systemd/tego-agent@.service does: a crash or the hour's wall limit restarts it, a Stop from the
# dashboard or `tego stop` (143) leaves it stopped, and a refused start (125) is not retried.
cmd_always_on() {
  need_tego
  unit=$UNIT
  BUS=/run/user/$(id -u)   # the user manager's bus; the unit itself gets the caller's XDG_RUNTIME_DIR below
  case "${1:-start}" in
    start)
      # Its own folders (stage/always-on/...): the other acts' plant() clears project/, and under the shared one it
      # pulled the running service's out/ and secrets from under it.
      SECRETS=$STAGE/always-on/secrets HOMEISH=$STAGE/always-on/home PROJECT=$STAGE/always-on/project
      export SECRETS HOMEISH PROJECT
      sink_up
      plant
      cp "$HERE/agents/watcher.sh" "$PROJECT/watcher.sh"
      cp "$HERE/contracts/always-on.yaml" "$PROJECT/always-on.yaml"
      say "Act 5c: an agent that runs 24/7 under Tego (a systemd --user service, restarted on failure)"
      tegobin=$(command -v "$TEGO")
      # The command is printed one option to a line, as the presenter would type it (it was one line of some 700
      # characters): show evaluates the text it prints, and the shell joins a line ending in " \" to the next. The
      # stage's own paths are quoted values (q). What the unit takes from the caller's environment is printed by name,
      # --setenv=PATH="$PATH", which the evaluation expands to one word whatever it holds: printed as its value, a
      # presenter's PATH was a line of 600 characters. The XDG_RUNTIME_DIR=$BUS in front is for systemd-run alone; the
      # words after it are expanded before it applies, so --setenv=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" is the caller's.
      br=" \\
    "
      c="XDG_RUNTIME_DIR=$BUS systemd-run --user --unit=$(q "$unit") --collect"
      c="$c$br--working-directory=$(q "$PROJECT")"
      c="$c$br--setenv=SECRETS=$(q "$SECRETS")$br--setenv=PROJECT=$(q "$PROJECT")"
      for v in TEGO_CONFIG TEGO_TEST_CHAIN_ANCHOR TEGO_TEST_OWN_LOG_HOME XDG_RUNTIME_DIR PATH HOME; do
        eval "val=\${$v:-}"
        [ -n "$val" ] && c="$c$br--setenv=$v=\"\$$v\""
      done
      c="$c$br-p Restart=on-failure -p RestartSec=3 -p SuccessExitStatus=143 -p 'RestartPreventExitStatus=143 125'"
      c="$c$br-p KillMode=mixed -p TimeoutStopSec=40s -p StandardOutput=append:$(q "$STAGE/always-on.log")"
      c="$c$br-p StandardError=append:$(q "$STAGE/always-on.log")"
      show "$c$br$(q "$tegobin") run always-on.yaml"
      echo "watch it:  ./demo.sh always-on status"
      echo "its log:   $STAGE/always-on.log"
      echo "stop it:   ./demo.sh always-on stop"
      ;;
    status)
      show "XDG_RUNTIME_DIR=$BUS systemctl --user status $(q "$unit") --no-pager -n 5 || true"
      show "'$TEGO' status --all 2>&1 | grep -E 'RUN|always-on' | tail -n 5"
      ;;
    stop)
      show "XDG_RUNTIME_DIR=$BUS systemctl --user stop $(q "$unit") || true"
      ;;
    *) die "usage: demo.sh always-on [start|status|stop]" ;;
  esac
}

cmd_reset() {
  for pid in sink sockd stub; do
    [ -f "$STAGE/$pid.pid" ] && kill "$(cat "$STAGE/$pid.pid")" 2>/dev/null || true
  done
  XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user stop "$UNIT" 2>/dev/null || true
  rm -rf "$STAGE"
  echo "demo reset: the stage is removed and the sink is stopped."
}

sub=${1:-}
[ "$#" -gt 0 ] && shift
case "$sub" in
  setup) cmd_setup ;;
  without) cmd_without ;;
  with) cmd_with ;;
  why) cmd_why ;;
  dashboard) cmd_dashboard "$@" ;;
  claude) cmd_claude "$@" ;;
  codex) cmd_codex "$@" ;;
  always-on) cmd_always_on "$@" ;;
  tiers) . "$HERE/scenes/tiers.sh"; cmd_tiers ;;
  reset) cmd_reset ;;
  network) . "$HERE/scenes/network.sh"; cmd_network ;;
  proxy) . "$HERE/scenes/proxy.sh"; cmd_proxy ;;
  rules|rule|always|limits|deny-write|ask|approve|deny|reason-hook|receipt|presets|selftest|identity|doctor|features)
    . "$HERE/scenes/features.sh"
    case "$sub" in
      approve|deny) answer "$sub" ;;
      *) "cmd_$(printf %s "$sub" | tr - _)" "$@" ;;
    esac ;;
  *)
    echo "usage: demo.sh setup | without | with | why | dashboard [serve args] | claude [args] | codex [args] | always-on [start|status|stop] | tiers | network | proxy | reset" >&2
    echo "       demo.sh rules | rule read|write|command|net|process | always | limits | deny-write | ask | approve | deny" >&2
    echo "       demo.sh reason-hook | receipt | presets | selftest | identity | doctor | features" >&2
    exit 2 ;;
esac
