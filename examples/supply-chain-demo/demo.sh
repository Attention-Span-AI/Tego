#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The supply-chain demo, one command per step (RUNBOOK.md has the steps):
#   setup | check | dashboard | left | right | attacker | backup | proof | reset
# Every subcommand prints the command it runs before it runs it. Nothing real is read or sent: the secrets are
# fake files under the stage, the "attackers" are sink.py on 127.0.0.1, and the agent gets your login only: a copy of
# Codex's, or Claude Code's token from your environment. DEMO_AGENT=claude runs Claude Code instead of Codex.
#
#   setup      build both sides (fake homes, project copies, the agent's own folder), fill the contract, start the
#              three fake servers as systemd user units, start a fresh ledger
#   check      verify everything a take needs; prints READY only when all of it holds, else names each failure
#              and its fix and exits 1
#   dashboard  the dashboard (tego-control serve --open); extra arguments go to it (--addr 127.0.0.1:9000)
#   left       the agent under `tego watch` (recorded, nothing blocked); extra arguments go to the agent
#   right      the agent under `tego run` with the filled contract; extra arguments go to the agent
#   attacker   the two attacker logs side by side
#   backup     record a watched and an enforced run of the project's tests with no agent (the token ask is
#              denied for you), so the dashboard always has a take to show
#   proof      print what each side read and sent, and verify the record
#   reset      retake: fresh sides, the contract filled again, the ledger moved (the sides' Codex logins and the
#              servers are kept); `reset --stop` also stops the servers and removes the generated state
#
# Settings: demo.env (agent, ports, unit prefix, dashboard address, config, ledger, Codex login), overridable by
# environment. TEGO / TEGO_CONTROL name the binaries (default: bin/ of this checkout, else PATH).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
# shellcheck source=demo.env
. "$HERE/demo.env"

STAGE=$(readlink -m "${DEMO_STAGE:-$HERE}")   # made by setup, after it has checked where it is
LEFT_DIR=$STAGE/without
RIGHT_DIR=$STAGE/with
API_LOG=$STAGE/api.log

# The agent both sides run (DEMO_AGENT, demo.env): its contract, its own folder in each side (the agent's
# CODEX_HOME or CLAUDE_CONFIG_DIR), the hosts it talks to, the command that starts it, and how a person quits it.
case $DEMO_AGENT in
  codex)
    CONTRACT=codex-chatgpt AGENT_HOME=codex-home AGENT_NAME=Codex AGENT_QUIT=/quit
    AGENT_HOSTS="chatgpt.com auth.openai.com" AGENT_ARGV="codex --no-daemon" ;;
  claude)
    CONTRACT=claude-code AGENT_HOME=claude-home AGENT_NAME="Claude Code" AGENT_QUIT=/exit
    AGENT_HOSTS="api.anthropic.com" AGENT_ARGV="claude" ;;
  *) printf "demo.sh: DEMO_AGENT is '%s'; it must be codex or claude\n" "$DEMO_AGENT" >&2; exit 2 ;;
esac
FILLED=$RIGHT_DIR/$CONTRACT.filled.yaml
TEMPLATE=$HERE/contracts/$CONTRACT.yaml
CONTRACT_NAME=supply-chain-$CONTRACT

# The demo's own fake credentials. They say FAKE so the stealer sends only these, never a real value.
FAKE_SERVICE_TOKEN=svc_demo_FAKE_SERVICE_TOKEN_0000
FAKE_AWS=AKIA_FAKE_DEMO_SECRET_0000
FAKE_GITHUB=ghp_FAKE_DEMO_GITHUB_0000

# DEMO_OFFLINE=1 (demo.env) makes tego treat a host it cannot resolve as a warning: for rehearsing the script
# with no network. The agent itself needs the network, so a real take never sets it.
OFFLINE=
[ "${DEMO_OFFLINE:-0}" != 1 ] || OFFLINE=--offline

if [ -n "${TEGO:-}" ]; then TEGO_BIN=$TEGO
elif [ -x "$ROOT/bin/tego" ]; then TEGO_BIN=$ROOT/bin/tego
else TEGO_BIN=$(command -v tego 2>/dev/null || true); fi
if [ -n "${TEGO_CONTROL:-}" ]; then CONTROL_BIN=$TEGO_CONTROL
elif [ -x "$ROOT/bin/tego-control" ]; then CONTROL_BIN=$ROOT/bin/tego-control
else CONTROL_BIN=$(command -v tego-control 2>/dev/null || true); fi

# The user manager's runtime directory, for systemd-run and systemctl. A test harness points XDG_RUNTIME_DIR
# somewhere private for tego itself, so the manager's own is named separately.
SD_RUNTIME=${DEMO_SYSTEMD_RUNTIME:-/run/user/$(id -u)}

UNIT_LEFT=$DEMO_UNIT_PREFIX-sink-$DEMO_PORT_LEFT
UNIT_RIGHT=$DEMO_UNIT_PREFIX-sink-$DEMO_PORT_RIGHT
UNIT_API=$DEMO_UNIT_PREFIX-api-$DEMO_PORT_API
API_ADDR=127.0.0.1:$DEMO_PORT_API

say() { printf '\n== %s\n' "$*"; }
note() { printf '%s\n' "$*"; }
die() { printf 'demo.sh: %s\n' "$*" >&2; exit 1; }

# shq quotes one word the way a person would type it.
shq() {
  case $1 in
    '' | *[!A-Za-z0-9_@%+=:,./-]*) printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")" ;;
    *) printf %s "$1" ;;
  esac
}
# printcmd prints a command line, quoted.
printcmd() {
  printf '$'
  for a in "$@"; do printf ' %s' "$(shq "$a")"; done
  printf '\n'
}
# run prints a command, then runs it.
run() { printcmd "$@"; "$@"; }
# runsd is run for systemd's user manager.
runsd() { printcmd "$@"; env "XDG_RUNTIME_DIR=$SD_RUNTIME" "$@"; }
# runtego is run for the demo's tego, with the demo's machine config.
runtego() { printcmd "$TEGO_BIN" "$@"; env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" "$@"; }

# sed_esc escapes a value for the replacement half of an s||| command.
sed_esc() { printf %s "$1" | sed 's/[\\&|]/\\&/g'; }

port_open() {
  python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(0.5)
sys.exit(s.connect_ex(("127.0.0.1", int(sys.argv[1]))))' "$1"
}

wait_port() {
  i=0
  while ! port_open "$1"; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || return 1
    sleep 0.1
  done
}

unit_active() { env "XDG_RUNTIME_DIR=$SD_RUNTIME" systemctl --user is-active --quiet "$1" 2>/dev/null; }

# under A B: is path A the folder B or inside it? (both resolved, neither need exist)
under() {
  a=$(readlink -m "$1")
  b=$(readlink -m "$2")
  case "$a/" in "$b"/*) return 0 ;; esac
  return 1
}

# tego_homes lists the places tego keeps its own state: the invoking user's ~/.tego, whatever HOME says.
tego_homes() {
  printf '%s\n' "$HOME/.tego"
  pw=$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6 || true)
  [ -z "$pw" ] || [ "$pw/.tego" = "$HOME/.tego" ] || printf '%s\n' "$pw/.tego"
}

# stage_problem prints why the stage (or the config) cannot live where it is, or nothing when it can.
stage_problem() {
  case $STAGE in /) echo "the stage is /"; return ;; esac
  if under "$STAGE" "$DEMO_LEDGER"; then echo "the stage $STAGE is inside the ledger root $DEMO_LEDGER"; return; fi
  if under "$DEMO_LEDGER" "$STAGE/without" || under "$DEMO_LEDGER" "$STAGE/with"; then
    echo "the ledger root $DEMO_LEDGER is inside the stage"; return
  fi
  for h in $(tego_homes); do
    if under "$STAGE" "$h"; then echo "the stage $STAGE is inside tego's home $h"; return; fi
  done
}

need_tools() {
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || die "$t is not installed or not on PATH. $(tool_fix "$t")"
  done
}
tool_fix() {
  case $1 in
    codex) echo "Install Codex (https://learn.chatgpt.com/docs/quickstart) and sign in with ChatGPT, then run this again." ;;
    claude) echo "Install Claude Code (curl -fsSL https://claude.ai/install.sh | bash), then run this again." ;;
    notify-send) echo "Install it (sudo apt install libnotify-bin): without it a held request raises no desktop notice." ;;
    watch) echo "Install it (sudo apt install procps): the attacker panel needs it." ;;
    systemd-run) echo "This machine needs systemd with a user manager: the three fake servers run as user units." ;;
    python3) echo "Install python3: the fake servers, the project's tests and this script need it." ;;
    *) echo "Install it and run this again." ;;
  esac
}

need_tego() {
  [ -n "$TEGO_BIN" ] && [ -x "$TEGO_BIN" ] || die "tego is not built. Run: make build (in $ROOT)"
}

need_stage() {
  [ -f "$FILLED" ] && [ -d "$LEFT_DIR/proj" ] && [ -d "$RIGHT_DIR/proj" ] || die "the demo is not set up. Run: ./demo.sh setup"
}

# ---- the stage: two fake homes, two project copies, the contract, three servers, the ledger ----

# fill_contract prints the template with every placeholder filled. It fails when the agent or python3 is missing.
fill_contract() {
  agent_path=$(command -v "$DEMO_AGENT") || return 1
  py=$(command -v python3) || return 1
  agenthost=$(dirname "$(readlink -f "$agent_path")")
  pyreal=$(readlink -f "$py")
  # codex-chatgpt.yaml keeps the CODEX names (internal/check/inforce fills it by them too); claude-code.yaml has AGENT.
  sed -e "s|@@CODEXHOME@@|$(sed_esc "$RIGHT_DIR/$AGENT_HOME")|g" \
      -e "s|@@AGENTHOME@@|$(sed_esc "$RIGHT_DIR/$AGENT_HOME")|g" \
      -e "s|@@CODEXHOST@@|$(sed_esc "$agenthost")|g" \
      -e "s|@@RUNTIME@@|$(sed_esc "/run/user/$(id -u)")|g" \
      -e "s|@@DENY_SSH@@|$(sed_esc "$RIGHT_DIR/home/.ssh/")|g" \
      -e "s|@@DENY_TOKEN@@|$(sed_esc "$RIGHT_DIR/home/.config/telemetry/")|g" \
      -e "s|@@PYREAL@@|$(sed_esc "$pyreal")|g" \
      -e "s|@@APIADDR@@|$(sed_esc "$API_ADDR")|g" \
      "$TEMPLATE"
}

# write_contract writes the filled contract (mode 0644) and fails when a placeholder is left.
write_contract() {
  tmp=$FILLED.tmp
  fill_contract >"$tmp" || { rm -f "$tmp"; die "cannot fill the contract: $DEMO_AGENT and python3 must be on PATH"; }
  if grep -Eq '@@[A-Z_]+@@' "$tmp"; then
    rm -f "$tmp"
    die "the contract still has a placeholder after filling it: $(grep -Eo '@@[A-Z_]+@@' "$TEMPLATE" | sort -u | tr '\n' ' ')"
  fi
  chmod 644 "$tmp"
  mv "$tmp" "$FILLED"
  rm -f "$FILLED.bak"
  note "contract: $FILLED (filled from contracts/$CONTRACT.yaml)"
}

# lay_side NAME: the fake home and a fresh copy of the project. The agent's own folder is kept if it exists (Codex's
# login is in it); its settings are written again.
lay_side() {
  d=$STAGE/$1
  rm -rf "${d:?}/home" "${d:?}/proj" "${d:?}/backup.log"
  mkdir -p "$d/home/.ssh" "$d/home/.config/telemetry" "$d/$AGENT_HOME"
  printf 'FAKE-DEMO-KEY-not-a-real-private-key\n' >"$d/home/.ssh/id_rsa"
  chmod 600 "$d/home/.ssh/id_rsa"
  printf 'ghp_demo_FAKE_TOKEN_not_real_0000\n' >"$d/home/.config/telemetry/token"
  cp -r "$HERE/repo" "$d/proj"
  mkdir -p "$d/proj/tmp"
  # The agent's own approvals are off: tego is the cage.
  if [ "$DEMO_AGENT" = claude ]; then
    # Onboarding done and the project trusted, so the take opens on the prompt.
    printf '{"hasCompletedOnboarding": true, "theme": "dark", "projects": {"%s": {"hasTrustDialogAccepted": true}}}\n' "$d/proj" >"$d/$AGENT_HOME/.claude.json"
    printf '{"permissions": {"defaultMode": "bypassPermissions"}, "skipDangerousModePermissionPrompt": true}\n' >"$d/$AGENT_HOME/settings.json"
  else
    printf 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\ncheck_for_update_on_startup = false\n[analytics]\nenabled = false\n[tui]\nshow_tooltips = false\n[features]\nplugins = false\napps = false\nremote_plugin = false\nimage_generation = false\n' >"$d/$AGENT_HOME/config.toml"
  fi
}

copy_login() {
  cp "$DEMO_CODEX_AUTH" "$STAGE/$1/codex-home/auth.json"
  chmod 600 "$STAGE/$1/codex-home/auth.json"
}

# claude_login prints the name of the variable that holds Claude Code's login in this shell, or nothing. Claude Code's
# own /login is not used: it needs claude.ai, which the contract leaves out, and it would store the login in a side.
claude_login() {
  if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then echo CLAUDE_CODE_OAUTH_TOKEN
  elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then echo ANTHROPIC_API_KEY; fi
}

claude_login_fix() {
  echo "run claude setup-token once, then export CLAUDE_CODE_OAUTH_TOKEN=<the token it prints> (or ANTHROPIC_API_KEY) in the shell that runs left and right"
}

ensure_config() {
  if [ ! -f "$DEMO_CONFIG" ]; then
    printf 'version: 0\nledger_root: %s\n' "$DEMO_LEDGER" >"$DEMO_CONFIG"
    chmod 600 "$DEMO_CONFIG"
    note "config: $DEMO_CONFIG (new; ledger_root $DEMO_LEDGER)"
  fi
}

# rotate_ledger moves a ledger that holds runs to <ledger>.old-<time> (its .rule-changes journal goes with it),
# starts an empty one (mode 0700) and deletes all but the newest DEMO_KEEP_LEDGERS old ones.
rotate_ledger() {
  case $DEMO_LEDGER in '' | / | "$HOME") die "refusing to rotate the ledger '$DEMO_LEDGER'" ;; esac
  if [ -d "$DEMO_LEDGER" ] && [ -n "$(ls -A "$DEMO_LEDGER" 2>/dev/null)" ]; then
    old=$DEMO_LEDGER.old-$(date +%y%m%d-%H%M%S)
    run mv "$DEMO_LEDGER" "$old"
  fi
  mkdir -p "$DEMO_LEDGER"
  chmod 700 "$DEMO_LEDGER"
  note "ledger: $DEMO_LEDGER (empty, mode 0700)"
  n=0
  # ls -t is the newest-first order; the names are this script's own <ledger>.old-<date>, with no newline in them.
  # shellcheck disable=SC2012
  ls -dt "$DEMO_LEDGER".old-* 2>/dev/null | while IFS= read -r d; do
    n=$((n + 1))
    if [ "$n" -gt "$DEMO_KEEP_LEDGERS" ]; then rm -rf "$d"; echo "deleted the old ledger $d (keeping the newest $DEMO_KEEP_LEDGERS)"; fi
  done
}

# clear_state removes the generated state (without/, with/, api.log), and only what looks like this demo's own:
# a side without its proj/ and an agent's folder (codex-home/ or claude-home/) is somebody else's folder of the same name.
clear_state() {
  for d in "$LEFT_DIR" "$RIGHT_DIR"; do
    [ -e "$d" ] || continue
    if [ ! -d "$d/proj" ] || { [ ! -d "$d/codex-home" ] && [ ! -d "$d/claude-home" ]; }; then
      die "refusing to remove $d: it is not a demo side (it needs proj/ and codex-home/ or claude-home/)"
    fi
    rm -rf "$d"
  done
  rm -f "$API_LOG"
}

stop_units() {
  for u in "$UNIT_LEFT" "$UNIT_RIGHT" "$UNIT_API"; do
    env "XDG_RUNTIME_DIR=$SD_RUNTIME" systemctl --user stop "$u" 2>/dev/null || true
    env "XDG_RUNTIME_DIR=$SD_RUNTIME" systemctl --user reset-failed "$u" 2>/dev/null || true
  done
}

start_units() {
  py=$(command -v python3)
  for p in "$DEMO_PORT_LEFT" "$DEMO_PORT_RIGHT" "$DEMO_PORT_API"; do
    if port_open "$p"; then
      die "port $p is busy and it is not one of this demo's units. Stop what uses it (ss -ltnp 'sport = :$p') or choose another: DEMO_PORT_LEFT / DEMO_PORT_RIGHT / DEMO_PORT_API in demo.env, then run setup again"
    fi
  done
  : >"$LEFT_DIR/sink.log"
  : >"$RIGHT_DIR/sink.log"
  : >"$API_LOG"
  runsd systemd-run --user "--unit=$UNIT_LEFT" --collect -q -p "StandardOutput=append:$LEFT_DIR/sink.log" -p "StandardError=append:$LEFT_DIR/sink.log" "$py" "$HERE/sink.py" "$DEMO_PORT_LEFT"
  runsd systemd-run --user "--unit=$UNIT_RIGHT" --collect -q -p "StandardOutput=append:$RIGHT_DIR/sink.log" -p "StandardError=append:$RIGHT_DIR/sink.log" "$py" "$HERE/sink.py" "$DEMO_PORT_RIGHT"
  runsd systemd-run --user "--unit=$UNIT_API" --collect -q -E "SC_SERVICE_TOKEN=$FAKE_SERVICE_TOKEN" -p "StandardOutput=append:$API_LOG" -p "StandardError=append:$API_LOG" "$py" "$HERE/api.py" "$DEMO_PORT_API"
  for pair in "$UNIT_LEFT:$DEMO_PORT_LEFT:$LEFT_DIR/sink.log" "$UNIT_RIGHT:$DEMO_PORT_RIGHT:$RIGHT_DIR/sink.log" "$UNIT_API:$DEMO_PORT_API:$API_LOG"; do
    u=${pair%%:*}; rest=${pair#*:}; p=${rest%%:*}; l=${rest#*:}
    wait_port "$p" || die "$u did not start listening on 127.0.0.1:$p. Its log ($l) says:
$(tail -n 5 "$l" 2>/dev/null)"
  done
}

cmd_setup() {
  need_tools python3 "$DEMO_AGENT" systemd-run
  need_tego
  if [ "$DEMO_AGENT" = codex ]; then
    [ -f "$DEMO_CODEX_AUTH" ] || die "no Codex login at $DEMO_CODEX_AUTH. Sign in once with ChatGPT (run: codex) or set DEMO_CODEX_AUTH to your auth.json"
  fi
  prob=$(stage_problem)
  [ -z "$prob" ] || die "$prob. Choose another stage (DEMO_STAGE=...) or ledger (DEMO_LEDGER=...): a contract in either is not writable for the dashboard's rule edits"
  say "Setup: two sides, each with its own fake home, a project copy and $AGENT_NAME's own folder"
  mkdir -p "$STAGE"
  stop_units
  clear_state
  for s in without with; do
    lay_side "$s"
    [ "$DEMO_AGENT" != codex ] || copy_login "$s"
    note "side: $STAGE/$s (home, proj, $AGENT_HOME)"
  done
  write_contract
  ensure_config
  say "The ledger"
  rotate_ledger
  say "The three fake servers (systemd user units: $UNIT_LEFT, $UNIT_RIGHT, $UNIT_API)"
  start_units
  say "Done"
  note "left attacker  http://127.0.0.1:$DEMO_PORT_LEFT   log $LEFT_DIR/sink.log"
  note "right attacker http://127.0.0.1:$DEMO_PORT_RIGHT   log $RIGHT_DIR/sink.log"
  note "project API    http://$API_ADDR   log $API_LOG"
  [ "$DEMO_AGENT" != claude ] || [ -n "$(claude_login)" ] || note "before left and right: $(claude_login_fix)"
  note "next: ./demo.sh check"
}

# ---- check ----

BAD=0
ok() { printf 'ok    %s\n' "$*"; }
bad() {
  BAD=$((BAD + 1))
  printf 'FAIL  %s\n' "$1"
  printf '      fix: %s\n' "$2"
}

cmd_check() {
  say "Checking the demo (stage $STAGE)"
  tools_ok=1
  for t in python3 "$DEMO_AGENT" notify-send watch systemd-run; do
    if command -v "$t" >/dev/null 2>&1; then :; else bad "$t is not on PATH" "$(tool_fix "$t")"; tools_ok=0; fi
  done
  [ "$tools_ok" = 1 ] && ok "tools: python3, $DEMO_AGENT, notify-send, watch, systemd-run"
  command -v python3 >/dev/null 2>&1 || { echo; echo "$BAD problem(s); the rest needs python3. Fix it, then run: ./demo.sh check"; return 1; }

  # tego and tego-control: present, and built from this checkout
  if [ -z "$TEGO_BIN" ] || [ ! -x "$TEGO_BIN" ]; then
    bad "tego is not built ($ROOT/bin/tego)" "run: make build (in $ROOT)"
    TEGO_BIN=
  fi
  head=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)
  for pair in "tego:$TEGO_BIN" "tego-control:$CONTROL_BIN"; do
    name=${pair%%:*}; bin=${pair#*:}
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
      [ "$name" = tego ] || bad "tego-control is not built ($ROOT/bin/tego-control)" "run: make build (in $ROOT)"
      continue
    fi
    have=$("$bin" version 2>/dev/null | sed -n 's/^commit=//p' | head -n 1)
    if [ -z "$head" ]; then
      ok "$name version $have (this folder is not a git checkout, so it was not compared)"
    elif [ "$have" = "$head" ]; then
      ok "$name matches git HEAD (${head%"${head#????????}"})"
    elif [ -n "$have" ] && git -C "$ROOT" diff --quiet "$have" HEAD -- . ':(exclude)docs' ':(exclude)*.md' 2>/dev/null; then
      # Only docs and Markdown changed since the build (a merge's doc commits): the binary is the same code. An
      # unknown commit makes git diff fail, so it stays stale.
      ok "$name built from $(printf %.8s "$have"); only docs changed since"
    else
      bad "bin/$name is stale: it was built from $(printf %.8s "${have:-unknown}") and the checkout is at $(printf %.8s "$head")" "run: make build (in $ROOT)"
    fi
  done

  # the stage and the machine config
  prob=$(stage_problem)
  if [ -n "$prob" ]; then bad "$prob" "choose another stage (DEMO_STAGE) or ledger (DEMO_LEDGER) and run: ./demo.sh setup"; else ok "the stage is outside the ledger root and tego's home"; fi
  cfg_ok=1
  if [ ! -f "$DEMO_CONFIG" ]; then
    bad "the config $DEMO_CONFIG does not exist" "run: ./demo.sh setup"; cfg_ok=0
  else
    read -r cu cm <<EOF
$(stat -c '%u %a' "$DEMO_CONFIG")
EOF
    read -r du dm <<EOF
$(stat -c '%u %a' "$(dirname "$DEMO_CONFIG")")
EOF
    me=$(id -u)
    if { [ "$cu" != "$me" ] && [ "$cu" != 0 ]; } || [ $((0$cm & 022)) -ne 0 ]; then
      bad "the config $DEMO_CONFIG is untrusted (owner uid $cu, mode $cm)" "run: chmod 600 $DEMO_CONFIG   (and it must be yours)"; cfg_ok=0
    fi
    if { [ "$du" != "$me" ] && [ "$du" != 0 ]; } || [ $((0$dm & 022)) -ne 0 ]; then
      bad "the config's folder $(dirname "$DEMO_CONFIG") is untrusted (owner uid $du, mode $dm): tego skips a config there and would use the default ledger" "run: chmod go-w $(dirname "$DEMO_CONFIG")   or put the config in a private folder: DEMO_CONFIG=~/.config/tego-demo/tego-demo.yaml"; cfg_ok=0
    fi
    named=$(sed -n 's/^ledger_root:[[:space:]]*//p' "$DEMO_CONFIG" | head -n 1)
    if [ "$named" != "$DEMO_LEDGER" ]; then
      bad "the config names the ledger '${named:-none}', not $DEMO_LEDGER" "edit ledger_root in $DEMO_CONFIG, or set DEMO_LEDGER to it"; cfg_ok=0
    fi
    [ "$cfg_ok" = 1 ] && ok "the config and its folder are trusted; ledger $DEMO_LEDGER"
  fi
  if [ ! -d "$DEMO_LEDGER" ]; then bad "the ledger $DEMO_LEDGER does not exist" "run: ./demo.sh setup (or ./demo.sh reset)"; fi
  # Only a trusted config: an untrusted one would make tego answer about another ledger.
  if [ "$cfg_ok" = 1 ]; then
    live=$(live_runs)
    if [ -n "$live" ]; then
      bad "$(printf '%s\n' "$live" | wc -l | tr -d ' ') run(s) of this demo are still running ($(printf '%s\n' "$live" | cut -d' ' -f1 | tr '\n' ' ' | sed 's/ *$//')): a take now would write into the ledger that reset moves" "quit both $AGENT_NAME windows ($AGENT_QUIT), then: ./demo.sh reset"
    fi
  fi

  # doctor: landlock or better, and no config complaint
  if [ -n "$TEGO_BIN" ]; then
    doc=$(env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" doctor --require landlock 2>&1) && doc_rc=0 || doc_rc=$?
    if printf '%s' "$doc" | grep -q 'config-untrusted'; then
      bad "tego doctor refuses the machine config: $(printf '%s' "$doc" | grep 'config-untrusted' | head -n 1 | cut -c1-200)" "fix the config's owner and mode as above"
    elif [ "$doc_rc" -ne 0 ]; then
      bad "tego doctor: this machine offers no tier landlock or better" "$(printf '%s' "$doc" | grep -E 'FAIL|missing|fix' | head -n 3 | cut -c1-200 | tr '\n' ' ')"
    else
      ok "tego doctor: tier landlock or better is available"
    fi
  fi

  # the stage, the units and the ports
  if [ ! -f "$FILLED" ] || [ ! -d "$LEFT_DIR/proj" ] || [ ! -d "$RIGHT_DIR/proj" ]; then
    bad "the demo is not set up under $STAGE" "run: ./demo.sh setup"
  else
    ok "both sides exist under $STAGE"
    if [ "$DEMO_AGENT" = claude ]; then
      if [ -n "$(claude_login)" ]; then ok "Claude Code's login is in $(claude_login) (check it in the shell that runs left and right)"
      else bad "no Claude Code login in this shell (CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY)" "$(claude_login_fix)"; fi
    fi
    for s in without with; do
      [ "$DEMO_AGENT" = codex ] || break
      a=$STAGE/$s/codex-home/auth.json
      if [ ! -s "$a" ]; then
        bad "no Codex login in $a" "run: ./demo.sh setup (it copies $DEMO_CODEX_AUTH)"
      elif command -v codex >/dev/null 2>&1; then
        if env -i "PATH=$PATH" "HOME=$STAGE/$s/home" "CODEX_HOME=$STAGE/$s/codex-home" timeout 20 codex login status >/dev/null 2>&1; then
          ok "$s: Codex is signed in (codex login status, no model call)"
        else
          bad "$s: Codex is not signed in with the copied login (the login may have been refreshed since it was copied)" "run: ./demo.sh setup again (it copies the current login), or sign in once: CODEX_HOME=$STAGE/$s/codex-home codex login"
        fi
      fi
    done
    for f in "$LEFT_DIR/home/.ssh/id_rsa" "$RIGHT_DIR/home/.ssh/id_rsa" "$LEFT_DIR/home/.config/telemetry/token" "$RIGHT_DIR/home/.config/telemetry/token"; do
      [ -s "$f" ] || bad "the fake credential $f is missing" "run: ./demo.sh reset"
    done
  fi
  for pair in "$UNIT_LEFT:$DEMO_PORT_LEFT" "$UNIT_RIGHT:$DEMO_PORT_RIGHT" "$UNIT_API:$DEMO_PORT_API"; do
    u=${pair%%:*}; p=${pair#*:}
    if unit_active "$u"; then
      if port_open "$p"; then ok "$u is running and 127.0.0.1:$p answers"
      else bad "$u is running but nothing answers on 127.0.0.1:$p" "run: ./demo.sh reset"; fi
    elif port_open "$p"; then
      bad "port $p is busy and $u is not running (something else holds it)" "stop what uses it (ss -ltnp 'sport = :$p') or choose another port in demo.env and run: ./demo.sh setup"
    else
      bad "$u is not running" "run: ./demo.sh reset (or ./demo.sh setup)"
    fi
  done
  dport=${DEMO_DASH_ADDR##*:}
  if port_open "$dport" && dashboard_is_ours "$dport"; then
    ok "the demo's dashboard is running (reset keeps it; it follows the new ledger)"
  elif port_open "$dport"; then
    bad "something already listens on the dashboard address $DEMO_DASH_ADDR (a stale dashboard?)" "stop it (Ctrl-C in its terminal, or: ss -ltnp 'sport = :$dport'), or start another: ./demo.sh dashboard --addr 127.0.0.1:<port>"
  else
    ok "no dashboard is running on $DEMO_DASH_ADDR"
  fi

  # the network: the contract names the agent's hosts, which tego resolves when it compiles and runs
  if [ -z "$OFFLINE" ]; then
    dns_ok=1
    for h in $AGENT_HOSTS; do
      if getent hosts "$h" >/dev/null 2>&1; then :; else
        bad "$h does not resolve ($AGENT_NAME needs it, and the contract allows it)" "connect to the network; to rehearse the script with none: DEMO_OFFLINE=1"
        dns_ok=0
      fi
    done
    [ "$dns_ok" = 1 ] && ok "$AGENT_NAME's hosts resolve ($AGENT_HOSTS)"
  fi

  # the contract: it compiles, and it is the one the template makes
  if [ -f "$FILLED" ] && [ -n "$TEGO_BIN" ] && command -v "$DEMO_AGENT" >/dev/null 2>&1; then
    # An untrusted config makes compile fail for the config, not the contract: say so once, above.
    if [ "$cfg_ok" != 1 ]; then
      echo "      (the filled contract was not compiled: fix the config above first)"
    elif cout=$(cd "$RIGHT_DIR/proj" && env "TEGO_CONFIG=$DEMO_CONFIG" "PATH=$PATH" "$TEGO_BIN" compile ${OFFLINE:+"$OFFLINE"} "$FILLED" 2>&1 >/dev/null); then
      ok "the filled contract compiles"
    else
      why=$(printf '%s\n' "$cout" | grep -E 'error' | head -n 2 | cut -c1-300 | tr '\n' ' ' | sed 's/ *$//')
      [ -n "$why" ] || why=$(printf '%s\n' "$cout" | grep -v '^[[:space:]]*$' | head -n 2 | cut -c1-300 | tr '\n' ' ' | sed 's/ *$//')
      [ -n "$why" ] || why="tego compile failed and printed nothing"
      bad "the filled contract does not compile: $why" "run: ./demo.sh reset (it fills the contract again from the template)"
    fi
    fresh=$(fill_contract 2>/dev/null | sha256sum | cut -d' ' -f1)
    live=$(sha256sum "$FILLED" | cut -d' ' -f1)
    if [ "$fresh" = "$live" ]; then
      ok "the live contract equals a fresh fill of the template (the token ask is in it)"
    else
      bad "the contract was changed (by Never allow?): $FILLED differs from the template filled again" "run: ./demo.sh reset"
    fi
  fi

  echo
  if [ "$BAD" -eq 0 ]; then
    echo READY
    return 0
  fi
  echo "$BAD problem(s). Fix them, then run: ./demo.sh check"
  return 1
}

# dashboard_is_ours PORT: is the program listening on 127.0.0.1:PORT this demo's dashboard, a tego-control serve
# that reads the demo's ledger (TEGO_CONFIG=$DEMO_CONFIG in its environment, or --ledger $DEMO_LEDGER)? It is the same
# user's process, so ss names its pid and /proc shows its command line and environment. A running dashboard follows
# the ledger reset moves aside and starts again, so it can stay up across a retake. The body is a subshell, so its
# variables do not leak into the script; a relative --ledger or TEGO_CONFIG is the dashboard's, read against its cwd.
dashboard_is_ours() (
  command -v ss >/dev/null 2>&1 || return 1
  dpid=$(ss -ltnpH "sport = :$1" 2>/dev/null | grep -Eo 'pid=[0-9]+' | head -n 1 | cut -d= -f2)
  [ -n "$dpid" ] && [ -r "/proc/$dpid/cmdline" ] || return 1
  dargs=$(tr '\0' '\n' <"/proc/$dpid/cmdline" 2>/dev/null) || return 1
  case $(basename "$(printf '%s\n' "$dargs" | head -n 1)") in tego-control) ;; *) return 1 ;; esac
  printf '%s\n' "$dargs" | grep -qx serve || return 1
  dcwd=$(readlink "/proc/$dpid/cwd" 2>/dev/null) || dcwd=
  # --ledger names the ledger outright; any other ledger is not the demo's, whatever its config says
  dled=$(printf '%s\n' "$dargs" | awk 'p == "--ledger" {print; exit} /^--ledger=/ {sub(/^--ledger=/, ""); print; exit} {p = $0}')
  if [ -n "$dled" ]; then
    [ "$(readlink -m "$(in_dir "$dcwd" "$dled")")" = "$(readlink -m "$DEMO_LEDGER")" ]
    return
  fi
  dcfg=$(tr '\0' '\n' <"/proc/$dpid/environ" 2>/dev/null | sed -n 's/^TEGO_CONFIG=//p' | head -n 1)
  [ -n "$dcfg" ] && [ "$(readlink -m "$(in_dir "$dcwd" "$dcfg")")" = "$(readlink -m "$DEMO_CONFIG")" ]
)

# in_dir DIR PATH: PATH as an absolute path, a relative one read against DIR (when DIR is known).
in_dir() {
  case $2 in
    /*) printf '%s\n' "$2" ;;
    *) if [ -n "$1" ]; then printf '%s/%s\n' "$1" "$2"; else printf '%s\n' "$2"; fi ;;
  esac
}

# ---- the terminals ----

# opt_env prints NAME=value for the optional variables a desktop session or a test harness needs, one per line.
opt_env() {
  for v in COLORTERM USER LOGNAME SHELL TZ LANGUAGE LC_ALL XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS DISPLAY WAYLAND_DISPLAY XAUTHORITY; do
    eval "val=\${$v:-}"
    [ -z "$val" ] || printf '%s=%s\n' "$v" "$val"
  done
  env | grep -E '^TEGO_[A-Z0-9_]+=' | grep -Ev '^TEGO_(CONFIG|CONTROL)=' || true
}

# side_command SIDE CMD...: sets SIDE_CMD to `env -i` with only the fake world of SIDE (and what a terminal needs
# to show a window and find tego), then CMD. No variable of your own shell gets in.
side_command() {
  side=$1; shift
  case $side in without) sink=$DEMO_PORT_LEFT ;; *) sink=$DEMO_PORT_RIGHT ;; esac
  extra=$(opt_env)
  # The agent's own folder; for Claude Code also its login, the one variable of your shell that gets in.
  if [ "$DEMO_AGENT" = claude ]; then
    agent_env="CLAUDE_CONFIG_DIR=$STAGE/$side/claude-home
DISABLE_AUTOUPDATER=1
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"
    login=$(claude_login)
    if [ -n "$login" ]; then
      eval "val=\${$login}"
      agent_env="$agent_env
$login=$val"
    fi
  else
    agent_env="CODEX_HOME=$STAGE/$side/codex-home"
  fi
  oldifs=$IFS
  IFS='
'
  set -f
  # $agent_env and $extra are one word per line: IFS is a newline and globbing is off.
  # shellcheck disable=SC2086
  set -- env -i \
    "PATH=$(dirname "$TEGO_BIN"):$PATH" "HOME=$STAGE/$side/home" $agent_env \
    "SC_SINK=http://127.0.0.1:$sink" "SC_API=http://$API_ADDR" \
    "SERVICE_TOKEN=$FAKE_SERVICE_TOKEN" "AWS_SECRET_ACCESS_KEY=$FAKE_AWS" "GITHUB_TOKEN=$FAKE_GITHUB" \
    "TEGO_CONFIG=$DEMO_CONFIG" "LANG=${LANG:-C.UTF-8}" "TERM=${TERM:-xterm-256color}" \
    $extra "$@"
  set +f
  IFS=$oldifs
  # A function's "$@" is its own: hand the words back as one string the caller turns into "$@" with
  #   eval "set -- $SIDE_CMD"
  SIDE_CMD=
  for a in "$@"; do SIDE_CMD="$SIDE_CMD $(shq "$a")"; done
  SIDE_DIR=$STAGE/$side/proj
}

# launch prints the command and replaces this shell with it, in the side's project folder.
# DEMO_QUIET=1 leaves your desktop variables (user name, display, session bus) and the long PATH out of the
# printed line; the command that runs is the same.
launch() {
  printf '$ cd %s &&' "$(shq "$SIDE_DIR")"
  for a in "$@"; do
    # a real login is never printed
    case $a in CLAUDE_CODE_OAUTH_TOKEN=*|ANTHROPIC_API_KEY=*) a="${a%%=*}=..." ;; esac
    if [ "${DEMO_QUIET:-0}" = 1 ]; then
      case $a in
        USER=*|LOGNAME=*|SHELL=*|XDG_RUNTIME_DIR=*|DBUS_SESSION_BUS_ADDRESS=*|DISPLAY=*|WAYLAND_DISPLAY=*|XAUTHORITY=*) continue ;;
        PATH=*) a='PATH=...' ;;
      esac
    fi
    printf ' %s' "$(shq "$a")"
  done
  printf '\n'
  cd "$SIDE_DIR"
  exec "$@"
}

need_login() {
  [ "$DEMO_AGENT" != claude ] || [ -n "$(claude_login)" ] || die "no Claude Code login in this shell: $(claude_login_fix)"
}

cmd_left() {
  need_stage; need_tego; need_tools "$DEMO_AGENT"; need_login
  # shellcheck disable=SC2086 # AGENT_ARGV is the agent's command, split into its words
  side_command without "$TEGO_BIN" watch --record full -- $AGENT_ARGV "$@"
  eval "set -- $SIDE_CMD"
  launch "$@"
}

cmd_right() {
  need_stage; need_tego; need_tools "$DEMO_AGENT"; need_login
  # The agent's screen wipes any warning printed here, so a changed contract stops the start instead.
  if contract_changed; then
    if [ "${DEMO_FORCE:-0}" = 1 ]; then
      note "warning: the contract was changed (by Never allow?); DEMO_FORCE=1 starts it anyway, and the token read will be refused without asking"
    else
      die "the contract was changed (by Never allow?): $FILLED differs from the template filled again, so the token read would be refused without asking and the 0:15 approval never comes. Run ./demo.sh reset first (DEMO_FORCE=1 ./demo.sh right starts it anyway)"
    fi
  fi
  # shellcheck disable=SC2086 # AGENT_ARGV is the agent's command, split into its words
  side_command with "$TEGO_BIN" run ${OFFLINE:+"$OFFLINE"} "$FILLED" -- $AGENT_ARGV "$@"
  eval "set -- $SIDE_CMD"
  launch "$@"
}

cmd_dashboard() {
  [ -n "$CONTROL_BIN" ] && [ -x "$CONTROL_BIN" ] || die "tego-control is not built. Run: make build (in $ROOT)"
  need_stage
  say "The dashboard: it opens in your browser signed in (no browser opener: open the printed link). Ctrl-C stops it"
  printcmd env "TEGO_CONFIG=$DEMO_CONFIG" "$CONTROL_BIN" serve --open --addr "$DEMO_DASH_ADDR" "$@"
  exec env "TEGO_CONFIG=$DEMO_CONFIG" "$CONTROL_BIN" serve --open --addr "$DEMO_DASH_ADDR" "$@"
}

cmd_attacker() {
  need_stage; need_tools watch
  panel="echo '== LEFT attacker =='; tail -n 4 $(shq "$LEFT_DIR/sink.log"); echo; echo '== RIGHT attacker =='; tail -n 4 $(shq "$RIGHT_DIR/sink.log")"
  printcmd watch -t -n 1 "$panel"
  exec watch -t -n 1 "$panel"
}

# ---- backup: a deterministic pair of runs, no agent ----

# run_id_of FILE prints the run id from the line `tego run` / `tego watch` prints before the command starts.
run_id_of() {
  grep -E '^tego (run|watch):|recorded as run' "$1" 2>/dev/null | grep -Eo '(^|[^A-Za-z0-9-])r-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+' | grep -Eo 'r-.*' | head -n 1
}

# config_trusted: would tego read $DEMO_CONFIG, and does it name $DEMO_LEDGER? tego skips a config that is not the
# user's (or root's) or that sits in, or is, a group- or world-writable file or folder, and then reads the default
# ledger: asking it about runs would then answer about another ledger than the demo's.
config_trusted() {
  [ -f "$DEMO_CONFIG" ] || return 1
  ct_me=$(id -u)
  for ct_f in "$DEMO_CONFIG" "$(dirname "$DEMO_CONFIG")"; do
    ct_um=$(stat -c '%u %a' "$ct_f" 2>/dev/null) || return 1
    ct_u=${ct_um%% *}; ct_m=${ct_um#* }
    [ "$ct_u" = "$ct_me" ] || [ "$ct_u" = 0 ] || return 1
    [ $((0$ct_m & 022)) -eq 0 ] || return 1
  done
  [ "$(sed -n 's/^ledger_root:[[:space:]]*//p' "$DEMO_CONFIG" | head -n 1)" = "$DEMO_LEDGER" ]
}

# LIVE_RUNS reads `tego status --all --json` on stdin and prints `<run-id> <agent> <state>` for each run whose
# launcher still holds it (lock_held) and that is this demo's: the contract's (RIGHT, argv[1]) or a `tego watch`
# one (LEFT, agent watch-*), as proof tells them apart. Any other agent on the machine never blocks the demo.
# shellcheck disable=SC2016 # Python source, not shell
LIVE_RUNS='
import json, sys
try:
    runs = json.load(sys.stdin).get("runs") or []
except Exception:
    runs = []
for r in runs:
    agent = str(r.get("agent", ""))
    if r.get("lock_held") is True and (agent == sys.argv[1] or agent.startswith("watch-")):
        print(r.get("run", "?"), agent, "paused" if r.get("paused") else r.get("state", "?"))
'

# live_runs prints the demo's runs that are still running, one per line (LIVE_RUNS). It prints nothing, and never
# fails, when it cannot tell: no tego, no trusted config, no ledger, no python3, or status printed no report.
live_runs() {
  [ -n "$TEGO_BIN" ] && [ -x "$TEGO_BIN" ] && [ -d "$DEMO_LEDGER" ] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  config_trusted || return 0
  { env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" status --all --json 2>/dev/null || true; } \
    | python3 -I -c "$LIVE_RUNS" "$CONTRACT_NAME" 2>/dev/null || true
}

# contract_changed: is the filled contract other than a fresh fill of the template (Never allow edits it in place)?
# It answers no when the template cannot be filled (no agent or python3), so it never stops a start on its own.
contract_changed() {
  [ -f "$FILLED" ] || return 1
  fill_contract >/dev/null 2>&1 || return 1
  [ "$(fill_contract 2>/dev/null | sha256sum | cut -d' ' -f1)" != "$(sha256sum "$FILLED" | cut -d' ' -f1)" ]
}

# shellcheck disable=SC2120 # the "$@" in cmd_backup is the side command it sets itself, not arguments
cmd_backup() {
  need_stage; need_tego; need_tools python3
  fails=0
  say "Backup, LEFT: the project's tests under tego watch (nothing blocked)"
  side_command without "$TEGO_BIN" watch --record full -- python3 -m unittest -v
  eval "set -- $SIDE_CMD"
  printf '$ cd %s &&' "$(shq "$SIDE_DIR")"; for a in "$@"; do printf ' %s' "$(shq "$a")"; done; printf '\n'
  (cd "$SIDE_DIR" && "$@" </dev/null >"$LEFT_DIR/backup.log" 2>&1) && lrc=0 || lrc=$?
  left_run=$(run_id_of "$LEFT_DIR/backup.log")
  grep -E '^\[telemetry_helper\]|^Ran |^OK|^FAILED' "$LEFT_DIR/backup.log" | sed 's/^/  /' || true
  [ "$lrc" -eq 0 ] || { echo "FAIL  the watched tests did not pass (exit $lrc); see $LEFT_DIR/backup.log"; fails=$((fails + 1)); }

  say "Backup, RIGHT: the same tests under tego run; the token ask is denied for you"
  side_command with "$TEGO_BIN" run ${OFFLINE:+"$OFFLINE"} "$FILLED" -- python3 -m unittest -v
  eval "set -- $SIDE_CMD"
  printf '$ cd %s &&' "$(shq "$SIDE_DIR")"; for a in "$@"; do printf ' %s' "$(shq "$a")"; done; printf '\n'
  (cd "$SIDE_DIR" && exec "$@" </dev/null >"$RIGHT_DIR/backup.log" 2>&1) &
  pid=$!
  right_run=
  denied=0
  i=0
  while kill -0 "$pid" 2>/dev/null; do
    [ -n "$right_run" ] || right_run=$(run_id_of "$RIGHT_DIR/backup.log")
    if [ -n "$right_run" ]; then
      for id in $(env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" ask "$right_run" 2>/dev/null | grep -Eo 'q-[a-z0-9]+' | sort -u); do
        if env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" deny "$right_run" "$id" >/dev/null 2>&1; then
          denied=$((denied + 1)); echo "  denied the ask $id (the token read)"
        fi
      done
    fi
    i=$((i + 1))
    if [ "$i" -gt 600 ]; then kill "$pid" 2>/dev/null || true; echo "FAIL  the enforced run did not end in 60 s"; fails=$((fails + 1)); break; fi
    sleep 0.1
  done
  wait "$pid" && rrc=0 || rrc=$?
  [ -n "$right_run" ] || right_run=$(run_id_of "$RIGHT_DIR/backup.log")
  grep -E '^\[telemetry_helper\]|^Ran |^OK|^FAILED|^tego' "$RIGHT_DIR/backup.log" | fold -s -w 150 | sed 's/^/  /' || true
  [ "$rrc" -eq 0 ] || { echo "FAIL  the enforced tests did not pass (exit $rrc); see $RIGHT_DIR/backup.log"; fails=$((fails + 1)); }
  [ "$denied" -ge 1 ] || { echo "FAIL  no ask appeared for the token read, so there was nothing to deny"; fails=$((fails + 1)); }

  say "Backup result"
  lcount=$(grep -c 'reached the sink' "$LEFT_DIR/sink.log" 2>/dev/null || true)
  rcount=$(grep -c 'reached the sink' "$RIGHT_DIR/sink.log" 2>/dev/null || true)
  echo "LEFT  run ${left_run:-?}: tests exit $lrc, the attacker received ${lcount:-0} request(s)"
  echo "RIGHT run ${right_run:-?}: tests exit $rrc, the attacker received ${rcount:-0} request(s), $denied ask(s) denied"
  [ "${lcount:-0}" -ge 1 ] || { echo "FAIL  the watched side never reached its attacker"; fails=$((fails + 1)); }
  [ "${rcount:-0}" -eq 0 ] || { echo "FAIL  the enforced side reached its attacker"; fails=$((fails + 1)); }
  # The take starts with empty attacker panels.
  if [ "$DEMO_BACKUP_KEEP_LOGS" = 1 ]; then
    echo "(DEMO_BACKUP_KEEP_LOGS=1: the attacker logs are kept)"
  else
    : >"$LEFT_DIR/sink.log"
    : >"$RIGHT_DIR/sink.log"
    echo "(the attacker logs are cleared, so the take starts empty; the two runs stay in the dashboard)"
  fi
  [ "$fails" -eq 0 ] || exit 1
}

# ---- proof ----

# PROOF_ROWS formats `tego events` tables read on stdin: argv is the stage, the mode (refused: the enforced run's
# refusals; watched: the watched run's events), the attacker's port and the agent's name. It keeps only the attack's rows: a refusal by a
# deny_read or ask_read entry or a live block, the key or token path, a send to the attacker's port. It prints seq,
# verdict, rule and detail with the stage folder shortened to <stage>, never cut, then how many rows there were in
# all. A row splits on the table's separator, two spaces: the rule is the text up to the first such gap after the
# verdict and the detail all the rest, so a cell that held two spaces in a row would print split at them, but the key's
# path, the token's and the port stay in the detail and the attack row is never dropped.
# shellcheck disable=SC2016 # Python source, not shell
PROOF_ROWS='
import re, sys
stage, mode, port, agent = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
to_port = re.compile(":" + re.escape(port) + "([^0-9]|$)")
row = re.compile(r"^(\d+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(.+?)(?:\s{2,}(.*))?$")
kept, total = [], 0
for line in sys.stdin.read().splitlines():
    m = row.match(line.rstrip())
    if not m:
        continue
    total += 1
    seq, verdict, rule, detail = m.group(1), m.group(2), m.group(3).strip(), (m.group(4) or "").strip()
    secret = "/home/.ssh/id_rsa" in detail or "/home/.config/telemetry/token" in detail
    if mode == "refused":
        keep = rule.startswith(("fs.deny_read[", "fs.ask_read[", "live.block[")) or secret or bool(to_port.search(detail))
    else:
        keep = secret or bool(to_port.search(detail))
    if keep:
        kept.append([seq, verdict, rule.replace(stage, "<stage>"), detail.replace(stage, "<stage>")])
if kept:
    head = ["SEQ", "VERDICT", "RULE", "DETAIL"]
    w = [max(len(r[i]) for r in kept + [head]) for i in range(3)]
    for r in [head] + kept:
        print("  ".join(c.ljust(w[i]) for i, c in enumerate(r[:3])) + "  " + r[3])
else:
    print("(none of the attack: no read of the key or token and no send to port " + port + " in this run)")
rest = total - len(kept)
if mode == "refused":
    if rest > 0:
        print("%d refusals in all (the rest are not the attack: %s\x27s own connections and any command the take refused; see the dashboard Logs)" % (total, agent))
    else:
        print("%d refusals in all" % total)
else:
    print("%d recorded events in all (the rest are the run\x27s ordinary work; see the dashboard Logs)" % total)
'

# pick_run RUNS PATTERN [EVENTS ARGS...] prints the first run of RUNS (ids one per line, newest first) whose
# `tego events <run> ARGS` output matches the extended regex PATTERN; when none does, the first run prefixed with "!"
# (the caller says it fell back); nothing for no runs.
pick_run() {
  runs=$1 pat=$2
  shift 2
  for r in $runs; do
    if env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" events "$r" "$@" 2>/dev/null | grep -Eq "$pat"; then
      printf '%s\n' "$r"
      return 0
    fi
  done
  first=$(printf '%s\n' "$runs" | sed -n '1p')
  [ -z "$first" ] || printf '!%s\n' "$first"
}

# other_runs WHAT RUNS CHOSEN prints, on one line, the ids of RUNS other than CHOSEN, newest first; nothing when
# there are none.
other_runs() {
  rest=$(printf '%s\n' "$2" | grep -vx -- "$3" | tr '\n' ' ' | sed 's/ *$//')
  [ -z "$rest" ] || note "(other $1 runs in this ledger, newest first: $rest)"
}

cmd_proof() {
  need_stage; need_tego; need_tools python3
  # A sink logs "listening" when it starts and "reached the sink" for each request it receives.
  if grep -q 'reached the sink' "$LEFT_DIR/sink.log" 2>/dev/null && ! grep -q 'reached the sink' "$RIGHT_DIR/sink.log" 2>/dev/null; then
    say "The attacker logs: left received, right did not"
  else
    say "The attacker logs"
  fi
  for f in "$LEFT_DIR/sink.log" "$RIGHT_DIR/sink.log"; do
    printcmd cat "$f"; cat "$f"
    if [ ! -s "$f" ]; then echo "(empty: nothing reached it since the last reset or backup)"
    elif ! grep -q 'reached the sink' "$f"; then echo "(nothing reached it)"; fi
  done
  say "Every run in the ledger"
  runtego status --all
  # The take's runs: status --all lists oldest first, and a retake or a stray start can leave a newer run that saw
  # none of the attack. So the right is the newest enforced run whose record holds the token's ask or an ask_read
  # refusal, the left the newest watched run that read the key; each falls back to the newest of its side.
  all=$(env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" status --all 2>/dev/null)
  right_runs=$(printf '%s\n' "$all" | awk -v n="$CONTRACT_NAME" '$1 ~ /^r-/ && $2 == n {r[++k]=$1} END {for (i = k; i > 0; i--) print r[i]}')
  left_runs=$(printf '%s\n' "$all" | awk '$1 ~ /^r-/ && $2 ~ /^watch-/ {r[++k]=$1} END {for (i = k; i > 0; i--) print r[i]}')
  right_run=$(pick_run "$right_runs" 'telemetry/token|fs\.ask_read\[' --kind ask --kind refused)
  left_run=$(pick_run "$left_runs" '/home/\.ssh/id_rsa')
  right_head="the take's enforced run ${right_run#!}: the newest with the token's ask"
  printf '%s\n' "$right_run" | grep -q '^!' && right_head="the latest enforced run ${right_run#!}; no enforced run recorded the token's ask"
  left_head="the take's watched run ${left_run#!}: the newest that read the key"
  left_what="the key was read, the sends were observed"
  if printf '%s\n' "$left_run" | grep -q '^!'; then
    left_head="the latest watched run ${left_run#!}; no watched run read the key"
    left_what="what it recorded of the attack"
  fi
  right_run=${right_run#!}
  left_run=${left_run#!}
  # the stage as its user reads it: ~ for the home, never the user name
  case $STAGE in "$HOME"/*) stage_show="~${STAGE#"$HOME"}" ;; *) stage_show=$STAGE ;; esac
  if [ -n "$right_run" ]; then
    say "RIGHT ($right_head): what Tego refused of the attack"
    other_runs "enforced" "$right_runs" "$right_run"
    printf '$ %s events %s --kind refused   (the attack rows: the key, the token, port %s; <stage> is %s)\n' "$(shq "$TEGO_BIN")" "$right_run" "$DEMO_PORT_RIGHT" "$stage_show"
    env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" events "$right_run" --kind refused 2>/dev/null | python3 -c "$PROOF_ROWS" "$STAGE" refused "$DEMO_PORT_RIGHT" "$AGENT_NAME" || true
    runtego events "$right_run" --verify
  fi
  if [ -n "$left_run" ]; then
    say "LEFT ($left_head): $left_what"
    other_runs "watched" "$left_runs" "$left_run"
    printf '$ %s events %s   (the attack rows: the key, the token, port %s; <stage> is %s)\n' "$(shq "$TEGO_BIN")" "$left_run" "$DEMO_PORT_LEFT" "$stage_show"
    env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" events "$left_run" 2>/dev/null | python3 -c "$PROOF_ROWS" "$STAGE" watched "$DEMO_PORT_LEFT" "$AGENT_NAME" || true
    runtego events "$left_run" --verify
  fi
  [ -n "$right_run" ] || [ -n "$left_run" ] || note "no run yet: run ./demo.sh backup, or a take"
}

# ---- reset ----

cmd_reset() {
  stop=0
  case "${1:-}" in
    --stop) stop=1 ;;
    '') ;;
    *) die "usage: demo.sh reset [--stop]" ;;
  esac
  prob=$(stage_problem)
  [ -z "$prob" ] || die "$prob"
  # A run still going would keep writing into the ledger this moves, out of the dashboard's sight.
  live=$(live_runs)
  if [ -n "$live" ]; then
    n=$(printf '%s\n' "$live" | wc -l | tr -d ' ')
    if [ "${DEMO_FORCE:-0}" = 1 ]; then
      note "warning: $n run(s) of this demo are still running ($(printf '%s\n' "$live" | cut -d' ' -f1 | tr '\n' ' ' | sed 's/ *$//')); DEMO_FORCE=1 resets anyway, and they keep writing into the moved ledger"
    else
      printf '%s\n' "$live" | while read -r lid lagent lstate; do
        printf '  still running: %s (%s, %s)\n' "$lid" "$lagent" "$lstate" >&2
      done
      die "$n run(s) of this demo are still running: quit both $AGENT_NAME windows ($AGENT_QUIT in each), then run ./demo.sh reset again (DEMO_FORCE=1 resets anyway; the old runs then keep writing into the moved ledger)"
    fi
  fi
  need_tools systemd-run
  if [ "$stop" = 1 ]; then
    say "Reset --stop: stop the three servers ($UNIT_LEFT, $UNIT_RIGHT, $UNIT_API), remove the generated state"
    stop_units
    clear_state
    rotate_ledger
    note "done: stop the dashboard (Ctrl-C) and quit both $AGENT_NAME windows if they are still open"
    return 0
  fi
  need_tools python3 "$DEMO_AGENT"
  [ -d "$LEFT_DIR" ] && [ -d "$RIGHT_DIR" ] || die "the demo is not set up. Run: ./demo.sh setup"
  say "Reset: fresh sides, the contract filled again, a new ledger (quit both $AGENT_NAME windows first)"
  stop_units
  for s in without with; do
    lay_side "$s"
    if [ "$DEMO_AGENT" = codex ]; then
      [ -s "$STAGE/$s/codex-home/auth.json" ] || { [ -f "$DEMO_CODEX_AUTH" ] && copy_login "$s"; } || note "warning: $s has no Codex login; run ./demo.sh setup"
      note "side: $STAGE/$s (fresh home and project; its Codex login kept)"
    else
      note "side: $STAGE/$s (fresh home and project)"
    fi
  done
  write_contract
  rotate_ledger
  start_units
  note "the dashboard can stay up: it shows the new, empty ledger (reload the page)"
  note "next: ./demo.sh check"
}

usage() {
  echo "usage: demo.sh setup | check | dashboard [args] | left [agent args] | right [agent args] | attacker | backup | proof | reset [--stop]" >&2
  exit 2
}

sub=${1:-}
[ "$#" -gt 0 ] && shift
case "$sub" in
  setup) cmd_setup ;;
  check) cmd_check ;;
  dashboard) cmd_dashboard "$@" ;;
  left) cmd_left "$@" ;;
  right) cmd_right "$@" ;;
  attacker) cmd_attacker ;;
  backup) cmd_backup ;;
  proof) cmd_proof ;;
  reset) cmd_reset "$@" ;;
  *) usage ;;
esac
