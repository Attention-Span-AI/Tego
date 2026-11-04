#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The Adjustable-mode demo, one command per step (README.md has the commands):
#   setup | run | dashboard | lift | restore | proof | reset
# Every subcommand prints the command it runs before it runs it. Nothing real is read: the "customer report" is a
# fake file under vault-data/, and the agent is agent.sh, a loop with no model.
#
# NEEDS ROOT. Adjustable runs only at tier cgroup or bpflsm, so `run`, `lift`, `restore` and `proof` use sudo. Root
# lets Tego put the run in a cgroup of its own and add that tier's kernel checks; the agent itself runs as you. While
# a root run is live its folder in the ledger is root's (mode 0700) and its live key is root's, so lifting and
# reading it need sudo too; when the run ends the folder is handed to you and the dashboard reads it.
#
#   setup      create vault-data/customer-report.csv (fake), fill the contract for this machine
#              (contract.filled.yaml), write the demo's machine config (ledger_root) and check tego compile accepts it
#   run        sudo tego run contract.filled.yaml -- ./agent.sh, writing to the demo's ledger
#   dashboard  tego-control serve for the same ledger, as you (extra arguments go to it: --addr 127.0.0.1:9000)
#   lift       sudo tego lift <run> read <vault-data> --for 2m: shows what the run will be able to do, asks you to
#              type "lift" (pass --yes to skip the question); the duration is DEMO_LIFT_FOR
#   restore    sudo tego restore <run> read <vault-data>: refused again now
#   proof      the ledger's lines for the lift, the restore or the expiry, and every read under the fence entry
#   reset      remove the filled contract, the fake data and the demo's ledger (the config is kept)
#
# Settings, overridable by environment: DEMO_CONFIG (~/tego-live-demo.yaml), DEMO_LEDGER (~/tego-live-demo-ledger),
# DEMO_LIFT_FOR (2m), DEMO_RUN (the run lift/restore/proof act on; default the newest run in the ledger).
# TEGO / TEGO_CONTROL name the binaries (default: bin/ of this checkout, else PATH).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(cd "$HERE/../.." && pwd -P)
TEMPLATE=$HERE/contract.yaml
FILLED=$HERE/contract.filled.yaml
VAULT=$HERE/vault-data
DEMO_CONFIG=${DEMO_CONFIG:-$HOME/tego-live-demo.yaml}
DEMO_LEDGER=$(readlink -m -- "${DEMO_LEDGER:-$HOME/tego-live-demo-ledger}")
DEMO_LIFT_FOR=${DEMO_LIFT_FOR:-2m}

if [ -n "${TEGO:-}" ]; then TEGO_BIN=$TEGO
elif [ -x "$ROOT/bin/tego" ]; then TEGO_BIN=$ROOT/bin/tego
else TEGO_BIN=$(command -v tego 2>/dev/null || true); fi
if [ -n "${TEGO_CONTROL:-}" ]; then CONTROL_BIN=$TEGO_CONTROL
elif [ -x "$ROOT/bin/tego-control" ]; then CONTROL_BIN=$ROOT/bin/tego-control
else CONTROL_BIN=$(command -v tego-control 2>/dev/null || true); fi

say() { printf '\n== %s\n' "$*"; }
note() { printf '%s\n' "$*"; }
die() { printf 'demo.sh: %s\n' "$*" >&2; exit 1; }

# Check physical paths even when HOME, the checkout or / was spelled through an
# alias. Only setup may claim a new/empty directory; reset requires its marker.
check_owned_path() {
  case $1 in /) die "refusing root: $1" ;; esac
  case "$(readlink -m -- "$HOME")/" in "$1/"*) die "refusing home or its ancestor: $1" ;; esac
  case "$ROOT/" in "$1/"*) die "refusing checkout or its ancestor: $1" ;; esac
}
require_owned() {
  check_owned_path "$1"
  [ ! -L "$1/$2" ] && [ -f "$1/$2" ] || die "no valid $2 from setup in $1"
  owner=$(cat "$1/$2") || die "cannot read marker: $1/$2"
  [ "$owner" = "$1" ] || die "no valid $2 from setup in $1"
}
claim_owned() {
  check_owned_path "$1"
  if [ ! -e "$1/$2" ] && [ ! -L "$1/$2" ]; then
    if [ -d "$1" ]; then
      # Count entries without exposing their names to newline trimming.
      entries=$(find "$1" -mindepth 1 -maxdepth 1 -printf x) || die "cannot list $1"
      [ -z "$entries" ] || die "refusing nonempty directory without $2 from setup: $1"
    fi
    mkdir -p "$1"
    (set -C; printf '%s\n' "$1" >"$1/$2") || die "cannot mark $1"
  fi
  require_owned "$1" "$2"
}

# shq quotes one word the way a person would type it.
shq() {
  case $1 in
    '' | *[!A-Za-z0-9_@%+=:,./-]*)
      printf "'"
      printf %s "$1" | sed "s/'/'\\\\''/g" || return
      printf "'"
      ;;
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
# tego runs the demo's tego as you, with the demo's machine config.
tego() { printcmd env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" "$@"; env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" "$@"; }
# sudotego runs it as root. sudo drops TEGO_CONFIG from the environment, so env sets it inside sudo. tego reads a
# config only when it is a regular file owned by root or you, in a folder no one else can write.
sudotego() { run sudo env "TEGO_CONFIG=$DEMO_CONFIG" "$TEGO_BIN" "$@"; }

need_tego() { [ -n "$TEGO_BIN" ] && [ -x "$TEGO_BIN" ] || die "no tego binary: run make build in $ROOT, or set TEGO"; }

# sed_esc escapes a value for the replacement half of an s||| command.
sed_esc() { printf %s "$1" | sed 's/[\\&|]/\\&/g'; }

# real prints the file a program name resolves to.
real() { p=$(command -v "$1") || die "$1 is not on PATH"; readlink -f "$p"; }

# newest_run prints DEMO_RUN, else the newest run folder in the demo's ledger. A live root run's folder is root's,
# but its name is listed in the ledger, which is yours.
newest_run() {
  if [ -n "${DEMO_RUN:-}" ]; then printf '%s\n' "$DEMO_RUN"; return; fi
  [ -d "$DEMO_LEDGER" ] || die "no ledger at $DEMO_LEDGER yet: run ./demo.sh setup, then ./demo.sh run"
  # The newest run folder by its time; run ids are r-<hex>-<base36>-<base36>.
  r='' newest=0
  for d in "$DEMO_LEDGER"/r-*; do
    [ -d "$d" ] || continue
    m=$(stat -c %Y "$d" 2>/dev/null || echo 0)
    if [ "$m" -gt "$newest" ]; then newest=$m; r=${d##*/}; fi
  done
  [ -n "$r" ] || die "no run in $DEMO_LEDGER yet: start one with ./demo.sh run"
  printf '%s\n' "$r"
}

cmd_setup() {
  need_tego
  [ ! -L "$VAULT" ] || die "the fake data directory is a symlink: $VAULT"
  claim_owned "$DEMO_LEDGER" .tego-live-demo-ledger
  claim_owned "$VAULT" .tego-live-demo-vault
  say "The fake customer data the contract refuses"
  run mkdir -p "$VAULT"
  note "\$ write $VAULT/customer-report.csv (fake rows)"
  printf 'customer_id,name,plan,monthly_usd\nC-1001,Acme Demo Ltd,team,490\nC-1002,Example Corp,business,4200\nC-1003,Sample Labs,starter,49\n' >"$VAULT/customer-report.csv"

  say "The contract, filled for this machine"
  sh=$(real sh); cat=$(real cat); sleep=$(real sleep)
  note "\$ sed 's|@SH@|$sh|; s|@CAT@|$cat|; s|@SLEEP@|$sleep|' contract.yaml > contract.filled.yaml"
  sed -e "s|@SH@|$(sed_esc "$sh")|" -e "s|@CAT@|$(sed_esc "$cat")|" -e "s|@SLEEP@|$(sed_esc "$sleep")|" "$TEMPLATE" >"$FILLED"

  say "The demo's machine config: the ledger root both tego and the dashboard use"
  if [ -f "$DEMO_CONFIG" ]; then
    note "config: $DEMO_CONFIG (kept)"
  else
    note "\$ printf 'version: 0\\nledger_root: $DEMO_LEDGER\\n' > $DEMO_CONFIG; chmod 600 $DEMO_CONFIG"
    printf 'version: 0\nledger_root: %s\n' "$DEMO_LEDGER" >"$DEMO_CONFIG"
    chmod 600 "$DEMO_CONFIG"
  fi
  # The ledger is yours, so what a root run writes there is handed to you when the run ends (docs/OPERATIONS.md).
  run mkdir -p -m 0700 "$DEMO_LEDGER"

  say "tego compile accepts it (Adjustable, one read entry in the fence, refused at start)"
  (cd "$HERE" && tego compile contract.filled.yaml)
  note ""
  note "Ready. Next: ./demo.sh run   (needs sudo)   and in a second terminal: ./demo.sh dashboard"
}

cmd_run() {
  need_tego
  [ -f "$FILLED" ] || die "no $FILLED: run ./demo.sh setup first"
  say "The agent under Adjustable mode (sudo: tier cgroup). Ctrl-C ends the run."
  cd "$HERE"
  sudotego run contract.filled.yaml -- ./agent.sh "$@"
}

cmd_dashboard() {
  [ -n "$CONTROL_BIN" ] && [ -x "$CONTROL_BIN" ] || die "no tego-control binary: run make build in $ROOT, or set TEGO_CONTROL"
  say "The dashboard, as you, for the demo's ledger (it never runs as root)"
  note "A live root run's folder is root's until the run ends; the dashboard shows the run in full once it has ended."
  run env "TEGO_CONFIG=$DEMO_CONFIG" "$CONTROL_BIN" serve --ledger "$DEMO_LEDGER" --open "$@"
}

cmd_lift() {
  need_tego
  r=$(newest_run)
  say "Lift the fence entry for $DEMO_LIFT_FOR on run $r"
  sudotego lift "$r" read "$VAULT" --for "$DEMO_LIFT_FOR" "$@"
}

cmd_restore() {
  need_tego
  r=$(newest_run)
  say "Refuse it again now, on run $r"
  sudotego restore "$r" read "$VAULT"
}

cmd_proof() {
  need_tego
  r=$(newest_run)
  rule="live.fence[read:$VAULT]"
  say "Every live change on run $r: lifted, restored, or the lift's time limit ending by itself"
  sudotego events "$r" --kind gap
  say "Every read of the fake data, refused or allowed, under the fence entry's rule"
  sudotego events "$r" --rule "$rule"
  say "The record is intact"
  sudotego events "$r" --verify
}

cmd_reset() {
  # Validate all deletion targets before removing any generated state or using sudo.
  require_owned "$DEMO_LEDGER" .tego-live-demo-ledger
  [ ! -L "$VAULT" ] || die "the fake data directory is a symlink: $VAULT"
  require_owned "$VAULT" .tego-live-demo-vault
  say "Retake: the filled contract, the fake data and the demo's ledger go; the config stays"
  run rm -f "$FILLED"
  run rm -rf -- "$VAULT"
  # A run that ended was handed to you; one still live, or one killed before it ended, may still be root's.
  if [ -d "$DEMO_LEDGER" ]; then
    if find "$DEMO_LEDGER" ! -user "$(id -u)" -print -quit 2>/dev/null | grep -q .; then
      run sudo rm -rf -- "$DEMO_LEDGER"
    else
      run rm -rf -- "$DEMO_LEDGER"
    fi
  fi
  note "Next: ./demo.sh setup"
}

sub=${1:-}
[ $# -eq 0 ] || shift
case $sub in
  setup) cmd_setup "$@" ;;
  run) cmd_run "$@" ;;
  dashboard) cmd_dashboard "$@" ;;
  lift) cmd_lift "$@" ;;
  restore) cmd_restore "$@" ;;
  proof) cmd_proof "$@" ;;
  reset) cmd_reset "$@" ;;
  *) sed -n '3,/^set -eu/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; [ -z "$sub" ] || exit 2 ;;
esac
