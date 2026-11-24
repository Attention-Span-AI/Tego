#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export JOB_PATH="${JOB_PATH:-$PATH}"
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


set -euo pipefail
here="$(/usr/bin/dirname "$0")"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
: "${DIR:?}" "${TEGO:?}" "${IN_USE_SUDO:?}" "${GITHUB_WORKSPACE:?}" "${RUNNER_TEMP:?}"
verify_binary
ev="$DIR/evidence"
/usr/bin/mkdir -p "$DIR/state" "$DIR/ledger"
export TEGO_CONFIG="$DIR/config.yaml"
/usr/bin/jq -n --arg root "$DIR/ledger" '{ledger_root:$root}' >"$TEGO_CONFIG"
want=landlock
[ "$IN_USE_SUDO" = false ] || want=cgroup
printf '%s\n' "$want" >"$DIR/state/tier-wanted"
setup_refusal() {
  /usr/bin/jq -n --arg tier "$want" '{diagnostic_source:"runner-setup",summary:"No systemd user manager; Tego doctor could not run.",missing:{($tier):["systemd user manager is unavailable"]}}' >"$ev/doctor.json"
  exit 211
}
uid="$(/usr/bin/id -u)"
if [ "$want" = landlock ] && [ ! -S "/run/user/$uid/systemd/private" ]; then
  # A no-root run can still need this privileged runner setup operation.
  /usr/bin/sudo -n /usr/bin/loginctl enable-linger "$(/usr/bin/id -un)" 2>/dev/null || setup_refusal
  for _ in $(/usr/bin/seq 1 30); do
    [ -S "/run/user/$uid/systemd/private" ] && break
    /usr/bin/sleep 1
  done
  [ -S "/run/user/$uid/systemd/private" ] || setup_refusal
fi
probe() {
  if [ "$want" = cgroup ]; then
    /usr/bin/sudo -n --preserve-env=TEGO_CONFIG "$TEGO" doctor "$@"
  else
    in_user_manager "$TEGO" doctor "$@"
  fi
}
probe --json >"$ev/doctor.json" || true
if ! probe --require "$want" >"$DIR/state/doctor.txt" 2>&1; then
  if ! /usr/bin/jq -e 'type == "object"' "$ev/doctor.json" >/dev/null 2>&1; then
    /usr/bin/jq -n --arg tier "$want" '{diagnostic_source:"runner-setup",missing:{($tier):["Tego doctor did not return usable JSON; see the job log"]}}' >"$ev/doctor.json"
  fi
  exit 211
fi
/usr/bin/jq -e --arg t "$want" '.tiers[$t] == true' "$ev/doctor.json" >/dev/null || exit 211
if [ -n "${IN_CONTRACT:-}" ]; then
  contract="$(/usr/bin/realpath -e "$GITHUB_WORKSPACE/$IN_CONTRACT")"
  case "$contract" in "$GITHUB_WORKSPACE"/*) ;; *) die 'contract must be inside the checkout' ;; esac
else
  contract="$DIR/input.yaml"
  WORKSPACE="$GITHUB_WORKSPACE" "$here/contract.sh" >"$contract"
fi
cd "$GITHUB_WORKSPACE"
"$TEGO" compile --merged "$contract" >"$DIR/merged.yaml"
# The merged form resolves profiles, anchors and aliases before safety flags are read.
RUNNER_ROOT="${RUNNER_ROOT:-$(/usr/bin/python3 -I "$here/policy.py" runner-root)}"
: "${RUNNER_TOOL_CACHE:?runner tools path is required}"
/usr/bin/mkdir -p "$GITHUB_WORKSPACE/.github"
protected=("$RUNNER_TEMP" "$DIR" "${GITHUB_ACTION_PATH:?}" "${AGENT_HOME:-$HOME}/.tego" "$(/usr/bin/dirname "$TEGO")"
  "$(/usr/bin/dirname "$RUNNER_TEMP")/_actions" "$RUNNER_ROOT" "$RUNNER_TOOL_CACHE" "$GITHUB_WORKSPACE/.github")
account_state="$(/usr/bin/python3 -I -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir + "/.tego")')"
read_protected=("$account_state" "$RUNNER_TEMP" "$DIR" "${AGENT_HOME:-$HOME}/.tego" "$RUNNER_ROOT/_diag")
for name in GITHUB_ENV GITHUB_PATH GITHUB_OUTPUT GITHUB_STEP_SUMMARY GITHUB_STATE GITHUB_EVENT_PATH; do
  [ -z "${!name:-}" ] || {
    if [ "$name" != GITHUB_EVENT_PATH ]; then /usr/bin/touch "${!name}"; fi
    protected+=("${!name}")
    read_protected+=("${!name}")
  }
done
for p in "${protected[@]}"; do
  [ -e "$p" ] || die 'a required protected runner path is missing'
done
# Check every original job PATH component and shell startup location, including
# nonexistent names. Deny rules are emitted only for existing paths; overlap
# refusal itself always includes the entire list.
JOB_PATH="${JOB_PATH:-$PATH}" /usr/bin/python3 -I "$here/policy.py" environment-paths >"$DIR/state/environment-paths"
mapfile -t environment_paths <"$DIR/state/environment-paths"
protected+=("${environment_paths[@]}" "$GITHUB_WORKSPACE/.git")
# Checkout and other later steps read global, system, worktree and included Git
# configuration. Resolve with the original HOME, before the agent can edit it.
/usr/bin/python3 -I "$here/policy.py" git-paths "$GITHUB_WORKSPACE" "$(/usr/bin/dirname "${COLLECTOR_SOURCE:-$GITHUB_ACTION_PATH}")" >"$DIR/state/git-paths"
mapfile -t git_paths <"$DIR/state/git-paths"
protected+=("${git_paths[@]}")
/usr/bin/python3 -I "$here/policy.py" save-paths "${protected[@]}" >"$DIR/state/protected-paths.json"
[ ! -d "$RUNNER_ROOT/_diag" ] || read_protected+=("$RUNNER_ROOT/_diag")
PATH="${JOB_PATH:-$PATH}" "$TEGO" compile --json "$DIR/merged.yaml" >"$DIR/state/input-compile.json" 2>"$DIR/state/input-compile.err"
/usr/bin/python3 -I "$here/policy.py" diagnostics "$DIR/state/input-compile.err"
/usr/bin/python3 -I "$here/policy.py" "$DIR/merged.yaml" "$DIR/state/input-compile.json" "${protected[@]}"
existing=()
for p in "${protected[@]}"; do [ ! -e "$p" ] || existing+=("$p"); done
/usr/bin/python3 -I "$here/policy.py" augment "$DIR/merged.yaml" "${existing[@]}" --read "${read_protected[@]}" >"$DIR/agent.yaml"
contract="$DIR/agent.yaml"
"$TEGO" compile --json "$contract" >"$ev/compile.json"
/usr/bin/python3 -I "$here/policy.py" "$DIR/merged.yaml" "$ev/compile.json" "${protected[@]}"
"$TEGO" compile "$contract" >"$ev/compile.txt" 2>&1
/usr/bin/cp "$contract" "$ev/contract.yaml"
root="$(/usr/bin/jq -r '.machine[] | select(.key == "ledger_root") | .value' "$ev/compile.json")"
[ "$root" = "$DIR/ledger" ] || die 'compiled ledger root differs from the private evidence directory'
# Discover this run without trusting agent stdout. Collection separately
# validates the launcher-owned status against this same run and scope.
/usr/bin/find "$root" -mindepth 1 -maxdepth 1 -type d -name 'r-*' -printf '%f\n' | /usr/bin/sort >"$DIR/state/runs-before.txt"
out contract "$contract"
out ledger-root "$root"
out tier-wanted "$want"
