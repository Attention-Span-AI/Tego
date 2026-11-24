#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
if [ "${1:-}" != --tego-ci-clean ]; then
  export JOB_PATH="$PATH" AGENT_HOME="$HOME"
fi
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# One collector invocation owns the fixed output path and preserves failures for
# the fresh verifier job. No final gate here: upload/reporting comes first.
set -euo pipefail
here="$(cd "$(/usr/bin/dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
umask 077
base="${RUNNER_TEMP:?}/tego-ci/${GITHUB_RUN_ID:?}/${GITHUB_RUN_ATTEMPT:?}"
[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ && "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || exit 125
identity="$(/usr/bin/python3 -I "$here/identity.py")" || exit 125
matrix="$(/usr/bin/jq -r .matrix_sha256 <<<"$identity")"
export DIR="$base/$matrix"
# Refuse stale state from a rerun in the same runner/attempt.
/usr/bin/mkdir -p "$base"
/usr/bin/mkdir -m 700 "$DIR" || exit 125
/usr/bin/mkdir -p "$DIR/state" "$DIR/evidence" "$DIR/bin" "$AGENT_HOME/.tego"
/usr/bin/mkdir -m 700 "$DIR/home"
export HOME="$DIR/home"
# Request this environment for later actions; the runner may prepend retained
# GITHUB_PATH entries, which are separately protected by grant refusals.
if [ -n "${GITHUB_ENV:-}" ]; then
  printf 'PATH=/usr/bin:/bin\nHOME=%s\nBASH_ENV=/dev/null\nENV=/dev/null\nPROMPT_COMMAND=\n' "$HOME" >>"$GITHUB_ENV"
fi
# Run only a pre-launch copy. Check original and copy with the system hash tool
# before executing even one post-run collector script.
export COLLECTOR_SOURCE
COLLECTOR_SOURCE="$(/usr/bin/dirname "$here")"
/usr/bin/python3 -I "$here/seal.py" "$COLLECTOR_SOURCE" "$DIR/collector" "$DIR/state/collector.sha256"
here="$DIR/collector/scripts"
out dir "$DIR"
out matrix-key "$matrix"
out artifact-attempt "$GITHUB_RUN_ATTEMPT"
out artifact-name "tego-receipt-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$matrix"
export TEGO="$DIR/bin/tego" TEGO_CONFIG="$DIR/config.yaml"
if [ -n "${IN_WORKSPACE:-}" ]; then export GITHUB_WORKSPACE; GITHUB_WORKSPACE="$(/usr/bin/realpath -e "$GITHUB_WORKSPACE/$IN_WORKSPACE")" || exit 125; fi
export CHECKOUT_SHA
CHECKOUT_SHA="$(/usr/bin/git -C "$GITHUB_WORKSPACE" rev-parse HEAD)" || exit 125
rc=0
"$here/check.sh" >"$DIR/state/check-outputs" || rc=$?
# Transfer only fixed known fields from the script's output, never agent stdout.
# check.sh writes to GITHUB_OUTPUT when running as an action, not this file.
if [ "$rc" = 0 ]; then "$here/install.sh" || rc=$?; fi
if [ "$rc" = 0 ]; then "$here/prepare.sh" || rc=$?; fi
printf '%s\n' "$rc" >"$DIR/state/prepare-exit"
if [ "$rc" = 0 ]; then
  export CONTRACT="$DIR/agent.yaml" LEDGER_ROOT="$DIR/ledger"
  "$here/run.sh" || rc=$?
  /usr/bin/sha256sum --check --strict --status "$DIR/state/collector.sha256" || exit 125
  /usr/bin/python3 -I "$here/seal.py" verify "$COLLECTOR_SOURCE" "$DIR/collector" "$DIR/state/collector.sha256" || exit 125
  export AGENT_EXIT
  AGENT_EXIT="$(/usr/bin/cat "$DIR/state/agent-exit")"
  "$here/collect.sh" || rc=$?
fi
prepare_exit="$(/usr/bin/cat "$DIR/state/prepare-exit")"
out prepare-exit "$prepare_exit"
out agent-exit-code "${AGENT_EXIT:-}"
if [ "$rc" = 0 ]; then
  export UNSIGNED_REASON
  UNSIGNED_REASON="$(/usr/bin/jq -r .reason "$DIR/evidence/eligibility.json")"
  "$here/render.sh" || rc=$?
fi
if [ "$rc" != 0 ]; then "$here/diagnostic.sh" || exit 125; fi
out evidence-exit "$rc"
MD="$DIR/evidence/receipt.md" DO_COMMENT=false DO_CHECK=false "$here/post.sh" || exit 125
# The unsigned handoff also preserves diagnostic artifacts without a receipt.
/usr/bin/python3 -I "$here/handoff.py" inventory "$DIR/evidence" >"$DIR/state/inventory-sha256" || exit 125
inventory_sha256="$(/usr/bin/cat "$DIR/state/inventory-sha256")"
out inventory-sha256 "$inventory_sha256"

# Publish exact core digests only after the owned teardown/status was copied.
if [ -f "$DIR/evidence/run-status.json" ]; then
  /usr/bin/python3 -I "$here/signing.py" core-outputs "$DIR/evidence" >"$DIR/state/core-outputs"
  while IFS='=' read -r key value; do
    case "$key" in receipt-sha256|receipt-bytes|record-sha256|record-bytes|anchor-sha256|anchor-bytes|contract-sha256|contract-bytes|status-sha256|status-bytes|core-inventory-sha256) out "$key" "$value" ;; *) exit 125 ;; esac
  done <"$DIR/state/core-outputs"
fi
