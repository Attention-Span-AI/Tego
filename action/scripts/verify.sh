#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# Fresh runner, trusted code only. Never execute evidence or caller code.
set -euo pipefail
here="$(cd "$(/usr/bin/dirname "$0")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
umask 077
export DIR="${RUNNER_TEMP:?}/tego-verifier"
/usr/bin/mkdir -m 700 "$DIR"
/usr/bin/mkdir "$DIR/state" "$DIR/bin" "$DIR/home"
export HOME="$DIR/home"
out dir "$DIR"
# Incoming agent-job values are transfer hints only. They cannot decide the
# gate, the requested-tier diagnostic or the comment target.
export AGENT_EXIT=unknown PREPARE_EXIT=125 EVIDENCE_EXIT=125 VERIFIED=false REFUSALS='' RUN_ID='' PR_NUMBER=''
# Keep evidence or install failures distinct from an agent failure.
finish_failure() {
  rc=$?
  trap - EXIT
  if [ "$rc" != 0 ]; then
    printf 'Evidence verification failed (%s); agent exit: %s\n' "$rc" "${AGENT_EXIT:-not started}" >&2
    # Replace the same marker comment even if download or comparison failed,
    # so a receipt from an earlier commit cannot continue to look current.
    if RECEIPT_FAILURE=true "$here/render.sh"; then
      MD="$DIR/evidence/receipt.md" DO_CHECK=false "$here/post.sh" || true
    fi
    exit 125
  fi
}
trap finish_failure EXIT
PR_NUMBER="$(/usr/bin/python3 -I "$here/handoff.py" pull-request)"
/usr/bin/python3 -I "$here/handoff.py" download "$DIR/artifact.zip"
/usr/bin/python3 -I "$here/handoff.py" extract "$DIR/artifact.zip" "$DIR/evidence"
export TEGO="$DIR/bin/tego"
if [ "${SIGNING_JOB:-false}" = true ]; then
  /usr/bin/python3 -I "$here/signing.py" core-check "$DIR/evidence"
fi
if [ ! -f "$DIR/evidence/receipt.json" ]; then
  # Doctor diagnostics are retained and shown even when no receipt was produced.
  PREPARE_EXIT="$(/usr/bin/python3 -I "$here/handoff.py" diagnostic "$DIR/evidence" "${TIER_WANTED:?}")"
  printf '%s\n' "$PREPARE_EXIT" >"$DIR/state/prepare-exit"
  printf '%s\n' "${TIER_WANTED:-unknown}" >"$DIR/state/tier-wanted"
  "$here/diagnostic.sh"
else
  "$here/install.sh"
  verify_binary
  check_rc=0
  check_args=()
  if [ "${SIGNING_JOB:-false}" = true ]; then
    check_args=(--require-ended --status-file "$DIR/evidence/run-status.json")
  fi
  "$TEGO" receipt --check "$DIR/evidence/receipt.json" "$DIR/evidence/run" "${check_args[@]}" --json >"$DIR/signer-check.json" || check_rc=$?
  out checked-file "$DIR/signer-check.json"
  [ "$check_rc" = 0 ]
  "$here/full-match.sh" "$DIR/signer-check.json"
  if [ "${SIGNING_JOB:-false}" = true ]; then
    /usr/bin/python3 -I "$here/signing.py" complete "$DIR/signer-check.json"
    /usr/bin/install -m 0600 "$DIR/signer-check.json" "$DIR/evidence/signer-check.json"
  fi
  /usr/bin/python3 -I "$here/handoff.py" decisions "$DIR/evidence" >"$DIR/state/decisions.json"
  RUN_ID="$(/usr/bin/jq -er .run_id "$DIR/state/decisions.json")"
  AGENT_EXIT="$(/usr/bin/jq -er '.agent_exit | tostring' "$DIR/state/decisions.json")"
  REFUSALS="$(/usr/bin/jq -er '.refusals | tostring' "$DIR/state/decisions.json")"
  VERIFIED="$(/usr/bin/jq -er '.verified | tostring' "$DIR/state/decisions.json")"
  PREPARE_EXIT=0
  EVIDENCE_EXIT=0
  # All post-check display inputs were also hashed in the out-of-band inventory.
  export UNSIGNED_REASON
  UNSIGNED_REASON="$(/usr/bin/jq -r .reason "$DIR/evidence/eligibility.json")"
  "$here/render.sh"
fi
MD="$DIR/evidence/receipt.md" DO_CHECK=false "$here/post.sh"
# Resolve consent and visibility independently in the reporting job. An explicit
# signing request without disclosure consent fails after report retention.
trap - EXIT
if [ "${DEFER_GATE:-false}" = true ]; then
  out agent-exit-code "$AGENT_EXIT"
  out prepare-exit "$PREPARE_EXIT"
  out evidence-exit "$EVIDENCE_EXIT"
  out run-id "$RUN_ID"
  out refusals "$REFUSALS"
  out verified "$VERIFIED"
  if [ "$PREPARE_EXIT" = 0 ]; then
    /usr/bin/python3 -I "$here/signing.py" decision >"$DIR/state/sign-decision.json" || { printf 'Signing policy refused; checked agent exit: %s\n' "$AGENT_EXIT" >&2; exit 125; }
    selected="$(/usr/bin/jq -r .sign "$DIR/state/sign-decision.json")"
    if [ "$selected" = true ]; then
      # Do not schedule an OIDC-enabled job before the non-OIDC reporting job
      # has established the copied complete teardown assertion too.
      /usr/bin/python3 -I "$here/signing.py" core-check "$DIR/evidence" || exit 125
      "$TEGO" receipt --check "$DIR/evidence/receipt.json" "$DIR/evidence/run" --require-ended --status-file "$DIR/evidence/run-status.json" --json >"$DIR/signer-check.json" || exit 125
      /usr/bin/python3 -I "$here/signing.py" complete "$DIR/signer-check.json" || exit 125
    fi
    out should-sign "$selected"
  else
    out should-sign false
  fi
else
  "$here/gate.sh"
fi
