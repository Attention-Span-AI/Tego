#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


#
# collect.sh: finds the run this job just made, reads its receipt, its chain check and its run_start line with the
# tego CLI, copies the ledger and its anchor line, and writes tego-ci.json, the action's own manifest that ties them
# together. It runs right after the run, before any later step can run code the agent left in the workspace.
# Outputs: run-id, tier, refusals, head, verified.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(/usr/bin/dirname "$0")/lib.sh"

: "${DIR:?}" "${TEGO:?}" "${LEDGER_ROOT:?}"
verify_binary
ev="$DIR/evidence"

# The run is the one directory under the ledger root that was not there before the run. tego run prints its id
# only in its human summary, so the action reads the ledger root instead.
# Process substitutions hide producer failures from errexit. Materialize each
# stage so a failed find/sort/comm aborts collection before reading a receipt.
/usr/bin/find "$LEDGER_ROOT" -mindepth 1 -maxdepth 1 -name 'r-*' -printf '%f\n' >"$DIR/state/runs-after-unsorted.txt"
/usr/bin/sort "$DIR/state/runs-after-unsorted.txt" >"$DIR/state/runs-after.txt"
/usr/bin/comm -13 "$DIR/state/runs-before.txt" "$DIR/state/runs-after.txt" >"$DIR/state/runs-new.txt"
mapfile -t new <"$DIR/state/runs-new.txt"
case "${#new[@]}" in
1) run="${new[0]}" ;;
0) die "tego run made no run under $LEDGER_ROOT; it did not start (its output is above)" ;;
*) die "${#new[@]} new runs under $LEDGER_ROOT (${new[*]}); this action runs one, so it cannot tell which is its own" ;;
esac
[[ "$run" =~ ^r-[0-9a-z-]+$ ]] || die "unexpected run id '$run'"

"$TEGO" events "$run" --json --kind run_start >"$ev/run_start.json" || die "tego events $run --kind run_start failed"
[ "$(/usr/bin/wc -l <"$ev/run_start.json")" = 1 ] || die "expected one run_start line for $run"
# Runtime provisioning adds grants after compile. Refuse collection if any of
# those writes overlap the exact pre-launch refusal list, before issuing a receipt.
/usr/bin/python3 -I "$(/usr/bin/dirname "$0")/policy.py" runtime-writes "$ev/run_start.json" "$DIR/state/protected-paths.json"

# Status is available only for a launcher that acquired a scope. An unsigned
# diagnostic may retain no status; signing always requires it and complete checks.
if [ -e "$DIR/status" ] || [ -L "$DIR/status" ]; then
  # Redirection runs as the collector, never as root. Exclusive creation avoids
  # replacing stale or planted files; the privileged reader writes stdout only.
  (
    umask 077
    set -o noclobber
    if [ "${IN_USE_SUDO:-false}" = true ]; then
      # shellcheck disable=SC2024 # The collector must own the redirected copy.
      /usr/bin/sudo -n -- /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/status.py" read "$DIR/status/run-status.json" >"$DIR/run-status.json"
    else
      /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/status.py" read "$DIR/status/run-status.json" >"$DIR/run-status.json"
    fi
  ) || exit 125
fi
if [ -e "$DIR/run-status.json" ]; then
  /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/signing.py" teardown "$DIR/run-status.json" "$run"
  /usr/bin/install -m 0600 "$DIR/run-status.json" "$ev/run-status.json"
fi
if [ -f "$DIR/state/binary-asset" ]; then
  /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/signing.py" producer "$DIR" >"$ev/producer.json"
fi
# tego run keeps its own copy of the receipt in the run folder, and `receipt --verify` also compares that copy with the
# record. The agent's user may write that name first, so a copy that differs (exit 1) or cannot be read (exit 125) must
# not fail the action when the record itself verifies: this action never reads the kept copy. It checks the receipt it
# has just printed from the record (below), and the record's chain on its own.
set +e
"$TEGO" receipt "$run" --verify --json >"$ev/receipt.json"
rrc=$?
"$TEGO" events "$run" --verify --json >"$ev/verify.json"
vrc=$?
set -e
if [ "$rrc" != 0 ]; then
  if { [ "$rrc" = 1 ] || [ "$rrc" = 125 ]; } && [ "$vrc" = 0 ] && [ "$(/usr/bin/jq -r .verified "$ev/verify.json" 2>/dev/null)" = true ] &&
    [ -s "$ev/receipt.json" ]; then
    warn "the receipt.json kept in the run folder of $run was not accepted by tego receipt --verify (exit $rrc); the record itself verified, and this action reads the receipt from the record, never that file"
  else
    die "tego receipt $run failed"
  fi
fi
[ "$vrc" = 0 ] || [ "$vrc" = 1 ] || die "tego events $run --verify could not check the record (exit $vrc)"

/usr/bin/mkdir -p "$ev/run"
/usr/bin/cp -p "$LEDGER_ROOT/$run/events.jsonl" "$ev/run/events.jsonl"
"$TEGO" receipt --check "$ev/receipt.json" "$ev/run" --json >"$ev/agent-check.json"
"$(/usr/bin/dirname "$0")/full-match.sh" "$ev/agent-check.json"
anchor="$(/usr/bin/jq -r .anchor "$ev/verify.json")"
head="$(/usr/bin/jq -r .head "$ev/verify.json")"
[[ "$head" =~ ^[0-9a-f]{64}$ ]] || die 'invalid verified chain head'
/usr/bin/grep -Fx "$run $head" "$anchor" >"$ev/anchor-line.txt" || die 'the verified anchor could not be copied'
[ "$(/usr/bin/wc -l <"$ev/anchor-line.txt")" = 1 ] || die 'the anchor is not one exact line'

sha() { /usr/bin/sha256sum "$1" | /usr/bin/cut -d' ' -f1; }
events_sha256="$(sha "$ev/run/events.jsonl")"
receipt_sha256="$(sha "$ev/receipt.json")"
contract_sha256="$(sha "$ev/contract.yaml")"
/usr/bin/jq -n \
	--slurpfile v "$ev/verify.json" \
	--slurpfile s "$ev/run_start.json" \
	--slurpfile r "$ev/receipt.json" \
	--arg events_sha256 "$events_sha256" \
	--arg receipt_sha256 "$receipt_sha256" \
	--arg contract_sha256 "$contract_sha256" \
	--arg agent_exit "${AGENT_EXIT:-}" \
	'{
	  manifest: "tego-ci/0",
	  note: "written by the tego receipt action from tego CLI output; not a tego format",
	  run: $v[0].run, head: $v[0].head, lines: $v[0].lines,
	  verified_on_runner: $v[0].verified, anchored: $v[0].anchored,
	  events_sha256: $events_sha256, receipt_sha256: $receipt_sha256,
	  contract_hash: $s[0].contract_hash, contract_file_sha256: $contract_sha256,
	  tier: $s[0].tier, tego_version: $s[0].tego_version, tego_commit: $s[0].commit,
	  refusals: $r[0].refusals.total, coverage_complete: $r[0].coverage.complete,
	  agent_exit_code: ($agent_exit | tonumber? // null),
	  github: {
	    repository: env.GITHUB_REPOSITORY, checkout_sha: env.CHECKOUT_SHA, action_sha: env.TEGO_CODE_SHA, workflow_sha: env.GITHUB_WORKFLOW_SHA, workflow_ref: env.GITHUB_WORKFLOW_REF, sha: env.GITHUB_SHA,
	    ref: env.GITHUB_REF, event: env.GITHUB_EVENT_NAME, run_id: env.GITHUB_RUN_ID,
	    run_attempt: env.GITHUB_RUN_ATTEMPT, job: env.GITHUB_JOB, runner_name: env.RUNNER_NAME,
      agent_runner: {environment: "github-hosted", image: env.ImageOS, version: env.ImageVersion, arch: env.RUNNER_ARCH}, runner_os: env.RUNNER_OS, runner_arch: env.RUNNER_ARCH
	  }
	}' >"$ev/tego-ci.json"

verified="$(/usr/bin/jq -r .verified "$ev/verify.json")"
[ "$verified" = true ] || warn "the record of $run did not verify on the runner: $(/usr/bin/jq -r '.error // "no reason given"' "$ev/verify.json")"
out run-id "$run"
printf '%s\n' "$run" >"$DIR/state/run-id"
tier="$(/usr/bin/jq -er '.tier' "$ev/run_start.json")"
refusals="$(/usr/bin/jq -er '.refusals.total | tostring' "$ev/receipt.json")"
out tier "$tier"
out refusals "$refusals"
out head "$head"
out verified "$verified"
