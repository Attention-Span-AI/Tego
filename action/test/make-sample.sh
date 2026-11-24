#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Visible, deterministic samples. The fake CLI models comparison, never runs Tego.
set -euo pipefail
A="$(cd "$(dirname "$0")/.." && pwd)"
W="${WORK:-${TMPDIR:?set WORK or TMPDIR}/tego-receipt-sample}"
run=r-5cd05e60-0dmrm463r69xq-kpyavw
mkdir -p "$W"
W="$(mktemp -d "$W/sample.XXXXXX")"
mkdir -p "$W/dir/evidence" "$W/dir/state" "$W/ledger/$run"
cp "$A/testdata/events.jsonl" "$W/ledger/$run/events.jsonl"
cp "$A/testdata/contract.yaml" "$A/testdata/compile.json" "$W/dir/evidence/"
sha256sum "$A/test/fake-tego" | cut -d' ' -f1 >"$W/dir/state/binary-sha256"
: >"$W/dir/state/runs-before.txt"
jq -n --arg dir "$W/dir" '[$dir, "/usr/bin", "/bin"]' >"$W/dir/state/protected-paths.json"
printf '%s %s\n' "$run" a48c6844922d6ea567be6d901561116d2b79255471b10ef3851464867443f6a8 >"$W/anchor.txt"
export FAKE_ANCHOR="$W/anchor.txt"
export DIR="$W/dir" TEGO="$A/test/fake-tego" FAKE_TEGO_DATA="$A/testdata" LEDGER_ROOT="$W/ledger" AGENT_EXIT=0
export GITHUB_OUTPUT="$W/out" GITHUB_REPOSITORY=example/app GITHUB_RUN_ID=42 GITHUB_SERVER_URL=https://github.com
export GITHUB_WORKFLOW_REF=example/app/.github/workflows/agent-receipt.yml@refs/pull/7/merge GITHUB_SHA=0123456789abcdef0123456789abcdef01234567
export GITHUB_REF=refs/pull/7/merge GITHUB_EVENT_NAME=pull_request GITHUB_RUN_ATTEMPT=1 GITHUB_JOB=agent GITHUB_ACTION=receipt
export RUNNER_OS=Linux RUNNER_ARCH=X64 WORKSPACE=/home/tego
export UNSIGNED_REASON='disabled: offline sample, not a GitHub run'
"$A/scripts/collect.sh"
"$A/scripts/render.sh"
for name in summary comment; do
  {
    printf '**Sample display. Not a GitHub run; not signed.**\n\n'
    printf 'The guest record is real; receipt JSON is reconstructed and compile JSON is hand-made. See testdata/README.md.\n\n'
    cat "$DIR/evidence/receipt.md"
  } >"$A/testdata/$name.md"
done
cp "$A/testdata/summary.md" "$A/SAMPLE-RECEIPT.md"
printf '211\n' >"$DIR/state/prepare-exit"
printf 'landlock\n' >"$DIR/state/tier-wanted"
jq '.tiers.landlock = false | .missing.landlock = ["systemd user manager is unavailable (constructed case)"]' "$A/testdata/doctor.json" >"$DIR/evidence/doctor.json"
"$A/scripts/diagnostic.sh"
{ printf '**Sample doctor refusal. Constructed; not signed.**\n\n'; cat "$DIR/evidence/receipt.md"; } >"$A/testdata/doctor-summary.md"
printf 'wrote summary, comment and doctor samples\n'
