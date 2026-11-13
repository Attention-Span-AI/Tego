#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -eu
: "${EXECMATCH_SCRATCH:?set EXECMATCH_SCRATCH under your task scratch}"
# GO_CHECK names the Go command for every step. It may name a wrapper that runs
# Go under the host's memory and CPU limits; it defaults to the go on PATH.
GO_CHECK=${GO_CHECK:-go}
export PATH=/usr/bin:"$HOME/.local/go/bin":"$HOME/go/bin":"$PATH"
if [ "${1:-}" = --matrices-internal ]; then
 exec "$GO_CHECK" test -p 1 -count=1 -v ./test/execmatchdiff -run 'Test(ReleasedComparison|OptionValueReleasedComparison|ReconciliationReleasedComparison|OrdinaryAllowRegression|ExceptionOracle|FrozenBaseline)'
fi
mkdir -p "$EXECMATCH_SCRATCH/tmp" "$EXECMATCH_SCRATCH/logs"
export TMPDIR="$EXECMATCH_SCRATCH/tmp" GOTMPDIR="$EXECMATCH_SCRATCH/tmp"
export GOMAXPROCS=2 GOMEMLIMIT=2GiB GOFLAGS=-p=1
export TEGO_EXECMATCH_KEYS=1
run_go() {
 "$GO_CHECK" "$@"
}
step() {
 name=$1; shift
 started=$(date +%s)
 "$@" > "$EXECMATCH_SCRATCH/logs/$name.log" 2>&1
 printf '%s rc=0 seconds=%s\n' "$name" "$(($(date +%s)-started))" | tee -a "$EXECMATCH_SCRATCH/logs/summary"
}
full_sweeps() {
 # Eight disjoint groups cover the reviewed 32-target inventory. Every selected
 # subtest retains its entire original typo generation and assertions.
 group=0
 for targets in 'stage|init-db|fsck-objects|pickaxe' 'widget|backfill|daemon|diff-pairs' \
  'difftool--helper|filter-branch|http-backend|http-fetch' 'http-push|imap-send|instaweb|merge-octopus' \
  'merge-one-file|merge-resolve|mergetool|quiltimport' 'refs|remote-ftp|remote-ftps|remote-http' \
  'remote-https|replay|request-pull|sh-i18n--envsubst' 'shell|submodule|subtree|web--browse'; do
  step "correction-$group" run_go test -p 1 -count=1 -v -run "^TestRound3CorrectionSweep$/^($targets)$" ./pkg/policy/execmatch
  group=$((group+1))
 done
 # Shards generate all vectors before selecting rows, preserving the exact
 # original seeded corpus. No timeout override or concurrent Go job is needed.
 for part in {0..7}; do
  export TEGO_EXECMATCH_PREFIX_SHARD="$part/8"
  step "prefix-$part" run_go test -p 1 -count=1 -v -run '^TestPrefixFinalHolds(EveryRow|Multicall)$' ./pkg/policy/execmatch/rows
 done
 unset TEGO_EXECMATCH_PREFIX_SHARD
}
if [ "${1:-}" = --sweeps-internal ]; then
 export TEGO_EXECMATCH_LONG=1
 full_sweeps
 exit
fi
python3 test/execmatchdiff/prepare.py --verify
step matrices env TEGO_EXECMATCH_LONG=1 "$0" --matrices-internal
python3 test/execmatchdiff/prepare.py "$EXECMATCH_SCRATCH/overlay" 70a9e8c56
step corpus run_go test -p 1 -count=1 -v -overlay "$EXECMATCH_SCRATCH/overlay/overlay.json" ./pkg/policy/execmatch/...
export TEGO_EXECMATCH_LONG=1
step generators run_go test -p 1 -count=1 -v -overlay "$EXECMATCH_SCRATCH/overlay/overlay.json" -run '^(TestTighteningOnly|TestRound2ComparisonCorpus|TestTerminatorOnlyTightens|TestTerminatorBaselineGrammar)$' ./pkg/policy/execmatch
full_sweeps
