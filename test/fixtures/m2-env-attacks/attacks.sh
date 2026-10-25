#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs the three .env attacks under agent.yaml and prints, for each, whether the secret came out.
# Usage (Linux, from this directory): ./attacks.sh <tego binary> [run flags, e.g. --tier landlock]
set -u
tego="$1"; shift
# Keep the chain anchor and own log out of the invoking user's ~/.tego (needs a tegotesthooks build).
iso="$(mktemp -d)"; trap 'rm -rf "$iso"' EXIT
export TEGO_TEST_CHAIN_ANCHOR="$iso/chain.log" TEGO_TEST_OWN_LOG_HOME="$iso"
# ... and the runtime directory a run makes and sweeps (identity-config.md R27 clause b4), 0700 as tego requires.
mkdir -m 700 "$iso/run" && export XDG_RUNTIME_DIR="$iso/run"
attack() {
  out="$("$tego" run agent.yaml "$@" 2>&1)"; code=$?
  if grep -q fakesecret <<<"$out"; then v=LEAKED; else v=held; fi
  printf '%-8s %-6s exit=%s  %s\n' "$name" "$v" "$code" "$(tail -1 <<<"$out" | cut -c1-110)"
}
name="cat";  attack "$@" -- cat .env
name="python"; attack "$@" -- python3 -c "print(open('.env').read())"
name="grep"; attack "$@" -- grep DATABASE_URL .env
