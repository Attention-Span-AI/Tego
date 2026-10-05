#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests kill test 2's pair counter (test/e2e/kt2-pairs.jq) on hand-made ledgers: a duplicated emission or an
# unrelated event must not make up for exchanges that were never captured. Needs only jq.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v jq >/dev/null 2>&1 || { echo "SKIP kt2_pairs_test.sh: no jq"; exit 0; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-kt2pairs.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }

req() { printf '{"kind":"ssl_request","seq":%s,"source":"ssl"}\n' "$1"; }
resp() { printf '{"kind":"ssl_response","seq":%s,"request_seq":%s,"status":200,"parser_version":"1"}\n' "$1" "$2"; }
orphan() { printf '{"kind":"ssl_response","seq":%s,"status":200,"parser_version":"1"}\n' "$1"; }
count() { jq -rs --arg src ssl -f "$here/kt2-pairs.jq" "$tmp/events.jsonl"; }

# 1. Three clean exchanges: three pairs.
{ req 1; resp 2 1; req 3; resp 4 3; req 5; resp 6 5; } >"$tmp/events.jsonl"
[ "$(count)" = "3 3 0 0 0 3" ] || fail "clean ledger: $(count)"

# 2. Duplicated emission: four requests and four responses that all name one request are one pair, however
# large the request and response counts (the caller caps those at the step count).
{ req 1; resp 2 1; req 3; resp 4 1; req 5; resp 6 1; req 7; resp 8 1; } >"$tmp/events.jsonl"
[ "$(count)" = "4 4 0 0 0 1" ] || fail "duplicates answering one request must be one pair: $(count)"

# 3. Responses that name no request line are no pair.
{ req 1; req 3; orphan 4; orphan 5; } >"$tmp/events.jsonl"
[ "$(count)" = "2 2 0 0 0 0" ] || fail "an unmatched response counted as a pair: $(count)"

# 4. kt_forwarded_problem (shared by kt2's and kt7's forwarder gates) judges pairing, not counts: requests
# whose responses all name request 1 are counted n/n/0 and must still be refused.
# shellcheck source=test/e2e/lib.sh
. "$here/lib.sh"
fq() { sed 's/"ssl"/"forwarder"/'; }
{ req 1; resp 2 1; req 3; resp 4 3; } | fq >"$tmp/events.jsonl"
[ -z "$(kt_forwarded_problem "$tmp/events.jsonl" 2)" ] || fail "a clean forwarder ledger was refused: $(kt_forwarded_problem "$tmp/events.jsonl" 2)"
{ req 1; resp 2 1; req 3; resp 4 1; } | fq >"$tmp/events.jsonl"
[ -n "$(kt_forwarded_problem "$tmp/events.jsonl" 2)" ] || fail "responses all naming request 1 passed the forwarder gate"
{ req 1; resp 2 1; req 3; orphan 4; } | fq >"$tmp/events.jsonl"
[ -n "$(kt_forwarded_problem "$tmp/events.jsonl" 2)" ] || fail "an orphaned response passed the forwarder gate"

echo "ok kt2_pairs_test.sh"
