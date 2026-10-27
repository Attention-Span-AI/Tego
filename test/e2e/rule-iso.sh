#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# rule-iso.sh — "make this a rule", end to end, in an isolated tego home: a run reads a fake secret (allowed),
# `tego rule <run> <seq> --block` is applied from that read's line, and the next run is refused the read by the new
# rule. Then the dashboard's Rule page writes the same bytes from the same line: the contract is put back from .bak,
# the page's Confirm POST is sent (session cookie, form token, Origin) and the file is compared with what the CLI
# wrote; a POST without the token, or from another Origin, writes nothing.
#
# Usage: test/e2e/rule-iso.sh <W> <BIN>
#   W    an isolated tego setup: $W/state/machine.yaml (ledger_root inside $W/state), $W/state/home, $W/xdg
#   BIN  a directory with tego and tego-control built with -tags tegotesthooks
# The project lives in $W/p/rule-e2e (outside $W/state). It never touches the invoking user's ~/.tego, ~/.claude,
# ~/.codex or shell history: every command runs under env -i with HOME, XDG_RUNTIME_DIR, TEGO_CONFIG and the
# test-hook chain anchor and own-log home pointed into $W.
set -euo pipefail
W=${1:?usage: rule-iso.sh <W> <BIN>}
BIN=${2:?usage: rule-iso.sh <W> <BIN>}
P=$W/p/rule-e2e
case "$W" in "$HOME"|"$HOME/.tego"*|"") echo "rule-iso: W must be an isolated directory" >&2; exit 2 ;; esac
iso() {
	env -i PATH="$BIN:/usr/local/bin:/usr/bin:/bin" HOME="$W/state/home" HISTFILE=/dev/null XDG_RUNTIME_DIR="$W/xdg" \
		TEGO_CONFIG="$W/state/machine.yaml" TEGO_TEST_CHAIN_ANCHOR="$W/state/chain.log" \
		TEGO_TEST_OWN_LOG_HOME="$W/state/home" TERM=xterm "$@"
}
fail() { echo "FAIL: $*" >&2; exit 1; }

rm -rf "$P"
mkdir -p "$P/out"
printf 'FAKE-SECRET-not-a-real-key\n' >"$P/secret.txt"
cat >"$P/agent.sh" <<'EOF'
cat secret.txt >out/copy.txt && echo "read it"
EOF
cat >"$P/agent.yaml" <<'EOF'
version: 0
name: rule-e2e
# the agent copies a file it should not
command:
  - sh
  - agent.sh
fs:
  write:
    - ./out/
    - /dev/null
  reads: held
exec:
  allow:
    - sh
    - cat
tier: landlock
capture: "off"
record: full
EOF
chmod 0600 "$P/agent.yaml"
ORIG=$(cat "$P/agent.yaml")

# 1. The first run reads the secret, allowed.
out=$(cd "$P" && iso tego run agent.yaml 2>&1) || fail "first run: $out"
grep -q "read it" <<<"$out" || fail "first run did not read: $out"
ROOT=$(sed -n 's/^ledger_root: //p' "$W/state/machine.yaml")
# newest_run is the newest run directory's name under $ROOT (by mtime, as ls -t had it).
newest_run() {
	local d n=""
	for d in "$ROOT"/r-*/; do
		if [ -z "$n" ] || [ "$d" -nt "$n" ]; then n=$d; fi
	done
	basename "$n"
}
RUN=$(newest_run)
EV="$ROOT/$RUN/events.jsonl"
SEQ=$(grep '"kind":"fs"' "$EV" | grep "\"path\":\"$P/secret.txt\"" | grep '"verdict":"allow"' | head -1 | sed 's/.*"seq":\([0-9]*\),.*/\1/' || true)
[ -n "$SEQ" ] || fail "no allowed read of secret.txt in $EV"
echo "first run $RUN read secret.txt at line #$SEQ"

# 2. tego rule --block from that line.
iso tego rule "$RUN" "$SEQ" --block --dry-run >/dev/null || fail "dry run"
[ "$(cat "$P/agent.yaml")" = "$ORIG" ] || fail "--dry-run wrote"
iso tego rule "$RUN" "$SEQ" --block | tee "$W/p/rule-e2e.cli.txt"
grep -q '# from run '"$RUN"' line #'"$SEQ" "$P/agent.yaml" || fail "no dated comment"
grep -q '# the agent copies a file it should not' "$P/agent.yaml" || fail "comment lost"
[ "$(cat "$P/agent.yaml.bak")" = "$ORIG" ] || fail ".bak is not the old file"
cp "$P/agent.yaml" "$W/p/rule-e2e.cli.yaml"
(cd "$P" && iso tego compile agent.yaml >/dev/null 2>&1) || fail "the new contract does not compile"

# 3. The next run is refused the read by the new rule.
rm -f "$P/out/copy.txt"
out=$(cd "$P" && iso tego run agent.yaml 2>&1) && fail "second run read the secret: $out"
RUN2=$(newest_run)
[ "$RUN2" != "$RUN" ] || fail "no second run"
grep '"reason":"read-denied"' "$ROOT/$RUN2/events.jsonl" | grep -q 'fs.deny_read\[./secret.txt\]' ||
	fail "the second run's refusal is not the new rule: $(grep read-denied "$ROOT/$RUN2/events.jsonl" | head -2)"
echo "second run $RUN2 refused by fs.deny_read[./secret.txt]"

# 4. The dashboard writes the same bytes from the same line.
cp "$P/agent.yaml.bak" "$P/agent.yaml"
PORT=$((20000 + RANDOM % 20000))
iso tego-control serve --addr "127.0.0.1:$PORT" >"$W/p/rule-e2e.serve.txt" 2>&1 &
SP=$!
trap 'kill $SP 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q 'http://' "$W/p/rule-e2e.serve.txt" && break; sleep 0.1; done
URL=$(grep -o 'http://[^ ]*' "$W/p/rule-e2e.serve.txt")
JAR=$W/p/rule-e2e.jar
curl -s -c "$JAR" -o /dev/null "$URL"
page=$(curl -s -b "$JAR" "http://127.0.0.1:$PORT/rule?run=$RUN&seq=$SEQ&a=block")
grep -q 'Block next time, this file' <<<"$page" || fail "the Rule page lacks the block option"
grep -q 'Ask me next time, this file' <<<"$page" || fail "the Rule page lacks the ask option"
TOK=$(grep -o 'name="csrf" value="[0-9a-f]*"' <<<"$page" | sed 's/.*value="//; s/"//')
[ -n "$TOK" ] || fail "no form token on the page"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -H "Origin: http://127.0.0.1:$PORT" \
	--data "run=$RUN&seq=$SEQ&a=block&csrf=bad" "http://127.0.0.1:$PORT/rule")
[ "$code" = 403 ] || fail "a POST with a bad token got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -H "Origin: http://evil.example" \
	--data "run=$RUN&seq=$SEQ&a=block&csrf=$TOK" "http://127.0.0.1:$PORT/rule")
[ "$code" = 403 ] || fail "a POST from another Origin got $code"
[ "$(cat "$P/agent.yaml")" = "$ORIG" ] || fail "a refused POST wrote"
saved=$(curl -s -b "$JAR" -H "Origin: http://127.0.0.1:$PORT" --data "run=$RUN&seq=$SEQ&a=block&csrf=$TOK" \
	"http://127.0.0.1:$PORT/rule")
grep -q 'Saved.' <<<"$saved" || fail "the POST did not save: $saved"
cmp "$P/agent.yaml" "$W/p/rule-e2e.cli.yaml" || fail "the dashboard wrote other bytes than tego rule"
echo "dashboard POST wrote the same bytes as tego rule"
echo PASS
