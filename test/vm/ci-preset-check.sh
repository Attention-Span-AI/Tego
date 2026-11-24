#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Owed acceptance check. Run only in a disposable guest with /vm/tego staged.
set -eu
test -x /vm/tego
test "$(id -u)" = 0
test -n "${SUDO_UID:-}"
test -n "${SUDO_GID:-}"
fixture=/vm/ci-check
mkdir -p "$fixture/work/out" "$fixture/work/.github/workflows" \
  "$fixture/work/runner/_temp" "$fixture/work/runner/_actions" \
  "$fixture/ledger" "$fixture/owner/.tego"
printf 'private-canary\n' > "$fixture/secret"
printf '{}\n' > "$fixture/work/runner/event.json"
printf 'ledger_root: /vm/ci-check/ledger\n' > "$fixture/config.yaml"
cat > "$fixture/probe.sh" <<'PROBE'
#!/bin/sh
set -eu
for name in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_RUNTIME_TOKEN \
  ACTIONS_RUNTIME_URL ACTIONS_CACHE_URL ACTIONS_RESULTS_URL ACTIONS_CACHE_SERVICE_V2 \
  GITHUB_TOKEN GH_TOKEN SIGSTORE_ID_TOKEN INPUT_TOKEN INPUT_GITHUB_TOKEN; do
  eval 'test "${'"$name"'+present}" != present' || exit 31
done
# Fail before the refusal probes if their output sink cannot be opened.
: >/dev/null
printf 'CI-TOKENS absent\n'
printf 'allowed\n' > out/allowed.txt
if cat /vm/ci-check/secret >/dev/null 2>&1; then exit 32; fi
printf 'CI-READ refused\n'
for path in .github/workflows/receipt.yml runner/_temp/step runner/_actions/action runner/event.json; do
  if (printf mutation > "$path") 2>/dev/null; then exit 33; fi
done
printf 'CI-WRITES refused\n'
PROBE
cat > "$fixture/ci.yaml" <<'CONTRACT'
version: 0
name: ci-guest
extends: tego/ci@1
command: [/bin/sh, /vm/ci-check/probe.sh]
tier: landlock
record: summary
capture: off
fs:
  write: [/vm/ci-check/work/, /dev/null]
  deny_read: [/vm/ci-check/secret]
  # These concrete paths stand in for the action's runtime inputs. The preset
  # supplies only .github. This is an ordinary-command check, not a race proof.
  deny_write: [./runner/_temp/, ./runner/_actions/, ./runner/event.json]
CONTRACT
chown -R "$SUDO_UID:$SUDO_GID" "$fixture"
chmod 700 "$fixture" "$fixture/owner" "$fixture/owner/.tego" "$fixture/ledger"
chmod 600 "$fixture/config.yaml"
export TEGO_CONFIG="$fixture/config.yaml"
export TEGO_TEST_CHAIN_ANCHOR="$fixture/owner/.tego/chain.log"
export TEGO_TEST_OWN_LOG_HOME="$fixture/owner"
for name in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_RUNTIME_TOKEN \
  ACTIONS_RUNTIME_URL ACTIONS_CACHE_URL ACTIONS_RESULTS_URL ACTIONS_CACHE_SERVICE_V2 \
  GITHUB_TOKEN GH_TOKEN SIGSTORE_ID_TOKEN INPUT_TOKEN INPUT_GITHUB_TOKEN; do
  export "$name=synthetic-ci-canary"
done
cd "$fixture/work"
/vm/tego doctor --require landlock
/vm/tego run "$fixture/ci.yaml"
/vm/tego receipt --last --verify --json > "$fixture/on.json"
printf '\nreason: {reads: off}\n' >> "$fixture/ci.yaml"
/vm/tego run "$fixture/ci.yaml"
/vm/tego receipt --last --verify --json > "$fixture/off.json"
python3 - <<'PY'
import json
from pathlib import Path
base = Path('/vm/ci-check')
for mode in ('on', 'off'):
    receipt = json.loads((base / (mode + '.json')).read_text())
    assert receipt['tier'] == 'landlock' and receipt['ended'] and receipt['exit_code'] == 0
    rn = receipt['reads_notified']
    expected = {'notified': True, 'why': 'reason'} if mode == 'on' else {'notified': False, 'why': 'reason-off'}
    assert rn == expected, (mode, rn)
    lines = [json.loads(line) for line in (base / 'ledger' / receipt['run'] / 'events.jsonl').read_text().splitlines()]
    reads = [line for line in lines if line.get('kind') == 'fs' and line.get('verdict') == 'refused'
             and line.get('reason') == 'read-denied' and line.get('path') == str(base / 'secret')]
    assert len(reads) == (1 if mode == 'on' else 0), (mode, reads)
    note = receipt['sensitive_reads_note']
    assert ('only refused reads are listed' if mode == 'on' else 'allowed or refused') in note, (mode, note)
assert (base / 'work/out/allowed.txt').read_text() == 'allowed\n'
assert (base / 'work/runner/event.json').read_text() == '{}\n'
for path in ('.github/workflows/receipt.yml', 'runner/_temp/step', 'runner/_actions/action'):
    assert not (base / 'work' / path).exists(), path
print('CI-RECEIPT on=reason off=reason-off')
print('CI-GUEST PASS')
PY
