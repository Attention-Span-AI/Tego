# test/fixtures

`ledger/<name>/` holds one run each, recorded by a kill test on a kernel-matrix row (P0-DESIGN §10: "every
kill test adds a recorded fixture"): `events.jsonl` as the run wrote it, `contract.yaml` and `blobs/` when
the run had them, and `chain.log`, the run's line of the anchor its ledger is verified against. The name is
`<kill test>-<half or kind>-<tier>`, the one `test/e2e/lib.sh` `kt_save_fixture` gives it.
Paths, the version key and the host tag were normalised after recording: the product's earlier name in the temporary
paths and in the `run_start` version key (now `tego_version`) was rewritten, the machine's tag in each run id became an
invented one, and each ledger's hashes, contract hash and `chain.log` line were computed again, so the chain still
verifies. The runs themselves are as recorded. A hash that is not recomputed still commits to the text it covered, so a
ledger is never scrubbed line by line: `scripts/scrub-capture.sh` refuses one.

A fixture is the product's record of a real run, not a certificate that the kill test passed: a kill test
saves the ledger of every run it judges, whatever its verdict, because the views must read every shape a
run can leave behind. The kill test's verdict for that run is in the matrix report of the same recording.

`replay_test.go` (`go test ./test/fixtures`) verifies each fixture's hash chain against its `chain.log`,
replays it with the frozen M0 fixture (`spec/record/v1/fixtures`) through `status`, `drift`, `measure` and
`events` as the CLI runs them, checks `events --json` returns the stored bytes, and fails when a kill test
that runs an agent (1, 2, 4, 6, 7) has no fixture, or when a fixture names an account or a home directory. Kill
tests 3 and 5 keep none: their runs are timing samples of other kill tests' workloads (`replay_test.go`).

Recording them: `test/vm/matrix.sh --save-fixtures ubuntu-24.04` runs the matrix and copies that row's
ledgers here, replacing the ones with the same names. Kill test 7 (a) needs the Claude Agent SDK, which the
guest carries only with `VM_KT7A=1`, so its fixtures (`kt7-a-landlock`, `kt7-a-cli-landlock`) were recorded on a
host: `TMPDIR=/tmp KT_FIXTURE_DIR=test/fixtures/ledger test/e2e/kt7-two-agents.sh a`. The kill tests keep their
paths under `$TMPDIR`, `/tmp` in the guest; `kt_save_fixture` refuses to save a ledger that names the account
anywhere (its name, any `/home/`, any home flattened into one directory name such as Claude Code's
`/tmp/claude-<uid>/-home-<name>-<project>/`, its `/run/user/<uid>`), and `TestFixturesNameNoAccount` holds the
checked-in fixtures to the same shapes. The name it checks is that of whoever runs the tests, which is not the
recording account (on GitHub's runners it is `runner`, and pytest's own `_pytest/runner.py` is in
`kt4-pip-landlock`), so the test counts that name only where it stands alone, not inside a longer word; the
recording side, which knows the recording account, refuses its name inside a longer word as well.
