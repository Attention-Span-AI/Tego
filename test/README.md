# test/ — anything that is not a unit test next to the code

| Dir | What | Runs where |
|---|---|---|
| `fixtures/ledger/` | ledgers the kill tests recorded on a kernel-matrix row, one directory per kill test and tier; `fixtures/replay_test.go` verifies each and replays it, with the frozen M0 fixture (`spec/record/v1/fixtures`), through `status`, `drift`, `measure` and `events` | anywhere (`go test ./test/fixtures`) |
| `fixtures/init/` | a throwaway project (fake `.env`, the Claude Code contract, a verdict table) for `maze init` to scan and `compile --test` to check; README says how to run it from a Mac | anywhere (Linux, or a container on a Mac) |
| `workloads/` | the agents and helpers the kill tests run: `python-steps/` (20 model steps over the system libssl), `python-anthropic/` (a tool-use agent on the Anthropic SDK), `model-stub/` (a local HTTPS stand-in for the Messages API), `python-httpx/`, `model-agent/`, `npm-agent/`, `go-agent/`, and `build/`, the §9 build workload, and `read-opener/`, the timed open loop `bench/read-notify` runs | host or VM |
| `integration/` | root-required tests of launch, enforce, ask, observe (`//go:build integration`) | VM or a box with sudo |
| `e2e/` | the kill tests of docs/P0-DESIGN.md as scripts, one per criterion | host (their unprivileged halves) and the VM matrix |
| `bench/` | measurements that decide a default: `read-notify/` (ADR 0077) times a read open told to the supervisor against one the filter lets pass, and the offline Claude Code workload, `reason.reads: on` against `off`; it labels a run started at load 2 or more `LOADED` and prints `TARGET-MISS` past the rule (docs/BENCHMARKS.md) | host, no root, through the capped slice |
| `vm/` | `kvm-run.sh`, a root KVM guest without host root, and the kernel matrix on it: Ubuntu 24.04 6.8, Debian 13 6.12, RHEL 9 5.14, AL2023 6.1 and 6.12, Fedora 7.0 (`make vm-matrix`). WSL 6.18 and the macOS Lima job are P2 and not built: WSL's kernel ships only inside its Windows installer | host with `/dev/kvm`, and CI |

Unit tests stay next to the code as `_test.go`. Nothing here is imported by the binary.

## Keeping the developer's own ~/.tego out of it

tego finds its home through the passwd database, never `$HOME` (identity-config.md R21), so a harness that sets
`HOME` isolates nothing: the chain anchor (`~/.tego/chain.log`), the own log (`~/.tego/tego.log`) and the built-in
ledger root are the developer's own. A harness that runs tego builds it with `-tags tegotesthooks`, writes a machine
config whose `ledger_root` is its own, and starts it with `TEGO_CONFIG`, `TEGO_TEST_CHAIN_ANCHOR` and
`TEGO_TEST_OWN_LOG_HOME` (Go tests: `testutil.TegoEnv`; shell: `kt_config` or `lib_init`); a driver that opens a
terminal sets `HISTFILE=/dev/null`; one that takes the binary from `TEGO_BIN` refuses a binary that is not a test build
(`kt_require_testhooks`, or `grep -aq TEGO_TEST_CHAIN_ANCHOR "$bin"`). A test build with no `TEGO_TEST_CHAIN_ANCHOR`
refuses to run, and one whose `ledger_root` (the built-in one included), anchor or own-log home is inside the
developer's own `~/.tego` refuses every command (R27), and
`go run ./tools/isocheck` (precommit, `make lint`, CI) fails a harness that could do otherwise. `vm/` is exempt: its
scripts run in the KVM guests, whose home is the guest's. The exception is `vm/root-suites.sh`, which isocheck reads:
its `VM_HOST=sudo` runs on this host, and its `tego doctor` there is the test build with an isolation of its own
unless `TEGO_DISPOSABLE_HOST` says the machine is disposable. isocheck sees that doctor (the `$0` of a `sh -c`
script) and asks only that the file set the isolation variables; `vm/root-suites_test.sh` checks which build the mode
runs and with which variables.
A Go package whose tests can start a run, a sweep, a gc or
the tego binary ends its `TestMain` with `os.Exit(testutil.GuardedMain(m))` (or `GuardedLeakCheckMain`), so a test
that reached the real `~/.tego` or `~/.bash_history` anyway fails the run it does. Under
`go test` the tests run in a re-executed child that the guard checks after, so a panic or the test timeout does not
skip the check; a binary run directly (as `vm/root-suites.sh` runs its suites) checks in its own process, which a
panic or the timeout ends first (identity-config.md R27).
