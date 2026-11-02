Operator scripts: `install.sh`, `install-maze.sh`, `release.sh`. Plain POSIX sh, reviewed like code. `install.sh` and
`install-maze.sh` are also release assets (`.goreleaser.yaml`). Turning on BPF LSM at boot is the machine owner's step;
`tego doctor` says whether it is on.

Developer scripts, not shipped: `check-spdx.sh` (CI's SPDX header check),
`check-licenses.sh [dist-directory]` (license texts, linked dependency notices, the licence files the binaries embed for
`licenses`, and optional checksummed release archive),
`install_test.sh` (install.sh's
verification paths, tego-control beside tego and its pin included, against a release laid out on local disk;
`make install-test`), `coverage.sh` (coverage
merged across the unit, integration and privileged suites, and with `--kill-tests ROW` the tego that one
kernel-matrix row's kill tests run; `make coverage`, `make coverage-vm`), which is bash, and `coverage_test.sh`
(how coverage.sh reads its arguments and what it does with a guest that returns no data, with stand-ins for go
and test/vm; `make coverage-test`), `bench-gate.sh` (CI's benchmark gate: the hot paths' benchmarks of this
checkout against a base checkout's, alternating rounds, decided by benchstat; bash; `make bench-gate
BASE=<dir>`) and `bench-gate_test.sh` (its decision and runs, with stand-ins for go and benchstat, or the pinned
benchstat when `BENCHSTAT` names it; `make bench-gate-test`), `timing-budgets.sh` (the absolute timing budgets,
ADR 0048 C8's, the plane fill's, the datagram flood's, ADR 0023 P1's Borrow ratio and the Rules page's 55k-line read (`TestInForceLongRunIsFast`), asserted as written with
`TEGO_TIMING_BUDGETS=1`; first in CI's bench-gate job; bash; `make budgets`, on an idle machine; its test list is held
to the tree's `testutil.TimingMode` callers by internal/testutil's `TestTimingBudgetsListsEveryBudgetTest`) and
`timing-budgets_test.sh` (its runs and decision, with a stand-in for go; `make budgets-test`), `skipgate.sh`
(which reads `go test -json` and fails on a skip that `test/unit-skips.txt` does not allow, or with `--must-pass`
on a listed test that did not pass, as CI's unit step and root-suites job use it; bash and jq) with `skipgate_test.sh` (`make
skipgate-test`), `check-skiplists.sh` (the skip and must-pass lists name tests that exist, once each, and every
root-only skip the integration step allows is in the root run's lists; CI's build-test), `check-exits.sh`
(`os.Exit` only in `cmd/`, no bare exit code in `internal/cli`: limits-check-doctor-cli.md I6, I9, checked by
`tools/checkexits` on the syntax tree; CI's build-test), `check-fd.sh` (ADR 0023's descriptor ownership:
`tools/fdcheck`'s birth rule, leases, listed sites, close-on-exec and per-package ratchet; `--base REV` holds the
baseline's per-kind totals and the F4 lists' to REV's, and each package's count of each kind, which rises only by
sites moved from another package with the declaration they are in; `make lint`, precommit, CI's build-test and
bench-gate)
with `check-fd_test.sh`
(golangci-lint on `testdata/fdlint`: one report per A4 primitive, the testutil denial, ADR 0021's text scope with
its negative control; CI's build-test), `check-edgelint_test.sh` (golangci-lint on `internal/control/web/testdata/edgelint`:
one report of the edge's socket ban, ADR 0100 (1d), on each marked dial, listen, name lookup, dialing HTTP client and
raw socket, none on what the edge is handed, and the edge's depguard denial of `net/rpc`, `net/smtp` and `log/syslog`;
CI's build-test and precommit), `deadcode-report.sh -o NEW_DIRECTORY` (ADR 0029 (4): deadcode v0.50.0
over ./cmd/tego in the eight production profiles, linux amd64/arm64 x plain, integration, tegobpf and both, then
`tools/deadcodereport -gate`, which fails on an unreachable function `tools/deadcode-allow.txt` does not classify,
on a classification no profile finds and on a profile the tool could not analyze; bash; CI's deadcode-report job,
gating) with `deadcode-report_test.sh` (its orchestration with stand-ins for go and deadcode; `make
deadcode-report-test`), `precommit.sh` (CI's
build-test checks before a commit; `make precommit` and `.githooks/pre-commit`; its steps run concurrently through `precommit-runner.sh`, `TEGO_PRECOMMIT_JOBS=1` serially, and `TEGO_PRECOMMIT_SINCE=<rev>` / `make precommit-affected BASE=<rev>` is the change-scoped in-between mode tools/affected selects for) with `precommit_test.sh` (precommit runs every self-test CI does; ci.yml gives each push its own concurrency group), `bpf-toolchain.sh` (fetches the pinned clang `make gen` compiles bpf/ with; CI's bpf-gen), `check-bpf-objects.sh` (`make gen` at a fixed path in a clean `git archive HEAD` copy must reproduce internal/bpf byte for byte, so a worktree's or other clang's BTF is caught; CI's bpf-gen, and precommit when bpf/ or internal/bpf/ differs from origin/main or TEGO_PRECOMMIT_BPF=1) and `--fix` (writes them), with `check-bpf-objects_test.sh` (a stand-in make; tampered, dropped and added files), `check-installer-repo.sh` (install.sh names
the repository a release is built in; release.yml runs it before building), `check-skiplists_test.sh` (the
self-test of `check-skiplists.sh`), `release_test.sh` (release.sh's push and tag refusals in a throwaway repository; `make release-test`), `bpf-toolchain_test.sh` (bpf-toolchain.sh's guard on the directory it empties), `tree-files.sh` (the tree's files for the copy into a KVM guest, minus tracked files deleted from the working tree) with `tree-files_test.sh`, `fd-churn.sh` (a package's tests under `-race`, repeated, beside a create/open/close/unlink churn in another process: each ADR 0023 package migration's gate) with `fd-churn_test.sh` (its negative control, `testdata/fdchurn`'s double close, fails under it within `-count=50`; CI's build-test), and `in-user-manager.sh` (a
command inside the invoking user's systemd user manager, where an unprivileged run can place its agent).

Also here: `gated-test.sh` (`go test -json` in the user's systemd manager, held to a skip list), `gofmt-clean.sh` (fails naming the files gofmt would reformat; `make lint` and precommit), `lint-untagged.sh` (golangci-lint over the files the build tags leave out), `live-e2e.sh [work-dir]` (live blocks end to end against a looping probe agent, isolated from the person's own tego: a held-reads run refuses and frees the probe's reads within 2 s, a watched run only records; needs a built tego, run by hand), and the self-tests `check-licenses_test.sh`, `check-spdx_test.sh`, `deadcode-report_test.sh`, `fuzz-corpus_test.sh`.
