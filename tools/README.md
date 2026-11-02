Developer tooling only, never imported by the binary, and exempt from checkexits' I6 (tools/ may call `os.Exit`).

- `dashgen/`: writes a big isolated ledger root for measuring the dashboard (`go run ./tools/dashgen -root DIR -anchor
  FILE`: 300 ended runs of 500 lines, one of 200,000 lines, one live run), every run through the ledger's own Writer
  with a valid chain; docs/DASHBOARD.md, "Read model, bounds and speed". The live run reads as running only while a
  process holds its lock (`flock <root>/<run>/lock sleep 1h`), as lost otherwise.
- `rulecheck/`: reads the rule IDs of docs/p0/*.md and fails on a duplicate ID, a reference to a lettered part or rule the
  named document does not define, and reports which rules no test mentions (CI's build-test; `go run ./tools/rulecheck`).
- `affected/`: the change-scoped selection behind `make precommit-affected BASE=<rev>` (`go run ./tools/affected
  -base REV [-plan]`): the changed files since the merge base, classified (global input → the full gate, Markdown
  alone → the docs gate, else the packages the change reaches per build), plus the source scanners found by scanning
  test code and the suites whose tests build a binary whose closure changed; it prints what it selected and why.
  For in-between checks only; merges keep the full gate (docs/OPERATIONS.md, "Precommit modes").
- `checkexits/`: `os.Exit` only in `cmd/`, no bare exit code in `internal/cli` (limits-check-doctor-cli.md I6 and
  I9), read from the syntax tree; run by `scripts/check-exits.sh`.
- `isocheck/`: no test harness can write the invoking user's own `~/.tego` or `~/.bash_history` (identity-config.md
  R27): an `os.Environ()` taken before `writeMachineConfig` sets the isolation variables, a `TEGO_CONFIG` entry with
  no `TEGO_TEST_CHAIN_ANCHOR`, a build of `cmd/tego` without `tegotesthooks`, a command that runs the tego
  binary with the inherited environment (GO-5), a script that assigns `TEGO_CONFIG`
  without the anchor and own-log variables, a script that builds `cmd/tego` without the tag or runs a tego binary
  with neither, a script that starts a run without an `XDG_RUNTIME_DIR` of its own or with the inherited one (SH-7:
  a launch makes and sweeps `<XDG_RUNTIME_DIR>/tego`, R27 clause b4), a script that runs the binary its caller names
  without checking it is a test build, a
  pseudo-terminal or interactive shell without `HISTFILE=/dev/null`, and a package whose tests can start a run, a
  sweep, a gc or the tego binary (its tests or its own code import `internal/cli` or `internal/runtime`, directly
  or through a package of the module, or it runs or configures the binary) without a `TestMain` that exits with the
  code of `testutil.GuardedMain(m)` or `GuardedLeakCheckMain(m)` (GO-4).
  Run by precommit, `make lint` and CI (`go run ./tools/isocheck`; `test/vm` is exempt, it runs in the KVM guests, but
  for `root-suites.sh`, whose `VM_HOST=sudo` runs on the host: SH-5 follows its doctor, the `$0` of a `sh -c` script,
  and asks that the file set the isolation variables; `test/vm/root-suites_test.sh` checks which doctor that mode runs).
- `fdcheck/`: ADR 0023's descriptor rules that forbidigo cannot hold (A9, A10 F1–F11), on packages type-checked
  with go/types under each build the project ships (load.go; a file no build includes fails): a fresh number
  becomes a `sys.FD` owner where it is created, leases are returned, a lent number is used only in the ways
  lent.go admits (a syscall's argument, a comparison, a local; never kept, returned or handed on), the listed Adopt, Abandon,
  Inherited and Stdio sites, close-on-exec flags, no exported API passes a bare number, no product binary links
  test code, and the ratchet: `baseline.txt` counts each unmigrated package's raw sites by kind, exactly, and any
  other package has none. `producers.txt` and `edges.txt` are generated (`-producers -w`, `-edges -w`) and checked
  to be current; `-baseline` prints the measured counts and `-list` every site. Run by `scripts/check-fd.sh`
  (`make lint`, precommit, CI).
- `spike/walk/`: the path-walk spike's program, `build.sh`, `run.sh` and the results of the run
  (`results-2026-09-29.tsv`); kept as the measurement an ADR cites, not part of the build.
- `deps.go` (build tag `tools`): keeps the TCB's allowed third-party modules, go-landlock among them, pinned in
  go.mod although no shipped package imports them.
- `adoptiongen/`: derives compact pinned-object checks from the committed BPF ELF files, with the same cilium
  parser as the full loader but outside the launcher's path; it checks every committed endian and architecture variant.
- `deadcodereport/`: formats the eight production reachability profiles (linux amd64/arm64 x plain,
  integration, tegobpf, integration+tegobpf) collected by `scripts/deadcode-report.sh -o NEW_DIRECTORY`
  using deadcode v0.50.0, and applies the ratchet (`-gate`, ADR 0029 (4)): every unreachable function in
  any profile is classified by exact function in `deadcode-allow.txt` (public-api, under pkg/ only;
  placeholder, pending, tag-only, test-api, tool-only, reflection; each with its reason), every
  classification matches a finding, and a tool failure is an unavailable profile that fails, never zero
  findings. A function only its own package's tests call is not classified: it moves into those tests. CI's
  deadcode-report job gates on it and uploads the raw JSON, stderr, status and report.
