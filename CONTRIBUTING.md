# Contributing

Thank you for looking. This page is the short version of how to build, test and send a patch.

## Your first patch

You need Linux, Go 1.27, `make` and [golangci-lint](https://golangci-lint.run/). Most of the code builds and tests as an ordinary user.

```sh
git clone https://github.com/Attention-Span-AI/Tego
cd Tego
make build                              # bin/tego and bin/tego-control
go test -count=1 ./internal/cli/...     # one package's tests, in seconds
make lint                               # format, vet, golangci-lint, SPDX, the repository's own checks
```

Change the code, add a test, run the tests of the package you touched and `make lint`, then open a pull request. The
pull request template lists what to include. `make precommit` runs the whole gate and is slow (see below), so it is fine
to let CI do that part.

Tests that need root or a particular kernel skip themselves when they cannot run. A skip is never a pass: the skip lists
(`test/unit-skips.txt` and friends) say which skips are allowed, and CI fails on any other.

## Layout and rules

- Read `docs/REPO-LAYOUT.md` first. The import rules are enforced by `golangci-lint` (depguard), so a forbidden import
  fails `make lint`.
- One concept per package. Every package has a package comment, usually in `doc.go`, that says what it does, what it
  imports, and what it must not import. Keep it true.
- Behaviour is specified before it is built: `docs/p0/` has one spec per engine component with numbered rules that code
  and tests cite, and `spec/` holds the versioned formats. If your change alters behaviour or a field, update the
  spec in the same pull request. Never renumber a rule.
- Decisions are recorded in `docs/adr/`. A decision that changes an accepted ADR is a new ADR, not an edit.
- No model calls anywhere in this repository (ADR 0003). Tego enforces and records; it never asks a model to judge.
- Exit codes come from `pkg/spec/identity`. Only `cmd/` calls `os.Exit`.

## File descriptors are owned values

Go's file descriptors are easy to leak, double-close or lend out by accident, so this repository has rules for them
(ADR 0023). `make lint` runs `scripts/check-fd.sh` (`tools/fdcheck`), which holds the ones golangci-lint cannot.

- Make a descriptor an owner in the expression that creates it: `sys.Own(unix.Openat(..., flags|unix.O_CLOEXEC, ...))`
  or one of the `sys` helpers (`sys.Pipe2`, `sys.PidfdOpenProcessFD`, and so on).
- Never close, dup or wrap a bare number. Lend it with `Borrow(fn)` (or `Hold` for a loop's lifetime), give it away with
  `Release`, close it with `Close`.
- Use an `*os.File`'s number only through `sys.FileDo`, `sys.Flock` or `sys.FstatFile`, never `Fd()`.
- A number lent to a callback is used inside that call only. Do not keep, return, send or capture it.
- A package not listed in `tools/fdcheck/baseline.txt` has no raw descriptor site at all. A listed package keeps at most
  the counted ones, and a commit that removes a site lowers its count (fdcheck prints the line to write). No count ever
  rises. A `//nolint` that silences forbidigo is itself a raw site.

A lint message that says "ADR 0023" names the forbidden primitive and the owner call to use instead.

## Kernel-side code

The BPF programs are in `bpf/`. The compiled objects and Go bindings are committed under `internal/bpf`, so a normal build
needs no clang. After a change in `bpf/`, regenerate them and commit the result:

```sh
scripts/check-bpf-objects.sh --fix
```

The script builds in a fixed directory with the pinned toolchain, because the compiler's output depends on the path it
runs in. A plain `make gen` in your checkout makes different bytes, and CI's `bpf-gen` job rejects them.

## Tests

- Anything that needs root or a specific kernel goes under `test/integration` or `test/e2e` with a build tag, never in
  unit tests.
- The privileged suites run in a KVM guest: `make vm-root-test` (see `test/vm/README.md`). They need `/dev/kvm`. CI runs
  them as root on its runner, on every pull request and on pushes to `main`.
- Use `go test -count=1`. A cached result can hide a change that only a subprocess test notices.
- Tests must not touch your real `~/.tego` or `~/.config/tego`. Point them at a temporary directory.

## Licence, headers and sign-off

- Apache-2.0, except the kernel programs and the headers written for them under `bpf/`, which are dual GPL-2.0-only OR
  BSD-2-Clause (ADR 0012). `bpf/include/vmlinux.h` is GPL-2.0-only and `bpf/include/libbpf/` keeps its LGPL-2.1 OR
  BSD-2-Clause.
  The Go tests under `bpf/tests` are Apache-2.0.
- Every source file needs an SPDX header (`scripts/check-spdx.sh` checks it).
- Sign off your commits under the Developer Certificate of Origin: `git commit -s`.

## Before a commit

`make precommit` (`scripts/precommit.sh`) runs CI's build-test checks locally: gofmt, `go vet` untagged and with each build
tag, golangci-lint twice (with the tags and without, as CI does), the SPDX check, shellcheck when installed, the skip-list
and exit-code checks, the descriptor check, `tools/rulecheck` (rule ids unique, no reference to a rule that does not exist,
every relative Markdown link and anchor resolves), and the unit and unprivileged integration tests through
`scripts/skipgate.sh`. Every `go test` step runs with `-count=1`, so the gate takes its full time: about 20 to 25 minutes on
a developer machine. To run it before every commit:

```sh
git config core.hooksPath .githooks
```

`git commit --no-verify` skips the hook for a work-in-progress commit.

## After you open a pull request

CI runs two workflows on it: `ci.yml`, whose jobs are `build-test`, `build-test-arm64`, `scripts-and-workflows`, `bpf-gen`,
`bpf-load`, `bench-gate`, `root-suites`, `race`, `reproducible`, `coverage` and `deadcode-report`, and `container.yml`.
[`.github/workflows/README.md`](.github/workflows/README.md) says what each job checks.

- `root-suites` runs the privileged test suites as root on the runner. It runs on every pull request and takes about two
  hours, so it is usually the last check to finish.
- GitHub runs no workflow on a pull request from a fork until a maintainer approves the run, a safeguard for public
  repositories. This repository asks for that approval on every pull request from outside the project, not only on a
  first one, so a wait before the checks start is normal.
- A job that fails on something your change did not touch, such as a network fetch or a timing budget on a busy runner,
  can be re-run. Say so in the pull request and name the job, and a maintainer re-runs it.

How your change lands: this repository is published from a source repository by an export, so a pull request is not
merged here. Once it is approved, a maintainer ports your change into the source repository with you as its author, and
the next export publishes it in a commit that credits you (a `Co-authored-by` line) and names your pull request. The
pull request then shows as closed rather than merged, with a link to that commit. If the port has to differ from your
patch, the maintainer says why in the pull request.
