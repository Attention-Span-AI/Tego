# Workflows

What each workflow does, for someone changing one or reading a red check.

All of them run on GitHub-hosted runners (`ubuntu-24.04`, and `ubuntu-24.04-arm` for one job). Each job has a timeout,
reads the repository with a read-only `GITHUB_TOKEN` unless it says otherwise, pins every action by commit SHA
(Dependabot proposes the updates, `.github/dependabot.yml`) and builds with one exact Go release, set in `GO_VERSION`.
A Go patch release is taken by editing that line in `ci.yml`, `fuzz.yml`, `vm-matrix.yml` and `release.yml` together.

## ci.yml

Runs on every push and pull request. A newer push to a pull request cancels the older run; a push to a branch is never
cancelled.

| Job | What it checks |
|---|---|
| `build-test` | gofmt, `go vet` (plain and with the build tags), golangci-lint, the SPDX check, `tools/rulecheck`, `govulncheck`, the shell-script self-tests, the unit tests held to `test/unit-skips.txt` by `scripts/skipgate.sh`, and every package's unprivileged integration tests |
| `build-test-arm64` | The arm64 build with its BPF objects, the unit tests, every BPF program through the verifier as root, and the first runs of the decision plane on an arm64 kernel |
| `scripts-and-workflows` | shellcheck over every tracked shell script and actionlint over the workflows |
| `bpf-gen` | The committed BPF objects are exactly what the pinned clang makes of `bpf/` |
| `bpf-load` | Every BPF program loads, and the tier-2 backend decides, on the runner's kernel, as root |
| `bench-gate` | The hot paths' benchmarks against the base commit's (`scripts/bench-gate.sh`), plus the absolute timing budgets (`scripts/timing-budgets.sh`) |
| `root-suites` | Every privileged test suite, as root on the runner through `sudo` (`test/vm/root-suites.sh`), in the seven parallel `root-suites-shard` jobs; `root-suites` passes only when every shard passed and the root-only tests of `test/vm/root-must-pass.txt` passed in them |
| `race` | The unit and unprivileged integration tests under the race detector, in shuffled order |
| `reproducible` | The release target built twice, at two paths with two build caches; the bytes of `tego`, `tego-control` and `maze` for linux/amd64 must match |
| `coverage` | Per-package coverage, uploaded as an artifact (report only) |
| `deadcode-report` | Every function the shipped binaries cannot reach is classified in `tools/deadcode-allow.txt`; an unclassified one or a stale entry fails the job |

**`root-suites` runs on every pull request**, a fork's included,
and on a push to `main`, and the main ruleset requires it, so a change is merged only after the privileged suites
pass. It runs the change's code as root, as `bpf-load` and `build-test-arm64` do: a pull request runs its own copy of
these files, and a fork's code is held by the runner, a fresh VM with no secrets and a read-only token, and by
GitHub's approval of a first-time contributor's run. Its shards' runners cost nothing on a public repository's hosted runners. Locally, `make vm-root-test` runs them in a KVM guest.

**`bench-gate` runs on a shared runner.** Its absolute timing budgets assume nothing else is running, and shared runners
are noisy. The budgets are figures on a developer's machine, and a hosted runner makes a system call at two to three
times its cost, so the job holds the two exec cases whose cost is a few system calls and that missed their limits there
to twice their figures (`scripts/timing-budgets.sh --hosted`), and compares the exec path with the base commit's
(`BenchmarkExecCommandCost`) for a smaller regression. Treat a failure as a prompt to re-run and look, not as proof.

## vm-matrix.yml

Boots KVM guests on a matrix of kernels and runs `tego doctor`, the kill tests, the BPF load tests and the tier-3 suites on
each. **It runs by hand only** (`workflow_dispatch`), not on a schedule and not on tags. The guests need `/dev/kvm`
read-write for the runner user; the workflow's first step tries to open it with a udev rule, and fails the row by name
when it cannot. Whether a hosted runner allows that has not been shown yet, so check the first rows before relying on it.

## container.yml

On every push and pull request: builds the container image from `examples/container`, then runs `tego doctor`, the image's
smoke test and the dashboard service inside it. See `docs/user/container.md`.

## fuzz.yml

Nightly, and on demand: every `Fuzz*` target in the tree for ten minutes each, with the generated corpus carried from night
to night. Scheduled workflows pause after 60 days without repository activity (a GitHub rule).

## release.yml

Runs on `v*` tags. A gate first (a tag named `vX.Y.Z` or `vX.Y.Z-pre`, annotated, on a commit in `main`'s history, with a
green `ci` run on it), then goreleaser builds the binaries, SBOMs and checksums into a draft release; `govulncheck` runs over
the built binaries; the checksums, which also list the two installers, are signed with cosign (keyless) and build provenance
is attested; then the release is published. A `reproduce`
job rebuilds the tag and compares it with the published checksums (`docs/VERSIONING.md`, section 5). The repository's
default branch must be named `main` for the gate to find the history. No release has been cut yet.

## Fuzz findings, kept as tests

A fuzz finding is fixed together with a committed input under its package's `testdata/fuzz` that fails with the fix taken
out. Some tests (`TestFuzzBodyCorpusSetsOnlyKnownModes` is one) keep committed inputs inside what their target defines.
