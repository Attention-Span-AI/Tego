# Versioning and releases

## 1. Binary
- Semver `0.y.z` until 1.0. The first release will be `v0.1.0`; no tag has been cut yet. `tego` and `tego-control` are built for linux on
  amd64 and arm64 with `-tags tegobpf` (`.goreleaser.yaml`), so `tego` carries the BPF objects and the root tiers (cgroup
  and bpflsm) are in the binary. They still need root and a kernel that offers them, which no build changes (`tego
  doctor` says what a machine gives). PATCH = fixes; MINOR = features or a new supported record/contract version; a MAJOR
  bump is required to drop a ledger reader or a contract reader.
- `tego version` prints `tego`, `commit`, `date`, `go`, `contract_schema`, `record_v`, `record_readers`, `bpf_hash`,
  `parsers`, `control_sha256`, one `key=value` per line and `--json`. It is the first line of every bug report and of
  `tego doctor`. `control_sha256` (*added 2026-10-24*, ADR 0100 (1b)) is the SHA-256 of the `tego-control` the build
  pinned, `none` for an unpinned build. `tego-control version` prints `tego-control`, `commit`, `date`, `go` and
  `sha256`, the hash of the image it runs; a matched pair prints the same version, commit and date, and that hash
  is the pin.
- Version source, the same for both binaries (`internal/buildinfo`): goreleaser's ldflags on tags
  (`-X github.com/attention-span-ai/tego/internal/buildinfo.version=...`, `commit`, `date`); otherwise `debug.ReadBuildInfo()` (`Main.Version` from the VCS tag,
  `+dirty` when modified; `dev` when none). `go.mod` declares `go 1.27` and `toolchain go1.27.3` (ADR 0029 step 1);
  CI, the fuzzers and the release build with exactly Go 1.27.3 (`GO_VERSION` in each workflow), the same patch
  release, so no job downloads another toolchain, pinned so that two builds of one commit are byte-identical (§5).
  A packager's older Go with the default `GOTOOLCHAIN=auto` downloads go1.27.3, and fails offline; with
  `GOTOOLCHAIN=local` it refuses the module. 1.26 was never tested: under 1.26.8 the tree built and vetted, but
  `compress/flate` wrote other bytes and httpstream's `TestGoldenEncodings` (gzip, deflate) failed, and the
  goroutine leak gate (internal/testutil) has no profile to read there and now fails rather than pass.

Library callers that need the CLI's decision model use `github.com/attention-span-ai/tego/pkg/policy/evaluate`.
That experimental bridge tracks the selected Tego module version; pin it with the binary being modeled.
It also links the core for the deprecated `pkg/spec/agent` evaluation methods. Loading and compiling a
contract alone does not link the core, and external modules cannot import `internal/policy/decide`.

## 2. Run record (`spec/record/v1`)

- `v: 1` is frozen at M0 as the field list in `spec/record/v1/README.md`; the M0 fixture ledger is the contract for
  every view.
- Within v1 only optional fields may be added; readers ignore unknown fields; `tego events --json` prints stored line
  bytes verbatim (the hash chain requires it).
- Removing or re-meaning a field bumps `v` and creates `spec/record/v<N>/` with its own README and fixtures. The
  binary keeps a reader for every `v` it has ever shipped; dropping one is a MAJOR bump. There is no migration or
  rewrite command: rewriting would change every `id` and break the `chain.log` anchor.
- CI runs every view in `internal/check` against every readable `spec/record/v<N>/fixtures/`.
- `run_start` records `tego_version`, `commit`, `contract_hash`, `bpf_hash`, `tier`, `kernel`, `parsers`; a live run
  keeps writing with the binary that started it, and a newer `status`/`drift` reads it.
- Exception, before any release (2026-10-24): when the product took its name, ADR 0060 renamed `run_start`'s
  product-version key to `tego_version` with no `v` or `record_minor` move. Nothing had shipped, the chain hashes
  no key names, and readers ignore unknown fields, so every earlier ledger still decodes and verifies (its version
  reads empty). No later rename or re-meaning of a field may use this exception.

## 3. Contract (`spec/agent/v0`)
- `version: 0` on the file. Unknown fields are errors from M0 (yaml.v3 `KnownFields(true)`): a misspelt `write:` must
  never pass silently.
- Until `v0.2.0` the v0 field set may change without notice. From `v0.2.0` fields are only added; a removed or re-meant
  field is `version: 1`, `compile` warns on the old field for one MINOR release, and `compile --upgrade` rewrites the
  file and prints the diff.

## 4. BPF objects
- Pinned under `/sys/fs/bpf/tego/<bpf_hash>/`, not `<version>`: two binaries with the same object share one attached
  copy, and a binary with a different map layout can never attach to old maps.
- The bpf2go output, objects included, is committed; CI's `bpf-gen` job regenerates it with the pinned clang (LLVM
  20.1.8, `bpf/README.md`) and fails on any difference, so one commit always yields one `bpf_hash` and a release
  build needs no clang.

## 5. Releases
- Two Linux binaries per target (*added 2026-10-24*, ADR 0100 (1a)): `tego` and `tego-control`, raw, side by side. The
  tego build's pre hook (`scripts/control-pin.sh`) builds tego-control with the tego-control build's own flags and
  links its SHA-256 into tego (`internal/handoff.controlSHA256`); release.yml fails the draft unless each tego pins
  the tego-control it ships (`scripts/check-control-pin.sh --static`), its `reproduce` job rebuilds and compares
  both binaries, and CI's `reproducible` job runs the same check. `make build` writes the pair the same way.
- `.goreleaser.yaml`: `CGO_ENABLED=0`, `-trimpath`, `-tags tegobpf`, `-buildmode=exe` (static and not PIE, a
  release choice for portability: since ADR 0021 (4) tier 2 runs a dynamically linked or PIE build too, and the guest
  run of a PIE build is that ADR's open condition), `tego` and `tego-control` for `linux` only, `amd64` and
  `arm64`, sha256 checksums, raw binaries, one SPDX SBOM per binary. `maze` ships beside them as a `.tar.gz` for macOS
  and Linux, `amd64` and `arm64`, which `scripts/install-maze.sh` unpacks on Linux. `make release` stays the snapshot build (no SBOM, nothing
  signed or published); `.github/workflows/release.yml` runs on `v*` tags only.
- Every release also includes `tego_<version>_licenses.tar.gz`, covered by those checksums and the release
  attestation. It contains `LICENSE`, `NOTICE`, `LICENSES/`, and `THIRD_PARTY_NOTICES.txt`. Distribute it with
  the raw executable. CI checks that linked module versions have notices; the release workflow checks
  that the archive contains the texts and is covered by its checksums before signing and publishing.
  (Amended 2026-10-05: `scripts/check-licenses.sh` also requires every LICENSE, LICENCE, COPYING or NOTICE file on
  a linked package's directory chain, up to its module's root, in `THIRD_PARTY_NOTICES.txt`, whitespace aside, so
  a sub-package's own licence such as `klauspost/compress`'s `zstd/internal/xxhash` MIT notice is not missed; an
  empty module listing fails; `scripts/check-licenses_test.sh` holds it to both.)
- `release.yml` has goreleaser create the release as a draft, fails it on a reachable vulnerability in the built
  binaries (`govulncheck -mode=binary`, in the read-only `reproduce` job, on the byte-identical rebuild), signs the checksums file with cosign keylessly (the certificate names
  `release.yml` at that tag; the bundle is published as `<checksums>.sigstore.json`), attests every checksummed
  file's build provenance (`actions/attest-build-provenance`), and only then publishes. Its `reproduce` job builds
  the tag again on a fresh runner and compares with the published checksums, and CI's `reproducible` job builds
  every commit twice, at two paths with two build caches, and requires identical bytes of `tego`, `tego-control` and
  `maze` for linux/amd64, the runner's target: the build embeds the
  commit's own date, `-trimpath` and `CGO_ENABLED=0` remove paths and cgo, and the pinned toolchain (§1) removes
  the compiler. Attestations need the repository public or on GitHub Enterprise Cloud.
- `install.sh` and `install-maze.sh` are release assets, and both are in the checksums file (`checksum.extra_files` in
  `.goreleaser.yaml`), so the signature and the attestations cover them. That helps someone who downloads, verifies and
  only then runs them (docs/INSTALL.md). It does nothing for a script piped into `sh`, which runs before anything can
  check it (docs/GAPS.md B11); `reproduce` does not compare them, since they are the tag's own files and no build makes them.
- `scripts/install.sh` downloads one tag (`TEGO_VERSION=v0.y.z` to pin), checks who published it when it can
  (`TEGO_VERIFY`: cosign against the signature bundle, or `gh attestation verify` against the provenance; with
  neither on the machine it says that the checksum alone proves integrity, not authenticity), verifies the
  checksum, writes next to the target and installs by `mv` (rename is atomic and leaves live supervisors on their
  old inode; overwriting in place fails with `ETXTBSY` while a run is live). Both verifiers are held to the
  requested tag, not only to the workflow: cosign to the certificate identity `release.yml@refs/tags/<tag>`, gh to
  that identity (`--cert-identity`) and to `--source-ref refs/tags/<tag>`. Without the tag, whoever can replace
  release assets could serve an older release's genuine binary as the newer one, and in gh mode, where the
  checksums file is not itself signature-checked, the attestation's tag is the only check of the version. A
  verifier that is present and fails, or a signature bundle the server says is not there, stops the install
  (exit 9) and prints the verifier's own output; a bundle that could not be fetched is a download failure (exit
  6). Neither falls back to the checksum. *Added 2026-10-25* (ADR 0100 (1b)): when the
  checksums file lists `tego-control_<version>_<os>_<arch>`, install.sh downloads it too, holds it to its checksum
  (and in gh mode to its own attestation), refuses a pair whose tego `version` names another `control_sha256` (exit 7:
  every handed-off command would be `[control-mismatch]`), installs it mode 755 beside tego by the same
  write-beside-then-`mv`, tego-control first, and does not run it (it refuses euid 0, and an install under sudo is
  one); a release that lists none installs tego alone and says that `tego serve` and every command `tego help` marks `(tego-control)` need it, and a pinned tego
  whose release lists none is an incomplete release (exit 7). Condition (amended 2026-11-01): `install.sh` installs the
  executable only and prints where the release's `tego_<version>_licenses.tar.gz` is; `install-maze.sh` copies
  `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.txt` from the maze archive to `share/doc/maze` beside its prefix. The
  binaries neither embed nor print the notices; embedding them behind a command is not built.
- Dependencies: `.github/dependabot.yml` proposes Go module and GitHub Actions updates weekly; every action is
  pinned by commit SHA, and CI runs `govulncheck` on every push.
- A release requires kill tests 1–6 green on the `test/vm` matrix, kill test 7 (docs/FEATURES.md) run by hand on one
  kernel, and the packet capture of kill test 8 (docs/OPERATIONS.md) run by hand once before beta. "No kill test regressed across two releases" means two consecutive `v0.y` tags.
- `docs/CHANGELOG.md`, one section per tag: Added / Changed / Removed / Record `v` / Contract schema / Kernel minimums.
- Built-in presets (*added 2026-10-25*, ADR 0068 D3): every preset revision a tag carries is released and frozen
  from that tag on, so `pkg/spec/presets`' `released` table must list each with the sha256 of its bytes before the
  tag is cut. `make preset-freeze VERSION=vX.Y.Z` fails while one is missing and prints the line to add;
  `scripts/release.sh tag` runs it before the gate, and `release.yml` runs it again before it builds, for a tag
  pushed by hand. From then on `TestReleasedRevisionsAreFrozen` fails if a listed revision's bytes change.

## 6. Licence (ADR 0012)
Apache-2.0 for everything except `bpf/`, which is dual `GPL-2.0-only OR BSD-2-Clause` with
`SEC("license") = "Dual BSD/GPL"` in every program (the kernel refuses non-GPL-compatible LSM programs and GPL-only
helpers at load); the BSD option lets bpf2go embed the objects in the Apache-2.0 binary, as Tetragon and Cilium do.
SPDX header on every source file, checked in CI; `vmlinux.h` and bpf2go output exempt; DCO sign-off.

## 7. Release runbook
`scripts/release.sh` (scripts/README.md: plain POSIX sh, reviewed like code) automates the mechanical, safe half
of this; retraction is deliberately not automated (§7.4).

### 7.1 What must be green before tagging
- `scripts/release.sh check`, which is `make lint` (the Makefile's `lint` target lists its steps: format, the four
  vets, spdx, both golangci-lint runs, skiplists, exits, rulecheck), `make vuln`, `make test` and `make integration`
  — the local half of the gate CI runs. CI alone adds the race detector, `root-suites`, `bpf-gen`, the privileged
  `bpf-load` job, the arm64 job, the reproducible build and `bench-gate`, so the commit being tagged must also be
  green there.
- §5's kill tests 1–6 green on the `test/vm` matrix, kill test 7 by hand on one kernel, the packet capture of kill
  test 8 by hand once before beta; "no kill test regressed across two releases" means two consecutive `v0.y` tags, so check the previous
  tag's results, not just this run's.
- `docs/CHANGELOG.md` has a `## vX.Y.Z` (or `## vX.Y.Z - date`) section for the exact version being tagged — not still folded into
  `## Unreleased` — ending in its Record `v` / Contract schema / Kernel minimums lines (§5). `release.sh tag`
  refuses to run without one; it becomes the annotated tag's message.
- Every built-in preset revision listed in `pkg/spec/presets`' `released` with its sha256 (§5, `make preset-freeze
  VERSION=vX.Y.Z`, which `release.sh tag` runs first and prints the lines to add).
- A clean working tree, on `master`, at the commit that passed CI. `release.sh push` refuses another branch, a
  lightweight tag and a tag off master's history, and pushes the tag only once `gh` shows a successful `ci` run for its
  commit (master goes first; rerun `push` when ci is green); `release.yml`'s `gate` job refuses, for a tag pushed by hand, the
  same and a commit with no successful `ci` run (it does not wait for vm-matrix: read that result before tagging).
  Both refuse first a tag not named `vX.Y.Z` or `vX.Y.Z-pre` (`pre` of letters, digits, `.` and `-`), since git lets a tag
  name hold shell syntax; the Makefile and the workflow pass the name as data whatever it holds.

- The repository the release is built in is the one `scripts/install.sh` names (`repo_owner`/`repo_name`, today
  `attention-span-ai/tego`): `release.yml` runs `scripts/check-installer-repo.sh` first and stops otherwise, since the
  installer would refuse a release signed by another repository's workflow. A fork or a renamed repository sets
  those two values first; until it does, every install and every release fails closed, rather than trust a namespace
  someone else may hold.

### 7.2 How the tag is made
1. `scripts/release.sh tag vX.Y.Z` — checks the above, runs the gate, and creates an **annotated** tag (`git
   tag -a`, not lightweight: goreleaser and `git describe` both need the tag object's own date and message).
2. `scripts/release.sh push vX.Y.Z` — pushes `master`, then the tag once ci is green for it, to `origin`. The tag push is the trigger: a
   `v*` tag on `origin` is what `.github/workflows/release.yml` builds and publishes from (§5). The tier-2
   objects are committed (§4) and `.goreleaser.yaml` builds with `-tags tegobpf`, so the published binary
   carries them with no clang and no `make gen`.
3. `release.yml` takes it from there: a draft release, the binary scan, the signature, the provenance, then
   publication; `reproduce` rebuilds the tag and compares. A release whose workflow failed stays a draft, never
   public; re-running the workflow for the same tag replaces that draft (`replace_existing_draft`), which is safe
   because the tag itself is unchanged and nothing was published under it.

### 7.3 What the schema version does at a release
Record `v` (`spec/record/v1`, currently `1`) and the contract's `version:` field (`spec/agent/v0`, currently
`0`) are their own axes, not the binary's semver (§1–§3); tagging `vX.Y.Z` does not itself change either. What
a release *does* is pin, in `docs/CHANGELOG.md`'s Record `v` / Contract schema lines, which schema versions that
specific binary speaks, so a reader (or `tego doctor`) can tell compatibility from the tag alone. If either
value actually moved since the last tag, §1's MINOR/MAJOR rule decides the version bump — a new reader is
MINOR, dropping one is MAJOR — the changelog entry does not decide it on its own.

### 7.4 Undoing a bad release
`scripts/release.sh undo vX.Y.Z` prints these steps; it does not run them, because retracting a release is a
judgment call each time, not a default-safe operation:
1. Delete the GitHub release and its tag (`gh release delete vX.Y.Z --cleanup-tag`, or the same by hand in the
   web UI).
2. **Never push a fixed commit under the same tag.** The Go module proxy caches a tag's content immutably the
   first time anyone fetches it; a second push under `vX.Y.Z` then serves different bytes to different callers
   forever depending on whether they hit that cache — a correctness bug, not a formality. Cut the next patch
   tag with the fix instead.
3. Mark the section in `docs/CHANGELOG.md` `### Yanked` (Keep a Changelog's own term) naming the replacement
   tag, rather than deleting it — the changelog stays an honest record of what was actually published.
4. If anyone may have already fetched `vX.Y.Z`, deleting the release does not reach them; the fix ships as a
   new tag with its own note pointing back at this one.
