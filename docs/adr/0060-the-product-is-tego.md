# ADR 0060: The product is Tego

Status: **accepted 2026-10-24**; implemented.
Amends `docs/VERSIONING.md` section 2 with one pre-release exception.

## Decision

The product, its binary, Go module, build tags, environment, state and runtime paths, kernel object names, cgroups, record
keys and documentation are named Tego (`tego`, `TEGO`). There is one name. There is no second command,
no alias, no environment variable under another prefix, no fallback path and no fallback record key.

| Area | Name |
|---|---|
| Command, main package | `tego`, `cmd/tego` |
| Build tags | `tegobpf`, `tegotesthooks`, `tegospike` |
| Environment | `TEGO_*` |
| State and runtime | `~/.tego`, `/etc/tego`, `/var/lib/tego`, `/run/tego`, `$XDG_RUNTIME_DIR/tego` |
| Own log | `tego.log`, `tego.log.1` to `.4` |
| BPF | maps, programs and types `tego_*`; pins under `/sys/fs/bpf/tego*` |
| cgroups | `tego.slice/tego-<agent>.slice`, cgroupfs `tego/<agent>/<id>` |
| Container image's user and group | `tego` |
| Per-run broker | `tegod` |
| Record | `run_start.tego_version` |
| CLI output | `status --json` `tego_version`; `version --json` `tego`; the version line `tego=` |
| Doctor's plane pin value | magic `0x4c504754` ("TGPL") |
| Agent contract schema `$id` | `https://tego.invalid/spec/agent/v0/agent.schema.json` |
| Installer and release coordinates | the repository's GitHub home, `<login>/tego` |

## Names that fail closed

Two names point outside this repository, and each is written so that a wrong value stops instead of trusting someone else:

- **The schema `$id`** uses the reserved `.invalid` top-level domain (RFC 2606), which can never resolve to anyone's server.
  A real domain would name a party that has not agreed to it.
- **The repository's home** is written in the installers, the release configuration and the Go module path. The installer holds
  a release's signature to the repository it names, so it refuses a release signed by another repository's workflow.
  `release.yml` runs `scripts/check-installer-repo.sh` before it builds anything, so a release from a repository the installer
  does not name stops there, with nothing published. A fork that publishes its own releases changes all of these together.

## The record format

`run_start`'s product-version key is `tego_version`, with `v` 1. `docs/VERSIONING.md` section 2 records one exception for
it. `tego status` shows no version for a run without the key, because there is deliberately no fallback reader.
`record_minor` does not say which key holds the version, and no reader may use it for that.

## Consequences

- A comparison against a base that names its tagged builds otherwise meets different names. The descriptor ratchet's total
  check (`tools/fdcheck -base`) cannot measure such a base, though each package's exact count still holds on every commit.
- A script that looks for the product by name must not match words that merely contain those letters. `tools/isocheck`
  reads the name with a pattern that excludes `category` and `$updateGolden`.

## Rejected options

- **A real-looking placeholder domain:** rejected. Another party can hold any name that looks real.

*Amended 2026-11-03 (container releases):* the release image's registry name is
`ghcr.io/attention-span-ai/tego`, lowercase as GHCR requires. Each release builds the tagged Dockerfile for amd64 and
arm64 with the exact release binaries, after binary reproduction and vulnerability checks. The image job
verifies the checksums and both binary/control pins before copying them. The isolated signing job described below
signs the checksums and multi-platform digest with the same keyless workflow/tag identity and attests provenance. Stable aliases are major.minor
and latest; prereleases publish only their full version. Binary reproducibility remains required; the Debian image
is not claimed reproducible. The release notes record the digest. A registry push happens before signing, so failed
runs can leave images in GHCR while the GitHub release remains a draft. New GHCR packages start private and need an
organization/package admin to make them public once; the documented API has no visibility-update endpoint.

*Amended 2026-11-04 (signing authority):* build jobs have no OIDC or attestation write permission. A dedicated `sign`
job downloads and verifies the release assets and image digest, reads artifacts without executing them, then signs
and attests both. It checks out no project code and runs no builds or build hooks. Registry write permission belongs
to `container` for the image push and `sign` for the signature/provenance push. Only `sign` holds `id-token: write`
and `attestations: write`; `publish` receives its checksum bundle as an artifact and uploads it before making the draft
public. Any failure leaves the release a draft. The certificate identity stays the workflow file at the tag, independent
of job name, so installer verification is unchanged. Exported CI tests guard the graph, permissions, action pins,
checkout and digest checks; the private gate also runs the export tool's tests.

*Amended 2026-11-04 (release body):* GoReleaser's changelog pipe must remain enabled to read the tag's
`--release-notes` file; the file itself bypasses automatic commit-log generation. Disabling the pipe discarded that
file in the first public release. The release job rejects blank generated notes and compares the draft body with
the tagged changelog section before it succeeds, then passes that section to publish as a same-run artifact. The
publisher compares the draft against this artifact immediately before publication and builds the final notes from
the artifact plus image metadata. It explicitly handles edit errors: an update may have applied remotely before a
client failure. It reads back both body and public status, including after an edit error; an edit error, body mismatch,
unexpected state or failed read attempts to restore draft status and fails the job. A failed restore requires manual
inspection. CI-run workflow tests cover the artifact boundary, changed drafts and edits that apply remotely before
reporting failure. No binary build, image contents or signing identity changes.
