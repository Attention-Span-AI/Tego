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
