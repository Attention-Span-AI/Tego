# pkg/spec/presets: the built-in presets

Normative for the names, the revisions and the freeze rule (ADR 0068). The user's page is
[docs/user/presets.md](../../../docs/user/presets.md).

## Names

A contract extends a preset by its name under the reserved namespace `tego/` (ADR 0066 D2), alone or in a list:

| Name | Promise (one line) | Newest revision | Sets |
| ---- | ------------------ | --------------- | ---- |
| `tego/no-secrets` | the agent cannot read your secret files, and your secret variables never reach it | 1 | `env.pass`: 25 names; the file half is the built-in `deny_read` list, which it leaves on |
| `tego/no-prod` | the agent reaches no network host except the ones your contract names | 1 | `net: {allow: []}` |
| `tego/repo-only-writes` | the agent writes only in the folders your contract names | 1 | `fs.write: [/dev/null]` |

`Source.Resolve` serves `tego/<name>` as the newest revision and `tego/<name>@<n>` as revision `n`; any other name,
an unknown preset or a revision that does not exist, wraps `fs.ErrNotExist`, and `Source.Names` lists every name it
serves, so an unknown one is answered with the list. The bytes are reported under `<builtin>/presets/v<n>/<name>.yaml`,
which diagnostics print as the file a line is in. `List` gives the presets in the order `tego init` writes them.

## Revisions

Revision `n` of a preset is the file `v<n>/<name>.yaml`. A preset's revisions are 1 to its newest, each a file, and
the catalog in `presets.go` and the embedded files name the same ones (`TestEveryRevisionHasItsFile`). A preset never
sets `revision`: its version in a run's record is `run_start.profiles` (its name as written, pin included, and the
sha256 of its bytes).

## The freeze rule

A revision is frozen once a release carries it. A change to a frozen revision is a new revision, `v<n+1>/<name>.yaml`
with the catalog's newest raised, never an edit of the old file. At each release, every revision it carries for the
first time is added to `released` in `presets.go` with the sha256 of its bytes, and `TestReleasedRevisionsAreFrozen`
fails from then on if those bytes change. The release enforces the addition: `make preset-freeze VERSION=vX.Y.Z`
runs that test with `TEGO_RELEASE_VERSION` set, which then fails for every catalog revision `released` lacks and
prints the line to add; `scripts/release.sh tag` runs it before the gate and `release.yml` before it builds
(docs/VERSIONING.md §5). A run records an unpinned preset by its name and the sha256 of the bytes it merged, which
`released` maps to the revision. v0.1.0, the first release, froze revision 1 of each preset: a change to one is now
revision 2.

## What a preset may set

`TestPresetsNeverLoosen` holds every revision of every preset: no `revision`, no `host_sockets: true`, no
`fs.reads: direct`, no `deny_read: []`, no `best-effort` assurance, no `io_uring`, `keyring`, `ipc`, `setuid` or
`exec.anonymous: true`, no `record: off` or `capture: off`, and only the keys of its allow-list, with the values it
allows (names in `env.pass`, an empty `net.allow`, the `/dev/null` write entry). A new key is a decision recorded in
ADR 0068 and in that test, never a file edit alone. `env.pass` is the one key through which a preset widens a
contract (the lists concatenate, so a name a preset passes is passed whatever narrower list the contract writes), so
no name in it may be credential-shaped (a credential word such as `TOKEN`, `SECRET`, `KEY` or `AUTH`, a cloud or
secret-store family such as `AWS_`, an agent socket, a container or cluster endpoint, a URL or a proxy:
`credentialShaped`), and a later revision passes no name the revision before it did not unless `envPassReviewed`
names the review that admitted it (`TestEnvPassNeverWidens`).

## Host groups

`hosts.yaml` names the hosts of seven package ecosystems: `github`, `npm`, `pypi`, `crates`, `go-proxy`, `rubygems`
and `maven-central`, each a list of `host:port`. `HostGroups()` returns them in the file's order, or an error for a
malformed file, which `TestHostGroups` keeps out of a build. `tego init` is to
expand a group into concrete `net.allow` entries with a comment naming it; a group is never contract
syntax. The file has one fixed shape, read with the standard library (`TestHostsFileIsYAML` holds it to what a YAML
parser reads).

## Imports

The standard library only (depguard `presets-are-data`): the presets are Layer 0 data, and `Source` has the shape of
`agent.ProfileSource` and `agent.ProfileNamer` without importing `pkg/spec/agent`. The CLI registers it by one line in
`internal/cli` `profileSources`.
