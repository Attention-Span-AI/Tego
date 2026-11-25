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
| `tego/ci` | named CI variables stay out, ordinary .github writes are refused, and refused read opens are recorded by default | 1 | `reason.reads: on`, 12 `env.deny` names, `fs.deny_write: [./.github/]`; see CI limits below |

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
`released` maps to the revision. v0.1.0, the first release, froze revision 1 of the original three presets: a change to one is now
revision 2. `ci@1` is new in v0.2.0, which froze it by the same rule, without changing any of those three frozen
files.

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

The ADR 0068 CI amendment also admits `reason.reads: on`, nonempty literal `env.deny` names and
`fs.deny_write: [./.github/]`. These add no grant. In particular `tego/ci` passes no variable, allows no host,
adds no write entry and changes no assurance or privilege setting. Its read setting is a contract-wins default;
the denial lists accumulate and an empty contract list removes none.

## CI limits

`tego/ci` and `tego/ci@1` remove the OIDC request URL and bearer token, runtime token and URL, cache URL,
results URL and cache-v2 switch. They also deny `GITHUB_TOKEN`, `GH_TOKEN`, `SIGSTORE_ID_TOKEN`, `INPUT_TOKEN`
and `INPUT_GITHUB_TOKEN`. `INPUT_TOKEN`, `INPUT_GITHUB_TOKEN` and `ACTIONS_CACHE_SERVICE_V2` are
recalled, to verify on a runner; input names depend on the action, and the cache switch is configuration.
`env.pass` cannot override these refusals; compile warns `redundant-rule` for each passed denied name.
`env.set` of one is a compile error.
`GITHUB_TOKEN` stays denied even when the contract names it on purpose: the receipt writer's token is not an
agent credential. Use a different contract without this preset for a job that deliberately gives that authority
to its agent, and do not treat it as preserving the CI signing boundary. This is an exact-name list, not all
possible secrets or action inputs; add a caller-owned `env.pass` list or combine `tego/no-secrets`.
Hyphenated names such as `INPUT_GITHUB-TOKEN` cannot be denied by any contract: environment rule
names accept only letters, digits and underscores, starting with a letter or underscore. GitHub preserves
the hyphen in a `github-token` action input. The action must scrub the launcher environment or the
contract must use an `env.pass` allow list that excludes it.

`reason.reads: on` notifies read opens at tier landlock so refused opens under enforced `deny_read` rules
are recorded. Allowed reads stay unrecorded under summary recording. ADR 0077 measured about 17 microseconds
extra per open and a 19 percent slower offline workload. A contract can set `reason.reads: off` or `auto`;
when no other mechanism records reads, the receipt says allowed and refused reads were not recorded.
Full recording, held reads, gates and root-tier recording keep their own behavior and limits.

Run from the workspace root. `./.github/` is relative to the run's working directory, not the preset file.
Filesystem entries support `~/` and relative or absolute paths, but do not interpolate `$RUNNER_TEMP`,
`$GITHUB_EVENT_PATH` or any other environment expression. `${TEGO_PROJECT_DIR}` works in `env.set` only.
Revision 1 cannot name the runtime temp directory, full `_actions` tree or event file. The action must resolve
those paths, runner installation and trusted tools, and reject overlapping write grants before launch and signing.
Do not substitute guessed `/home/runner` paths or put literal dollar expressions in this preset.
The file-command files named by `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE` and
`GITHUB_STEP_SUMMARY`, and stdout workflow commands, are not protected by the preset. Writable command
files can change later steps' environment, PATH, outputs, action state or summaries. The action must
protect the concrete paths and control workflow-command parsing while forwarding agent output. Removing
a variable does not deny its file. See GitHub's
[workflow commands reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).

The `.github/` refusal is blocked for ordinary commands; not race-free at the no-root tier (ADR 0071).
It is also best effort on the cgroup fanotify listener. A missing directory under a write grant produces an
`unenforced` warning from a profile, and a narrower `fs.write` inside it reopens that subtree. The action must
reject both cases. With a retained denial beneath a write grant, `fs.assurance: kernel` makes compile
fail at tier landlock with `unenforced` (exit 1). A landlock pin alone keeps the best-effort refusal.
Outside every write and ask scope the profile denial is silently omitted as redundant; a missing
`.github/` there produces no warning. Broad grants that include signer inputs must be narrowed, rather
than relying on nested refusals. Environment denial does not close credential files, other processes' `/proc` views, descriptors or
sockets. This preset alone is not a signing boundary; ADR 0143 requires those checks separately.

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
