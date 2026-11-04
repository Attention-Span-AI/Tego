# ADR 0068: the three presets are built-in profiles under tego/, pinned by revision, and compile --merged prints the one rule file

Status: **accepted 2026-10-25**; implemented 2026-10-25: D1 to D6.
Builds on ADR 0066 D2 and D7; refines agent-contract R5 (the profile name, built-in profiles), limits-check-doctor-cli
R29 (`compile --merged`). Amended by `tego init --preset` (Implementation notes 2026-10-26). Revision 1
sets neither `fs.reads` nor CI `deny_write` entries.

## Context

The rule setup is "pick a preset, then adjust": three presets, each a filled-in set of the rule
templates (`no-secrets` blocks reads of secret files, `no-prod` denies the network except the hosts the user names,
`repo-only-writes` allows writes only in named folders), customizable, compiled to one rule file. ADR 0066 gave the
contract a list `extends` and a reserved namespace `tego/` that only built-in sources serve, and left the built-in
sources to this package. Three questions were open: where a preset's content lives and how a contract reaches it, how
a fix to a preset reaches users without changing what an existing run reproduces, and what "one rule file" is.

## Decision

**D1. Presets are built-in profiles named under `tego/`.** `pkg/spec/presets` holds each preset as a YAML profile
embedded in the binary (`v<n>/<name>.yaml`) and a `Source` that serves it by name in the shape of
`agent.ProfileSource`, without importing `pkg/spec/agent` (Layer 0 data; depguard `presets-are-data`: the standard
library only). The CLI's one constructor registers it by one call line (`internal/cli` `profileSources`,
`c.WithBuiltin(presets.Source{})`, ADR 0066 D7). A contract names a preset in `extends` like any profile, and combines
it with others: `extends: [tego/no-secrets, tego/no-prod, tego/repo-only-writes]`. The presets set disjoint keys, so
every combination loads without `extends-conflict`.

**D2. Revision 1.** `tego/no-secrets` sets `env.pass` to an allow-list of 25 names a toolchain needs (`PATH`, `HOME`,
`USER`, `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`, `TERM`, `COLORTERM`, `TZ`,
`NO_COLOR`, `GOPATH`, `GOROOT`, `GOCACHE`, `GOMODCACHE`, `CARGO_HOME`, `RUSTUP_HOME`, `JAVA_HOME`, `NVM_DIR`,
`PYENV_ROOT`, `VIRTUAL_ENV`, `CONDA_PREFIX`), so a token in an exported variable never reaches the agent; its file
half is the built-in `deny_read` list, on in every contract that does not switch it off, and the preset adds no
entry to it. `tego/no-prod` sets `net: {allow: []}`: every host is refused except the ones the contract's own
`net.allow` names (the lists concatenate) and the model the contract declares under `models:`, reached through the
forwarder; a contract with no `models:` entry starts no forwarder (gap `capture/no-models`), so under `tego/no-prod`
its agent's connection to its model is refused like any other host's, and the presets page's example declares the
model and passes its key (*amended 2026-10-25*: this said "the model reached through the forwarder"
of every contract). The machine's DNS resolver stays reachable (`net.dns.mode` defaults to `system`). `tego/repo-only-writes` sets `fs.write: [/dev/null]`, so every write
outside the contract's own folders is refused; `/dev/null` is there because many tools open it for writing, and a
present `fs.write` is what turns the write side to an allow-list. `TestRevisionOneContents` holds each file to this.

**D3. Revision pins, and the freeze rule.** `tego/<preset>` is the preset's newest revision; `tego/<preset>@<n>`
is revision `n` alone (precedent: Kubernetes Pod Security Standards levels, enforced at a named `enforce-version`).
A fix reaches every unpinned contract with a release, and a pin keeps a run reproducible across releases. A released
revision is frozen: a change is a new revision `v<n+1>/<name>.yaml`, never an edit, and `TestReleasedRevisionsAreFrozen`
holds every revision listed in `released` to the sha256 of its bytes at release. Before the first release carried
the presets, revision 1 was edited in place and `released` was empty; v0.1.0 filled it. The release fills
the table, or does not happen: `make preset-freeze VERSION=vX.Y.Z` runs that test with `TEGO_RELEASE_VERSION` set,
which then fails for every catalog revision `released` lacks and prints the line to add; `scripts/release.sh tag`
runs it before the gate and `release.yml` before it builds (docs/VERSIONING.md §5). The profile-name rule
takes a pin on a `tego/` name only (`@` and a revision from 1 with no leading zero, at most nine digits, in Go and in
the JSON Schema alike): only a built-in profile has revisions, and a directory profile keeps its one spelling.

**D4. A preset carries no `revision` and never loosens.** A preset's rules version is `run_start.profiles` (its name,
pin included, `builtin`, and the sha256 of its bytes, ADR 0066 D6), so a preset sets no `revision` key (which is
`refused-in-profile` anyway, R28). `TestPresetsNeverLoosen` fails a preset that sets `revision`, `host_sockets: true`,
`fs.reads: direct`, `deny_read: []`, a `best-effort` assurance, `io_uring`, `keyring`, `ipc`, `setuid` or
`exec.anonymous: true`, `record: off` or `capture: off`, or any key outside an allow-list of the keys the presets set
with the values they may hold (an empty `net.allow`, the `/dev/null` write entry, `env.pass` names), and each preset
loads alone with no diagnostic at all. `env.pass` is the one key through which a preset widens a contract (the
lists concatenate, R5), so no name in it may be credential-shaped (`credentialShaped`: a credential word, a cloud or
secret-store family, an agent socket, a container or cluster endpoint, a URL, a proxy), and revision `n+1` passes
no name revision `n` did not unless `envPassReviewed` names the review that admitted it (`TestEnvPassNeverWidens`).

**D5. An unknown preset names the known ones.** A built-in source may implement `agent.ProfileNamer` (`Names()`),
and a `tego/` name no built-in source holds is `extends-not-found` at its line with the fix listing every name the
listing sources serve, sorted: a typo (`tego/no-secret`) and a revision that does not exist (`tego/no-prod@2`) alike
are answered with the names there are. `presets.Source` lists each preset by its name and by each pin.

**D6. `tego compile --merged` prints the one rule file.** After the contract has loaded and compiled (a contract
with an error prints nothing and exits 1), `--merged` prints `agent.Contract.Canonical()` in place of the rule table:
the merged contract, every profile of its `extends` laid in, which is what the run's ledger keeps as `contract.yaml`
and whose sha256 is `contract_hash` (R13), so `tego compile --merged agent.yaml | sha256sum` is the hash the run will
record (`TestCompileMerged`). It keeps its `extends:` line, which the hash covers; loaded again it would merge the
presets a second time, so it is the record of what a run enforces, not a contract to run in place of `agent.yaml`.
`--merged` beside `--json`, `--test` or `--exec` is a usage error.

**Host groups.** `pkg/spec/presets/hosts.yaml` names the hosts of seven package ecosystems (`github`, `npm`, `pypi`,
`crates`, `go-proxy`, `rubygems`, `maven-central`), served by `presets.HostGroups()` for `tego init --allow-host
@<group>`, which expands a group into concrete `net.allow` entries. A group is never contract syntax:
the contract stays the one readable list of what a run may reach.

## Consequences

- A contract takes a preset in one line and adjusts it in its own: its folders, its hosts, the variables it needs.
- A fix to a preset reaches every unpinned contract with a release; a pinned contract keeps its revision until its
  author moves the pin, and `run_start.profiles` says which bytes each run merged.
- `deny_read: []` in a contract extending `tego/no-secrets` still switches the built-in list off, warned
  `deny-read-disabled`, as in any contract: the preset's file half is the built-in list, and the contract is its
  author's. The presets page says so.
- A contract listing both `tego/no-secrets` and `tego/no-secrets@1` while revision 1 is the newest names one file
  twice: it merges once, under the first name (which alone `run_start.profiles` lists), with one `redundant-rule`
  warning at the second name's line in the contract (*amended 2026-10-25*: the bytes merged twice and
  compile printed one warning per repeated entry inside `<builtin>`, 26 for the three presets). Once revision 2
  exists, `tego/no-secrets` and `tego/no-secrets@1` are two files and merge as two profiles.

## Rejected options

- **Copying a preset's content into `agent.yaml`** (a generator that writes the entries). The contract would carry
  every entry, but a fix to a preset would reach no contract written before it, and nothing would say which preset,
  at which revision, a contract's entries came from. `tego init` still writes concrete entries for what is the
  project's own (its folders and hosts), and names the presets by reference.
- **Installing preset files into `~/.tego/profiles`.** A file there is the user's to edit, so the name would no
  longer mean the shipped content; an upgrade would have to merge or overwrite it; and the run's record would name a
  preset whose bytes nobody can tell from an edit. ADR 0066 D2 already reserves `tego/` against such a file
  (`shadowed-builtin`).
- **A `revision` key in each preset.** It is the top-level file's own (R28), and the pin with `run_start.profiles`
  says the same without a second source of truth.
- **Host groups as contract syntax** (`net.allow: [@github]`). The contract would no longer be the list of hosts a
  run reaches, and a group changing in a release would widen every contract naming it with no edit to any.
- **A pin on every profile name.** A profiles directory has one file per name, with no revisions to pin.

## Implementation notes

- 2026-10-25: built as decided. `pkg/spec/presets` (`Source`, `List`, `HostGroups`, `released`);
  `agent.ProfileNamer`; the profile-name pattern with the pin; `compile --merged`; the end-to-end test
  `TestIntegrationPresetsAtTierLandlock` (unprivileged, tier landlock: a write outside `src/` and an unlisted
  connect refused, each ledger line naming rule `unmatched` with reason `write-outside-contract` and
  `net-not-allowed`; the listed port reached; a planted variable outside the allow-list absent from the agent's
  environment).
- 2026-10-25: D2's "the model reached through the forwarder" held only for a
  contract that declares `models:`; with none no forwarder starts and `tego/no-prod` refuses the model, so D2, the
  preset's comment and the page say so, and the page's example declares the model and passes its key
  (`TestPresetsPageExampleReachesItsModel`). `TestPresetsAloneRefuse` compiles each preset with no `net:`, `fs:` or
  `env:` of the contract's own, so no contract entry stands in for the preset's. D4 holds `env.pass` to
  `credentialShaped` and each later revision to its predecessor (`TestEnvPassNeverWidens`). D3's freeze is enforced
  at the release (`make preset-freeze`). A preset and its pin merge once (Consequences, ADR 0066's note). The page
  carries the "From source" label on every paragraph that names a preset or `--merged`, and rulecheck's
  `unreleasedRe` holds every `docs/user` page to it. The page now discloses, as the engine's specifications already
  did: under `tego/no-secrets`, shell startup files re-export what they export in every login or interactive shell
  the agent starts (Codex runs each command as `bash -lc`) and are readable with the shell history, and a listed
  secret file in a write folder can be moved or hard-linked and read under the new name at tier landlock
  (`held-reads`); under `tego/repo-only-writes`, mode changes are refused at no tier and owner, extended-attribute
  and timestamp changes are not refused at tier landlock (timestamps not recorded); `./` is refused while the
  contract sits in it.
- Known limits (decided here, not built): revision 1 keeps shell startup files readable and discloses
  them, since a login shell that cannot read `~/.profile` loses the `PATH` and toolchain setup a run needs
  (measured: bash reports `Permission denied` and starts without it); the shell history files (`~/.bash_history`,
  `~/.zsh_history`), which no tool needs, are to be denied in the built-in `deny_read` list, not by a preset
  `fs.deny_read`, which `allowedKeys` refuses and which would have to be shown not to switch the built-in list off.
  No table yet gives the per-tier truth of the attribute and timestamp changes. A compile warning for a
  harness command (`claude`, `codex`) with no `models:` under a `net:` that refuses its model needs a per-harness
  model host table, which no package has yet: deferred to `tego init --preset`, which writes `models:` for the detected
  harness.
- 2026-10-26: `tego init --preset <list> [--write <dir>]... [--allow-host
  <host[:port]|@group>]... [--command <line>] [--list] [dir]` writes a contract that extends the chosen presets in
  catalog order. As decided under Rejected options, init writes concrete entries, never a group or a marker: a
  `@group` becomes its `host:443` lines and a project marker its folders (`package.json` `./node_modules/`,
  `Cargo.toml` `./target/`, `pyproject.toml` or `requirements*.txt` `./.venv/`, `go.mod` the Go caches under
  `./.tego/cache/`), plus `TMPDIR` under `./.tego/tmp/`, each line with a comment naming the flag or marker it came
  from. The logic is Layer 2 (`internal/setup`, depguard `setup-never-imports-engine`); `internal/cli` init.go parses
  flags and prints. `setup.Draft` composes and compiles the bytes offline against the machine the caller passes
  (init passes what `tego compile` uses) without creating anything, so the same call serves a dashboard form;
  `setup.Create` makes the folders. Not built: `--agent` and the harness descriptor
  (so no `models:` entry is written for a detected harness, and the compile warning deferred above stays deferred),
  `--prompt`.


### Amendment 2026-11-03: agent setup and movable projects

`tego init --agent claude-code|codex [--prompt <text>]` selects a descriptor in
`internal/setup/harness.go`. With no explicit presets it uses no-secrets, no-prod and
repo-only-writes, and with no write entries it grants `./out/`. It writes the harness,
its model through the capture forwarder, the required environment names and writable
state and terminal paths. It never reads credentials. Claude Code runs one task in
print mode (`claude -p --permission-mode acceptEdits`), accepting an API key
or setup-token; Codex uses `codex exec` with `CODEX_API_KEY`. ChatGPT sign-in remains
an explicit example contract because the forwarder does not capture it. The generated
notes name the credentials and the next commands. `--list` includes these descriptors.
`--command` and `--agent` cannot be combined. `--prompt` is one literal argv element,
including quotes and shell metacharacters; it needs `--agent`. Both agents default to
“Describe this project without changing files.” when no prompt is given. No model is
called by init; the user starts the agent with `tego run agent.yaml`.

Round-2 correction: fresh interactive Claude state performs a direct connectivity
check which ignores the forwarder's base URL (test/poc/interactive-claude/RESULTS.md).
Init therefore selects print mode; it does not seed onboarding or login state. For
the full-screen interface, use examples/agents/claude-code-interactive.yaml, whose
direct model connection is allowed and whose model bytes are not captured.

Generated env.set paths use `${TEGO_PROJECT_DIR}`. At compile time this exact token
expands to the absolute working directory, the same base used by relative fs entries.
No other shell or environment expression is expanded, and the source contract and its
hash retain the token. This keeps Go caches (which need absolute paths), TMPDIR and
agent state paths aligned with their write grants after a project moves. This does not
change the existing rule that a contract is run from its project's directory.

The earlier implementation note's missing --agent, descriptor and --prompt are closed.
Automatic contract selection for an unregistered `tego run claude` remains an owner
choice; this amendment creates explicit contracts and changes no registry precedence.

The installed Codex rehearsal clarified its generated CODEX_HOME comment: it names
settings to copy; the forwarder supplies a writable home for each run. This supported
settings source is an informational compile note (also visible with run -v), rather
than an actionable warning on every start. Overrides of actual runtime-owned values
remain warnings. Init leaves informational notes to the compile command it prints as
its next step, and keeps errors and warnings about weakened enforcement visible.
