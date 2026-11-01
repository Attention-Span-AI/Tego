# ADR 0067: The built-in deny_read list covers the agents' own token stores and the documented credential stores; compile names secret-looking variables a contract passes

Status: **accepted 2026-10-25**. Implemented 2026-10-25 (D1 to D4). Amends SEMANTICS §1 (the "no `deny_read:`" row) and §9,
agent-contract R6 and R12; adds `docs/spec/builtin-deny-read.md`. No record change.

## Context

Reads are allowed by default (SEMANTICS §1), so the built-in `deny_read` list is the whole defence against an agent
reading a credential outside the project. The list covered the credential classes the nx "s1ngularity" compromise
collected (SSH keys, `gh` tokens, `~/.npmrc`, `.env` files) and browser profiles. It did not cover the stores of the
agents themselves: `~/.claude/.credentials.json` holds a Claude Code login, `~/.codex/auth.json` a Codex login,
`~/.gemini/oauth_creds.json` a Gemini login. An agent under tego could read any of them, its own harness's and every
other harness's, and act as the person on another vendor's account. Nor did it cover the stores of the tools agents
commonly run beside (Azure CLI, 1Password CLI, pass, twine, Cargo, Terraform, Vault, libpq).

The environment has the same gap from the other side. A contract with no `env.pass` hands the agent the launcher's
whole environment, and developers keep `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY` and API keys there. Nothing told the
author.

## Decision

**D1. Rows.** `builtInDenyRead` gains the agents' token stores `.claude/.credentials.json`, `.claude.json`,
`.claude/backups` (the copies of `.claude.json` Claude Code keeps), `.codex/auth.json`, `.gemini/oauth_creds.json`, `.gemini/.env`, `.gemini/mcp-oauth-tokens.json`, `.copilot/config.json`,
`.copilot/mcp-oauth-config`, `.copilot/mcp-secrets`, and the credential stores `.azure`, `.config/op`,
`.password-store`, `.pypirc`, `.cargo/credentials`, `.cargo/credentials.toml`, `.terraform.d/credentials.tfrc.json`,
`.vault-token`, `.pgpass`, all relative to the home directory. The existing granularity rule holds: a file row where
the file is the secret, a directory row where the secret is one of several files. A row that does not exist costs
nothing.

**D2. The citation rule.** A row is kept only where the tool's vendor names the location, and
`docs/spec/builtin-deny-read.md` cites the document for each. A location no vendor document names is dropped and the
page says so: `.config/github-copilot` (named only by third parties) is dropped, and GitHub's documented Copilot CLI
store, `~/.copilot`'s `config.json`, `mcp-oauth-config/` and `mcp-secrets/`, takes its place. Gemini's documented MCP
token file (`.gemini/mcp-oauth-tokens.json`) is added beside its login file for the same reason.

**D3. Patterns, and a row created during the run.** The rows are part of `builtInDenyRead`, which
`builtInDenyReadPatterns` reads whole, so each joins `RuleTable.DenyReadPatterns` whether it exists or not: a person's
alternate naming it, for a held read or a held write, is refused by name (ADR 0057 D2). The patterns refuse alternates
only. A row absent at compile compiles no rule, since nothing exists to key one on, and is recorded instead in
`RuleTable.AbsentDenyRead` as an `AbsentRow`: the row, where its walk lands (for a row that is a symlink leading
nowhere yet, the place the link leads, since that is the file a login writing through the link makes), and `At`, the
first name on that path missing at compile, directly beneath the nearest directory that exists (`~/.codex` for
`~/.codex/auth.json` when `~/.codex` is missing too). A row whose `At` a write or exec.allow directory entry covers is
left out, since that grant reaches it whatever the ruleset enumerates, and so is a row beneath a regular file, where
nothing can be made. The Landlock backend holds `At`'s directory and enumerates it with `At` left out (enforce-landlock
R3, E9), or holds `At` and denies it where it exists by then, so a file created at the row during the run gets no grant
and a direct read of it is refused. Any other state at `Prepare` (the directory gone or no longer a directory, or
either reached through a link compile did not see) fails the run as drift: the ruleset would leave out another name than
the one the models refuse. This holds wherever that ruleset applies: tier landlock, and tiers cgroup and bpflsm, which
compose it. No other mechanism installs the list: a plane row keys an inode and a fanotify mark a mount, and a name with
no inode has neither. The tier models read it (`decide.AbsentRead`): a read at or beneath `At` that the tier's own rule
would allow is refused, `read_denied`, named by the row (`fs.deny_read[<row>]`), in `Evaluate` (`tego compile --test`,
the held open's chain model), in tier 1's advisory verdict and its unrestricted exec verdict, and in tier 2's and 3's
recorder, so the ledger records the refusal the ruleset made and the chain's `-EACCES` is attributed to Tego, not to
another LSM (ADR 0016). No second list of rows exists to drift.

**D4. Warning `secret-env`.** `agent.WithEnviron(os.Environ())` gives `Compile` the launcher's variable names; the
option drops each value before the compiler sees it, and Compile still never reads the process environment. When the
merged contract has no `env.pass` and the names include any of `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`,
`AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or a name ending, after a prefix
of its own, in `_TOKEN`, `_SECRET`, `_SECRET_KEY`, `_PASSWORD`, `_API_KEY`, `_ACCESS_KEY`, `_PRIVATE_KEY` or
`_CREDENTIALS` (case ignored), Compile warns once at the `env:` key (else line 1). The warning names the variables
sorted and once, and skips a name that `env.deny` removes or `env.set` replaces. It never shows a value, carries the
fix "add env.pass naming the variables the agent needs", and removes no variable (amended: it also
said "or extend tego/no-secrets", a profile the binary did not have then). `tego compile` and `tego run` pass the
option. `tego drift`'s sealed reload does not, since it compares tables, not findings, and neither does an
adoption's compile (`tego adopt`, the guard; amended): the adopted process's environment is its own,
not the adopting process's, and `env:` is refused for an adoption, so the warning would name the wrong variables and
give a fix adoption refuses. Nor does the compile of a contract tego generated (`tego watch` with no `--boundary`;
amended 2026-10-26): it passes the whole environment because tego chose to observe
everything, and its user cannot add the `env.pass` the fix names. The CLI's compiles read the environment through one seam, `launchEnviron`, so its tests
compile against a fixed one rather than the caller's shell (a `CLAUDE_CODE_MESSAGING_TOKEN` in a Claude Code session
failed a test that wants no warning).

**The harness's own store is denied too.** No rule keys on the command being run. A harness gets its credential from
a variable its contract passes (`ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token`; Codex's
`CODEX_API_KEY` for `codex exec`, or the key typed into the run's own `CODEX_HOME`) and keeps its state in the project
(`CLAUDE_CONFIG_DIR`, the launcher's `CODEX_HOME`). This is what `examples/agents/claude-code.yaml` and `codex.yaml`
already do.

## Rejected

- **Harness-specific exceptions keyed on the command name** (lift `~/.claude/.credentials.json` when the command is
  `claude`). The command name is the agent's to choose: a copy of any binary named `claude` would inherit the
  exception. It would also put Layer 3 knowledge (which harness keeps what where) into the Layer 0 compiler, and every
  harness release could move a file.
- **Leaving `~/.claude` readable** (or the harness's own store only). An agent under tego could then read other
  sessions' logins and other harnesses' credentials. The login is the person's account, not the run's.
- **Stripping secret-looking variables by default.** That silently breaks tools that need them, such as
  `gh pr comment` with `GH_TOKEN`, and a name list cannot tell a needed token from a stray one. The warning tells the
  author. The `tego/no-secrets` preset (ADR 0068) carries an `env.pass` allow-list; when this ADR was written it had not
  shipped, so the fix names `env.pass` alone.
- **Rows for `~/.codex/config.toml` and `~/.gemini/settings.json`, or stripping `oauth.client_secret` from the
  launcher's copy**. Either file can hold an MCP secret, as `~/.claude.json` can, but unlike
  `~/.claude.json` neither holds the login, and each is the harness's working configuration: Gemini CLI reads
  `settings.json` in place, and the launcher copies `config.toml` into the run's `CODEX_HOME` only when no `deny_read`
  covers it (`internal/runtime/codexhome.go`), so a row would take the person's settings out of every Codex run.
  Under tego Claude Code needs no `~/.claude.json` at all (`CLAUDE_CONFIG_DIR`), so that row costs a configured run
  nothing. Editing the copy would make tego parse and rewrite a vendor's format at each release. The page states the
  choice: keep MCP secrets in variables (`bearer_token_env_var`, `env_http_headers`, `env_vars`), or name the file in
  `fs.deny_read`.
- **Warning on an `env.pass` list that names a secret.** Naming a variable in `env.pass` is the author's explicit
  choice, so the warning would be noise on the contracts that already did the work.
- **Private-key names inside the project** (`id_rsa`, `*.pem`) as built-in rows. Test fixtures use them, and a
  built-in or preset `deny_read` can never be removed by an extending contract (R5).
- **Taking the names left out from the Landlock handle at `Prepare`** for the tier models.
  `tego compile --test` runs without a handle, and the supervisor and the recorder are given the table, so the
  prediction would have two sources. Compile names `At` once; the builder installs exactly it or refuses the run.
- **An `FSRule` for the missing name.** Every consumer of `RuleTable.FS` would then meet a rule with no inode: the
  plane rows, the fanotify marks, the print, the run_start line, `tego drift`. The tier models ask `AbsentRead` only
  where their own answer is allow.
- **Letting the builder walk up to whatever exists at `Prepare`** (an earlier code). When a directory vanished
  between compile and the run it left out a wider name than compile recorded, and the ledger said allow for reads the
  kernel refused.

## Consequences

- A contract that runs Claude Code without `CLAUDE_CONFIG_DIR` now has its reads of `~/.claude.json` and
  `~/.claude/.credentials.json` refused; Claude Code then behaves as if not logged in. A Claude subscription user runs
  `claude setup-token` once and passes `CLAUDE_CODE_OAUTH_TOKEN`; an API user passes `ANTHROPIC_API_KEY`.
- Codex, Gemini and Copilot logins kept in the home directory are refused the same way.
- A write entry meets a new file row by R6's existing rules (added;
  `TestWriteEntryAtATokenStoreRow`). One equal to a row that exists, `fs.write: ["~/.claude.json"]` as Claude Code was
  run before `CLAUDE_CONFIG_DIR`, is the error `contradiction` and the contract no longer compiles; `deny_read: []`
  is the only way to drop a built-in row. One above a row, `fs.write: ["~/.claude/"]` or `["~/.cargo/"]`, leaves it
  out of the Landlock ruleset, with a warning (the root tiers still refuse it; since ADR 0069 the held reads refuse
  it at tier landlock under `fs.reads: auto`, warned `held-reads`, and a copy the agent moves elsewhere is not
  refused). The way out is
  `CLAUDE_CONFIG_DIR` or the launcher's `CODEX_HOME`, which keep the harness's state in the project, not a write entry
  in the home directory.
- A run that needs Azure, 1Password, pass, PyPI, Cargo, Terraform, Vault or PostgreSQL credentials gets them from
  variables the contract passes, or from a credential file inside a write or project path the author names.
- `tego compile` prints `secret-env` for most contracts without `env.pass` on a developer machine. That is the intent:
  the warning names what the agent can read.
- The rows' sources are recorded per row, so a vendor that moves a file is a data change with a new citation.
- At tier landlock the directory an absent row would appear in is enumerated (D3): `~` on nearly every machine (a
  row such as `~/.netrc` is absent), and `~/.claude`, `~/.codex`, `~/.config`, `~/.cargo` and the rest where they exist
  without their token. A file or directory created directly in such a directory during the run is unreadable to the
  agent until the next run, as one created directly in `~` already was wherever `~/.ssh` existed. Each entry of an
  enumerated directory costs one held descriptor, within the run's descriptor budget (enforce-landlock E11). Such a
  file outside every row's `At` (`~/notes.txt` made by the person mid-run) is still recorded allow when its read is
  refused: the models know the names left out, not every name an enumerated directory gains later (enforce-landlock
  E10, SEMANTICS §2). Reads at or beneath a row's `At` are recorded as refused.
- A row whose directory vanishes or becomes a link between compile and `Prepare` fails the run (D3); `tego run`
  compiles right before it prepares, so this is a race with another process, and the next run compiles afresh.

## Implementation notes

- 2026-10-25: `pkg/spec/agent/compile_fs.go` (the rows), `compile_env.go` (`WithEnviron`,
  `secretEnvName`, `secretEnv`, called after `env()`), `diagnostic.go` (`CodeSecretEnv`), `internal/cli/compile.go`
  and `run.go` (the option). Tests: `TestBuiltInDenyReadCoversAgentTokenStores`, `TestAbsentTokenStoreRowsCostNothing`,
  `TestTokenStoreRowsJoinTheAlternatePatterns`, the `TestSecretEnv*` cases and `TestSemanticsDenyReadRowNamesBuiltInList`.
- **Departure from the first wording.** It says a row is kept if "the tool's own documentation" names the
  location. For `.gemini/oauth_creds.json` and the directory of `.terraform.d/credentials.tfrc.json`, the vendor's
  manual names the credential but not its path, and the vendor's own published source names the path
  (`packages/core/src/config/storage.ts`; Terraform's `internal/command/cliconfig`). Both rows are kept on that
  citation: each file is the tool's login token, and dropping either would leave the tool's most common login open. The
  spec page marks both. `.config/github-copilot`, which no GitHub document or source we read names, is dropped by D2,
  and GitHub's documented `~/.copilot` files replace it. `.gemini/mcp-oauth-tokens.json` is added because
  Gemini's docs name it as an agent token store.
- 2026-10-25: D3 said the patterns refused a file created at a row during the run; only the
  alternate guard reads them, and a probe at tier landlock read `~/.codex/auth.json`, `~/.claude/.credentials.json`
  and four more created while the agent ran. `RuleTable.AbsentDenyRead` (`compile_fs.go` `absentBuiltIn`) and the
  Landlock backend's `snapshotAbsent` (`internal/runtime/enforce/landlock/enumerate.go`) now refuse them;
  `TestAbsentRowsAreRecordedForLandlock`, and `TestTokenStoreCreatedDuringRunIsRefused` (internal/runtime, tier
  landlock, unprivileged), which failed with all eleven files read before the change.
- 2026-10-25: `.claude/backups` is a directory row. The page that names `.claude.json` names
  `backups/` too: "Earlier versions of `~/.claude.json`, copied when Claude Code rewrites the file", the five newest
  kept, so the `.claude.json` row was read through its copies. `~/.claude/remote/.api_key` and `.oauth_token`, which
  Claude Code was seen to probe (test/poc/watch-demo/real-agents/README.md), and a legacy `~/.claude.json.backup`
  are not rows: no Anthropic document names them. The spec page lists them under Rows left out.
- 2026-10-25: the fix said "add env.pass, or extend tego/no-secrets", and a
  contract that followed it failed `extends-not-found`. It now says "add env.pass naming the variables the agent
  needs"; the fix may name the preset.
  `TestFixesNameOnlyRegisteredBuiltinProfiles` (internal/cli) reads every fix text in the compiler and the CLI and
  fails for a `tego/` name the binary does not resolve.
- 2026-10-25: `internal/maze/scan`'s hand-kept copy of the list (`builtInHome`; maze cannot
  import `pkg/spec/agent`, which does not build on macOS) gains the rows, and `extraHome` drops `.pypirc` and
  `.terraform.d/credentials.tfrc.json`, now built-in. `TestBuiltInHomeMirrorsTheEngine` parses `compile_fs.go` and
  fails when the copy differs, so a later row cannot leave maze behind.
- 2026-10-25: an earlier fix refused the reads, but tier 1's ledger recorded each
  `allow`, `unmatched`, `tego compile --test` predicted allow, and at tiers cgroup and bpflsm the chain's `-EACCES`
  was attributed to another LSM (`observed`, `by: other`). `AbsentRow` (`pkg/spec/agent/absentrow.go`) now carries
  `At`; `decide.AbsentRead` is asked by `evalFS`, the indexed `Evaluator`, `execRead`, `AdvisoryFS`, the
  supervisor's unrestricted exec verdict and the recorder's `handleOpen`; `snapshotAbsent` installs `At` or fails the
  run. Tests: `TestAbsentRowReadIsRefusedByEveryModel` (decide), `TestRecorderAttributesAnAbsentRowsRefusalToTego`
  (observe), `TestUnrestrictedExecBeneathAnAbsentRowIsRefused` (supervisor), and `TestTokenStoreCreatedDuringRunIsRefused`
  under `record: full`, which failed with every line `allow`, `unmatched` before the change. The same class, two more
  readers of the table: `tego drift` declares each absent row as the compiler's entry (`declare`), so the refusal is
  reported under a declared name (`TestAbsentRowIsTheCompilersEntry`); and `tego adopt` clears the list
  (`compileAdoptionTable`), since an adopted process runs under no Landlock domain and the recorder would otherwise
  infer refusals the kernel never made (`TestBoundaryAdoptionCompilesAgainstTheAgentOwnersHome`).
- 2026-10-25: a row that was a symlink leading nowhere (`~/.claude.json` linked
  to a dotfiles file not made yet) was not recorded, and a login writing through the link made a file the agent read.
  It is recorded by where the link leads (`danglingPlace`, the walk R10's targets use), which joins the alternate
  patterns too. `TestAbsentRowsNameTheNameLandlockLeavesOut`; the runtime test's `~/.vault-token` link, read before.
- 2026-10-25: `TestAbsentRowLeavesOutTheNameCompilePredicted` and
  `TestAbsentRowDriftIsRefused` (landlock) and `TestTokenStoreMadeBeforeTheRunIsRefused` (internal/runtime) cover a row
  made between compile and the run (denied), a row beneath a regular file (not recorded; the file reads as before), and
  the drift states (refused).
- The long tail (keyrings, kwallet, Maven, Gradle, gem, Composer, `.my.cnf`, `.s3cfg`, `.boto`, rclone, OCI, doctl,
  hub, glab, fly, Supabase) is a later data addition, a data addition under D2.
