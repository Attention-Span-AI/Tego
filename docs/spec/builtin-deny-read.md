# The built-in deny_read list: rows and their sources

The built-in `deny_read` list (SEMANTICS §1, agent-contract R6) is Go data, `builtInDenyRead` in
`pkg/spec/agent/compile_fs.go`. Every enforcing tier refuses reads of each row that exists at compile time. A row
absent at compile compiles no rule and no diagnostic; the Landlock ruleset (tier landlock, and the tiers cgroup and
bpflsm compose) enumerates the directory it would appear in, so a file created at it during the run is refused too,
and recorded refused by the row (ADR 0067 D3). A row that is a symlink leading nowhere yet is held where the link
leads, so a login writing through the link is refused the same way. Two shapes are not covered: a row beneath a
regular file (`~/.cargo` a file), where nothing can be made, and a row whose directory vanishes or becomes a link
between compile and the run, which fails the run instead. Every row, existing or not, is in `RuleTable.DenyReadPatterns`, so a person's alternate naming it is
refused by name (ADR 0057 D2). A row inside a write entry is refused only if it exists at compile, and then only at the
root tiers (agent-contract R6).

This page covers the rows [ADR 0067](../adr/0067-agent-token-stores-and-credential-rows.md) added: the agents' own
token stores and the credential stores of the tools an agent runs beside. **A row is kept only where the tool's vendor
names that location.** Each row below gives the vendor document that names it, read on 2026-10-25. A location no
vendor document names is not a row; the last section lists the ones left out. Rows added before ADR 0067 (`~/.ssh`,
`~/.aws`, `~/.netrc`, `~/.gnupg`, `~/.npmrc`, `~/.git-credentials`, `~/.config/gh`, `~/.docker/config.json`,
`~/.kube/config`, `~/.config/gcloud`, the browser profiles) are explained in `builtInDenyRead`'s comment.

Granularity follows where the secret lives: a **file** row where the file is the secret, a **directory** row where
the secret is one of several files in the directory. The rest of a harness's home directory (`~/.claude/settings.json`,
`~/.codex/config.toml`, `~/.gemini/settings.json`) is not a row; the last section says why the two configuration files
that can hold an MCP secret stay readable.

## The agents' own token stores

| Row | Kind | Tool | Vendor document naming the location |
|---|---|---|---|
| `~/.claude/.credentials.json` | file | Claude Code | Anthropic, [Authentication, Credential management](https://code.claude.com/docs/en/iam): "On Linux, credentials are stored in `~/.claude/.credentials.json` with file mode `0600`"; under `CLAUDE_CONFIG_DIR` the file lives in that directory instead |
| `~/.claude.json` | file | Claude Code | Anthropic, [Settings](https://code.claude.com/docs/en/settings) and [the .claude directory](https://code.claude.com/docs/en/claude-directory): `~/.claude.json` "holds your account details, MCP server configurations" (an MCP server's configuration can carry its token) |
| `~/.claude/backups` | directory | Claude Code | Anthropic, [the .claude directory](https://code.claude.com/docs/en/claude-directory), Application data: `backups/` holds "Earlier versions of `~/.claude.json`, copied when Claude Code rewrites the file. Claude Code keeps the five newest, plus a copy of any version it couldn't parse." Without this row the `~/.claude.json` row is read through its copies |
| `~/.codex/auth.json` | file | Codex CLI | OpenAI, [Codex authentication](https://learn.chatgpt.com/docs/auth): "Codex caches login details locally in a plaintext file at `~/.codex/auth.json`"; "treat `~/.codex/auth.json` like a password: it contains access tokens" |
| `~/.gemini/oauth_creds.json` | file | Gemini CLI | Google, the CLI's own source, [`packages/core/src/config/storage.ts`](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/config/storage.ts): `OAUTH_FILE = 'oauth_creds.json'`, joined to the global `~/.gemini` directory by `getOAuthCredsPath`. The prose docs say only that a login credential is cached; see the note below |
| `~/.gemini/.env` | file | Gemini CLI | Google, [Gemini CLI authentication](https://geminicli.com/docs/get-started/authentication): the CLI loads variables from "your home directory's `.gemini/.env` (for example, `~/.gemini/.env`)", the documented place for `GEMINI_API_KEY` |
| `~/.gemini/mcp-oauth-tokens.json` | file | Gemini CLI | Google, Gemini CLI MCP server docs (Token management): OAuth tokens are "Stored securely in `~/.gemini/mcp-oauth-tokens.json`" |
| `~/.copilot/config.json` | file | GitHub Copilot CLI | GitHub, [Copilot CLI configuration directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference): the directory is `~/.copilot`; `config.json` "Stores internal application state ... including authentication data", and tokens are kept there in plain text "when no system keychain is available" |
| `~/.copilot/mcp-oauth-config` | directory | GitHub Copilot CLI | the same page: "Contains MCP OAuth token, registration, and PKCE fallback files when keychain-backed storage is unavailable" |
| `~/.copilot/mcp-secrets` | directory | GitHub Copilot CLI | the same page: "Contains fallback file storage and an index for MCP secret placeholders" |

## Credential stores of the tools an agent runs beside

| Row | Kind | Tool | Vendor document naming the location |
|---|---|---|---|
| `~/.azure` | directory | Azure CLI | Microsoft, [Azure CLI configuration](https://learn.microsoft.com/en-us/cli/azure/azure-cli-configuration): "The default value of `AZURE_CONFIG_DIR` is `$HOME/.azure` on Linux", whose `config` can hold `storage.key`, `storage.sas_token`, `storage.connection_string` and `batch.access_key`; [MSAL-based Azure CLI](https://learn.microsoft.com/en-us/cli/azure/msal-based-azure-cli): "The MSAL token cache and service principal entries are saved as ... plaintext files on Linux and macOS" |
| `~/.config/op` | directory | 1Password CLI | 1Password, [config directories](https://www.1password.dev/cli/config-directories/): "`~/.config/op` when `${XDG_CONFIG_HOME}` is not set". The page does not describe the contents; a 1Password staff answer on the vendor's forum says the `config` file there stores the accounts' details "including the secret key" |
| `~/.password-store` | directory | pass | [pass(1)](https://git.zx2c4.com/password-store/about/), FILES: `~/.password-store` is "The default password storage directory" |
| `~/.pypirc` | file | PyPA tools (twine) | PyPA, [The .pypirc file](https://packaging.python.org/en/latest/specifications/pypirc/): "To set your API token for PyPI, you can create a `$HOME/.pypirc`" |
| `~/.cargo/credentials.toml` | file | Cargo | Rust, [Cargo configuration, Credentials](https://doc.rust-lang.org/cargo/reference/config.html#credentials): "Configuration values with sensitive information are stored in the `$CARGO_HOME/credentials.toml` file" (`$CARGO_HOME` is `$HOME/.cargo`) |
| `~/.cargo/credentials` | file | Cargo | the same section: "Cargo also reads and writes credential files without the `.toml` extension, such as `.cargo/credentials`" |
| `~/.terraform.d/credentials.tfrc.json` | file | Terraform | HashiCorp, [terraform login](https://developer.hashicorp.com/terraform/cli/commands/login): the token is saved in plain text "in a local CLI configuration file called `credentials.tfrc.json`"; the directory is named by Terraform's own source, [`internal/command/cliconfig`](https://github.com/hashicorp/terraform/tree/main/internal/command/cliconfig) (`configDir` joins the home directory and `.terraform.d`; `CredentialsConfigFile` joins it and `credentials.tfrc.json`). See the note below |
| `~/.vault-token` | file | Vault CLI | HashiCorp, [Token helper](https://developer.hashicorp.com/vault/docs/commands/token-helper): the default helper "caches tokens from any enabled authentication backend in a `~/.vault-token` file" |
| `~/.pgpass` | file | PostgreSQL clients (libpq) | PostgreSQL, [The Password File](https://www.postgresql.org/docs/current/libpq-pgpass.html): the file is `~/.pgpass` on Unix |

**Two rows cite the vendor's source, not its prose.** For `~/.gemini/oauth_creds.json` and the directory of
`credentials.tfrc.json`, the vendor's manual names the credential but not where it is written; the vendor's own
published source names the path. A vendor's source is the vendor naming the location, so both are kept: the file is
the login token in each case, and leaving it readable would leave the most common login of each tool open. The
departure from "the tool's documentation" is recorded in ADR 0067.

## Rows left out

| Location | Why |
|---|---|
| `~/.claude/remote/.api_key`, `~/.claude/remote/.oauth_token` | Claude Code 2.1.290 was seen to probe both at start (test/poc/watch-demo/real-agents/README.md), but no Anthropic document names them or says what they hold: the `.claude` directory page and the Remote Control page list no `remote/`. To deny them, name `~/.claude/remote` in `fs.deny_read`. |
| `~/.claude.json.backup` | A backup name older Claude Code versions are reported to write beside `~/.claude.json`; no Anthropic document names it. The documented copies are in `~/.claude/backups`, a row above. |
| `~/.codex/config.toml`, `~/.gemini/settings.json` | Kept readable by decision (ADR 0067, Rejected), though each can hold a secret: OpenAI's [MCP page](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) says "Codex saves the secret as `mcp_servers.example.oauth.client_secret` in `config.toml`", and an MCP server's entry in either file can carry a token. Each is the harness's working configuration (model, sandbox, MCP servers), not its login: Gemini CLI reads `settings.json` in place, and the launcher copies `config.toml` into the run's `CODEX_HOME` only when no `deny_read` entry covers it (a row would leave every Codex run without the person's settings). Keep MCP secrets in variables instead (Codex: `bearer_token_env_var`, `env_http_headers`, `env_vars`, per the same page), or name the file in `fs.deny_read`, and the launcher then copies nothing from it. |
| `~/.config/github-copilot` | No GitHub document names it. It is where the Copilot editor plugins (copilot.vim, the JetBrains and Neovim plugins) keep `hosts.json` or `apps.json`, by third-party accounts only; GitHub's copilot.vim help and the language server's README do not name it. GitHub's documented Copilot CLI store is `~/.copilot`, whose credential files are rows above. To deny it, name it in `fs.deny_read`. |

Not added in this list, by decision (ADR 0067): private-key file names inside the project (`id_rsa`, `*.pem`), since
test fixtures use them and a preset's `deny_read` can never be removed by an extending contract (R5). The long tail
of credential stores (system keyrings, kwallet, Maven, Gradle, gem, Composer, `~/.my.cnf`, `~/.s3cfg`, `~/.boto`,
rclone, OCI, doctl, hub, glab, fly, Supabase) is not added yet; it is a data addition under the
same citation rule.

## What a harness does instead

Denying the harness's own home store is deliberate (ADR 0067): no rule keys on the command name. A harness run under
tego gets its credential from a variable its contract passes and keeps its state in the project:

- **Claude Code**: `ANTHROPIC_API_KEY`, or for a Pro, Max, Team or Enterprise subscription `CLAUDE_CODE_OAUTH_TOKEN`,
  the one-year token `claude setup-token` prints; `CLAUDE_CONFIG_DIR` set to a project directory
  (`examples/agents/claude-code.yaml`). **A subscription user runs `claude setup-token` once first**: the login a
  plain `claude` keeps in `~/.claude/.credentials.json` is refused under tego.
- **Codex CLI**: `codex exec` takes `CODEX_API_KEY` from the contract's environment; the interactive interface keeps
  the key typed at its login screen as `auth.json` in the run's own `CODEX_HOME`, which the launcher makes under
  `capture: forwarder` and removes with the run (`examples/agents/codex.yaml`). `~/.codex/auth.json` is never read.
- **Gemini CLI**: `GEMINI_API_KEY` passed in the contract's environment, not from `~/.gemini/.env`.
