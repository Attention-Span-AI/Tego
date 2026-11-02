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
token stores and the credential stores of the tools an agent runs beside, and the long tail of credential stores added
under the same rule on 2026-11-02. **A row is kept only where the tool's vendor names that location.** Each row below
gives the vendor document that names it, read on 2026-10-25 (the long tail's on 2026-11-02). A location no
vendor document names is not a row; the last section lists the ones left out. Rows added before ADR 0067 (`~/.ssh`,
`~/.aws`, `~/.netrc`, `~/.gnupg`, `~/.npmrc`, `~/.git-credentials`, `~/.config/gh`, `~/.docker/config.json`,
`~/.kube/config`, `~/.config/gcloud`, the browser profiles) are explained in `builtInDenyRead`'s comment.

Granularity follows where the secret lives: a **file** row where the file is the secret, a **directory** row where
the secret is one of several files in the directory. The rest of a harness's home directory (`~/.claude/settings.json`,
`~/.codex/config.toml`, `~/.gemini/settings.json`) is not a row; the last section says why the two configuration files
that can hold an MCP secret stay readable, and why Maven's `settings.xml` and Gradle's `gradle.properties`, which can
hold a repository password, do too.

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

## The long tail of credential stores

| Row | Kind | Tool | Vendor document naming the location |
|---|---|---|---|
| `~/.local/share/keyrings` | directory | GNOME Keyring | GNOME, the daemon's own source, [`pkcs11/gkm/gkm-util.c`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/main/pkcs11/gkm/gkm-util.c): `gkm_util_locate_keyrings_directory` returns `g_build_filename (g_get_user_data_dir (), "keyrings", NULL)`, and GLib's [user data directory](https://docs.gtk.org/glib/func.get_user_data_dir.html) is `XDG_DATA_HOME`, `~/.local/share` unless set ([XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/)); the secret store keeps each keyring there as a `.keyring` file. See the note below |
| `~/.local/share/kwalletd` | directory | KWallet (KDE) | KDE, [The KWallet Handbook](https://docs.kde.org/trunk_kf6/en/kwalletmanager/kwalletmanager/introduction.html): an old wallet's `.kwl` file is "located in the folder `kwalletd` in `qtpaths --paths GenericDataLocation`", whose writable path Qt's [QStandardPaths](https://doc.qt.io/qt-6/qstandardpaths.html) gives as `~/.local/share` on Linux; the framework's source, [`kwalletbackend.cc`](https://invent.kde.org/frameworks/kwallet/-/blob/master/src/runtime/kwalletbackend/kwalletbackend.cc), saves every wallet there (`getSaveLocation`) |
| `~/.my.cnf` | file | MySQL clients | Oracle, MySQL 8.4 Reference Manual, [Using Option Files](https://dev.mysql.com/doc/refman/8.4/en/option-files.html): `~/.my.cnf` holds "User-specific options"; [End-User Guidelines for Password Security](https://dev.mysql.com/doc/refman/8.4/en/password-security-user.html): "Store your password in an option file. For example, on Unix, you can list your password in the `[client]` section of the `.my.cnf` file in your home directory" |
| `~/.mylogin.cnf` | file | MySQL clients (`mysql_config_editor`) | the same manual, [mysql_config_editor](https://dev.mysql.com/doc/refman/8.4/en/mysql-config-editor.html): the login path file is in "the current user's home directory on non-Windows systems" and holds `host`, `user` and `password`, obfuscated in a way "not likely to deter a determined attacker" |
| `~/.s3cfg` | file | s3cmd | S3tools, [S3cmd usage](https://s3tools.org/usage): `--config=FILE`, "Defaults to $HOME/.s3cfg"; [S3cmd How-To](https://s3tools.org/s3cmd-howto): `s3cmd --configure` asks for "the two keys", and then "all available options are spitted into your `~/.s3cfg` file" |
| `~/.boto` | file | gsutil, boto | Google Cloud, [boto configuration file](https://docs.cloud.google.com/storage/docs/boto-gsutil): "The default location for the boto configuration file is in the user home directory, ~/.boto, for Linux and macOS", and its `[Credentials]` section holds `gs_oauth2_refresh_token` and `gs_secret_access_key`; AWS, [Boto3 credentials](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html): Boto3 loads credentials from the Boto2 file, "otherwise it will check `/etc/boto.cfg` and `~/.boto`" |
| `~/.config/rclone/rclone.conf` | file | rclone | rclone, [Documentation](https://rclone.org/docs/), `--config`: rclone looks for an existing configuration file at `~/.config/rclone/rclone.conf`, and makes a new one there where `XDG_CONFIG_HOME` is not set; "The configuration file will typically contain login information" |
| `~/.rclone.conf` | file | rclone | the same section: the last place rclone looks for an existing configuration file, and where it writes one when it cannot make its directory |
| `~/.gem/credentials` | file | RubyGems | RubyGems, [Command Reference](https://guides.rubygems.org/command-reference/), `gem push`: "The push command will use ~/.gem/credentials to authenticate to a server" |
| `~/.local/share/gem/credentials` | file | RubyGems | the same page, `gem owner` and `gem yank`: `--key` "Use the given API key from ~/.local/share/gem/credentials" |
| `~/.config/composer/auth.json` | file | Composer | Composer, [Authentication for privately hosted packages](https://getcomposer.org/doc/articles/authentication-for-private-packages.md): "These credentials are stored in a global auth.json in your Composer home directory"; [Command-line interface](https://getcomposer.org/doc/03-cli.md), `COMPOSER_HOME`: "On \*nix systems that follow the XDG Base Directory Specifications, it points to `$XDG_CONFIG_HOME/composer`" |
| `~/.composer/auth.json` | file | Composer | the same two pages: "On other \*nix systems, it points to `/home/<user>/.composer`" |
| `~/.m2/settings-security.xml` | file | Maven | Apache Maven, [Password Encryption](https://maven.apache.org/guides/mini/guide-encryption.html): "Store this password in the `${user.home}/.m2/settings-security.xml`", the master password that decrypts the server passwords in `settings.xml`, itself encrypted "with a hardcoded key, so please treat it as if the password is stored in the file in plain text"; Maven 4 still reads it ([the Maven 4 edition](https://maven.apache.org/guides/mini/guide-encryption-4.html), the Legacy dispatcher) |
| `~/.config/doctl/config.yaml` | file | doctl (DigitalOcean) | DigitalOcean, the [doctl README](https://github.com/digitalocean/doctl): "The `doctl` configuration file is used to store your API Access Token", and "On Linux, `doctl` saves its configuration as `${XDG_CONFIG_HOME}/doctl/config.yaml` if the `${XDG_CONFIG_HOME}` environmental variable is set, or `~/.config/doctl/config.yaml` if it is not" |
| `~/.config/hub` | file | hub (GitHub) | GitHub, [hub(1)](https://hub.github.com/hub.1.html): hub exchanges the login "for an OAuth token, which it saves in `~/.config/hub`" |
| `~/.config/glab-cli/config.yml` | file | GitLab CLI (glab) | GitLab, [glab auth login](https://docs.gitlab.com/cli/auth/login/): "If no keyring is available, or if you pass `--insecure-storage`, glab stores them in the global configuration file (default `~/.config/glab-cli/config.yml`) as plaintext instead" |
| `~/.fly/config.yml` | file | flyctl (Fly.io) | Fly.io, [Authenticating to Fly.io](https://fly.io/auth.md): "The session lands in `~/.fly/config.yml` and every `fly` command uses it" |
| `~/.supabase/access-token` | file | Supabase CLI | Supabase, [CLI reference, supabase login](https://supabase.com/docs/reference/cli/supabase-login): "If native credentials storage is unavailable, it will be written to a plain text file at ~/.supabase/access-token" |
| `~/.oci` | directory | OCI CLI and SDKs (Oracle Cloud) | Oracle, [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm), Linux and Mac OS X: "create an `.oci` directory to store the credentials", the API signing key `~/.oci/oci_api_key.pem`; [SDK and CLI Configuration File](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm): the default configuration file `~/.oci/config`, which names the key file and, for session authentication, a token file |

Where a tool keeps more than its secret in the same directory, the row is the file: `~/.fly/bin` holds the flyctl
binary, `~/.gem` and `~/.local/share/gem` the gems installed for the person, Composer's home its globally installed
packages, `~/.m2` Maven's local repository. Each row is the tool's default location under the passwd home; a store moved
by a variable (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `COMPOSER_HOME`, `BOTO_CONFIG`, `HUB_CONFIG`, `GLAB_CONFIG_DIR`) is
not covered, so name it in `fs.deny_read`.

A tool whose store is refused gets its credential from a variable the contract passes, as a harness does
(`GEM_HOST_API_KEY` for RubyGems, `COMPOSER_AUTH` for Composer, `SUPABASE_ACCESS_TOKEN` for the Supabase CLI, each
documented on the pages above). Some tools stop rather than run without a store they cannot read, whatever their
variable says. Composer reads its global `auth.json` whenever the file exists, and stops when the read fails (its
source, `Factory::createConfig`), so a run that uses Composer sets `COMPOSER_HOME` to a directory in the project.
flyctl loads `~/.fly/config.yml` before it reads `FLY_API_TOKEN` and stops when that load fails (its source,
`internal/config/config.go`), so a run that uses it sets `FLY_CONFIG_DIR` to a directory in the project and passes
`FLY_API_TOKEN`. doctl reads `~/.config/doctl/config.yaml` whenever the file exists and stops when the read fails
(`commands/doit.go`), so a run that uses it passes `--config` with a file in the project and `DIGITALOCEAN_ACCESS_TOKEN`.

**Three rows cite the vendor's source, not its prose.** For `~/.gemini/oauth_creds.json`, the directory of
`credentials.tfrc.json` and `~/.local/share/keyrings`, the vendor's manual names the credential but not where it is
written; the vendor's own published source names the path. A vendor's source is the vendor naming the location, so all
three are kept: the file is the login token in the first two cases, and the keyring directory holds the passwords
desktop applications save through GNOME's Secret Service; leaving any of them readable would leave the most common store
of the tool open. The departure from "the tool's documentation" is recorded in ADR 0067.

## Rows left out

| Location | Why |
|---|---|
| `~/.claude/remote/.api_key`, `~/.claude/remote/.oauth_token` | Claude Code 2.1.290 was seen to probe both at start (test/poc/watch-demo/real-agents/README.md), but no Anthropic document names them or says what they hold: the `.claude` directory page and the Remote Control page list no `remote/`. To deny them, name `~/.claude/remote` in `fs.deny_read`. |
| `~/.claude.json.backup` | A backup name older Claude Code versions are reported to write beside `~/.claude.json`; no Anthropic document names it. The documented copies are in `~/.claude/backups`, a row above. |
| `~/.codex/config.toml`, `~/.gemini/settings.json` | Kept readable by decision (ADR 0067, Rejected), though each can hold a secret: OpenAI's [MCP page](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) says "Codex saves the secret as `mcp_servers.example.oauth.client_secret` in `config.toml`", and an MCP server's entry in either file can carry a token. Each is the harness's working configuration (model, sandbox, MCP servers), not its login: Gemini CLI reads `settings.json` in place, and the launcher copies `config.toml` into the run's `CODEX_HOME` only when no `deny_read` entry covers it (a row would leave every Codex run without the person's settings). Keep MCP secrets in variables instead (Codex: `bearer_token_env_var`, `env_http_headers`, `env_vars`, per the same page), or name the file in `fs.deny_read`, and the launcher then copies nothing from it. |
| `~/.config/github-copilot` | No GitHub document names it. It is where the Copilot editor plugins (copilot.vim, the JetBrains and Neovim plugins) keep `hosts.json` or `apps.json`, by third-party accounts only; GitHub's copilot.vim help and the language server's README do not name it. GitHub's documented Copilot CLI store is `~/.copilot`, whose credential files are rows above. To deny it, name it in `fs.deny_read`. |
| `~/.m2/settings.xml` | Kept readable by decision, for the reason `~/.codex/config.toml` is: Maven's [Settings Reference](https://maven.apache.org/settings.html) puts a server's `username` and `password` there ("This type of information should exist on the build server in the `settings.xml`"), but the file is Maven's configuration for every build (the local repository, mirrors, proxies, profiles), and Maven stops with "Non-readable settings" when it cannot read it (`DefaultSettingsBuilder`), so a row would stop every Maven build on a machine that has one. A password encrypted in it needs the master password, `~/.m2/settings-security.xml`, a row above. Keep a plain password out of it (`settings.xml` interpolates environment variables, `${env.HOME}` and the like), or name it in `fs.deny_read`. |
| `~/.gradle/gradle.properties` | Kept readable for the same reason: Gradle's [Handling credentials](https://docs.gradle.org/current/userguide/supported_repository_protocols.html) takes repository credentials from Gradle properties ("`gradle.properties` file, command-line arguments, environment variables"), and the user's file in `GRADLE_USER_HOME` comes first ([Build Environment](https://docs.gradle.org/current/userguide/build_environment.html)), but the same file sets the daemon's JVM arguments and the build settings (`org.gradle.jvmargs`, `org.gradle.caching`) of every build. Pass credentials in environment variables instead, or name the file in `fs.deny_read`. |
| `~/.gnome2/keyrings` | GNOME Keyring's directory before it moved to the XDG data directory. The daemon still uses it where `~/.local/share/keyrings` does not exist, but creates only the new one (`gkm_util_locate_keyrings_directory`). Where it holds a keyring, name it in `fs.deny_read`. |

Not added in this list, by decision (ADR 0067): private-key file names inside the project (`id_rsa`, `*.pem`), since
test fixtures use them and a preset's `deny_read` can never be removed by an extending contract (R5).

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
