---
title: Built-in refusals
description: "The secret files, protected files, Tego's own files and host sockets every Tego session refuses, whatever the rules file allows, and how to change it."
summary: "What every session refuses, whatever its rules file says."
section: Reference
group: Rules file
order: 3
---

Every session that enforces rules refuses the items on this page, even when the rules file says nothing about them. The secret file list is the only part you can switch off ([below](#switching-the-list-off)). A session with nothing enforced (`tego run --observe`, or `tego watch` without `--boundary`) has no built-in refusals.

## Secret files

The agent cannot read these paths in your home folder. A path that does not exist when the session starts is still refused if the agent creates it.

| Kind | Paths under `~/` |
|---|---|
| SSH, GPG and network logins | `.ssh`, `.gnupg`, `.netrc`, `.git-credentials` |
| Cloud and cluster logins | `.aws`, `.azure`, `.config/gcloud`, `.kube/config`, `.oci`, `.config/doctl/config.yaml`, `.fly/config.yml`, `.supabase/access-token` |
| Package registry logins | `.npmrc`, `.pypirc`, `.cargo/credentials`, `.cargo/credentials.toml`, `.gem/credentials`, `.local/share/gem/credentials`, `.config/composer/auth.json`, `.composer/auth.json`, `.m2/settings-security.xml` |
| Git host and container logins | `.config/gh`, `.config/hub`, `.config/glab-cli/config.yml`, `.docker/config.json` |
| AI agent logins | `.claude/.credentials.json`, `.claude.json`, `.claude/backups`, `.codex/auth.json`, `.gemini/oauth_creds.json`, `.gemini/.env`, `.gemini/mcp-oauth-tokens.json`, `.copilot/config.json`, `.copilot/mcp-oauth-config`, `.copilot/mcp-secrets` |
| Password stores and keyrings | `.password-store`, `.config/op`, `.vault-token`, `.local/share/keyrings`, `.local/share/kwalletd` |
| Database and storage tools | `.pgpass`, `.my.cnf`, `.mylogin.cnf`, `.s3cfg`, `.boto`, `.config/rclone/rclone.conf`, `.rclone.conf`, `.terraform.d/credentials.tfrc.json` |
| Browser profiles | `.mozilla/firefox`, `.config/google-chrome`, `.config/google-chrome-beta`, `.config/google-chrome-unstable`, `.config/chromium`, `.config/BraveSoftware`, `.config/microsoft-edge`, `.config/microsoft-edge-beta`, `.config/microsoft-edge-dev`, `.config/vivaldi`, `.config/opera`, `snap/firefox/common/.mozilla`, `snap/chromium/common/chromium`, and the Flatpak folders `.var/app/org.mozilla.firefox`, `.var/app/org.chromium.Chromium`, `.var/app/com.google.Chrome`, `.var/app/com.brave.Browser`, `.var/app/com.microsoft.Edge`, `.var/app/com.vivaldi.Vivaldi` |

Each path is the tool's default location. A store you moved with a variable such as `XDG_CONFIG_HOME` is not covered: add it to `fs.deny_read`.

[Claude Code](/docs/claude-code/) and [Codex](/docs/codex/) show how an agent logs in with a key instead of its saved login.

### .env files in your project

Tego also refuses reads of every file named `.env` or `.env.<anything>` in the rules file's folder and the folder the session starts in, up to six folders deep. `.env.example`, `.env.sample`, `.env.template` and `.env.dist` stay readable.

### Switching the list off

```yaml
fs:
  deny_read: []
```

An empty `deny_read` switches off the secret file list and the `.env` refusal. `tego rules check` warns `deny-read-disabled`. A `deny_read` with entries adds them to the built-in list. [Secrets](/docs/secrets/) covers what else keeps keys from the agent.

## Files that run code later

Inside a folder the agent may write, Tego refuses changes to files that would run code outside the session the next time something reads them:

| Kind | Files |
|---|---|
| Git | a repository's `.git/hooks` and `.git/config`, and `~/.gitconfig` or `~/.config/git/config` when they resolve inside a write folder |
| Agent and editor settings | `.claude`, `.mcp.json`, `.cursor`, `.codex`, `.gemini`, `.vscode` at a write folder's root or a repository's root |
| Shell startup files | `.bashrc`, `.bash_profile`, `.bash_login`, `.profile`, `.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`, `.config/fish/config.fish` at a write folder's root, or your home folder's copies when they resolve inside a write folder |

The rest of the git folder stays writable, so `git commit` works. Your own `fs.deny_write` adds to this set and cannot remove from it. How strictly each [protection level](/docs/tiers/) holds it, and `fs.assurance: kernel`, are on [Rules file fields](/docs/rules-reference/#files-fs).

## Tego's own files

The agent cannot read `~/.tego` (records, machine settings, logs), the records folder, `/run/tego`, the price table or the profiles folder. No `deny_read` value changes this. The one exception: when the records folder also holds the project or a write folder, Tego leaves it readable and `tego rules check` warns `ledger-readable`. Give the records folder a place of its own.

A write folder that covers the rules file, the records folder or `/run/tego` is an error: `tego rules check` reports it as `contradiction`, and `tego run` exits 125.

## Host sockets and terminals

Three fixed rules refuse what lets a process reach outside its session. A record names the rule that refused an action.

| Rule | What it refuses |
|---|---|
| `builtin.host_ipc` | The session bus, the systemd user manager and other sockets under your runtime folder (`/run/user/<uid>`); the system D-Bus, X11, tmux and screen sockets; the WSL sockets. |
| `builtin.tego_surface` | Tego's control sockets, other sessions' sockets, and local connections to port 8484 and to the `serve.port` machine setting. |
| `builtin.other_tty` | Opening another terminal or virtual console. The session keeps its own terminal. |

SSH agent sockets are not refused, so `git` over SSH works. An SSH agent can sign with every key it holds unlocked.

Container daemon sockets are refused. An exact `unix:` entry for one in `net.allow` allows it, and `tego rules check` warns `container-socket-escape`, because a daemon can start containers outside the session. Any other `net.allow` or `net.ask` entry for a socket on this list is an error (`contradiction`).

## Next steps

- [Secrets](/docs/secrets/): keep your own keys and variables from the agent.
- [Presets](/docs/presets/): ready-made rules that add to this list.
- [Rules file fields](/docs/rules-reference/): `fs.deny_read`, `fs.deny_write` and `fs.assurance`.
