# Presets: rules ready in minutes

A preset is a set of rules that ships inside the `tego` binary.
Your contract (`agent.yaml`) names the presets it wants in `extends:`, then adds what is particular to your project:
its folders, its hosts, its model, the variables it needs. There are three:
- `tego/no-secrets`: the agent cannot read your secret files, and your secret variables never reach it.
- `tego/no-prod`: the agent reaches no network host except the ones your contract names.
- `tego/repo-only-writes`: the agent writes only in the folders your contract names.

## Pick and combine

Name one preset, or several in a list. They set different
rules, so any combination works. This contract runs Claude Code under all three:
```yaml
version: 0
name: my-agent
extends: [tego/no-secrets, tego/no-prod, tego/repo-only-writes]
command: ["claude"]
models:
  - {provider: anthropic, host: api.anthropic.com, port: 443}   # the model, reached through Tego's forwarder
fs:
  write: ["./src/", "./tests/"]        # the folders repo-only-writes lets the agent write
net:
  allow: ["registry.npmjs.org:443"]    # the hosts no-prod lets the agent reach
env:
  pass: ["ANTHROPIC_API_KEY", "NPM_CONFIG_REGISTRY"]   # variables no-secrets would otherwise keep out
```

Keep the `models:` entry and the key variable when you use
`tego/no-prod` and `tego/no-secrets`. The agent reaches its model through Tego's forwarder only when the contract
declares the model under `models:`; without that entry no forwarder starts, and `tego/no-prod` refuses the agent's
connection to its model like any other host. `tego/no-secrets` passes no API key unless `env.pass` names it, and the
forwarder adds none.

Your own entries are added to the preset's: lists join, the
preset's entries first. A name under `tego/` is always the built-in preset; a file of your own under `profiles/tego/`
is never read in its place, and `tego compile` says so (`shadowed-builtin`). A misspelt preset such as
`tego/no-secret` is an error that lists the names there are:
```
error: agent.yaml:3:10: built-in profile "tego/no-secret" not found: names under tego/ are tego's own profiles, and this binary has none by that name [extends-not-found]
  fix: the built-in profiles are tego/no-prod, tego/no-prod@1, tego/no-secrets, tego/no-secrets@1, tego/repo-only-writes, tego/repo-only-writes@1; name one of them, or remove it from extends:
```

## Pin a revision

Each preset has numbered revisions. `tego/no-prod` is its newest
revision, so a fix to a preset reaches you with the next release of Tego. `tego/no-prod@1` is revision 1 and nothing
else, whatever release you run: pin when a run must be reproducible across upgrades. A released revision never
changes; a change is a new revision. Every run records the presets it merged (`run_start.profiles` in the run's
ledger): each by the name the contract wrote, the pin included when there is one, and the checksum (sha256) of the
rules merged. For an unpinned name the checksum is what says which revision ran: each released revision's checksum
is listed in Tego's source (`pkg/spec/presets`). Naming one preset both ways, `tego/no-prod` and `tego/no-prod@1`,
merges it once, and `tego compile` warns `redundant-rule` at the second name.

## See the one rule file

`tego compile --merged agent.yaml` prints your contract with
every preset laid in: the rules the run enforces, in one file. It is what the run keeps as `contract.yaml`, and its
sha256 is the run's `contract_hash`, so `tego compile --merged agent.yaml | sha256sum` tells you the hash before you
run. It keeps its `extends:` line, so it is a record to read and compare, not a contract to run in place of yours.

## What each preset covers, and what it does not

### No secrets

`tego/no-secrets` passes the agent only these variables from
your shell: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`,
`TERM`, `COLORTERM`, `TZ`, `NO_COLOR`, `GOPATH`, `GOROOT`, `GOCACHE`, `GOMODCACHE`, `CARGO_HOME`, `RUSTUP_HOME`,
`JAVA_HOME`, `NVM_DIR`, `PYENV_ROOT`, `VIRTUAL_ENV` and `CONDA_PREFIX`. A token you exported in the shell that starts
the run (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, an API key) is absent from the agent's environment. Its file half
is Tego's built-in list of secret files, which every contract has unless it switches the list off: SSH keys, cloud
credentials (`~/.aws`, `~/.config/gcloud`, `~/.kube/config`), token stores (`~/.config/gh`, `~/.npmrc`,
`~/.git-credentials`, `~/.docker/config.json`), browser profiles and `.env` files.

What it does not cover:
- A variable you add to `env.pass` reaches the agent, and so do the variables Tego sets for the run itself
  (`TEGO_*`, and the forwarder's address when the model is reached through it).
- Your shell's startup files. `HOME` and `SHELL` are passed, so every login or interactive shell the agent starts
  reads `~/.profile`, `~/.bash_profile`, `~/.bashrc`, `~/.zshenv`, `~/.zprofile` or `~/.zshrc` again, and a variable
  exported there is back in that shell's environment. Codex runs each command as `bash -lc`, so under this preset a
  Codex agent's commands still see every token those files export. The files, and your shell history
  (`~/.bash_history`, `~/.zsh_history`), are readable unless you add them to `fs.deny_read`; keep tokens out of them,
  or deny them (a shell that cannot read a startup file reports the error and starts without it).
- A secret kept in a file the list does not name (a key under another name, a token inside a project file) is
  readable unless you add it to `fs.deny_read`.
- A listed secret file inside one of your write folders, a `.env` in `./src/` for example, can be moved or
  hard-linked to another name at tier landlock and read under that name; `tego compile` warns `held-reads`. Keep
  secrets outside the folders the agent writes.
- A contract that writes `deny_read: []` switches the built-in list off, preset or not; `tego compile` warns
  `deny-read-disabled`.

### No production hosts

Under `tego/no-prod` every network connection is refused except
to the hosts your contract's `net.allow` names and to the model your contract declares under `models:`, which the
agent reaches through Tego's forwarder. No host is listed by the preset, and no production host is listed by
default anywhere. A contract with no `models:` entry starts no forwarder, so the preset refuses the agent's own
connection to its model (see Pick and combine).

What it does not cover: the machine's DNS resolver stays
reachable (`net.dns.mode` is `system` unless the contract says otherwise), so the agent can look names up, and a
lookup can carry a few bytes to the name server of any domain. A host you list is reachable on its port for whatever
the agent sends it.

### Writes only in your folders

Under `tego/repo-only-writes` every write is refused except in
the folders your contract's `fs.write` names, and to `/dev/null`, which many tools open for writing and which stores
nothing. A write here is a change to a file's contents and the making, removing, renaming or linking of a file or
folder. With no folder in the contract, the agent writes nothing else.

What it does not cover:
- Reads. The agent still reads files outside those folders (other than the secret files above).
- A file's attributes outside the folders. A change of a file's mode is not refused at any tier: `chmod` is recorded
  in the ledger as allowed (rule `unmatched`), and a mode change can make a file writable by other users. A change
  of its owner or group, its extended attributes or its timestamps is not refused at tier landlock, and a timestamp
  change is not recorded at all.
- A folder you name is writable in full, apart from the few files Tego refuses beneath every write folder (git's
  hooks and config, and shell startup files such as `.bashrc`, which run programs the next time they are read).
- To widen writes, name more of the project's folders. `./` itself is refused while the contract file sits in it
  (`contradiction`: the contract file stays out of the agent's reach); with the contract kept outside the project, `./` makes
  the whole project writable.
- A tool that writes its temporary files to `/tmp` is refused there: give it a folder of yours, for example `TMPDIR`
  under one of your write folders.

## Start from tego init

`tego init --preset` writes an `agent.yaml` that extends the presets you choose and lists your folders and hosts,
each generated line with a comment saying why it is there. Run it in the project folder:
```
tego init --preset no-secrets,no-prod,repo-only-writes --write src --write tests \
  --allow-host @npm --allow-host api.example.com --command "claude"
```

What each flag does:
- `--preset <list>`: a comma list of `no-secrets`, `no-prod` and `repo-only-writes`, in any order; `extends:` lists
  them in that fixed order. An unknown name is a usage error listing the three.
- `--write <dir>` (repeatable): a folder the agent may write. A missing folder inside the project is created; one
  outside it must exist. `repo-only-writes` with no `--write` and no project marker is a usage error naming `--write`.
- `--allow-host <host[:port] | @group>` (repeatable): a host the agent may reach, port 443 when none is given (an
  IPv6 address with a port is written `[::1]:8080`). A
  group (`@github`, `@npm`, `@pypi`, `@crates`, `@go-proxy`, `@rubygems`, `@maven-central`) is written out as its
  hosts, each with a comment naming the group; `tego init --list` prints the groups and the presets.
- `--command <line>`: the agent's command. A line with no shell syntax is split into words; one with pipes, quotes
  or `&&` runs under `/bin/sh -c`. Without it init writes a short demo: a write in your first folder (allowed), a
  write outside it (refused) and a check that no secret variable reached the agent.
- `--name`, `--force` and the directory argument work as for plain `tego init`, which still writes the starter.
  Run again on an `agent.yaml` init wrote, `--preset` leaves the file as it is and says the new flags were not
  applied; edit the file, or add `--force` to replace it.
- A `--write` folder that is, holds or lies inside a path of the built-in `deny_read` list (`~/.ssh`, `~/.aws`, ...)
  is accepted, since you named it, and init prints a note naming that path.

When writes are restricted init also adds what the project's
markers need: `./node_modules/` for `package.json`, `./target/` for `Cargo.toml`, `./.venv/` for `pyproject.toml` or
a `requirements*.txt`, and for `go.mod` the Go caches under `./.tego/cache/` (`GOCACHE`, `GOMODCACHE`); `TMPDIR` goes
to `./.tego/tmp/`. Those folders under `.tego/` are added to `.gitignore`. Before writing, init compiles the contract
offline, as `tego compile --offline` would, and when it does not compile prints compile's diagnostics, exits 1 and
writes nothing: no `agent.yaml` and no folder. The paths are relative to the project, so run `tego compile` and
`tego run` from it.

The file reads top to bottom: what each preset promises, the
`extends:` line, then each section with a comment saying why it is there and each entry with the flag or project
marker it came from, for example:
```
# Where the agent may write; a folder covers everything beneath it. repo-only-writes refuses every
# write outside these entries.
fs:
  write:
    - "./src/"           # --write
    - "./.tego/cache/"   # go.mod: the Go build and module caches
    - "./.tego/tmp/"     # TMPDIR: the agent's temporary files stay in the project
```

Always on, in every contract init writes and every other: the
host's local daemon sockets (docker, the D-Bus bus, ssh-agent) are refused unless the contract sets `host_sockets:
true`, and the agent cannot gain privilege (`no_new_privs` is set on every run). Your agent's own needs are yours to
add: `--allow-host` passes a model host straight through, not through the forwarder (use a `models:` entry, as in the
example above, to have tokens counted), its API key goes in `env.pass`, and a home folder it writes (Claude Code's
`~/.claude`) needs its own `--write`.

## Start from the dashboard

The dashboard (`tego-control serve`) writes the same file without a terminal: Rules, then
"Set up a new agent". Type the project folder, tick the presets, add the folders it may write and the hosts it may
reach (comma-separated, as `--write` and `--allow-host` take them) and its command, then Preview: the page shows
what the agent may do in plain sentences, every preset laid in, and what `tego compile --offline` says. Create
writes `agent.yaml` in that folder (never over an existing one) and shows the line to start it, for example
`cd ~/project && tego run agent.yaml`: the command you typed is in the file. "From a run" drafts the file from a finished run instead: it allows
what that run did and no more (`tego learn`), except where a run that leaked sent its secrets: that address is left out, and a red notice says so. The new file is on the Rules page as "not run yet" until its first run.
