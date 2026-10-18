# The real interactive Codex under an enforcing contract, fully offline

The real full-screen Codex (`codex`, codex-cli 0.159.2), typed into on a pseudo-terminal, held to an enforcing
contract at tier `landlock` (no root), with every model request answered by a local stand-in and no credential on the
machine but an obvious dummy key. It shows tool use, refusals, a human approval that holds the session, and the same
approval answered at once the second time. Nothing is sent to an OpenAI address: the ledger is read back to prove it.

```
test/poc/interactive-codex/run.sh            # unit, startup probes, the session, learn; about 6 minutes
test/poc/interactive-codex/run.sh session    # just the session
test/poc/interactive-codex/run.sh startup    # what Codex's own start-up does under the contract
test/poc/interactive-codex/run.sh learn      # the same session recorded with no boundary, and `tego learn` over it
test/poc/interactive-codex/run.sh contracts  # the two contracts for a real key: they compile, and their rule tables hold
test/poc/interactive-codex/run.sh negative   # the session four times, a rule removed each time: checks must FAIL
test/poc/interactive-codex/run.sh unit       # the stand-in's own self-test only
```

It needs `codex` on `PATH` (or `CODEX=<path>`), `go`, `python3`, `openssl`, `jq`, and a kernel with Landlock (the box
this was written on has ABI 7). No root. Everything happens under `$ROOT` (a temporary directory by default;
`ROOT=<dir>` keeps it): tego's own machine config, ledger, chain anchor and log (the `tegotesthooks` build redirects
them), an isolated `HOME`, the agent's workspace, Codex's configuration, the stand-in and its certificate. `~/.tego`
is listed before and after, and the contract denies the agent the files of `~/.codex`, `~/.claude`, `~/.claude.json`,
`~/.config/anthropic` and `~/.tego` that exist. The scripts never read those paths: `~/.codex` also holds Codex's own
installation (`~/.codex/packages`), which is run, and nothing else in it is opened.

## The parts

| File | What it is |
|---|---|
| `codex-interactive-offline.yaml` | The contract, as a template: every entry carries a comment saying what it is for. `run.sh` fills in the stand-in's port, the scratch root and the real home's files that exist, and tego loads and compiles the result (`tego compile` is printed). |
| `codex-config.toml` | The `config.toml` Codex starts from, as a template, every switch commented with what it does and was measured to do. |
| `stub-script.json` | What the stand-in's "model" says, turn by turn: the tool calls Codex is told to make (a command in the workspace, a read of the decoy secret, `git push`, a connection, `apply_patch` into the held directory, two appends to a file in it, two writes to another). The stand-in is `test/workloads/model-stub/openai_responses.py`, a scripted OpenAI Responses API like the Anthropic one kill test 7 uses; `--selftest` checks it. |
| `git` | A harmless stand-in `git` on the agent's `PATH`. It is never started under the contract. |
| `drive.py` | The person at the keyboard: starts `tego watch --boundary ... -- codex --no-daemon`, types the dummy key into Codex's login screen, types prompts, and, from separate `tego` processes, answers tego's approvals (`tego ask`, `tego approve [--always]`, `tego deny --always`). It uses `../interactive-claude/ptyscreen.py`, the one terminal emulator the POC has. |
| `report.py` | Reads the run's ledger back and checks every claim against ledger events; trusts nothing the driver printed. |
| `dns_probe.py`, `procself_probe.sh` | Two small programs of their own that show what `net.dns.mode: off` does at tier `landlock` and what `exec.allow: ["/proc/self/exe"]` granted when this was recorded (since 2026-10-16 `compile` refuses that entry, `exec-proc`, and `run.sh`'s L2 checks the refusal instead of running the probe). |
| `codex-real-forwarder.yaml`, `codex-real-direct.yaml` | Contracts for a real OpenAI API key, wider than the offline one: no `fs.ask` for `held/`, a write grant of `./`, and `git`, `ls` and `mkdir` allowed ("With a real key" below). Written and compiled offline; **not run**. |
| `run.sh` | Builds an isolated tego, starts the stand-in, lays the scratch out, runs the probes, the session and `learn`, prints the checks. |

## How the model never leaves the box

The contract has `models: [{provider: openai, host: 127.0.0.1, port: <stand-in>}]` and `capture: forwarder`. Tego
starts a plaintext listener on 127.0.0.1 for that entry. Codex takes no base-URL variable (it ignores
`OPENAI_BASE_URL`: with the variable set it went for `api.openai.com`, which the contract refused), so for an `openai`
entry the launcher makes a `CODEX_HOME` of its own for the run, in `$XDG_RUNTIME_DIR/tego/<run id>/codex`, whose
`config.toml` holds `openai_base_url` for the listener, then the `config.toml` that the contract's `CODEX_HOME` names
(capture-derive.md R19b; this is the first time that route met a real Codex). The listener speaks TLS to the stand-in,
trusting its self-made certificate through `SSL_CERT_FILE` in tego's own environment (Codex is not given it). Every
request is recorded as `ssl_request source=forwarder`. `net.allow` has only the name-service socket, so a direct
connection around the forwarder is refused.

`ROUTE=b run.sh session` does the same with the other way Codex can be pointed at a local endpoint, the one its own
documentation gives: a custom provider, `[model_providers.stand-in]` with `base_url`, `wire_api = "responses"` and
`env_key`, and `model_provider = "stand-in"`. The base URL has to be written before the run, so the forwarder's port
is pinned in the machine config (`forwarder: listen: 127.0.0.1:<port>`). The key is then read from the environment,
Codex asks for no login and makes no WebSocket offers, and the run is otherwise the same.

## What a person has to know to run Codex this way

- **Its own sandbox has to be off.** Codex's sandbox (bubblewrap) cannot start inside the Landlock domain: left on,
  every command the model asks for fails with `error building bubblewrap command: Permission denied (os error 13)`,
  exit 1, and never reaches the shell. Codex does not die of it; it hands the error to the model. `sandbox_mode =
  "danger-full-access"` and `approval_policy = "never"` in `config.toml`, or
  `--dangerously-bypass-approvals-and-sandbox`, or `-s danger-full-access -a never` (`codex exec` takes `-s` and not
  `-a`) turn it off; Codex then says `permissions: YOLO mode`, and nothing asks a person on its side. The contract's
  `ask` is the approval.
- **`codex --no-daemon`.** Codex's interface starts a shared background server (`codex app-server --managed-daemon`,
  with a control socket under `CODEX_HOME/app-server-control/`) and is its client, so the commands it runs are the
  server's. Under the contract the server's start is refused (`sh` first, then `/tmp/codex-daemon-<uid>`) and the
  interface exits 1: "rerun the same command with --no-daemon" (P1). The flag matters more than that:
  `features.daemon_auto_start = false` only stops Codex from starting a server. With a stored login in a `CODEX_HOME`
  the run may write, the interface still connects to the control socket of one that is already running, and tego lets
  that connect through because a socket under a write entry is taken to be the run's own (P2c);
  `--no-daemon` makes no such connect. A server already running is not under tego.
- **Its start-up switches** (`codex-config.toml`):
  `check_for_update_on_startup = false`, `[analytics] enabled = false`, `[feedback] enabled = false`, and `[features]`
  `plugins`, `remote_plugin`, `apps`, `shell_snapshot` and `daemon_auto_start` off. Without `plugins = false` Codex
  runs `git ls-remote https://github.com/openai/plugins.git` and connects to chatgpt.com and a GitHub address at
  start, straight out whatever the base URL is; without `shell_snapshot = false` it runs a login shell that starts 23
  more programs. What stays, with the resolver reachable: a connection to raw.githubusercontent.com (an announcement
  file, no switch found), and, whatever the resolver, Codex's `lsb_release`/`getconf` probes of the operating system
  and an attempt at the D-Bus session bus.
- **The login screen.** Codex's interactive interface reads no API key from the environment (`OPENAI_API_KEY` and
  `CODEX_API_KEY` were both set and ignored); with the built-in provider it shows its login screen and the driver
  chooses "Provide your own API key" and types the dummy. Codex stores it in `auth.json` in the run's private
  `CODEX_HOME`, which tego removes with the run (when the launcher was killed first, the next run launched under
  the same `XDG_RUNTIME_DIR` removes it). "Sign in with ChatGPT" starts a login server on a local port
  (refused here: `failed to start login server: Permission denied`) and "Sign in with Device Code" asks
  auth.openai.com (refused): P0. `codex exec` runs with no key at all against a stand-in, and takes `CODEX_API_KEY` as
  the bearer when it is passed on.
- **A model name Codex knows, or a catalog of your own.** An unknown name works, with a warning at every start and no
  `apply_patch` tool; a bundled name brings an upgrade dialog; the newest bundled models are given a JavaScript `exec`
  tool the stand-in does not script. `run.sh` therefore makes a one-model catalog from the bundled `gpt-5.5` entry
  (`model_catalog_json`).
- **The stand-in answers the WebSocket offer with 426.** Codex tries `GET /v1/responses` with an upgrade first, and
  retries five times with back-off (about 6 s) if the answer is 404; 426 sends it to `POST /v1/responses` at once. The
  forwarder strips the upgrade headers (R20) and records the offer as one more `ssl_request`.
- **The run's private `CODEX_HOME` needs a write grant a contract cannot name.** Its name holds the run id. In the
  session recorded here the contract granted its parent, `$XDG_RUNTIME_DIR/tego/` (here
  `$ROOT/xdg-tego/tego/`), which reached every other run's private directory; and without an `XDG_RUNTIME_DIR` in
  tego's own environment the launcher made no such directory and routed nothing, with no warning (Codex failed
  closed: it could not write its state, exit 1). Since 2026-10-16 the run grants Codex write on its own `CODEX_HOME`
  itself (`fs.codex_home[<path>]`, listed in `run_start.runtime_grants`), a contract entry over or inside
  `$XDG_RUNTIME_DIR/tego` is refused by `compile` and by the launcher, and a run that routes Codex with no
  `XDG_RUNTIME_DIR` is refused, exit 125, naming the fix (agent-contract.md R10a). The contracts here grant no such
  entry any more; the session has not been run again since. The directory is closed to the writes of other enforcing
  runs, not to their reads: while a run lasts (and after a killed launcher, until the next run removes it), an
  agent of any other tego run of the same user can read its
  `CODEX_HOME`, the `auth.json` with a typed key included (R10a's open condition), and a `tego run --observe` agent,
  which enforces no file-system rule, or any of the user's processes outside tego can write it too
  (docs/OPERATIONS.md step 4 says what to do meanwhile).
- **Codex starts itself.** Before every command it runs `/proc/self/exe --codex-run-as-process-setup`, and
  `apply_patch` as a shell command is a symlink to it in `CODEX_HOME/tmp/arg0/`. Both are the command's own binary and
  need no `exec.allow` entry. A `/proc/self/exe` entry compiled to the tego binary, not to Codex, when this ran, and
  `tego learn` proposed it; since 2026-10-16 `compile` refuses it (`exec-proc`, agent-contract.md R8a) and `tego
  learn` lists it as observed, not allowed.
- **A login shell prints one refused line.** Codex runs each command as `bash -lc`, which sources `/etc/profile`,
  which runs `run-parts`; refused by `exec.allow`, it prints `/etc/profile: line 21: /usr/bin/run-parts: Permission
  denied` ahead of every command's output. Harmless; allowing `run-parts` allows the chain of programs it starts.
- **Do not deny `~/.codex` as a whole.** Codex's own installation is `~/.codex/packages/...`, next to its login
  (`auth.json`), history and sessions. The contract denies each file that exists, by name.
- **`net.dns.mode: off` does not stop every name lookup at tier `landlock`.** It refuses the lookups of a program
  whose resolver connects its datagram socket first, and records as refused, but lets through, a lookup sent with an
  address on an unconnected socket (the ledger line says `refused` and `best_effort: true`). Codex has both: its
  start-up lookups were refused outright, its WebSocket client's were sent and answered, and a program of its own
  shows the difference in two lines (P4, P4b). A contract that needs no name lookup from the agent, such
  as one that reaches its model through the forwarder, loses nothing by `off`, and the report checks that no refused
  datagram of the session was sent anyway. The root tiers decide these datagrams in the kernel.

## What the session does

| Step | Codex | The contract | Where it shows |
|---|---|---|---|
| 0 | the first screen, the login screen | `net.allow` only the forwarder; no `auth.json`, no key in the environment | Codex asks for a key; the driver types the dummy; the prompt box appears |
| 1 | `echo ... > work/note.txt; cat work/note.txt` | `fs.write: ./work/`, `exec.allow: [bash, cat]`: allowed | the file exists; ledger `fs allow fs.write[./work/]` |
| 2 | `cat <decoy secret>` | `fs.deny_read`: refused, `read-denied` | Codex's output: `Permission denied (os error 13)`; the marker is in none of the model requests |
| 3 | `git push origin main`, with a harmless stand-in `git` | `exec.allow` has no `git`: `exec-not-allowed` | `git exit=126`; ledger `exec refused`; the stand-in never ran |
| 4 | a connection from bash to `127.0.0.1:9` | no `net.allow`: `net-not-allowed` | `/bin/bash: connect: Permission denied`; ledger `net refused` |
| 5 | the `apply_patch` tool, `Add File: held/report.txt` | `fs.ask: ./held/`: held until `tego approve` | the spinner; `tego ask` lists it; the file is written in place, so the approval is enough |
| 6 | `echo first >> held/journal.txt` | held; a person runs `tego approve --always` | ledger `ask`, `answer ... always` |
| 7 | the same append again | answered at once by the standing answer | ledger `ask` and `answer by standing:<id>` in the same instant |
| 8 | `echo nope > held/other.txt`, twice | held; a person runs `tego deny --always`; the repeat is refused at once | `Permission denied`; ledger `ask-denied` twice |
| 9 | `/exit` | | Codex quits, `tego watch` exits 0, the run ends `exit` |

## With a real key (written, not run)

`codex-real-forwarder.yaml` has the offline contract's shape, with `models` naming `api.openai.com:443` where the
stand-in was and the paths of a real account marked CHANGE, but it differs by more than that. It has no `fs.ask`, so
the `held/` approval gate of rows 5 to 8 above is gone and nothing waits for a person. Its write grant is the whole
project (`./`, which would cover `held/` anyway, since an ordinary grant decides before an ask), not `./work/`, and it
sets no `TMPDIR`. `exec.allow` adds `git`, `ls` and `mkdir`, and `limits.wall` is 2h. For the gate, start from
`examples/agents/codex.yaml`: the same forwarder route with the write grant narrowed to `./work/` and the `fs.ask`
for `held/` kept (its rule table is tested; it was not run either). Run either as
`XDG_RUNTIME_DIR=/run/user/$(id -u) tego watch --boundary codex.yaml -- codex --no-daemon`. The forwarder dials the
real endpoint over TLS itself and resolves its name, so Codex needs no connection and no lookup of its own; the key is
typed into Codex's login screen once per run (or `CODEX_API_KEY` for `codex exec`), and the model's requests and
responses are recorded. `codex-real-direct.yaml` is the variant for a machine without an `XDG_RUNTIME_DIR` (a
container, cron, an ssh session without a login manager), where the forwarder variant is refused, exit 125: Codex connects to `api.openai.com:443` itself, `net.allow`
names only that, a name lookup has to be allowed, and the model's traffic is not recorded (Codex is one static,
stripped musl binary, so it loads no TLS shared library for a uprobe to attach to; `capture: uprobe` was not tried).
Both compile (`tego compile --offline`), and `run.sh contracts` checks their rule tables with `compile --test` (the
forwarder variant refuses a direct connect to `api.openai.com:443` in every tier; the direct variant allows that one
endpoint and refuses `chatgpt.com` and `raw.githubusercontent.com`; each check is shown to fail on a contract with the
rule changed). `compile` may warn about `fs.write "./"` (the project root) when the tree beneath it is deeper than
four levels: the search for git hooks and configs to protect stops there. Its fix is to name the directories the agent
edits. Neither was run, because a run needs a key. Not known: what the real API answers to
the WebSocket offer once the forwarder has stripped its upgrade headers (Codex falls back to POST either way, at once
or after its five retries); how a ChatGPT login behaves (it needs a listening socket, auth.openai.com and chatgpt.com,
none of which either contract allows; whether `net` listener declarations can admit the bind was not tried); whether
the forwarder's `net.http` rules, held requests or cost limits behave with Codex's `/v1/responses` as they do with
Claude Code's `/v1/messages`.

The `config.toml` to put in the directory that `CODEX_HOME` names in `codex-real-forwarder.yaml` (the same switches as
`codex-config.toml`, without its stand-in model catalog and route lines; `model` is a name your key can use, and a
name Codex has an upgrade for brings its "Meet the next model" dialog, which is Codex's own and a person answers it):

```toml
model = "gpt-5.5"
sandbox_mode = "danger-full-access"
approval_policy = "never"
check_for_update_on_startup = false
[analytics]
enabled = false
[feedback]
enabled = false
[features]
plugins = false
remote_plugin = false
apps = false
shell_snapshot = false
daemon_auto_start = false
[projects."/path/to/the/project"]
trust_level = "trusted"
```

It must not set `openai_base_url`: with `capture: forwarder` the launcher writes that key itself, and a duplicate
makes the file invalid, which Codex refuses to start on.

## Looking at it yourself

```
. $ROOT/state/env.sh                 # tego ask / approve / deny / events / status against the last run
tego events <run> --kind ssl_request --json | jq .      # the model requests the forwarder recorded
tego events <run> --verdict refused                      # everything the contract refused
tego events <run> --verify                               # the hash chain, and where it is anchored
ROOT=/some/dir KEEP=1 test/poc/interactive-codex/run.sh session   # keep $ROOT/evidence/ (screens) and ledgers/
```

## Not in scope

Tego governs the agent session only: the processes the operator chose to govern and their descendants. This does not
hide from or resist root, and says nothing about the rest of the host. The contract is tier `landlock`; the root tiers
are not run here, so the name lookups that tier lets through are not shown closed. The one step that
cannot be done offline, a real key or a ChatGPT login, is described above.
