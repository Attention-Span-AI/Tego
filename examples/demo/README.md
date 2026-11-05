# Tego demo (about 10 minutes)

## Cheat sheet

```
make build && export PATH=$PWD/bin:$PATH && cd examples/demo
./demo.sh setup
./demo.sh without
./demo.sh with
./demo.sh why
./demo.sh dashboard            # in a second terminal, left running; opens the dashboard (else open the URL it prints)
# Claude sockets use Tego's private run runtime (%R). Keep invoking XDG_RUNTIME_DIR short
# (normally /run/user/<uid>); launch validates the complete 103-byte socket-path budget.
./demo.sh claude               # or: ./demo.sh codex   (needs your own login)
./demo.sh always-on            # then: ./demo.sh always-on status, ./demo.sh always-on stop
./demo.sh tiers                # tier 1 here, tier 2 with sudo (your password), tier 3 or its enable steps
./demo.sh network              # one allowed destination, another refused, a backdoor listener refused
./demo.sh features             # the feature map below: one short scene per feature
./demo.sh reset
```

An agent without Tego causes harm; the same agent under Tego is refused, and Tego says why. Then the
dashboard, then real Claude Code and Codex in a terminal (two examples), a custom Python agent, then an agent that never stops.
Everything is fake and local: the "secrets" are planted files under `stage/`, the "internet" is a sink on
`127.0.0.1` that only counts bytes, and the demo never reads your real home.

## Feature map

Every scene prints each command before it runs it. `./demo.sh features` prints this table; the scenes are described
under "The feature scenes" below.

| Feature | Command | What you see | Where in the dashboard |
|---|---|---|---|
| The spine: harm, then the same agent refused | `./demo.sh without`, `./demo.sh with` | the sink gets the secret, the profile and a git hook change; then 0 requests and a refusal per step | Overview, then the run |
| Block read | `./demo.sh rule read` | `../secrets/.env` refused, `src/keep.txt` read | run page: `read-denied`, `fs.deny_read[../secrets/]` |
| Block write | `./demo.sh rule write` | `out/report.txt` written, the shell profile refused | run page: `write-outside-contract` |
| Block command | `./demo.sh rule command` | `ls` runs, `rm -r src` refused, src/ still there | run page: `exec.deny[rm -r]` |
| Network host | `./demo.sh rule net` | the listed host answers, an unlisted one is refused | run page: `net-not-allowed` |
| Process type | `./demo.sh rule process` | `unshare -U` and an in-memory (memfd) program refused | run page: `landlock-topology` (memfd: no line, see the scene) |
| No local daemon sockets (always on) | `./demo.sh always` | stand-in docker.sock and ssh-agent answer without Tego, refused under it | run page: rule `host-sockets` |
| No privilege escalation (always on) | `./demo.sh always` | `NoNewPrivs: 0` without Tego, `1` under it; sudo cannot raise | none (nothing left to refuse) |
| Reason, status file | `./demo.sh with` (step 7), `./demo.sh why` | the agent reads `$TEGO_REASON`: "Tego refused open ... (rule ...)" | run page, Refusals tab |
| Reason, Claude Code hook | `./demo.sh reason-hook` | a stand-in Claude Code (no login) under Tego; its next model request carries "Tego refused open ..." | run page of `demo-claude-standin` |
| Reason, real Claude Code | `./demo.sh claude` | ask it to read `~/.ssh/id_rsa`; it says why it was refused | the run, live |
| Receipt | `./demo.sh receipt` | `tego receipt --last`: time, files written, refusals with rules, asks | run page, Receipt tab |
| Presets | `./demo.sh presets` | `tego init --preset no-secrets,no-prod,repo-only-writes ...`, `tego compile`, the rogue agent under it | Rules (`/rules`) |
| Escape self-test | `./demo.sh selftest` | `tego test`: four tricks, each succeeds without Tego and is refused under it, with its rule | none |
| Approvals | `./demo.sh ask`, then `./demo.sh approve` (or `deny`) in a 2nd terminal | the agent pauses on a write to `held/` until you answer | Approvals (`/approvals`): Approve / Deny |
| Limits | `./demo.sh limits` | a fork bomb stops at 32 processes; a memory hog is killed at 128 MiB | run page: exit `pids`, `oom` |
| Protect .git/hooks in a writable repo | `./demo.sh deny-write` | `src/` writable, `.git/hooks/pre-commit` refused | run page: `fs.deny_write[./.git/hooks/]` |
| Tamper-evident ledger | `./demo.sh why` | `--verify` passes; one changed word in a copy fails | the run page's chain badge: "Chain verified" |
| 24/7 agent | `./demo.sh always-on` | a systemd --user service; a refusal every 5 s, run after run | Overview: the live run, refusals climbing |
| Run identity | `./demo.sh identity` | who started the newest scene's run, on which host, the contract hash; `./demo.sh ask` shows who answered (`approved by uid:...`) | top bar: the host; the timeline's answer line names the uid |
| What this machine can enforce | `./demo.sh doctor` | `tego doctor`: tier 1 ok; the root tiers say "requires root"; tier 3 needs the BPF LSM | none |
| Real agents | `./demo.sh claude`, `./demo.sh codex` | the real tools, interactive, under a contract | the runs, live |

## Before you start

```
make build && export PATH=$PWD/bin:$PATH      # tego and tego-control
cd examples/demo && ./demo.sh setup            # plants the fake world, starts the sink
```
Say: "Everything you will see is a stand-in. Nothing real is read, nothing leaves this machine."
Optional second terminal: `tail -f examples/demo/stage/sink.log` (the sink prints one line per request).
Each subcommand prints the command it runs before it runs it. `DEMO_STAGE` and `DEMO_PORT` move the stage and the sink.
A stage path holding `'`, `"`, `\`, `|`, `&` or a line break is refused: the kit puts it into the commands it shows
and into contracts. The kit's own folder and tego's path go into the commands only, so just a `'` or a line break is
refused there; a kit under a folder such as `R&D` runs with `DEMO_STAGE` set elsewhere (its default stage, inside that
folder, is refused).

## Act 1: without Tego

```
./demo.sh without
```
Say: "An ordinary agent. It read the secrets, sent them out, edited the shell profile, planted a git hook, deleted a file and ran what it liked."
Proves: the risk is concrete. Point at the `What is left on the machine` block: the sink got the bytes, the profile is tampered, the hook is planted, `notes.txt` is gone.

## Act 2: the same agent under Tego

```
./demo.sh with
```
Say: "Same script, now under a contract the kernel enforces. Every step is refused, and the rule is named."
Proves: file, network and program rules (`contracts/guarded.yaml`). The sink got 0 requests, the machine is untouched, and the last table is the ledger's refusals, one row per refusal: `read-denied` (rule `fs.deny_read[...]`), `net-not-allowed`, `write-outside-contract` (twice), `delete-outside-contract` and `exec-not-allowed`. The RULE column names the contract entry that decided; `unmatched` means no entry allowed the action, so the default deny refused it (the contract grants a few things and nothing else).
`python3` is on the allow list for step 7, which reads `$TEGO_REASON`, a JSON file, with it. The copy the act shows names it by the file it runs as (`/usr/bin/python3`, or the interpreter a pyenv or asdf shim starts: a `#!` shim could not be granted, its own `/usr/bin/env` being on no list), and the agent gets that path as `PYTHON3`.
If tego refuses to start the run, the act stops at its message (`the run failed (tego run exited 125)`, tego's own
exit, not the output filter's) and shows no damage report and no earlier run's refusals; `./demo.sh why` then says
there is no run yet.

## Act 3: why, and the record

```
./demo.sh why
```
Say: "Tego does not only fail the call. In step 7 above the agent read why, in words, from `$TEGO_REASON`, so a model can re-plan instead of retrying. The record is a hash chain: change one word and it stops verifying."
Proves: the reason channel; the tamper-evident ledger (`tego events --verify` passes, then fails on an edited copy: `does not verify ... id does not match line bytes`, exit 1). The copy is `tego events <run> --json`, the record's lines byte for byte, so the step works wherever the machine config puts the ledger.

## Act 4: the dashboard

```
./demo.sh dashboard          # runs: tego-control serve --open; opens the dashboard signed in (or open the one URL it prints). Keep it running in a second terminal
```
Say: "Everything you just saw, in a browser: the runs, their refusals, the logs."
Show: Overview, the run from Act 2 and its refusals (`/runs/<id>`), the Logs page (`/logs`), Approvals (`/approvals`).
If this build prints `[not-built]` the dashboard is not in this binary yet; use `tego status --all` and `tego events <run>`.

## Act 5: real agents in a terminal

Use your own login. Nothing is stored in this kit and the demo never logs in for you.

```
claude setup-token             # once, outside Tego: your Pro/Max subscription login as a token
export CLAUDE_CODE_OAUTH_TOKEN=... # the token it printed (or: export ANTHROPIC_API_KEY=... for an API key)
# Claude sockets use Tego's private run runtime (%R). Keep invoking XDG_RUNTIME_DIR short
# (normally /run/user/<uid>); launch validates the complete 103-byte socket-path budget.
./demo.sh claude               # Claude Code, interactive, under contracts/claude-code.yaml (the copy-paste form is examples/agents/claude-code-interactive.yaml)
./demo.sh codex                # Codex, interactive, under contracts/codex.yaml; choose "Provide your own API key" on its login screen
```
Codex signed in with a ChatGPT plan instead of a key: its sign-in listener cannot run inside Tego, so sign in once outside it and copy `auth.json` into a Codex home of its own (never `~/.codex`), then run `contracts/codex-chatgpt.yaml` (fill its two `@@` words; `examples/agents/codex-chatgpt.yaml` says how):
```
mkdir -p ~/.local/share/tego/codex-chatgpt && codex login && cp ~/.codex/auth.json ~/.local/share/tego/codex-chatgpt/auth.json && chmod 600 ~/.local/share/tego/codex-chatgpt/auth.json
printf 'sandbox_mode = "danger-full-access"\napproval_policy = "never"\ncheck_for_update_on_startup = false\n' > ~/.local/share/tego/codex-chatgpt/config.toml   # Tego is the cage
sed -e "s|@@CODEXHOME@@|$HOME/.local/share/tego/codex-chatgpt|g" -e "s|@@CODEXHOST@@|$(dirname "$(readlink -f "$(command -v codex)")")|g" contracts/codex-chatgpt.yaml > ~/codex-chatgpt.filled.yaml
mkdir -p ~/chatgpt-proj/work/tmp ~/chatgpt-proj/held && cd ~/chatgpt-proj && tego run ~/codex-chatgpt.filled.yaml
```
Say: "The real tools, in a normal terminal. Tego is the cage: they can only do what the contract lines allow."
The contract lines that make it work: `net.allow: tcp://api.anthropic.com:443` with `capture: off` (Claude Code exits on its first connectivity check if its model traffic is forced through the forwarder), `fs.write` has `/dev/tty` (the full-screen interface), `CLAUDE_CONFIG_DIR` inside the project (so `~/.claude` is never written), `exec.allow: [bash, git]`. For Codex: `capture: forwarder` with `models: openai` (every model call is recorded), Codex's own sandbox switched off in the `config.toml` the kit writes because Tego is the cage, `codex --no-daemon`, `fs.write: ./work/` only and `fs.ask: ./held/` (a write there pauses Codex until you run `tego approve` in a second terminal).
No wall limit on `claude-code.yaml` and `codex.yaml`: they set `limits.stall_after: 1h`, not `wall`. `codex-chatgpt.yaml` is the one exception: it records as a short demo does (`record: summary` with `reads: held`, so the dashboard shows what matters) and keeps `wall: 2h`; `examples/agents/codex-chatgpt.yaml` is its long-session form, with `record: full` and `stall_after`. A wall is a hard cap that ends a working session at the minute it expires; `stall_after` ends a run that did nothing for an hour, and typing at the terminal counts as activity. There is no `cost_usd` (it needs a price table, and `no price table` is not printed unless a cost limit is set).
Expected, not a fault: `tego compile` (the line `demo.sh` runs first) prints `[mount]` for `/dev/pts/` and, for Codex, `[env-runtime-reserved]` (the run replaces `CODEX_HOME` with its own private one). `tego run` itself starts quiet: it prints before the agent starts only what needs you or what means this run enforces less than the contract says (for Codex that is `[env-runtime-reserved]` again, with its `fix:` line, and the answer line below); add `-v` (`tego run -v <contract>`) to see the compile notes there too. The ChatGPT contract (`contracts/codex-chatgpt.yaml`) also compiles with `[held-reads]` and `[wall-hard-cap]` (its `wall: 2h` ends an interactive session at the minute it expires; the long-session form uses `stall_after`). On AppArmor, `tego run` prints one more line before the answer line, not after it: held reads ignore a tighter profile, with its fix.
Show a refusal: ask the agent to read `~/.ssh/id_rsa` or run `curl example.com`; then `tego status --all` and `tego events <run> --kind refused` in a second terminal.
Without a login you can still show that both start under Tego: `./demo.sh claude --version`, `./demo.sh codex --version`.

### 5b: asking, stopping, and the dashboard while the agent runs

```
tego events <run> --rule deny-read-snapshot   # second terminal, after a refusal that says read-denied
tego-control serve --open                     # second terminal: prints the dashboard URL and opens it, signed in
```
- **The one answer line.** A contract that can ask (`fs.ask`, `ask:`) makes `tego run` print one line before the agent starts: `tego run: <run> can hold an operation for your approval; answer from another terminal: tego ask <run>, then tego approve <run> <ask_id> (or deny), or on the dashboard's Approvals page`. It carries the run id; it stays above the agent's screen after the agent takes over. Copy the id from it.
- **The desktop notice.** At tier `landlock`, as a normal user, with a root-owned `notify-send` on PATH (it is on a typical Linux desktop; `apt install libnotify-bin` elsewhere), a desktop notice appears for each held request: the agent, the operation and the run, never the target. Nothing is written into the agent's terminal. Over SSH, at the root tiers or with no notifier, use the answer line, `tego ask <run>` or the Approvals page. Answer within about 30 seconds: Codex gives up on a command that waits much longer (the ask itself times out after `ask.timeout`, 5 minutes).
- **Ctrl-Z and `fg`.** Ctrl-Z in Claude Code stops Claude Code and `tego run` together: the shell prints `Stopped` and gives the terminal back. `fg` resumes it with its screen; `bg` resumes it in the background. (A tier-2 run and a run already in the background do not follow the stop.)
- **The dashboard.** `./demo.sh dashboard` runs `tego-control serve --open` (the URL is printed too, for a machine with no browser opener). The header has an **Auto / Light / Dark** switch (Auto follows the system; the choice is kept in the browser). Every run carries a **kind** label, **Interactive**, **Deployed**, **Background** or **Unknown**, on Overview, Runs and the run page: the Claude Code and Codex runs say Interactive, the always-on service (no terminal, no deployment) says Background. A run ended with `tego stop` or the Stop button says **Stopped**.
- **One refusal that looks odd.** At tier `landlock`, a file made beside a protected file after the run started (for example a new entry in `$HOME` while `~/.ssh` is denied) is unreadable for the rest of the run. The ledger names it: `refused`, `read-denied`, rule `deny-read-snapshot` (`tego events <run> --rule deny-read-snapshot`). It is the rule working, not a fault; stop the run and start it again to list the directories anew.

### 5c: an agent that never stops

```
./demo.sh always-on            # a systemd --user service: tego run always-on.yaml, restarted if it dies
./demo.sh always-on status     # the unit, and its runs
./demo.sh always-on stop
```
Say: "A governed agent as a service. It does its work every few seconds and keeps trying a secret; every try is refused and recorded, run after run, on the same ledger, visible in the dashboard."
Known problem: runs are detached from any terminal, so there is nobody to answer an `fs.ask`; an unanswered ask is a refusal after `ask.timeout`.

## Tiers

```
./demo.sh tiers                # DEMO_SUDO=no prints the sudo command instead of running it
```
- Tier 1 `landlock`: no root. Landlock + the seccomp supervisor; the default on a laptop.
- Tier 2 `cgroup`: root. cgroup BPF + fanotify: every process of the run is in one cgroup, enforced by the kernel.
- Tier 3 `bpflsm`: root + `bpf` in the kernel's `lsm=` list: decisions in the kernel's LSM hooks.
Why three: each needs more of the machine and enforces more; `tego doctor` says which this machine has.
The scene: `tego doctor` (short), the guarded agent with `--tier landlock`, the same with `sudo ... --tier cgroup` (needs `make build`; the ledger goes to your own `~/.tego/runs`), then tier 3, or the one-time `lsm=...,bpf` steps (in `GRUB_CMDLINE_LINUX_DEFAULT`, the variable `tego doctor` names) when BPF LSM is off (printed, never run).
A tier whose sudo or tego refuses the run says so (`(tier 2 did not run: exit 1, see the message above)`, the exit
being the command's own, not the output filter's) and shows no damage report and no run of its own.

## Network

```
./demo.sh network
```
Say: "The contract names one destination. The agent reaches it; the next port over is refused, and so is
opening a listening port, a backdoor." What you see: `ALLOWED connect 127.0.0.1:<port>`, `REFUSED connect
127.0.0.1:<port+1>` (in the ledger as `net-not-allowed`), `REFUSED listen on 127.0.0.1:4444` (the contract's
`net.listen: []` names no listener, so the bind is in the ledger as `net-not-allowed` too; with `listen` left out
the kernel still refuses it at tier 1, but leaves no ledger line). `./demo.sh proxy` (capture of model calls through
Tego's proxy, and a call the proxy rejects) only prints its plan in this build.

## The feature scenes

Each is short: the stand-in agent (`agents/mini.sh`) without Tego where that is harmless, the scene's contract (written
to `stage/c/<scene>.yaml`, outside the project, so the agent cannot rewrite it), the run under Tego, then what the
ledger recorded. Say before them: "Five rule templates, each one line of a contract, each enforced by the kernel."
Where a scene's contract allows `python3` (`rule process`, `limits`, and `network`'s listener), it names the file
python3 runs as and the agent runs that, as in Act 2, so a pyenv or asdf shim on PATH does not stop the run.

- `./demo.sh rules` (or one at a time: `./demo.sh rule read|write|command|net|process`). Say: "What it may read, write,
  run and reach, and what kind of process it may become." Process type is not a contract word: the scene shows the
  process kinds tiers 1 and 2 refuse in every contract (new namespaces, fileless memfd programs), and says that the
  memfd refusal has no ledger line.
- `./demo.sh always`. Say: "Two rules no contract has to ask for. An agent that reaches the Docker socket is root on the
  host; one that reaches your ssh-agent signs as you. Both are refused. And no setuid program, sudo included, can raise
  its privileges." The sockets are stand-ins (`sockd.py`) in the stage, never your real ones. Where sudo needs a
  password even without Tego, the proof is `NoNewPrivs: 1`.
- `./demo.sh reason-hook`. Say: "The agent is told why, in the place a model reads." It builds the stand-in Claude Code
  (`test/e2e/reason-claude/fakeclaude`, so it needs `go` and this repo) and starts a local model stub (needs `openssl`
  and `python3`): no login, no model, no network. `modelsaw.py` prints what the model's next request carried, written
  by Tego's hook.
- `./demo.sh receipt` (the newest run's receipt), `./demo.sh presets`, `./demo.sh selftest`. The presets scene puts the
  fake secrets in the project's own `.env` (no-secrets is the built-in list, whose `.env` scan covers the project, not
  the stage's `secrets/`), adds the stand-in's four variables to `env.pass` where the generated file says to, and runs
  the rogue agent: the read, the send (the sink is not an allowed host), the profile, the hook and the delete are
  refused; `whoami` runs, since no preset limits programs.
- `./demo.sh ask`, then in a second terminal `./demo.sh approve` (or `./demo.sh deny`, or the dashboard's Approvals
  page). Say: "Some folders are a question, not a yes or no: the agent waits for you." Unanswered, it is a refusal after
  3 minutes. `approve` and `deny` answer only the ask scene's run, never another agent's ask.
- `./demo.sh limits`. Say: "A runaway agent cannot take the machine with it." The run's end (`pids`, `oom`) is its
  `run_end` line and `tego status`. The fork bomb is bounded at 500 anyway.
- `./demo.sh deny-write`. Say: "The whole repo is the agent's, except the hooks that would run outside any sandbox on
  your next commit." At tier landlock this is best effort and the run says so in its gaps.
- `./demo.sh identity`, `./demo.sh doctor`. Say: "Every run says who started it. And Tego tells you what this machine can
  enforce, without pretending." The root tiers need `sudo`; tier 3 also needs the BPF LSM on the kernel command line.

A 15-minute order: `setup`, `without`, `with`, `why` (4 min); `rules` (3); `always` (1); `reason-hook` (1); `presets`,
`receipt`, `selftest` (2); `ask` with `approve` in a second terminal (1); `limits`, `deny-write` (1); `dashboard` (2).

## Reset

```
./demo.sh reset                # stops the sink and the service, removes generated children of stage/
                               # (a DEMO_STAGE other than the default names its own unit, tego-demo-agent-<n>;
                               #  TEGO_DEMO_UNIT overrides: reset never stops a unit it did not start)
```

`setup` (also implicit in an act) claims a new or empty stage with a
`.tego-demo-stage` marker naming its physical path. Reset requires that marker
before stopping anything or deleting files. `/`, `$HOME`, the checkout, its
ancestors and the kit directory are refused, including aliases. Reset keeps the
stage, marker and unrelated siblings; the named generated children may be
regenerated, so keep personal files outside them. Old unmarked stages are
refused: move them aside manually or choose a fresh `DEMO_STAGE` and run setup.
These shell checks do not protect against a concurrent same-user process
replacing path components; [the script spec](../../docs/p0/demo-scripts.md)
states that limit.

## What the commands are

| Subcommand | Runs |
|---|---|
| `setup` | plants `stage/{secrets,home,project}`, starts `sink.py` |
| `without` | `sh rogue.sh` in the project, no Tego |
| `with` | `tego run agent.yaml` (a copy of `contracts/guarded.yaml`), then `tego events <run> --kind refused` |
| `why` | `tego events <run> --last`, `--verify`, then `--json` into a copy, one word changed with sed, and `--verify` on it |
| `dashboard [args]` | `tego-control serve --open` (extra arguments go to it: `--addr 127.0.0.1:8585` when 8484 is busy) |
| `claude`, `codex` | `tego compile` then `tego run contracts/<agent>.yaml` (extra arguments replace the interactive start) |
| `always-on` | `systemd-run --user ... tego run always-on.yaml`, in `stage/always-on/` (its own secrets and project, so the other acts never clear them) |
| `rules`, `rule <t>` | `tego run stage/c/<t>.yaml` with `sh mini.sh <t>`, then `tego events <run> --kind refused` |
| `always` | starts `sockd.py`, then the sockets and privesc tricks, without and under Tego |
| `reason-hook` | builds fakeclaude, starts the model stub, `tego run ... -- claude -p ...`, `modelsaw.py` |
| `receipt`, `presets`, `selftest` | `tego receipt --last`; `tego init --preset ...`, `tego compile`, `tego run`; `tego test` |
| `ask`, `approve`, `deny` | `tego run stage/c/ask.yaml`; `tego ask <run>` then `tego approve`/`tego deny <run> <ask_id>` |
| `limits`, `deny-write` | `tego run` of the fork, memory and hooks tricks; `tego events <run> --kind run_end`, `tego status <run>` |
| `identity`, `doctor`, `features` | `tego events <run> --kind run_start --json`; `tego doctor`; prints the feature map |
| `reset` | stops everything (the sink, the stand-in sockets, the model stub, the service), removes generated children of a marked stage |

`go test -tags integration ./examples/demo/` proves Acts 1 to 3, every feature scene that runs without root, a key or a
login (the Claude Code hook scene when `go` and `openssl` are installed), and compiles every contract, in isolation.
