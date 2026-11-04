# The real interactive Claude Code under an enforcing contract, fully offline

The real full-screen Claude Code (`claude`, 2.1.290), typed into on a pseudo-terminal, held to an enforcing contract at
tier `landlock` (no root), with every model request answered by a local stand-in and no credential on the machine. It
shows tool use, refusals, a human approval that holds the session, and the same approval answered at once the second
time. Nothing is sent to an Anthropic address: the ledger is read back to prove it.

```
test/poc/interactive-claude/run.sh            # P1 P1b P2 probes, then S the session; about 3 minutes
test/poc/interactive-claude/run.sh session    # just the session
test/poc/interactive-claude/run.sh negative   # the session three times, a rule removed each time: checks must FAIL
```

It needs `claude` on `PATH` (or `CLAUDE=<path>`), `go`, `python3`, `openssl`, `jq`, and a kernel with Landlock (the box
this was written on has ABI 7). No root. All durable files stay under `$ROOT` (a temporary directory by default; `ROOT=<dir>`
keeps it): tego's own machine config, ledger, chain anchor and log (the `tegotesthooks` build redirects them), an
isolated `HOME`, the agent's workspace, the stand-in and its certificate. `~/.tego` is listed before and after, and the
contract denies the agent `~/.claude`, `~/.claude.json`, `~/.codex`, `~/.config/anthropic` and `~/.tego` (Claude Code
reads the passwd-database home's `~/.claude/skills` whatever `HOME` says). The scripts never read those paths. Session sockets use `%R`, Tego's private per-run harness runtime inside a short mode-0700 temporary base beneath `/run/user/<uid>` (removed at script exit); launch validates the complete seven-digit-PID socket path against 103 bytes. The shared `/tmp` fallback stays ungranted. The captured 2.1.290 model/tool results below are historical; C40 Round 3 revalidated 2.1.318 socket initialization without login, not real model/tool execution.

## The parts

| File | What it is |
|---|---|
| `claude-interactive-offline.yaml` | The contract, as a template: every entry carries a comment saying what it is for. `run.sh` fills in the stand-in's port, the scratch root and the real home's agent-config paths that exist, and tego loads and compiles the result (`tego compile` is printed). |
| `stub-script.json` | What the stand-in's "model" says, turn by turn: the tool calls Claude Code is told to make (`Write` inside the workspace, `Write` outside it, `Bash` `git push`, `Write` into the held directory, `Bash` appends to a file in it, twice). The stand-in is `test/workloads/model-stub/server.py`, the one kill test 7 uses. |
| `git` | A harmless stand-in `git` on the agent's `PATH`. It is never started under the contract. |
| `ptyscreen.py` | A pseudo-terminal session and a small terminal emulator, so the driver reads what is on the screen, not the byte stream. |
| `drive.py` | The person at the keyboard: starts `tego watch --boundary ... -- claude --permission-mode default`, gets past the first-run dialogs, types prompts, answers Claude Code's own permission questions, and, from separate `tego` processes, answers tego's approvals (`tego ask`, `tego approve [--always]`). |
| `report.py` | Reads the run's ledger back and checks every claim against ledger events; trusts nothing the driver printed. |
| `run.sh` | Builds an isolated tego, starts the stand-in, lays the scratch out, runs the probes and the session, prints the checks. |

## How the model never leaves the box

The contract has `models: [{host: 127.0.0.1, port: <stand-in>}]` and `capture: forwarder`. Tego starts a plaintext
listener on 127.0.0.1 for that entry and puts its address in the agent's `ANTHROPIC_BASE_URL`; the listener speaks TLS
to the stand-in, trusting its self-made certificate through `SSL_CERT_FILE` in tego's own environment (the agent is
not given it). Every request is recorded as `ssl_request source=forwarder`. `net.allow` has only the name-service
socket, so a direct connection around the forwarder is refused, and `net.dns.mode: off` removes the machine resolver
as well, so no name lookup leaves either.

## What a person has to know to run Claude Code this way

- **The first-run record.** With a dummy `ANTHROPIC_API_KEY` and a fresh `CLAUDE_CONFIG_DIR`, Claude Code's first act is
  a connectivity check that goes straight to `api.anthropic.com:443` and ignores `ANTHROPIC_BASE_URL`. Refused, it
  prints "Unable to connect to Anthropic services" and exits 1; the key does not skip it, and nothing in a contract can
  make it succeed offline. Writing `{"hasCompletedOnboarding": true}` into `CLAUDE_CONFIG_DIR/.claude.json` (a flag,
  no credential) skips it, and then no Anthropic address is tried at all. `run.sh` writes it; P1 and P1b show the
  failure without it.
- **The key.** With the first-run record and no key, the prompt box appears and the first prompt answers "Not logged in".
  A dummy key is enough, since the stand-in does not look at it. Claude Code asks once whether to use it; the driver
  answers Yes.
- **`--permission-mode default`.** Claude Code 2.1.290 defaults to "auto mode", which sends each tool call to a
  classifier model call. `default` makes its own permission questions appear (the driver says yes to each: the contract
  is the boundary; Claude Code's own prompts are its own) and keeps the model traffic to the conversation.
- **What is refused and tolerated.** Claude Code starts dozens of programs it does not need (`git`, `zsh` probes,
  `cat`, `dpkg`, `ssh`) and reads the real home's skills; each is refused and recorded, and the session carries on.

## What the session does

| Step | Claude Code | The contract | Where it shows |
|---|---|---|---|
| 1 | `Write work/note.txt` | `fs.write: ./work/`: allowed | the file exists; ledger `fs allow` |
| 2 | `Write <outside>/leak.txt` | not writable: `write-outside-contract` | Claude's UI: `EACCES`; the file does not exist; ledger `refused` |
| 3 | `Bash git push origin main` | `exec.allow: [bash]`: `exec-not-allowed` | Claude's UI: Permission denied, `git exit=126`; ledger `exec refused` |
| 4 | `Write held/report.txt` | `fs.ask: ./held/`: held until `tego approve` | the screen sits on a spinner; `tego ask` lists it; then **the rename is refused** |
| 5 | `Bash echo first >> held/journal.txt` | held; a person runs `tego approve --always` | ledger `ask`, `answer ... always` |
| 6 | the same append again | answered at once by the standing answer | ledger `ask` and `answer by standing:<id>` in the same instant |

## Not in scope

Tego governs the agent session only: the processes the operator chose to govern and their descendants. This does not
hide from or resist root, and says nothing about the rest of the host. The contract is tier `landlock`; the root tiers
are not run here. The one step that cannot be done offline, a real login or a real model, is not done here.
