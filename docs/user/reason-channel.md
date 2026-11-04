# Why was my agent refused? The reason channel

When Tego refuses something an agent does, the agent's system call fails: a file or exec refusal is `EACCES` or
`EPERM`, and a refused command commonly exits with status 126. The errno alone does not say that a contract
decided, so Tego also tells the agent why, in three ways.

## 1. The ledger

Every refusal is a `refused` line in the run's ledger, with its reason code and the rule. `tego events --last`
prints the last one. The ledger is the authoritative record; the two channels below are hints for the agent.

## 2. The reason file

Inside the run, `$TEGO_REASON` names `last-refusal.json`: the latest refusal, a count of every refusal of the run,
and the newest 32, each with its seq, reason code, rule and one sentence. Any harness or script in the run can read
it. It is written at most every 10 ms, so it may lag the refusal by that much.

**Reads Landlock refuses.** At tier landlock under `record: summary` or `off`, a read of a `deny_read` file (an
`~/.ssh` key, a `.env`) fails with `EACCES` and, by default, leaves no refusal here: the seccomp filter does not tell
tego of read opens, because doing so costs every open. `reason.reads: on` in the contract turns it on: every read open
is then told to the supervisor, and a refused one is one refusal here, `read-denied`, with `mechanism: landlock`. The
default, `reason.reads: auto`, is off because we measured it (ADR 0077): about 17 µs more per open, and the offline
Claude Code workload ran 19 % longer (more on a loaded box). `tego compile` prints `reason-reads-off` with these
figures, and `run_start.reads_notified` says whether a run's reads were told to tego and why. A run that holds its reads
(`fs.reads`, ADR 0069) or runs under `record: full` records such a refusal whatever this key says.

## 3. The Claude Code hook

`tego hook claude-code` is a Claude Code command hook. At
session start it tells Claude the run's facts (the contract is fixed, what a refusal looks like, where the reason
file is). After each tool call, after a batch of parallel calls, and when Claude would stop, it adds the refusals
Claude has not been told yet as a note beside the tool result, each refusal once, in sentences such as:

```
Tego, this run's access control, refused 1 action:
- Tego refused write "/home/user/out.txt": this run may not write to that path (rule fs.write).
```

With nothing new it adds nothing. A note at the end of a turn keeps Claude going once; when Claude would stop
again, the hook stays silent, and refusals that came meanwhile are told after the next tool call. It reads only the reason file and its own state (and the few files every Go program reads
at start), never your home or Tego's configuration, so it never causes a refusal of its own. Outside a Tego run it does nothing at all.

Tego installs the hook for you when the run's command is `claude` (or the contract says `harness: claude-code`). It
writes a settings file for this run only, in the run's runtime directory, and starts Claude Code as
`claude --settings <that file> ...`, followed by your own arguments. Your `~/.claude`, `CLAUDE_CONFIG_DIR` and the
project's `.claude/` are not touched, so the hook is gone when the run ends. If you pass your own `--settings`,
Tego merges it into that file: your keys and hooks stay, and Tego's hook is added after yours. Claude Code
rejects the whole file if one of your values is invalid (Claude Code 2.1.310 prints "These settings files did not
load"), and Tego's hook goes with it: the run still says the hook was provisioned, so check that message. Give it inline
(`--settings '{"model": "..."}'`) or as an absolute path. A path the contract's `deny_read` covers is refused before
the run starts (exit 125); pass it inline or set `harness: none`. When Tego runs as root it installs no hook at all
(the run has no runtime directory, and run_start says `reason-unavailable`), so claude gets your arguments, your own
`--settings` included, as you wrote them.

The settings file always sets `"disableAllHooks": false`. It outranks your user settings and the project's
`.claude/` files, so a `true` there (or one the agent writes during the run) cannot switch the hook off. It also means
your own hooks from those files run, even if you switched them off there. Your organization's managed settings still
win: if they turn hooks off, or allow only managed hooks, the hook does not run, though the run says it is
provisioned. The agent still has `$TEGO_REASON`, and the ledger still records every refusal.

Safe mode (`claude --safe-mode` or `CLAUDE_CODE_SAFE_MODE=1`, in the environment or in your own `--settings`
`env`) loads none of these hooks, and bare mode (`claude --bare` or `CLAUDE_CODE_SIMPLE=1`, in the same places)
runs no hook at all, so Tego refuses either run (exit 125); drop the flag and the variable, or set `harness: none`.
The settings file sets `CLAUDE_CODE_SAFE_MODE` and `CLAUDE_CODE_SIMPLE` to `"0"` in its `env`, so a project's
settings cannot switch either mode on during the run.

Give `--settings` before any `--` in the command. Claude Code reads a `--` that follows an option which takes a
value (`--model --`) as that value, so Tego cannot tell whether a `--settings`, `--safe-mode` or `--bare` after a
`--` is a flag or a prompt, and refuses the run (exit 125).

If your command is a wrapper script rather than `claude` itself, Tego leaves its arguments alone and sets
`TEGO_CLAUDE_SETTINGS` to the file's path; have the wrapper pass --settings "$TEGO_CLAUDE_SETTINGS" to claude. The
Agent SDK takes the same path as its settings.

A contract with an `exec: allow` list that does not name tego gets the hook all the same: the launcher grants the
hook's exact command line for that run and no other tego command, and `run_start` says so (`harness.hook` granted,
`exec.harness-hook[<tego binary>]` under `runtime_grants`; ADR 0064). Where that grant could be turned against the
run, such as a write or `fs.ask` entry over the tego binary, the hook is left out with a `harness-hook-refused`
warning and the agent still has `$TEGO_REASON`. The hook is also left out when the contract's own rules would refuse
the tego binary.

The hook also has a `--mode stderr`, for a hook you wire by hand: it prints the same text on stderr with exit 2,
which Claude Code shows to Claude after a tool call and at the end of a turn. Tego's own settings file always uses
the default, `--mode json`.


Built-in refusals name `builtin.host_ipc`, `builtin.tego_surface` or `builtin.other_tty` in the existing
`rule` field. An allow entry cannot override them. Read the [built-in refusals](built-in-refusals.md)
for the fixed exceptions and the datagram and kernel-only recording limits.
