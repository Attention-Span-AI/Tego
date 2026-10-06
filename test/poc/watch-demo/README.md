# tego watch: a safe demonstration

One stand-in agent (`agent.sh`, a script that behaves like any agent: it reads, writes, runs a program, connects,
and writes where a person must say yes) run four ways. Tego never knows what it is; it is a black box.

```
test/poc/watch-demo/run.sh        # builds an isolated tego, runs A to D, prints what happened
```

It needs `go`, `python3`, and a Linux kernel with Landlock (the box this was written on has ABI 7). It needs no root.
Everything happens under `$DEMO_ROOT` (a temporary directory by default): its own machine config, ledger, chain
anchor and log, redirected with the `tegotesthooks` build, so your real `~/.tego` is never read or written. The agent
touches only its own scratch workspace and one throwaway listener on 127.0.0.1; its `git` is a stand-in script.

| Run | What it shows |
|---|---|
| **A** `tego watch -- bash agent.sh` | No boundary: everything is allowed and **recorded**: the credential read, the `git push`, the connection. A recording is not a cage, and the command says so first. |
| **B** `tego watch --boundary boundary.yaml -- bash agent.sh` | The same agent held to a boundary, with a person answering: the credential read, the `git push` and the connection are **denied**, each with the rule that refused it. The write under `held/` **pauses the agent** until the person runs `tego approve --always`; the same write again goes through at once, recorded as `standing:<ask id>`. The other file is answered `tego deny --always`, and its retry is refused at once. |
| **C** the same boundary, nobody answering | The held write waits `ask.timeout` (5 s here, at most 1 h) and is then **refused** (`ask-timeout`): nobody answering is never a yes. |
| **D** `tego watch -- bash -i` on a pseudo-terminal | An interactive program works: a real terminal, its size, Ctrl-C stopping the command and not the shell, the exit status. |

## Try the approvals by hand

`run.sh` plays the person for you. To be the person: run B's command in one terminal, and in a second:

```
source $DEMO_ROOT/tego/env.sh        # run.sh prints the exact path
tego ask <run>                       # the held write, with its ask id
tego approve <run> <ask_id>          # let this one through
tego approve <run> <ask_id> --always # ... and every later identical request in this run
tego deny <run> <ask_id> --always    # refuse it, and its retries
```

## What this does not show

This runs at tier 1 (Landlock and the seccomp supervisor), as an ordinary user. The root tiers add kernel-side
decisions that cannot be raced, and are tested separately in the VM suites. Reads of an allowed file are recorded
(`record: full`), at a cost for every open; use `--record summary` to cut it. Approval is for file writes and for TCP,
UDP and Unix-socket connections; a contract cannot ask before running a program: that is refused today.
