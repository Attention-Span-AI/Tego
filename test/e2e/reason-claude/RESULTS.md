# Results: tego's reason channel through the real Claude Code

Captured 2026-10-25 on the development box (Linux 6.17, Landlock ABI 7, an ordinary user, no root, tier `landlock`)
with `test/e2e/reason-claude/run.sh a c d e f p h`: the real Claude Code **2.1.310** (`claude -p`, and once the
interactive interface through `test/poc/interactive-claude/drive.py`), tego built from this branch with
`-tags tegotesthooks`, the model `test/workloads/model-stub/server.py` behind tego's forwarder. No key but the dummy,
no network, no login. The real `~/.tego` was listed before and after: unchanged. This file went through
`scripts/scrub-capture.sh`. The CI twin (`fakeclaude/e2e_integration_test.go`) holds the stand-in to the same golden.

## What the model saw

Scenario h (the interactive session; its scripted turn is scenario a's), the request after the refused `Write`
(the stub's raw request after the model's last message; `|` is a newline). The tool result is Claude Code's own; the
next message, of role **system**, holds tego's hook notes, one per hook that had something new: PostToolUseFailure's
(two start-up reads of the account's `~/.claude`, which the contract denies, and the refused open) and PostToolBatch's
(the unlink of the temporary file, which landed after the first hook had read the reason file: R7).

```
0 user   tool_result  "EACCES: permission denied, open '$ROOT/outside/leak.txt.tmp.523693.787539c577e5'" is_error=True
1 system text         PostToolUseFailure:Write hook additional context: Tego, this run's access control, refused 3 actions:|- x2 Tego refused open "$HOME/.claude/rules": files under that path are not readable in this run (rule fs.deny_read[$HOME/.claude]).|- Tego refused open "/proc/self/fd/17/leak.txt.tmp.523693.787539c577e5": this run may not write to that path (rule unmatched).|||PostToolBatch hook additional context: Tego, this run's access control, refused 1 action:|- Tego refused unlink "/proc/self/fd/17/leak.txt.tmp.523693.787539c577e5": this run may not delete files at that path (rule unmatched).|||<total_tokens>14999980 tokens left</total_tokens>
```

## Findings

- **R1. Claude Code 2.1.310 sends a hook's `additionalContext` after a tool result as a message of role `system`**,
  `<Event>:<Tool> hook additional context: <text>`, after the user message that holds the tool results: one system
  message for all of a turn's hooks, each note followed by a blank line pair, then Claude Code's token counter.
  SessionStart's comes the same way after the first user message (with Claude Code's own environment section), and
  a Stop hook's as a `<system-reminder>` text in a user message. The stub logs `tail` (every message after the last
  assistant message, with its role), `report.py` counts a system message's notes one by one, and fakeclaude now
  sends them the same way, which the CI twin holds to the golden.
- **R2. Bare mode runs no hook at all.** `claude --help` (2.1.310): "--bare  Minimal mode: skip hooks (those defined
  in settings and by installed plugins ...)". Measured before the fix: with `--bare`, and with
  `CLAUDE_CODE_SIMPLE=1` in the contract's `env.set`, no exec of tego's hook and no tego text in any request, while
  run_start said `provisioned: true` (stderr mode). Neither json nor stderr mode reaches a bare session, so tego now
  refuses one with exit 125 before run_start, as it refuses safe mode (scenario f), and writes json mode only
  (ADR 0063 (3) and (8)).
- **R3. Claude Code's `Write` writes `<name>.tmp.<pid>.<12 hex>` through `/proc/self/fd/N/`** (an `O_PATH`
  descriptor of the target's directory) and unlinks it 0.4 ms after a refused open, so tego refuses and tells two
  actions under `/proc/self/fd/N/`, the open and the unlink, while the tool result names the real directory. The
  reason text is what the agent asked for, true to ADR 0016, but a model has to match the two by the file name.
  fakeclaude now writes the same way.
- **R4. A runtime directory under a directory tego denies the agent breaks the provision.** tego denies the agent
  its machine config's directory and its own state; the POC first put `XDG_RUNTIME_DIR` under it, and the CI twin
  first kept tego's chain anchor beside its runtime directory: Claude Code could not read the provisioned settings
  file (`Error processing settings: EACCES`) while run_start said `provisioned: true`. The harnesses keep it apart;
  tego does not yet refuse such a provision (open).
- **R5. The start-up reads.** Claude Code reads the passwd-database home's `~/.claude` (skills, CLAUDE.md,
  AGENTS.md, later rules/) whatever `HOME` says, and makes name lookups; under the contract each is refused and told
  to the model once, as the reason channel promises. `report.py` leaves the `~/.claude` ones out of its comparisons.
- **R6. The interactive run (h) passed once and failed once** at Claude Code's workspace-trust dialog in the first
  capture (the driver saw the dialog eight times and never the prompt box). run.sh's first-run record now marks the
  workspace trusted, and gives the driver the `claude` it was asked to run on its PATH; h passed in both runs since.
- **R7. A refusal reaches the reason file up to 10 ms after its system call** (the ledger's refusal window), so the
  hook that starts right after a call can miss it and a later one tells it: here PostToolUseFailure started 4 ms after
  the unlink and told only the open, PostToolBatch 13 ms after and told the unlink, in the same request. A refusal in
  the last 10 ms before a turn's last hook is told one request later, still once (open).
  fakeclaude starts PostToolBatch 50 ms after a turn's last call, so the twin does not depend on that margin.
- **R8. The project cannot turn the hook off.** Scenario p: the workspace's `.claude/settings.json` sets
  `disableAllHooks: true`, `CLAUDE_CODE_SIMPLE` and `CLAUDE_CODE_SAFE_MODE` to `"1"`; the real binary read it (the
  ledger shows the opens) and tego's hook still ran and told the refusal. That is the outcome; the run does not show
  which mechanism gives it (the provisioned file's `disableAllHooks: false`, its `"0"` values, or Claude Code not
  taking either variable from a settings env block).
- **R9. One invalid value of the user's drops tego's hook too.** Scenario v (run after the capture below, alone):
  the command's own `--settings '{"cleanupPeriodDays": "soon"}'`, which tego merges as given, makes Claude Code
  print "These settings files did not load, so nothing in them is in effect, including hooks and permission rules"
  for the merged file; no hook runs and no refusal reaches the model, while run_start says `provisioned: true`, as
  under a managed policy that turns hooks off. The kernel boundary is unchanged and the agent keeps `$TEGO_REASON`;
  a run's own account of whether its hook ran is open.

```
==== v. scenario a, the command's own --settings holding an invalid value
PASS  tego run of claude -p exited 0 (scenario v)
PASS  Claude Code says the merged settings file did not load (one invalid value of the user's drops it all)
PASS  ... so no hook ran and no refusal reached the model (KNOWN, R9: the run still says provisioned)
```

## The output of `run.sh` (all scenarios, comparing with the golden)

```

==== Claude Code
version: 2.1.310 (Claude Code)
tego: tego=v0.0.0-20261025103557-0d0638868200+dirty

==== a. claude -p, scenario a
PASS  tego run of claude -p exited 0 (scenario a)
PASS  the run left a ledger ($ROOT/state/runs/r-3f9c2a1b-0dmdv0jj0pxr9-pqfxvt/events.jsonl)
PASS  scenario a: the stub answered every request with 200 (3 requests, 0 refused)
PASS  one request carries turn 1's results (turn 2 requests: 1)
PASS  the ledger has a open refused write-outside-contract
PASS  the next request carries the write-outside-contract refusal of open /proc/self/fd/@FD@/leak.txt.tmp.@TMP@
PASS  ... with its rule (unmatched)
PASS  ... and no later request repeats it (seq 1001)
PASS  no refusal line is told twice in the run (26 told)
PASS  the next request, normalised, equals next-request.golden[a]

==== c. claude -p, scenario c
PASS  tego run of claude -p exited 0 (scenario c)
PASS  the run left a ledger ($ROOT/state/runs/r-3f9c2a1b-0dmdv0jz29jvr-y0wy8q/events.jsonl)
PASS  scenario c: the stub answered every request with 200 (3 requests, 0 refused)
PASS  one request carries turn 1's results (turn 2 requests: 1)
PASS  the ledger has a exec refused exec-not-allowed
PASS  the next request carries the exec-not-allowed refusal of exec @W@/bin/git
PASS  ... with its rule (exec.deny[git push])
PASS  ... and no later request repeats it (seq 1407)
PASS  no refusal line is told twice in the run (25 told)
PASS  the next request, normalised, equals next-request.golden[c]

==== d. claude -p, scenario d
PASS  tego run of claude -p exited 0 (scenario d)
PASS  the run left a ledger ($ROOT/state/runs/r-3f9c2a1b-0dmdv0kgwpj3p-kaabby/events.jsonl)
PASS  scenario d: the stub answered every request with 200 (5 requests, 0 refused)
PASS  one request carries turn 1's results (turn 2 requests: 1)
PASS  the ledger has a open refused write-outside-contract
PASS  the next request carries the write-outside-contract refusal of open /proc/self/fd/@FD@/leak.txt.tmp.@TMP@
PASS  ... with its rule (unmatched)
PASS  ... and no later request repeats it (seq 1003)
PASS  the ledger has a exec refused exec-not-allowed
PASS  the next request carries the exec-not-allowed refusal of exec @W@/bin/git
PASS  ... with its rule (exec.deny[git push])
PASS  ... and no later request repeats it (seq 1502)
PASS  no refusal line is told twice in the run (27 told)
PASS  the next request, normalised, equals next-request.golden[d]

==== e. claude -p, scenario e
PASS  tego run of claude -p exited 0 (scenario e)
PASS  the run left a ledger ($ROOT/state/runs/r-3f9c2a1b-0dmdv0l1ualaj-2m3m7p/events.jsonl)
PASS  scenario e: the stub answered every request with 200 (4 requests, 0 refused)
PASS  one request carries turn 1's results (turn 2 requests: 1)
PASS  the next request carries no tego text (0 refusal lines)
NOTE  it carries 1 refusal(s) of the account's own agent configuration (isolation)
PASS  no refusal line is told twice in the run (24 told)
PASS  the next request, normalised, equals next-request.golden[e]

==== f. scenario c, bare (--bare)
PASS  tego refused the bare run with exit 125 (--bare; exit 125)
PASS  ... saying what to do instead
PASS  ... before run_start: no ledger, no request reached the model

==== f. scenario c, bare (CLAUDE_CODE_SIMPLE: "1")
PASS  tego refused the bare run with exit 125 (CLAUDE_CODE_SIMPLE: "1"; exit 125)
PASS  ... saying what to do instead
PASS  ... before run_start: no ledger, no request reached the model

==== p. scenario a, the project's settings turning the hook off
PASS  tego run of claude -p exited 0 (scenario p)
PASS  the run left a ledger ($ROOT/state/runs/r-3f9c2a1b-0dmdv0lra48oc-y6rdg4/events.jsonl)
PASS  scenario a: the stub answered every request with 200 (3 requests, 0 refused)
PASS  one request carries turn 1's results (turn 2 requests: 1)
PASS  the ledger has a open refused write-outside-contract
PASS  the next request carries the write-outside-contract refusal of open /proc/self/fd/@FD@/leak.txt.tmp.@TMP@
PASS  ... with its rule (unmatched)
PASS  ... and no later request repeats it (seq 1008)
PASS  no refusal line is told twice in the run (26 told)

==== h. one interactive session (drive.py reason)
PASS  Claude Code reaches its prompt box with a dummy key and no login screen
PASS  part 1 ended: the stand-in's three tool calls were each tried
PASS  write inside the workspace: work/note.txt exists
PASS  write outside the workspace: outside/leak.txt does not exist
PASS  the driver's own checks
PASS  the run left a ledger ($ROOT/state/runs/r-3f9c2a1b-0dmdv0m96h8q3-kpwsss/events.jsonl)
PASS  scenario a: the stub answered every request with 200 (5 requests, 0 refused)
PASS  one request carries turn 1's results (turn 2 requests: 1)
PASS  the ledger has a open refused write-outside-contract
PASS  the next request carries the write-outside-contract refusal of open /proc/self/fd/@FD@/leak.txt.tmp.@TMP@
PASS  ... with its rule (unmatched)
PASS  ... and no later request repeats it (seq 9484)
PASS  no refusal line is told twice in the run (28 told)
PASS  the real ~/.tego is unchanged (listing before and after)
directory: $ROOT
```
