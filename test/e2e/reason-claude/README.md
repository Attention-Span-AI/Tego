# reason-claude: a stand-in Claude Code for harness tests

`fakeclaude/` is a small Go program (standard library only) that plays the harness side of Claude Code's public,
documented protocol, so that anything that sits beside Claude Code (the reason-channel hook, a settings file, a
launcher that adds `--settings`) can be tested without a model, a key, a login or the real binary. It is test
infrastructure (Layer 3): it lives under `test/`, never reaches a product binary, and is not a mock of Tego.

It is dated against the Claude Code **2.1.310** documentation (hooks reference, CLI reference, headless page, read on
2026-10-24). A rule that changes in a later release is changed in `fakeclaude/` with its golden under
`fakeclaude/testdata/cc-2.1.310/`.

## What it does

```
fakeclaude [--settings FILE|JSON] [--bare] [--script FILE] [--result FILE] [--cwd DIR] [--session-id ID]
           [--model NAME] [-p] [prompt]
```

- **Settings.** `--settings` takes a path or inline JSON as one whole argv element (`--settings=X` too; the last one
  wins). An empty value is an error (exit 1), never "no settings": a launcher that expands an unset variable into
  `--settings` must not get a run without hooks; the same holds for an empty `--script`, `--result`, `--cwd`,
  `--session-id`, `--model` or `--spill-dir` (exit 2). A path must be a regular file of at most 2 MiB: a directory, FIFO,
  device or a larger file is refused before it is read, as the CLI reference says (the file is opened without
  blocking and judged from the descriptor, so a name swapped for a FIFO cannot hang the run; `--script` is read the
  same way). Only `hooks` and `disableAllHooks` are read. A hook it cannot run faithfully
  (a type other than `command`, an `if` filter, `asyncRewake`, `onFailure`, a PowerShell shell) is an error, not a
  skip. Hooks for events it never fires (PreToolUse and the rest) are accepted and reported on stderr.
- **Bare mode.** `--bare` or `CLAUDE_CODE_SIMPLE=1`. No hook runs, those of `--settings` included, as Claude Code
  2.1.310 does ("Minimal mode: skip hooks"; measured, `RESULTS.md` R2); the settings are still read and checked.
- **A script** (`script*.json`) is a prompt and a list of turns; a turn is one assistant message's tool calls, some
  of them parallel. A call is `write` (the Write tool as 2.1.310 does it, `RESULTS.md` R3: the directory opened
  `O_PATH`, `<name>.tmp.<pid>.<12 hex>` created through `/proc/self/fd/<that descriptor>/` and renamed over the
  target, and unlinked through the same path at once when that fails, so a contract sees the open, the rename or the
  unlink there while the error names the real directory; `inplace` writes the path itself), `read`, `run` (an argv
  exec'd directly), `bash` (a command line for `/bin/bash -c`, its output and error on one pipe in the order they were
  written, as the real binary shows them) or `connect` (`host:port`; a TCP connect(2) reported as a tool named `Connect`, which
  stands for a `curl` or `nc` and is not a Claude Code tool). Each call is performed by fakeclaude itself with real
  system calls; a failure is reported the way Node reports it (`EACCES: permission denied, open '/path'`, `Exit code 3`).
  `read` refuses a directory (`EISDIR`), a FIFO or a device, and a file over 1 MiB, rather than blocking or growing.
  If the model stub asks for more tool calls than the script has turns, that request is recorded
  `agrees_with_script: false`, which `report.py check --result` fails; so is a tool call the model asks for in reply
  to a Stop hook's continuation, which the script has no turn left to run.
- **Hooks.** SessionStart once (`source: startup`); after each call PostToolUse, or PostToolUseFailure when it failed
  (concurrently for the calls of a parallel turn); PostToolBatch after the turn; Stop at the end, repeated with
  `stop_hook_active: true` after a continuation. Each configured hook runs in exec form (`args` set: spawned directly,
  no shell) or shell form (`bash -c`), with the documented payload on stdin, the agent's environment plus
  `CLAUDE_PROJECT_DIR`, its own session and no terminal, and the hook's `timeout` (default 600 s, the documented
  default for command hooks, so that the behaviour is Claude
  Code's; every stand-in hook the tests register sets `timeout: 10`, and a hook that hangs without a `timeout` stalls
  a run for ten minutes, as it would in Claude Code; a timeout is a non-blocking error). Identical commands for one event run once.
  Results follow the documented exit-code table: exit
  0 reads stdout as JSON only when it is one object (SessionStart's plain stdout is context); exit 2 shows stderr to
  Claude for PostToolUse and PostToolUseFailure, ends the loop for PostToolBatch, blocks the stop for Stop, and goes to
  the user for SessionStart (stdout JSON is then ignored); any other code is a non-blocking error shown to the user.
  Two corners are not modeled the documented way, and the end-to-end run can settle the real behaviour: an exit other
  than 0 and 2 is always a non-blocking error here, although the exit-code table says that a valid JSON object with
  "any other exit code" is a success whose fields decide; and exit-0 stdout that starts with `{` but is not one valid
  JSON object is treated as plain stdout (SessionStart's is context), although the reference calls unparseable JSON
  a non-blocking error.
  `continue: false` "stops processing entirely" and takes precedence over the event's other fields: from SessionStart
  it ends the session before the first request (no tool call, `ended: stopped_by_hook`; the reference does not say
  that SessionStart honours it, this is the reading of the universal field); from PostToolUse or PostToolUseFailure
  it stops the turn there (a sequential turn's later calls are not performed, they are listed `skipped`; in a parallel
  turn all calls are already running; PostToolBatch does not fire); from Stop it ends the run.
  `decision: block` and `additionalContext` are handled per event; context over 10,000 characters
  is written to a file and replaced by its path and a 2,000-character preview. After eight continuations in a row
  Stop no longer continues the turn (`CLAUDE_CODE_STOP_HOOK_BLOCK_CAP`, a positive integer, raises or lowers the eight).
- **Requests.** Request 0 carries the prompt and SessionStart's context; request k+1 carries turn k's tool results in
  call order and the hooks' feedback as plain text, then, as 2.1.310 sends it (`RESULTS.md` R1), one message of role
  `system` holding every note of the turn (`<event>:<tool> hook additional context: <text>`, `SessionStart` without a
  tool, PostToolBatch's last); a Stop hook's context comes as a `<system-reminder>` block in a new user message.
  PostToolBatch's hooks start 50 ms after the turn's last call: the real binary's started 13 ms after it, and a
  refusal reaches tego's reason file up to 10 ms after its system call (`RESULTS.md` R7). Requests go to
  `ANTHROPIC_BASE_URL` (`/v1/messages`, non-streaming) and only there: an unset URL, or a host that is not loopback, is
  refused, and a redirect is a failed request that is never followed (Go would resend the body and `x-api-key` to the
  target), so no run can reach a real model. `SSL_CERT_FILE` is honoured, which is how the HTTPS stub is trusted.
- **Result.** `--result FILE` receives a JSON summary (requests, turns with their tool_use ids, hook runs, dropped
  context, how the run ended) that `report.py` reads. A run a hook ended (`ended: stopped_by_hook`) is checked too: `report.py check --result` accepts the absence of the request that would have carried the last turn's results (and of any request when SessionStart ended it), and of no other. The final model text goes to stdout, as `claude -p` prints it.

## What it does not model

No model: it does not decide anything; the script does, and the stub's reply is read for its tool_use ids and checked
against the script (`agrees_with_script`). No permission prompts or permission modes (`permission_mode` is `default`).
No MCP, no subagents, no skills, no CLAUDE.md, no auto-discovered settings (user, project and local files are never
read; `~/.claude` and `CLAUDE_CONFIG_DIR` are not touched, the transcript path is named in payloads and never
created), no PreToolUse, no streaming, no compaction, no resume. The wording around hook text (the reminder header,
`... hook blocking error from command: ...`) is not documented by Claude Code; `report.py` matches the hook's own
text and never the wording. The `Read` tool's structured `tool_response` is the SDK's shape, which the hooks reference
does not show; a golden holds it, and the end-to-end run is where the real binary confirms or corrects it.

## Files

| File | What |
|---|---|
| `fakeclaude/` | the program and its tests; `go test ./test/e2e/reason-claude/fakeclaude/` (unit), `-tags integration` (with the model stub, needs `python3`) |
| `script.json`, `script-parallel.json`, `script-bare.json` | fakeclaude scripts: sequential with a failing call, a parallel batch, a bare session |
| `stub-script.json`, `stub-script-parallel.json`, `stub-script-bare.json` | the same three scenarios as the model stub's `--script` (`@W@` is the working directory). The real Claude Code is driven by these; fakeclaude is driven by its own and checks that the stub's replies name the same tools |
| `report.py` | reads the stub's `--log-content` log (and fakeclaude's `--result`): every tool result delivered once and in order with the right `is_error`, exact counts of reminders and feedback, no reminders when bare, and the request shape |
| `test_report.py` | report.py's tests: `python3 -I -m unittest` in this directory |
| `golden/shape*.json` | the request shape each scenario must produce, whoever the harness is |
| `golden/hooks*.json` | the hook settings each shape golden was made with (the stand-in's command is `@HOOK@`) |

## Held to the real binary through a shared golden

`golden/shape*.json` is the contract between this stand-in and Claude Code: per request, the stub's turn number, the
`is_error` flag of each tool result, and how many hook-written reminders and feedback blocks arrived (blocks that
contain a marker the hook writes). `report.py shape` makes it from any stub log, ids and wording left out. The
integration test checks fakeclaude against it.

The counts depend on the hooks that wrote them, so each shape golden has its hook set beside it,
`golden/hooks<suffix>.json` (an integration test keeps the two in step). The end-to-end run runs the real `claude` against
the same stub scripts with **those hook settings** (`--settings` the file, `@HOOK@` replaced by the test binary that
`go test -c ./test/e2e/reason-claude/fakeclaude` builds, which serves the `__hook__` modes) and marker `stand-in hook:`,
and checks `report.py check ... --shape golden/shape.json --marker 'stand-in hook:'`. That compares Claude Code's
request shape with the stand-in's; Tego's own hook, which registers another event set, is held to its own expected
counts there, not to this golden. Where the real binary differs, the golden is wrong about Claude Code and gets fixed
here, with the finding.

```
python3 test/workloads/model-stub/server.py --cert C --key K --ready R --script S --log L --log-content
fakeclaude --script script.json --settings settings.json --result R.json     # ANTHROPIC_BASE_URL, SSL_CERT_FILE set
python3 -I report.py check L --result R.json --marker 'stand-in hook:' --shape golden/shape.json
```

## End to end: tego's reason channel through the real Claude Code

`run.sh` runs the real `claude -p` (version printed; no `claude` prints a `SKIP` line and exits 77, which
`make e2e-reason` passes on) under `tego run` at tier `landlock` with `contract.yaml`: no network but tego's
forwarder, an obvious dummy key, and the model stub behind the forwarder with `--log-content`. It is local, not CI:
it needs the binary. `report.py e2e` reads the stub's log and the run's ledger and prints PASS or FAIL per check.
The model never sees a reason code: the hook's text tells each refusal as its operation, target, the code's sentence
("this run may not write to that path") and rule, so a check finds the ledger's refusal by its operation, target and
rule, and the golden holds the whole line.

| Scenario | The scripted turn (`testdata/stub-<s>.json`) | Checked in the request after it |
|---|---|---|
| a | `Write` outside the workspace | the ledger's `write-outside-contract` refusal: its target and rule, told once |
| c | `Bash` `git push` (`exec.deny: [git push]`) | the `exec-not-allowed` refusal and its rule |
| d | both, as one turn's two `tool_use` blocks | both refusals, and no later request repeats either |
| e | an allowed `Write` | no tego text: no line holding `Tego refused ` whatever its bullet, no `N more not listed.` and no heading alone, in a hook note or anywhere else |
| f | c with `--bare`, and with `CLAUDE_CODE_SIMPLE=1` | bare mode runs no hook (R2), so tego refuses the run: exit 125 before run_start, no request |
| p | a, the project's `.claude/settings.json` setting `disableAllHooks` and both mode variables | tego's hook still runs (R8, the outcome only): the checks of a |
| v | a, the command's own `--settings` holding a value Claude Code rejects | the known behaviour (R9): Claude Code drops the merged file, tego's hook with it |
| h | one interactive session (`test/poc/interactive-claude/drive.py <root> reason`) | the checks of a |

Every scenario starts with a warm-up `Write` inside the workspace (turn 0): the request after it carries what Claude
Code's start-up made tego refuse. The real binary reads the passwd-database home's `~/.claude` whatever `HOME` says;
the contract denies those reads (the account's configuration is neither seen nor changed), and their refusals are real
and told to the model, so `report.py` leaves them out of every comparison (`--isolation`) and notes them. The next
request of a, c, d and e, normalised (the scratch paths, a temporary file's suffix, a descriptor number and Claude
Code's token counter masked; the notes' channels, not their labels or number, since which hook tells a refusal
depends on when it lands), must equal `testdata/next-request.golden`. The real binary writes the golden
(`WRITE_GOLDEN=1 run.sh a c d e`). The CI twin, `fakeclaude/e2e_integration_test.go`
(TestReasonEndToEndThroughTheStandIn, `-tags integration`, every CI run), runs a, c, d and e with the stand-in built as
`claude` (scripts `testdata/fakeclaude-<s>.json`) under the same contract and stub scripts, and holds it to the same
checks and the same golden, so that drift between the stand-in and the real binary shows; it also finds every
refusal of the run in the next request as `reason.Text` renders the ledger line.
`RESULTS.md` is a run's output, passed through `scripts/scrub-capture.sh`, which exits 1 when the home, the user name
or the host name is still in it anywhere (in any case, inside a longer word too).
