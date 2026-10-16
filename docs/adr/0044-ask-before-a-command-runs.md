# ADR 0044: ask before a command runs: hold the exec, let the kernel build it, and run it only when the kernel's own facts are the ones a person approved

Status: **accepted 2026-10-16**; design only, not built: the work packages are in [docs/p0/exec-ask-plan.md](../p0/exec-ask-plan.md), and WP0's evidence gates the rest.

Supersedes, before either was accepted, the 2026-10-05 draft of this number (exec approval at the plane tiers by
refuse-and-retry under a kernel claim) and the POC draft numbered 0056; [ADR 0056](0056-exec-approval-poc-draft.md) is now only a pointer here. Amends in part ADR
0007, 0008, 0016, 0019, 0041, 0048 and 0054, each of which carries an "Amended in part by ADR 0044" line under its
Status line ((13) says what changes in each).

ADR 0048 names 0044 as the decision that may give `exec.ask` entries a completion, and
says such a decision "must state how the claim composes with the refused list floor and restate 0044's security
argument". (4) and the Security argument do both.

Evidence: probes run 2026-10-06 on Linux 6.17 (Landlock ABI 7, Yama `ptrace_scope` 1, unprivileged), and on the real
Claude Code 2.1.290. The measurements are stated here; the probes themselves are not published. What was not run is listed in "Evidence not yet run" and is WP0
of the plan; the decision is accepted now, WP0 gates only the trace-gate's construction, and that section says
what the decision already fixes if WP0 fails.

## Context

### The request

While an agent runs, if it tries to run a program or a command the contract does not already
allow, Tego should pause the agent and ask a person (allow once, always allow, deny, deny always, wait), and refuse
when nobody answers before the ask timeout, as it already does for file writes (`fs.ask`) and TCP connects
(`net.ask`). FEATURES W8 tracks it.

### What exists

- **Approvals are completed by the supervisor, never by `CONTINUE` (ADR 0008).** A held write-open is completed by
  the supervisor's own open and `SECCOMP_IOCTL_NOTIF_ADDFD|SECCOMP_ADDFD_FLAG_SEND`; a held connect is performed on a
  `pidfd_getfd` duplicate, and at the root tiers one exact socket-cookie credit is consumed by the connect hook.
  SEMANTICS §6: "No ask path uses `CONTINUE`."
- **ADR 0041** puts every rule, action and tier cell in one of three outcomes: (A) completed race-free in the run's
  own kernel context, (R) refused, (D) disclosed best effort. Its context table says "exec: argv — no [race-free
  completion], at any tier: the kernel re-reads argv after any decision", and the gate's `exec matches` ask range is
  (R), an unsupported-completion refusal, at every tier.
- **ADR 0048 (exec command rules; P1 built, P2 partly built)** adds command patterns to `exec.allow`, `exec.deny` and
  `exec.ask`, one argv matcher (`pkg/policy/execmatch`) and the precedence: image floor, then deny, then ask, then
  unlisted under a constrained tool, then allow, then the gate. `exec.ask` is reserved: parsed, and every match refused
  at every tier with `completion_unsupported: true`; an ask entry grants no image and constrains no tool. P1 decides on
  copied facts, so an allow is the disclosed cell `exec.rules/argv`. P2 would have the supervisor write a per-exec pin
  that the plane checks at `bprm_check` (image identity, names, `#!` chain) and at `sched_process_exec` (a keyed MAC of
  the kernel's own argv; SIGKILL before the first user instruction on a mismatch).
- **Standing answers (ADR 0054)**: `approve|deny --always` stand for the rest of the run for the exact
  `(op, rule, target)` of an `open` or `connect` hold, take effect only once the person's answer line is recorded, and
  every automatic answer is its own `ask` and `answer` pair, `by: standing:<ask_id>`. At most 256 per run.
- **The broker** (`internal/runtime/ask`) knows the holds `open`, `connect`, `first_write` and `request`;
  `ask.max_pending` is 1 to 64 (default 64), `ask.timeout` defaults to 5 minutes and is at most 1 hour, and a held ask
  polls `ID_VALID` every 50 ms and closes `ask-unavailable` when the notification is withdrawn.
- **The run's filter** is installed with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.19+), already returns `ENOSYS`
  for `clone3`, and already checks `clone(2)`'s flags (a scalar) for namespace creation. Every `execve` and
  `execveat` is notified at every tier.

### The problem

An approval needs a point where the agent can wait for minutes, and a completion that runs what the person saw.

1. **Waiting.** For an exec the only point that can wait for a person is the seccomp notification of `execve` or
   `execveat`. A fanotify permission event is answered under a deadline, and a BPF program cannot wait.
2. **Completing.** No system call runs a program inside another task, so the supervisor cannot perform an approved
   exec the way it performs an approved open or connect. The exec that finally runs is the kernel's own, after
   `CONTINUE`, and the kernel resolves the pathname and copies argv and the environment again, from memory the agent's
   other threads can write and through links any process can swap. Measured: a hold followed by a
   plain `CONTINUE` ran the unapproved argv (a sibling thread's rewrite) or the unapproved image (a symlink swap) in
   **1000 of 1000** attempts each. "Best effort" would understate that: it binds nothing.
3. **Not freezing the agent.** glibc `posix_spawn`, CPython `subprocess`, Go `os/exec` and the Bun runtime of Claude
   Code start children with `CLONE_VM|CLONE_VFORK`: the parent stays blocked until the child's exec releases its
   memory. Measured: a 2 s hold at the notification kept `posix_spawn` and `Popen` blocked for 2000.7 and 2000.8 ms, and
  holding the Bash tool's own `bash`, a direct `posix_spawn` child of Claude Code, **froze
   Claude Code's interface for the whole hold** (static glyph, no timer, input blocked); holding the same exec at the
   exec stop below left the interface live.

### The two drafts this ADR replaces

- **The 2026-10-05 draft of 0044** (plane tiers only): refuse the gate-asked exec at once with `EACCES` and an
  `ask_id` on the reason channel, open an ask that holds nothing, and on approval let the agent's identical retry run
  once under a per-task `TASK_STORAGE` claim that `bprm_check` consumes and compares with a per-run anchor of the
  approved file (inode, directory, name and a ctime/size stamp). Tier 1 unsupported; `exec.ask` lists rejected (the
  list's floor is refused, so a claim would have to admit rather than narrow). It rejected an earlier
  proposal "approval writes a per-run exec row keyed by the approved inode" because such a row grants nothing
  (the gate asks only over an allowed floor), binds nothing (the retry's `CONTINUE` lets the kernel load any image the
  rows allow) and outlives the approval.
- **The POC draft numbered 0056** (every tier): hold at the notification; on approval `PTRACE_SEIZE` the held task,
  let the kernel run the exec, stop at `PTRACE_EVENT_EXEC` before the first instruction, compare the kernel's facts
  with the approved ones, and detach or kill (the trace-gate); `exec.ask` entries admitted at the launch-time floor; an
  ask that outlives its requester; `--always` on exact facts. Its provisional and open items are decided below.

## Decision

### (1) One mechanism at every tier: the trace-gate

An exec that a person must approve is held, the person decides, and the exec the kernel then builds runs only if its
facts are the approved ones. The binding is the **trace-gate**:

1. The exec is held in its seccomp notification (or at its exec stop, (2)).
2. On approval the supervisor, while the task is still held, calls `PTRACE_SEIZE` on it with
   `PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL`, queues one `PTRACE_INTERRUPT`, checks `ID_VALID`, and answers `CONTINUE`.
3. The kernel runs the exec. At `PTRACE_EVENT_EXEC` the new image is built and no instruction of it has run. The
   supervisor reads the kernel's own facts: the identity and content stamp of `/proc/<pid>/exe`, the new mm's
   `[arg_start, arg_end)` and `[env_start, env_end)`, and the identity of `/proc/<pid>/cwd`.
4. Equal to the approved facts (5): it detaches, and the program runs. Different, or unreadable: it sends SIGKILL,
   which is pending before the return to user mode, so the program runs no instruction.
5. **A failed exec** gives no exec stop. The interrupt queued before `CONTINUE` stops the task about 1 ms later; the
   supervisor rechecks `/proc/<pid>/exe` (unchanged), detaches, and the task carries on with the kernel's errno. Its
   retry is a new notification.
6. **A denial or a timeout at the notification** is answered `EACCES` while the task is held; the task lives and
   nothing ran.

Measured: with the trace-gate, the races above were **caught in 1000 of 1000** attempts and none ran;
it works with the task inside a tier-1 Landlock domain and the supervisor outside it; it costs about 50 µs of
supervisor work per traced exec, 0.629 against 0.579 ms per exec over 2000 execs; an `execveat(fd, "",
AT_EMPTY_PATH)` whose descriptor a sibling swapped ran another inode under the copied facts, and the stop's identity
check caught it.

**Required parts, each from a measured failure:**

- **One tracer thread.** Every ptrace call for every traced task comes from one dedicated, locked OS thread: a
  `PTRACE_INTERRUPT` from a second thread fails `ESRCH`. `PTRACE_O_EXITKILL` means the tracer thread's
  death kills every task it holds, so a dying supervisor fails closed; a notified exec whose listener closed returns
  `ENOSYS` anyway.
- **A non-leader thread's exec.** `de_thread` reports the exec stop under the old leader's pid, so waiting on the
  notification's tid hangs. The tracer waits on the thread group id, accepts the tid for a failed exec's
  interrupt stop, and never waits on `-1`, which would take the launcher's own children's exits.
- **Stopped tasks.** At the exec stop a SIGSTOP parks the task and a plain wait hangs: the tracer waits with
  `WUNTRACED`. A default-action SIGTERM or SIGINT queued during the stop kills the program on the detach before it
  runs; SIGKILL kills it at once. Both end the exec, never run something else.
- **Fail-closed refusals while still held**, answered `EACCES`, reason `ask-unavailable`, field `trace_unavailable`:
  a task already traced by someone else (`PTRACE_SEIZE` gives `EPERM`), a non-dumpable task the supervisor
  cannot trace (tier landlock), ptrace unavailable on the host (Yama `ptrace_scope` 2 or 3 for an unprivileged
  supervisor, 3 for root), and a seize that fails for any other reason. An exec stop whose facts cannot be read is
  killed (`trace_mismatch: unreadable`).
- **The integrity guard after the detach** ((7)): no process of the run can write the approved process's memory, cwd
  or root between the detach and the program's first instruction. Without it, an ancestor rewrote the approved argv
  before `main` with `process_vm_writev` and through `/proc/<pid>/mem` in every attempt.

The trace-gate is a new completion class beside ADR 0041's three: **(V) verified before the first instruction**. The
supervisor answers `CONTINUE`, but the kernel's own facts are compared before any instruction of the new program runs,
so the decision binds what runs, which is the property (A) exists for. ADR 0048's "kernel-pinned" is the same kind of
cell; (V) differs only in who compares (the supervisor, through ptrace, instead of the plane).

### (2) Where the exec waits

- **At the notification**, for every exec except a vfork child. A denial or timeout there is `EACCES`, which shells
  print as "Permission denied" (exit 126) and which Claude Code's Bash tool passed to the model as exactly that.
- **At the exec stop**, for a vfork child: a task whose mm is its parent's (`kcmp(tid, ppid, KCMP_VM) == 0`, measured
  0 for a held `posix_spawn` child and non-zero for a `fork` child). The supervisor seizes it and answers
  `CONTINUE` at once, without asking yet. At the exec stop it compares the kernel's facts with the copied facts the
  matcher decided on (a mismatch is killed unasked) and only then opens the ask, showing the kernel's facts. The vfork
  parent is released at `mm_release`, which precedes the exec stop: measured 0.2 ms (`posix_spawn`) and 0.6 ms
  (`Popen`) against 2000 ms at the notification. An approval detaches; a denial or timeout is
  SIGKILL, which shells print as "Killed" (exit 137), so the ledger line and `$TEGO_REASON` name the
  denial (8).
- **Why per exec and not the exec stop for every exec**: a denial at the exec stop kills
  the process, and the model reads "Killed" as a crash rather than a refusal. Holding at the notification wherever
  that freezes nothing keeps the clean `EACCES`. A task misclassified either way costs only that: a frozen vfork parent
  for the hold, or a SIGKILL instead of `EACCES`; neither runs anything unapproved. A `CLONE_VM` child that is not a
  vfork child (rare) is held at the exec stop, which is harmless.
- **Below 5.19** (no `WAIT_KILLABLE_RECV`), any signal withdraws a held notification and the kernel restarts the
  syscall. The restart is a new notification of the same task with the same facts; it takes that task's place as the
  same waiter of the pending ask ((6), coalescing) instead of asking again or adding a waiter.

### (3) How long it waits: the default is the request's

- **`ask.exec_hold`** (new, a duration from 0 to `ask.timeout`; default `ask.timeout`, so 5 minutes unless the
  contract says otherwise). The exec waits until it is answered or `ask.exec_hold` passes, which is the pause that was asked for.
- When `ask.exec_hold` passes before `ask.timeout`, the held exec is refused (`EACCES` at the notification, SIGKILL at
  the exec stop), reason `exec-not-allowed`, its rule, `ask_state: pending` and the `ask_id`; the ask stays open until
  `ask.timeout` and becomes a pass ask ((6)). `ask.exec_hold: 0` refuses at once and keeps the ask open: the
  refuse-then-retry behaviour of the 2026-10-05 draft, for unattended runs where a hold blocks the agent on nobody.
- **Evidence for the default.** A 20 s hold of a command Claude Code's Bash tool runs was invisible to the model and
  its interface stayed live. Past the Bash tool's timeout (`BASH_DEFAULT_TIMEOUT_MS`, 120 s by
  default) the tool sent no signal, kept the held process, and told the model the command "was moved to the
  background" and that it would be notified. So a hold longer than the tool's timeout reads to the model as a
  backgrounded command, not a failure, and the approved command still runs and is reported when it ends. That is
  acceptable, and `ask.exec_hold` exists for operators who prefer a fast refusal. Codex was not measured.

### (4) The contract: `exec.ask` completes, and how it composes with the floor

- **`exec.ask` is un-reserved.** A match holds and asks instead of refusing. Its entries keep ADR 0048's syntax
  (command word, then subcommand, option and operand words; deny-side matching: any reading matches).
- **In a restricted section (an `allow` key), an ask entry admits its tool at the launch-time floor and constrains
  it**, unless an allow entry already grants the tool's file (next item). Compile resolves the entry's command word
  as an `exec.allow` bare entry would (the files the name resolves to on the run's `PATH`, their `#!` chains and
  `PT_INTERP` loaders, and the row's helper images) and grants them at the
  floor: Landlock `EXECUTE|READ_FILE` at tier 1, the fanotify grant on tier 2's fallback, plane exec rows at C+ and B.
  There the ask entry is what admits the tool, so the tool is then constrained as if a worded allow entry named it: an
  invocation that matches neither an allow pattern nor an ask pattern is refused as unlisted (or asked, under (11)),
  except the helpers of an approved exec (below). So in `exec: {allow: [/usr/bin/ls], ask: [curl]}` curl runs only
  when a person agrees, and with `ask: [npm install]` and no allow entry for npm, npm runs only as `npm install`, and
  only when a person agrees. A bare allow entry for the tool still lifts it, as in ADR 0048: with `allow: [npm]` and
  `ask: [npm publish]`, every npm command runs and only `npm publish` asks. Compile prints every admission on the
  entry's print line ("admits at launch: /usr/bin/curl").
- **An ask entry admits and constrains only where it is what admits the tool.** When an explicit allow entry already
  grants one of the files the command word resolves to on the run's `PATH` (a bare path naming it, or a directory
  entry at or above it), the author has already chosen which of the tool's files run, with any arguments. The ask
  entry then grants nothing at the floor, neither the tool's own files nor the row's helper images, and constrains
  nothing: what runs, and with which arguments, is what the allow entries already let run, and the entry adds only
  the ask step, as in a deny-list section. So `exec: {allow: [/usr/bin], ask: [git push]}` and `exec: {allow:
  [/usr/bin/git], ask: [git push]}` run `git status` unasked, as they did before the ask entry was written, and ask
  before `git push`. The helper images are the allow entries' to grant: a bare path entry for the tool
  (`/usr/bin/git`) grants the row's helper images as ADR 0048 (2) says for a bare entry, and a directory entry grants
  only what lies beneath it, so under `allow: [/usr/bin]` git's helper images (`/usr/lib/git-core/git`, the
  `git-remote-https` beside it) stay refused at the floor with or without the ask entry, and an approved `git push`
  that needs them fails there, as an unasked one does. Compile says both on the entry's line ("/usr/bin/git is
  granted by exec.allow[/usr/bin]; git stays unconstrained; this entry adds the ask step and grants nothing", with
  "git is constrained by exec.allow[git status]" in place of "git stays unconstrained" where a worded allow entry
  names the tool) and, when the row has helper images that no allow entry grants, names them ("not granted:
  /usr/lib/git-core/git, /usr/lib/git-core/git-remote-https; git push runs them: grant /usr/lib/git-core, or allow
  git bare"). When only some of the resolved files are granted (`/usr/local/bin/git` and `/usr/bin/git` on `PATH`,
  `allow: [/usr/bin]`), the ungranted ones stay refused at the floor, as without the ask entry. An implicit grant of
  ADR 0048 (1) (the contract's `command`, an `mcp[].command[0]`, a `#!` interpreter of either, the command given to
  `tego run`) counts as such a grant: the tool it names keeps any arguments whatever the entries say, so an ask
  entry for it grants nothing and constrains nothing either, and adds the ask step to the spellings it names (granting the entry's other resolved files or helper images there would run them
  unconstrained, the case rejected below). A worded allow entry
  constrains the tool as ADR 0048 says, whatever path grants exist: `allow: [/usr/bin/git, git status], ask: [git
  push]` runs only `git status` unasked, asks before `git push`, and refuses `git log` as unlisted. There the worded
  entry, not the ask entry, constrains git; the ask entry still grants nothing, and an approved `git push` records a
  release as every approved exec of a constrained tool does (next item), so the push's helpers run inside the tree it
  released. Rejected: constraining whenever an ask pattern names the tool, because adding `ask: [git push]` to `allow: [/usr/bin]` then refused `git status`, which the contract
  allowed: the opposite of the request. Rejected:
  admitting the ungranted files and leaving the tool unconstrained, which would run, with any arguments, a file no
  entry granted. Rejected: granting the row's helper images for the ask entry in this case (an earlier text, which
  said the entry then "adds only the ask step"): under a directory grant they are
  exactly such files, so adding `ask: [git push]` to `allow: [/usr/bin]` let `git fetch https://...`, `git clone
  https://...` and a direct `git-remote-https` run unasked, where without the entry they failed at the floor.
  Rejected: granting those helper images but admitting them only for a descendant of a live release (below): it
  would make one floor admission depend on runtime state, add a release check to every exec of those images, and
  still leave the tool unconstrained inside the release, where a descendant could run the images with any arguments.
  Rejected: constraining only the files the ask entry admitted, because the matcher keys constraints by tool, and
  one command would then pass or fail by which `PATH` directory the exec searched first.
- **The helpers of an approved exec.** git runs git (ADR 0048 (2)): an approved `git push` execs `git pack-objects`,
  `git send-pack`, `git-remote-https`, or for a local transport `sh -c "git-receive-pack '<path>'"`. Under a
  constrained git, none of these matches an allow pattern, so each would be refused as unlisted (or asked again, one
  helper at a time, under (11)) and the approved push would fail. **Decided: an ask entry's helper closure is admitted
  only for the process tree the approval released.** When the trace-gate releases an exec approved under an ask
  entry (an answer, a pass, a standing answer or a `#!/usr/bin/env` continuation) whose tool is constrained ((5) step
  4: by an allow pattern, or by the ask entry that admits it) and whose row has a helper closure, the supervisor
  records a **release**: the released process's tgid and start time, the ask entry and the `ask_id`, kept while that
  process lives. Which entry constrains the tool does not matter. `allow: [/usr/bin/git, git status], ask: [git
  push]`, and `extends: base/read-only-git` with `allow: [/usr/bin, /bin]` and `ask: [git push]`, constrain git by
  their worded entries while a path or directory entry grants its file, and the approved push there runs `git
  pack-objects` through `/usr/lib/git-core/git`, an image those sections admit at the floor and an invocation no
  allow pattern admits, exactly as under `allow: [sh], ask: [git push]`. Where the tool is unconstrained (a deny-list
  section, a bare name allow entry, a path or directory grant with no worded allow entry naming the tool, or a tool
  an implicit grant names, which keeps any arguments whatever the entries say: ADR 0048's contract `command`, each
  `mcp[].command[0]`, a `#!` interpreter of either, and the command given to `tego run`), no helper is unlisted, and
  nothing is recorded. A release is recorded at the exec stop, once the kernel's facts
  compare equal and before the detach, so the program's first helper exec cannot come before it; a release whose
  detach then fails is pruned with its process. At most 256 releases are live per run; an approved exec past that
  runs with no release, its helpers are decided as unlisted, and its terminal `exec` line, written after the detach,
  says so: the optional field `release_closure`, on the terminal line of a trace-gated exec whose approval records a
  release when the table has room (here, and (11)'s `exec.args[<tool>]` approvals below), is `admitted` when a
  release was recorded and `table_full` when none was ((8)); an `exec.args[<tool>]` approval whose readings disagree
  says `readings_disagree` instead, whatever the table holds (below). The answer line, written before the
  trace-gate ran, never states a closure outcome. An exec of a constrained tool that no allow pattern or allow
  closure admits is allowed when its task is the released process of a live release whose closure holds every reading of the exec, or
  descends from one. A release's closure is its ask entry's, and closures overlap (`git index-pack` lies in fetch's
  and in push's), so with `ask: [git fetch, git push]` an approved fetch's `git index-pack` is admitted by the fetch
  release whatever the push entry says. The supervisor walks the task's parents once (`/proc/<pid>/stat`, at most 16
  levels, each ancestor matched by pid and start time, and the notification checked `ID_VALID` afterwards) and takes the
  nearest ancestor's release whose closure holds every reading. The walk passes through any intermediate process,
  because git runs a local transport's helper through `sh -c`; a reparented task (its chain broken) is not in the tree.
  Otherwise the exec is refused as unlisted, or asked under (11). The helper's line is an allowed command-rule exec's
  (ADR 0048 (8)), authority `rule`, with `command_list: allow`, `command_via: closure`, `closure_of` and
  `command_rule` naming the ask entry of the release that admitted it (`exec.ask[git push]`; ADR 0048's `closure_of`
  named only allow entries until now) and the new optional field `release_of: <ask_id>`. It carries no `ask_id`: it
  is not an approval of its own. It is not trace-gated: it is
  decided as an allowed command-rule exec is, under ADR 0048's disclosure, and its argv comes from the approved
  process tree, which no process of the run can attach to or write ((7)). Deny and ask entries still match a helper
  as any other exec, before this step: `deny: [git gc]` still refuses the `git gc` an approved push's
  auto-maintenance runs. Compile prints each ask entry's closure where its tool is constrained ("helpers admitted
  under an approval: git pack-objects, git send-pack, ..."). Under `exec.unlisted: ask` (11), an approved
  `exec.args[<tool>]` exec's release admits the closure of its own subcommand when every reading agrees on that
  subcommand, and none otherwise: the
  release records that subcommand, a helper whose every reading lies in its closure is admitted as above,
  and the helper's `closure_of` and `command_rule` name `exec.args[<tool>]`. When the readings disagree no release is
  recorded, since it would admit nothing: the approval takes no slot of the table, its helpers are decided as
  unlisted (asked, under (11)), and the approved exec's `release_closure` is `readings_disagree` whether or not the
  table had room, so `table_full` names only an approval whose release would have admitted a closure (rejected: recording an empty release, which took a slot for nothing and left two values true
  of one full-table approval). Every release decides at the
  command step only and grants no image: a helper whose image the floor does not admit (git's `git-remote-https`, a
  link to `git-remote-http`, which is a file of its own, in a section whose grants stop at git's own files) stays
  refused there, and one whose image only an `exec.ask_paths` entry admits is still asked (`exec.unlisted`), since
  that admission is for asking. So an approved https push under the catch-all needs git's helper directory granted.
  A local transport's `git-receive-pack` is no such helper where it is a link to git (measured on Ubuntu 25.10: a
  symbolic link to `git` in `/usr/lib/git-core`; a hard link shares git's inode alike): the kernel loads git's own
  image, which a worded entry's helper grant already admits (ADR 0048 (2)), so an approved `file://` push passes the
  floor under `allow: [sh, git status]`. Where it is a copy, it is a file of its own and needs the same grant as
  `git-remote-https`.
  Rejected: admitting an ask entry's closure statically on the allow side, as an allowed constrained pattern's is (ADR
  0048 R11), because git push's closure holds `send-pack` and `remote-https`:
  under `ask: [git push]` the agent could run `git send-pack origin main` itself and push without asking, so the ask
  would protect nothing. Rejected: asking about every helper, because one push then asks three to five times about
  plumbing a person cannot judge, and a deny of one helper fails the push the person approved. Rejected: admitting
  only the released process's own execs, because git forks its helpers. Rejected: walking only through processes
  whose image is the tool's, because the local transport's `sh -c` would break the chain and the approved push would
  fail.
- **In a deny-list section (no `allow` key), an ask entry only adds the ask step.** Images are unrestricted there and
  no tool is constrained (ADR 0048's mode table), so the floor already admits the tool and nothing is granted or
  constrained: `exec: {ask: [git push]}` asks before `git push` and runs `git status` unasked, exactly as
  `exec: {deny: [git push]}` refuses only `git push`. Constraining the tool there would refuse what the contract
  already allows, the opposite of the request (ask only about what the contract does not already allow).
- **So `execmatch`'s `constrained = len(allow) > 0 && !lifted[tool]`** becomes "no bare name allow entry and no
  implicit grant (ADR 0048 (1)) lifts the tool, and either some allow pattern names it, or some ask pattern names it
  and that ask entry is what admits it". Compile
  decides the second part (it alone resolves names on the run's `PATH` and knows the grants) and passes the set of
  tools whose ask entries admit them to the index; it is empty in a deny-list section, so there no tool is
  constrained, as before. The index also keeps each ask pattern's closure for every constrained tool, whichever entry
  constrains it, reports with an ask verdict whether the tool is constrained (which decides whether its approval
  records a release), and reports for an unlisted invocation every ask pattern whose closure holds all its readings
  (a set: closures overlap) and every subcommand of the row whose closure does (for (11)'s releases), so the
  supervisor can apply the release rule above without the index knowing which releases are live.
- **How this composes with the floor (ADR 0048's condition, and the 2026-10-05 draft's refusal of `exec.ask` lists).** That
  refusal was right in its frame: if the floor stays refused, something must admit at runtime. This ADR changes the frame: the
  admission is **static and compiled**, made at launch, named on the print line, and the same for every exec of the
  run. Nothing admits at runtime. Every runtime mechanism (an answer, a pass, a standing answer, the trace-gate) only
  lets an exec that the floor already admits past the ask step, or refuses it. The admission is inert without a
  person's yes: every `execve` and `execveat` is notified at every tier, the supervisor decides every exec of an
  admitted image, and a run whose supervisor is gone gets `ENOSYS` for every notified exec.
- **Paths a tool can be reached by** are ADR 0048's: names, image identity, argv[0], dashed forms, multicall binaries,
  interpreters, `#!` lines (read for every exec of a run with command rules) and the dynamic loader. An exec that
  reaches an ask entry **through a dynamic loader run as a command** (ADR 0048's interpretation 7, `ld.so prog`) is
  refused, rule `exec.ask[<entry>]` with `completion_unsupported: true`, never asked: the exec stop shows the loader,
  and the program the loader will open is invisible to it.
- **The run's own commands.** ADR 0048 keeps: an ask entry that matches the contract's `command` is an `exec-rule`
  error, and one that matches an `mcp[].command` is a warning naming the server.
- **Incompatible modes** stay as for every ask (`pkg/spec/agent/ask_config.go`): `observe`, `setuid` and `io_uring`
  cannot combine with an exec ask, so compile refuses `exec.ask`, `exec.unlisted: ask` and an exec gate that can ask
  in those runs.
- **`/proc` is never writable in a run that can ask about an exec** ((7)). Compile refuses (`exec-rule`, error) a
  contract with an exec ask and an `fs.write` entry at, above or beneath `/proc`, and the launcher refuses the run
  (exit 125) when any write grant covers a procfs mount point in its own view (a container's second procfs, for
  example).
- **`extends` and nesting.** `extends` concatenates `exec.ask` (ADR 0048). Nested runs (not designed yet) union ask
  lists; only one supervisor can trace a task, so a second tracer's `PTRACE_SEIZE` fails `EPERM` and that exec is
  refused (fail closed) until nested runs say which supervisor asks.

### (5) Precedence, the facts, and the exact key

**Precedence** (amends ADR 0048's (1)):

1. the image floor (a refused image is never asked about);
2. `exec.deny`, any reading;
3. `exec.ask`, any reading: a standing answer for the exact key answers it, else a pass, else the ask;
4. the unlisted step: under a constrained tool (only an allow pattern, or an ask entry that is what admits the tool,
   constrains one, (4)), an invocation that no allow pattern or allow closure admits is allowed when it is a helper of
   a live release (4), else refused as unlisted, or asked under `exec.unlisted: ask` (11);
5. `exec.allow`;
6. the gate, which may still escalate an allowed exec into its ask range (10) or refuse it.

A deny always beats an ask, and no answer passes a deny or the floor. Standing answers and passes act only where an
ask would be opened.

**The facts** of an exec ask, read under `ID_VALID` at the notification (or at the exec stop for (2)'s vfork case):

- The requested pathname (raw) and its spelling, the syscall (`execve` or `execveat`, its flags, the dirfd's identity);
- The image: its path, identity (`st_dev`, `st_ino` from the walk's own descriptor), content stamp (`st_size`,
  `st_ctime` with nanoseconds), owner and mode, and whether the agent can write it (`agent_writable`, the supervisor's
  write verdict at the image's link);
- every `#!` stage's interpreter path and identity, from the walk ADR 0048 already does;
- The full argv, read whole;
- The environment, read through the syscall's own `envp` pointer, never `/proc/<pid>/environ` (that is the old
  image's);
- The cwd's path and identity;
- up to 8 ancestors (pid, exec id, argv[0]) for display;
- The matched rule and the matcher's reading; the tier and its assurance.

**Bounds.** An exec whose argv or environment passes the read budget (8192 elements or 128 KiB each, supervisor R16's
budget) cannot be shown or compared whole: it is refused `args-unreadable`, never asked. Every string is shown
escaped (the display rule below) and compared as bytes.

**The exact key** of an exec ask is `(op exec, rule, image identity and content stamp, every #! stage's identity, the
full argv, the cwd identity, the environment minus the volatile names)`. A pass and a standing answer are keyed on it,
and coalescing groups by it; the trace-gate compares a superset of it (below). Never in it: the pid, the parents, the
time.

- **The environment is in the key, whole, minus a volatile set**: `_`, `OLDPWD`, `PWD`, `SHLVL`, `COLUMNS`, `LINES`,
  plus the contract's `ask.exec_volatile_env` (at most 32 exact names). Measured: two consecutive Claude Code Bash tool
  calls had byte-identical environments, so the whole-environment key is stable within a run; and
  an early fixed list of influential names missed `NODE_EXTRA_CA_CERTS`, which redirects TLS trust, the failure
  any fixed list invites. A list of loader-, interpreter- and trust-relevant names (`LD_*`, `PATH`, `PYTHON*`,
  `NODE_*`, `*_CA_*`, `SSL_CERT_*`, `GIT_*`, `BASH_ENV`, `ENV` and the like) is used only to highlight values in the
  display.
- **The trace-gate compares** the exe identity and content stamp with the approved image's (for a `#!` script, with
  the last interpreter's, and the kernel's vector with the vector `fs/binfmt_script.c` builds from the approved chain:
  `[interpreter, optional argument, the raw pathname, argv[1:]...]` per stage); the whole kernel argv and environment
  byte for byte with the approved ones (the environment's volatile names included, since the comparison is with this
  exec's own copy, not with a key); and the cwd identity. An image the kernel ran through `binfmt_misc` differs in form
  and is killed (`trace_mismatch: form`).

**What the person sees.** `tego ask <run> <id>` shows every fact. Each argument and environment value is shown with
its index, quoted injectively (`strconv.Quote`: control, bidi and format characters, backslashes and invalid bytes
escaped), so `["push origin"]` and `["push", "origin"]` differ; paths go through `record.Printable`. Every environment
name is shown; a value is shown unless its name looks secret (`*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`,
`*CREDENTIAL*`, `*AUTH*`, case-insensitive), in which case its SHA-256 prefix is shown; highlighted names come first.
`agent_writable: true` is shown on its own line. `--json` is the byte-exact form, values of secret-looking names
again reduced to digests.

### (6) Answers: once, always, deny, timeout, and the requester that is gone

- **Allow once** completes exactly one exec through the trace-gate: this one, or, when other tasks joined the ask
  (coalescing, below), the one that has waited longest. One approval is one exec, as one request approval is one
  upstream dispatch (SEMANTICS §6) and one pass is one use.
- **Deny** refuses this exec (`ask-denied`). It also answers the same thread's identical next exec within 2 s (same
  tid and start time, same requested basename, argv and environment) with the same `ask_id`, because glibc `execvp`
  continues its `PATH` search after `EACCES` and reaches the same file again as `/bin/x` after `/usr/bin/x` under
  usrmerge. Otherwise a later identical exec asks again: a plain deny means "not this
  time", and `deny --always` means "never in this run".
- **Nobody answering is never a yes.** `ask.timeout` refuses (`ask-timeout`), with the same 2 s rule. No contract key,
  no default and no pass turns silence into approval.
- **A `PATH` candidate that resolves to no image is never asked about**: it keeps its lookup errno (`ENOENT`), as
  supervisor R28 handles a `PATH` search today. Measured: one absent command under a 13-directory `PATH` made 13
  notifications.
- **Coalescing.** An exec from another task with the same exact key while an ask for it is pending joins that ask as a
  waiter instead of opening a second ask; `tego ask` shows `waiters: N`, and at most 64 tasks wait on one ask (past
  that the exec is refused at once, `ask-unavailable`). The same task's exec restarted after a withdrawn notification
  (same tid and start time, (2)) is the same waiter, not a new one. The answers fan out only where that is safe:
  - **a deny, a timeout or a `deny --always`** refuses every waiter (refusing more is never a risk);
  - **`approve --always`** answers every waiter, each through its own trace-gate and its own `by: standing:<ask_id>`
    pair, because the standing answer covers each of them anyway;
  - **a plain `approve`** releases only the longest-waiting task. The others stay held and are asked again at once,
    as a new ask with a new `ask_id`, the same facts, `waiters: N-1` and `follows: <ask_id>` on its ask line, each
    keeping its own `ask.exec_hold` deadline from its own notification. Only the person can tell two parallel
    identical commands from a duplicate: Claude Code's Bash tool tells the model a command held past
    `BASH_DEFAULT_TIMEOUT_MS` "was moved to the background" ((3)), so the model may issue it again, and one yes running
    `npm publish` or a `curl -X POST` twice is exactly what a person approving once did not agree to.
  Rejected: one `approve` releasing every waiter: it ran N copies on one yes, with no count shown. Rejected: refusing the other waiters `exec-not-allowed` after
  an approve-once: it turns a legitimate parallel command into a failure the person never chose. Rejected: an
  `approve --all` flag: `--always` already releases every waiter for an image the agent cannot write, and a flag that
  releases a counted batch is one more number a person types without reading.
- **The requester that is gone.** When every task waiting on an ask has died (the agent's tool killed it) or been
  released by `ask.exec_hold`, the ask stays answerable until `ask.timeout`, shown `requester: gone`; a waiter that dies
  while others are held only leaves the waiter count. Only an explicit approval then creates a **one-use pass** for the
  exact key, valid for `ask.timeout` after the answer, taken by the first identical exec from any process of the run
  (the retry is a new process, and the run is the principal), completed through the trace-gate, and recorded as its own
  `ask` and `answer` pair, `by: once:<ask_id>`. A timeout creates nothing. At most 64 passes are live per run; past that
  an approval of a gone requester is recorded and creates no pass, and the CLI says so.
- **`#!/usr/bin/env` continuations.** `npm` is two execs in one process: the script, then `node /usr/bin/npm ...`.
  An approval of an exec whose last `#!` interpreter is `env` also answers that process's next exec once,
  when it is exactly the exec `env` will make (the program `PATH` gives and the vector `env` builds), which the person
  is shown with the ask. The continuation is completed through the trace-gate. A broader lineage window (the next 4
  execs within 2 s) is rejected as easier to abuse.
- **Always allow** (`approve --always`) stands for the rest of the run for the exact key, as ADR 0054's standing
  answers do for opens and connects, under all of ADR 0054's rules (installed only once the person's answer line is
  recorded, its own `ask` and `answer` pair per use, `by: standing:<ask_id>`, at most 256 per run, never across runs).
  Every exec it answers is completed through the trace-gate. **It is refused for an `agent_writable` image**
  (`ask: this program can be rewritten by the agent; approve it once`): the content stamp in the key catches a
  rewrite, but a same-size rewrite within one timestamp tick does not change it, and an always answer should not rest
  on timestamp granularity.
- **Deny always** (`deny --always`) stands for the exact key. With `--command '<pattern>'` (ADR 0048 syntax, matched
  deny-side: any reading) it stands for every exec at the ask step that the pattern matches, so one answer covers the
  agent's variations of a command it must never run. An allow-side pattern is not offered: a pattern approval is a rule
  learned at runtime, and the contract is where rules live.
- **A scored gate request is never remembered** (ADR 0054), and a pass for one is delivered only when the passing
  exec's own re-score is still in the ask range.

### (7) The integrity guard: nothing of the run writes the approved process

In a run whose contract can ask about an exec (an `exec.ask` entry, `exec.unlisted: ask`, or an exec gate that can
reach its ask range), from launch:

- **The filter refuses** (`EPERM`, as a plain seccomp errno action on a scalar register, no notification)
  `ptrace(PTRACE_ATTACH)`, `ptrace(PTRACE_SEIZE)` and every `process_vm_writev` from every process of the run.
  `PTRACE_TRACEME` stays allowed: a task traced that way is already traced when it execs, so its trace-gate refuses it
  (`EPERM` at the seize).
- **The filter refuses** `clone(2)` with `CLONE_FS` and without `CLONE_THREAD` (`clone3` is already `ENOSYS`). Exec
  does not unshare `fs_struct`, so a `CLONE_FS` peer could change the approved process's cwd or root after the detach;
  threads die in `de_thread`, and exec unshares the descriptor table.
- **No write under `/proc`** ((4)): a Landlock domain with no write grant beneath `/proc` refuses an `O_WRONLY` or
  `O_RDWR` open of `/proc/<pid>/mem`. An open from before the exec names the old mm,
  which the exec released.

Why refuse outright rather than per target (the POC draft notified both calls and refused those aimed at a verified
process): a target check followed by `CONTINUE` is racy in the same way the exec was. A call checked while its target
was not yet verified can be delayed by scheduling until after the detach, and then resolve the target's new mm. A
static errno action has no window. The cost is that in-run debuggers (`strace`, `gdb -p`) cannot attach in such a run;
compile says so on the exec-ask print line, and status lists it. ADR 0048 P2's argv-guarded mark, once built, decides
the same in the kernel per target at the plane tiers and may then narrow this to the guarded processes.

### (8) Broker, ledger and the agent's signal

- **A new hold kind, `exec`**, and the exec facts on the request: `exec_requested`, `exec_image` (path, `dev:ino`,
  stamp), `exec_chain`, `exec_args`, `exec_cwd`, `exec_env` (names, highlighted values, digests of secret-looking
  values, a digest of the key's environment), `exec_ancestors`, `agent_writable`, `hold_point` (`notification` or
  `exec_stop`), `requester` (`held` or `gone`), `waiters` (the tasks waiting on the ask, (6)) and `follows` (the
  `ask_id` an approve-once answered before this ask was opened again for the remaining waiters). `validRequest` bounds
  every field (valid UTF-8 after escaping, the read budget). The listing returns a bounded summary (the image and an
  argv preview of at most 256 bytes with `args_truncated`), so 64 maximal exec asks fit the 128 KiB reply bound; the
  facts come from `detail`.
- **Older CLIs.** The socket protocol gains `list_v2`, `detail_v2` and `answer_v2`. A v1 `list` omits exec asks and
  keeps its shape; a v1 `detail` or `answer` naming an exec ask gets the existing error shape with
  `code: client-too-old`. Nobody approves an exec without seeing its facts.
- **Exec holds are capped** at `ceil(ask.max_pending / 2)` (32 at the default 64; 1 at `max_pending: 1` or 2; 2 at 3),
  so file and network asks are not starved and a contract with an exec ask always has at least one exec hold: half
  rounded down would be 0 at `max_pending: 1` and refuse every exec ask with nothing said at compile. At `max_pending:
  1` the one slot is shared by every kind, as it already is between file and network asks. Past the cap an exec that
  would ask is refused at once, `ask-unavailable`; coalesced waiters (6) count once, as their one ask. A held exec
  leaves the worker pool: its handler returns without answering, the answer is sent later by notification id, and one
  ticker polls `ID_VALID` for every hold, so holds never take the standbys that connect relays share. `limits.pids`
  bounds a fork bomb of asks.
- **The ledger** (ADR 0016: the verdict is what the mechanism answered). The `ask` and `answer` lines carry the exec
  fields, `target` the image path verbatim (never `RedactTarget`, which is for HTTP), argv verbatim like an exec line
  (record-ledger R9a), and never an environment value of a secret-looking name. The exec's terminal line is the
  supervisor's at every tier, because the trace-gate is the mechanism that answered (at a plane tier the kernel's
  terminal record of the same attempt is consumed by the attempt marker, as §2.19 of enforce-plane already does when
  the supervisor owns an exec, so there is one line):

  | Outcome | Line |
  |---|---|
  | approved, verified, ran | `exec`, `allow`, authority `human`, `ask_id`, `argv_facts: verified_trace`; where the approval is one that records a release ((4): an ask entry's approval of a constrained tool whose row has a helper closure, whichever entry constrains the tool, or an `exec.args[<tool>]` approval), `release_closure: admitted\|table_full\|readings_disagree` (`readings_disagree` only for an `exec.args[<tool>]` approval, which then records none whatever the table holds) |
  | approved, the kernel's facts differ | `exec`, `refused`, rule `exec.trace`, `trace_mismatch: image\|argv\|env\|cwd\|form\|unreadable`, the approved and the kernel's argv, `signal: SIGKILL`, authority `rule` |
  | the trace-gate could not seize | `refused`, `ask-unavailable`, `trace_unavailable: traced\|nondumpable\|ptrace\|error`, `EACCES` |
  | denied | `refused`, `ask-denied`, authority `human`, `EACCES` or `signal: SIGKILL` |
  | timed out | `refused`, `ask-timeout`, `EACCES` or `signal: SIGKILL` |
  | released by `ask.exec_hold` | `refused`, `exec-not-allowed`, the rule, `ask_state: pending`, `ask_id` |
  | approved once while other tasks wait (6) | one of the rows above for the released task; a new `ask` line with `waiters` and `follows` for the rest |
  | a pass or a standing answer | its own `ask` and `answer` pair, then one of the rows above |
  | a helper of a released approval ((4)) | an allowed command-rule exec's line, authority `rule`, `command_via: closure`, `closure_of` and `command_rule` the ask entry of the release that admitted it, or `exec.args[<tool>]` for the release of an `exec.args[<tool>]` approval ((11)), `release_of: <ask_id>`, no `ask_id` |

  Identical refusals while one ask is pending (same key, same `ask_id`, same reason) aggregate into one line with
  `count`, `first_mono_ns` and `last_mono_ns`, as reads aggregate. Under `record: off` the allowed line is not written;
  asks, answers and refusals are. An approved exec's `release_closure` is then not written either, so the unlisted
  refusals of a `table_full` approval's helpers would have no recorded cause: `run_end`'s `exec_asks` counts the
  approvals that recorded no release, `release_table_full` and `release_readings_disagree`, in every record mode.
  Rejected: writing the approved exec's allowed line under `record: off` when its
  `release_closure` is not `admitted`, which would put allowed lines in a `record: off` ledger, an exception every
  reader of one would have to know.
- **Record version.** The fields are optional, in one `record_minor` step. `hold: exec` is a new value in a closed
  field: VERSIONING §2 gains the rule "an existing field may gain a value at a `record_minor` step only when every
  older reader fails closed on it" (an older `tego status` rejects the hold as unsupported and reports that run's
  status as an error; `events`, `verify` and the hash chain are unaffected). `reason`'s closed set is unchanged:
  `exec-not-allowed` plus `ask_state` and `ask_id` carry the pending state.
  `argv_facts` gains `verified_trace`. The optional `release_of` (on a helper of a release, (4)) and
  `release_closure` (a closed set, `admitted`, `table_full` or `readings_disagree`, on the terminal `exec` line of an
  approved exec whose approval records a release when the table has room, written after the release was or was not
  recorded at the exec stop, (4); `readings_disagree` whatever the table holds) join in the same step, and
  `closure_of` (an open string) may name an ask entry or `exec.args[<tool>]`. `run_end` gains `exec_asks{asked,
  coalesced, approved, denied, timed_out, passed, standing, verified, mismatched, unavailable, released_helpers,
  release_table_full, release_readings_disagree}`.
- **The agent's signal.** `last-refusal.json` and the mirrored `refused` line carry `ask_id` and `ask_state`
  (`pending`, `denied`, `timeout`, `unavailable`) and, for a SIGKILL at the exec stop, `signal`; `record.RefusedPayload`
  gains them additively. `$TEGO_REASON` names that file (REASON-CHANNEL §2). The errno stays `EACCES`: `EAGAIN`
  means `RLIMIT_NPROC` on `execve`, some spawn wrappers retry it in a tight loop, and shells print "Resource
  temporarily unavailable".
- **Status and measure.** An exec hold with `requester: held` makes the run `waiting approval` (the agent waits);
  one with `requester: gone` counts in pending approvals without that state. `measure`'s wait seconds count held
  time only.

### (9) Per tier

| Tier | Held at | Completed by | Guaranteed | Not guaranteed (disclosed) |
|---|---|---|---|---|
| L (landlock) | the notification; the exec stop for a vfork child | the trace-gate, unprivileged: the supervisor is an ancestor of every run process (it is the launcher, a child subreaper), which Yama scope 1 allows | an unanswered, denied or timed-out exec never runs; the image lies within the launch-time floor; the image identity and stamp, the `#!` chain, argv, environment and cwd that run are the approved ones; no process of the run writes the approved process before its first instruction | (V)'s residuals below |
| C⊘ (cgroup, fanotify fallback) | as L | as L, by the root supervisor; the listener's grant includes the ask-admitted images | as L | as L |
| C+, B (decision plane) | as L | as L; the plane's exec rows (ask admissions included) decide the floor on the file the kernel loads; ADR 0048 P2's pins, once built, add a kernel check of the same facts | as L | as L |
| observe | — | compile refuses an exec ask in an observe run | — | — |

Where the trace-gate cannot run (ptrace unavailable; the task already traced; a non-dumpable task at tier landlock),
the exec is refused, never continued unverified. **Disclosure:** a capability row, `exec.ask_trace`, appended last
("exec approval verified before the first instruction"), with cells landlock "conditional (supervisor ptrace: Yama
`ptrace_scope` at most 1)", cgroup and bpflsm "conditional (Yama `ptrace_scope` at most 2)"; `run_start.capabilities`
sets it from a launch-time check of the Yama setting and a seize of the stage child; with it false, every exec ask of
the run is refused `exec-not-allowed`, its rule, `completion_unsupported: true`, as ADR 0048's reservation did. `compile
--test` reads an exec ask cell as `verdict: ask`, `completion: trace` in every column, never simulating an answer.
No cell joins `best_effort`: an exec ask is (V) or (R), never (D).

### (10) The gate's exec ask range

The gate's `exec matches` score in the ask range takes the same hold, facts, answers and trace-gate at every tier
(its rule is the gate's, `gate_rule` and the score on the ask line). It is never remembered (ADR 0054). This replaces
the 2026-10-05 draft's refuse-and-retry under a kernel claim and ADR 0041's (R) cell for it.

### (11) The catch-all: `exec.unlisted: ask` and `exec.ask_paths`, in the first cut

The request's words are "a program or command the contract does not already allow", so the first cut includes the
catch-all, as the last contract work package:

- **`exec.unlisted: refuse | ask`** (default `refuse`). Under `ask`, the unlisted step asks instead of refusing: a
  constrained tool's invocation that no allow or ask pattern matches is asked about (rule `exec.args[<tool>]`), and so
  is an image under an `exec.ask_paths` entry that no grant admits (rule `exec.unlisted`). It is valid only in a
  restricted section (an `allow` key): in a deny-list every unlisted program already runs, and compile says to name
  commands with `exec.ask` instead (`exec-rule`, error).
- **`exec.ask_paths: [<dir>...]`**: the directories whose programs are admitted at launch for asking only (Landlock
  `EXECUTE|READ_FILE` beneath them; ask-only rows at the plane tiers). A program outside every grant and every
  `ask_paths` entry is refused unasked: a Landlock domain cannot gain a grant after launch, and this ADR admits nothing
  at runtime. `ask_paths` is valid only with `unlisted: ask`.
- **Agent-writable programs.** Compile warns (`exec-rule-coverage`) when an `ask_paths` entry lies at or beneath an
  `fs.write` entry: the agent can write programs there that become askable. The ask shows `agent_writable: true`, and
  `approve --always` is refused for such an image ((6)). The trace-gate still binds the identity, stamp, argv and
  environment of what runs.
- **Composition.** Under `extends` the stricter `unlisted` wins (an explicit `refuse` anywhere in the chain beats
  `ask`, as `fs.assurance`'s stricter value wins), and `ask_paths` concatenate. Nested runs intersect `ask_paths`.

### (12) Command rules and the trace-gate: verifying every command-rule exec

The trace-gate could turn ADR 0048's disclosed cells (`exec.rules/argv`, `gate.exec`) into verified ones at every
tier, at about 50 µs of supervisor work per guarded exec. **Decided: yes, as an opt-in, after
the first cut**: `exec.assurance: verified` (a new value beside ADR 0048's `kernel`) trace-gates every exec that a
command rule or the exec gate decided to allow, refuses the run before the child starts (exit 125) when
`exec.ask_trace` is unavailable, and moves those cells out of `best_effort`. `exec.assurance: kernel` keeps meaning
ADR 0048 P2's pins. It is not the default because it refuses in-run debuggers in every run with command rules ((7)) and
refuses the exec of any task an in-run debugger already traces, a behaviour change ADR 0041 D1 (a) reserves for an
opt-in. Budget: at most +60 µs p50 and +200 µs p99 of supervisor time per guarded exec, and none for an unguarded
exec.

### (13) What this amends

- **ADR 0007.** The gate's exec ask range is completed by (10) at every tier.
- **ADR 0008.** An approved exec is the one approval completed by `CONTINUE`, and only with the trace-gate seized
  before it: the kernel's own facts are compared before the first instruction, and a mismatch is killed. Every other
  approval keeps its supervisor completion.
- **ADR 0016.** (4)'s producer table: the supervisor writes the terminal line of a trace-gated exec (an approved
  `exec.ask`, `exec.unlisted: ask` or gate ask-range exec, a pass, a standing answer, and every exec under
  `exec.assurance: verified`) at every tier, because the trace-gate is the mechanism that answered; at tiers 2 and 3
  the kernel's `sched_process_exec` record of the same attempt is consumed by the attempt marker, so the action keeps
  one line ((8)). Every other successful exec at tiers 2 and 3 stays the kernel's.
- **ADR 0019.** `compile --test` cells gain the additive string field `completion` (`trace` for an exec ask cell; (9)),
  beside the existing `completion_unsupported`. The document ADR 0019 (4) versions stays `v: 1`: the field is optional
  and additive (absent means the cell claims no completion), as ADR 0048's `command_rule` and `argv_facts` were, and a
  reader that does not know it still reads the cell's `verdict: ask`.
- **ADR 0041.** A fourth outcome, (V) verified before the first instruction. D1's rows: `exec.ask` → match is (V) at
  every tier (or (R) where the trace-gate is unavailable); the gate's exec ask range is (V); the context table's
  "exec: argv — no, at any tier" becomes "verified by the trace-gate for an approved exec at every tier".
- **ADR 0048.** (1)'s precedence as (5) above; (5)'s reservation of `exec.ask` ends, and in a restricted section an
  ask entry admits and constrains its tool where it is what admits it (4): `constrained` counts such ask patterns; an
  ask entry for a tool whose file a bare path or directory allow entry grants, or that an implicit grant names, adds
  only the ask step and grants no image, helper images included; and in a deny-list section an ask entry constrains
  nothing, as before. (2)'s helper
  closure gains an ask side: an ask entry's closure is admitted only for the process tree an approval of it released,
  under a constrained tool whichever entry constrains it, never statically (4), so R11 does not extend to ask
  entries. P2 (not built): bprm_check's step 4 (`exec-traced` for a guarded exec of a traced task) does not refuse an
  exec whose pin carries the new flag `trace_gate`, which the supervisor sets only after its own `PTRACE_SEIZE`
  succeeded (a task has one tracer, so the tracer is the supervisor); with P2 built, an exec ask is both pinned and
  trace-gated.
- **ADR 0054.** Standing answers gain the `exec` hold, keyed on (5)'s exact key, refused for agent-writable images, and
  a deny-side `--command` pattern.

## Why

- **The trace-gate is the only candidate that binds at every tier.** The 2026-10-05 draft's claim binds the image only,
  at the plane tiers only, needs `PIDFD_THREAD` (6.9) for a non-leader's exec, adds two maps, an optional doctor cell
  and a `bprm_check` branch, and proves argv only after the fact in the record (an approved image could run with
  another argv, recorded without authority `human`). ADR 0048 P2's pins bind the decided prefix of argv in the kernel
  but are not built, need the plane, and do not cover the environment. The trace-gate binds the image, the `#!` chain,
  the whole argv, the environment and the cwd, at tier 1 included, with no BPF change, at about 50 µs (measured).
- **It is ADR 0008's principle kept, not dropped.** ADR 0008 forbids `CONTINUE` for approvals because the kernel then
  acts on facts nobody checked. Here the kernel's facts are checked after its last copy and before any instruction
  runs; what ADR 0008 guards against cannot happen unseen.
- **The hold point follows the measurement.** The notification hold froze vfork parents and Claude Code's interface;
  the exec-stop hold froze nothing; the notification keeps a clean `EACCES`. The per-exec switch takes the good side of
  each, and a misclassification costs availability only.
- **Pause is the default because it is the request and it works.** Claude Code's Bash tool neither kills nor signals a
  held command past its timeout (measured), so a long hold does not lose the command.
- **The key is exact because the person approved exact facts.** A looser key would let an approval stand for something
  nobody saw; the environment is in it because the measured environment is stable and a fixed list measurably missed
  a trust-redirecting variable.

## Security argument (restated for exec asks, as ADR 0048 requires)

- **The floor is static.** An ask entry's admissions are compiled, printed and fixed at launch; `ask_paths` names the
  directories it admits. Nothing admits at runtime, so the runtime mechanisms cannot widen the floor.
- **Every exec is decided.** Every `execve` and `execveat` is notified at every tier; with the supervisor gone the
  notified syscall fails (`ENOSYS`), and `PTRACE_O_EXITKILL` kills every task the dead tracer held. An admitted image
  never runs undecided.
- **A deny beats an ask; no answer passes a deny or the floor.** Standing answers and passes act only at the ask step.
- **Silence refuses.** A timeout refuses; only an explicit approval creates a pass or a standing answer.
- **One yes is one exec.** A plain approval releases one task, however many identical execs wait on the ask; the
  others are asked again ((6)). Only `--always` answers more than one, and never for a program the agent can write.
- **An ask entry never refuses what the contract allows.** In a deny-list section, and in a restricted section where
  an allow entry already grants the tool's file or an implicit grant names the tool, it adds the ask step to the
  commands it names, grants nothing and
  constrains nothing; it admits and constrains a tool only where it is the entry that admits it ((4)).
- **Under a constrained tool, an approval admits its own helpers, and nothing the agent can run itself.** Where the
  tool is constrained, by the ask entry that admits it or by a worded allow entry ((4), (5) step 4), an approval's
  helper closure is admitted only for the process tree it released, while the released process lives, and only at
  the command step (a release grants no image), and the agent's own `git send-pack` stays unlisted. Where the tool
  stays unconstrained (a deny-list section, a bare name allow entry, an allow entry that grants the tool's file by
  path or directory with no worded allow entry naming the tool, or a tool an implicit grant names, ADR 0048 (1): the
  contract's `command`, an `mcp[].command[0]`, a `#!` interpreter of either, the command given to `tego run`), an
  ask entry covers only the spellings it
  names, as a deny entry does there: under `ask: [git push]` the agent's own `git send-pack origin main` runs
  unasked, and the row's "not covered" note, which compile prints on the entry's line ("git push: does not cover
  send-pack or http-push"), names the spellings that escape it. No release is recorded there, since no helper is
  unlisted.
- **What runs is what was approved.** The trace-gate compares the kernel's own facts, read after the kernel's last copy
  and before the first instruction, with the approved facts, and kills on any difference or unreadable fact. Measured
  1000 of 1000 races caught.
- **Nothing changes the approved process before its first instruction.** No process of the run can ptrace-attach it,
  write its memory with `process_vm_writev` or through `/proc/<pid>/mem`, or share its cwd and root; its threads died
  in `de_thread` and its descriptor table was unshared by the exec; an earlier tracer makes the seize fail.
- **What the person saw is what is compared.** The display is the facts, quoted injectively; secret-looking values are
  digests in both the display and the ledger, and the comparison is on bytes.
- **The verifier is TCB code.** A bug that calls two different fact sets equal would run an unapproved exec; that is
  the one failure the design cannot make fail closed by construction. WP3 carries a mutation test per compared field
  (each field changed alone must be killed) and the 1000-iteration race cells.
- **Scope.** The supervisor traces only processes of the governed run, which it launched; root outside the run can
  still see and remove everything (host-wide control is out of scope).

## Residuals, stated plainly

1. **Identity is not content.** The image's identity and content stamp are compared; a same-size rewrite within one
   timestamp tick of the approval, on a filesystem without fine-grained timestamps, is not seen. An agent-writable
   program may also be rewritten in place after the detach, and pages not yet faulted in then come from the new
   content. `agent_writable` is shown, and `--always` is refused for such images.
2. **Everything the program reads is an input, not an approved fact**: its configuration, the files it opens, and a
   `#!` script's own body, which the interpreter opens again by name after the exec. Approving `./deploy.sh` approves
   the interpreter, the vector and the environment; whether the script's bytes are the ones the person had in mind is
   bounded by who can write the script and its directory, which `agent_writable` shows.
3. **In-process effects** (ADR 0048's residual 1): an approved program can do in-process what its arguments allow.
4. **A denial at the exec stop is SIGKILL** (exit 137, "Killed"), which a model may read as a crash. The ledger line
   and `last-refusal.json` name the denial.
5. **In-run debuggers cannot attach** in a run that can ask about an exec, and an exec of a task already traced by one
   is refused ((7)).
6. **An image the kernel runs through `binfmt_misc`** is killed at the exec stop (`trace_mismatch: form`): the
   supervisor does not predict `binfmt_misc` matches.
7. **A long hold reads to Claude Code's model as a backgrounded command** past the Bash tool's timeout (measured);
   operators who dislike that set `ask.exec_hold`.
8. **Hosts without ptrace** (Yama 2 or 3 for the unprivileged tier, 3 for root, or an LSM denying it) refuse exec
   asks; the capability row and doctor say so.
9. **Root outside the run** can do anything to the run (host-wide control is out of scope).
10. **An approved command's helpers include what its inputs make it run.** The release admits the ask entry's helper
    closure to every descendant of the approved process, through any intermediate process: a git hook or a
    `core.sshCommand` the agent wrote runs under the release, and a git it runs gets the approved subcommand's closure
    (`git send-pack` under an approved `git push`) while the approved process lives. This is residual 2 seen from the
    helpers' side: the approved push already pushes wherever the repository's configuration, which the agent can
    write, says. Nothing beyond the closure is admitted: a `git push` from a hook asks again, and every other tool is
    decided by the contract.

## Evidence not yet run (WP3 waits for it)

The decision above is accepted; this evidence gates only the construction of the trace-gate (the plan's WP3), and
its outcomes are already decided here, so no WP0 result can turn an exec ask into an unverified `CONTINUE`:

- **The tracer cannot leave the launcher's own waiters alone** for the agent's main process: a traced exec of that
  process is refused while held, `ask-unavailable`, `trace_unavailable: error`; every other process's exec asks go
  ahead.
- **The trace-gate fails at a tier** (the root tiers' seize, the `kcmp` switch, or `#!` verification does not hold
  there): every exec ask at that tier is refused at the notification, `exec-not-allowed`, its rule,
  `completion_unsupported: true`, as ADR 0048's reservation does today, and that tier's `exec.ask_trace` cell reads
  `no`. It never falls back to `CONTINUE`.
- **The integrity guard as specified does not hold** (a run member can still write an approved process before its
  first instruction): no exec ask completes at all until it does, with the same refusal at every tier.

Status changes to "built" only after the plan's WP8. What WP0 runs:

- **Codex**: its shell tool's timeout, what it tells the model, whether `exec_command` returns at `yield_time_ms` and
  keeps a held process, and its environment between calls. Codex runs each command as `bash -lc`, so a held command is
  bash's fork child and the Claude Code through-bash results should carry over; that is a reading, not a measurement.
- **The Go tracer**: the one-thread design is from C probes and a code reading (`launch/reap.go` waits per pid on
  zombies only and the main child through `waitid(P_PIDFD)`, neither of which takes a ptrace stop); no Go prototype
  ran. If the tracer cannot avoid consuming an exit the launcher's own waiters own, a traced exec of the agent's main
  process is refused (`trace_unavailable: error`) rather than risked.
- **The root tiers**: the trace-gate with a root supervisor and the plane attached (C⊘, C+ in both modes, B) in a
  guest, including that the plane's `ptrace_access_check` does not refuse the launcher's seize; the `kcmp` switch end
  to end; `#!` multi-stage verification against the approved chain.
- **The integrity guard as specified here** ((7)'s outright refusals and the `CLONE_FS` arm) was not probed; the earlier probe's
  per-target refusal was.

## Options rejected

1. **Hold, then `CONTINUE` with no binding at tier landlock** (disclosed best effort): measured a
   total bypass, 1000 of 1000.
2. **Refuse now, retry under a kernel claim, plane tiers only** (the 2026-10-05 draft): binds the image only, needs the
   plane and 6.9 for non-leaders, proves argv after the fact, leaves tier 1 and the fallback without exec approval,
   and does not pause, which is the request. Its reason channel, record shape, coalescing (with one exec per
   approve-once, (6)), aggregation, protocol versioning and injective display are kept above.
3. **A per-run exec row keyed by the approved inode**: grants nothing, binds nothing, and turns one approval into a
   rule for the run (the 2026-10-05 draft's Context).
4. **A fanotify identity credit at C⊘**: the trace-gate binds more at every tier, and the credit was
   never run.
5. **Refuse at once as the default**: it does not pause the agent and depends on the agent retrying;
   kept as `ask.exec_hold: 0`.
6. **The exec stop for every exec**: every denial would be a SIGKILL; the notification keeps `EACCES`
   wherever it freezes nothing.
7. **Per-target ptrace and `process_vm_writev` refusal by the supervisor** (the POC draft): racy between the check
   and the call's own resolution of the target ((7)).
8. **A fixed list of influential environment names in the key**: measured to miss `NODE_EXTRA_CA_CERTS`.
9. **An environment-free key**: `LD_PRELOAD` or a trust variable
   would change what an approved command does without the person seeing it.
10. **Lifting the whole Landlock exec floor for the catch-all** and **`exec.ask: ["*"]` with a broad
    floor**: every program the agent writes would be one ask away from running, and a `*` command word is
    an ADR 0048 error and would sit above allow in the precedence, where a catch-all cannot.
11. **A hold at fanotify `FAN_OPEN_EXEC_PERM`**: the listener answers under a deadline.
12. **SIGSTOP on the new process** (ADR 0048's option 4): any process of the run can SIGCONT it; a ptrace stop is not
    ended by SIGCONT.
13. **Ask entries that require their tool in `exec.allow`** (ADR 0048 as written): the ask could not complete without
    the author hand-writing the grant, which would also let the tool run unasked.
14. **Passes scoped to the requester's process tree**: the retry is a new process, and the run
    is the principal.
15. **A pass created by a timeout, or an "allow on timeout" setting**: silence is never a yes (ADR 0054).
16. **Allow-side `--always` patterns** (the POC draft's optional pattern): a rule learned at runtime; write it in the
    contract.
17. **A new reason code `ask-pending`** and **`EAGAIN` for a pending ask**: the closed set already carries the pending state, and
    `EAGAIN` on `execve` means `RLIMIT_NPROC`.
18. **Making `exec.assurance: verified` the default** ((12)): it changes every command-rule run's debugger behaviour,
    which ADR 0041 D1 (a) reserves for an opt-in.
19. **An ask entry's helper closure admitted statically**, as an allowed constrained pattern's is (ADR 0048 R11):
    `git push`'s closure holds `send-pack`, so the agent could push unasked; asking about every helper instead fails
    the approved push on plumbing nobody can judge ((4) keeps the closure to the released process tree).
20. **An ask entry constraining its tool whenever it names it**: it refused commands a bare path or directory grant
    already allowed ((4)).
21. **An ask entry granting its row's helper images where an allow entry already grants the tool's file**, and
    **those images granted but admitted only inside a release**: the first ran,
    unasked and with any arguments, helper images no allow entry granted (`git fetch https://...` under `allow:
    [/usr/bin]` once `ask: [git push]` was added); the second made a floor admission depend on runtime state and left
    the tool unconstrained inside the release ((4)).
22. **Stating the closure outcome on the answer line, or reserving the release slot when the answer is recorded**: the
    answer line is written before the trace-gate runs, and a failed exec, a mismatch or a refused seize releases
    nothing, so the line could state an outcome that never happened; the terminal `exec` line, written after the
    release was recorded or not, carries `release_closure` instead ((4), (8)).
23. **Recording a release only under an ask entry that is what admits its tool**, and **keeping that rule with a compile warning that such a push fails**: a worded allow entry constrains
    the tool whatever path grants exist, so under `allow: [/usr/bin/git, git status], ask: [git push]`, (4)'s own
    example, and under `extends: base/read-only-git` with `allow: [/usr/bin, /bin]`, the approved push's `git
    pack-objects` would have been refused as unlisted and the push would have failed (measured at tier landlock
    today, ADR 0048 P1, for the agent's own `git pack-objects` under `allow: [/usr/bin/git, git status]` and under
    `allow: [/usr/bin, git status, git log]`: refused `exec.args[git]`, unlisted, its image admitted at the floor); a
    warning would have kept a contract whose every approved push fails. A release grants no image and decides only
    inside the tree an approval released, so recording one under a worded constraint widens nothing that the third
    round's floor fix closed ((4), options rejected 21).
24. **An empty release for an `exec.args[<tool>]` approval whose readings disagree**, and **the approved exec's
    allowed line kept under `record: off` when no release was recorded**: the first took one of the 256 slots for a
    release that admits nothing and left `table_full` and `readings_disagree` both true of a disagreeing approval
    that met a full table; the second put allowed lines in a `record: off` ledger, an exception every reader of one
    would have to know, where `run_end`'s counters record the cause in every mode ((4), (8)).

## Consequences

- **For the agent.** A command a person must approve pauses (up to `ask.exec_hold`), then runs exactly as asked, or
  fails with `EACCES` ("Permission denied") or, for a vfork child, SIGKILL ("Killed"). `$TEGO_REASON` names the ask.
- **For the person.** `tego ask <run>` lists exec asks with the program and an argv preview; `tego ask <run> <id>`
  shows every fact; `approve`, `approve --always` (never for an agent-writable program), `deny`, `deny --always
  [--command <pattern>]`. Claude Code in `--permission-mode default` asks its own question first; the operator section
  says so.
- **Cost.** Contract, compile, broker, CLI, supervisor tracer, filter arms, record and readers, gate path, catch-all,
  acceptance and docs: the plan's WP0 to WP9, plus WP10 for (12)'s opt-in. No BPF
  object changes; ADR 0048 P2 gains one pin flag when it is built.
- **Performance.** Runs with no exec ask pay nothing. In a run that can ask, an exec that matches no ask pays ADR
  0048's matcher only; the filter arms are errno actions on scalars. A traced exec pays about 50 µs of supervisor time
  plus a ptrace round trip (budgets in the plan).

## Questions answered

1. **Ship `exec.unlisted: ask` in the first cut?** Yes, as the last contract package (11), restricted mode only, with
   explicit `ask_paths`, a compile warning for agent-writable paths and no `--always` for agent-writable programs.
2. **The default hold?** `ask.exec_hold` defaults to `ask.timeout`: the pause that was asked for (3). `0` gives
   refuse-then-pass for unattended runs.
3. **Verify every command-rule exec at about 50 µs?** Yes, as the opt-in `exec.assurance: verified` after the first
   cut (12); not the default.
4. **What does a yes mean?** One exec of the exact facts; `--always` means the exact facts for the rest of the run;
   nothing persists across runs (ADR 0054's question 3 stands).
