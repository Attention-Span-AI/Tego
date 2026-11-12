# The agent watcher: govern any agent as a black box

Status: a design page for `tego watch`, `tego agents` and `tego adopt`. The decisions are in
[ADR 0054](../adr/0054-govern-any-agent-as-a-black-box.md) and [ADR 0055](../adr/0055-adopt-a-running-agent.md). This page keeps
the design, the limits and what was tested.

## The goal

Tego should govern any agent, Claude Code and Codex being only examples, as a black box: it never needs to know what the agent
is. It should handle the full interactive agent, not only a one-shot form, watch it the whole time it runs, record what it does,
and, where a rule says so, refuse an access and keep the agent inside a declared cage.

## The fact that shapes the design

Tego has two ways to see an agent, and they differ by when Tego arrives.

- **Tego starts the agent** (`tego run <contract>`). It installs a seccomp filter and Landlock before the agent's first
  instruction and sets the agent's environment, so model traffic goes through the forwarder. This needs no root, and
  Tego is there from the first step.
- **The agent is already running.** A seccomp filter and Landlock are self-imposed and cannot be added from outside, and a
  running process's environment cannot be changed. What a root watcher can still do is attach kernel programs (cgroup BPF and the
  decision plane) to the agent's control group and see and decide its file, exec and network actions from the kernel.

So the black-box, already-running case is a root, kernel-side job.

## The design: three milestones, record first

The agent is a black box throughout. The only agent-specific thing anywhere is a short, editable list of signatures (a binary
name, a path, or an argv pattern such as `node .../cli.js`). The watcher governs a matched process and its descendants, and
nothing else on the machine. Root can always list and remove the watcher's kernel programs.

### M1: record a launched black box

`tego watch -- <any agent>` launches the unchanged agent under a generic "record everything, deny nothing" contract. This is the
observe-only backend (`internal/runtime/enforce/observe`): the tier-1 filter records every exec, write and connect, and no rule
refuses anything. Tier 1's fixed syscall guards still answer `io_uring`, `openat2`, `clone3` and `open_by_handle_at` with "not
implemented" and refuse the terminal-input ioctls and MPTCP. None of those, nor truncate, chmod, chown, setxattr or a unix socket
bound to a path, is recorded. A live view streams the trace. This needs no root.

### M2: the resident watcher

A watcher listens on the Linux proc connector (`NETLINK_CONNECTOR`, `PROC_EVENT_EXEC`: the kernel's own exec notifications, which
need `CAP_NET_ADMIN`, not BPF). On every exec it checks the new process against the signature list. On a match it can adopt that
process's control group into a governed run and record its actions from the kernel, using the cgroup programs and the plane in
observe mode. It also flags any matched agent that started outside a governed run. Nothing that is not a matched agent, or its
child, is touched.

**Detection** is `tego agents [--signature <rule>]... [--follow] [--children] [--json]`. It names the agent processes on the
machine and, with `--follow`, reports each one as it starts and exits. It only observes: it reads `/proc/<pid>/{stat,exe,cmdline,
environ,cgroup}` and the kernel's process events, and it never signals, moves, blocks, traces or changes any process, writes to
no cgroup, and starts nothing. It needs root of the initial user namespace and says so (exit 125 `[privilege]`) when it is not.
Adopting what it finds, `tego adopt` and `tego agents --follow --adopt`, is ADR 0055 and [OPERATIONS.md](../OPERATIONS.md).

Four small packages under `internal/watch`, each testable without the next:

| Package | What it does | Pure? |
|---|---|---|
| `procconn` | the proc connector: decode fork, exec and exit; a listener that `Close` can wake, that reports an overflow (`ENOBUFS`) as `IsOverrun` and that `Drain`s what survived | decoder: yes |
| `sig` | recognises an agent from facts the caller supplies (exe, argv, comm, the exe's file identity) against a list of rules | yes |
| `tree` | follows a recognised agent's descendants from fork and exit events; bounded; repaired from a `/proc` snapshot | yes |
| `watcher` | reads `/proc` for each event, applies the rules, drives the tree, writes one sighting per fact | no |

**Signatures** are data. A rule is a basename (`claude`: the program, `argv[0]` or `comm` is that name), an exact path, an argv
pattern (`web=node .../web/cli.js`: the program, then arguments in order, each a glob), or a file identity
(`pin=file:<dev>:<inode>`: the binary, whatever it is called). The shipped list names `claude`, `codex`, `opencode` and `gemini`,
each by its program and by its node entry point. `--signature` adds a rule, replaces every shipped rule of the same name, or
(`gemini=`) removes it, and `--no-default-signatures` starts empty.

**Sightings** are one line each, JSON with `--json`, printable text otherwise:

| Event | Meaning |
|---|---|
| `agent_started` | a process a rule names: pid, ppid, exe, argv (at most 4 KiB), comm, the rule, `seen` (`exec`: the kernel said so; `scan`: `/proc` held it when the watcher looked) and `outside_governed_run` |
| `agent_exited` | the agent's own process exited: status or signal (absent when only a scan saw it go), its descendants counted, and how many still run |
| `child_forked`, `child_exec`, `child_exited` | with `--children`: each process an agent's session starts |
| `session_dropped`, `untracked` | the watcher's bounds were reached; it says so, and which agent it stopped following |
| `resync` | the kernel dropped events and `/proc` was read again |

`outside_governed_run` is true when the agent's cgroup is no Tego run's. The `TEGO_RUN_ID` in its environment is reported
(`run_id`) and not believed: every child of a governed process inherits it, so an agent whose environment names a run but whose
cgroup does not is outside, and a cgroup that names a run with no variable is inside.

**Following.** A fork of a followed process joins its session; threads are not processes. A process leaves when none of its
tasks runs. A wrapper and the program it starts are one session: a descendant is never a second agent. Memory is bounded: 64
sessions and 8192 processes by default. Past either, the oldest session is dropped whole and a `session_dropped` line says so,
and a single session that alone fills the process cap stops growing and counts what it refused (`untracked`). A pid reused after
a missed exit is told from the process it replaced by its start time.

**When the kernel drops events.** The proc connector delivers into a socket buffer (4 MiB is asked for), and a fork storm can
overflow it: `recvfrom` then fails with `ENOBUFS`. The watcher reads the events that survived, scans `/proc` once, and reconciles:
a followed process that is gone is ended, a descendant that was missed joins its session, and a process a rule names that no
session holds is reported as seen by `scan`. The same scan runs once at start, so agents already running are listed.

### M3: the cage

A contract with deny rules (for example: no read of `~/.ssh`, no run of a program outside the allow list, no write outside the
workspace), enforced by the decision plane. The plane decides which program runs, never its arguments, so `tego adopt --boundary`
refuses a command rule such as a ban on `git push`. A denied access shows in the ledger as a refusal. Without `bpf` in the boot LSM list, the plane runs in
`fmod_ret` mode (see [TIERS.md](../TIERS.md)).

## Limits

- **It cannot make an already-running process safer.** Nothing here confines an agent that is already running until it is moved
  into a cgroup of its own. The agent shares its cgroup with the user's terminal and whatever else the user started there, so
  attaching programs to that cgroup would govern the terminal. Detection deliberately does not move anything; adoption does, and it
  needs a fresh cgroup.
- **A process that exits before `/proc` is read is not seen** (counted in the watcher's `Skipped`; a `--version` that ends in a
  few milliseconds is the usual case). An agent that starts and ends wholly inside an overflow is seen by neither an event nor the
  scan. A process that execs twice quickly is read at each exec event, but a read can land on the later image.
- **A rule is a name, no more.** Any program called `claude` matches `claude`, and renaming a binary defeats a name rule (the
  file-identity rule is for that). An argv pattern matches arguments in order with anything between them. Evading detection is not
  something this tries to prevent: it governs the operator's own agents, not an adversary.
- **A thread-group leader that exits while other threads run** does not end the process. The process is followed until its last
  thread exits, and its status is printed only where its threads' exit codes agree on it (ADR 0055, "What was measured"); else
  the line says the status is unknown.
- **Cost.** Each exec event costs two reads of `stat` plus `exe` and `cmdline`; a fork of a followed process, one `stat`; the exit
  of a task of a followed process, none. A build that execs thousands of programs a second makes the watcher read thousands of
  small files a second, and may overflow the buffer, which the rescan then repairs.
- **Sightings go to standard output.** `argv` is printed as the process has it, up to 4 KiB, so a key passed on the command line
  would show. Detection writes nothing to a ledger.
- **Root of the initial user namespace only:** the proc connector is a multicast netlink group that needs `CAP_NET_ADMIN`, and
  another user's `environ` and `exe` are root's to read.
- **No model traffic from an adopted agent.** The watcher records connections, not their plaintext, unless the agent was started
  with the forwarder environment (M1) or its own settings point at it.
- **A few instructions may run between exec and adoption.** A contract that must hold from instruction zero wants the launch path
  (M1), not adoption.

## What was tested

Table tests for `sig` and `tree` (races, a missing `/proc` entry for a process that already exited, a pid reused, the caps,
`ENOBUFS` repaired from a fake `/proc`), a fuzz target for the rule grammar, and the watcher against a fake `/proc` and a
scripted source, including an overrun between two reads. As root in a KVM guest on the real kernel: a script named `claude` is
found by exec, its child followed and both exits reported; one already running is found by the scan; a program that is no agent
is never reported; there is no overflow on the quiet path; and a real `ENOBUFS` (the buffer made 4 KiB, the watcher held away,
the buffer filled, an agent started and another ended with their events dropped) is followed by a scan that reports each agent
once. `tego agents --follow` was also run end to end in the guest.

## Scope

The watcher governs agent sessions only: processes matching the signature list and their descendants. It does not monitor or
control other processes, users or the host. Root keeps full visibility and can remove it at any time. It is consensual audit and
control of the operator's own AI-agent processes on the operator's own machine.
