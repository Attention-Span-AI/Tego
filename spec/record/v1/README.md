# Run record v1

One `events.jsonl` per run, one JSON object per line, written with one `write(2)` on `O_APPEND`. Readers ignore an
unterminated last line. Bodies live in `blobs/` and are referenced by hash: `blob` names the file `blobs/<blob>` that
holds a body whole (unless the event carries `truncated`, below), and a request body stored by its conversation's elements has no `blob` (see `ssl_request`). `v: 1` is
frozen at M0 as this field list; within v1 only optional fields may be added and readers ignore unknown fields (`docs/VERSIONING.md`).

Every event: `v`, `seq`, `id` (sha256 of the line bytes as written), `prev` (id of the previous line), `ts`,
`mono_ns`, `run`, `agent`, `pid`, `tid`, `cgroup`, `kind`, `source`
(`kernel|landlock|seccomp|fanotify|ssl|forwarder|hook|python|node|supervisor|proxy`).
*Amended 2026-09-24:* a `tid` of `0` means the producer could not know the thread. The forwarder's `ssl_request`,
`ssl_response` and `decision` lines carry the `pid` of the run's process that held the connection and `tid` `0`,
since a socket belongs to a process (they carried the launcher's own `pid` and `tid` before;
`docs/p0/capture-derive.md` R34). A tier 2 fanotify refusal (`source: fanotify`) carries the opener's `tid`,
reported by `FAN_REPORT_TID`, and its separately resolved thread-group `pid` (zero if attribution is no longer
available). Exec deduplication uses the thread identity, so a sibling's refused read keeps its own line.
No field changes.

Kinds: `run_start run_end exec fs net mcp ssl_request ssl_response decision ask answer refused gap boundary limit`.
*Added 2026-09-29 (ADR 0016 step 3):* one action has one line, from one producer per (tier, kind, outcome). Tier 1
and an observe run: the supervisor (`source: seccomp`, `supervisor` for net) for every notified action. Tier 2 while
its kernel recorder reads the run: the recorder (`source: kernel`) for every fs action its hooks see and for a
continued IP connect; the supervisor for its own refusals, mode changes, every exec, and relayed connects and sends;
the fanotify listener (`source: fanotify`) for an open it refuses after Landlock let it through
(`docs/p0/supervisor.md` R7a). A tier-2 run whose recorder does not read is recorded as tier 1 is.
*Added 2026-09-29 (TIER3-PLAN T9):* where the kernel decision plane runs (tier bpflsm, and tier cgroup with a plane
mode) and the recorder reads the run, a refusal the plane makes on a hook the recorder's fexit wraps (an open,
rename, link, unlink or rmdir) is that fs line itself, never a second one; an exec the plane refuses in `bprm_check`
is the plane's own line (`source: kernel`), and, when the plane decides the run's execs, an exec the supervisor
continues is the kernel's line too, allowed from `sched_process_exec` named by the plane's rule; the supervisor keeps
the execs it refuses itself (`docs/p0/enforce-plane.md` §2.8).

`run_start` carries `launcher_pid`, `launcher_start_ns`, `tego_version` (named so since ADR 0060, with no version move), `commit`, `bpf_hash` (empty in the
unprivileged tier), `tier`, `capture` (the mechanism that runs: `off|forwarder|uprobe`, never the contract's wish, and never a source that
started only to report its own `mechanism-unavailable` gap),
`kernel`, `contract_hash`, `parsers` (`{anthropic, openai, mcp}`), `stop_grace`,
`limits{tokens,cost_usd,wall,stall_after,repeats}` (the compiled values, so views never re-run the compiler; a key is
present exactly when the run had that budget, and `0` is a budget), and the optional `capabilities` (the run's
capability line: one boolean per row of `spec/backend/CAPABILITIES.md`, keyed by `pkg/spec/backend`'s row name, every
row written, `true` only for what this run could do; absent in ledgers that predate it), and the optional `stdio`
(`{stdin, stdout, stderr}`, the kind of each descriptor the agent kept from its caller:
`tty|null|char|pipe|socket|file|dir|other|unknown`; additive within v1, 2026-09-24, absent in ledgers that predate it),
and the optional `run_command_grant` (the absolute path of the exec rule the command given after `--` on `tego run`
added for that run, admitted for every exec of that file in the run, which the contract hash does not cover; absent
when the run execs the contract's own command or a declared entry already covered it; additive within v1,
2026-09-24, absent in ledgers that predate it), and the optional `record_minor` (the revision of v1's
optional fields the writer implements, every revision from `1` to it included: a revision is the next free number in
the build that merges it, whatever number a plan expected, so a reader's "absent at revision N or later" holds for
every ledger at N or later (*added 2026-10-25*, `TestRecordMinorsAreContiguous`);
`1`: `run_command_grant` is written for every run that had a grant, so its
absence means none; `2`: `decision_plane` is written for every run of tier `cgroup` or `bpflsm`; `3` to `7` as the
paragraphs below say; `8` (2026-10-16, ADR 0057 D5): held reads and alternates, below; absent, read as `0`,
in ledgers that predate it, whose missing `run_command_grant` says nothing; additive within v1, 2026-09-24), and the
optional `decision_plane` (`lsm|fmod_ret` where the kernel decision plane decided the run's fs actions and execs in
that mode, `fanotify` where tier `cgroup` ran on the listener; absent for a tier with no plane, and in ledgers that
predate it; `docs/p0/enforce-plane.md` R19, I7; additive within v1, 2026-09-30, `record_minor` 2), and the optional
`ask_read_relaxes` (one `{rule, builtin, how}` per built-in `deny_read` entry an `fs.ask_read` entry of the top-level
contract relaxes, a refused read becoming one held for a person: `rule` the `fs.ask_read[...]` entry, `builtin` the
built-in entry's path, `how` `replaces` (at its path) or `inside` (beneath it, the rest still refused); absent when
there is none, which at `record_minor` 9 or later means none; additive within v1, 2026-10-16,
[ADR 0057](../../../docs/adr/0057-fs-ask-read-and-alternates.md) D4).
Kinds `ask` and `answer` are written by the bounded local approval broker (minor 5); `boundary` remains declared for the container roadmap.

Action events (`exec fs net mcp`) carry `rule` (the declared entry or `unmatched`), `verdict`
(`allow|ask|refused|observed`), `authority` (`rule|gate|human`), and

```json
"attribution": {"thread": "t1", "step": 3, "tool_use_id": "toolu_8812", "confidence": "exact|likely|unattributed", "method": "tool_id|tid|time|none"}
```

`method` says which rule tied the action to a step (`docs/p0/capture-derive.md` R34, R42): `tool_id` = the action
fell inside exactly one reply's tool window (the reply asked for the `tool_use` and no request had reported its
result yet), and `tool_use_id` names it; `tid` = the action's thread is the one that made the step's model call, as
the uprobe source named it by its tid; `time` = a single open step by time; `none` = no derivation has run.
`likely` is what this writer gives every attributed action, whichever method: none of the methods observes what
caused an action. `exact` stays a v1 value no writer here produces. `unattributed` = more than one candidate or no
step at all. Views never present `unattributed` as fact. `tool_use_id` is optional within v1 and written, between
`step` and `confidence`, exactly when `method` is `tool_id`, from `record_minor` 29 (`MinorAttribution`; 2026-10-20); a reader accepts a
`tool_id` attribution without one, as v1 always has.

`exec` carries `argv`, `path`, `script` (when a `#!` stage preceded), `stage` on a refusal, and, from the seccomp
supervisor, the optional flags `argv_truncated` (argv cut at its byte budget), `path_search` (a `PATH`-search
candidate, nothing ran), `fileless` (an anonymous image: a memfd, an `anon_inode:`, an unlinked file; `path` is the
kernel's raw spelling) and `dropped` (an image under a write entry changed during the run); each is additive within v1
(`docs/p0/record-ledger.md` §2.2).
At `record_minor` 3 (2026-10-04), terminal kernel exec failures also carry the
actual negative `syscall_ret`; a failure outside a policy hook, such as `ENOEXEC`,
`ETXTBSY` or `ENOENT`, is `observed` rather than an invented policy refusal.
`attempt_path` distinguishes the attempted spelling from a kernel-opened
interpreter or loader path. `argv_from` is `kernel`, `attempt`, or
`kernel-prefix+attempt`; the last preserves `argv_truncated: true` because the
unseen kernel argument tail is not proven. Failed attempts use blocked attempt
metadata. Successful mapped arguments remain authoritative; a verified binfmt
interpreter rewrite can explain their difference from the original attempt.
`by: lsm-chain` and positive `errno` identify a chain refusal whose source is not
a Tego plane decision. These fields are additive within ledger v1; the internal
BPF ring ABI is separately versioned.
`fs` carries `op` (`open|unlink|rename|mkdir|symlink|link|truncate|chmod|chown|xattr`; `link` and `chmod` amended 2026-09-29, `chown` and `xattr` listed 2026-09-30, additive within v1; `chown` and `xattr` appear as the decision plane's attribute refusals below and, from 2026-10-16, as the supervisor's line for a `chown` or an extended attribute set or removed under an `fs.write` gate, which names the syscall's family: its ACL set is `xattr`, where the plane's `inode_set_acl` writes `chmod`), `path`, `path2` (a rename's or link's new name,
a symlink's target), `flags` and, on an aggregate of reads, `count`; and, additive within v1 (2026-09-29, ADR 0016
step 2), the optional `created` (the open created its file), `verdict_from` (`chain`: the verdict is the return of the
kernel's LSM chain, read by the tier-2 record's fexit program; `model`: the tier model's prediction, where the kernel
record carries no return) and, on an `observed` line whose refusal no Tego mechanism explains, `by: other` with the
`errno` the chain returned. Such a line is not a refusal: it has no `reason` and no `refused` mirror
(`spec/reason/REASON-CHANNEL.md`). Absent in ledgers that predate them.
A seccomp-supervised `fs` line's `path` and `path2` (other than a symlink's target) are the pathname the task passed,
joined to its directory and cleaned lexically, except where that pathname holds a `..` component or ends in a `.`
(which the clean drops): there they are
the place the physical walk of the pathname's directory lands, joined with its final component as spelled and never
followed, when that walk succeeded, since a `..` after a symlink cleans lexically onto another file (`out/lk/../e` is
not `out/e` when `out/lk` is a symlink). The rule holds whatever the line's verdict, a refused rename's new name
included. An `exec` line's `path` follows the same rule. The name is taken from the walk the line's verdict and rule
were taken on (for an `exec` line, the walk that reached the image; once an ask holds an open, the walk that pinned
it), never from a second walk. Amended 2026-10-19 (`docs/p0/supervisor.md` R15b, R16b); earlier ledgers carry the
cleaned spelling, ledgers written between the first two amendments of that date name such an end where its fully
followed walk landed (a final symlink's target), and ledgers written before the third can name an end the syscall
follows by a second walk, apart from its verdict's. The verdict and rule of such an end are taken where it is named
or lands, never on the lexical clean (amended 2026-10-19, R15b, R15c: earlier ledgers can carry a `deny_write`
refusal under a target the clean named, on a line naming another file, and name an unfollowed attribute change of a
final `..` or `.` by its clean). An end a syscall makes, removes or renames in its directory (an `unlink`, an `rmdir`, a
`mkdir`, a `rename`'s ends, a `link`'s new name) spelled with a trailing slash is decided at that name, never where a
final symlink leads, as the kernel acts on it (amended 2026-10-19, R15b: earlier ledgers carry, on such a line, the
verdict and rule of the place the link led to: `refused, unmatched` for an `rmdir` of `out/lk/` the `out/` entry grants
and the kernel answered `ENOTDIR`, or `allow` for one Landlock refused).
`exec` and `fs` lines whose verdict the kernel decision plane gave carry, additive within v1 (2026-09-29, TIER3-PLAN
T9), `mechanism: plane`, `decision_plane` (`lsm|fmod_ret`: the mode it ran in) and, on a refusal whose cause the
closed reason set has no code for, `plane_reason` (`refer`: a move out of a stricter tree; `deny-write-ancestor`: a
rename of a `deny_write` target or of a directory above one; `identity-mismatch`: a row whose inode no longer
carries its identity; and, on an `exec` line of a pinned run, ADR 0048 (3) P2's `pin-missing`, `pin-mismatch`,
`pin-unverifiable` and `exec-traced`, a bprm_check pin step's refusal, which is `exec-not-allowed` under rule
`exec.pin`; `argv-changed` and `argv-unreadable` are the kill sample's, on the line of an exec the plane killed, as are
`pin-missing` and `pin-unverifiable` there). `reason` stays in the closed set (`rename-outside-contract` or `write-outside-contract`, and
`path-unresolved`, for those three), since a v1 reader validates it; `rule` is the entry the plane's `rule_idx`
names, an `exec.allow` directory's for an exec it matched. Absent in ledgers that predate them.
The decision plane's attribute refusals (TIER3-PLAN T13) are `fs` lines too, additive within v1 (2026-09-29): `op`
`chmod` (a mode change, or a POSIX ACL set or removed), `chown` or `xattr` (an extended attribute set or removed) on a
file beneath a `deny_write` target, `reason: write-outside-contract`, `rule` the target. A socket the plane refused
(its `socket_create`, io_uring's included) is a `refused` line naming the family, type and protocol, as the
supervisor's own socket refusal is, whose payload carries, additive within v1 (2026-09-29), `mechanism: plane` and
`decision_plane`. An inet socket tier 2's `cgroup/sock_create` refused (ADR 0018 PR 2, on a path the seccomp filter
did not decide) is the same `refused` line, `op: socket`, `reason: net-not-allowed`, `rule: unmatched`, whose payload
carries, additive within v1 (2026-10-05), `mechanism: cgroup` and no `decision_plane`, since no plane decided it. An
upper-layer protocol refused under a `net:` section (ADR 0018 (7), additive within v1, 2026-10-17) is a `refused` line
`op: setsockopt`, `target: TCP_ULP "<name>"` (the name as the kernel would have read it, quoted), `reason:
net-not-allowed`, `rule: unmatched`: the supervisor's on `setsockopt(2)`, with no `mechanism`, and tier 2's
`cgroup/setsockopt`'s on any other path, with `mechanism: cgroup`. An executable mapping the plane refused (TIER3-PLAN T14, additive within v1, 2026-09-30) is a
`refused` line too: `op` `mmap` or `mprotect`, `target` the mapped file, the truncated path (with a
`path-truncated` gap) for a named file whose name the kernel could not read, or `anonymous` for a file no path names,
`reason: exec-not-allowed` and `rule: exec-map` (`path-unresolved` and the unmatched rule where the plane failed
closed), with `mechanism: plane` and `decision_plane`.
At `record_minor` 6 (2026-10-05, [ADR 0041](../../../docs/adr/0041-race-free-supervisor-decisions.md) D7),
`run_start` also carries the optional `best_effort`: the stable ids of the run's disclosed best-effort cells, a gate
rule and action whose supervisor decision is taken on copied syscall facts and continued when it does not refuse,
so a sibling thread can change what the kernel then acts on and the cell is never counted as enforced
(`gate.fs.read/open`, `gate.fs.read/move`, `gate.fs.write/open`, `gate.fs.write/mutation`, `gate.exec`,
`gate.net/unix-datagram`, `gate.net/unix-connect`), and, from 2026-10-05 (ADR 0041 D1 (a)), `deny_write/default`:
the built-in `deny_write` set of a run no kernel decision plane decides (tier landlock, tier cgroup on the fanotify
listener), refused by the supervisor on copied pathnames. It is a static property of the compiled contract at the
run's tier and decision plane, not an event; absent at revision 6 or later, the run had none, and absent in ledgers
that predate it.
*Added 2026-11-04 (SEC08, ADR 0041):* the extensible `best_effort` list also discloses
`apparmor/assumed-root-namespace` whenever the top-level contract enables
`fs.apparmor_assume_root_namespace: true` (default false). This records the administrator opt-in even when
no open needed the assumption; it is not a per-open use counter. Hidden ancestor restrictions may differ
when AppArmor namespace depth is unreadable. Other authority facts remain mandatory.
At `record_minor` 7 (2026-10-06, [ADR 0048](../../../docs/adr/0048-exec-command-rules.md) (8)), an `exec` line an exec
command rule decided carries, all optional and additive: `command_rule` (the entry as compiled: `git push`, or the
constrained tool for an unlisted invocation), `command_list` (`deny`, `ask`, `allow` or `unlisted`), `command_match`
(`definite`, or `ambiguous` when the readings of the invocation disagreed; absent on an unlisted refusal, which no
entry matched), `command_via` (the interpretation that
read it: `name`, `image`, `argv0`, `identity`, `dashed`, `multicall`, `interpreter`, `shebang`, `closure`, with
`closure_of` the allowed entry whose helper closure admitted it, or `loader`, the program a dynamic loader run as a
command runs in-process, or `overflow`, a dispatch the matcher could not resolve within its bounds), `argv_facts` (`copied_syscall`: the supervisor's own
copy; `kernel_pinned` and `unproven` arrive with ADR 0048's P2) and `argv_read` (the argv elements the decision
read). A refusal's `rule` is `exec.deny[<entry>]`, `exec.ask[<entry>]` (with `completion_unsupported: true`: the
list is reserved) or `exec.args[<tool>]`, its `reason` `exec-not-allowed`, or `args-unreadable` naming the bound
when the verdict depended on argv past it or no argv[0] could be read, `interpreter-unresolved` when a `#!` interpreter's walk failed,
`image-unreadable` when the image's first bytes could not be read (so its `#!` line could name any ruled tool),
`loader-unresolved` when a dynamic loader run as a command names a program the supervisor cannot read as the loader
will, or `loader-program-unmatched` when no `exec.allow` entry of a restricted run grants that program, or
`codex-home-exec` when, in a deny-list run, the image or a loader's program lies in the run's own `CODEX_HOME`
(added 2026-10-16, agent-contract.md R10a), or
`command-unresolved` when a dispatcher re-dispatches deeper than the matcher resolves, or an exec's reading yields
more interpretations than the matcher keeps, and the exec could still reach a ruled tool (fail closed, `command_via:
overflow`); `reason`'s closed set is unchanged. `refused` payloads may carry
`command_rule` and `command_match` where a command rule itself refused (`command_list` deny, ask or unlisted), not on a sentinel refusal (args-unreadable and the like) nor where the command rule allowed and the gate refused; `run_end`'s `supervisor` block carries `exec_rules` (`refused`, `ambiguous`, `asked`)
for a run with command rules. `run_start.best_effort` lists `exec.rules/argv` for such a run at every tier.

At `record_minor` 12 (2026-10-19, [ADR 0048](../../../docs/adr/0048-exec-command-rules.md) (8), P2), an exec of a run
whose decision plane holds its execs to their decided facts (exec pins) may be refused `exec-not-allowed`, rule
`exec.pin`, with `pin_unavailable: true`: the supervisor could not write the pin that would hold the exec to its
decision (the facts are past the pin's bounds, the image's identity as the plane holds it could not be read, or the
slot's pin map is full of live pins), so it refused the exec, which the kernel would otherwise refuse or kill. The
plane's own pin refusals are its `refused` lines with the `plane_reason` values above. An exec the plane killed at
`sched_process_exec`, before the new program's first instruction, because its mapped argument area was not the one its
pin covers (or could not be read, or no pin was armed) is one `refused` line, rule `exec.pin`, `signal: SIGKILL`, its
`plane_reason`, `argv` the kernel's mapped vector (`argv_from: kernel`) and `argv_decided` the vector the decision read;
when the kernel could not send the kill, `kill_failed` is the helper's errno and `detected_bypass: true` (the launcher
then killed the process through its pidfd, late), with the integrity gap `exec-pin-kill-failed`. No line says `allow`
for an exec the plane killed. A pinned exec that ran says `argv_facts: kernel_pinned` only when the plane's held sample
of the pin its decision wrote arrived; otherwise (a ring loss, another pin) `unproven`, with the gap
`exec-pin-unproven`. `run_end.supervisor.exec_rules` counts `killed`, `kill_failed` and `pin_refused` (bprm_check's pin
refusals and `pin_unavailable`), each absent when zero.
At `record_minor` 8 (2026-10-16), an exec whose pathname names nothing (the supervisor's walk, made as the task's
own lookup, met `ENOENT` or `ENOTDIR`) writes no `exec` line and no `refused` mirror at any record level: the
supervisor answers that errno itself, in an observe run too (never continued, so no later lookup can run what the
walk did not find), nothing was named, decided or run, and a program started by name (`execvp`,
one `execve` per `PATH` directory) otherwise left one line per directory tried. `run_end`'s `supervisor` block
counts them in the optional `exec_missing` (absent when there were none). `path_search` then marks only a candidate
that holds a file. In a ledger below revision 8 such an exec has a line: refused `unmatched` in a restricted run,
observed `path_search` for a candidate, observed in a run with command rules, allow `unmatched` in a run with no
`exec:` section. A walk the task's own lookup may not make the same way is no miss and keeps its line: one through a
procfs magic link or directory of a process outside the task's own thread group (the kernel lets the task in only
when it may ptrace that process, or see it under `hidepid`, so a failure there is `EACCES`), one through a
directory at tiers cgroup and bpflsm on a filesystem outside the closed list of those whose permission operation
reads only the mode bits and access ACL (FUSE, NFS, SMB, Ceph, kAFS, 9p, ZFS and any other: its server or daemon may
decide by the caller's credentials, so a failure there is `EACCES`), and one that failed at an automount point, an
autofs directory or any stub its
filesystem marks automount (NFS, CIFS and FUSE submounts, debugfs's `tracing`: the kernel's walk mounts an idle
automount point the supervisor's does not), looking a name up there or, since 2026-10-17, stepping `..` out of it.
Each is decided as before revision 8, and its line is that decision's:
refused (observed for a `PATH` candidate or under command rules) where the supervisor decides the run's execs,
`allow` and continued for a granted spelling or under a contract with no `exec:` section, the kernel recorder's
where a decision plane takes the exec (2026-10-16, supervisor R16b (0) and *the walk*).
At `record_minor` 13 (2026-10-20, [agent-contract.md](../../../docs/p0/agent-contract.md) R26), `run_start` also
carries the optional `contract_source`: the contract file the launching user named, `{"path": <absolute path>}` (the
file read: a `..` after a link in the path given is taken from the link's target, as the open took it), with
`"name"` and `"registry"` (`project` or `user`) when it was resolved from an agent name (`tego run retriever`). It
is the file whose bytes the run compiled: `contract_hash` says what the contract was, `contract_source` where it came
from. Absent at revision 13 or later, tego generated the contract (`watch` or `adopt` with no `--boundary`); absent
in ledgers that predate it.
At `record_minor` 14 (2026-10-24, [agent-contract.md](../../../docs/p0/agent-contract.md) R27,
[ADR 0062](../../../docs/adr/0062-harness-provisioning-point.md)), `run_start` also carries the optional `harness`:
`{"name", "provisioned", "why", "files", "reason_file", "state_dir"}`. `name` is the harness the run was provisioned
for, resolved (`claude-code`, `codex` or `generic`; `auto` is resolved from the command's basename before the run
starts). `provisioned` says the launcher made the provision: the files it lists in `files` (each made exclusively,
without following a link, `0444` in the run's runtime directory or `0600` in its own `CODEX_HOME`), and the argv and
`TEGO_` environment additions. When it is `false`, `why` says why: `no-provisioner` (this build provisions nothing
for that harness), `reason-unavailable` (no usable runtime directory: no absolute `XDG_RUNTIME_DIR`, or a root
launcher; a `gap` with `what` `record` and `why` `reason-unavailable` follows `run_start`), `hook-refused` (the run's
exec rules refuse the hook the harness would exec on every tool call) or `hook-not-granted` (an allow-list contract,
which granted no hook below revision 20; from it, a hook no exact grant can admit). `reason_file` is the readable
`last-refusal.json` the agent's `TEGO_REASON` names, and `state_dir` the run's `hook-state` directory, the one place in its runtime directory the agent may write, listed in
`runtime_grants` as `fs.harness-state[<path>]` (absent when nothing was provisioned). Absent at revision 14 or later,
the contract says `harness: none` or the run was adopted; absent in ledgers that predate it.
At `record_minor` 15 (2026-10-24, [ADR 0066](../../../docs/adr/0066-extends-list-and-built-in-profiles.md) D6,
[agent-contract.md](../../../docs/p0/agent-contract.md) R5), `run_start` also carries the optional `profiles`: every
profile the run's contract merged through `extends`, in merge order (a profile's own parents before it, a list left to
right), each once, as `{"name": <the extends name>, "source": "builtin" | "dir", "sha256": <hex of the bytes read>}`;
`builtin` is a profile built into tego (a name under `tego/`), `dir` a file of the machine config's profiles
directory. `contract_hash` covers the merged contract, whose entries already hold what each profile gave; `profiles`
says which profiles gave them, so a reader can tell which version of a built-in profile a run merged. Its `source`
sits inside each entry and is no line's common `source`. Absent at revision 15 or later, the contract extends no
profile; absent in ledgers that predate it.
Fixture: `fixtures/profiles.jsonl`.
A `net` line to `family(16)` may carry the rule `route-query`, `allow`, for a read-only `NETLINK_ROUTE` request or a bind of
such a socket, or `route-change`, `refused`, for a message to the kernel on one that is not read-only (2026-11-01,
[ADR 0128](../../../docs/adr/0128-read-only-route-queries.md)). Neither adds a field, so neither has a minor of its own.
At `record_minor` 16 (2026-10-24, [ADR 0070](../../../docs/adr/0070-host-sockets-refused-by-default.md)), a contract
with no `net:` section refuses every unix destination no process of the run bound (a pathname or an abstract name):
its `net` line is `refused` with the rule `host-sockets`, and, when `dst` names a socket on agent-contract R19's list
of well-known daemon sockets, the optional `what` says what reaching it gives an agent (`the Docker daemon,
root-equivalent`); `what` is absent for a socket the list does not name. `run_start` also carries the optional
`host_sockets`, true when such a contract set `host_sockets: true`, the opt-out that restores the host's unix sockets;
its `best_effort` may list `host_sockets/datagram` (tier landlock: the datagram sends the supervisor continues rather
than relays) and `host_sockets/root-tier` (tiers cgroup and bpflsm). Absent at revision 16 or later, `host_sockets`
means the restriction held, or the contract has a `net:` section; a reader of a ledger that predates revision 16
reads a missing `host_sockets` as the old reach, every host socket open to a contract with no `net:` section.
At `record_minor` 17 (`MinorRunIdentity`; 2026-10-25, [ADR 0073](../../../docs/adr/0073-run-identity-on-run-start.md)),
`run_start` also carries the run's identity, each field what the launcher read when the run started and none a
verified fact about a person:
- `launcher_uid` (integer): the launcher's real uid, written on every `run_start` at `MinorRunIdentity` or later, 0
  included; absent only in ledgers that predate it.
- `launcher_user` (string): `launcher_uid`'s passwd name; absent when the passwd database names none, or names one
  that is not UTF-8 or breaks `host`'s character rule (the database is the mount namespace's to replace); so `sudo_user`.
- `sudo_uid` (integer) and `sudo_user` (string): written only when the launcher's real and effective uid were 0 in the
  initial user namespace (not under `unshare -r`) and the launcher process's own `SUDO_UID` (the variable its drop to
  the invoking account reads, never the environment it builds for the agent) was the plain decimal of a uid (not
  `4294967295`); `sudo_user` is that uid's passwd name, never the `SUDO_USER` string, and absent when it has none.
  They are sudo's claim, which any root process can set.
- `host` (string): the launcher's kernel nodename (`uname -n`), at most 255 bytes of UTF-8 with no control, format,
  line or paragraph separator character (a label value's rule: the nodename is whoever holds the UTS namespace's to
  set); absent when it could not be read or breaks that rule, never cut or cleaned. A payload key of `run_start`, as
  of `net` and `ssl_request`, never a common field.
- `parent_run` (string): the run the launcher's environment says this run is nested in, a valid run id: for a
  `tego run` started inside a governed agent the enclosing run's `TEGO_RUN_ID` (that agent's `TEGO_PARENT_RUN` is the
  enclosing run's own parent), else the `TEGO_PARENT_RUN` an orchestrator handed the launcher; absent when it named
  none. It is the environment's claim, not a link tego checked (until nested runs are verified); a launcher refuses a value that
  is not a run id before the run exists.
- `labels` (object of string to string): the caller's labels, at most 32, each key
  `^[a-z0-9][a-z0-9._-]{0,62}$` outside the reserved `tego.` prefix and each value at most 256 bytes of UTF-8 with no
  control, format, line or paragraph separator character; absent when there are none.
- `role` (string): reserved: `check` marks a run a checking command started, and no shipped command sets it; absent
  for the agent's own run. A reader treats a role it
  does not know as a run that is not the agent's own.
- `contract_revision` (string): the contract's `revision` ([agent-contract.md](../../../docs/p0/agent-contract.md)
  R28); absent when the contract has none.

At `MinorRunIdentity` or later an absent optional field among these means the run had none.
Fixture: `fixtures/run-identity.jsonl`.
At `record_minor` 18 (2026-10-24, [ADR 0069](../../../docs/adr/0069-held-reads-make-deny-read-true-at-tier-landlock.md)
D4), `run_start` carries `fs_reads` on every run: `{"reads": "held" | "direct", "why": ..., "nested": [<rule>...]}`.
`held` says the run held its read opens: the open deputy completed every read-capable open and the supervisor refused
one on the object it reached, so a `deny_read` inside a write entry held at tier landlock; `direct`, reads went to the
kernel as they were. `why` is `contract` (`fs.reads: held`), `nested` (`auto` at tier landlock with a target inside a
write entry), `contract-direct` (`fs.reads: direct`), `none-nested` (`auto`, no such target), `kernel` (`auto` at a
root tier, whose kernel refuses such a target itself) or `records-only` (a run that enforces nothing). `nested` names
those targets by rule, absent when there is none. A held read's `fs` line is the ordinary one: its `path` is the object
the deputy reached (as `gate_facts: held_object`'s is, record_minor 10), and an allowed one is written only where the
record mode keeps reads or a read gate scores it; a refusal is `read-denied` under the entry that refused it, a name
rule's label (`fs.deny_read[<scope>/**/.env.*]`) for a file no table row names. Absent in ledgers that predate it.
Fixture: `fixtures/held-reads.jsonl`.
*Added 2026-10-26 (ADR 0069's note of that date), no new minor or code:* an `fs` open or an `exec` the tier-1
ruleset refuses because its `deny_read` enumeration froze at launch (a name made, or a listed file replaced, beside an
ancestor of an enforced target after the run started) is `refused`, reason `read-denied`, rule `deny-read-snapshot`,
authority `rule`, whether this loop refused it (it answers the kernel's own `EACCES`) or a held read's deputy met that
`EACCES` (then with `syscall_ret: -13`). Such a line was `allow` before; a reader that keys on `fs.deny_read[...]`
rules for read refusals sees these as a refusal no declared entry names.
*Added 2026-11-02 (GAPS A10, supervisor R36), no new minor:* a watch the supervisor refuses, an `inotify_add_watch`, a
`fanotify_mark` adding a mark or a dnotify `fcntl(F_NOTIFY)` whose object the run withholds a read of, is a `refused`
line, `op` `inotify_add_watch`, `fanotify_mark` or `fcntl` (the last also names a refused `F_SETOWN`, reason
`landlock-topology`, R33), `target` the name watched (a descriptor's own file by its path), and the rule and reason a
read of that object is refused with: reason `read-denied`, rule the `deny_read` entry (the `fs.ask_read` entry's own
beneath one), a name entry's or name rule's label, `fs.deny_read[<tego's own state>]` in a run that holds its reads, or
a live block's or fence entry's (`live.block[read:...]`, `live.block[path:...]`, `live.fence[read:...]`); reason
`path-unresolved`, rule `unmatched`, where a name entry's climb could not decide; or reason `read-denied` with
`args-unreadable`, `path-truncated`, `path-unreliable` or `fd-unreadable` where the name or the descriptor could not be
read. A fanotify mark of a whole mount, filesystem or mount namespace is refused (`EPERM`) under the rule
`deny-read-watch`. A watch that is continued has no line: v1 has no watch kind. Before, no watch was refused or
recorded, so a ledger without such a line says nothing about watches.
At `record_minor` 19 (`MinorUserDenyWrite`; 2026-10-25, [ADR 0071](../../../docs/adr/0071-user-deny-write.md)), a contract may declare
its own `fs.deny_write` entries: a modification at or beneath one is refused with the rule `fs.deny_write[<entry as
declared>]` (`fs.deny_write[./deploy/]`), the entry's text as the author wrote it, where a built-in target's rule holds
its resolved path (`fs.deny_write[/home/u/proj/.git/hooks]`); the line's `source` is `seccomp` where the supervisor
refused it and `kernel` with `mechanism: plane` where the decision plane did. `run_start.best_effort` may list
`fs.deny_write`, apart from `deny_write/default`, where no decision plane decided the entries (tier landlock, tier
cgroup on the fanotify listener): blocked for ordinary commands; not race-free at the no-root tier. Below revision 19
every `fs.deny_write[...]` rule names a built-in target.
Fixture: `fixtures/user-deny-write.jsonl`.
At `record_minor` 20 (`MinorHarnessHook`; 2026-10-25, [ADR 0064](../../../docs/adr/0064-harness-hook-exec-grant.md),
agent-contract.md R27), `run_start`'s `harness.hook` is `{"argv", "granted"}` for every provision that names a hook: `argv` is the hook's exact argv, the tego binary and every
argument, and `granted` says the launcher granted it on its own authority, which an allow-list contract whose own exec
rules do not admit the hook gets: `runtime_grants` then lists `exec.harness-hook[<tego binary>]`, the rule of both the
binary's image grant and the command rule that admits that argv and no other. An exec of the binary with the hook's
argv is `allow` under that rule (its `command_rule` the binary, `command_list` `allow`); an exec of it with any other
vector is `refused` under it, `exec-not-allowed`, `command_list` `unlisted`. At tier landlock the argv is the
supervisor's copy (`argv_facts` `copied_syscall`, `best_effort` `exec.rules/argv`). `granted` is `false` when the
contract's rules admitted the hook themselves (no exec section, a deny-list, or an allow entry naming the binary), and
for a provision that was dropped. `why` may also be `harness-hook-writable`: the binary, or its ELF loader, lies at or
below a write entry or an `fs.ask` scope by a name the launcher sees (a place the mount table shows it included), or
has names it cannot see (more than one link, an unreadable mount table, or one that shows no mount holding it), or a write entry meets a layer, backing file or image beneath its filesystem, or that filesystem is one whose layers cannot be named (FUSE), so no grant is made and the provision is
dropped; from this revision
`hook-not-granted` means only a hook the launcher cannot grant exactly (another program than the tego binary, no ELF
binary, a set-id one, or a name a bare entry or an implicit grant keeps at any arguments), and `hook-refused` also a binary or loader under a `deny_read`
entry. Absent at revision 20 or later, `harness.hook` means the provision named no hook; below it, every allow-list
contract's provision with a hook was dropped `hook-not-granted`.

At `record_minor` 21 (`MinorLiveBlock`; 2026-10-25, [ADR 0100](../../../docs/adr/0100-second-binary-and-handoff.md)'s
implementation note "Live blocks"), a running run can be given live blocks (`tego block`, the dashboard's Block now):
entries of kind `exec` (a program: an absolute path, a directory ending in `/`, or a bare name), `net` (a host or
address with an optional port, a unix socket path or an `@` abstract name) and `path` (a path and everything beneath
it), which the run's supervisor refuses on top of the contract. Live blocks only tighten: an action a live block
matches is refused with the rule `live.block[<kind>:<value>]` (`live.block[exec:curl]`,
`live.block[net:example.com:443]`, `live.block[path:/home/u/proj/.env]`) and the reason its kind always has
(`exec-not-allowed`, `net-not-allowed`, or the fs operation's), and removing a block allows only what the contract
allows. A refusal this loop already makes keeps its own rule. Every add and remove is a `gap` line `what=enforce`,
`why` `live-block-added` or `live-block-removed`, written when the launcher puts it in force (within about a second),
with `live_block` `{op, kind, value, rule, by, serial, at}`: `op` `add` or `remove`, the block's normalized `kind` and
`value`, the `rule` its refusals carry, `by` who made the change (`uid:<uid> pid:<pid> cli` or `... dashboard`, as the
writer saw itself), `serial` the change's number in the run's overlay (from 1, one per change) and `at` when it was
made. An overlay the launcher could not read (malformed, not a regular file, owned by another user, or writable by
others) is one `gap what=enforce why=live-block-unreadable` per state of the file, and the blocks it read last stay in
force; changes the overlay no longer held when the launcher read it (it keeps the newest 256) are counted in one
`gap what=enforce why=live-block-lost` line's `count`. Below revision 21 no rule is `live.block[...]` and no gap names `live_block`.
Fixture: `fixtures/live-block.jsonl`.

At `record_minor` 22 (`MinorLedgerCap`; 2026-10-26), a machine config's `record.max_run_bytes` bounds one run's
`events.jsonl` and blobs together: `run_start.limits.ledger_bytes` is the ceiling the run was started under, and once
they hold that many bytes (checked at each line the run's pipeline records and once a second, so it passes the ceiling
by the lines in flight) the run is ended as a limit: one
`limit` line `which=ledger_bytes`, `value` the bytes they held at the check and `ceiling` the setting, with no
`reason` (the closed reason set has no code for it, and a `limit` line's reason is optional), then
`run_end reason limit`, exit 124. Blobs count from 2026-11-01; before that `value` was `events.jsonl` alone. The ledger is not rotated: the run ends and a unit that restarts it starts a
new run with its own ledger and chain. Absent at revision 22 or later, `limits.ledger_bytes` means the run had no
ceiling; below it no `limit` line is `which=ledger_bytes`.

At `record_minor` 23 (`MinorReasonReads`; 2026-10-26, [ADR 0077](../../../docs/adr/0077-reads-recorded-for-the-reason-channel.md)), `run_start` carries
`reads_notified` on every run: `{"notified": true | false, "why": ...}`. `notified` says tier 1's seccomp filter told the
supervisor of every read open of the run, so a read the Landlock ruleset refuses under `deny_read` wrote a refused line
under every record mode; not notified, under `record: summary` or `off` such a refusal was Landlock's alone and wrote
none. `why` is, when notified, `record-full`, `gate` (an `fs.read` gate), `ask-read` (an `fs.ask_read` entry), `held`
(the run held its reads, `fs_reads`) or `reason` (`reason.reads` at tier landlock); when not, `reason-off`
(`reason.reads: off`, or `auto`, ADR 0077's measured default), `kernel` (a root tier, whose kernel record carries a refused read), `records-only` (a run that enforces nothing) or
`no-supervisor` (no started supervisor answered the run's notifications). At the same revision a read open the
supervisor continued at tier landlock and the Landlock ruleset then refused is its `fs` line, `refused`, `read-denied`
under the entry, from `seccomp`, with `mechanism: landlock` (additive within v1): the supervisor wrote it from the
ruleset's own model of the path before the kernel answered, as a refused write's line at tier 1 is; its `refused` mirror
carries the action line's `mechanism` and `decision_plane` (a plane's refusal's too, from this revision). Absent in
ledgers that predate it. Fixture: `fixtures/reason-reads.jsonl`.

At `record_minor` 24 (`MinorLiveControl`; 2026-10-27, beside revision 21's live blocks), a person can
pause and resume a running run (`tego pause`, `tego resume`, the dashboard's Pause and Resume), and a live block may
also be of kind `read` or `write`.
- A pause and a resume are changes in the run's overlay, numbered in one sequence with its live blocks' changes. The
  launcher reads them in serial order and applies each to the run's cgroup in turn (a pause freezes every process of
  the run, a resume thaws them), then writes one `gap` line `what=enforce` per change, carrying `live_control`
  `{op, by, serial, at}`: `op` `pause` or `resume`, and `by`, `serial` and `at` as `live_block` has them (who made
  the change, its number in the overlay, when it was made). The line's `ts` is when the launcher applied it. Its `why`
  is `run-paused` (a pause in force: the run's cgroup was frozen, or already was), `run-resumed` (a resume in force:
  the cgroup was thawed, or was not frozen, as after a pause that failed), `pause-failed` (a pause the launcher could
  not apply: the run was not frozen and kept running) or `resume-failed` (a resume it could not apply: the run stays
  frozen until a later resume or its stop). A run is paused from its `run-paused` or `resume-failed` line until a
  later `run-resumed` line or its `run_end`. A run stopped or ended while paused is thawed by the launcher first; that
  thaw is not a person's change and writes no line.
- A live block of kind `read` names a path and everything beneath it and matches read opens only; one of kind
  `write` names the same and matches every modification there (write opens, creates, unlinks, renames at either end,
  mkdir, links and symlinks); `path` still matches both. An action one refuses carries the rule
  `live.block[read:<path>]` or `live.block[write:<path>]` (`live.block[read:/home/u/proj/.env]`,
  `live.block[write:/home/u/proj/src/]`) and the fs operation's reason, as `path`'s does, and its `live-block-added`
  and `live-block-removed` lines carry `live_block.kind` `read` or `write`.
- A launcher that does not know a change's op or a block's kind (every launcher below revision 24) reads an overlay
  that holds a pause, a resume or a block of kind `read` or `write` as unreadable (`gap what=enforce
  why=live-block-unreadable`): it keeps the blocks it read last and freezes nothing.
- Nothing at this revision is written on every run: a ledger at 24 or later with none of these lines had no pause and
  no `read` or `write` block.

This build's `Event.ValidateAt(minor)` holds a gap line's live changes, in a ledger of any revision: `live_block` is
on a `gap what=enforce` whose `why` is `live-block-added` (`op` `add`) or `live-block-removed` (`op` `remove`) and
only there, every such line has one, its `kind` is `exec`, `net`, `path`, `read` or `write`, its `value` is not empty,
its `rule` is `live.block[<kind>:<value>]` and its `serial` is 1 or more [`live-block`]; `live_control` is on a
`gap what=enforce` of one of the four whys above and only there, every such line has one, with the `op` its `why`
names and a `serial` of 1 or more [`live-control`]. Below revision 24, one of those whys, a `live_control`, a
`live_block.kind` `read` or `write`, and a `live.block[read:...]` or `live.block[write:...]` rule on any line are
refused [`below-minor`]. A key a case-insensitive reader would take for `live_block`, `live_control` or one of their
members but spelt otherwise is refused [`field-case`], and a null, a repeated name or a value of the wrong type inside
either by its field's code. `by` and `at` are not checked: the launcher copies them from the overlay, which the run's
user writes, and a line refused here would be a change the ledger never records; for the same reason a field the
Writer moved to a blob (`live_block_blob` or `live_control_blob`, a change past the blob threshold) stands for the
field and is not read. The Writer and Verify apply these
rules as they do the reserved fields' below. Fixtures: `fixtures/live-control.jsonl` (a run) and `fixtures/live` (a valid
and an invalid document for each rule).

At `record_minor` 25 (`MinorCredentialsAndMCPTools`; 2026-10-27, [ADR 0126](../../../docs/adr/0126-mcp-tool-rules.md)
D1), a run can use credentials it never holds and per-tool MCP rules.
- **Credentials.** A `net` line of source `forwarder`, `op: http_request`, may carry `credential` `{name, version}` under
  the rule `credential[<name>]`, `allow` or `refused` with reason `credential-not-allowed`, `credential-revoked` or
  `credential-unavailable`. These fields are reserved: this build refuses `credentials:` at compile and writes no such
  line. No value is ever on a line, a blob or a log.
- **MCP tools.** An `mcp` line of source `proxy` (Tego's own MCP relay) records each `tools/call` decision: `allow` under
  `mcp[<s>].tools.allow[<tool>]`, `mcp[<s>].live[<tool>]` or `mcp[<s>]`, authority `human` after an approved ask, or
  `refused` with reason `mcp-tool-denied` under `mcp[<s>].tools.deny[<tool>]`, `mcp[<s>].tools.allow` (not on the
  list) or `mcp[<s>].live[<tool>]`, or the broker's `ask-denied`, `ask-timeout`, `ask-unavailable`. A call whose tool the
  relay could not name, and a client message it could not read at all, is `refused`, `mcp-tool-denied`, under
  `mcp[<s>].relay` with no `tool`. A declared stdio
  server started by anything but a child of an admitted shim is refused under `mcp[<s>].relay`, `exec-not-allowed`. A person's live switch is a
  `gap` `what=enforce` `why=mcp-tool-changed` with `mcp_tool` `{server, tool, decision, by, serial, at}`, `decision`
  `allow`, `ask`, `deny` or `reset`.
- Nothing at this revision is written on every run: a ledger at 25 or later with none of these lines injected nothing
  and relayed nothing.

`Event.ValidateAt(minor)` holds them: below revision 25 the four reasons, the rules `credential[...]`,
`mcp[<s>].tools.*`, `mcp[<s>].live[...]` and `mcp[<s>].relay`, a `credential`, a `why` `mcp-tool-changed` and an
`mcp_tool` are refused [`below-minor`]; `credential` is on a `net` line only, its `name` matches `^[a-z0-9-]{1,40}$`
and an allowed line names a `version` of 1 or more [`credential`]; `mcp_tool` is on a `gap what=enforce
why=mcp-tool-changed` and only there, every such line has one, with a `server`, a `tool`, a `decision` of the four and
a `serial` of 1 or more [`mcp-tool`]; a key a case-insensitive reader would take for either is refused
[`field-case`]. `by` and `at` are not checked, as `live_block`'s are not. Fixtures: `fixtures/credential-mcp.jsonl`
(a run, generated through the real Writer) and `fixtures/credmcp` (a valid and an invalid document for each rule).

At `record_minor` 26 (`MinorLiveModes`; 2026-10-27, [ADR 0125](../../../docs/adr/0125-locked-and-adjustable-modes.md)),
a live change may have a time limit, and a run may be Adjustable.
- A live block, an unblock (a remove), and on an Adjustable run a lift, may end by itself at an instant. Its
  `live-block-added`, `live-block-removed` or `live-rule-lifted` line carries it as `live_block.until`. The launcher
  judges it on the wall clock and on `CLOCK_BOOTTIME` (a block ends only when both have passed it; an unblock or a lift
  as soon as either has), and writes one `gap what=enforce` line, `op` `expire`, with the `until` that passed, when it
  ends: `live-block-expired` (the block refuses nothing from then on), `live-unblock-expired` (the block refuses
  again) or `live-lift-expired` (the fence entry is refused again). Each is written once.
- An Adjustable run's `run_start` carries `live_mode` (`adjustable`, the only value) and `live_fence`
  `{sha256, entries[{kind, value, source, rule, name}]}` together, and a Locked run carries neither. `kind` is `read`,
  `net` or `exec`; `source` is `deny` (one of the contract's own refusals, which the fence takes out) or `new` (access
  the contract does not have); `rule` is `live.fence[<kind>:<value>]`; `name`, only on an exec entry of source `deny`,
  is the bare program name of the `exec.deny` entry it takes out; at most 64 entries, `[]` for an empty fence.
  `sha256` is the SHA-256 of the JSON array `[{"Kind","Value","Source","Name"}]` of the entries in order, `Name`
  left out when empty, so a reader recomputes it from the record.
- The launcher writes, from its own state and never from the writer's change list: `live-rule-lifted` (`op` `lift`,
  a fence entry it allowed, a lift or a grant), `live-rule-restored` (`op` `restore`, a lifted entry refused again)
  and `live-lift-refused` (`op` `lift`, a lift it did not apply), whose `live_block.refused` says why: `mac` (the
  lift's MAC did not check under the run's key, or was already used: a replay), `outside-fence`, `locked` (the run
  is Locked) or `until` (its limit had passed). These lines carry the rule `live.fence[<kind>:<value>]`, except a
  refused lift that names no fence entry of the run: `outside-fence` and `locked` always, and `mac` for a lift outside
  the fence, carry the request's rule `live.lift[<kind>:<value>]`, so no line names a `live.fence[...]` rule that
  `run_start.live_fence` does not list.
- A refusal by a fence entry, and an action allowed only because one is lifted, carry the rule
  `live.fence[<kind>:<value>]`, never a contract rule: the ledger never says the contract allowed what Tego's live
  layer allowed.
- An overlay with a time limit is version 2, and one with a lift or a restore is version 3. A launcher below this
  revision reads either as unreadable (`why=live-block-unreadable`), keeps the blocks it read last and loosens nothing.
- Nothing at this revision is written on every run: a ledger at 26 or later with no `live_mode` is a Locked run, and
  one with none of these lines had no time limit.

`Event.ValidateAt(minor)` refuses below 26 a `live_block.until`, a `live_block.refused`, each of the six whys above, a
`live_mode`, a `live_fence` and a `live.fence[...]` rule on any line [`below-minor`]. At 26 or later: the three expiry
whys need `until`; `refused` is on `live-lift-refused` only, always there, and one of the four values; a fence why's
`kind` is `read`, `net` or `exec` and its `rule` is `live.fence[<kind>:<value>]`, or on `live-lift-refused`
`live.lift[<kind>:<value>]`, either for any `refused` value (a launcher built before the launcher's fence, whose timed-block form at this revision
wrote every refused lift under `live.fence[...]`; the fence launcher writes `live.lift[...]` where the lift names no fence entry, so
a reader takes both and the two builds agree) [`live-block`]; `live_mode` is
`adjustable` and comes with `live_fence` [`live-mode`]; `live_fence.sha256` is 64 lower-case hex digits and each entry
is well formed, with a `value` of at most 4096 bytes, a `name` only on an exec entry of source `deny`, and listed
once [`live-fence`]. `live_mode` and `live_fence`
are never moved to a blob. Fixtures: `fixtures/live` (`live-block-*-until`, `*-expired`, `live-rule-*`,
`live-lift-*`, `run-start-adjustable*`, `refused-fence-rule`, and an invalid document for each rule).

At `record_minor` 27 (`MinorModelRoutes`; 2026-10-27, [ADR 0127](../../../docs/adr/0127-model-routes.md)), a person
may send a `models[]` endpoint's requests to one of the backends its `routes:` declares (agent-contract.md R32), and
back, while the run lives.
- Every `ssl_request` of an endpoint that declares routes carries `route {name, authority}`: the route the forwarder
  sent it by (`direct` for the endpoint itself) and that backend's `host:port`. `host` and `endpoint` stay the
  declared endpoint's, so derive and drift read the exchange as before. The `net` line of a credential injected into,
  or refused for, such a request carries the same `route`, and its `dst` and `http_authority` are the route's backend.
- Each route change the forwarder put in force is one `gap what=enforce` line, source `forwarder`, why
  `model-route-changed`, with `model_route {model, route, authority, by, serial, at}`: the endpoint (its declared
  `host:port`), the route now in force (`direct` for a revert) and its backend, who made it (`uid:<uid> pid:<pid>
  <via>`), its serial in the run's `model-routes.json` (from 1) and when. The lines of one endpoint follow the serial
  order; lines of two endpoints served by two listeners may interleave in either order. A route already set when the
  forwarder first reads the overlay gets a line from the overlay's entry. When the
  routes in force move with no change to say so (the overlay removed, or replaced by one whose serial went down or
  started again, or naming a route the contract does not declare), the forwarder writes a line per endpoint that moved:
  from the overlay's own entry for it when it has one, or else a revert to `direct` with `serial` 0 and `by`
  `forwarder: ...`, since no change numbered it.
- A request held for a person's approval whose endpoint's route moved while it was held is not sent: one `net` line,
  verdict `refused`, reason `model-route-changed`, rule `models[<host:port>].routes` (the declared endpoint), with
  `op http_request`, `dst` and `http_authority` the backend it would have gone to, and its `route`.
- Under `net.proxy`, a CONNECT or WebSocket upgrade to an endpoint on a route other than `direct` is refused: one `net`
  line, verdict `refused`, reason `net-http`, rule `models[<host:port>].routes`, `op connect_tunnel` or `websocket`,
  `dst` the declared endpoint, with the `route` in force.
- Nothing at this revision is written for an endpoint without routes: such a run's lines are as at 26.

`Event.ValidateAt(minor)` refuses below 27 a `route`, a `model_route`, the why and the reason `model-route-changed` and
a `models[<host:port>].routes` rule [`below-minor`]. At 27 or later: `route` is on `ssl_request` and `net` lines with a
route name (`^[a-z0-9-]{1,40}$`) and an `authority` of `host:port`; the reason `model-route-changed` is on a refused
`net` line that names its `route`; `model_route` is on a `gap what=enforce why model-route-changed` and only there,
every such line has one, with `model` and `authority` of `host:port`, a route name and a `serial` of 1 or more, 0 only
on a revert to `direct` [`model-route`]; a member spelt otherwise is refused [`field-case`]. Fixtures:
`fixtures/modelroute`.

At `record_minor` 28 (`MinorFSMutationAsk`; 2026-10-27, [ADR 0047](../../../docs/adr/0047-fs-ask-mutations-made-on-pinned-names.md)), a mutation in an `fs.ask` scope (unlink, rmdir, mkdir, rename, symlink, link) may be held for a
person: its `ask` line carries hold `mutation` and, for a rename, a link or a symlink, `target2`; its `answer` line
`target2` too; and the mutation an approval made is one supervisor `fs` line with authority `human` (the `ask` and
`answer` lines below say what each carries). A rename or link across entries is refused with `completion_unsupported`
and no other gate field. Nothing at this revision is written on every run; below it, every such mutation was refused
unasked.

Record minors 30 to 34 are reserved. Their fields are declared and validated ahead of any writer (`Event.ValidateAt`) and
refused in a ledger below their revision; nothing writes `record_minor` 30 or more, and a launcher refuses to start a run whose `run_start` would carry one.

At `record_minor` 11 (2026-10-16, [agent-contract.md](../../../docs/p0/agent-contract.md) R10a), `run_start` also
carries the optional `runtime_grants`: the rule name of every grant the run makes on its own authority
rather than read from the contract, in table order — each capture listener (`net.capture[<addr>]`), the DNS broker's
socket (`net.dns-broker[unix:<path>]`) and the run's own generated `CODEX_HOME` (`fs.codex_home[<path>]`, a write grant
on exactly `$XDG_RUNTIME_DIR/tego/<run id>/codex`). At revision 14 the run's `hook-state` directory joins them
(`fs.harness-state[<path>]`, a write grant on exactly `$XDG_RUNTIME_DIR/tego/<run id>/hook-state`); at revision 20 the
harness hook's exact-argv exec grant (`exec.harness-hook[<tego binary>]`) follows them. Since the SEC06 compatibility
follow-up (2026-11-03, ADR 0126), a relayed stdio server also lists `exec.mcp-stage[<tego path>]`: a conditional
allowance for the admitted shim's exact fresh-socket child, authenticated and pidfd-pinned at its held stage exec.
This adds no general command pattern to the table; its presence records the available runtime authority, while
an exec line with that rule records its use. Explicit denies and asks still hold. The contract hash does not cover them; lines those grants decide
carry the same rule names. `net.resolver`, the run's own allowance of a query to a configured resolver on port 53
(docs/p0/supervisor.md R14), is a decision the supervisor makes, not an entry, and is not listed here; its lines carry
the rule `net.resolver`. Absent at revision 11 or later, the run added no such entry; absent in ledgers that predate
it.
With no revision of its own (2026-10-27, [ADR 0043](../../../docs/adr/0043-name-entries-for-deny-read.md) D8), `deny_read` name entries decide files created after compile at tiers `cgroup` and `bpflsm`,
and a refusal one makes (the plane's, `mechanism: plane`; on the fanotify fallback the listener's or the
supervisor's) carries `rule` the entry's name: a declared glob's own entry, `fs.deny_read[<glob>]`, or the built-in
`.env` list's label with the scope's spelling, `fs.deny_read[<scope>/**/.env]` or `fs.deny_read[<scope>/**/.env.*]`,
the rule forms held reads' refusals already carry from revision 18 (ADR 0069 D3 (c)). A file that existed at compile
is named by its own expansion entry, `fs.deny_read[<path>]`, even where the plane dropped its row for the name row
(D6's compaction). A directory move a name entry refuses (D5: it would take covered files out of their scope) is
`reason: rename-outside-contract` with that rule. `run_start.capabilities` carries `fs.deny_read.created_later`
(below). A ledger below revision 18 holds no line with a name entry's rule.
At `record_minor` 4 (2026-10-04), `run_start` also carries `net_assurance`
(`best-effort|kernel`) and `net_guarantees` (`tcp`, `udp`, `unix`,
`socket_imports_denied`, `listeners_denied`). These booleans come from the run's
actual enforcement attachments and strict filter, rather than its tier name.
They describe client destination admission and do not promise packet filtering
or established-connection revocation.
*Additive within v1, 2026-10-16 (ADR 0018 PR 2):* `net_guarantees` also carries `socket_families`, true when every
socket the run can make is one ADR 0018's allowlist admits, decided in the kernel on every path (the filter's socket arm
with io_uring refused and `cgroup/sock_create`, or a plane mode's `socket_create`), and `capabilities` carries the row
`net.socket_families` with the same value; a ledger that predates it has neither key. *2026-10-17 (ADR 0018 (7)):*
that includes a socket turned into another family by an upper-layer protocol: the value is true only with `TCP_ULP`
refused on every path (the filter's arm, and `cgroup/setsockopt` at tiers `cgroup` and `bpflsm`). A socket made
outside the run and passed in is not one the run made: `socket_imports_denied` is the key that bounds those.
*No format change, 2026-10-27 (ADR 0043):* the row `fs.deny_read.created_later` (ADR 0069's) is also
true at tier `cgroup` or `bpflsm` when the plane's name check decides the run, so a file created after compile at a
name a `deny_read` name entry covers is refused beneath the entry's scopes (a plane mode with the table's name rows),
and only when no name-eligible entry was left out by a cap or a key collision (ADR 0043 D7).

`net` carries `proto` (`tcp|udp|unix|raw|http`), `dst`, and, to a daemon, cluster or database, `boundary: true` and
`propagated`: the subset of `env:TEGO_RUN_ID`, `env:OTEL_RESOURCE_ATTRIBUTES`, `env:PGAPPNAME`, `header:X-Tego-Run`,
`header:traceparent`, `header:tracestate` the run installed for that process or request (what was installed, never
what the client did with it). A `POST /build` through the Docker proxy is a `boundary` with `context_bytes`,
`dockerfile_sha256`, `tags`, `network_mode` (Docker proxy behavior remains roadmap).
A supervisor `net` line may carry the optional `best_effort: true` (an addition within `v: 1`, VERSIONING §2): the
supervisor answered the syscall `CONTINUE`, so the destination the line names is the copy it read and decided,
and the kernel acted on its own copy, which a sibling thread of the agent can have rewritten in between; for a unix
pathname the kernel also looks the name up again, so a rename or a symlink swap by any process of the run in between
can lead the datagram to another socket than the one the supervisor checked (docs/p0/supervisor.md R11a). It marks
an admitted unconnected datagram (`allow`), a connect or datagram under a contract with no `net:` section, which
decides nothing (`allow`), and one whose address or socket could not be read there (`observed`). A `refused` net
line never carries it: every refusal the supervisor records is one it enforced (docs/p0/supervisor.md R13b).
*Amended 2026-10-16:* an unconnected datagram to a destination the contract
does not admit was continued and recorded `refused` with `best_effort: true` while it left the kernel; it is
refused now, and its line carries no mark. A reader of an older ledger reads `refused` with `best_effort: true` as
"recorded, not stopped".

Minor 4 forwarder policy decisions carry `op: http_request`, `proto: http`,
`http_authority` (the fixed upstream host and port), `method` and a query-free
`path`. `http_authority` is distinct from the common decision `authority` field.
The first matching declaration names `rule: net.http[<index>]`; an unmatched
request is refused with `reason: net-http` and the ordinary `refused` mirror.
Both path fields use capture target redaction: known provider routes remain
recognizable while other resource paths become `/redacted`. Denied requests are
not forwarded and do not create a synthetic model response or usage charge.

Minor 5 listener decisions carry `op: bind|listen`. A kernel-owned Unix bind or listen
completion also carries `syscall_ret`/`syscall_errno` when the syscall failed,
and `verdict_from: plane|lsm-chain|unknown`. `allow` describes a proven permission
decision, independently of whether the syscall succeeded. A failure before a
policy decision, such as an existing pathname returning `EADDRINUSE`, is
`observed` with `verdict_from: unknown`. A plane refusal names `mechanism: plane`, `decision_plane`, and
the kernel's listener or filesystem rule. The terminal producer retains
refusals under `record: off`. Missing copied name or attempt metadata is
explicitly gapped; it never substitutes an earlier attempt's path or rule.
Abstract Unix names retain their exact bytes, including embedded NULs.
Kernel process-scope, BPF-command and keyring refusals use the existing
`refused` kind with `mechanism: plane`; no new public event kind is introduced.

`mcp` carries `name` (the declared server), `transport` (`stdio|http`), `command` on a stdio server's start (the
supervisor's line riding on the allowed exec that started it, `verdict: allow`), and `tool` on a tool call. From
2026-10-19 (no `record_minor` revision: the fields are v1's, only their use is new;
[capture-derive](../../../docs/p0/capture-derive.md) R41) an HTTP server's exchanges captured by the uprobe source
also derive `mcp` lines, `source: ssl`, after the request's `ssl_request`, stamped with its time and thread (the
exchange's `ssl_response`, if one comes, has `parser_version` `mcp/1`):
one with no `tool` for the client's `initialize` (its connection) and one with `tool` per `tools/call`, both
`verdict: observed` (read off the wire, decided by no mechanism), `rule: mcp[<name>]`. The net lines of the
connections an HTTP server's URL admits carry the same rule (agent-contract R16a). `run_start.parsers["mcp"]` is
then the `+`-joined list of the run's MCP producers: `exec` and `mcp/1`.

At `record_minor` 29 (`MinorAttribution`; 2026-10-20, `docs/p0/capture-derive.md` R40, R42), `ssl_request` carries `side: true` when it
is a model host's side traffic (a path the parser calls silent: telemetry, token counting, a model listing, a health
check), which opens no step, and `tool_results`, the `tool_use` ids whose results the request's last message reports,
in wire order: an empty list when derive read the request and found none, absent when it did not read it (no parser
reads the path, the body was cut or stayed coded, or its reading was not certain). Both are optional within v1.

`ssl_request` carries `retry_of` when it is a client retry of a held request (not a new step), and `trace_id`,
`span_id` (forwarder only), `parent_span_id` (the client's incoming parent id, when any). The optional `body_sha256`,
`frame` and `messages` (all sha256, set together; added within v1 on 2026-09-22) mean the body was stored by the
elements of its conversation array (`messages[]`, `input[]` or `contents[]`), in groups stored once per run by hash,
rather than whole: `body_sha256` is the whole body's sha256, `frame` names the blob that rebuilds it and `messages` the
last link of its chain of groups. Such an event has no `blob`, since no file holds the body whole
(`docs/p0/record-ledger.md` R11); a reader that does not know the three fields sees a body that was not stored. `ssl_request` and `ssl_response` carry the optional `truncated: true` and `wire_size` (added within v1 on 2026-09-30) when capture cut the body (the kernel's 128 KiB cap or the body cap) and `blob` holds only its prefix; `wire_size` is the body's length on the wire.
`ssl_response` carries `model`, `response_id`, `stop_reason`, `usage{input,output,cache_read,cache_write}` (with the
optional `output_bound`, true when `output` is the request's `max_tokens` charged for a stream cut before its final
usage report, ADR 0036; additive within v1, 2026-09-24, absent in ledgers that predate it; and, additive within v1
on 2026-09-24 the optional `cache_write_1h`, the part of `cache_write` written with the
1-hour cache lifetime, and `server_tool`, an object of per-request server-tool counts keyed by the name the upstream
reported each under (e.g. `web_search_requests`), at most 8 names with the rest summed under `other_requests`),
`latency_ms`, `request_id`, `content_encoding`, `parser_version`; unparseable bodies become `decision: unparsed` with
`why` (`encoding|schema|h2`), never a crash.
`ask` carries `ask_id`, `hold` (the line's `id` is always the chain id); `answer` carries `ask_id`, `by`, `after_s`.
`by` names who answered: `uid:<uid> pid:<pid>` for a human, `timeout` or `cancelled` or `shutdown` for the broker, and, since the standing answers of 2026-10-06 (SEMANTICS §6), `uid:<uid> pid:<pid> always` for a human answer that also stands for the run and `standing:<ask_id>` for a later request answered from it (the `ask_id` is the human answer behind it, and the request's own `ask` line precedes it as for a held one); since 2026-10-16, `timeout always` for a timeout that also stands under `ask.on_timeout: refuse_always`, whose `ask_id` the later `standing:<ask_id>` answers then name.
`hold` is `connect`, `first_write` or `request` for a network ask and `open` for a held file open (`open` added within
v1 on 2026-10-05; such asks carried `connect` before, and a reader that does not know `open` sees an unknown hold).
*Added at `record_minor` 28 (2026-10-27, [ADR 0047](../../../docs/adr/0047-fs-ask-mutations-made-on-pinned-names.md)):*
`hold` `mutation` is a held fs mutation in an `fs.ask` scope, `op` its fs op (`unlink`, also for an rmdir, `mkdir`,
`rename`, `symlink`, `link`), `target` the name it acts on and, on the ask and the answer, `target2` a rename's or a
link's new name or a symlink's stored target. The mutation an approval made is one `fs` line from the supervisor:
verdict `allow`, authority `human`, `path` and `path2` the held names, `operation_completed` (the syscall the supervisor
made as the agent returned 0), `syscall_ret` (the result the agent got) and `result_unknown` when the agent's syscall
was gone before it was answered; it is not written under `record: off` when completed. A rename or link whose ends lie
in different entries is a `refused` fs line with `completion_unsupported: true` and no other gate field.
*Added within v1 on 2026-10-19 (supervisor R13d):* a held UDP datagram's ask carries `op: send` and a held
UDP connect's `op: connect`, each with hold `connect` and `target` `udp://<ip>:<port>`; a TCP connect's target stays
`<ip>:<port>`, so a standing answer for one transport never answers the other. The net line of an approved datagram is
`proto: udp`, `allow` with authority `human`, as an approved connect's is. *Added within v1 on 2026-10-20 (supervisor
R13d, R13's pending frames):* at tiers 2 and 3 an approved datagram the kernel sent but whose one-shot credit its hook
left untaken (the datagram joined a frame pending on the socket, so its bytes went to that frame's destination, or a
refresh admitted the destination meanwhile) is `observed`, authority `human`, under the scope's rule, never `allow`; a
refused `setsockopt(UDP_CORK)` is a `refused`
line, op `setsockopt`, target `setsockopt level 17 option 1` (or level 136), rule `datagram-corked`; and a `sendfile`
or `splice` whose output descriptor the supervisor could not duplicate or read, refused because it may be a socket
that holds a frame, is a `refused` line, op `sendfile` or `splice`, target `fd <n>`, reason `net-not-allowed`, rule
`fd-exhausted`, `fd-unreadable` (the descriptor cannot be taken for a lasting reason: its `pidfd_getfd` failed `EPERM`,
a non-dumpable process at tier 1, or, below 6.9, the thread's descriptor table is not its leader's or `kcmp` cannot
say; the last two were `fd-raced` until 2026-10-20) or
`fd-raced`; it carries no `proto`, since nothing says the descriptor was a socket (2026-10-20).
An observe run, which continues both, writes neither `refused` line: the binary's first such call of each syscall and
rule is `gap what=record why=<rule>-<syscall> binary=<exe>`, for example `why=datagram-corked-setsockopt` or
`why=fd-unreadable-sendfile` (supervisor R30; 2026-10-20). A non-dumpable process hides its
binary behind the ptrace check that refuses its `pidfd_getfd`, so its line has no `binary` and is written once for
each such process, the event's `pid` naming it (supervisor R31; 2026-10-20);
the same holds for the supervisor's other once-per-binary gaps (`keyring-<syscall>`, `sysv-ipc-<syscall>`,
`landlock-topology`).
*Added within v1 on 2026-10-06 (SEMANTICS §6), revision 9 since 2026-10-16
([ADR 0057](../../../docs/adr/0057-fs-ask-read-and-alternates.md) D1, D5):* the ask of a held read under `fs.ask_read`
carries `op: read` (hold `open`, `ask_rule` `fs.ask_read[...]`); a held write-open keeps `op: open`. An answer that
gave an alternate (`tego alternate`) carries `alternate`, the absolute path of the file delivered in place of the
target, as the supervisor read it from the descriptor the person's command opened when they named it, and
`alternate_dev` and `alternate_ino`, that file's identity (`st_dev`, `st_ino`), with `approved: false` and no
`answer_reason`. That is the record's truth, not a placeholder: `approved` answers whether the operation as asked (the
`target`) was granted, and it was not; nothing was refused either; and `by` names the person's authority (`uid:<uid>
pid:<pid>`, or `standing:<ask_id>` for a later answer from a standing alternate), so a reader that does not know
`alternate` reads an answer that granted nothing. A standing alternate's later answers repeat the `alternate`,
`alternate_dev` and `alternate_ino` of the answer that set it: `alternate` is then the path recorded when the person
named the file, and the file can have been renamed since, while its identity is `alternate_dev`/`alternate_ino`,
fixed with the descriptor the run keeps, and the path it had when delivered is the `fs` line's `path`. The open it
completed is a separate `fs` line with `authority: human`, `verdict: allow`, whose `path` is the file delivered and
whose `alternate_for` is the requested target (the ask's `target`), with `operation_completed`, `fd_delivered` and
the optional `result_unknown`/`syscall_ret` as for an approved open (not written under `record: off` when delivered,
as for an approved open; the answer line is); its gate fields, present when the contract's gate scores such an open,
are the gate's decision on the file delivered (its `path`), never the requested target's (amended 2026-10-16: the target's score and outcome were written on the alternate's line); an
alternate that fails its checks when it is delivered leaves the requested path's `refused` line, `ask-unavailable`.
Every reader takes it so: `tego events` writes such an answer as `alternate <path> (not the file asked for) by
<who>`, `drift` counts the `fs` line in its rule's `alternate` count, never its `allow`, `measure` counts the answer
lines as `alternates` (neither refusals nor approvals), and `learn` proposes nothing from such an open. At
`record_minor` 9 every alternate answer carries all three fields; below it, a ledger an early build wrote may
carry `alternate` alone (no revision was taken then, an omission ADR 0057 D5 corrects), and one older still has no
held read and no alternate. An absent `alternate` means "no alternate" in every ledger.
*Added within v1 on 2026-10-16 (SEMANTICS §6 `ask.on_timeout`):* under `ask.on_timeout:
refuse_always` the answer line of an ask that timed out carries `by: timeout always` (with `answer_reason:
ask-timeout`) when it also set a standing refusal, and every later answer taken from it carries `by:
standing:<that ask_id>` with `answer_reason: ask-timeout`, never `ask-denied`: no person denied it. A reader that
matched `by` against `timeout` exactly reads such a line as a `by` it does not know; the reason still says
`ask-timeout`. No `record_minor` revision: the values are new, the fields are not.
Minor 5 approval records add `op`, `target`, and `ask_rule`; answers also carry
`approved` and optional `answer_reason`. `target` is what the approver was shown: an
`open`'s exact path and a `connect`'s exact `ip:port`, as the action line records them; an
`http_request`'s `authority METHOD path` has only its path projected onto the public routes
(docs/p0/record-ledger.md R9a; amended 2026-10-05: every target was stored as `/redacted`). These are coordination records, without action
`verdict` or `authority`. An approved answer authorizes an attempt; it does not establish
that an operation or upstream delivery succeeded.

An approved filesystem open emits a separate `fs` action with `authority: human`,
`operation_completed` and `fd_delivered`. `operation_completed` says the supervisor's
open completed, including any authorized create/truncate effect; `fd_delivered` says
atomic ADDFD+SEND delivered the descriptor and result to the target. Optional
`syscall_ret` carries the actual delivered descriptor or returned negative errno.
If the notification disappears after the open, or the kernel took it as answered without
installing the descriptor (ADR 0008, amended 2026-10-16), the effect may remain: the event carries
`fd_delivered: false`, `result_unknown: true` and no `syscall_ret`. It is retained under
record off so that the authorized effect is not misreported as an ordinary refusal.

A `first_write` connect is recorded when it completes into the private relay: a `net`
`allow` with `hold: first_write`, `relay_dst` and `upstream_connected: false`. Once the
relay has read the agent's first bytes, its end is recorded too (additive within v1,
2026-10-05): a delivery refused before its answer line was accepted (broker capacity, a
process no longer in the run, cancellation) writes the same `refused` line with `op:
first_write` that a recorded denial mirrors; an approval writes a `net` `allow` with
`authority: human`, `op: first_write`, `hold`, `upstream_connected` (the relay's upstream
connection was made) and `delivered` (the first bytes reached it). A delivered outcome is
omitted under record off; a failed one is kept.
`gap` carries `what` (`capture|record|enforce|limits`), `why`, `binary` (absent when it could not be read), `count` (dropped events, when applicable), and
the optional `decision_plane` on a gap the kernel decision plane's counters give (additive within v1, 2026-09-30):
at run end, one `what=enforce` line per counter of the run's slot that is not zero, `why` one of
`plane-identity-mismatch`, `plane-path-unresolved`, `plane-walk-bound`, `plane-no-rows`, `count` the refusals the
plane made for that cause, and `why=plane-counters-unread` with no count when the slot could not be read
(`docs/p0/enforce-plane.md` §2.8). Each counts refusals already made; none is an action allowed.
An adopted run (ADR 0055, additive within v1, 2026-10-06) writes, after `run_start`, one `exec` line per process it moved
with `by: adoption` (the process was already running and its exec was not seen; its `exec_id` carries its start time), and
`gap what=record` lines with `why` `adoption-pre-attach` (`binary` the agent, `count` the processes adopted: what each did
before the attach is not in the record), `adoption-not-moved` (processes of its tree not moved), `adoption-open-sockets`
(sockets it held when adopted, which no rule governs) and, at the end, `adoption-left-in-scope` (processes a release could
not move out); and, for a boundary, one `gap what=enforce why=adoption-open-descriptors` counting the files its processes
held across a rule when adopted: open for writing outside every write entry or open under a `deny_read` entry, and
(amended 2026-10-16) mapped, a shared writable mapping outside every write entry or any mapping under `deny_read`, since
loads and stores through a mapping pass no hook the plane decides at. Amended 2026-10-16: the test is
the plane's own rows, so a file held where the plane refuses a read (any `deny_read` entry, a name entry such as the
built-in `.env` list included) or a write (outside every write entry, or a `deny_write` target beneath one, such as a
repository's hooks and config or a shell startup file) counts, read through any mapping and written through a shared
mapping that is writable or may be made so (`VmFlags mw`); files under `/dev` count but the terminal and the byte
sinks (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`, `/dev/console`,
`/dev/pts/*`) held for writing, which a launched run's agent inherits and writes the same way; a file on a
kernel-internal mount no path names never counts (amended 2026-10-16: decided from the file's device, one of the
kernel-internal superblocks tego finds by making a memfd, a hugetlb memfd of each page size, shared anonymous memory
and an AIO ring, such as a memfd, a System V segment, the AIO ring or hugetlb memory, never from the name nor from
which mount shows the file: a file held from a chroot counts, and a pseudo file of an internal superblock tego does
not probe, such as a dma-buf, counts its process unread, below; amended 2026-10-16: a file is asked about by its path and by
each other path through another mount of tego's namespace of the same filesystem that shows its directory, such as
a bind mount of a directory above it; amended 2026-10-17: and by the path of each `fs` rule's file the
plane keyed at the same inode, a hard link of a `deny_read` file or a keyed file renamed since, as the plane decides an
inode under every name it has; amended 2026-10-17: and, for each directory its name passes through that a
rule's row is keyed at, by its path beneath that rule's path, a file of a `deny_read` directory renamed since; so, of
the files `/proc` lists, the count can be high, never low; amended 2026-10-17: the descriptors are those
of every thread's table, a thread that unshared its own, `unshare(CLONE_FILES)`, included; amended 2026-10-17: two tables' entries are one only when they hold the same file, never two io_uring instances, and a process
whose main thread exited while its threads run is read through a live thread). A moved process whose
descriptors or mappings could not all be read (more than 4096 of either, or a listing that failed, a thread's table
included; amended 2026-10-17: or one holding a descriptor /proc cannot name, a file open at a path longer
than `PATH_MAX`, or whose open flags its fdinfo would not give; amended 2026-10-17: or one holding an io_uring instance with a table of registered files, or whose table its fdinfo would
not show, as a registered file is read and written through the ring with no descriptor /proc lists), and, for a
boundary (amended 2026-10-16), one in a mount namespace other than tego's, whose files /proc names by paths that
need not be tego's namespace's, one mapping an io_uring instance it holds no descriptor of (amended 2026-10-17: where the kernel puts every ring on its shared anonymous inode, no descriptor tells which ring a mapping is,
so any mapped ring counts), and
one holding a file whose name is no path of it in tego's namespace (amended
2026-10-16: held through a mount tego's namespace does not hold, such as a detached clone or a lazily
unmounted mount, which /proc names from that mount's root, a pseudo file on a mount no line of tego's mountinfo
shows, or a file whose mount could not be read or whose name now leads elsewhere), is counted in
`gap why=adoption-descriptors-unread` (`what=enforce` for a boundary, `record` otherwise), never taken as holding only
what was read. Neither count sees what /proc lists of no process (amended 2026-10-17): a descriptor in flight in a unix
socket's queue (`SCM_RIGHTS` sent and not received), an io_uring instance registered with itself and neither held nor
mapped, a file another kernel object holds. A boundary adoption also writes, once after `run_start`, `gap what=enforce why=adoption-no-syscall-filter`
(count 1, amended 2026-10-16): what only tier 1's seccomp filter refuses is not held on a process that was already
running (System V IPC, which a contract refuses unless it sets `ipc: true`; the socket families outside the network
rules; io_uring, openat2, open_by_handle_at, clone3, the terminal-input ioctls; and, amended 2026-10-16, new mount and
user namespaces and `setns`, so the file rules hold on the process's mount topology as it stands, ADR 0055). Its `run_end`
`reason` is `exit` when the tree ended (its `exit_code` and `signal` the adopted root's, as the kernel's process events say
it: the end of its last thread, and only a status its threads' exit codes agree on, a signal like any other code,
else `detail` says it is unknown; amended 2026-10-17, and 2026-10-19: the end is told by the events alone, so a
thread's exec, or one that failed, no longer ends it early; 2026-10-20: only events filled after the root was listed
count, and every compared code must agree with the main thread's, whichever was read first, ADR 0055 (e)), `stopped`
when it was released (the `detail` says it was released, never killed, and
who asked when a release request did) and `orphaned` when its adopter died and the reaper released it, or, with the
reaper gone too, when a root sweep (`sudo tego gc`, a root `tego run`'s sweep) released it from the adoption's record;
that `run_end` is the sweep's own (no `detail`) and is written only once the tree is out of the scope. A sweep that cannot
release it (not root, or a process stays in the scope) writes nothing and the run stays lost (amended 2026-10-16).
`what=capture why=codex-unrouted binary=codex` (additive within v1, 2026-10-16) is written once, right after
`run_start`, by a run whose forwarder has an openai listener and that wrote no `CODEX_HOME`, which only a root launcher
does: a Codex in it is not routed through the forwarder, and the `models[]` guard refuses its own calls to the model
([agent-contract.md](../../../docs/p0/agent-contract.md) R10a (3)).
`what=record why=reason-unavailable` (additive at `record_minor` 14) is written once, right after `run_start`, by a
run whose harness is anything but `none` (the default `auto` included) and that has no readable reason file: no
absolute `XDG_RUNTIME_DIR`, or a root launcher. The agent has no `TEGO_REASON`, nothing was provisioned for its
harness (`run_start.harness.why` is `reason-unavailable`), and it learns why an action was refused only from the
error the call returned ([agent-contract.md](../../../docs/p0/agent-contract.md) R27, ADR 0062).
`what=record why=own-state-mode-restored binary=<path>` (additive within v1, 2026-11-02), no `count`, is one of tego's
own files or directories whose owner's rights had been taken, which tego gave back: `~/.tego`, the config layer or
`tego.log` in it, `chain.log` or the directory that holds it, the ledger root or its live index, tego's runtime parent
(`$XDG_RUNTIME_DIR/tego`), or, at the run's end, the run's directory or an entry in it, or its runtime directory. No
Landlock ABI has a chmod right, so an agent can chmod the files its user owns: their contents and the record are not
changed by it, but tego could not have used them. Only the owner's bits are added; the mode's other bits are as they
were. One line each, right after `run_start` for what the launcher restored before the run, and as the last lines
before `run_end` for what the run restored at its end ([record-ledger.md](../../../docs/p0/record-ledger.md) §3,
"Modes taken from the owner"). No action was lost: a reader does not count the line among the gaps that make the run's
counts a minimum.
`what=limits` (additive within v1, 2026-09-24) is a limit the run's cgroup cannot hold as asked: `why=memory-swap-uncapped`,
a memory cap on a kernel that accounts no swap to cgroups while swap is on (`docs/p0/runtime-launch.md` §4 `SetLimits`).
`limit` records a budget hit (`which`, `value`, `ceiling`).
`run_end` carries `reason` (`exit|signal|stopped|oom|pids|limit|exec-failed|orphaned|error`), `exit_code`, `signal`
and `escalated` for `signal`, `detail` for `error` (at most `MaxDetailBytes`, 4096 bytes: a longer one is cut at a
character boundary and ends ` [cut N bytes]`, `record.CutDetail`, 2026-10-25), `supervisor{notifications, held_ms,
anomalies, orphaned, starved,
order_lost}` (the last four optional; `order_lost`, additive at `record_minor` 11, counts the supervisor lines written
without waiting for the previous line of their thread, which may then precede it along `seq`), the optional `resources{memory_peak, pids_peak, cpu_usage_usec, cpu_user_usec,
cpu_system_usec, cpu_nr_throttled, cpu_throttled_usec, memory_events{high, max, oom, oom_kill}}` (what the run's
cgroup reported it used; each key present only when the kernel wrote it, never a zero for unknown), and `head` (the
final chain id); the launcher appends `run head` to `~/.tego/chain.log` so the chain has an anchor outside the run directory.
Minor 5 also adds optional `network{available, bytes_in, bytes_out, datagrams_in,
datagrams_out, connections_active, connections_pending, refusals}` from the
backend's final atomic snapshot before its maps are detached. `available`
records the actual attached measurement coverage. A missing measurement is
unknown; a measured zero is explicitly written. Packet bytes include IP and
transport headers and retransmissions, and describe kernel admission before
any later queue loss. Connection totals are current reservations, including
pending TCP and socket-lifetime UDP reservations; `connections_pending` counts
conservative incomplete inbound SYN reservations. `refusals` reports the
available `ingress`, `bytes`, `datagrams`, `connections` and `pending` counters.
Older v1 ledgers omit `network`. A run without coverage or whose snapshot failed
also omits it; snapshot failure adds diagnostic detail rather than zero counters.
`orphaned` is written by the sweeping process, not the launcher. Reader rule: a ledger with `run_start` and no
`run_end` is `running` while `runs/<id>/lock` is held and `lost` otherwise; views never show `lost` as `done`.

Field ownership: `rule` and `reason` are common line fields written once in their canonical slot; a payload never repeats them (`run_end.reason` and `refused.reason`/`refused.rule` are those common fields). `mono_ns` is `CLOCK_MONOTONIC`. Payload bodies larger than 4 KiB are split to blobs: `body` becomes `blob`, any other field `f` becomes `f_blob`; an `ssl_request` body stored by its conversation's elements becomes `body_sha256`, `frame` and `messages` instead.

Files are `0600` in a `0700` run directory. `record: summary` stores no bodies. Retention is `tego gc --keep <d>`
(default 30 days), and once per the machine's `gc_interval` a `tego run` start's pass (2026-10-26). Ledgers are never
rewritten: rewriting would change every `id` and break the anchor. Removing an ended run's directory leaves its
`chain.log` line: every other run still verifies, and `tego events <removed run> --verify` reports the anchored ledger
missing, which is the record that the run existed and was removed.

Gate fields (optional, record minor 5): `score` is the saturated integer score 0..100, `gate_rule` names the first contributing bounded declaration, `gate_outcome` is the scored allow/ask/refused decision, and `gate_facts: copied_syscall` labels its provenance. At `record_minor` 10 (2026-10-16, [ADR 0041](../../../docs/adr/0041-race-free-supervisor-decisions.md) D5, under a contract's `gate.completion: held`), `gate_facts: held_object` labels a decision taken on the object the run's open deputy pinned, the larger of the copied name's score and the pinned object's: the open was completed in the run by the deputy and the descriptor delivered is that object, so the line's `path` is the pinned object's and its authority `rule` (`human` once a person approved it, `gate` for a gate refusal). A held open that failed with the kernel's errno, or was performed and not delivered, carries `operation_completed`, `fd_delivered`, the optional `result_unknown` and `syscall_ret`, as an approved open's line does; a held refusal this loop made without the kernel's word names `held-unsupported`, `held-unavailable` or `held-limit` in `rule`, reason `fs-gate`. `run_start.best_effort` then lists `gate.fs.read/o_path` in place of `gate.fs.read/open` and no `gate.fs.write/open`, unless the deputy did not start. `completion_unsupported: true` marks a scored ask that the operation cannot safely complete and therefore refused. Kernel final outcome remains authoritative and may differ from the copied-fact gate allow; metadata is attached to that same action line. Human-approved actual outcomes retain authority human. Ask/answer records may carry score and gate_rule; they report the coordination decision separately from the actual operation result.


Writer clarification (2026-11-03, review M5): production pipeline and DNS refused
action/mirror pairs are prepared together and appended contiguously under the
ledger writer's mutex. Each remains a separate chained line. No payload or envelope
field changes, so this does not allocate a record minor or change verifier rules.
Readers of older ledgers still use the bounded legacy pairing heuristic: a mirror
already displaced beyond that window has no reliable action reference and can count
as a separate refusal. A failed pair append may leave its action without its mirror.

### Built-in refusals (ADR 0113, implemented 2026-11-03)

Ordinary refusal lines use the existing `rule` strings `builtin.host_ipc`, `builtin.tego_surface` and
`builtin.other_tty`. Net connects/sends/binds keep `net-not-allowed`; tty reads/imports keep
`read-denied`; filesystem writes keep their existing write refusal reason. No new event kind, reason
or record minor is introduced. The pty relay records an installed slave as an allowed filesystem open
under `builtin.other_tty`. `builtin.host_ipc/datagram` is a `best_effort` cell disclosing admitted or
unsupported datagram/address alias limitations where no native peer plane runs, not a
new reason. The native Unix peer plane emits an ordinary refused net/sendmsg line with its built-in rule and `mechanism: plane`. At root tiers, an actual kernel refusal of a numeric terminal is attributed to `builtin.other_tty` using the recorded file identity and inherited-terminal exception. Tier landlock may have no line for a read without a notification under summary mode.
