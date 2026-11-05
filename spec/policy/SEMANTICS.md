# Policy semantics (spec v0)

Revised 2026-09-21. This is what the compiler validates against and the runtime implements. Anything not written
here is undefined and must be added here before it is coded.

## 1. Defaults

| Section absent | Meaning |
|---|---|
| no `fs:` | no write entry: every write is refused as under `fs: {}` (next row); reads allowed; the built-in `deny_read` list and the implicit entries (§2, last paragraph) apply; record per `record:` (amended, below) |
| `fs: {}` or `fs.write: []` | all writes, deletes, renames, mkdir, symlink, link, truncate and mknod (fifo, unix socket, device) refused; chmod is not refused at any tier (`fs.deny_chmod` is absent at every tier, CAPABILITIES.md; amended 2026-10-19, below), only beneath a `deny_write` target where a decision plane decides; reads allowed |
| no `net:` | apply the immutable built-in refusals below first; otherwise deny no IP destination, except guarded `models[]` endpoints under `capture: forwarder` (below; amended 2026-10-05: the 2026-10-01 text also refused every undeclared destination on a named model's port here, which no longer holds); every IP destination is allowed, but a unix connect, or a datagram sent to a socket the run did not bind (pathname or abstract), is refused, rule `host-sockets`: the run reaches only the unix sockets a process of it bound and Tego's own endpoints (the DNS broker's socket), the unix-only state (*amended 2026-10-24*, [ADR 0070](../../docs/adr/0070-host-sockets-refused-by-default.md); before, it reached every host socket its uid could open). Top-level `host_sockets: true` restores that reach, and `compile` then warns naming the well-known host daemon sockets that exist (agent-contract R19); a profile cannot set it. A `net:` section decides unix destinations by its own entries and is unchanged |
| `net: {}` or `net.allow: []` | all connects refused |
| no `exec:` | deny nothing |
| `exec:` with `deny` or `ask` and no `allow` key, even `deny: []` (amended 2026-10-06, ADR 0048 (1)) | deny-list mode: images unrestricted, as no `exec:`; the command rules of §4 apply. The mode is the keys present, never whether a list is empty |
| `exec: {}` or `exec.allow: []` | all execs refused except the agent command; in the Landlock tier its ELF loader is granted for the kernel's own `PT_INTERP` load, and an `execve` of the loader itself is refused like any other unlisted binary (§4, amended 2026-09-23) |
| no `deny_read:` | the built-in list applies: `~/.ssh`, `~/.aws`, `~/.netrc`, `~/.gnupg`, `~/.npmrc`, `~/.git-credentials`, `~/.config/gh`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gcloud` (a file where the credential is the file, a directory where it is one of several files in it), the agents' own token stores `~/.claude/.credentials.json`, `~/.claude.json`, `~/.claude/backups` (Claude Code's copies of `~/.claude.json`), `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/.env`, `~/.gemini/mcp-oauth-tokens.json`, `~/.copilot/config.json`, `~/.copilot/mcp-oauth-config` and `~/.copilot/mcp-secrets`, and the stores of the tools an agent runs beside, `~/.azure`, `~/.config/op`, `~/.password-store`, `~/.pypirc`, `~/.cargo/credentials`, `~/.cargo/credentials.toml`, `~/.terraform.d/credentials.tfrc.json`, `~/.vault-token` and `~/.pgpass` (*amended 2026-10-25*, [ADR 0067](../../docs/adr/0067-agent-token-stores-and-credential-rows.md): the harness's own store is denied too, and a harness gets its credential from a variable its profile passes; a row absent at compile compiles no rule, but the Landlock ruleset, at tier landlock and in the tiers that compose it, enumerates the directory it would appear in, so a file created at it during the run is refused, as is anything else created directly in that directory; [the row list](../../docs/spec/builtin-deny-read.md) cites the vendor document that names each location), the long tail of credential stores, `~/.local/share/keyrings`, `~/.local/share/kwalletd`, `~/.my.cnf`, `~/.mylogin.cnf`, `~/.s3cfg`, `~/.boto`, `~/.config/rclone/rclone.conf`, `~/.rclone.conf`, `~/.gem/credentials`, `~/.local/share/gem/credentials`, `~/.config/composer/auth.json`, `~/.composer/auth.json`, `~/.m2/settings-security.xml`, `~/.config/doctl/config.yaml`, `~/.config/hub`, `~/.config/glab-cli/config.yml`, `~/.fly/config.yml`, `~/.supabase/access-token` and `~/.oci` (*amended 2026-11-02*, under the same rule and in the same row list; `~/.m2/settings.xml` and `~/.gradle/gradle.properties` stay readable, since each configures every build of its tool), browser profile directories (Firefox, Chrome and its beta and unstable channels, Chromium, Brave, Edge and its beta and dev channels, Vivaldi, Opera, at their usual paths under `~/.config`, the snap paths `~/snap/firefox/common/.mozilla` and `~/snap/chromium/common/chromium`, and the flatpak directories `~/.var/app/<id>` of the same browsers; a browser installed elsewhere is not covered, name it in `deny_read:`), and `.env` files under the project root — the contract file's directory — and under the directory the run starts in, resolved at compile time; at tiers `cgroup` and `bpflsm` one created later beneath them is refused as well, by the built-in name entries (amended 2026-10-27, ADR 0043; tier `landlock` keeps the files resolved at compile time unless the run holds its reads, ADR 0069) (amended 2026-09-29: the snap, flatpak and beta/unstable channel browser paths were not in the compiler's list, so a snap Firefox profile stayed readable; the credential rows from `~/.npmrc` to `~/.config/gcloud` were applied by the compiler but not written here; amended 2026-09-24: the scan was rooted at the working directory alone, so a run started in a subdirectory left the project root's `.env` readable); `deny_read: []` disables it and `compile` warns |
| no `fs.deny_write:`, or `fs.deny_write: []` (*added 2026-10-25*, [ADR 0071](../../docs/adr/0071-user-deny-write.md)) | no declared entry: only the built-in `deny_write` set (§2) refuses writes inside a write entry; `[]` adds nothing and never removes the built-in set, across `extends` either (a union) |
| no `env:` | the launcher's environment plus the identity set; `env.pass` narrows it. Under a root launcher, a `HOME`, `USER` or `LOGNAME` naming root is the invoking user's |
| no `limits:` | the machine config's ceilings (spec/config/v0) |
| no `record:` | `summary` |
| no `tier:` / `capture:` | `auto`: the highest at or below the machine config's ceiling |

`extends: <profile>` merges a profile from the profiles directory or a registry namespace underneath the contract:
lists concatenate, scalars in the contract win, `deny_read` entries are never removed by an extending contract, and
`fs.assurance` keeps the stricter value (`kernel` over `best-effort`; amended 2026-10-05, ADR 0041 D1 (a)).
*Amended 2026-10-25 (ADR 0068):* a name under `tego/` is a built-in profile, never a file (ADR 0066 D2); the presets
are three, each meaning a row of the table above: `tego/no-secrets` passes only an allow-list of variables
(`env.pass`) and keeps the built-in `deny_read` list on as any contract that does not write `deny_read: []` does,
`tego/no-prod` is `net.allow: []` (all connects refused but the contract's own `net.allow` entries; the resolver
stays reachable under `net.dns.mode: system`), and `tego/repo-only-writes` is `fs.write: [/dev/null]` (every write
refused but `/dev/null` and the contract's own `fs.write` entries). `tego/<preset>@<n>` pins revision `n`.
*Amended 2026-10-24 (ADR 0069 D1):* `fs.reads` (`auto` | `held` | `direct`, default `auto`) keeps the stricter value,
`held` over `auto` over `direct`; `direct` counts only from the top-level contract, and a profile's is ignored with
`profile-cannot-loosen`. `auto` holds the run's read opens at tier landlock while a `deny_read` target lies at or
beneath a write entry (§2), `held` at every enforcing tier, `direct` never; a records-only run never holds them.
*Amended 2026-10-25:* `held` is refused with `io_uring: true`, as `gate` and `ask` are: a
ring's opens, which a root tier's plane admits, never reach the open deputy. `auto` holds only at tier landlock,
where io_uring is always `ENOSYS`. *Amended 2026-10-25:* `held` is refused with `setuid: true` as well,
as `gate` and `ask` are: the open deputy completes a read with the run's starting credentials, and `setuid: true` lets
a task change its own at a root tier. Tier landlock, the only tier `auto` holds at, keeps `no_new_privs` set.

**Merge classes (added 2026-10-24, ADR 0065).** Every key of the contract, sections' keys included, has one merge
class, and the merge reads it from one table (agent-contract R5 lists each key's): `section` (a mapping whose keys
merge by their own classes), `concat` (a list, the profile's entries first), `union` (a list of what a run is
denied, which no file's rule ever shortens: `deny_read`, `deny_write`), `keymerge` (`env.set`, the contract winning per key),
`contract-wins` (a value the contract replaces whole when it writes the key), `stricter` (an ordered value set where
the stricter value wins and the contract's on a tie; a value marked loosening counts only when the top-level contract
writes it, where it overrides, and a profile's is ignored with the warning `profile-cannot-loosen` at its line),
`refused-in-profile` (the top-level contract's alone: a profile that sets the key is a `schema` error) and `own` (the
top file's own and never inherited: `version`, `name`, `extends`). Every class keeps each merged entry's file and line.

**A list of profiles (added 2026-10-24, ADR 0066).** `extends:` names one profile or a list of 1 to 8. Each is resolved
with its own profiles first, then they are combined in the order the list names them and the contract goes on top:
lists take each profile's entries in that order, then the contract's; a stricter-wins key keeps the stricter; and a key
the contract replaces whole, or an `env.set` variable, that two profiles set to different values is the error
`extends-conflict` unless the contract sets it, so a later profile never silently overrides an earlier one's value
(*amended 2026-10-24*: `env.set` took a later profile's value, so a later profile's
`PATH` silently chose what every command name ran and its `HTTPS_PROXY` where every connection went). A profile two entries reach merges once, at its first position, but each profile is
checked as it resolves in full, so whether a list conflicts never depends on its order: two profiles that extend one
base, one of them overriding a base value the other inherits, conflict in either order (*amended 2026-10-24*). Names beginning `tego/` are tego's built-in
profiles: they are never read from the profiles directory, and a file there under `tego/` is the error
`shadowed-builtin`. `run_start.profiles` records which profiles a run merged, from where, and the sha256 of each.

**Amended (2026-09-22): no `fs:` refuses writes.** This row used to read "deny nothing except the implicit
entries", and no tier ever did that: Landlock is allow-only and cannot deny beneath an allow, so writes open
everywhere with the run directory and the contract file still closed is not a ruleset it can build. Leaving the
write rights unhandled instead would leave the implicit entries writable from inside the run, the ledger
included; enumerating write grants around them the way `deny_read` enumerates reads would refuse creating a file
at every ancestor level of the run directory and of the contract file, the worktree root among them; and the root
tiers' walk (§2) already refuses what no entry covers. The fail-closed reading is the one all three components
implemented (the Landlock ruleset, `compile --test`'s `Evaluate` and the supervisor's advisory verdict), so the
row now says it. The difference from `fs: {}` is only the rule a refusal names: `unmatched` rather than the
implicit `/` entry. The unrestricted reading stays expressible in no tier: `fs.write: ["/"]` contains the run
directory and is a `contradiction` (agent-contract R10). It becomes buildable where a tier can deny beneath an
allow — the root tiers' nearest-wins walk can, with a `/` write grant and the implicit entries nearer — once a
tier that does not install a Landlock fs ruleset (`containers: rootless`, §10) ships.

*Amended 2026-09-24:* "no `net:`" is the key absent. The key present with no value
(`net:` with every entry commented out, or `net: ~`) used to parse as absent too, unrestricted, while it reads as an
empty section; it is now a schema error whose fix is `net: {}` (refuse all) or removing the key, as for `exec:`,
`fs:`, `env.pass` and `env.deny`, and `compile` names an unrestricted section (`net unrestricted (no net:
section)`, `net_unrestricted` in `--json`).
*Amended 2026-10-25 (ADR 0070):* with no `net:` section `compile`'s net line reads `IP unrestricted,
unix sockets the run's own only (no net: section)`, and `--json` adds `host_sockets_refused: true` beside
`net_unrestricted: true`; under `host_sockets: true` the line reads `net unrestricted (no net: section,
host_sockets: true)` (`TestCompileSaysUnrestricted`).
*Amended 2026-09-24:* the same refusal applies to each `limits:` key (absent is
unbounded) and to `fs.deny_read` (absent is the built-in list only).
*Amended 2026-10-19 (ADR 0017's 2026-10-19 generator note):* the `fs: {}` row said chmod was
refused "at tier 3 only (`fs.deny_chmod`)". No tier refuses it: no Landlock ABI has a chmod right, fanotify has no
permission event for it, and the plane's `path_chmod` refuses a mode change beneath a `deny_write` target only, not
under the write rules (agent-contract E35, 2026-09-29; CAPABILITIES `deny chmod`: no at every tier). The row now says
what every tier does, and the conformance oracle's mutation invariant no longer holds a chmod outside every write
entry, while its `deny_write` invariant still holds chmod beneath a target where a plane decides. A tier that comes
to claim `fs.deny_chmod` amends this row with its capability line.

`no net:` and `no exec:` are read off the merged contract by every component alike: the Landlock builder handles
no net right, or adds `EXECUTE` to its read sets; tier 2 attaches no network program; `Evaluate` answers
`allow`/`unmatched`; the supervisor records an exec no entry names as allowed, and answers every connect `CONTINUE`
so that the kernel performs it as the agent, recorded `allow` with `best_effort` — save under the `models[]`
exception below. *Amended 2026-10-25 ([ADR 0070](../../docs/adr/0070-host-sockets-refused-by-default.md)):* that
is the reading under `host_sockets: true`. In the default unix-only state the Landlock builder handles
`RESOLVE_UNIX` (ABI ≥ 9) and the supervisor performs every connect, and every addressed datagram it can reproduce,
on its own duplicate of the agent's socket (supervisor R7b): an IP one with the address it copied, a unix one on the
thread that holds the task's credentials, to the socket the name resolves to in the task's view, and only when a
process of the run bound it or it is Tego's own endpoint, so neither its root credentials at tier 2 nor its missing
Landlock domain reach a socket the agent's could not. *Amended 2026-11-01:* a live `net` block narrows the opt-out too,
so while one exists the supervisor performs a connect or TCP Fast-Open send on an IP socket on the copy it checked
(supervisor R7; what stays the agent's own, docs/GAPS.md C47). Otherwise, under the opt-out the supervisor does not perform
those connects itself (amended 2026-09-22): it has no Landlock domain and at tier 2 runs as root, so its connect
reached an abstract name the agent's own domain refuses and a socket the agent's uid cannot open. One kernel check
stays stricter than "deny nothing", on purpose, because it is the agent's own domain: the Landlock scope refuses,
at ABI ≥ 6, an abstract unix name bound outside the run. `Evaluate` and the connect's ledger line cannot see the ABI
or who bound a name, and say `allow` there; whether the run had the scope is on its `run_start.capabilities` line,
`net.unix_abstract_scope` (added 2026-09-23). *Amended 2026-09-22:* the ruleset used to handle `RESOLVE_UNIX` at ABI ≥ 9 here too,
refusing a pathname socket outside a write entry that this row allows; it is the pathname-socket half of `net:`
and is no longer handled without one, save in the unix-only state above. One address form is refused even here, in the unprivileged tier: an
`AF_UNSPEC` address in a send, which a UDP or raw socket sends to as the `sockaddr_in` behind the family word
and which that tier cannot place — a `NULL` address or `AF_INET` spells the same send
(`docs/p0/supervisor.md` R4, R7); it refuses a spelling, not a destination. An exec is still a read of the program (§4), so an undeclared binary under a
`deny_read` the tier enforces is refused as `read-denied`. Tier 2's fanotify exec check reads the same absent-exec
policy through `decide.ListenerExec`: an undeclared binary is not refused merely because no `exec:` section
was declared (`internal/runtime/enforce/cgroup`, `decideExec`).

**The `models[]` forwarder boundary (amended 2026-10-01; recorded 2026-10-05 as ADR 0040 (2)).** Under `capture: forwarder`, known model endpoint
addresses and their local aliases are refused even if `net.allow` names them. Under a `net:` section, for a model
declared by a non-localhost name, all undeclared destinations on its port are also refused (`models.port[host:port]`);
only explicit unrelated `net.allow` destinations and the runtime's capture-listener grant may pass. This closes
divergent DNS/direct-IP bypasses without restricting unrelated ports. *Amended 2026-10-05:* the port
reservation applied with no `net:` section too, which made a contract that declares no network policy refuse every
other HTTPS host (`pip`, `npm`, `git` over https) at tier landlock, where `capture: auto` is the forwarder, and
`compile` only warned (`model-port-restricted`, now removed). With no `net:` section the port is again not reserved,
as before 2026-10-01: the run refuses the model's resolved addresses and local aliases and, until its name has
resolved, every destination on its port (`rule: unresolved`), and admits another address there `unmatched`;
`Evaluate`, which never resolves the name, answers `refused`/`unresolved` for every literal on that port and `allow`
for another name. An address only the agent's resolver returns therefore reaches the model under no `net:`
(supervisor R7's Limit (a)); only a `net:` section closes that. Local alias checks enumerate interfaces
at each decision and fail closed on enumeration errors. Uprobe and off capture keep ordinary network policy.
Explicit allowed intermediaries and alternative service ports remain trust grants; see supervisor R7 for syscall
coverage and the batch forms that fail closed as unsupported. Guarded non-stream IP batches that cannot be
relayed safely return `ENOSYS`; supported single-message forms use immutable copies.

**The kernel keyring, tiers 1 and 2 (amended 2026-09-23; 2026-10-05).** The kernel keyring is a non-namespaced, same-uid
credential store — on a RHEL/IPA host its default `KEYRING:persistent` ccache holds live Kerberos tickets — that no
`fs`, `net` or `exec` rule can see and Landlock has no right for, so left to run unseen it is a credential channel the
ledger never records. (The planned BPF-LSM hook set had no `security_key_*` hook; since 2026-10-04 the plane's optional
`key_permission` refuses keyring access in its modes unless `keyring: true`, a second layer under the rule below;
ADR 0024's 2026-10-05 note.)
Its three syscalls are therefore decided by the contract's top-level `keyring:` scalar (a boolean, merged like
`io_uring:`):

| `keyring:` | `add_key`, `request_key`, `keyctl` |
|---|---|
| absent or `false` | refused with `-EPERM` and recorded `refused reason=read-denied rule=keyring op=<syscall>`, as Docker's and firejail's default seccomp profiles refuse them |
| `true` | continued; each binary's first use of each syscall in the run is recorded `gap what=record why=keyring-<syscall> binary=<exe>` |

An observe run enforces nothing (§3), so it continues them whatever the contract says and records the same gap line,
which is how a learn pass over an observe run sees that the agent needs `keyring: true`. The use is a `gap` because
record v1 has no keyring action kind — a new kind is a `v: 2` bump (VERSIONING §2) — and a gap is the existing
kind that says "this happened and the record cannot describe it as an action"; it names the syscall and the binary,
never a key id or its payload. Refusing by default is the fail-closed choice over the spec's former silence, and
`keyring: true` is what a Kerberos-keyring host's contract declares.

**System V IPC, tiers 1 and 2 (amended 2026-09-24).** Shared memory, message queues and
semaphores live in the IPC namespace, which tiers 1 and 2 share with the host, and are reached by small ids anyone can
guess: a segment made outside the run was attached read-write inside it, and the ledger had no line about it. No
`fs`, `net` or `exec` rule can see them and Landlock has no right for them. Their syscalls are decided by the
contract's top-level `ipc:` scalar (a boolean, merged like `keyring:`), exactly as the keyring's are:

| `ipc:` | `shmget`, `shmat`, `shmctl`, `semget`, `semop`, `semtimedop`, `semctl`, `msgget`, `msgsnd`, `msgrcv`, `msgctl` |
|---|---|
| absent or `false` | refused with `-EPERM` and recorded `refused reason=read-denied rule=sysv-ipc op=<syscall>` |
| `true` | continued; each binary's first use of each syscall in the run is recorded `gap what=record why=sysv-ipc-<syscall> binary=<exe>` |

An observe run continues them and records the same gap line. `shmdt` is not decided: it takes an address, and an
exec leaves no segment attached. POSIX message queues (`mq_open`) are refused at every tier whatever `ipc:` says,
because their filesystem lies outside every rule of the Landlock domain (a test pins it); POSIX
shared memory and semaphores are files under `/dev/shm`, decided by the `fs` rules. `ipc: true` is what a contract
declares for an agent that starts a PostgreSQL server or an X client using MIT-SHM. *Condition:* a root tier could
give the run a private IPC namespace in place of refusing, which would make `ipc: true` safe to grant; that is not
built, so `ipc: true` reaches the host's IPC objects at every tier.

**A `deny_read` directory's names and activity (amended 2026-09-24, 2026-11-02).** At tiers 1 and 2 a `deny_read`
directory refuses reading its files' contents, not listing them: Landlock's `READ_DIR` is inherited from the nearest
granting ancestor, so `ls` of a `deny_read` directory under a readable one lists its names. An inotify, fanotify or
dnotify watch of it is refused at every tier (*amended 2026-11-02*; before, such a watch reported which of its files
were opened and changed; not `fs.watch`, §7): a watch opens nothing, and neither Landlock nor a decision plane has a
hook for one, so the seccomp filter of every enforcing run notifies `inotify_add_watch`, `fanotify_mark` and `fcntl`'s
`F_NOTIFY` (dnotify, which watches the directory a descriptor holds, such as one the agent opened to list the target),
and the supervisor refuses with `EACCES` a watch whose object a read of would be refused, or held for a person
(`fs.ask_read`, §6: a watch has no answer to wait for) — the target, anything beneath it, a name that leads there (a
symlink, a `..`, a `/proc/self/fd` link) and a fanotify mark or dnotify watch of a descriptor of it — and continues the
rest. The refusal is a `refused` line: op the syscall (`fcntl` for dnotify), target the name watched (a descriptor's own
file by its path), reason `read-denied`, rule the entry, block or fence entry that refused it. A watch follows the run's
reads: it is refused wherever a read of its object is, by a `deny_read` target, by a file a name entry covers at tiers
cgroup and bpflsm (§2; reason `path-unresolved`, rule `unmatched`, where the entry's climb cannot decide, as for the
read), by a name rule or tego's own state where the run holds its reads (`fs.reads`), and by a live read or path block
or an unlifted read fence entry (§6); and a `deny_read` nested in a write entry at tier landlock under
`fs.reads: direct`, whose reads the ruleset leaves open, leaves its watch open too. It differs twice: a live block
refuses a watch of what it covers also in a run whose reads tego does not see, where it refuses no read; and a read
gate's score is not asked, since a gate scores no watch, so a watch of a file only a read gate would refuse is made. A
fanotify mark of a whole mount, filesystem or mount namespace (privileged, so `setuid: true` at a root tier) reports
every file it covers, the targets on that mount included, so it is refused wherever it is placed, with the `EPERM` an
unprivileged caller meets anyway, rule `deny-read-watch`. The supervisor decides on the copied pathname or descriptor,
best effort as for `deny_write` (§2): a sibling thread that rewrites the name or swaps the descriptor, or a process that
repoints a symlink, between the check and the kernel's own lookup places the watch elsewhere. A watch of the directory
that holds a target is not refused, so it still reports a target file's own activity (an `.env` in a watched project,
`~/.netrc` in a watched home) and a target directory's own entry, as a listing shows their names. A contract that must
hide a secret's name or its activity, not only its bytes, keeps it outside every readable tree (GAPS A10).

## 2. Filesystem rules

*Note 2026-09-29 (ADR 0024/0025/0028, accepted; steps A to D built, at tier 2 and as tier `bpflsm` (T7, T13, T14; corrected 2026-09-30); [enforce-plane](../../docs/p0/enforce-plane.md) R5 to R11, R25):* at tier 2 where a plane mode is selected (and at tier 3, tier `bpflsm`) the nearest-wins walk below is decided in the kernel by the plane on the object the kernel resolved, for opens, execs, renames, links, unlinks and rmdirs (and, from step B, mkdir, mknod, symlink, truncate, chmod, chown and the xattr/ACL protection hooks), and "Identity" below is amended: rows are keyed by the kernel inode pointer in per-run maps pinned by the run's Landlock domain, not by BPF inode storage (ADR 0010, superseded by ADR 0025). Each tier's statement of the rule comes from one core, `internal/policy/decide` (ADR 0028; `decide.CompilePlane`, `PlaneEvaluator`, `TestPlaneRowsMatchEvaluate`). The text below stays as the rule's statement; the plane implements it.

**Identity.** Every `fs` entry names an existing directory or file. `compile` (unprivileged) checks existence and
prints each entry's mount, filesystem type and device, warning on mount points, overlay layers and btrfs; `run`
creates declared `write` directories and refuses to start for other missing entries. A `write` entry is a path, never
a glob: one holding `*`, `?` or `[` that names nothing is `path-missing` at `compile`. Identity is taken by `run`:
each entry is opened `O_PATH` and the fd is held for the run, which pins the inode; the root tiers key the inode in
BPF inode storage (ADR 0010), the Landlock tier adds rules from the same fds. A `(device, inode)` pair is never used.

**The walk (root tiers).** At a hook the kernel walks the target's `(mount, dentry)` upward, crossing mount roots
into the parent mount like `d_path` and Landlock do, bounded to 64 steps, and the **nearest ancestor with an entry for
this run** decides; ancestors carrying only other runs' entries are skipped. A walk that ends without a hit is
`unmatched` (reads allowed, everything else refused); a disconnected dentry or an exhausted bound is refused with
`path-unresolved`.

- Nearest wins: `write: [/work]`, `deny_read: [/work/secrets]` refuses reads under `/work/secrets` and allows writes
  elsewhere under `/work`.
- A rule on `/work` covers a tmpfs or a second disk mounted under it. An entry that is itself a mount point resolves
  to the mounted filesystem's root.
- Bind mounts share dentries and inodes with their source: a rule on the source directory applies through the bind,
  including a container volume, with no path translation; a rule on an ancestor of the source does not.
- An overlay rootfs has its own superblock: rules on upper or lower directories never apply to the merged tree and
  vice versa; an adopted container's rootfs gets its own entry from `containers.rootfs` (default `write`).
- Hard links and renames cannot move a file out of a rule but can create a name under a less restricted directory:
  `path_link` and `path_rename` refuse when the source's nearest entry is more restrictive than the destination's,
  which is Landlock's `REFER` rule, so both tiers behave the same. *Amended 2026-09-24:* a `deny_read` nested in a
  write entry is the exception Landlock's `REFER` cannot see (the write entry's rights are equal on both ends), and
  at tier 2 the fanotify listener enforcing it matches paths, so a link or rename out of it was an escape; the
  supervisor refuses such a link or rename at tier 2, best effort (docs/p0/supervisor.md R15d). At tier 1 the entry
  refuses no read (compile warns `unenforced`); tier 3 decides on the inode. *Amended 2026-10-17:* Landlock's `REFER`,
  which every tier keeps under its own decision, also compares the rights its ruleset grants rather than the entries'
  kinds: a file moved or hard-linked into an `exec.allow` directory inside a write entry gains `EXECUTE` there and is
  refused (`EXDEV`), and a hard link needs `REFER` on the source's directory, which a write entry naming a single file
  does not grant, so such a file gets no second name in another directory. The ledger and `compile --test` say so at
  every tier (docs/p0/supervisor.md R17). *Amended 2026-10-17:* the comparison is the
  kernel's: a rename or link within one directory compares nothing; across directories the rights at the new name's
  directory are compared with the moved object's own, never with a rule on the name it replaces, so replacing an
  `exec.allow` file entry inside a write entry (`mv out/tool.new out/tool`) is allowed; and only the file rights count
  for an object that is no directory. *Amended 2026-10-17:* a rename, a link and an
  unlink act on the name itself, never following a final symlink, so an end that is a symlink fs entry's own name is
  the symlink, decided by its own directory (the entry governs its target, not the link); and a rule is on the inode
  its entry named when the run started, so an `exec.allow` directory renamed inside a write entry keeps its `EXECUTE`
  under its new name, and a directory made at the old name has none. The ledger follows the inodes; `compile --test`
  answers the starting tree. Tier 3 keeps Landlock's directory rights under its hooks: a write entry naming a single
  file is refused a rename or an unlink of itself at every tier.
- Creating a fifo, socket or device node is a write on the parent directory in both tiers.

**The Landlock tier.** Landlock is allow-only and, within a layer, grants an access if any rule on the path grants
it (union, not nearest-wins). So:
- `deny_read: X` compiles as **sibling enumeration** at every level from X's parent up to `/` of the run's mount
  namespace (verified by experiment: stopping below a `READ_FILE` ancestor leaks the secret; stacked
  layers only intersect and cannot express a deny): no ancestor of X receives `READ_FILE`; each enumerated ancestor
  receives `READ_DIR` (listing and `stat` work, contents do not); every sibling directory receives the tier's default
  read set (`READ_FILE|READ_DIR|EXECUTE`); a sibling file receives file rights only (a directory right on a file is
  `EINVAL`). Rules are added from the `O_PATH` fds the launcher holds. A domain cannot change after
  `landlock_restrict_self`, so an entry created during the run at an enumerated level gets no rule: it is unreadable
  and cannot be renamed or hard-linked into a readable sibling (`EXDEV` under `REFER`). The record (*amended
  2026-10-25*, [ADR 0067](../../docs/adr/0067-agent-token-stores-and-credential-rows.md) D3): a read at or beneath the
  name the ruleset leaves out for a built-in row absent at compile is recorded refused, `read_denied`, named by the row,
  at every enforcing tier, and `compile --test` answers the same; a read of any other entry created at an enumerated
  level is recorded with the verdict the contract gives it (allow), though the kernel refused it, since no model knows
  the names an enumerated directory gains after the ruleset was built (enforce-landlock E10).
- **Stated exception: an exec grant carries read (*added 2026-09-29*).** A declared `exec.allow` entry that lies
  strictly inside an enforced `deny_read` target (a file, or a directory whose whole subtree) stays **readable** at
  tier 1: `file_open` opens the program `O_RDONLY|__FMODE_EXEC`, which sets `FMODE_READ`, so Landlock requires
  `READ_FILE` for an exec and the grant cannot be `EXECUTE` alone (enforce-landlock R5, I11 (1)). The `deny_read`
  holds for everything else beneath the target. `compile` warns `unenforced` for each such entry, naming both
  (agent-contract R15), and `Evaluate` and the supervisor's advisory verdict report the read `allow` under the exec
  entry's name. Tier 2 does not share the exception: its fanotify listener decides every open by the nearest-wins
  walk and refuses the read (`read-denied`), though the exec itself still runs. Tier 3 decides on the inode and
  refuses it too. An exec entry at the target is a sealed deny node (E32 (c)) and one above it leaves the target
  unenforced; neither is this exception.
- A `deny_read` entry is compiled in this tier only when no enumerated level lies at or below a `write` entry or an
  `fs.ask` entry (the supervisor's `ADDFD` creates files there outside the domain); otherwise `compile` reports it
  `unenforced (landlock: parent writable)` and the run's capability matrix carries it. In particular `.env` inside a
  writable worktree is enforced by the root tiers only. *Amended 2026-10-24 (ADR 0069):* the ruleset still cannot
  enforce such an entry, but under `fs.reads: auto` (the default) such a target makes the run hold its reads at tier
  landlock: the seccomp filter notifies every open, the open deputy (ADR 0041 Stage B) pins and opens every
  read-capable open (`O_RDONLY`, `O_RDWR`, a directory, `O_CREAT` with read access) in the run's own domain, and the
  supervisor refuses it `read-denied` on the object the deputy reached when that object lies at or beneath a
  `deny_read` entry that is the nearest entry deciding a read there, nested or not (a nested target directory itself
  included), so `.env` inside a writable worktree is enforced at tier landlock too. `compile` warns `held-reads` at
  each such target, with the cost (about 0.1 ms per read open), and `compile --test` answers its read refused.
  `O_WRONLY` and `O_PATH` opens are not held. What it does not catch: the target renamed or hard-linked to another
  name and read there (capability `fs.deny_read.moved`, false at tier landlock until ADR 0069's identity pinning);
  one written or replaced during the run from outside it and then moved; a device outside the mem and tty classes is
  refused while reads are held. `fs.reads: direct` keeps the entry `unenforced` as before.
- Globs in `deny_read` are expanded at compile time to existing matches under `$HOME` and the worktree in every tier;
  files created later are not covered and `compile` says so. *Note 2026-09-30 (ADR 0039, a design, not built):* at
  tier bpflsm a glob whose last component is an exact name (the built-in `.env` scan's) will also be a name-keyed
  row scoped to the directories it was expanded under, which denies a matching file created later as well: a
  tier-3 strengthening, shown in `compile --test`'s bpflsm column, never a wider rule. *Note 2026-10-05 (ADR 0043,
  which amends 0039; decided, the compiler and the decision core built, no tier enforces it yet):* a name entry is
  the built-in `.env` list (exact `.env`, and the prefix `.env.` but `.env.example`, `.sample`, `.template` and
  `.dist`) or a declared glob whose last component is a literal or a literal and one trailing `*`; it matches the
  final name ASCII-folded, beneath its scopes (the contract's directory and the run's working directory for the
  built-in, the glob's literal base for a declared one) outside the dependency directories the scan skips, and
  decides a covered file as a `deny_read` entry at its own path would, creation included, at tiers cgroup and
  bpflsm; a directory rename that takes covered files out of coverage is refused there. Tier landlock keeps the
  compile-time expansion. Until the plane and the fallback enforce it, `compile --test` and the plane's rows answer
  as if no name entry existed, so no column predicts a refusal no tier makes. *Amended 2026-10-24 (ADR 0069 D3
  (c)):* where the run holds its reads (§1, `fs.reads`), a read of a file such a rule covers is refused whenever the
  file was made: a declared `deny_read` glob matched against the object's path and its ancestors, the built-in home
  paths while the built-in list is on, and the built-in `.env` names ASCII-folded beneath the scan's roots outside
  the dependency directories (D3's exemptions kept). That is how tier landlock refuses a `.env.local` made during the
  run, at `auto` whenever reads are held, and every enforcing tier under `fs.reads: held`; `compile --test` answers
  the same. *Amended 2026-10-25:* a write entry nearer the object than the ancestor such a rule
  matched reopens its own subtree, as the nearest entry does in the walk above: `fs.write: ["~/.ssh/out/"]` keeps
  its reads while a `.env` elsewhere makes the run hold them, and the rest of `~/.ssh` stays refused. *Amended
  2026-10-25:* `compile`'s warning at a whole `deny_read` glob, and its `names` heading, say at which
  tiers a matching file made during the run is refused because the run holds its reads, and keep "not covered" for
  the tiers that read direct. *Note 2026-10-27 (ADR 0043 enforced, ported):* every build enforces name entries at tiers cgroup and bpflsm, the plane's name check in a plane
  mode and, on tier 2's fanotify fallback, the listener's refusal of an open by name and the supervisor's best-effort
  refusal of a creation, link or rename onto a covered name; `compile --test` and the plane's rows answer with them.
  An entry the per-run caps leave out keeps only its expansion, and `compile` warns `unenforced` naming it; for a
  glob whose entry is kept, `compile`'s glob warning says files created later are covered at tiers cgroup and
  bpflsm and not at tier landlock.
- A landlocked task cannot `mount`, `move_mount`, `umount`, `remount` or `pivot_root` (§10).

**One statement per tier, implemented once** (*amended 2026-09-28*, ADR 0028). The root tiers' walk and the
Landlock tier's union above, with tier 2's listener between them, are each implemented in one place, the decision
core `internal/policy/decide`, and every component that decides or predicts a verdict asks it: `compile --test`,
the supervisor's advisory verdict, tier 2's fanotify listener and recorder, and tier 3's plane rows. The kernel still
judges; the core is what the tiers' predictions and records are held to, so they cannot drift apart.

**Implicit entries** compiled into every ruleset, even when `fs:` is absent: the run directory, the contract file,
`/sys/fs/cgroup`, `/sys/fs/bpf` are never writable from inside the run. The run directory lives outside every declared
write directory (`compile` reports `contradiction`; `run` exits 125), because Landlock cannot deny beneath an allow.
*Amended 2026-09-24:* tego's own files are never **readable** from inside the run either: tego's directory
(`~/.tego`: the chain anchor, the machine config, the price table, the profiles, tego's own log), the ledger root and
the host state (`/run/tego`) are read-denied whatever `deny_read` says, `deny_read: []` included (agent-contract R6a).
Before, every run's `events.jsonl` and blobs were readable from inside any run, so a stricter run could read what a
looser one had recorded. A ledger root that also holds the project (a shared data disk, `/tmp`) cannot be denied
without denying the agent its own files, and `compile` says so (`ledger-readable`).
*Amended 2026-10-20:* the user registry's `agents/` and `skills/` (the machine config's `registry:`, agent-contract
R26) are never writable from a contract: a write entry at, over or inside either is a `contradiction`, since every
later `tego run <name>` the user registry answers loads what is there. They are not read-denied: an `fs.ask_read`
entry beneath them compiles and a held read there is asked as anywhere else (§6). A write entry over
the directory that holds a symlink on the way to them, or to any other path tego keeps every write entry off, is a
`contradiction` as well (agent-contract R10): with `~/.config/tego` a link into a dotfiles tree, a write over
`~/.config` would let the agent repoint the registry.
*Amended 2026-10-20 (ADR 0059):* no run writes what a later run loads. The contract is protected as the file it is,
by every name the walk of its whole path reads, so a write entry at the contract file itself, or over the directory
of any link in its path's chain, is a `contradiction`; so is one reaching any layer file of the machine config, which
decides the registry, the profiles, the prices and the ledger root of the runs after. What a name comparison cannot
see, the loaders refuse: a registry entry is read through `agents/` itself, never following a link out of it, and a
layer, the price table, a profile, a registry entry or a contract with a second name (a hard link) is untrusted
unless no run of the user could write it by any name. A run cannot give such a file a second name, since Landlock
grants a link out of a directory only beneath a write entry.
*Amended 2026-10-20 (ADR 0059 (1)):* "every name the walk reads" is every name: a write entry over any
directory the walk of a protected path looks a name up in is a `contradiction`, whether that name is a symlink now, a
directory a later `..` leaves (`registry: <w>/sub/x/../../reg` and a write over `<w>/sub`) or nothing yet, since the
agent could make it a link and choose where the next walk lands.
*Amended 2026-10-16:* tego's runtime parent, `$XDG_RUNTIME_DIR/tego`, where every run keeps its private directory
(its generated `CODEX_HOME`, its last-refusal mirror), is never writable from a contract either: a write or ask entry
at, over or inside it is a `contradiction` (`run` checks it again, exit 125), and so is one over the invoking user's
logind directory, `/run/user/<uid>/tego`, whatever the environment says (a launcher under plain `sudo` or cron has
no `XDG_RUNTIME_DIR`, and the same user's other runs keep their directories there). A run's own `CODEX_HOME` is a
write grant the run makes itself, on exactly that directory, rule `fs.codex_home[<path>]`, and an `exec.allow` or
`exec.ask` directory over it refuses the run, since everything the agent wrote there would run (agent-contract R10a).
Its reads are not denied (an open condition: another run's agent of the same uid can read it where no `deny_read`
covers it, the `auth.json` of a key typed at Codex's login screen included; docs/OPERATIONS.md gives the interim
measure, *amended 2026-10-17*). Its writes are closed to enforcing runs only: an `--observe` run enforces no
file-system rule, so its agent, like any of the user's processes outside tego, can write it (*amended 2026-10-17*).

**The built-in `deny_write` set** (agent-contract R20, added 2026-09-23) names what a write entry reaches that runs
code outside the run when something else next reads it: the git hooks and config of the repositories the entry is or
holds (found within one bounded budget per entry beneath an entry that is not itself one), of their submodules, and
the directory each `core.hooksPath` names (Husky's `.husky`, a `.githooks`, including one the repository enclosing the
entry names beneath it), the harness and editor settings (`.claude`, `.mcp.json`, `.cursor`, `.codex`, `.gemini`, `.vscode`) at the entry's
root and at each repository's, the shell startup files at its root, and a home dotfile that resolves into it. In the root tiers' walk each is an entry nearer than the write entry that allows reads and refuses
writes, so nearest wins as for `deny_read`; a declared write entry at a target's own path drops it from the set.
A target that is a symlink is held at the link's own place as well as where it leads, and at the link alone when it
leads out of every write entry (*amended 2026-10-25*: such a link was left out, and the agent could
replace it with a directory of its own). A file beneath a directory target with another hard link when compile runs
is keyed by the plane at its inode (a write through the other name walked to the write entry), once per
file, as for the entries below.
Landlock cannot express this denial beneath an allow without also preventing ordinary file creation around it.
A working kernel decision plane (cgroup with lsm/fmod_ret, or bpflsm) refuses a write to a target race-free: its
attached hooks decide their supported actions on held inode identities, with the deny_write entry nearer than the
write grant. Where no plane decides the run (tier landlock, tier cgroup on the fanotify listener) the seccomp
supervisor refuses a modification that reaches a target on its copied pathname (supervisor R15c): best effort, not a
closure, since a sibling thread or a swapped symlink between its check and the kernel's own lookup, or a hard link
made before the run, can still reach one. That is the default (`fs.assurance: best-effort`), disclosed: `compile`
warns `unenforced` once per target, and run_start's `best_effort` lists `deny_write/default`. A contract that says
`fs.assurance: kernel` is refused before its child starts wherever no plane would decide its targets (exit 125;
a compile error at a tier landlock the contract pins or the machine config holds). `compile` names the targets
and reports bounded search failures: the repository search's as warnings under either setting, since it finds the
targets, and the linked-file search's (below) as an error under `fs.assurance: kernel`, since it decides whether the
plane holds a named target against a hard link. *Amended 2026-10-05 ([ADR 0041](../../docs/adr/0041-race-free-supervisor-decisions.md) D1 (a)):*
from 2026-10-03 to now every run with a target and no plane was refused; before that, and again now by
default, such a run went ahead on the supervisor's best-effort refusal. The model and plane use the same compiled targets
(`RuleTable.DenyWrite`). With git's config in the set, git's own writes to it (`git config`, `git remote add`,
`git push -u`) are refused too; an agent that needs them names `.git/config` in `fs.write`.

**A contract's own `fs.deny_write`** (*added 2026-10-25*, [ADR 0071](../../docs/adr/0071-user-deny-write.md)): blocked
for ordinary commands; not race-free at the no-root tier. Each entry is a literal file or directory, spelled as any
`fs` path (a glob character is a `schema` error), and each one beneath a write entry is a rule of its own beside the
built-in targets (`BuiltIn` false), named `fs.deny_write[<entry as declared>]`. It refuses what a built-in target
refuses, at and beneath it: a write-open, a create, a truncate, an unlink, an rmdir, a rename at either end or of a
directory above it, a link, a symlink, a mkdir, a mknod, and, where a decision plane decides, a chmod, chown or xattr
change. Nearest wins: a write entry strictly beneath an entry reopens its own subtree (`write: [./, ./deploy/tmp/]` with
`deny_write: [./deploy/]` leaves `deploy/tmp/` writable and the rest of `deploy/` refused), and the reopening entry is
not redundant; its own name `deploy/tmp` stays the entry's, so a rename of it at either end and a create of the name
(a mkdir, a mknod, a symlink, an exclusive create, a hard link's new name) are refused, while what it names stays
writable and removable (an `O_CREAT` open that makes it anew after a removal is continued below a plane and refused by
one); a built-in target is never reopened, a write entry inside one granting nothing beneath it (only one at
its own path lifts it), and an entry at a built-in target's place never takes the target's place: both rules hold,
the entry naming the refusals it reaches. An entry is placed where it leads and, when its name is a symlink, at the
link's own place, where it is held even when it leads out of every write entry, since a link beneath a write entry can
be replaced (the same holds for a built-in target). An entry at a write entry's own path is a contradiction; one outside every write entry and
every `fs.ask` scope, or beneath another entry with no write entry between, is `redundant-rule` from the top-level file
and silent from a profile; one that does not exist is `path-missing` from the top-level file and an `unenforced`
warning from a profile, since no tier holds a name with no inode and the agent may create it; one only an `fs.ask`
scope covers is kept from every approval. Enforcement is the built-in set's: race-free in the plane's inode rows (tier
cgroup with lsm or fmod_ret, tier bpflsm), a hard link made before the run included, to a file entry or to a file
beneath a directory entry, whose inode compile records for the plane when it has another link: one name
per file, since the plane keys one fs row per inode, and none for a file whose every name lies beneath a deny_write
place or whose inode another row the plane keys refuses modifying, while a file another row grants writing (an
`fs.write` file entry) is a `contradiction` (*amended 2026-10-25*: each name was keyed, and a table two
of whose rows were one file ran on the fanotify listener at tier cgroup and was refused at tier bpflsm). The search
adds at most 256 rows to the plane's 4096 (a table past them runs on the listener at tier cgroup and is refused at
tier bpflsm, as any table) and is bounded; where a bound cuts it, compile warns at the entry, and under `fs.assurance:
kernel` the cut is an error, since a file the search did not reach may be written through another name at every tier
(*amended 2026-10-25*); best effort at
tier landlock and on the fanotify listener (supervisor R15c, on the copied pathname), where `compile` warns per entry
"best effort at tier landlock", run_start's `best_effort` lists `fs.deny_write`, and `fs.assurance: kernel` refuses
the run as it does for the built-in set.

**Why not strings.** From a BPF LSM program `bpf_d_path` is allowed only on hooks in the kernel's sleepable set; the
`path_*` hooks are in it from 6.8 and `bpf_path_d_path` exists from 6.12, so string rules would not run on 6.1–6.7; the
sleepable `inode_*` hooks provide no `struct path`; and a prefix does not follow a rename, a hard link or a bind mount.

## 3. Verdicts and precedence

`ask` scopes are implemented as bounded local approvals under §6. Static evaluation and kernel rows remain refused until the live supervisor safely completes the approved operation.

Kernel decision first, gate second, gate only escalates.

1. **Lists decide in the kernel** (or in Landlock): inside `write`/`allow` → `allow`; inside `ask` → `ask`, which is
   compiled as refused (an ask entry carries no rights of its own; the approval is the supervisor's `ADDFD` or
   connect-on-duplicate, never a `CONTINUE`); otherwise → `refused` with a reason code. Other modifications inside an
   `fs.ask` directory (rename, unlink, mkdir, truncate, chmod) are refused, not asked. *Amended 2026-10-27
   ([ADR 0047](../../docs/adr/0047-fs-ask-mutations-made-on-pinned-names.md)):* unlink, rmdir, mkdir, rename, symlink and link inside a
   scope that asks are now `ask` too, held whole and, once approved, made by the supervisor as the agent on the
   directories it pinned (never continued); a rename or link whose ends lie in different entries is refused `EXDEV`
   as unsupported; truncate, chmod, chown, xattr and mknod stay refused (§6). *Added 2026-10-06:* a
   read inside an `fs.ask_read` entry is `ask` the same way: compiled as a `deny_read` (refused, read-denied, named
   `fs.ask_read[...]`), and completed only by tier 1's supervisor with `ADDFD` (§6).
2. **The gate runs in the supervisor** on copied facts of actions that reach it (asks, execs with argv, and enabled open/network action kinds in full, summary and off). A gate rule can raise `allow → ask` or `ask → refused` by score against `thresholds`; it never
   lowers a verdict. Predicates are a closed set: `fs.write outside worktree`, `fs.read matches <glob>`,
   `exec matches <argv pattern>`, `net to undeclared host`, `net to <host:port>`. No expressions.
   *Amended 2026-11-01:* `net to <host:port>` on this host is on the destination, not a spelling of it: it scores every
   loopback address, each of the host's own, and a group or broadcast datagram on its port (gate.md R3).
   *Amended 2026-11-02:* what the kernel's routing tables send here (their `local`, `broadcast` and `anycast` routes in
   tables local, main and default) is this host as well: an address of an AnyIP range counts as one of the host's own,
   and a datagram to a broadcast address set by hand or to an IPv6 anycast address the host joined as a broadcast or
   group datagram (gate.md R3).
   *Amended 2026-10-06 (ADR 0048 (1)):* exec command rules are lists and decide before the gate, after the image
   floor: any `exec.deny` match refuses, any `exec.ask` match refuses (reserved), and a constrained tool's unlisted
   invocation is refused; specificity never changes the order, and no exception syntax exists.
3. **Nested runs compose**: allow lists intersect, deny and ask lists union, limits take the minimum, `record` the
   more verbose. A child can never do more than its parent.
4. `authority` on the event records who decided: `rule` (lists), `gate`, `human`, `llm` (a decision event).

The bounded implementation is specified in agent-contract R22a. Scores sum to at most 100 (the sum, not the highest rule), across both fs kinds for an action both score, a read-write open or a rename's or hard link's source (*amended 2026-10-20*, ADR 0007), and across both ends of a rename or hard link, one action whose every matching rule counts once (*amended 2026-10-20*, ADR 0007); an `fs.read matches` pattern holding a `/` is component globs matched one name at a time against a clean path, and compile refuses one no clean path matches (*amended 2026-10-20*, ADR 0007); a score below `allow` allows, `allow` to `ask` asks and above `ask` is refused (defaults 50/80; *amended 2026-10-20, ADR 0007:* a score of exactly `allow` asks, and `allow` is at least 1); a refused floor remains refused. Hostname predicates need an existing declared DNS binding and match every covering current alias. Approved regular-file read/write opens and ordinary TCP connects/first-write holds use safe held objects; separate fs.ask remains write-only, and `fs.ask_read` (added 2026-10-06, tier landlock only) holds regular-file read-opens (§6). A held file open, read or write, also takes a third answer, an alternate file (§6). UDP/Unix/raw, Fast Open, non-open filesystem mutation and exec approval completion are unavailable and explicitly refuse. IP datagram batches return ENOSYS while frozen individual datagrams are supported. Exec matching conservatively checks the requested copied executable name, resolved copied image name and copied argv[0], each with argv[1:], under 128 arguments/4096 bytes; unreadable/truncated relevant facts refuse. Each of those names is a basename, so an `exec matches` pattern's first word cannot hold a `/` and is refused at compile, its fix naming the basename (amended 2026-10-05: `exec matches "/usr/bin/curl *"` was accepted and never fired). This is copied-syscall provenance, not proof of immutable final argv or pathname. *Amended 2026-10-05 ([ADR 0041](../../docs/adr/0041-race-free-supervisor-decisions.md) D6):* a connect, Fast-Open send or addressed datagram a network gate admits on an IP-domain socket is performed by the supervisor on the copy the gate scored, so for those the scored destination is the one used; filesystem and exec gate verdicts stay copied-syscall provenance (ADR 0041 D1). *Amended 2026-10-16 ([ADR 0041](../../docs/adr/0041-race-free-supervisor-decisions.md) Stage B):* under `gate.completion: held`, an open of a filesystem kind the gate can score to allow or above (*amended 2026-10-20*, ADR 0007) is decided on the object the run's open deputy pinned and completed by the deputy on that object, in the run's own Landlock domain, cgroup and credentials, never continued (`gate_facts: held_object`); an `O_PATH` open, a non-open mutation and exec stay copied-syscall provenance. The default, `copied`, changes nothing. Kernel outcome lines retain additive gate metadata and their actual final verdict. `compile --test` remains a pure hypothetical evaluation and cannot approve a live operation. *Amended 2026-10-25 ([ADR 0071](../../docs/adr/0071-user-deny-write.md)):* where a decision plane decides, a held write-open through a hard link made before the run to a `deny_write` file (an `fs.deny_write` file entry, a built-in file target, a linked file beneath a directory entry) meets the plane's EACCES in the deputy, and nothing is written; the open's one line is refused under the rule the plane keys that file at, explained by the opened object's identity (*amended 2026-10-25*: it kept the floor's allow with `syscall_ret` -13 and named no refusal, [GAPS](../../docs/GAPS.md) C38, closed).


## 4. Exec

*Note 2026-09-29 (ADR 0024 (4), 0027, accepted; R9 built for step A at tier 2, R26 built at T14 (§4's tiers 2 and 3 note on mapped code); [enforce-plane](../../docs/p0/enforce-plane.md) R9, R26):* below, the tier-3 sentence "allowed when its interpreter is allowed" is withdrawn, because tier 3 also installs Landlock, whose EXECUTE rule refuses an unlisted script; tiers 2 (where a plane mode is selected) and 3 decide exec only in `bprm_check_security`, by inode, parent inode and name (`TestPlaneExecComparesTheWholeName`). ADR 0027's tiers 2 and 3 rule for the dynamic loader and PROT_EXEC mmap follows that paragraph.

`exec.allow` entries are resolved paths or basenames; a basename matches the final component of the file's dentry
after symlink resolution, and `compile` prints the resolved candidates on `PATH`.

An exec entry (the command, an MCP server's command, an `exec.allow` entry or a pattern's command word) that is a
`/proc` path, or reaches one by its symlinks or its `PATH` directory, is refused by `compile` (`exec-proc`, *added
2026-10-16*): `/proc/self/exe` names the executable of whichever process opens it, so `compile` resolved it to tego's
own binary and the run granted that (docs/p0/agent-contract.md R8a).

### Command rules (added 2026-10-06, ADR 0048)

An exec entry with unquoted spaces is a *command pattern*: a command word, then words. `exec.deny: [git push]` never
runs `git push`; `exec.allow: [git status, git diff, git log]` runs git only as those (and git's own helpers, the
helper closure). One matcher (`pkg/policy/execmatch`) reads a pattern and an invocation with the tool's row
(docs/spec/exec-command-rows.md), so the subcommand is found behind global options, clusters, abbreviations, dashed
and argv[0] forms, multicall binaries, interpreter entry points and git's autocorrection. Where the row cannot be
sure how the tool reads a token, every reading is kept: a deny or ask entry matches when any reading matches, a
constrained allow entry only when every reading does.

- **Option words** in an allow entry are required (not a whitelist); in a deny entry each must be present anywhere
  the tool could read it. Options a pattern does not name are free. **Operand words** in an allow entry equal the
  operands in number and order (a trailing `*` allows more); in a deny entry they are an ordered subsequence.
- **Precedence** (§3): the image floor, then deny, then ask (refused, reserved), then a constrained tool's unlisted
  invocation, then the gate.
- **Constrained tool**: one an allow entry names with words, unless a bare name entry or an implicit grant (the
  agent command, an MCP server's command, their `#!` interpreters, `tego run`'s command) names it.
- **Enforcement.** At every tier the supervisor decides on copied argv and refuses before the syscall runs (R). An
  allow is a copied fact (D), disclosed as the cell `exec.rules/argv`; ADR 0048's P2 pins the decided facts in the
  kernel at plane tiers. *Amended 2026-10-19 (ADR 0048 P2, built; [enforce-plane](../../docs/p0/enforce-plane.md)
  §2.22):* at tier `cgroup` with a plane mode and at tier `bpflsm`, where doctor's exec pin cell (`plane.exec_pin`)
  passed in the run's mode, the kernel holds each exec the supervisor continued to the facts it decided:
  `bprm_check` refuses another image or interpreter (`pin-mismatch`; in a run with an exec gate alone, also a
  binfmt_misc handler with the P flag, which hands argv[0] on, unless the decided argv[0] is the exec's filename) or
  an exec with no pin (`pin-missing`), EACCES,
  and `sched_process_exec` kills an exec whose argument area differs from the decided vector or cannot be read
  (`argv-changed`, `argv-unreadable`, SIGKILL before the new image's first instruction); the exec's line says
  `argv_facts: kernel_pinned` only on the kernel's own proof, and the cell leaves `best_effort`. Elsewhere (tier
  `landlock`, the fanotify fallback, a mode whose cell did not pass, a kernel whose recorder has no exec outcomes) the
  cell stays (D), and `exec.assurance: kernel` refuses the run (exit 125).
- **Every image's `#!` line is read** in a run with command rules, since any ruled tool can be a script's
  interpreter. An image whose first bytes the supervisor cannot read is refused `image-unreadable`, EACCES, whether
  or not a rule names it: at tier landlock run unprivileged, where the supervisor reads as the agent's user, that is
  every execute-only file that user cannot read (RHEL's `sudo`, mode 4111). A supervisor running as root (tiers
  cgroup and bpflsm, `sudo tego run`) reads every image on a local file system; an NFS export with `root_squash`
  serves it as the export's anonymous user and a FUSE mount without `allow_other` or `allow_root` refuses it, so an
  image there that it cannot read is refused `image-unreadable`, or its exec answered `EACCES` where the walk is
  refused. `compile` warns at tier landlock.
- **A dynamic loader run as a command** (`ld-linux-x86-64.so.2 /usr/bin/rm -rf tree`) runs its program in-process,
  with no exec of the program's own, so the program is decided as the exec's image, with the argv the loader gives
  it (`command_via: loader`). A loader is known by a loader's name or by the identity of one of the host's loaders,
  never by its ELF type, which a static-pie program shares. A program the supervisor cannot read as the loader will
  is refused `loader-unresolved`, and in a run whose images are restricted one no `exec.allow` entry grants is
  refused `loader-program-unmatched`.
- **The harness hook's grant is one exact vector** (*added 2026-10-25*, [ADR 0064](../../docs/adr/0064-harness-hook-exec-grant.md),
  agent-contract.md R10a (5)). Under an allow-list contract whose rules do not admit a provisioned hook, the run admits
  the tego binary with the hook's argv only: a runtime command rule no contract can write, which matches when the whole
  vector equals it, argv[0] included, read to its end, with no glob and no trailing token, and only on the exec's own
  image. Every other vector of the binary is refused `exec-not-allowed` under `exec.harness-hook[<tego binary>]`. At
  tier landlock the vector is the supervisor's copy, as every command rule's is (best effort, `exec.rules/argv`).
- **A deny-list run's own `CODEX_HOME` is not a place to run from** (*added 2026-10-16*, agent-contract.md R10a).
  The run grants the directory for writing on its own authority; an exec whose image, or whose directly-invoked
  loader's program, lies there is refused `codex-home-exec`, since a copy of a denied program under another name is
  not that program to the command rules. A symlink there to a program elsewhere is that program. Where an image lies
  is the kernel's spelling of it, even where the supervisor cannot walk that spelling back to the file (*amended
  2026-10-17*: a copy in a directory the agent made unsearchable, run through its descriptor, ran).
  The run's `hook-state` directory, the write grant a harness provision makes (agent-contract.md R10a (4), R27, ADR
  0062), is held the same way under the rule `harness-state-exec` (*added 2026-10-24*).
  The refusal holds a copy linked there only (*amended 2026-10-16*): a deny-list leaves
  images unrestricted, so in every deny-list run a copy in a memfd (with or without a write entry) or in a file the
  agent wrote and then deleted runs as an image with no name, and a program's own file can be mapped into a process
  and run with no exec. A deny entry refuses a command, not the program's code; `compile` warns
  `exec-rule-coverage` on every deny-list. `exec.allow` keeps copies from running (a memfd, an image with no name, and at tiers cgroup and bpflsm
  a written file mapped executable, ADR 0027); a program's own file mapped executable where it lies is ADR 0027's
  residual in either mode.
- **A dispatcher the matcher cannot resolve within its bounds fails closed.** A multicall binary that re-dispatches
  to itself (busybox's own `busybox` applet, nested past the depth bound) could still reach a ruled tool, so rather
  than drop the interpretation the exec is refused `command-unresolved` (`command_via: overflow`), as an argv past the
  bound is refused `args-unreadable`. So is an exec whose reading yields more distinct interpretations than the
  matcher keeps (32), whatever the one past the bound would have been, and one a directly-invoked loader runs whose
  program's own reading overflows (*amended 2026-10-16*: both were dropped in silence and the exec decided on the
  rest), and an interpreter whose options make more readings than the row keeps (16), so that no reading names its
  script (*amended 2026-11-01*). In a run with command rules, an exec whose argv[0] was not read, unreadable or past
  the bound, is refused `args-unreadable` as well: a binary can read its applet from argv[0], so its names alone do
  not settle what runs (*amended 2026-11-01*).
  *Amended 2026-11-03 (C49):* Node's row inventories 20.19.4 and 22.21.1 with native and V8 argv
  arities ([row reference](../../docs/spec/exec-command-rows.md#node)). Each reading stops Node options
  at the entry script, so ordinary script flags do not fork that reading. *Review correction:*
  config/default-config raw prefixes anywhere in argv, and env-file raw prefixes before `--`,
  can still load code after the script and are refused. Node allows require the whole bounded
  vector. *Round-3 architecture decision:* exact inventoried standalone executable hashes select
  the full inventory; unknown hashes/versions/builds, shared-libnode launchers and absent
  attestations select exactly master's Node row plus these universal raw scans. An absent pin
  alone no longer refuses an exec. The master fallback retains both unknown-arity readings,
  bounded at 16 and failing closed past the bound; ordinary unknown-build commands cannot gain
  refusals except from the raw scans. Pinned builds keep bare `--stack-trace-limit` unknown
  because its arity differs between 20 and 22. Their known `--entry-url`, `--run` and
  `--experimental-test-isolation=none` fail closed. Alongside external `NODE_OPTIONS` preloads,
  unknown builds retain master's future attached-option residual: Node 24/25
  `--test-global-setup=./b.js` or `--test-isolation=none` can execute denied B in process while
  the resolver names and allows A. The fallback does not claim to identify all code newer
  versions load.

**Root tiers.** (Tier 3. Tier 2 installs the Landlock tier's ruleset and filter and adds a fanotify
`FAN_OPEN_EXEC_PERM` check that matches exact and directory paths, so its exec semantics are the Landlock tier's
below: no match by name, and an unlisted script is refused.) The kernel exec hook runs once per binfmt stage, not once per `execve` (verified in `fs/exec.c`; at
most six stages). For `./agent.sh` it runs first with the script (`bprm->buf` starts `#!`), then with the
interpreter. The program passes any stage whose buffer starts with `#!` and keeps the script path for the event; on
every other stage it matches the file against `exec.allow` and returns `-EPERM` with a reason on a miss. So a script
matches its interpreter; `#!/usr/bin/env python3` matches `env` and then `python3`, so a contract that allows an
interpreter must allow `env`, and `compile` warns when a listed script's `#!` names a binary outside the list: one
no entry names as the same file (either spelling, or a directory above it), a same-named binary elsewhere counting
only where every tier the run can land on matches by name. A
binfmt_misc target is decided at both stages. An allowed exec is one event per `execve` with `argv` and the script
path from the seccomp notification; a refusal names the stage. Argv predicates are evaluated in the supervisor from
the `execve` notification, before any kernel hook runs.

**Landlock tier.** The kernel opens the program, its ELF `PT_INTERP` loader and a `#!` script's interpreter with
`O_RDONLY|__FMODE_EXEC`, so Landlock's `file_open` hook requires `READ_FILE|EXECUTE` on each of them (verified in
`fs/exec.c`, `binfmt_elf.c`, `binfmt_script.c` and `security/landlock/fs.c`); Landlock has no `mmap_file` hook, so
shared libraries and extension modules need `READ_FILE` only. It cannot match by name. `compile` grants
`EXECUTE|READ_FILE` on: the resolved inode of every `exec.allow` entry (a basename resolves to its `PATH` candidates;
a same-named binary elsewhere, such as a `uv`- or `pyenv`-managed Python, is a different inode and must be declared by
path or directory; a venv's `python` symlink is the same inode and needs nothing); the loader named in each binary's
`PT_INTERP`, read per binary (`/lib64/ld-linux-x86-64.so.2` on x86-64 glibc, `/lib/ld-musl-*.so.1` on musl, none for a
static binary); the agent command and its `#!` interpreter; every declared MCP `command`. A script run directly needs
`EXECUTE` on the script file and its `#!` interpreter must itself be allowed (`#!/usr/bin/env python3` needs `env` and
`python3`); an `exec.allow` entry may name a directory to grant `EXECUTE` beneath it; `sh tool.sh` needs only
`READ_FILE`, with every interpreter: Tego never sets `SECBIT_EXEC_RESTRICT_FILE` (6.14), which asks an interpreter that
honours it to check its script with `AT_EXECVE_CHECK` and so to need `EXECUTE` (ADR 0032, *added 2026-10-19*). On each
row the conformance suite runs on, `TestExecveCheckDetector` records whether bash, dash, python3 and node honour the bit
and fails once one does, ADR 0032's condition to revisit; below 6.14 it records `n/a`; `TestChildNeverSetsExecRestrictBits`
holds the agent's securebits 8-11 clear at tiers 1 and 2. An unlisted script is refused in this tier and in tiers 2 and 3, which install this tier's ruleset too
(2026-09-30, ADR 0019's note; `compile --test`'s bpflsm column asks it, `decide.ScriptFloor`). A `#!` naming a hardlink of an allowed file under
another path is refused by `run` even though it is the same inode: `compile --test` cannot see inodes, and the two
must not disagree. The same holds the other way for a multi-call binary, one file hard-linked under many names
(Ubuntu 25.10's uutils coreutils, where `/usr/bin/ls` and `/usr/bin/cat` are symlinks to two links of one inode;
busybox's applets): each name `exec.allow` lists runs, under its own entry, and every other name of the file is
refused at every tier (*amended 2026-09-30*, ADR 0025's note of that day). Which applet such a binary runs is its
own choice from `argv[0]`, which no exec rule sees: a binary that honours any `argv[0]` (busybox) runs every applet
through any name `exec.allow` lists, so list such a binary only where all of it may run.

**What the supervisor decides, tiers 1 and 2 (amended 2026-09-23).** The seccomp supervisor used to
continue every exec for Landlock's `EXECUTE` bit to decide and record a verdict it took from the pathname's spelling.
Three classes of exec then ran while the ledger read `refused`: an anonymous image (below), which Landlock does not
govern; a granted binary reached by another spelling than its entry's — its symlink-resolved path, a symlink or hard
link to it, its own descriptor through `fexecve` — which Landlock allows because its rule is bound to the entry's
inode; and a directly-invoked ELF loader, which holds `EXECUTE` as some binary's `PT_INTERP`. The supervisor now
resolves what an exec names the way the task's own lookup does — from the task's root, cwd or `execveat` descriptor,
following every symlink, reading procfs's `self` and `thread-self` as the task's own and following a `/proc/<pid>`
magic link from the pid directory it sits in — and decides on the file that reaches:

| The exec | Supervisor |
|---|---|
| an anonymous image (below) | refused, `rule: exec-anon`, `fileless: true`; allowed and still recorded `fileless` under a contract with no `exec:` section (§1, deny nothing) or one that set `exec.anonymous: true` |
| matched to an entry: by its spelling, by the inode an entry named when the run started (Landlock's own binding), or under a directory entry's resolved path | continued; Landlock decides it on the inode |
| a candidate of the run's own `PATH` search (supervisor R28) | recorded `observed`, answered with its lookup's own errno (`ENOENT` where the directory holds no such name) |
| anything else | refused by the supervisor itself, `exec-not-allowed`: `EACCES`, or the lookup's own `ENOENT`/`ENOTDIR`/`ELOOP` when there is nothing there to run |

`execveat`'s `AT_EMPTY_PATH` names the image by descriptor only when the pathname is empty; a non-empty pathname is
resolved as usual. A refused exec line is true by construction — the supervisor made the refusal — and a continued
one is decided by Landlock on the inode the match was made on. `compile --test` resolves a row's existing path
through the filesystem as the kernel does before it matches (*amended 2026-09-29, ADR 0019*), so a symlink to a
granted binary is allowed as the run allows it; it still cannot see inodes, so a hard link under another name is
refused, as the run refuses it.

**The race this walk does not close.** The decision reads the task's descriptor table and filesystem, and the
kernel resolves the exec again after the supervisor answers `CONTINUE`. Two things can change between the two
lookups. A **descriptor** the walk read can be swapped for another by any thread of the process or any `CLONE_FILES`
child, which share the descriptor table. A **filesystem path** — a symlink on the way to the image — can be
repointed by *any* concurrent process that can write that directory, not only a thread of the agent: another
process in the run, or one outside it with access to the path. So a racing peer can have the kernel load another
image than the one decided on — a memfd included, which Landlock then allows. Only a run with no concurrency at all
on the descriptor and no writable path on the way to the image is free of it. So the direct-loader refusal and the
supervisor's own anonymous-image refusal (the residual sources below) are **best-effort in tiers 1 and 2, not
closures**: a raced exec's line reads `allow` for the file the walk reached, never `refused` for one that ran, but
the image that ran is not the one recorded. The race-free enforcement is tier 3's `bprm_check_security`, which
decides on the file the kernel is loading; its condition is BPF LSM in the boot `lsm=` list (`docs/GAPS.md` B1,
C30). The main anonymous vector, `memfd_create`, is closed race-free in tiers 1 and 2 on every supported kernel
without waiting for tier 3 (below), because it is refused at creation, not by a second lookup.

**Anonymous images (memfd / fexecve), tiers 1 and 2 (amended 2026-09-23).** `exec.allow` bounds which binary
*on disk* runs. An anonymous image — a `memfd_create(2)` region, another `anon_inode:`, or a file unlinked since it
was opened — is not governed by Landlock's exec check. The exec open does reach Landlock's `file_open` hook
(`do_open_execat` opens the descriptor's file with `LOOKUP_EMPTY`, and that open runs `security_file_open`), but the
hook allows it outright: `is_nouser_or_private()` in `security/landlock/fs.c` matches the `SB_NOUSER` superblock a
memfd lives on. A regular file reached the same way is checked, which is why a regular-file `fexecve` of an unlisted
binary is refused and a memfd's is not. Tier 2's `FAN_OPEN_EXEC_PERM` sees no open a memfd `fexecve` produces. So a
static ELF written into a memfd and run by `execveat(AT_EMPTY_PATH)`, or by any pathname that reaches the
descriptor (`/proc/self/fd/N`, `/dev/fd/N`, a symlink to either, `/proc/<pid>/task/<tid>/fd/N`, a dirfd-relative
name), ran under a tier-1 contract whose `exec.allow` never named it, while the ledger marked it `refused`. No
contract entry can name a runtime-created anonymous inode, so such an image is never a granted exec.

*The closure — at creation, not by a spelling.* Deciding the exec after the fact from the descriptor the walk reads
loses the race above (a memfd is exactly the image a peer can swap in). `memfd_create`'s number and flags are
scalars in registers, immutable once the syscall traps, so tier 1's seccomp filter — which tier 2 inherits — refuses
at *creation* any `memfd_create` that would yield an image the kernel can exec, and no executable anonymous image
ever exists inside the run (`docs/p0/enforce-landlock.md` R11a). Where the kernel honours `MFD_NOEXEC_SEAL` (6.3
and later, or a backport such as RHEL 9.8's 5.14; a probe decides, never the version) that is a `memfd_create`
without the flag (`-EACCES`): the flag clears a memfd's execute bits and seals them, so a memfd made with it cannot
be exec'd (`mm/memfd.c`; verified on 6.17), while a data memfd that sets it — shared memory an ordinary workload
needs — is created normally. A hugetlb memfd (`MFD_HUGETLB`) is refused with or without the flag, because hugetlbfs
does not enforce the `F_SEAL_EXEC` it sets: an `fchmod` gives such a memfd its execute bits back (verified on 6.17).
On a kernel without the flag (upstream before 6.3, or a distribution kernel that did not backport it, such as
Amazon Linux 2023's 6.1) no flag distinguishes an executable memfd from a data one, and every `memfd_create` is
refused (`-ENOSYS`, what a kernel without the syscall answers, so a runtime falls back to a file
in `/dev/shm` or an `O_TMPFILE`, which the ruleset governs): that costs such a run every memfd, data included, and is
the fail-closed choice (*amended 2026-09-23:* below 6.3 no arm was installed and the vector rested on the
supervisor's best-effort walk alone; a sealed hugetlb memfd passed the 6.3+ arm). An arm is installed only when the
run restricts exec; a contract may opt out with `exec: {anonymous: true}`, which drops the arm, allows the anonymous
exec and still records it `fileless` — the opt-out is on record in the run's contract copy, its `contract_hash`, a
compile warning and the run's capability line, which reports `exec.deny` `false` at tier 1 (tier 2's handle does
once it reads the inherited tier-1 row, `docs/p0/enforce-landlock.md` R11a), since `exec.allow` then no longer
bounds what runs. The supervisor's own refusal of an anonymous image (table above) is **kept as the record and the
best-effort backstop** for images that arrive by another route — a descriptor received over `SCM_RIGHTS` or
inherited at launch, a file unlinked after opening — deciding anonymity on the inode it reached (no link count, or
the kernel's own `/memfd:`/non-`/`-rooted spelling), never on a name the agent chose. A memfd's name follows
`/memfd:` and may hold `/` and `..`, so the recorded path is that raw spelling, never cleaned into a disk path.

`vm.memfd_noexec` is not the tier-1 route. In mode 1 it defaults a flagless `memfd_create` to executable and
`MFD_EXEC` still creates an executable memfd; only mode 2 (`MEMFD_NOEXEC_SCOPE_NOEXEC_ENFORCED`) refuses a creation
without `MFD_NOEXEC_SEAL` with `-EACCES` — the same effect as the arm — but it is scoped to a pid namespace, needs
`CAP_SYS_ADMIN` over it, cannot be set from an unprivileged tier-1 launch and does not exist below 6.3, which is why
the seccomp filter is the tier-1 equivalent. Landlock's non-coverage of anonymous images is inherent to every ABI;
tier 3 gets a race-free refusal of every anonymous image from `bprm_check_security`. An observe run enforces nothing
(§3, R30), so the image is continued and recorded `observed` there.

**The dynamic loader and `PROT_EXEC` mmap (tiers 1 and 2).** `exec.allow` also did not bound which native ELF
runs when a *granted loader is invoked directly*, and does not when code is mapped `PROT_EXEC` from a readable file.
The loader named in a binary's `PT_INTERP` is granted `EXECUTE|READ_FILE` for the kernel's own load of it, so
`ld-linux-x86-64.so.2 /path/to/prog` passed Landlock; the loader then `open`s its target `O_RDONLY` (not
`__FMODE_EXEC`) and `mmap`s it `PROT_EXEC`, and Landlock has no `mmap_file` hook at any ABI, so it executes bytes it
holds only `READ_FILE` on. On glibc ≥ 2.42 the C library's own `argv[0]`-mismatch guard blocks that spelling, but
that is libc, not Tego: musl and pre-2.42 glibc (RHEL, Debian, Alpine) have no such check.

- *The direct loader* is an `execve` the supervisor sees, and a loader that is not itself an `exec.allow` entry is
  refused by it like any other unlisted binary (table above), recorded `refused exec-not-allowed`. That closes the
  spelling in tiers 1 and 2 unless a concurrent peer wins the path/descriptor race above — it is a path- or
  descriptor-keyed decision like every other, so it is best-effort, not a closure.
- *The `PROT_EXEC` mmap* makes no exec at all: a granted process — an interpreter loading an extension module, or a
  program `mmap`ing a file it can read — runs native code no `exec.allow` entry names, and the mapped file produces
  no exec event. Tego does not fix this in tiers 1 or 2. **Condition:** the tier-3 BPF-LSM `mmap_file(PROT_EXEC)`
  hook refuses a `PROT_EXEC` map of a non-granted inode (and `bprm_check_security` closes the raced loader exec),
  buildable once BPF LSM is in the boot `lsm=` list (`docs/GAPS.md` B1, C31). The same residual holds on non-Ubuntu targets without it.

*Tiers 2 and 3 with a plane mode (built 2026-09-30, ADR 0027, [enforce-plane](../../docs/p0/enforce-plane.md) R26,
§2.14).* With an `exec:` section, the plane's `mmap_file` and `file_mprotect` decide on the prot the kernel maps with
(READ_IMPLIES_EXEC included) and refuse `EACCES`: a `PROT_EXEC` map of a file under a write entry that no `exec.allow`
entry covers (an `exec.allow` directory above it, its own entry under its name, or a bare-name entry, as for an
exec); a writable and executable private file map (execmem); making a private file map with copy-on-write pages
executable (execmod, text relocations); and an anonymous file (a memfd, an unlinked file) without `exec.anonymous`.
A readable file under no write entry maps as before, so the loader, a system library and an interpreter's own
extension modules load. A contract that loads native code it installs or builds under a write entry names that
directory in `exec.allow`, as it must to execute a binary there. This narrows, it does not close: code mapped from a
readable pre-existing file outside every write entry, never modified, still maps, and anonymous memory is A2. Tier 1
keeps the paragraph above.

## 5. Network

*Note 2026-09-29 (ADR 0024 (7), accepted; built for step A, `TestPlaneReturnsOnlyZeroOrEACCES`; `socket_create`'s allowlist built, T13; [enforce-plane](../../docs/p0/enforce-plane.md) R2):* a plane decision returns 0 or -EACCES and nothing else, and refusals read EACCES in every tier once a plane mode is selected; fanotify's EPERM exception and tier 3's designed EPERM for exec end. Network verdicts stay on the per-run cgroup programs; `socket_create` adds the family allowlist (R14).

*Amended 2026-09-24 (ADR 0018):* a `net:` section also bounds which sockets exist. `socket(2)` and `socketpair(2)`
are admitted only as what the network rules govern — unix, netlink, and TCP, UDP and (with an ICMP entry) ping
sockets on IPv4 and IPv6 — and every other family or protocol (SCTP, UDP-Lite, DCCP, vsock, TIPC, packet sockets)
is refused at creation and recorded, since no entry can name where it would go and SCTP associates and sends
through calls the connect and send decisions never see. With no `net:` section nothing is refused (§1).
*Amended 2026-11-01 ([ADR 0128](../../docs/adr/0128-read-only-route-queries.md)):* of netlink, `NETLINK_ROUTE` alone: another
protocol is refused at creation, `EPROTONOSUPPORT` and a line. On that socket a run reads and does not change: a read-only
route query (rtnetlink's GET kind, read from what is sent, addressed to the kernel) is relayed and recorded `allow`, rule
`route-query`, so interface lists and `AI_ADDRCONFIG` work; anything else addressed is refused, rule `route-change` or
`unmatched`. What a run learns so is the host's interfaces, addresses, routes and neighbour table (ADR 0128 says what
exactly). The kernel holds the rest: no process of a run under a `net:` section holds `CAP_NET_ADMIN`, `setuid: true`
included, so a change sent by a call the supervisor does not see (`write(2)`, an unaddressed `send(2)`) fails `EPERM`, with
no line.
*Amended 2026-10-16 (ADR 0018 PR 2):* at tiers 2 and 3 the bound holds on every path a run can make a socket by, not
only `socket(2)`: `cgroup/sock_create` refuses an inet socket outside it wherever it is made (with `EPERM`; an
`io_uring` `IORING_OP_SOCKET`, for one), and a plane mode's `socket_create` every family (`EACCES`). `io_uring: true`
stays refused where no plane decides the run, since nothing there decides a socket of another family made through it.
A run records the bound as the capability row `net.socket_families`, and `net.assurance: kernel` requires it.
*Amended 2026-10-17 (ADR 0018 (7)):* the bound also holds after a socket is made. An upper-layer protocol
(`setsockopt(SOL_TCP, TCP_ULP)`) is how an admitted TCP socket was turned into another family in place (`"smc"`
built an `AF_SMC` socket), so under a `net:` section every ULP name is refused and recorded: `ENOENT` from the
supervisor on `setsockopt(2)` at every tier, so a runtime that tries kTLS falls back to its own TLS, and `EPERM` from
`cgroup/setsockopt` on any other path at tiers 2 and 3 (io_uring's). A contract cannot admit kTLS yet. The bound is on
the sockets a run makes; a socket made outside the run and passed in is the socket-import guard's
(`net.assurance: kernel` refuses the import).

Entries are `host:port`, `cidr:port` or `unix:<path>` (`unix:@name` for abstract). Bare IP and hostname entries
admit both TCP and UDP. Prefix an IP, hostname or CIDR destination with `tcp://` or `udp://` to admit only that
transport, for example `tcp://api.anthropic.com:443` or `udp://[2001:db8::1]:5353`. These are destination selectors,
not URLs: paths, queries, user information and transport-specific port 0 are rejected. The selected transport
is preserved through DNS refresh, supervisor evaluation, Landlock port rights and kernel rows. Hosts resolve at compile time and
re-resolve on TTL in the launcher; the kernel map holds IP:port. A host name never admits a loopback, unspecified,
link-local (the cloud metadata endpoint `169.254.169.254` among them), other cloud-metadata or multicast address, nor
one in the machine config's `denied_resolved_addresses`, whatever the resolver answers: `compile` drops such an address
and warns, and the supervisor refuses one a refresh brings in, `rule: net.denied_resolved[<entry>]` (agent-contract
R18, added 2026-09-23, multicast added later). Nor does it admit one of this host's own interface
addresses, which reach every service bound to all interfaces as loopback does: the supervisor refuses such a
destination from a snapshot of the host's addresses, and `compile`, which does not know them, neither drops nor warns.
*Amended 2026-11-02:* the host's own addresses take in every address of a `local` route in the routing tables its
default rules look up, an AnyIP range's, as a live block, a `net to` rule and the `models[]` guard read this host
(agent-contract R18).
A name whose compile-time answer held only public addresses is also refused a private one (`10/8`,
`172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`) that a refresh brings in — DNS rebinding towards the host's own
network — while a name that first resolved to a private address (split-horizon DNS) keeps them. A literal address or
CIDR entry is never filtered, a `localhost` name keeps loopback and this host's addresses, and another entry that
admits a destination on its own admits it behind a refused one.
When several entries cover one destination (a literal address or a host inside a declared CIDR, two nested CIDRs),
a refusing one decides whatever the declaration order, and otherwise the first declared names it; every tier applies
this one rule (`Evaluate`, the supervisor's set, and tier 2's rows, which are composed by it).
`HTTPS_PROXY` in the run's env changes the effective destination and `compile` warns; when any `*_PROXY` variable is
passed in, the run appends `127.0.0.1,localhost` to `NO_PROXY`.

**TCP.** Root tiers: `socket_connect` (tier 3) or `cgroup/connect4,6` (tier 2) decide host:port in the kernel.
Unprivileged tier: Landlock handles `CONNECT_TCP` and each declared port becomes a rule, which sees the port and never
the host (below ABI 4 there is no rule and the supervisor decides alone), so a `connect(2)` that reaches the kernel from
inside the run to an undeclared port is refused with `EACCES`; the seccomp filter notifies on `connect`, and the supervisor
takes a `pidfd_getfd` duplicate, reads the sockaddr under `ID_VALID`, matches host:port, performs every allowed
`connect()` itself on the duplicate (returning `0` or `-EINPROGRESS` for non-blocking sockets), answers undeclared
hosts with `-EACCES` and a reason, and holds `ask` entries. `CONTINUE` is never used for a connect. A `sendto` or
`sendmsg` with an address on a stream socket (TCP Fast Open) is decided like a connect. A relative unix `sun_path` is
resolved against `/proc/<pid>/cwd`.

**The errno of a refusal.** A connect, Fast-Open send or unix connect the run refuses fails with `EACCES` in every
tier, and so does a datagram the supervisor refuses, so a refusal reads the same however it was reached. The
supervisor answers `-EACCES` (docs/p0/supervisor.md R10), and Landlock's own backstop, which the runtime cannot
change, answers `EACCES` too. Tier 2 inherits the supervisor, which decides a connect first and never relays one it
refuses, so the agent meets `EACCES` there as well. Tier 2's `cgroup/connect4,6`, `sendmsg4,6` and unix programs then
decide again what the supervisor let through: a connect it relayed, and an unconnected datagram it admitted and
continued, which tier 1 decides once, on its own copy of the address (supervisor R13b; enforce-cgroup-observe R5,
R7). Their refusal is the kernel's `EPERM`: they
return only `0` or `1` (enforce-cgroup-observe I3), and a `CGROUP_SOCK_ADDR` program's `0` fails the syscall with
`EPERM`, which the supervisor returns as a relayed connect's real result. So at tier 2 an agent meets `EPERM` for
an unconnected datagram to a destination the contract does not admit, and for a connect only where the kernel's rows
and the supervisor disagree. *Amended 2026-10-05:* the supervisor answers such a datagram itself,
with the program's errno (`EPERM`, or `EACCES` where the decision plane decides unix names below 6.7), so the agent's
errno is unchanged and the datagram's one ledger line is that refusal (docs/p0/supervisor.md R13b). *Amended
2026-10-16 (R13b):* a refused datagram of a shape the supervisor leaves to the kernel's own
checks — an IPv4 or v4-mapped destination on an `AF_INET6` socket, UDP port 0, a datagram that is not UDP (an ICMP
ping socket's), a relative unix name — is no longer continued to the program, which refused it with `EPERM` (or
`ENETUNREACH` under `IPV6_V6ONLY`): the supervisor refuses it with `EACCES` (R10). So at tier 2 a refused datagram
reads `EPERM` where the supervisor answers with the program's errno, and `EACCES` for those shapes; nothing is sent
either way. A datagram to a name under a write entry that names nothing reads the lookup's own `ENOENT` or `ENOTDIR`
in every tier (supervisor R11a, `unix-absent`). Tier 3's `socket_connect` program returns an errno of its own choosing, and it is to
return `-EACCES` (P1). `ECONNREFUSED` is never used for a refusal: it is what a real peer answers, and a relayed
`ECONNREFUSED` is returned as it came and recorded `allow` (supervisor R9, I3), so the two must stay apart.
*Settled 2026-09-23:* ARCHITECTURE §7 said `-ECONNREFUSED`, REASON-CHANNEL §1 said `-EPERM`, and
docs/p0/supervisor.md §11 carried the three values as an open conflict. This section, P0-DESIGN §4.2 and R10 said
`-EACCES`, which is what the supervisor has always returned, and every document now says the same.

**UDP.** A connected datagram socket is decided at connect (glibc's resolver connects and then sends with no address,
verified); an unconnected one is decided from the destination of `sendto`/`sendmsg`/`sendmmsg`: in the root tiers by
`socket_sendmsg` or `cgroup/sendmsg`, race-free; in the unprivileged tier by the supervisor reading the address: a
destination the contract does not admit is refused with `EACCES` and nothing is sent, and an admitted one is
continued, so the kernel reads the address again, a stated best-effort limit listed in the capability matrix (only
an allow is exposed to a sibling thread's rewrite; a refusal needs no race). *Amended 2026-10-16:* the supervisor continued every such datagram and recorded a refused one with
`best_effort`, so under `net.dns.mode: off` a lookup sent from an unconnected socket reached the machine resolver
while the same lookup from a connected socket was refused at its connect. Each is refused now, in every tier, and a
refused line never carries `best_effort` (spec/record/v1/README.md). ICMP and raw datagram sockets match by
host with port 0. *Disclosed 2026-10-16 (GAPS C34):* an admitted datagram, or a relayed connect
on a socket no net gate covers, that carries a source route (an `IP_RETOPTS` control message, or `IP_OPTIONS` LSRR or
SSRR or `IPV6_RTHDR` set on the socket, which an unprivileged task may set, LSRR and SSRR only where the kernel lacks
the CVE-2026-53249 restriction) is sent first to the route's first hop,
which the contract need not admit, in every tier: the decision and the root tiers' programs see only the destination.
*Amended 2026-11-02 (GAPS C34):* under a `net:` section, as under a net gate before, a run cannot route around its
destinations, save for the residuals below. The filter refuses `setsockopt` of `IP_OPTIONS`, `IPV6_RTHDR`,
`IPV6_2292RTHDR` and `IPV6_2292PKTOPTIONS` with `EPERM`, race-free on the scalar level and option, in every tier
(docs/p0/enforce-landlock.md R11b), so no process of the run puts a route on a socket through `setsockopt(2)`; what
that costs is a tool that sets IP options, such as `ping -R`. The supervisor reads a socket's route before every connect, Fast-Open send
or approved datagram it performs, and refuses a routed one `relay-source-routed`, for a socket that carried a route
before the filter applied. It reads each `sendmsg` and `sendmmsg` message's control buffer and refuses, with `EACCES`
and the same rule, a datagram on an IP socket whose `IP_RETOPTS`, `IP_OPTIONS`, `IPV6_RTHDR` or `IPV6_2292RTHDR`
message would route it, connected or not, and one whose buffer is longer than the 4 KiB it reads
(docs/p0/supervisor.md R9, R13b). Residuals: (1) that control-buffer read is best effort in every tier: the buffer
stays in the agent's memory until the kernel copies it, and a sibling thread can write a route into it after the
read, which no tier's kernel program sees; (2) an admitted datagram the supervisor continues on a socket that carried
a route before the filter applied (inherited, or received over a unix socket) is sent with it, since a socket's
options are read only before a call the supervisor performs; (3) under `io_uring: true` a ring's
`SOCKET_URING_OP_SETSOCKOPT` (6.7+), connect and `IORING_OP_SENDMSG` reach neither the seccomp filter nor the
supervisor, so a ring can put a route on a socket, connect or send through it, and send a datagram its control
messages route, and the supervisor's read before a relay is a snapshot such a ring can race; (4) a contract with no
`net:` section admits every IP destination and gets no arm and no read, so where a live net block narrows it a route
can still take a connect or datagram to the blocked host first. The resolver is read from `/etc/resolv.conf` at run start (127.0.0.53 under systemd-resolved) and
allowed on UDP and TCP 53 in every tier (glibc falls back to TCP on truncation); DNS is recorded as `net proto=udp|tcp`.
On Landlock ABI 10+ (Linux 7.2) the port rule is also applied in-kernel; the address check stays in the supervisor.
Explicit listener declarations and their distinct per-tier address/port guarantees are implemented; see
`docs/p0/network-controls.md`. They supersede the original assumption that the schema declared no listen ports.
An omitted listener list adds no new listener restriction, and a `net:` section alone admits no TCP listener: an
explicit bind fails on the withheld `BIND_TCP` and, *amended 2026-11-01*, a `listen()` with no bind, which that right
never sees, is refused by the supervisor and recorded. *Amended 2026-11-02:* a ring's `IORING_OP_LISTEN` under
`io_uring: true`, where a root tier's plane admits io_uring, reaches no supervisor, and the plane decides a listen only
against an explicit list, so nothing refuses its autobind (GAPS C44): `compile` warns `io-uring` wherever such a run may
land at tier `cgroup` or `bpflsm`, and an explicit list closes it. An explicit empty list refuses new binds/listens,
and a nonempty list grants its declared endpoints subject to the tier's capabilities and requested assurance.
DNS tunnelling through the allowed resolver is a stated limit shared with every host-based tool.

**Unix sockets with no `net:` section** (*added 2026-10-24*, ADR 0070). The unix-only state of §1: a socket a
process of the run bound is reached wherever it lies (a pathname one lies under a write entry, where the run can bind,
and is matched there as the implicit admit below matches it, R11a); a runtime unix: grant (the DNS broker's socket)
by its rule; an abstract name while a socket of the run holds it (the supervisor records the sockets the run binds to
abstract names and asks the kernel which name each holds); anything else is refused `host-sockets`. A connect, an
addressed datagram or a stream send on a socket whose domain is neither IP nor unix (`AF_NETLINK`, `AF_PACKET`) is
refused `host-sockets` too, keyed on the socket's own domain: the unix-only state reaches no such destination, and it
is never relayed from the supervisor with its own credentials (*amended 2026-10-25*). A route query, an
addressed send on a `NETLINK_ROUTE` socket to the kernel (`nl_pid` 0, no group) without ancillary data, is admitted
and relayed as the task, recorded allow, so interface enumeration (`getifaddrs`, `if_nameindex`) works; a `sendmmsg`
batch on such a socket is continued, as every batch is (*amended 2026-10-25*; *amended 2026-11-01*, ADR 0128:
only a GET is relayed, and a change is refused `route-change`, as under a `net:` section). At tier landlock every connect is relayed on
the supervisor's duplicate of the socket, so the refusal is race-free for connect; a Fast-Open send and a send on a
stream socket without a peer are relayed on the duplicate too (*amended 2026-10-25*), as is an admitted
addressed datagram the supervisor can reproduce exactly. An addressed send on a connected socket names nothing the
kernel reads, so its address is neither decided nor recorded (R13a): on a unix stream socket it gets the kernel's
`EISCONN` on the duplicate, and on an IP stream socket its payload goes to the peer on the duplicate where the
supervisor can reproduce the call (*amended 2026-10-25*). What it continues instead (an unaddressed
`sendmsg`, a `sendmmsg` batch, a datagram with ancillary data or `MSG_MORE`, an addressed send on a connected
seqpacket socket, whose receiver reads the sender's pid in `SCM_CREDENTIALS`, and one on a connected IP stream socket
with ancillary data or a payload past what is copied) is best effort, run_start cell `host_sockets/datagram`: below
Landlock ABI 9 (6 for an abstract name) a sibling thread's rewrite can deliver such a send to a host datagram socket
(the journal's), never to a stream daemon. The agent chooses the shape of its calls, so it can choose a continued
one. At tiers cgroup and bpflsm the same relay and Landlock carry it, with no kernel program of the run deciding it:
best effort (`host_sockets/root-tier`) until the root tiers carry a kernel program for it.

**Unix sockets.** Pathname entries are matched on the resolved socket (parent-directory inode plus final component),
so symlinked paths and daemon restarts keep matching; abstract names match by bytes. In the unprivileged tier the
supervisor decides the name a connect passes and then the socket it resolves to, walked as the agent, and makes
the connect with the agent's credentials: a symlink the agent makes under a write entry admits only a socket that
itself lies under one, and the listener's DAC check and `SO_PEERCRED` uid and gid are the agent's, not the
supervisor's (`docs/p0/supervisor.md` R11, amended 2026-09-22). A datagram send there is decided on the name it
carries and then, as a connect is, on the socket that name reaches when the agent's own lookup resolves it: refused
with `EACCES` when either refuses, and an admitted one sent by the agent's own syscall (the stated UDP limit above).
*Amended 2026-10-16 (ADR 0041's note of that date):* every unix pathname — a connect's, a
datagram's, a bind's — is resolved in the agent's own view (its root, cwd and mount namespace, through its
`/proc/<pid>` entries) and decided on the identity of what it reaches; a name through a procfs magic link
(`/proc/self/cwd`, `/proc/thread-self/...`, `/dev/fd/N`), which the supervisor would resolve as itself, or one that
otherwise cannot be resolved there, is refused (`rule: path-unreliable`). A datagram was decided on its lexically
cleaned spelling, so a symlink the agent put at a name a `unix:` entry declares, a `..` after a symlink, or a
`/proc/self/cwd` link sent it to a socket outside every entry under an `allow` line. Stream and seqpacket are decided
once at connect, datagram at connect and at every send. **A socket the run bound** (rule `docs/p0/supervisor.md`
R11a, decided 2026-10-16): a pathname socket under a declared `fs.write` path is allowed implicitly only when a
process of the run bound it — `multiprocessing`, Ray, local MCP servers the agent starts. Any other socket there, one
that existed before the run or that a process outside it made, is refused (`rule: unix-foreign`) unless a `unix:`
entry names it: what the program behind it runs is outside the run, and the premise "the run created it" is false
for it (Codex's app-server control socket in `CODEX_HOME`). The supervisor records
each socket object the run binds (the filter notifies `bind` under a `net:` section) and when it answered the bind,
never the bind's name, and asks the kernel's socket diagnostics which file each is bound to, matched on the file's
superblock and inode number and, on btrfs and overlayfs, where those are shared by files of several subvolumes, also
on the file's birth time (within ten seconds after a bind of that socket, and before the socket was seen bound) and
on no socket outside the run being bound by the same pair in the agent's network namespace (amended 2026-10-17, below)
— so a renamed socket of the run's stays its own, and whichever of its binds took, by whatever name, does not matter; a kernel that cannot answer, or a file it cannot tell apart (an inode number wider
than the 32 bits the diagnostics report), refuses (`unix-origin-unread`), and so does a run holding more sockets
bound to nothing than one decision asks the kernel about (the work is bounded per notification). A bind it could not record refuses
(`unix-bind-unrecorded`), never `unix-foreign`: at tier landlock that is any socket a non-dumpable process of the run
binds, such as `ssh-agent`, which then needs a `unix:` entry. A datagram to a name that names nothing reads `ENOENT`
(`unix-absent`). A `net.ask` `unix:` scope is a place (*amended 2026-10-19;
supervisor R11c): the path it names as the run starts, walked from the root one name at a time, every symlink
followed, one whose target the run makes later included, and the names that do not exist yet kept, a `..` the walk
meets in a link's target applied where the kernel's lookup applies it, after the symlink before it is followed, as
`realpath -m` does, never by a lexical clean (*amended 2026-10-19*: a dangling link's target was cleaned lexically, so a scope
at `s -> sub/../x.sock` with `sub` a symlink was placed beside `s`, and an approval connected a socket there) (compile
resolves it the same way, `compile --test` included). The path written in the contract is cleaned lexically when
compiled, as every contract path is: a `..` written in it removes the name written before it, and the cleaned path is
what a person is shown (*amended 2026-10-19*). A path the walk cannot place within 1024 names
and 40 links is its spelling as given, and a connect's name it cannot place so is no scope's and is decided where it
leads (*amended 2026-10-19*: the placement of an agent's chain of dangling
links cost the supervisor tens of seconds per connect). Each name is read without following a symlink in the
directories before it, so a name the walk passed that the agent makes a symlink meanwhile ends the placement, not
placed, where it made every later read follow that link (*amended 2026-10-19*). A connect whose name reaches that place in the agent's view —
the scope's own spelling, a relative name, the canonical spelling `getcwd` gives, a symlink or a symlinked directory,
a name that is a symlink leading there before the socket exists (*amended 2026-10-19*: the
scope's own name as such a link was allowed by the write entry around it with nobody asked), a name whose directory
is missing yet that leads there once it is made, a relative one walked from the cwd uncleaned (*amended 2026-10-19*: a `..` after a symlinked directory in a relative name was cleaned lexically
first, and the name allowed by the write entry with nobody asked) — is asked
(§3.1), whoever bound the socket there, the run included, and is never allowed by the write entry around it; an
approval connects at that place only. A name that reaches another place is decided there as every connect is: the
run's own socket is allowed implicitly, a hard link to it or the name it was renamed to included, since the run could
bind a fresh socket there all the same, and a socket the run did not bind — a scope's too, reached by a hard link or
after a rename — is refused (`unix-foreign`) unless a `unix:` entry names the place it is reached at. A datagram, which nobody is asked about, is refused
at a scope's place (`rule: unix-ask-scope`) and decided the same way elsewhere. Before (the same
day), the scope was matched by the spelling the agent passed, so a relative name in a project reached through a
symlink was refused with nobody asked and a scope through a symlink that led nowhere at start was refused when
approved; and the run's own socket was tracked as the scope's across its renames and links, which walked every bind,
refused under rules of its own (`unix-ask-scope-unread`) and still lost the socket to a rename with no decision in
between, to guard nothing the run could not reach by binding afresh. Rejected: that tracking, and closing it by
trapping every rename and link. *Amended 2026-10-16 (R11a):* every socket the run bound on btrfs was refused, a non-dumpable
process's and a renamed one were called foreign, and so was a name that named nothing. Rejected:
removing the implicit allow, which would push contracts to a directory-wide `unix:` grant over the random socket
names those programs use, admitting every foreign socket beside them; a birth-time or bound-path check, which an
outside process or a rebind defeats. Every tier decides it in the supervisor first; the kernel layers (tier 2's unix
programs, the plane's, Landlock's `RESOLVE_UNIX` at ABI 9+) still admit any name under a write entry, which leaves as
disclosed residuals (supervisor R11a lists them with the condition that closes them): a datagram whose name, or the
file it leads to, changes between the supervisor's lookup and the kernel's — a sibling thread rewriting the name, or
any process of the run renaming a file or swapping a symlink under the write entry — which reaches a socket the run
did not bind under an `allow` line marked `best_effort`; on btrfs or overlayfs, a socket a process in another network namespace
binds, on the same filesystem, during one of the run's binds and at the inode number of the run's socket (or a
process in the agent's namespace binds so with its bind still under way when the supervisor reads the namespace's
sockets), which the supervisor cannot tell from the run's own (amended 2026-10-17: it was a run that changed the filesystem between the
supervisor's walk of a bind's name and the kernel's); and, under `io_uring: true` at tier `bpflsm`, an `io_uring`
connect or unix-addressed send, and a socket bound through `io_uring`, which is never recorded. *Amended 2026-10-17, superseded the same day by the next amendment:* a bound
socket was attributed to the directory the name of one of its recorded binds reached, trusted only when no bind of the
run had gone unread and no bind from another cwd could have taken it; that is gone, with its cost that one
`ssh-agent` at tier landlock refused the run's own btrfs sockets for the rest of the run. *Amended 2026-10-17:* that attribution is gone, because each of its rules
was met by another ordering — a bind continued with no record, a rewrite or a swap onto a recorded name after a symlink
changed at leisure, a swap whose other socket had gone — and each admitted a foreign btrfs socket. A bound socket is no
longer placed in a directory by any bind's name: its file is the one the agent's name reaches when that file was born
during one of the socket's binds and no socket outside the run shares its superblock and inode number in the
namespace; a foreign file that existed before the bind is refused `unix-foreign` whatever the bind's name did, and the
run's own btrfs or overlayfs socket is refused `unix-origin-unread` only while a live socket outside the run shares
that pair, or when its filesystem reports no birth time — an unread bind such as `ssh-agent`'s no longer refuses it.
The birth time differs from the birth-time check rejected above: it is checked against the binds of the socket the
run bound, not the run's start. *Amended 2026-10-17:* the kernel sends a long list
of the namespace's sockets in several datagrams and resumes each at a saved place in one of its hash buckets, so a
socket that leaves that bucket in between — one the run closes whenever it likes — makes it skip a socket bound
throughout, and a skipped foreign socket was admitted to a connect. A connect's list is therefore taken only as one
pass of the kernel's walk, of the unconnected sockets for a stream or seqpacket socket's connect (which reaches no
connected socket) and of every socket for a datagram socket's: a socket an outside process makes during the run in the
agent's namespace is in that list; where the namespace's sockets do not fit one pass (some 600 unconnected ones, or,
for a datagram socket's connect, a busy desktop's connected streams) the connect is refused `unix-origin-unread`. A
datagram's decision, best effort already (above), reads the list however many datagrams it takes, and a socket the
list skipped is within that `best_effort` mark. *Amended 2026-10-17:* the run's own
socket the list does not show is refused `unix-origin-unread` too, whether it closed meanwhile, a datagram's list
skipped it, or the list leaves it out because it cannot take the connect: a connected stream or seqpacket socket, and,
for a stream or seqpacket socket's connect, a datagram socket another socket connected to, where the kernel answers
`EPROTOTYPE` (it was admitted before the one-pass list, and the kernel refused it). `compile --test` answers such a socket `allow`, the run's own case.
`/dev/log` is allowed in the base profiles. When the contract has `docker:`, `compile` adds the run's proxy socket to `allow` and the resolved
real daemon socket to `ask`; neither is written by hand, and `compile` warns when `env.pass` names `DOCKER_HOST` or
`DOCKER_CONTEXT`. On Landlock ABI 9+ (7.1) `unix:` entries also compile to `RESOLVE_UNIX` rules.

**HTTP rules (`net.http`).** Rules apply to declared model forwarders and require explicit `capture: forwarder`
and an enforcing tier. Every model listener must be covered, and a model host may appear only once (its declared
port defaults to 443). A rule has `host`, `allow` (path prefixes) and optional `methods` (exact method names).
The first matching declaration names the decision. Queries do not participate in matching. Prefixes match path
segments: `/v1/messages` includes `/v1/messages/count_tokens`, but not `/v1/messages-extra`. Ambiguous paths,
including encoded separators, dot segments, double encoding and control bytes, are refused. A dot segment is
any segment an upstream may resolve as one (*amended 2026-10-05:* the matcher refused only `.` and `..`, so
`/v1/chat/..;/admin` was allowed under `/v1/chat` and a Tomcat, Jetty or Spring upstream, which cuts
`;parameters` before resolving, served `/v1/admin`): a segment that is only dots once a `;parameter`, raw or
`%3B`, and trailing spaces are cut is refused, in requests, WebSocket routes and declared prefixes alike. An empty `allow`
list admits no ordinary request. The authenticated, bodyless `HEAD /api/hello` health probe is a local exception
and is never forwarded.

The listener authenticates its peer before evaluating an HTTP/1.1 request and evaluates every keep-alive request
before reading its body or contacting the fixed, TLS-verified upstream. Unmatched method/path requests fail with
403; CONNECT and Upgrade require an explicit `net.proxy` grant, and other unsupported protocol forms fail with
400. Declared HTTP/2 streams receive the same per-request policy. CONNECT can target only the listener's declared
model authority, and WebSocket routes require validated GET upgrades. Their bounded opaque tunnels cannot
enforce model token, cost or repeat limits; any such declared or machine-inherited limit prevents release.
See [proxy protocol bounds](../../docs/p0/proxy-protocols.md). The request's Host cannot choose a new
upstream, redirects are not followed, and refused requests create no model response or usage charge. A required
policy listener that cannot start prevents agent release. Record modes retain policy refusals; URL targets use
the same redaction as capture targets, and query strings are never stored in the policy path field.

Uprobes capture plaintext and do not veto HTTPS requests. Ordinary socket grants control destination and transport, not URL, tool use or request content.

**Network assurance (`net.assurance`).** `best-effort` is the default and retains existing behavior. `kernel`
requires an enforcing root tier with actually attached TCP, UDP and Unix destination hooks, together with the
strict client filter. The runtime refuses the contract before starting its agent if those guarantees are missing.
Strict mode rejects `io_uring: true`, `setuid: true`, unsafe inherited standard descriptors and unsupported
destinations; extra inherited descriptors are closed. Its filter refuses `recvmsg`, `recvmmsg`, `pidfd_getfd`,
`listen`, `accept` and `accept4` with ENOSYS when no listener policy is declared, to close descriptor-import and
accepted-socket paths. An explicit listener policy instead requires its actual listener enforcement mechanisms
before release; a missing mechanism never silently widens access. These restrictions can break applications
that use the blocked calls for otherwise ordinary work.

`run_start.net_assurance`, `net_guarantees` and capability rows report the selected mode and actual attachments.
Assurance covers destination admission when connecting or sending addressed datagrams. It does not implement
ingress filtering, packet inspection, established-connection revocation or content control over an allowed peer.
Allowed DNS resolvers, helpers, pipes and destination services can relay data; they remain part of the trust scope.

Explicit listener, ingress, resource and DNS declarations add separate controls. Their tier requirements,
packet accounting and helper boundaries are specified in [Network controls](../../docs/p0/network-controls.md).

**Docker — roadmap, not accepted contract support.** The loader rejects nonempty `docker:` and container
configuration. The following describes the proposed proxy behavior. Requests through the run's proxy socket are decided by the `docker:` section: an item absent from
`docker.allow` and `docker.ask` is refused with `rule: docker.<name>`; bind sources default to `fs.write` (rw) and to
paths readable by the invoking uid outside `deny_read` (ro); container ids are resolved and rewritten before
forwarding (ARCHITECTURE §9).

**HTTP MCP servers.** *Added 2026-10-19 ([agent-contract](../../docs/p0/agent-contract.md) R16a; FEATURES I5):* an
`mcp:` entry with a `url:` (an HTTP server the agent connects to) admits that URL's host and port under a `net:`
section, as one more allow entry after the author's, decided and resolved like any `tcp://host:port` entry (TCP
only: a UDP datagram to the port is refused), and its net lines carry `rule: mcp[<name>]`. An endpoint `net.allow`
lists already is decided by that entry, and one a `net.ask` entry would decide (same port, and the same host or an
address compile resolved the URL to, kept or dropped under R18, inside the entry's CIDR or kept addresses) derives
nothing, so a connect the entry holds still asks: a server's URL never turns an approval compile can see into an
allowance or a refusal. An address R18 dropped from the ask entry's own name is one it never asks for and does not
count. The server's other addresses, kept or dropped, which no ask entry holds (an entry naming the server's host
holds only the addresses its own lookup kept), are then refused unless another allow entry admits them, and the
warning names them, a dropped one with its class. An address a later answer brings to the server's name is decided by the derived
rule, the first match (R16a). With no `net:` section it adds nothing
(§1). A stdio server (`command:`) gets its exec grant instead (§4); neither kind is launched or configured by the
run itself. *Amended 2026-10-19:* an address dropped from the ask entry's name
counted and one dropped from the server's name did not, the reverse of what the run asks and refuses; and a
partial ask's warning said every connect to the server asked. *Amended 2026-10-19:* that warning said connecting asks first where an entry naming the server's host had kept none of its
addresses, and R18's warning said the URL's other addresses still admitted where no rule was derived; the decisions
are unchanged.

## 6. Ask

`fs.ask` contains up to 256 literal file/directory scopes, each at most 4096 bytes. It pauses regular-file write-opens or creation; reads keep their ordinary policy, and rename, unlink, mkdir, chmod, special files and O_TMPFILE are not approval operations. Scope identities are pinned before actor release. An approved open reuses the pinned actual inode or exclusively creates the absent leaf beneath its held parent, under the target's credentials and umask, then returns the descriptor atomically through `ADDFD|SEND`. It never continues the tracee's mutable pathname lookup or grants the scope permanently. A held file open, an `fs.ask` write-open or a gate-raised open, is presented and recorded with hold `open`, whatever `ask.hold` says: that key places network asks only. *Amended 2026-10-05:* such an approval said hold `connect`, a network hold, on a file path. *Amended 2026-10-16 ([ADR 0041](../../docs/adr/0041-race-free-supervisor-decisions.md) Stage B):* under `gate.completion: held` a gate-raised open is pinned, approved and opened by the run's open deputy, inside the run's domain, rather than under the target's credentials outside it; an `fs.ask` or `fs.ask_read` approval, whose scope by design carries no kernel right of the run's, is still completed by the supervisor as above.

*Amended 2026-10-27 ([ADR 0047](../../docs/adr/0047-fs-ask-mutations-made-on-pinned-names.md), designed 2026-10-20):* inside an `fs.ask` scope that asks, unlink, rmdir, mkdir, rename (no flag, `RENAME_NOREPLACE`, `RENAME_EXCHANGE`), symlink and link are approval operations too, under hold `mutation`: the person is shown each name where the mutation will act (a rename's or a link's new name, or a symlink's stored target, as `target2`), and an approval makes exactly that mutation on the directories the supervisor pinned, as the agent (its credentials, umask, root and cwd), so a symlink swapped during the hold cannot redirect it. Every end must lie in the one scope (else `EXDEV`, unsupported, before anyone is asked); no approval reaches a protected target, a directory above one, any entry's own path, tego's own state or a `deny_read`, and a live block refuses one before the ask and again after the answer. An approved open does not license a later rename: a write made as a temporary file renamed over the target (Claude Code's Write tool) is two questions, the create and the rename, and a standing answer for a rename names both ends. A mutation the kernel would fail anyway (a missing name to remove, an existing name to make) is not asked. truncate, chmod, chown, xattr writes and mknod stay refused.

Approval authorizes the open attempt, not guaranteed target success. A create/truncate may complete before notification withdrawal or descriptor delivery failure. The separate human filesystem event reports `operation_completed` and `fd_delivered`; a vanished notification reports `result_unknown` with no fabricated syscall return, and so does a delivery the kernel took as answered without installing the descriptor, which is then answered nothing again (the delivery's ioctl runs with the supervisor thread's signals blocked, which leaves only a stop, a freeze or a ptrace interrupt of tego itself able to cause it; ADR 0008, amended 2026-10-16). The approved filesystem effect has no rollback guarantee.

`net.ask` requires explicit `tcp://host:port` entries. `ask.hold` chooses `connect` (default: the syscall and copied address/socket are held), `first_write` (a private loopback relay accepts the connect and bounded buffered bytes, then asks before connecting or delivering to upstream), or `request` (an authenticated fixed-model HTTP forwarder applies static policy, reads a complete bounded body under deadlines, then asks before upstream dispatch). The relay changes the socket's visible peer to loopback, and original sends may enter kernel buffers: it guarantees held delivery, not a transparent parked send syscall. UDP, Unix, raw/MPTCP approvals, opaque TLS request inspection, CONNECT and WebSocket request holds are unsupported and fail closed. *Amended 2026-10-19:* `net.ask` also takes `unix:<path>` and `unix:@<name>` entries, matched as a `net.allow` `unix:` entry is (§5), and only under `ask.hold: connect`, which compile requires of a contract that lists one. A unix connect whose name reaches the place such an entry names (§5: a pathname scope is a place, whatever spelling reaches it) and that nothing admits is held at the syscall; an approval is carried out as the agent and connects at that place only (a name the agent repoints elsewhere during the wait is decided where it then leads, with no person's authority), and a denial or timeout refuses it with `EACCES`. At tiers 2 and 3 an approved abstract name needs the run's kernel to admit that one connect; where it cannot, the connect is refused `ask-unavailable` before anyone is asked. UDP and raw approvals stay unsupported. *Amended 2026-10-19:* `net.ask` also takes `udp://host:port` and a bare `host:port`, which names TCP and UDP as a `net.allow` entry does, each with a port (so `ask: ["queue.internal:5672"]` compiles as written), under `ask.hold: connect` only: an addressed UDP datagram or a UDP connect to such a destination that nothing admits is held, asked as op `send` or `connect` with target `udp://ip:port`, and once approved relayed from the address and payload copied before the wait (supervisor R13d); an approval also covers that socket's later datagrams to that destination, and another socket is asked again or answered by a standing `--always`. At tiers 2 and 3 the run's kernel admits each relayed operation by a one-shot grant. A `sendmmsg` batch to such a destination stays refused, and a UDP connect of an `AF_INET6` socket to an IPv4 peer is refused `ask-unavailable` at tiers 2 and 3. UDP approval is therefore no longer among the unsupported ones above; raw and MPTCP approvals still are (an MPTCP socket is refused at `socket(2)` under any `net:` section, ADR 0018).

`ask.timeout` defaults to 5 minutes, or 4 minutes for request holds; explicit timeout must be positive and at most 1 hour. `ask.max_pending` defaults to 64 and permits 1..64; it bounds unanswered asks, so a `first_write` relay counts until its approved first delivery, and a run's established relays are bounded separately at 256 (amended 2026-10-05). Missing `ask` with declared scopes uses connect defaults. Unknown/duplicate/null fields and invalid scalar types are refused. Ordinary allows take precedence; protected state and credential guards cannot be approved. Observe, setuid and io_uring opt-in cannot combine with ask.

Request retries coalesce only with identical sender birth, fixed authority, method, path/query, complete body and credential/header hashes. Their metadata contains neither body nor credential. Only one upstream dispatch receives approval; replay storage shares the existing bounded capture budget, and an oversized or unavailable replay answers with an error rather than dispatching again. A finished replay holds that budget for its retry window (650 s) and is released when the window ends, whether or not another request asks (*amended 2026-10-05:* it was released only by the next request-ask's sweep, so a run that asked nothing more kept approved responses pinned and could refuse later bodies 413). The HTTP body bound applies before asking; an incomplete or oversized body is refused.

`tego ask <run> [ask_id] [--json]` lists or inspects pending operations; a listed rule cut at 64 bytes or target cut at 128 is marked `rule_truncated` or `target_truncated`, and the inspection returns both whole (amended 2026-10-26, ADR 0122). `approve` and `deny` answer one pending identifier exactly once. The local broker authenticates the packet writer, checks a live pidfd, and rejects governed run members and descendants as administrators. The CLI independently verifies the live launcher/lock and broker peer. Ledger acceptance of both ask and answer precedes operation completion; append failure ends the run. Timeout records `ask-timeout`; denial records `ask-denied`; missing broker, kernel support, cancellation, capacity exhaustion or teardown records `ask-unavailable`. A `first_write` delivery records its refusal even when it ends before an answer line exists, and an approved one records whether the upstream connection and first delivery succeeded; its ask re-checks the connecting process, not the thread, which may exit after its connect (amended 2026-10-05: such refusals left only the connect's `allow` line, and an exited connecting thread was refused unasked). No ask path uses `CONTINUE`. Root TCP completion additionally requires one exact cookie/destination credit, atomically consumed by the destination hook and revoked on every outcome. Adopted or external cgroups without the launcher's filter/broker remain unavailable.

*Added 2026-10-06 (standing answers):* `tego approve` and `tego deny` take `--always`. The answer then also stands for the rest of this run, for a later request with the same operation, the same contract rule and the same exact target (an `open`'s path, a `connect`'s `ip:port`), and for none other: a request that differs in any of the three is held as before, so an answer never reaches the scope, a sibling path or another endpoint. It does not contradict "never grants the scope permanently": the approval of one open still authorizes one open, and a later identical open is answered by the recorded standing answer, not by a grant on the scope. A held request already waiting for the same key is answered with it, once the human's answer line is recorded: the standing answer takes effect only then, so an `--always` cancelled, closed or refused by the ledger before its answer line is written answers once and stands for nothing (the CLI says so), and a second `--always` for a key whose first is still being recorded is refused (`ask: another always answer for the same operation, rule and target is being recorded`) with the request still pending. For a file the key is the path, not how it is opened: an approved append also covers a later truncate or create of that path, since the ask line shows the path and not the flags. Each such automatic answer is its own `ask` and `answer` pair in the ledger, the answer's `by` reading `standing:<ask_id of the human answer>`; the human answer's `by` ends in ` always`. Standing answers live in the broker and end with the run, and count against the cap of open asks while their two lines are written; at most 256 are kept, and an `--always` that cannot be kept leaves the request pending (`ask: this request cannot be remembered` or `ask: too many standing decisions in this run`), so it can be answered once. An `--always` already chosen and still being recorded holds its place among the 256 (amended 2026-10-16), so an answer line ends in ` always` only for an answer that stands: before, two answers chosen at once could both pass the check and the later-recorded one, its line already saying ` always`, stood for nothing. *Amended 2026-10-16:* what stands is decided by the recorded line, not by what became of its own request afterwards: an `--always` (or a `timeout always`) whose line is in the ledger stands even when its request's owner is cancelled between that line and the install (a held thread killed as the answer was written). The cancellation refuses that one request's operation (it is answered `ask-unavailable` to the agent, and the CLI says the answer stands though this request's operation was refused); only a run already shutting down installs nothing, as it answers no later request. Before, such a cancellation installed nothing and the line named a standing answer that never stood, so a later identical request was held again and could be answered otherwise. Rejected: keeping the undo (it is the false line), and writing a second line that withdraws the standing answer (the ledger would carry a retraction nobody decided, for a cause that concerns one thread, not the key). A scored gate request and a `first_write` or `request` hold are never remembered: their approval is bound to the score or the bytes the approver saw. A missing answer is never an approval: a timeout refuses, as before (`ask-timeout`), and no contract key makes it allow.

*Added 2026-10-16:* `ask.on_timeout` says what an ask nobody answers leaves behind.
`refuse`, the default and the behaviour before the key existed, refuses the operation once (`ask-timeout`), so an agent
that retries is held again for the whole timeout each time: five tries held 15.2 s of a 16 s run in one test, and with
the 1-hour maximum an unattended agent that retries is held for the night, while `stall_after` does not run during a
hold. `refuse_always` refuses it and leaves a standing refusal for the same operation, the same contract rule and the
same exact target, as `tego deny --always` would: the timed-out answer's `by` reads `timeout always`, and every later
request for that key is refused at once as its own `ask` and `answer` pair, `by: standing:<ask_id of the timed-out
ask>`, reason `ask-timeout` (never `ask-denied`: nobody denied it). It follows the standing answers' rules exactly: it
is installed only once the timed-out answer's line is recorded (a timeout cancelled, closed or unrecorded before its
line stands for nothing; once `timeout always` is recorded it stands, even if the held request is cancelled just after); it counts against a bound of its own, 256 standing refusals that timeouts left, apart from the 256 a person's
answers have, and its place is held from the moment the timeout is chosen, so `timeout always` is written only for a
refusal that then stands (past the bound the timeout refuses once, `by: timeout`); a scored or gate-raised ask
and a `first_write` or `request` hold are never remembered and refuse once; a person's `--always` for the same key
that is still being recorded stands instead and the timeout refuses its own request once, and a person's `--always`
while a timeout's standing refusal is being recorded is refused as busy, the request still pending; a held request
already waiting for the key is refused with it. It never allows anything, and no person can lift it for the rest of the
run: it is the contract's choice that an unanswered question is answered no for the run. Rejected: remembering a timeout
by default (it changes what an existing contract does to a retry), a timeout that stands for a time instead of the run
(a second clock beside `ask.timeout` with no person behind its end), and a refusal keyed on the target alone (it would
refuse an operation or a rule the timed-out ask never showed). *Amended 2026-10-16:* the
agent alone decides how many distinct asks nobody answers (every path under an `fs.ask` directory scope is its own
key), so the timeouts' refusals have their own bound rather than sharing the person's: sharing it let an agent that
asked about 256 paths nobody answered leave every later `tego approve --always` or `tego deny --always` of the run
refused as full. Rejected: a person's `--always` evicting a timeout's refusal when the table is full (it would lift a
refusal the contract chose, for a key nobody looked at), and a smaller bound for timeouts (it only brings forward the
point past which a retry is held for the whole timeout again). `tego compile` prints `ask hold=... timeout=...
max_pending=... on_timeout=...`, with what `refuse_always` does.

*Added 2026-10-06 (held reads):* `fs.ask_read` lists up to 256 literal files or directories, each at most 4096
bytes, that must exist (`path-missing` otherwise; a glob is a schema error, `/` is refused). A read-open of a regular
file the nearest read-deciding entry of which is an `fs.ask_read` entry is held for a person exactly as an `fs.ask`
write-open is: `tego ask` lists it with hold `open` and op `read`, `tego approve|deny [--always]` answers it, the
agent's thread waits, `ask.timeout` refuses it (`ask-timeout`), and an approval delivers a read-only descriptor of the
pinned inode with `ADDFD|SEND`. A standing answer's key is op `read`, the entry's rule and the exact path, so it never
answers a write. Each entry compiles as a `deny_read` entry marked for the supervisor (agent-contract R22): the Landlock
ruleset withholds its reads by the sibling enumeration of §2, `Evaluate` refuses them read-denied under the rule
`fs.ask_read[...]`, and anything the supervisor continues the kernel refuses. Not held, and decided as before: an
`O_PATH` or `O_DIRECTORY` open, a write-open (an `O_RDWR` open included), a file a `deny_read` or a write entry nested in
the entry decides (nearest wins), a non-regular file, and a path the pinned walk cannot resolve. A file in tego's own
state is refused read-denied and never asked, whatever entry is nearer, and so is every read when the entry's pinned
scope was replaced (`ask-unavailable`). A read gate can escalate a held read (its refusal refuses, `fs-gate`; its score
goes with the ask, which is then never remembered). Held reads need tier landlock: the root tiers decide a read in the
kernel, so `compile` refuses `fs.ask_read` when the table's tier is `cgroup` or `bpflsm` (pinned, or `auto` on a
machine whose highest tier is one: pin `tier: landlock`), and the launcher refuses such a table at any other tier,
the observe backend included (observe cannot ask). To find the reads it holds, tier 1's filter notifies every open of
such a table, as `record: full` does (its cost per open, enforce-landlock R12); under `summary` and `off` a read that is
neither held nor refused leaves no line, so the record keeps what §7 says it keeps, and a refused read keeps its refusal
line. Compile decides the conflicts: an entry that is, or lies beneath, a declared `deny_read` is a `contradiction` (an
ask never lifts a deny, from whichever file of an `extends` chain either came); one at or beneath tego's own state
(agent-contract R6a's list) is a `contradiction` (those stay refused whatever is listed); one at or beneath a write entry
or an `exec.allow` directory, or holding an exec grant, is refused `unenforced` (Landlock could not withhold that read,
so it would reach the file unheld; an `fs.ask_read` entry never compiles unenforced); an `fs.ask` scope at or beneath
one is a `contradiction` (its write-opens would be refused read-denied, never asked); an entry of the top-level contract
at a built-in `deny_read` path replaces that built-in entry, and one beneath a built-in entry is nearer than it, each
with a warning (`unenforced`), while the same from a profile is a `contradiction`. A `deny_read` or a write entry nested
inside an `fs.ask_read` entry is nearer and decides beneath itself.

*Amended 2026-10-27, a live block outranks the answer to a held file open.* A held file open (an
`fs.ask_read` or `fs.ask` hold, a gate-raised open, a gate-held ask on the open deputy's pin) is refused before anyone
is asked when a live block (`tego block`, the dashboard's Block now and Never allow) or an Adjustable run's unlifted
fence entry of its access class covers the held file, as before; one that lands while the person decides takes the
request back (it is answered `ask-unavailable` by `cancelled`, so `tego ask` and the dashboard no longer list it), and
one in force when an answer comes back refuses the open whatever the answer, before anything is opened. Either refusal
names the block's rule (`live.block[read:...]`, read-denied for an open that reads), never the ask's. Before, an ask
made before the block landed stayed answerable, and an approval delivered the file the block named. A held mutation is
refused after the answer as before (above), but not taken back while it waits.

*Amended 2026-10-27 (net), a live block outranks the answer to a held connect.* The same holds for a
connect held for a `net.ask` scope or a gate's ask range, and an addressed UDP datagram held for a `udp://` scope: a
live `net` block naming the destination, by its address (with or without the port) or by the declared host the scope
or the admitting entry matched it under, that lands while the person decides takes the request back (`ask-unavailable`
by `cancelled`), and one in force when an answer comes back refuses the connect or datagram whatever the answer, before
anything is granted, connected or sent; the refusal names the block's rule (`live.block[net:...]`, net-not-allowed).
A unix connect held for a `net.ask unix:` scope is taken back the same way when a block names the scope's place, the
name as spelled or the abstract name, an approval that comes back after such a block connects nothing, and the
approval is matched again where the relay's walk lands, as before. A block in force when the connect or datagram
reaches the scope refuses it before anyone is asked, by the scope's declared host as well as by the address. A UDP
socket's approval of a destination does not outlive a block: each later datagram there is put to the live blocks
before it is sent, and one a block refuses drops the approval, so the socket is asked again once the block is lifted.
Under `ask.hold: first_write` the relay asks at the agent's first write and applies the same rule there: a block in
force at the connect refuses it before a relay is reserved, one in force at the first write refuses the delivery before
anyone is asked, one landing while the person decides takes the request back, and an approval after the block, or a
block that lands while the relay dials, delivers nothing (a `refused` `first_write` line under the block's rule; a
request taken back keeps its answer's `ask-unavailable` refusal). Before, an approval reached the destination the block
named.

*Decided 2026-10-16 ([ADR 0057](../../docs/adr/0057-fs-ask-read-and-alternates.md) D3), an ask beneath a write
entry.* One rule for both kinds of ask: an ordinary grant takes precedence over an ask (above), so an ask at or
beneath a write entry is never asked. For an `fs.ask` scope that loses only a question the write grant already
answered, and nothing is less protected than its author granted: `compile` warns (`redundant-rule`, "the scope never
asks") and the table compiles; the supervisor allows such a write by the write entry, as it always did. For an
`fs.ask_read` entry it would lose the protection itself, since the entry is also the `deny_read` that keeps a secret
and Landlock unions grants, so the agent would read the file outright: `compile` refuses it (`unenforced`), as it did.
A write entry nested strictly inside an `fs.ask_read` entry has a meaning, nearest wins: it decides beneath itself
(its reads and writes are not held) and the rest of the entry is held; the same holds for a write entry nested in an
`fs.ask` scope. Rejected: one error for both (an `fs.ask` scope beneath a write entry weakens nothing, and refusing it
would break contracts for a redundancy); one warning for both (an `fs.ask_read` entry would then compile unenforced,
a secret its author listed readable without a hold); letting an ask take precedence over the write grant (Landlock
cannot withhold a read or a write beneath a grant at tier 1, so the ask could not be enforced where it mattered).

*Decided 2026-10-16 ([ADR 0057](../../docs/adr/0057-fs-ask-read-and-alternates.md) D4), an `fs.ask_read` entry that
relaxes a built-in `deny_read` entry.* It stays allowed from the top-level contract, and is disclosed twice: compile's
warning names the built-in entry it relaxes and how (`relaxes the built-in deny_read entry <path>, which it replaces`,
or `..., inside which it lies`, the rest of that tree still refused), and every run of the table says so in its
record: `run_start.ask_read_relaxes` lists `{rule, builtin, how}` per relaxed entry (`how` `replaces` or `inside`;
absent when there is none, `record_minor` 9). It is allowed because it relaxes a refusal to a question, never to an
allow: every read is still held for a person who sees the path, and the author of the contract file asked for exactly
that, as a top-level write entry may lift a built-in `.env` entry (ADR 0043 D3). Rejected: refusing it (it would leave
no way to be asked for one's own `~/.aws/credentials` short of editing the built-in list away); allowing it with the
warning alone (compile output is not the record: a ledger read later would not say the default had been weakened);
allowing it from a profile (a profile would lift a built-in protection for every contract that extends it, which stays
a `contradiction`).

*Added 2026-10-06 (alternates):* a held file open, a read or an `fs.ask` write (and a gate-held open), takes a
third answer: `tego alternate <run> <ask_id> --file <path> [--always]`. The supervisor opens the person's file in place
of the target and delivers that descriptor as the open's result, by the same atomic `ADDFD|SEND`; the target is not
opened. The path is an attack surface though only a person supplies it, so (*amended 2026-10-16,
[ADR 0057](../../docs/adr/0057-fs-ask-read-and-alternates.md) D2*): the file's identity is fixed when the person names
it: `tego alternate` opens the path in the person's own process, `O_PATH`, with no symbolic link and no magic link
anywhere on the way (`openat2` `RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`; a path through a link is refused, naming
the path it resolves to, for the person to check and name), and passes that descriptor to the run's broker over its
socket (`SCM_RIGHTS`, exactly one with an alternate answer and none with any other packet); the broker and the
supervisor never look the path up again. Every check is made on that descriptor: a regular file with one link, on no
kernel pseudo filesystem (procfs, sysfs, cgroupfs, bpffs and the like), whose kernel path names the same inode in the
supervisor's view (a file removed since is refused) and lies outside tego's own state (the ledger root and with it
every run directory, the chain anchor's directory, `~/.tego`, `/run/tego`, `$XDG_RUNTIME_DIR/tego`, the price
table, the profiles directory), the contract file's directory (but beneath a write entry), every `deny_read`,
`fs.ask_read` and implicit entry, and every declared `deny_read` glob and built-in `deny_read` path, whether or not it
existed at compile, whose name is none of the built-in `.env` list's, and, for a write, outside the user registry's
`agents/` and `skills/` (`RuleTable.OwnReadable`, *amended 2026-10-20*, agent-contract R26: a run may read them, so a
read alternate there is one like any other), of no built-in `deny_write`
class by its names, outside every `deny_write` target and beneath a write entry or an `fs.ask` scope (D2 below),
that no live block and no unlifted read fence entry refuses the agent's own open of with the held open's flags (a live
read or path block, or a read fence entry, for a read; a write or path block for a write; the run's live blocks as they
stand when the check runs, at the answer and again at delivery; *amended 2026-10-27*: the compiled
table holds no live block, and compile takes a read fence entry's `deny_read` out of it, so a file there was handed
over), and that the contract's gate does not refuse (a read gate for a held read, a write gate for a held write and both for an `O_RDWR` one, scoring the file
as the agent's own open of it; *amended 2026-10-16); only then is it reopened through the descriptor, with the agent's credentials and umask (so it can grant nothing the
agent's own credentials could not open) and the held open's flags: read-only for a held read (an open with a write flag
is no read), and for a held write the agent's access mode, append, truncate and sync flags with create and exclusive
dropped (the alternate exists; the person's choice replaces the create). The same checks run when the person answers,
with the access mode alone so nothing is truncated, and a refused alternate leaves the request pending with the
reason (`ask: the alternate cannot be used: ...`); they run again at delivery on the same descriptor, since the file
can be renamed between the answer and the delivery, and one that fails then refuses the open (`ask-unavailable`). Only a held file open takes one (`ask: this request cannot be
answered with an alternate file` otherwise, the request still pending). An alternate is never an approval of the
target: the answer is `approved: false` with no refusal reason, so anything that does not know alternates refuses the
operation, and every path that turns an answer into a refusal (a timeout, a shutdown, a ledger that refuses the line)
delivers nothing. `--always` is allowed and keyed exactly as an approval's (op, rule, exact target): every later
identical request is given the same file, by the descriptor the person's command passed (the broker keeps it until the
run ends), checked anew each time, as its own recorded ask and answer pair;
it is allowed because the person's choice is as bounded as an approval (one file, the agent's credentials, every check
repeated per delivery) and an agent retrying a read the person already answered should not be held again. Whether the
agent's credentials are the right bound was decided as: they are the existing held open's (an approval cannot grant
more than they allow either), and the protected-path checks, not the credentials, are what keep tego's own state out
of reach, since at tier 1 the agent and the person share a uid.

*Decided 2026-10-16 ([ADR 0057](../../docs/adr/0057-fs-ask-read-and-alternates.md) D1), what the record says of an
alternate.* The answer line keeps `approved: false` and no `answer_reason`, and that is the truth, not a placeholder:
`approved` answers whether the operation as asked, the `target`, was granted, and it was not; nothing was refused. The
line also carries what was done instead and on whose authority: `alternate`, the file delivered, by the path the
supervisor read from the person's descriptor; `alternate_dev` and `alternate_ino`, its identity when the person named
it; and `by`, the person (`uid:<uid> pid:<pid>`, or `standing:<ask_id>` for a standing alternate's later answers).
A standing alternate's later answers repeat the `alternate`, `alternate_dev` and `alternate_ino` of the answer that
set it, so their `alternate` is the path recorded when the person named the file, which the agent may have renamed
since; the file is the one `alternate_dev`/`alternate_ino` name (the run keeps its descriptor), and the path it had
when delivered is the `fs` line's. Rejected: reading the path again for each standing delivery (a second read of the
same descriptor, before the delivery's own, would still race a rename, and the `fs` line already names the path at
delivery). The open it completed is its own `fs` line (`authority: human`, `verdict: allow` on the file delivered,
`alternate_for` the target). Every reader takes it the same way: `tego events` says `alternate <path> (not the file
asked for) by <who>`, `drift` counts the `fs` line in the rule's own `alternate` count and never as an `allow` of the
rule that held it, `measure` counts the answer lines as `alternates` (neither refusals nor approvals; the answer line is
kept under every record mode, the delivered open's line not under `record: off`), and `learn` proposes nothing from it,
for the file asked for or the file given. Rejected: `approved: true` with the alternate beside it (every reader that
does not know alternates would read a grant of the target, and the ledger would say something other than what
happened); a fourth verdict, `alternate`, on the `fs` line (the v1 verdict set is closed, and the open the agent made
did succeed, on the person's file, which `allow` with `alternate_for` says); an `answer: alternate` field (it says
nothing `alternate` does not).

*Decided 2026-10-16 ([ADR 0057](../../docs/adr/0057-fs-ask-read-and-alternates.md) D2), where an alternate may come
from.* Who opens the file, and when, was the open question: the first version's supervisor opened the person's path itself, after
the answer and again at delivery, outside the agent's Landlock domain and, at tier 1, with the person's full identity.
Between the person's command and those opens the agent could rebind the path (rename a directory on the way, swap a
symbolic link into it), and the supervisor would then open, for reading or for writing, a file the agent's own domain
could never reach and no protected-path list names (one created after launch beside a `deny_read` target, a dotfile in
the home directory for a held write): a confused deputy. The descriptor is now opened by the person's command when they
name the file and is the only thing used after; a link anywhere on the way is refused rather than resolved, since the
agent can swap a link and the person cannot see it. Refused as alternates, whatever the person types: tego's own state
(above); the contract file's directory, but for a file beneath a write entry; every `deny_read` target declared or built
in, every `fs.ask_read` entry and every implicit entry; every file a declared `deny_read` glob names and every path of
the built-in `deny_read` list under the home directory, or a file beneath one, whether or not it existed when the table
compiled and whatever `deny_read` says (a glob's rows are the files that existed then, and compile skips a built-in path
that does not exist; the table carries them as `DenyReadPatterns`, matched also ASCII case folded); and any file named
as the built-in `.env` list names secrets (`.env`, `.env.*` but its examples), wherever it lies, so a mistyped
`.env.example`, `~/keys/new.pem` or a `~/.netrc` written during the run never hands the agent the secret. For a held
write, also: a file of a built-in `deny_write` class by its names alone, wherever it lies (beneath a `.git`, a `hooks/`
file, a `config` or `config.worktree`; a `.git` file; a file beneath `.husky` or `.githooks`; anything beneath
`.claude`, `.mcp.json`, `.cursor`, `.codex`, `.gemini` or `.vscode`; a shell startup name such as `.bashrc` or `.zshenv`,
or `fish/config.fish`; `.gitconfig` or `git/config`), since the compiled `deny_write` sets hold only what compile found
beneath a write entry or an `fs.ask` scope; every `deny_write` target; and every file outside every write entry and
`fs.ask` scope: a write alternate is a file the contract lets the agent write, or be asked to write. And, for any held
open, a file the contract's gate refuses (*amended 2026-10-16*): the gate scores the file as the agent's
own open of it would be scored (`fs.read` predicates for a held read, `fs.write` for a held write and both for an `O_RDWR` one, with the floor `ask`,
since it reaches the agent through a person's answer), and a score above the `ask` threshold refuses it, at answer time
and at delivery, as it refuses the agent's own open and a held target; a score at or below it leaves the person's
choice standing. A gate refusal is the contract protecting a path no less than a `deny_read` entry, and before this a
`tego alternate` handed over a `*.pem` the agent's own `cat` was refused, or let a held write land outside the worktree
under `fs.write outside worktree`. The delivered open's line carries the gate's decision on the file delivered, never
the target's. Not refused: a file
beneath a write entry (the agent's own tree), the project's included: its identity is fixed when it is named, its bytes
are the agent's own already, and R10 keeps the contract file out of every write entry. Rejected: letting the supervisor
resolve the path and re-check the inode the person saw (the person's command would have to report an inode it did not
hold open, and the window between its stat and the supervisor's open stays); resolving the path with `RESOLVE_BENEATH` a
root the agent cannot write (no such root contains every legitimate stand-in); refusing every file the agent could write
(it removes the common case, a stand-in the person or the agent prepared in the project, and buys nothing once identity
is fixed); refusing only declared `deny_read` targets (a built-in one is the likelier typo); refusing write alternates
by name class alone, anywhere (*amended 2026-10-16*: the supervisor, outside the agent's Landlock domain,
would hand the agent a writable descriptor of whatever the class list does not name, a crontab, an autostart entry,
`~/.ssh/authorized_keys`, a directory on `PATH`, and no list enumerates every file that runs code later); exempting an
`fs.ask` scope in the project from the contract directory's refusal (an ask scope can lie above a file that steers the
next run, a profile the contract extends, which R10 keeps out of write entries only); and leaving a declared glob's and
an absent built-in path's later files as an accepted residual (a typo there is the harm this decision exists for).

*Decided 2026-10-16 ([ADR 0057](../../docs/adr/0057-fs-ask-read-and-alternates.md) D5), the record revision.* The fields
fs.ask_read and alternates add (an ask's `op: read`, an answer's `alternate`, `alternate_dev` and `alternate_ino`, an
`fs` line's `alternate_for`, `run_start.ask_read_relaxes`) take `record_minor` 9 (`record.MinorAskRead`): at 9 or later
every alternate answer carries all three alternate fields, every held read's ask says `op: read`, and an absent
`alternate` or `ask_read_relaxes` means none; below 9 a ledger an early build wrote may carry `alternate` alone
(`spec/record/v1/README.md`). Rejected: leaving revision 7 (the argument that an absent `alternate` means none in
every ledger is true of that field, but not of `alternate_dev` and `alternate_ino`, whose absence a reader must be able
to read, nor of what `record_minor` exists to say: what an optional field's absence means at that revision); a new record
version (every field is optional and additive, which is what a minor revision is for).

## 7. Reads, watch lists, aggregation

Reads are aggregated per (exec id, nearest rule) into counts, except paths under `deny_read` or `fs.watch`, which are
always individual events. `record: full` disables aggregation. In the unprivileged tier read-opens never reach the
supervisor (except under `fs.ask_read`, whose filter notifies every open to find the reads it holds, §6, and records
no read it neither holds nor refuses unless the record mode keeps reads), so watch-list reads are individual events
only under `record: full`; otherwise the run records
`gap what=record why=unprivileged-tier`, once, right after `run_start`, whenever the contract has a `deny_read`
(declared or built in) or `fs.watch` entry. An observe run installs the same filter and records the same gap. The
filter cannot be narrowed to the watched paths: it sees the path argument as a pointer, never as a string.
*Amended 2026-10-24 (ADR 0069 D4):* a run that holds its reads (§1, §2) is notified of every open as an `fs.ask_read`
run is, and records the same way: an allowed held read has no line unless the record mode keeps reads or a read gate
scores it, and every refusal has its line. Since every read of a `deny_read` target is then refused with its line,
the gap is written for such a run only when it has an `fs.watch` entry. *Amended 2026-10-25:* an
`O_PATH` open reads nothing and no tier's mechanism decides one (the kernel runs no `file_open` hook for it), so at
tier landlock its line beneath a `deny_read` says `allow` by that entry with the marker ` (O_PATH: reads nothing)`,
neither `refused` nor ` (unenforced: parent writable)`; the reads through its descriptor are opens of their own.
*Amended 2026-10-25:* the same holds at tier cgroup and bpflsm, where neither the fanotify listener nor
the decision plane (whose only open hook is `file_open`) nor the kernel recorder sees an `O_PATH` open: its line beneath
a `deny_read` says `allow` with the marker, and it is the supervisor's line even while a recorder reads.
*Amended 2026-10-25:* that line is kept under `record: full`. Under `summary` or `off` a run that holds
its reads writes none for an `O_PATH` open it does not refuse, beneath a `deny_read` or not, as an `fs.ask_read` run
writes none: the open reads nothing, so it is not one of the reads beneath a `deny_read` this section keeps as
individual events, and no tier's recorder sees one (the record mode decides, and a run without held reads was never
told of it).

## 8. Limits and config precedence

Ceilings (`tier`, `capture`, `limits.*`) come from the machine config (spec/config/v0). Every layer, the contract
included, may lower a ceiling, never raise it; `compile` prints each effective value with its source.

*Added 2026-10-16:* `limits.stall_after` ends a run that has done nothing the run sees for
that long: what it records, every notification the supervisor answers under `record: off`, model traffic in flight,
and the wait of a published ask. At tier `landlock` under `record: summary` or `off` a read-open never reaches the
supervisor (§7), so a read is neither a line nor activity there, and an agent busy only reading is ended as stalled
(in one test 14 s of reads ended at 6 s of `stall_after: 5s`; under `record: full` the same agent ran to its own end).
`compile` warns of it (`stall-reads-unseen`) when the contract sets `stall_after`, the record mode is not `full` and the
run can land at tier `landlock`; the warning holds at that tier alone, so `tego run` prints it again once a run lands
there, and names the ways out: `record: full`, under which every read is a line, or a root tier under `record:
summary`, whose recorder counts reads in aggregates flushed at least every 5 s. A `stall_after` a machine ceiling alone sets is not warned: it is not the
contract author's to fix. *Amended 2026-10-16:* the record mode the warning is
derived from is the run's: `tego run --record` is handed to `compile` before any finding is derived, so `--record
full` over a `record: summary` contract is not warned and `--record summary` over a `record: full` contract is, naming
`--record`; it used to be derived from the contract's mode and then printed unchanged. A `tego run --observe` installs
tier `landlock`'s filter (§7), so the warning holds in an observe run too, whatever tier the contract names. At a root
tier under `record: summary` a read reaches the record, and so the stall check, only in the aggregate the recorder
flushes every 5 s, up to 5 s after it happened (under `full` each read is a line): a `stall_after` at or under 5 s ends an agent that only reads between two flushes, and one under 10 s leaves a
pause shorter than the window enough to end it, so `compile` warns there too (`stall-reads-unseen`, holding at `cgroup`
and `bpflsm` alone) when `stall_after` is under 10 s, twice the window, and the landlock warning offers a root tier only
with a `stall_after` of at least 10 s. Rejected for that case: a shorter aggregation window (it multiplies the lines
`summary` exists to save), and counting each aggregated sample as activity under `summary` as `off` does (the stall
check would then see activity the ledger, from which `tego status` reads idle, does not show for up to 5 s).
*Amended 2026-10-16:* each warning's fix offers only what changes the run it is printed
for. An `--observe` run installs tier `landlock`'s filter whatever tier is pinned, so a warning that holds there alone
offers `record: full` and a longer `stall_after`, and no root tier; one that holds at `landlock` too offers the root
tier outside `--observe`. A record mode that came from `tego run --record` is changed with `--record` in every clause
(`run with --record full`, `run with --record summary`). *Amended 2026-10-16:* at a root
tier under `record: off` a read is neither a line nor activity either: the kernel recorder writes no sample for an
allowed open under `off` (only refusals, execs and the like), so the activity each sample gives under `off` never comes
from a read. The two warnings said the opposite (a root tier "where under `record: off` every read counts as activity
at once", and `record: off` as the way out of the root tiers' late aggregates), and that combination was never warned;
in a KVM guest a pure reader under `record: off` and `stall_after: 2s` was ended `limit-stall` at `cgroup` and at
`bpflsm`. Now `compile` warns it (`stall-reads-unseen`, holding at `cgroup` and `bpflsm` alone, whatever the
`stall_after`), offering `record: full`, `record: summary` (with a `stall_after` of at least 10 s when it is shorter)
or a longer `stall_after`; the landlock warning under `off` offers a root tier only together with `record: summary` and
that floor; and no fix offers `record: off`. A root tier is offered only where pinning one changes the run: one this
tego builds and the machine config's `tier` admits (`pin tier: cgroup` when that is the only one, `pin a root tier
(cgroup or bpflsm)` when both are), and none on a landlock-only build or under a `landlock` ceiling, where a pinned root
tier is refused `[tier-unavailable]` or lowered. *Amended 2026-10-16:*
under `record: off` a root tier's kernel recorder writes no sample for an allowed open, read or write, or path change
(unlink, rmdir, rename, mkdir, mknod and the like), only for an exec, a process's exit and a refusal, so what the
decision plane decides in the kernel without notifying the supervisor (a read, and a write-open or path change) is no
activity there. The root-tier `off` warning spoke of reads alone, and in a KVM guest an agent that only appended to a
file every 50 ms under `record: off` and `stall_after: 2s` was ended `limit-stall` at `cgroup` and `bpflsm` (under
`summary`, where every write is a line, it ran to its end). The warning now names write-opens and path changes
beside reads, and its fix ends "raise `stall_after` past the longest stretch without an exec, a connect or a refusal"
(a connect is activity, below). Tier
`landlock` differs for writes: its filter notifies every write-open, each is activity, and a writer runs to its end
there under `off`. And `tego run --tier landlock` pins the run in the selection, after `compile`, refusing a contract
that pins another tier as a conflict, so the landlock warning of such a run offers a root tier "without --tier
landlock" (`compile` is handed `--tier` as it is `--record` and `--observe`). Rejected: a per-run activity stamp the
kernel would write for each allowed open under `off` (a change to every plane object on every matrix row, adding back
part of the cost `off` exists to save); the gap is warned instead. *Amended 2026-10-16:* under `off` every notification the supervisor answers is activity, at every
tier, and a root tier installs tier `landlock`'s filter too. So a connect, a send and an exec, which the filter notifies
at every tier and no plane hook decides, are activity under `off` at a root tier whatever the kernel recorder writes:
the warning had named an allowed IP connect as unseen, and in a KVM guest an agent that only connected to a loopback
listener every 50 ms under `record: off` and `stall_after: 2s` ran to its end at `cgroup` and `bpflsm`. The contract's
gate and ask entries widen what is notified: a read gate or an `fs.ask_read` entry has the filter notify every
read-open at every tier, and any fs gate or fs ask entry keeps every fs notification with the supervisor at a root
tier, where the plane then decides none in the kernel; on `cgroup`'s fanotify row, which loads no plane hooks,
write-opens and path changes are notified as at tier `landlock`. Under a read gate a pure reader and a pure writer, and
under an `fs.ask` scope a pure writer, ran to their end in the KVM guest under a warning that said they were ended as
stalled. `stall-reads-unseen` is now derived from what the run notifies and records: it is not printed where every
read is a line (`summary` under a read gate, which gives each read it scores a line of its own, skipping the aggregate
at a root tier) or a notification the supervisor answers (`off` under a read gate or an `fs.ask_read` entry; an
`fs.ask_read` entry alone gives a read no line under `summary`, so that is still warned); at a root tier under `off`
with an fs gate or ask entry it names reads alone; otherwise it names a read, and a write-open or path change the
decision plane decides in the kernel, says that a syscall the supervisor answers (an exec, a connect or a send, and on
`cgroup`'s fanotify row every write-open and path change) is activity, and its fix ends "raise `stall_after` past the
longest stretch without an exec, a connect or a refusal". Rejected: naming at compile the `cgroup` row a run lands on
(fanotify or a plane), which the selection decides on the machine after `compile`; the warning names both. The stall check is not given another source of activity. Rejected: the run's CPU time
(`cpu.stat`), under which an agent spinning in a loop never stalls; the read counters of `/proc/<pid>/io`, which count
pipe, socket, eventfd and terminal reads alike, so an idle event loop's periodic wakeups would keep a hung agent alive
for good, and which a non-dumpable process hides; and notifying read-opens only to count them, which is the cost of
`record: full` without its record and leaves `tego status`, which reads idle from the ledger, disagreeing with the
check. *Amended 2026-10-19 (limits-check-doctor-cli.md R4):* the rejection above of a per-run activity stamp the kernel writes is reversed, and with
it the root-tier `off` warning. Under `off` a root tier's kernel recorder writes no sample for an allowed open, path
change, regular-file create or connect, so before the stamp a pure reader at tier `cgroup` or `bpflsm`, and a pure
writer where the plane decides writes, was ended as stalled, and `compile` warned it. Each such action of a run with a
`stall_after` now stamps the run's slot of the kernel's `tego_activity` map instead, which the stall check reads once a
second and `tego status` through the run's activity sidecar (`idle_from`), so the two agree. What the rejection
feared, measured: for a run without a `stall_after` the stamp is one test of a byte the program has already loaded,
and for one with it a jiffies read and a compare, the clock being read and the slot stored once a jiffy;
`tego_file_open`'s own run time grew by +4.2 ns an open on 6.17 and +4.8 ns on 6.1 in KVM guests, under the rig's
resolution and inside the plan's +25 ns and +40 ns (docs/BENCHMARKS.md), and every object loads on every matrix row it
was run on. So `stall-reads-unseen` is printed at no root tier under `off`, whatever the gate and ask entries, and the
landlock warning under `off` offers a root tier as it is ("where the kernel stamps each allowed open as activity at
once"), no longer only with `record: summary` and the 10 s floor. Tier `landlock` and an `--observe` run are unchanged:
their filter does not notify a read, and no kernel program of theirs sees one. Nor is this another source of activity
in the sense rejected above: it is the kernel's own record of the actions `summary` would have sampled, kept as one
timestamp instead of a sample, written by the programs that see the action, and it counts no pipe, socket or terminal
read, and nothing a spinning agent does. Model traffic in flight includes, at tier 2 and above, every TLS call that
moves bytes through the uprobe source's probes, in every record mode.

## 9. Environment

`env.pass` selects inherited variables, `env.deny` removes, `env.set: {NAME: value}` adds or overrides after both;
*amended 2026-11-03 (ADR 0068)*: the exact `${TEGO_PROJECT_DIR}` token in a set value expands once
at compile time to the absolute working directory used by relative filesystem rules. Other dollar expressions
stay literal. The source contract and its hash retain the token;
`compile` rejects a name present in both `set` and `deny`. Runtime variables are applied last and cannot be
overridden by the contract: `TEGO_*`, the propagation set, `ANTHROPIC_BASE_URL` and its peers when `capture:
forwarder`, `DOCKER_HOST` when `docker:` is present. `compile` warns when the contract sets `ANTHROPIC_BASE_URL` or
`HTTPS_PROXY` while `capture: forwarder`.

*Added 2026-10-25 ([ADR 0067](../../docs/adr/0067-agent-token-stores-and-credential-rows.md)):* with no `env.pass` in
the merged contract the agent inherits the launcher's whole environment, and `compile` (and `tego run`, though not an
adoption's compile, whose process has its own environment, nor that of a contract tego generated, `tego watch` with no
`--boundary`, whose user cannot add `env.pass`; *amended 2026-10-26*) warns once,
`secret-env`, when that environment holds variables whose names look like credentials: `GITHUB_TOKEN`, `GH_TOKEN`,
`NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or a name ending, after
a prefix of its own, in `_TOKEN`, `_SECRET`, `_SECRET_KEY`, `_PASSWORD`, `_API_KEY`, `_ACCESS_KEY`, `_PRIVATE_KEY` or
`_CREDENTIALS` (case ignored). A variable `env.deny` removes or `env.set` replaces is not named. The warning names the
variables, sorted, never a value (compile is given names only), with the fix "add env.pass naming the
variables the agent needs" (*amended 2026-10-25*: the fix also said "or extend
tego/no-secrets", a built-in profile, and the working
fix is `env.pass`). No variable is removed: a tool the agent runs may need one (`gh` with `GH_TOKEN`), and an `env.pass`
list is the author's choice of what passes. An `env.pass` list, empty included, never draws the warning.

## 10. Containers and mount namespaces inside the run

A Landlock domain with filesystem rights refuses `mount(2)` and `pivot_root(2)` for every sandboxed thread, so
rootless podman, buildah, bubblewrap, `unshare -m` and agent-started sandboxes do not run in the unprivileged tier;
they are refused and recorded as `gap what=enforce why=landlock-topology`. The filter notifies `mount`, `umount2`,
`pivot_root` and `move_mount`, the four entry points the domain refuses; the supervisor answers each with the
domain's own `-EPERM` and records a `refused` line with reason `landlock-topology` per refusal and the gap once per
binary; `compile` warns when the command, an MCP server or `exec.allow` names `bwrap`, `podman`, `buildah`,
`unshare`, `runc` or `crun`. Tier 2 installs the same domain, so the same holds there. *Amended 2026-09-24
:* the domain refuses `mount(2)`, not the creation of a mount namespace, and
`unshare(CLONE_NEWUSER|CLONE_NEWNS)` copied the mount tree into new mounts that carry none of tier 2's `FAN_MARK_MOUNT`
marks, where a `deny_read` fanotify alone enforces (one nested in a write entry, a planted `.env` among them) was read
with no permission event. The filter now also notifies `unshare(2)` and `clone(2)` whose flags ask for a new mount or
user namespace, and every `setns(2)`; the supervisor refuses each with `-EPERM` (what a host without unprivileged user
namespaces answers) and records it like a mount, `refused reason=landlock-topology op=unshare|clone|setns`, the target
naming the namespace flags. A thread's or a process's ordinary `clone` is left alone; `clone3` is ENOSYS already.
Rootless/container contracts and Docker-proxy/daemon adoption are future product work: nonempty `containers`
and `docker` fields are rejected by this binary. The proposed design would omit filesystem rights from the
root-tier Landlock domain, retain network/scope rights, and use BPF ancestry with a pre-created daemon parent.
Neither the selected root-tier implementation nor generic run-set membership implements that container flow.

*Amended 2026-11-03 (ADR 0069 D3(b), SEC09/SEC10):* the held-read floor retains device/inode identities of
launch-nested deny_read targets and denied descendants. A rename, hard link or nameless reopen cannot remove that
refusal. A file put at a protected entry or in a denied directory during the run is pinned in turn; a change that
cannot be followed, or a lost watch history, makes identity uncertain and refuses held reads until restart
(`held-read-identity-unknown`); inability to establish the launch snapshot refuses launch.
Human-selected alternates obey the same retained-identity and history floor, including write-only alternates
(ADR 0057 D2); a late refusal records any completed truncate without delivering the descriptor. So do approvals of
an `fs.ask`, `fs.ask_read` or copied gate's ask, which reopen the supervisor's own pin: its identity is checked before
the person is asked and again on the reopened descriptor before delivery. An approval's identity floor holds whatever
the access mode (a write-only alias of a protected file is refused, as its name is); a held open that is not an
approval is checked only when it can read. This amends
the moved-target residual in §2 above. Future name-only matches outside those watched launch targets are not part
of that snapshot. ADR 0041's same-date amendment applies live write/path blocks to ordinary held write-opens too,
with a live-set recheck after descriptor identity verification, before delivery.

*Amended 2026-11-04 (SEC08, ADR 0041):* `fs.apparmor_assume_root_namespace` is a boolean, default false,
`refused-in-profile` (top-level contract only). True accepts hidden-ancestor AppArmor restrictions when the
reader cannot read its policy namespace depth; the administrator must establish root namespace visibility
externally. It does not override known nonzero/malformed depth, any label comparison, module discovery,
SELinux creation attributes or Smack refusal. Canonicalization includes true; compile warns and
`run_start.best_effort` lists `apparmor/assumed-root-namespace` whenever enabled, even when no open needed it.


### Built-in refusals — 2026-11-03, ADR 0113

Every enforcing contract first applies `builtin.host_ipc`, `builtin.tego_surface` and
`builtin.other_tty`. They precede `net.allow`, `host_sockets: true`, filesystem grants and empty deny
lists. The no-`net:` case keeps IP destinations allowed except local Tego control ports and the
existing model guard. Protected IPC sockets include the session runtime (SSH-only fixed exceptions
and the run's own runtime excepted), system D-Bus, X11 and listed multiplexer/editor directories.
Tego sockets and local configured serve.port/default 7433 plus legacy 8484 are refused. Numeric pty
slaves and consoles other than the inherited terminal and master-relayed own ptys are refused.
Only an exact explicit container-daemon socket allow removes that socket's default refusal, with
`container-socket-escape`. Both named and reached paths are checked, multiple-link sockets are
refused, and protected directory identities are pinned at Prepare. Protected directory mutations
cannot be enabled by a contract. See [ADR 0113](../../docs/adr/0113-built-in-refusals-for-tego-surfaces.md)
for the full fixed list and implementation note, including fail-closed abstract attribution,
`pidfd_getfd` imports, root-tier io_uring refusal, FIFO snapshots and datagram/copied-path residuals.

*Amended 2026-11-05 (release rollback, C55):* write declarations add no built-in scan/name scopes;
ADR 0043 D10 remains the contract directory and launch cwd. The rejected coverage extension and its
Landlock directory-move floor are reverted. Root-tier pip moves into an uncovered `target` remain an
explicit limit; OPERATIONS gives the tested staging/target declarations plus target-cwd arrangement.
Landlock future-name aliases, including declared held patterns moved out of scope, remain GAPS A11.
