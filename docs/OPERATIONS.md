# Operations

## Machine config
Normative: `spec/config/v0/README.md` (layers, ceilings vs settings, trust rules; an untrusted or invalid layer stops
`tego run` with exit 125 `[config-untrusted]`, which replaced 213). Example there.

## Agents by name: the registry (2026-10-20)
`tego compile retriever` and `tego run retriever -- <cmd>` find the contract of the agent named
`retriever` (docs/p0/agent-contract.md R26):

1. the working directory's `agent.yaml`, when its `name:` is `retriever` (what `tego init` writes), or its
   `.tego/agents/retriever.yaml`; then
2. the user registry, `~/.config/tego/agents/retriever.yaml` (the machine config's `registry:` moves it; `""`
   turns it off).

A path still works (`tego run ./agent.yaml`); any argument with a `/` or a `.` is a path. The project is the working
directory only, not its parents: run from the project's root. A name both registries hold (two files) is refused, never
answered by the project's file: an agent you run from your user registry may write the directory you run it in, and
would otherwise choose the contract of your next run. `tego compile <name>` prints which file and registry answered;
every run records the file in `run_start.contract_source`.
A refusal names its fix: `agent-not-found` (the files to create, the names there are), `agent-ambiguous` (both
registries hold the name, or the project holds it twice: give the path of the one you mean; or a file in the
working directory has the name: write `./<name>`), `registry-entry` (the
entry's `name:` differs, it is a link out of its `agents/` directory or no regular file, or it lies in `~/.tego`, the ledger
root or the profiles directory, which every run read-denies, and the working directory does not), `config-untrusted` (the entry, `agents/` or the
registry directory is writable by others or owned by another user: `chmod go-w`, common under a `umask` of 002; or
the entry has a second name, a hard link: remove it, or replace the entry with a copy).
No contract may write the user registry's `agents/` or `skills/`: a write entry over `~/.config` (or wherever
`registry:` points) is a `contradiction`, since it would let the agent rewrite what your later runs resolve by name.
`skills/` beside `agents/` is reserved for skills. Keep each contract in `agents/` itself (a relative link inside it
is fine; a link to elsewhere, even elsewhere in the registry, is refused), and copy rather than hard-link it.

**What no run may write (ADR 0059, 2026-10-20).** Whatever decides a later run's boundary is out of every write
entry's reach, by every name it is read by: the contract file (the file itself, not only its directory, and every
link on its path), each layer of the machine config (`/etc/tego/config.yaml`, `~/.tego/config.yaml`,
`$TEGO_CONFIG`), the price table, the profiles and the user registry. A write entry that reaches one, or the
directory of a link on the way to one, is a `contradiction`. And none of these files may have a second name (a hard
link), which no write entry is compared with: `config-untrusted`, unless the file is someone else's and not writable
by you or your group (a root-owned store). `find / -xdev -samefile <file>` lists a file's other names.
`$TEGO_CONFIG` must be an absolute path that does not pass through `/proc`: a relative one, or one like
`/proc/self/cwd/machine.yaml` that the kernel resolves against each process's own working directory, names another
file in every directory a run starts in, so `tego run` refuses it (`config-invalid`, exit 125) and `compile` and
`doctor` skip it with a warning. The same holds for the path settings (`ledger_root`, `prices`, `profiles`,
`registry`, `privileged_binary`). A script that exports `$TEGO_CONFIG` from a work directory it was given makes
that directory absolute first (`work="$(cd "$work" && pwd)"`). A run is kept
off the layers its own command loaded: a run started without `$TEGO_CONFIG` can write the file it names when a write
entry reaches it, so keep that file outside every directory a contract writes (ADR 0059's residual).

## The control binary, tego-control (ADR 0100, 2026-10-24)

The dashboard and the other control commands live in a second binary, `tego-control`, shipped and built with `tego` (`make build` writes
`bin/tego` and `bin/tego-control`). `tego serve` hands off to it, and `tego help` marks every command that does as
`(tego-control)`. Install the two side by side: tego looks for
`tego-control` in its own directory only, never on `PATH` or in the working directory. `scripts/install.sh` installs
both from a release (VERSIONING.md §5), and refuses a pair whose pin does not match.

- **What the handoff checks.** The file must be a regular file (not a link), owned by root or by you, not
  writable by its group or others, executable by you (the execute bit of your class: owner, group or others), and on
  a mount that allows exec, so `chmod a-x` or a `noexec` mount disables tego-control as it would any program; an
  ACL's named entries and a security module's exec rule on the file are not read. tego copies it into a sealed memfd, checks the copy's SHA-256 against the hash
  its own build pinned, and runs the copy, so changing or replacing the file afterwards changes nothing that runs.
  `tego version` prints that hash as `control_sha256`; `tego-control version` prints `sha256`, which must be the
  same, and the same version and commit.
- **Refusals** (one line on stderr, exit 125):

  | Code | Cause | Fix |
  |---|---|---|
  | `control-not-installed` | no `tego-control` beside `tego` | install the `tego-control` of the same release in tego's directory |
  | `control-unpinned` | a `tego` built without the hash (`go build ./cmd/tego`) | build with `make build`, or install a release |
  | `control-mismatch` | the file's hash is not the pin: another build or release, or a changed file | install the pair from one release or one `make build` |
  | `control-untrusted` | a symbolic link, not a regular file, another user's file, a group- or world-writable one, one you may not execute, or one on a `noexec` mount | `chmod go-w`; `chmod a+x` if it is meant to run; install on a mount that allows exec; or reinstall the file |
  | `control-as-root` | `tego <noun>` under sudo, or `tego-control` at euid 0 or with a capability | run it as yourself; `tego-control` never runs as root |
  | `memfd-noexec` | the kernel refuses an executable memfd: `vm.memfd_noexec=2`, or a security module's policy | `cat /proc/sys/vm/memfd_noexec` shows the setting as any user (`tego doctor` reads it only as root); as root, `sysctl vm.memfd_noexec=1` (or 0) |
  | `not-built` | `tego-control <noun>` for a service this build does not have yet (help names these on its "planned, not in this build" line, never as commands) | use `tego status`, `tego events`, `tego approve` and `tego deny` |

- **Process names.** A handed-off tego-control runs from a sealed memfd: `/proc/<pid>/exe` reads
  `/memfd:tego-control (deleted)`, and the process names itself `tego-control`.
- **Limits.** tego-control, and every process it starts, gets the soft open-file limit (`ulimit -Sn`) tego was
  started with; the raise Go makes inside tego does not carry over. A governed run's agent gets it too, at every tier.

## Privileged path (ADR 0042, 2026-10-05)
- **Tiers 2 and 3 need a root launcher.** That is `sudo tego run` on a host whose sudo users are its administrators,
  or (not built yet) a root unit or cron job that names the agent's account with `--run-as <user>`.
  Users who are not administrators run tier `landlock`; tegod, which would give them the root tiers, is built only
  on ADR 0042's trigger T1.
- **Granting sudo for tego is granting root**, as membership of the docker group is: the launcher runs as root over
  inputs the invoker controls (contract and profile files, the per-user config layer, the hidden helpers' argv). A
  sudoers entry limited to tego is not a boundary Tego supports, and a service account never gets one: an agent
  that escaped to that account would inherit root. The one exception (FEATURES I9) is a CI runner account that is
  already root-equivalent, on an ephemeral or dedicated runner VM.
- **Run the agent as a dedicated account with no sudo rights** once `--run-as` lands; until then `sudo tego run`
  drops the agent to the invoking user with that user's primary group alone, and with that user's `HOME`, `USER` and
  `LOGNAME` where sudo left root's (identity-config.md R3a).
- **Capability or setuid copies of tego are refused.** A launcher that gained privilege without being root (a
  `setcap` or setuid copy, a unit that grants it a privileged capability) exits 125
  `[privileged-path-unsupported]` for every command but `version`. A unit's incidental ambient capabilities
  (`AmbientCapabilities=CAP_NET_BIND_SERVICE` and the like) are cleared and the run continues at tier `landlock`,
  with one note.
- **`/run/tego` is root 0700.** A root launcher creates it so. A host that installed the old
  `packaging/tmpfiles.d/tego.conf` line (`d /run/tego 1770 root tego -`) must
  `chmod 0700 /run/tego && chgrp root /run/tego` and remove the line; until then root runs exit 125 with that fix.
- **Root units:** the agent runs in `tego.slice/.../run-<id>.scope`, not the unit's cgroup, so the unit's
  `MemoryMax=`, `CPUQuota=`, `TasksMax=`, `systemctl status` and `KillMode=` do not cover it; the contract's
  `limits:` do. `systemctl stop` reaches it through the launcher's SIGTERM forwarding, `stop_grace` and the reaper.
- **The ledger is tamper-evident against the agent, not against the launching user**: the chain anchor sits in the
  user's own `~/.tego/chain.log` (GAPS C9). A record the user cannot rewrite is ADR 0042's trigger T3.
- `users:` is honoured from `/etc/tego/config.yaml` only and read by nothing in this release; `privileged_binary`
  stays parsed and warns that it is not used.

## Watching any command, and answering what it asks (2026-10-06)

`tego watch -- <command> [args]` runs any command, an agent included, as a black box. Tego never needs to know what
the command is. With no contract it only records (observe mode) and no rule refuses anything: every program it
starts, every file it opens (reads included under `record: full`, the default here; `--record summary` leaves reads
out and `--record off` keeps only the run's start and end), every connection it makes, to the same hash-chained
ledger as any run. The fixed syscall guards of a tier-1 run still apply, and are not recorded: 32-bit programs cannot
run; `io_uring`, `openat2`, `clone3` and `open_by_handle_at` answer "not implemented" (programs fall back); the
terminal-input ioctls `TIOCSTI` and `TIOCLINUX` and MPTCP sockets are refused. Truncate, chmod, chown, setxattr and a
unix socket bound to a path are not recorded either.
`tego status|events|drift <run>` read it, and the command prints the run id when it ends. The program's own flags
come after the `--`, untouched, and its exit code is yours.

A recording is not a cage. Observe mode has no rule that refuses, and a process can still ask another service on the
machine (`systemd --user`, D-Bus, an SSH or GPG agent) to act for it outside the run; `compile` names the sockets in its
warnings, which `watch` prints. To confine the command, write a contract (files, programs, connections, limits, `ask`
scopes) and run `tego watch --boundary agent.yaml -- <command>`, which is `tego run agent.yaml -- <command>`
with the command given on the line. An interactive program works: its terminal, window size and Ctrl-C are the
agent's, as for `run`.

A full-screen agent (Codex, Claude Code) that is killed or crashes leaves nothing behind to undo its terminal modes,
and the shell does not repair them either, because its job, tego, exits normally with 128+n. So when the agent's
stdin, stdout or stderr is a terminal, `run` saves the terminal's modes (termios) before the agent starts and puts them
back once the agent's processes are gone, if they changed. When the agent died by a signal (its own crash, a limit,
the stop_grace kill after Ctrl-C, SIGTERM, SIGHUP or `tego stop`) or left the terminal in raw mode, it also writes a
short reset to that terminal, never to a pipe or a file: leave the alternate screen, show the cursor, turn the mouse,
bracketed paste and focus reports off, and pop kitty keyboard flags. A tego running in the background, or whose
terminal hung up, leaves it alone. A tego that is itself SIGKILLed repairs nothing: the shell then restores the modes
it saved, not the screen; `reset` or `stty sane` fixes what is left.

Ctrl-Z works as it does without tego. A full-screen agent reads Ctrl-Z as a key and stops only itself (Claude
Code does); tego, the shell's job, then stops too: it puts back the terminal modes it saved, stops with the same
signal, and the shell prints `Stopped` and gives you the prompt. `fg` gives the terminal back to the agent with its
modes and resumes it; `bg` (or `kill -CONT`) resumes it in the background without touching the terminal. A tego that
is not in the terminal's foreground, or whose agent has no terminal, does not follow the stop. A tier-2 run (`--tier
cgroup`) never stops, because its listener answers for the whole machine: the agent stays stopped, Ctrl-C there ends
it after `stop_grace`, and `kill -CONT` on the agent resumes it. While a run is stopped its `wall` and `stall_after`
clocks keep counting.

`nohup tego run ...` keeps the run through a hangup: tego leaves a `SIGHUP` that it started with ignored ignored,
for itself and the agent, as nohup intends. Without nohup, a hangup starts `stop_grace` as SIGTERM does.

A boundary's `fs.ask` and `net.ask` scopes hold the operation (the agent waits) until a person answers from a second
terminal: `tego ask <run>` lists what is held, `tego approve <run> <ask_id>` and `tego deny <run> <ask_id>` answer
it. That terminal is the person's own, as the run's user (or root, for a run launched with sudo): the run refuses an
answer from inside any run or adoption, a shell under `tego watch` included, and from another cgroup namespace (a
container's), and the request stays held. A record-only `tego watch` agent is not a cage, though: it can first move
itself out of its scope, into a cgroup of its own under the person's user service or through `systemd --user`, and
then answer as the person's own software would. `tego watch --boundary` closes both ways. A model request's target is listed as the ledger records it, its path cut
to a public route and its query to `?redacted`. The run id may be left out: `tego ask` alone lists the pending asks of every running run under the ledger root,
one line each led by its run id, and `tego approve <ask_id>`, `tego deny <ask_id>` and `tego alternate <ask_id>
--file <path>` find the running run that holds that id (each run's broker is reached exactly as with the run id
given, its peer check included). A running run that serves no ask socket (no ask rule in its contract, or a
watched run) holds no asks: `tego ask` passes over it, `tego ask <run>` says why (`<run> is a watch run, and a
watch run takes no approvals`, or `<run> takes no approvals: its contract has no ask rule`, exit 0), and an answer
named to it says the same, `[not-found]`, exit 1. An answer to a run that has ended says `<run> has ended; nothing
waits for an answer` `[not-running]`, exit 1. `tego ask <run> <ask_id>` for a request that no longer waits (answered,
timed out, or its run ended) prints what the ledger recorded, `<ask_id>: no longer waits: denied by uid:1000 pid:… after
77 ms, line #18` (`--json`: the record), exit 0. A lone argument that is neither kind says `is neither a run id (r-…)
nor an ask id (q-…)` `[usage]`, exit 2. Add `--always` and the answer also stands for the rest of the run, for the same operation, contract rule and exact
target and no other; every later request it answers is its own `ask` and `answer` pair in the ledger, `by:
standing:<ask_id>`, so nothing is granted or refused unrecorded. A file's key is its path, not how it is opened: an
approved append also covers a later truncate or create of that path. A scored gate request and a `first_write` or
`request` hold are answered once and never remembered. Nobody answering is never a yes: after `ask.timeout` (at most
1 hour, 5 minutes by default) the operation is refused and recorded `ask-timeout`, so an unattended run holds an agent
at an ask for at most that long. For a long unattended run, put the decisions in the contract (what it may do, what it
may never do) and keep `ask` for the few that need a person, answering `tego approve --always` or `tego deny --always`
when you see them so that a retrying agent is not held again. When nobody may be there to answer, `ask.on_timeout:
refuse_always` does the second for you: an ask that times out also refuses the same operation, rule and target at once
for the rest of the run (`by: standing:<ask_id>` of the timed-out ask, reason `ask-timeout`), so an agent that retries
is held once, not once per try (the default, `refuse`, holds every retry for the whole timeout). It is a refusal no
person can lift during the run, and `tego compile` prints it on the `ask` line. A run keeps at most 256 such refusals,
apart from the 256 standing answers people give, so an agent asking about many paths nobody answers never uses up your
`--always`; past 256 a timeout refuses once again.

*Knowing that an ask waits (ADR 0122, 2026-10-26).* A run whose contract can ask prints one line before the agent
starts: `tego run: <run> can hold an operation for your approval; answer from another terminal: tego ask <run>, then
tego approve <run> <ask_id> (or deny), or on the dashboard's Approvals page`. In an interactive session, that line is
the run id to answer with; it stays above the agent's screen once the agent leaves it. At tier `landlock`, when tego
is not root and a root-owned `notify-send` is on its PATH (libnotify; `apt install libnotify-bin`), tego also shows a
desktop notice for each held request, naming the agent, the operation and the run, never the target. tego writes
nothing into the terminal while the agent runs: a full-screen agent owns it, and a byte between two of its writes can
corrupt its screen. Over SSH, at the root tiers, or with no notifier, use the answer line, `tego ask`, or the
dashboard's Approvals page. The machine config's `ask.notify` sets both: `[cli, desktop]` by default, `[cli]` for the
line only, `[]` for neither. `tego ask <run> --json` marks a rule it cut at 64 bytes with `rule_truncated: true`
(a target cut at 128 bytes has `target_truncated`); `tego ask <run> <ask_id> --json` returns both whole.

`limits.stall_after` counts what the run sees. At tier `landlock` under `record: summary` or `off` that is not a read;
what the supervisor answers (an exec, a connect, a send, every write-open and path change), a process's exit and a
refusal are. A read gate (`fs.read matches`), an `fs.ask_read` entry or `reason.reads: on` (tier `landlock`) has
every read-open answered by the supervisor, so under `off` a read is activity then, and under `summary` a read gate
gives each read a line. Otherwise an agent
that does nothing but read for `stall_after` (a long scan of a repository, say) is ended as stalled, and
`tego compile` and `tego run` warn `[stall-reads-unseen]` (a `tego run --observe` too, and `tego run --record`
is what the warning reads, not the contract's `record:`). Choose `record: full`, which records every read (and costs
the disk that saves), a root tier (not an `--observe` run, which uses tier `landlock`'s filter whatever tier you pin),
or a `stall_after` longer than the agent's longest stretch of reading. At a root tier under `record: off` each allowed
open, path change and connect of a run with a `stall_after` stamps a per-run kernel timestamp the stall check reads
every second, so an agent that only reads or writes files is busy there, not stalled, and nothing is warned; under
`record: summary` a root tier counts reads in aggregates flushed every 5 s, so a read can reach the stall check up to
5 s late (keep `stall_after` at 10 s or more there, which compile also warns of). Under `tego run --tier landlock`
the warning offers a root tier only without that flag, which refuses a contract that pins another tier.

*Interactive Claude Code under a boundary, offline (2026-10-06, Claude Code 2.1.290, tier `landlock`).* Four things a contract for the full-screen
Claude Code has to know. (1) With a dummy `ANTHROPIC_API_KEY` and an empty `CLAUDE_CONFIG_DIR` its first act is a
connectivity check that goes straight to `api.anthropic.com:443` and ignores `ANTHROPIC_BASE_URL`; refused, it exits 1
("Unable to connect to Anthropic services"), and a key does not skip it. `{"hasCompletedOnboarding": true}` in
`CLAUDE_CONFIG_DIR/.claude.json` skips it, and then no Anthropic address is tried. (2) The default `net.dns.mode: system`
lets the agent reach the machine's resolver, so a name lookup (api.anthropic.com included) can leave the box even when
every connection is refused; `net.dns.mode: off` closes it, and the forwarder's loopback address needs no name
(at tier landlock from 2026-10-16 for a lookup sent from an unconnected socket too, which was recorded refused and
still sent). (3) It
reads the passwd-database home's `~/.claude/skills` whatever `HOME` says: `fs.deny_read` the real home's agent config
(106 refused reads in one session, none allowed). (4) Its `Write` tool writes a temporary file and renames it, and the
approval of an `fs.ask` write covers the open only: the rename is refused (`rename-outside-contract`; SEMANTICS §3,
"other modifications inside an `fs.ask` directory are refused, not asked") and the temporary file stays. A standing
`approve --always` is keyed on the exact path, and that temporary name is new every time, so `--always` can never match
it. Writes made in place (a shell redirect) are held, answered and remembered as documented. Whether an `fs.ask`
directory should let an approved file be renamed inside it is a scope decision; nothing was changed here.

*A harness's home login is not readable under tego (2026-10-25, [ADR 0067](adr/0067-agent-token-stores-and-credential-rows.md)).*
The built-in `deny_read` list holds the agents' own token stores (`~/.claude/.credentials.json`, `~/.claude.json`,
`~/.codex/auth.json`, the Gemini CLI's and the Copilot CLI's login files) and the stores of the tools agents run beside
(docs/spec/builtin-deny-read.md lists every row and the vendor document that names it). The run's own harness is not
excepted, so give it a credential through its environment and its state in the project: for Claude Code, pass
`ANTHROPIC_API_KEY`, or with a Pro, Max, Team or Enterprise subscription run `claude setup-token` once and pass the
token it prints as `CLAUDE_CODE_OAUTH_TOKEN`, and set `CLAUDE_CONFIG_DIR` to a project directory
(`examples/agents/claude-code.yaml`); a plain `claude` under tego otherwise starts as not logged in. For `codex exec`,
pass `CODEX_API_KEY`. `tego compile` warns `secret-env` when a contract with no `env.pass` hands the agent variables
whose names look like credentials; add `env.pass` to choose what passes. A contract that wrote the harness's home
state directly no longer works as it did: `fs.write: ["~/.claude.json"]` is now the error `contradiction`, and
`fs.write: ["~/.claude/"]` leaves the login file to the held reads at tier landlock (ADR 0069), with a warning, and a
copy the agent moves elsewhere is readable. Move the state into the
project with `CLAUDE_CONFIG_DIR` (Codex: the launcher's `CODEX_HOME`) instead. A file created during the run directly
in `~`, `~/.claude`, `~/.config`, `~/.local/share` or another directory a built-in row would appear in is unreadable to
the agent until the next run.

*The long tail of credential stores is not readable either (2026-11-02).* The built-in list also holds the desktop
keyrings (`~/.local/share/keyrings`, `~/.local/share/kwalletd`), MySQL's `~/.my.cnf` and `~/.mylogin.cnf`, the s3cmd,
boto and rclone configuration files, the RubyGems and Composer credential files, the key to Maven's encrypted passwords
(`~/.m2/settings-security.xml`), and the doctl, hub, glab, flyctl, Supabase and OCI CLI logins
(docs/spec/builtin-deny-read.md cites each). A tool whose store is refused takes its credential from a variable the
contract passes (`GEM_HOST_API_KEY`, `COMPOSER_AUTH`, `SUPABASE_ACCESS_TOKEN`). Composer, flyctl and doctl stop when their
store exists and cannot be read, whatever their variable says, so for a run that uses one point it at the project:
`COMPOSER_HOME`, `FLY_CONFIG_DIR` with `FLY_API_TOKEN`, or doctl's `--config` with `DIGITALOCEAN_ACCESS_TOKEN`. `~/.m2/settings.xml` and `~/.gradle/gradle.properties` stay readable, since every Maven and Gradle build reads
them: keep repository passwords in variables, not in those files.

*A unix socket under a write entry that the run did not bind is refused (2026-10-16, supervisor R11a).* The agent
reaches the sockets it binds itself under an `fs.write` path with no `unix:` entry (`multiprocessing`, Ray, a local
MCP server it starts). A socket there that existed before the run, or that another program made, is refused with
`EACCES` and a ledger line `rule: unix-foreign`: Codex's interface, for one, connects to a background app-server's
control socket in its `CODEX_HOME`, and a server an earlier, ungoverned session left running runs its commands
outside the run. Start the agent so that it serves itself (Codex: `--no-daemon`), or declare the socket with
`net.allow: ["unix:<path>"]` to reach it on purpose, knowing what the program behind it can do. A line `rule:
unix-origin-unread` means tego cannot tell whose socket it is and refuses: the kernel's socket diagnostics for
`AF_UNIX` (`CONFIG_UNIX_DIAG`, the `unix_diag` module) are missing (`tego doctor` says so on its unix sockets row,
and the run warns at start), the socket's file has an inode number wider than 32 bits (XFS `inode64` on a large
filesystem, tmpfs mounted `inode64`), or the run holds more than 256 unix sockets on which it called `bind` without
the bind taking (tego asks the kernel about at most that many per syscall). On btrfs or overlayfs, where two
subvolumes can number two files alike, it also means that a socket outside the run is bound to a file with the same
inode number as the run's own socket (tego cannot tell the two files apart while that socket lives), that the
filesystem reports no birth time for the file, or that the file was born during the run but not while the run was
binding that socket (more than ten seconds after the bind); a `unix:` entry declares such a socket. A connect to
such a socket also reads `unix-origin-unread` when the network namespace holds more unix sockets than one pass of the
kernel's socket list holds: about 600 that are not connected, for a stream or seqpacket connect, or every unix socket
of the namespace, connected ones included, for a datagram socket's `connect` (`ss -xa | wc -l` counts them), and
when the run's own socket there cannot take the connect, which the kernel would refuse anyway: a stream or seqpacket
`connect` to the run's datagram socket that another socket connected to, or to the run's connected stream socket. Bind
such a socket where the inode number alone tells files apart (tmpfs, ext4, xfs; `$XDG_RUNTIME_DIR` is tmpfs on
systemd hosts), or declare it. A line `rule: unix-bind-unrecorded` means a bind of the run could not be
recorded, so tego cannot say the socket is foreign either: at tier `landlock` a non-dumpable process, such as
`ssh-agent` (it makes itself non-dumpable at start), cannot be read by the unprivileged supervisor, so the socket it
binds is never the run's as far as tego knows. Under a `net:` section it cannot serve from inside the run at that
tier at all (*since 2026-11-01*): its `listen()` is refused `rule: fd-unreadable` and it exits with `unix_listener:
Permission denied` (GAPS C44). Start it outside the run and declare its socket (`net.allow: ["unix:<path>"]`), or run
at a root tier. A datagram to a
name that names nothing fails `ENOENT`, `rule: unix-absent`. A line `rule: unix-ask-scope` (*since 2026-10-19*) is a
`net.ask` `unix:` scope's place reached with no person asked: a datagram addressed there (nobody is asked about a
datagram), or a connect whose name the agent repointed at the scope between tego's two looks at it. A connect is
asked when its name reaches the scope's place — by the scope's path, a relative name, a symlink, a symlinked
directory — whoever bound the socket there; under any other name (a hard link, the name a socket was renamed to) it
is decided there, so the run's own socket is allowed by the write entry and one bound outside the run is refused
`unix-foreign`: connect through the scope's place to be asked, or declare the other name with a `unix:` entry. A
scope spelled through a symlink, also one whose target directory the run makes later, is the place the symlink
leads to. *Since 2026-10-16* a unix name is decided on the socket
it reaches, not on how it is spelled: a datagram or a connect whose name leads through a symlink or a `..` to a
socket outside every entry is refused `rule: unmatched` with `EACCES`, even at a name a `unix:` entry declares, and
one through `/proc/self`, `/proc/thread-self` or `/dev/fd` is refused `rule: path-unreliable` (tego does not
resolve those links as the agent would): name the socket by its own path. *Since 2026-10-17* the name a socket was
bound by decides nothing: a socket of the run's bound through such a link, by a relative name, or by an address a
thread rewrote is still the run's, on btrfs too (it used to read `unix-bind-unrecorded` or `unix-origin-unread`). What stays open: a datagram's name is looked up again
by the kernel when it is sent, so a process of the run that renames a file or swaps a symlink onto that name in
between reaches the socket it then names, and the line reads `allow` with `best_effort: true`; at tier `bpflsm`
under `io_uring: true`, `io_uring` connects and sends to a unix name under a write entry are not decided by tego,
and a socket bound through `io_uring` is refused `unix-foreign` (supervisor R11a).

*Interactive Codex under a boundary, offline (2026-10-06, codex-cli 0.159.2, tier `landlock`; `test/poc/interactive-codex/run.sh`
reproduces it in about six minutes, 80 checks).* The real full-screen Codex ran a whole session with no root and no network, its model a
local stand-in (test/workloads/model-stub/openai_responses.py, a scripted OpenAI Responses API) and no credential but
an obvious dummy key: a command in the workspace, a read of a decoy secret refused by `fs.deny_read` (and shown never
to reach the model), `git push` refused by `exec.allow`, a connection refused by `net.allow`, a write by Codex's own
`apply_patch` tool held until a second process ran `tego approve`, an append answered by `approve --always` and then
at once from the standing answer, a write answered by `deny --always`; all 14 model requests recorded as `ssl_request
source=forwarder`, and no address but the forwarder's loopback listener allowed. Nine things a contract and Codex's
`config.toml` have to say, which Claude Code's do not:

1. **Codex's own sandbox is off, because Tego is the cage.** Its bubblewrap sandbox cannot start inside the Landlock
   domain: left on, every command the model asks for fails with `error building bubblewrap command: Permission denied
   (os error 13)`, exit 1, and never reaches the shell; Codex does not exit, it gives the model the error. Use
   `sandbox_mode = "danger-full-access"` and `approval_policy = "never"` in `config.toml`, or
   `--dangerously-bypass-approvals-and-sandbox`, or `-s danger-full-access -a never` (`codex exec` takes `-s` but
   refuses `-a`). Codex then asks nobody; the contract's `ask` is the approval. Its `apply_patch` tool writes in
   place, so an approved `fs.ask` open is all it needs (Claude Code's `Write` renames a temporary file, which `fs.ask`
   refuses).
2. **Run `codex --no-daemon`.** The interface starts a shared background server (`codex app-server --managed-daemon`,
   a control socket under `CODEX_HOME/app-server-control/`) and is its client, so the commands it runs are the
   server's. Under a contract its first step (`sh`) is refused and Codex exits 1 saying "rerun the same command with
   --no-daemon". `features.daemon_auto_start = false` alone only stops it from starting a server: with a stored login
   it still connects to the control socket of one that is already running, and Tego allowed that connect when this
   ran, because a socket under a write entry was taken as the run's own; since 2026-10-16 such a socket is refused
   `unix-foreign` unless a process of the run bound it (supervisor R11a, the paragraph above). A server already running
   is not under Tego; `--no-daemon` makes no such connect.
3. **Switch off what leaves the box on its own:** `check_for_update_on_startup = false`, `[analytics] enabled =
   false`, `[feedback] enabled = false`, `[features] plugins = false`, `remote_plugin = false`, `apps = false`,
   `shell_snapshot = false`. With Codex's defaults and the resolver reachable, its start connects straight to
   chatgpt.com, a GitHub address and raw.githubusercontent.com (its announcement file), runs `git ls-remote` on
   github.com/openai/plugins, probes `bwrap`, starts `lsb_release -a` and `getconf LONG_BIT` in every `PATH`
   directory, and tries the D-Bus session bus; every one of them, refused, is tolerated and Codex reaches its prompt.
   With the switches the only direct connection left is the announcement fetch (no switch stops it), and
   `net.dns.mode: off` kept it from getting an address.
4. **The model goes through the forwarder by a `CODEX_HOME` of the run's own.** Codex ignores `OPENAI_BASE_URL`; with
   a `models` entry of provider `openai` and `capture: forwarder` the launcher writes `$XDG_RUNTIME_DIR/tego/<run
   id>/codex/config.toml` with `openai_base_url` for the listener, then the `config.toml` that the contract's
   `CODEX_HOME` names, and gives Codex that directory (capture-derive.md R19b). Three consequences: the run grants
   Codex write on that one directory itself (`fs.codex_home[<path>]`, listed in `run_start.runtime_grants`), so the
   contract names no entry for it, and `compile` and the launcher refuse an entry over or inside
   `$XDG_RUNTIME_DIR/tego` (`contradiction`), which would reach the private directory of every other run of the same
   user (agent-contract.md R10a; until 2026-10-16 a contract had to grant that parent); the user's `auth.json` is
   hidden, so the interactive interface shows its login screen on every run (choose "Provide your own API key"; Codex
   stores it in the run's `CODEX_HOME`, which the run removes at its end, or, when its launcher was killed first, the
   next run you launch under the same `XDG_RUNTIME_DIR` does (`rm -r $XDG_RUNTIME_DIR/tego/<run id>` by hand), and
   reads no key from the environment); and with no `XDG_RUNTIME_DIR` in Tego's own environment an unprivileged
   launcher refuses the run, exit 125, naming the
   fix (log in through a session that sets it, export it as an absolute directory only you can write, or drop the
   `openai` model entry). A root launcher makes no `CODEX_HOME`, runs Codex unrouted and records `gap what=capture
   why=codex-unrouted`; the `models` guard refuses Codex's own calls to the model.
   **That directory is closed to other users and to the writes of every enforcing run, not to other runs' reads.** No
   enforcing run can write it but its own, and no contract may grant it (above), but while the run lasts (and after
   a killed launcher, until the next launch removes it) an agent of any other governed run of the same user can read
   it, `auth.json` with the key you typed and Codex's `sessions/` included: nothing denies reads of `$XDG_RUNTIME_DIR/tego` by default (agent-contract.md R10a, an open condition).
   A `tego run --observe` run enforces no file-system rule, so its agent can read *and write* it, `config.toml`,
   `auth.json` and the last-refusal mirror included, and so can any process of yours outside Tego, as with any of
   your files. Until it is closed, while a real key is typed run no other agent of yours, under Tego (observe runs
   included) or outside it, or give each other contract you run meanwhile, enforcing, an `fs.deny_read` entry for
   that directory, `/run/user/<uid>/tego/` (it exists once any unprivileged run of yours has started; such a run
   cannot read its own last refusal there, `TEGO_REASON`, either).
   The other way Codex can be pointed at a local endpoint, a custom provider (`model_provider`,
   `[model_providers.<id>]` with `base_url`, `wire_api = "responses"`, `env_key`), also works through the forwarder:
   pin `forwarder: listen: 127.0.0.1:<port>` in the machine config and put that port in `base_url`; the key is then
   read from the environment, there is no login screen, and `supports_websockets = false` spares Codex's WebSocket
   offers. Two concurrent runs cannot share the pinned port.
5. **Do not list `/proc/self/exe` in `exec.allow`, and do not deny `~/.codex` as a whole.** Codex starts itself as
   `/proc/self/exe --codex-run-as-process-setup` before every command, and `apply_patch` as a shell command is a
   symlink to it: the `command` entry covers both. When this ran, a `/proc/self/exe` entry compiled to Tego's own
   executable (a contract with only that entry let the agent run `tego`), and `tego learn` proposed it; since
   2026-10-16 `compile` refuses an entry that is or leads through a `/proc` path (`exec-proc`, agent-contract.md
   R8a), and `tego learn` lists it as observed, not allowed (the learn section below). Codex's installation is
   `~/.codex/packages`, next to `auth.json`, its history and its sessions, so `fs.deny_read` names the files that
   exist, not the directory.
6. **`net.dns.mode: off` was a record, not a block, for some lookups at tier `landlock` when this ran.** A lookup sent
   from a connected datagram socket is refused (the `connect` fails). A lookup sent with an address from an
   unconnected socket was written to the ledger as refused (`best_effort: true`) and then let through; since
   2026-10-16 it is refused with `EACCES` before it leaves, and a refused line never carries `best_effort` (supervisor
   R13b). In the captured run Codex's start-up lookups were refused outright; its WebSocket
   client's were sent and answered, and the TCP connect to the answer is what was refused. A contract that reaches its
   model through the forwarder needs no lookup from the agent.
7. **A login shell adds one refused line to every command**: `/etc/profile: line 21: /usr/bin/run-parts: Permission
   denied`. Harmless.
8. **A ChatGPT login is not covered by these contracts**: "Sign in with ChatGPT" starts a login server on a local port
   (refused: `failed to start login server: Permission denied`) and "Sign in with Device Code" asks auth.openai.com
   (refused). A real API key through the forwarder, or `CODEX_API_KEY` for `codex exec`, is the way;
   examples/agents/codex.yaml is the contract for one through the forwarder (compiled and its rule table tested in
   the repository, never run against the real service; its `fs.write` names `./work/`, not `./`, because a write
   grant that covers `held/` decides before the `fs.ask` for it does), and test/poc/interactive-codex/codex-real-forwarder.yaml and
   codex-real-direct.yaml are two more, compiled and not run, and wider: no `fs.ask` (no `held/` gate), a write
   grant of `./`, and `git`, `ls` and `mkdir` allowed.
9. **`tego learn` over a record-only run** of the same session proposed a contract that holds what Codex did and
   flagged the D-Bus session bus as observed, not allowed. When this ran, two kinds of entry in it needed review by
   hand: `/proc/self/exe` (item 5) and two programs that do not exist (`/usr/sbin/cat`, `/usr/sbin/lsb_release`, which
   a failed search of `PATH` left), so it did not compile as proposed. Since 2026-10-16 learn lists both kinds as
   observed, not allowed, and proposes only programs on the machine (the learn section below).

Under `capture: forwarder` the ledger holds each request as its size, headers on an allow-list and digests of its body
and messages, each response in full (the streamed events), and the credential nowhere.

## Holding a read for a person, and answering with another file (2026-10-06)

`fs.ask_read` lists files or directories whose reads wait for a person instead of being refused, at tier `landlock`:

```yaml
tier: landlock            # required: no other tier holds a read
fs:
  write: ["./out/"]
  ask_read: ["~/.aws/credentials", "/srv/secrets/"]
ask:
  timeout: 10m            # nobody answering refuses the read after this (at most 1h)
```

When the agent opens a file under one of them for reading, its thread waits, and `tego ask <run>` lists the read:
`q-... open read /home/me/.aws/credentials`. Answer it from a second terminal:

```sh
tego approve <run> <ask_id>                      # the agent reads the real file (read-only)
tego deny <run> <ask_id>                         # the read is refused (ask-denied)
tego alternate <run> <ask_id> --file fake.txt    # the agent reads fake.txt in its place
```

Add `--always` to any of the three and the answer also stands for the rest of the run, for a read of the same file
under the same entry, and for nothing else: every later one is answered at once and recorded as its own ask and
answer, `by: standing:<ask_id>`. An alternate given `--always` is the same file each time (tego keeps it open for
the run), checked anew each time.
Nobody answering is never a yes: after `ask.timeout` the read is refused (`ask-timeout`).

`tego alternate` also answers a held `fs.ask` write: the agent then writes into the named file instead of the one
it asked to write (with its own flags: an append appends to it, a truncating open truncates it). Use it to give the
agent a fake credentials file, or to collect a write you want to review before it reaches the real file.

What an alternate may be: an existing regular file, named by an absolute path or a path relative to where you run the
command, with no symbolic link anywhere in the path (name the file by its real path: `tego alternate` refuses a link
and says where it leads), with one link, not on `/proc`, `/sys` or another kernel filesystem, not named `.env` or
`.env.<anything>` but the example files, and outside tego's own state (`~/.tego`, the ledger root, `/run/tego`,
`$XDG_RUNTIME_DIR/tego`, the price table and profiles; for a write also the user registry's `agents/` and
`skills/`, which a run may read), the contract file's directory (a file beneath a write entry
there, such as `./out/fake.txt`, is fine) and every path the contract protects (`deny_read` and `fs.ask_read`, a file a
`deny_read` glob or the built-in credential list names even if it was created after the run started, and for a
write the built-in `deny_write` targets), and never a file the contract's `gate` refuses (a score above its `ask`
threshold for the agent's own open of that file, a read gate for a held read, a write gate for a held write, and both for an `O_RDWR` one: a gate
refusal protects a path as `deny_read` does, and no answer lifts it). A file for a held write must also lie beneath a write entry or an `fs.ask`
scope, and is never a git hook or git config, harness or editor settings (`.claude`, `.mcp.json`, `.cursor`,
`.codex`, `.gemini`, `.vscode`), a shell startup file (`.bashrc`, `.zshrc`, ...) or `.gitconfig`, wherever it lies: a
stand-in for a write is one the contract already lets the agent write, or be asked to write. The file
given is the one `tego alternate` opened when you ran it: it passes the open file to the run, so renaming or
replacing the path afterwards changes nothing about what the agent gets. It is reopened with the agent's own
credentials, so it can never give the agent a file the agent's user could not open. Tego checks it when you answer,
and a refused one leaves the read pending with the reason, so you can name another file, approve or deny; it checks
again when it delivers it, and if the file was moved into a protected place or removed meanwhile the read is refused
(`ask-unavailable`). Create the stand-in before you answer.

What is held: a read-open of a regular file the listed entry decides. A `deny_read` or a write entry nested inside an
`fs.ask_read` entry decides beneath itself, as nearest-wins says. Listing a directory, an `O_PATH` open and an open for
writing are not held (an `O_RDWR` open of a listed file is refused as a write outside the contract). A file in tego's
own state is refused, never asked.

What `compile` refuses (the run does not start): `fs.ask_read` at tier `cgroup` or `bpflsm`, or with `tier: auto` on a
machine whose highest tier is one of them (pin `tier: landlock`); an entry that is, or lies beneath, a `deny_read`
you declared (an ask never lifts a deny); an entry inside tego's own state; an entry inside a write entry or an
`exec.allow` directory, or holding a program `exec.allow` grants (Landlock could not keep that read from happening
without a hold); an `fs.ask` scope inside an `fs.ask_read` entry; a glob, a missing path and `/`. (An `fs.ask`
scope inside a write entry is only warned: the write entry already allows those writes, so it never asks.) An entry at, or
beneath, a path of the built-in credential list (`~/.aws`, `~/.ssh`, ...) is honoured when the contract file itself
declares it, with a warning that names the built-in entry it relaxes (the read is now held instead of refused), and
every run's `run_start` line lists it under `ask_read_relaxes`, so the record says the default was relaxed; the same
entry from a profile is refused.

Cost: to find the reads it holds, tier 1 is told of every open the agent makes, as under `record: full`. Under
`record: summary` and `off` the ledger still keeps no line for a read that is neither held nor refused.

The record: the ask line names the file the agent asked for (`op: read`); an approval's answer says `approved: true`;
an alternate's answer says `approved: false` (what the agent asked for was not granted) with `alternate: <the file
given>`, its `alternate_dev` and `alternate_ino`, and `by` naming you; the open the answer completed is an `fs` line
with `authority: human`, naming the file delivered, with `alternate_for: <the requested file>` for an alternate. Read
them with `tego events <run>`, which writes such an answer as `alternate <file> (not the file asked for) by uid:...`.
`tego measure` counts them as `alternates`, `tego drift` in the rule's `ALTERNATE` column (never as an allow of the
rule), and `tego learn` proposes nothing from them.

Verified 2026-10-06 on the test machine (Linux 6.17, Landlock ABI 7, unprivileged): `internal/runtime`'s
`TestIntegrationAskRead*` and `TestIntegrationAskWriteAlternateWritesIntoTheStandIn` run the real binary on a real
contract and answer from separate `tego` processes (alternate, approve, deny, timeout, and approve, deny and alternate
with `--always`; `tego run --observe` of such a contract is refused, exit 125). The same five tests pass as root in a
KVM guest on the test machine's kernel (`test/vm/root-suites.sh`, the agent dropped to the invoking user).

## Learning a first contract from a run (`tego learn`, 2026-10-06)

`tego learn <run> [--out <file>] [--workspace <dir>]` (FEATURES C9, E65) reads a finished run's ledger, an observe-only
`tego watch -- <agent>` run for instance, and prints a boundary contract PROPOSED from what the run did: it allows that
and no more. It is deterministic over the record and calls no model. It only ever proposes: you read it, you edit it,
`tego compile` it, and only then run the agent under it (`tego watch --boundary <file> -- <agent>`). Without `--out`
the proposal is printed; `--out <file>` writes a new file, mode 0600, and refuses to replace one (exit 1 `[exists]`).
Keep the file outside the agent's workspace: tego refuses a contract the agent could rewrite, and `learn` warns when
`--out` is inside one of the proposal's own `fs.write` entries.

What it proposes, and what it never does:
- `command` is the run's. `fs.write` is the directories under the **workspace** (the run's working directory, or
  `--workspace`) that the run wrote to, merged to the outermost, never a broader one and never tego's own state
  (the run's record, the ledger root, `~/.tego`, `/run/tego`); plus `/dev/null` and `/dev/tty` when the run opened
  them. A write outside the workspace is not allowed, only listed, which is usually the agent's own config or cache
  directory: point that inside the workspace and learn again, or give `--workspace` a directory that holds both.
- `exec.allow` is the distinct programs the run started, as absolute paths, except the agent's own first program. The
  record keeps no line for a directory a PATH search tried that holds no such name (`run_end`'s
  `supervisor.exec_missing` counts them), except at tiers cgroup and bpflsm for a directory whose search permission
  the supervisor cannot read for the agent (on NFS, FUSE, ZFS or another filesystem outside supervisor R16b's closed
  list, or behind an access ACL), whose misses keep their lines; of the rest, only the one that ran is listed: the
  attempt whose path is a program on this machine (a regular file with an execute bit, links followed, as `tego compile` checks a path
  entry), not the last one recorded, since a record taken before 2026-10-16 could hold a search's attempts out of order
  (`/usr/sbin/bash` after the `/usr/bin/bash` that ran) and has a line for each miss. A program that is not on this
  machine when you learn (a search's miss in such a record, a file the run removed) and a `/proc` path
  (`/proc/self/exe`, which `tego compile` refuses, `exec-proc`; a program that re-executes itself that way is admitted
  by its own entry) are listed, not allowed, so the proposal compiles. A program that makes a mount namespace (`bwrap`,
  `unshare`, `podman`, `runc`, `crun`, `buildah`) is listed, not allowed: it fails inside a Landlock domain, and an
  agent's own sandbox probes it at start-up. *Amended 2026-10-16.*
- `net.allow` is the TCP and UDP endpoints connected to. The ledger holds the address a program connected to, never the
  host name it asked for, so the entries are addresses, a service's addresses change, and the file says how to allow
  it by name instead (`tcp://api.example.com:443`, which tego resolves when the run starts). DNS to the machine's
  resolver needs no entry. A UDP connect to port 65535 is a route probe (musl's `getaddrinfo` connects a UDP socket to
  port 65535 of each address a lookup returns, to choose among them, and sends nothing): all of them are one
  `observed, not allowed` line. The record does not show sends on a connected socket, so a UDP connect to an address
  and port the run also reached over TCP is kept, with a note that it may be glibc's own probe (made on the service's
  port) rather than QUIC: remove it unless the agent speaks UDP there. *Amended 2026-10-16.*
- **Dangerous endpoints are never allowed**, only reported as `observed, not allowed`: the D-Bus session and system
  buses, systemd's private socket, gpg-agent and its ssh socket, an ssh-agent socket, X11 sockets, the Docker, Podman
  and containerd sockets, raw sockets, and any unix socket under `/run/user/<uid>` that the run did not create itself.
- `limits` are suggested in comments (memory about twice the run's peak, pids four times, wall three times how long it
  lasted), never written as limits. `fs.deny_read` is never touched: the built-in list applies, so a read the run made
  of a path on it will now be refused. Reads are not listed. `env`, `models`, `capture` and `tier` are not learned.
- **A proposal leaves env and reads open, and says so** in its header and on stderr: with no `env` section every
  variable of the launcher's environment reaches the agent, secrets included, and the agent can read any file the
  built-in list does not name. A secret it can read can leave through any address the proposal allows. Add `env.pass`
  and `fs.deny_read` yourself.
- **A place first reached next to a secret read is not proposed** (the leak rule, the same "secret read, then send"
  rule as the dashboard's verdict). An address off the contract whose first contact lies within 5 s and 16
  ledger lines of a secret touch, when the run opened a secret for reading next to such a place, is listed as
  `observed, not allowed`, the file opens with a `# WARNING` line, and stderr says the same. Every such open counts,
  not only the first. A secret is a path by its name (`secretpath`) or by the rule that decided the line. An open for
  reading is the receipt's test (`secretpath.ReadOpen`): a create, an unlink, a rename, a write-only or a failed open
  reads nothing. A watched line carries no return, so the words are "opened for reading, or tried to".
  What the rule cannot do, and the warning or header says: a destination recorded only by host name has no address to
  compare with an entry, so the warning asks you to check every `net.allow` entry; a unix socket is reported and stays
  proposed (it may be the agent's own); port 53 on this machine, a resolver the engine named (`net.resolver`) and the
  system lookup sockets are not judged; port 53 elsewhere is judged and left out with a warning of its own, since the
  port alone says nothing and tego allows the machine's resolvers itself; a place first reached before the read is not caught, nor a secret
  renamed to a plain name and read there; and it goes by file names and closeness, so it proves nothing either way.
  It can also withhold the agent's own service, when the agent reads its token and calls its service at once on a
  watched run: add that address back by hand. A watched run is judged on its own here, while the dashboard judges it
  against the enforced run of its pair.
- Every entry says how many times it was seen. The header says which run it came from, that it is a proposal for a
  person to review, and lists what was left out and why. A refused or failed action in the record is never proposed.

The proposal is only as good as the run was representative, and everything the agent did while it was watched is in
it: read every entry. It is built from the agent's own recorded behaviour, so a name with a control character or a
pattern in it is reported, never copied into a list. The file is YAML `tego compile` reads; paths are as recorded,
and tego follows symlinks when it compiles. Verified 2026-10-06 against the real Claude Code 2.1.290 and Codex 0.159.2
start-up ledgers (internal/check/learn/testdata), and by running a script under its own proposal at tier 1: nothing
refused.
## Unattended runs: what to put in the contract (2026-10-06)

A run nobody watches ends in one of four ways: the agent finishes, a limit ends it, the kernel ends it (memory,
tasks), or tego stops it because it can no longer keep the record. Everything in between is the contract's. This
section is what the custom-agent proof (test/poc/custom-agent/, run at tier `landlock`, an ordinary user, no root) found a contract for such a run needs. The numbers are measured on one box (Linux
6.17, Landlock ABI 7) with a Python agent that opens about 45 files a second, and say so where they matter.

**Start from the agent's own record.** `tego watch -- <agent>` with no boundary records everything it does; `tego
learn <run> --out <file>` drafts a contract from it. The draft allows what the run did and no more, and the run may
have done what you do not want (the custom agent's draft allowed its `git push` and its connection to a port nobody
should reach, because the record-only run made both): read every entry and delete the ones you did not mean to grant.
It can also list a `PATH`-search miss as a program that ran (`/usr/sbin/bash`, which does not exist; in five of eight
drafts here), which `tego compile` rejects as `[path-missing]`: delete the line. It never writes `models`, `capture`,
`limits`, `ask`, `record` or `env`, and it adds nothing to `fs.deny_read` beyond the built-in list, so the secrets in
reach are yours to name. Then `tego compile <contract>` and `tego compile <contract> --test <table>` (one row per
action the boundary must refuse or allow; nothing runs): put both in the launch script and refuse to start the night
if either fails.

**Route the model through the forwarder, or `tokens`, `cost_usd` and `repeats` count nothing.** Declare the provider
under `models:`, set `capture: forwarder`, leave the model host out of `net.allow`, and have the agent honour the
provider's base-URL variable (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`): tego then records every call (`ssl_request`,
`ssl_response`, a `decision` per tool call the model asks for) and counts them, and a connection straight to the
declared host is refused, so the agent cannot spend unseen, only fail. A budget the contract declares with nothing to
count it is refused: `tego compile` reports it `[budget-unmetered]`, and `tego run` exits 125 `[budget-unmetered]`
before the agent starts, naming the cause and the fix (see "Model budgets need something to count them" below).
`cost_usd` also needs the machine config's price table (`prices:`) with at least one model priced; without one a
declared `cost_usd` budget is refused the same way, and a model the table does not name is charged at the dearest
price it has ("The price table" below; `examples/prices.example.yaml` is one to start from). Only a budget a machine `limits:` ceiling alone imposes runs with nothing to count it, recording
`gap what=record why=budget-unmetered` and drawing an `[unenforced]` compile warning: in a launch script, treat any
`[unenforced]` or `[budget-unmetered]` line as a failure.

**Limits: set each one above the worst healthy night.** The watcher checks a monotonic clock once a second and the
model traffic as it arrives, and ends the run with a `limit` event naming the ceiling and the value, `run_end
reason=limit`, exit 124. The kernel's limits are the run's cgroup, which every run has, root or not (tier `landlock`
needs a delegated cgroup; a missing controller refuses the run, naming it).

| Limit | At the limit | Measured here |
|---|---|---|
| `wall` | the whole run is killed, 124. A hard cap on elapsed time: the agent working or you typing does not move it; for an interactive session set `stall_after` and leave `wall` off or large | `wall: 12s` ended the run at 12.000 s |
| `stall_after` | no event for that long: killed, 124. A held ask, a streaming model response and, when the agent's stdin is your terminal, your typing count as activity (seen up to 8 s late: the kernel stamps a terminal's read time once per 8 s, so keep `stall_after` at a minute or more; tego reads no key) | a hung agent was ended 5.49 s after its last event with `stall_after: 5s` |
| `repeats` | the same tool call from the model that many times in a row: killed, 124 | `repeats: 6` ended a runaway loop at its sixth call; a healthy loop's longest streak was 1 |
| `tokens` | input plus output tokens of the calls so far, cache tokens excluded: killed, 124 | `tokens: 300` ended at 317, the call that crossed it; the value equals the sum of the ledger's own usage |
| `cost_usd` | the same, priced: killed, 124 | `cost_usd: 0.002` ended at $0.002127, equal to the ledger's tokens priced by the table |
| `memory` | the kernel kills inside the cgroup, `run_end reason=oom`, 137 | a hog under `memory: 40MiB` reached the limit 38 times and was killed; peak exactly 40 MiB |
| `pids` | a refused fork ends the run, `reason=pids`, 137 (it does not wait for the agent to cope) | `pids: 16`: the 16th task's fork was refused and the run ended; peak 16 |
| `cpu` | throttled, never killed | `cpu: 0.25` over 6 s of a busy loop: 1.56 s of cpu, throttled 62 times |

Two things the limits do not do. `stall_after` reads events, and under `record: summary` a read of an allowed file is
not an event: an agent that is busy but only reads (a long search, a compile that writes nothing yet) is ended as
stalled after `stall_after` (measured: a reader was ended at 6.0 s of `stall_after: 5s` under summary, and ran its 14
s to the end under full). Use `record: full`, or a `stall_after` longer than twice the longest quiet phase. And a
limit set too low is a surprise at three in the morning: the agent's own peaks are in `tego status` (`resources:`),
which `tego learn` turns into a suggestion (twice the peak for memory, four times for pids, three times how long it
ran for wall).

**Decide in the contract; keep `ask` for the few that need a person.** A write under an `fs.ask` directory holds the
agent until `tego approve|deny <run> <id>` or `ask.timeout` (5 minutes by default, 1 hour at most), then is refused,
recorded `ask-timeout`. Nothing remembers a timeout: the next try at the same file is held for the whole timeout again
(measured: 5 tries, 5 holds of 3.00 s, 15.2 s of a 16 s run), so an agent that retries spends the night held. Either
do not list the directory (the write is refused at once, like any write outside `fs.write`), or keep `ask.timeout`
short, and answer the first request of each kind with `--always`: `tego approve <run> <id> --always` or `deny
--always` stands for the rest of that run, for that operation, rule and exact target and no other (measured: 2 human
answers, 31 repeats answered at once as `standing:<ask id>`, the slowest in under 1 ms), and every automatic answer is
its own `ask` and `answer` pair in the ledger. A held ask is not a stall. Approvals are for file writes and TCP
connects; running a program is refused, not held.

**What the ledger costs.** One file per run, `<ledger_root>/<run>/events.jsonl`, appended, never rotated, and capped
only when the machine config sets `record.max_run_bytes` (below); `tego events --verify` reads it start to end. Measured over 2.0 hours for this agent: `record: full` (every open, reads included) 53 events a second, 754
bytes an event, 145 MB an hour, so 2.9 GB for 20 hours; `record: summary` (execs, writes, connections, refusals, model
calls) 12 events a second, 29 MB an hour, 0.57 GB for 20 hours. Tego's own process held 18 to 25 MB of resident
memory for either, with no growth over the two hours, a constant descriptor count and 1.8% (full) or 1.3% (summary) of
one core; the agent's recording cost is about 60 us for each open under `full` and 1 us under `summary` (about 17
us more with `reason.reads: on`, which tells tego of every read open at tier `landlock` and writes no line for an
allowed one; ADR 0077). A faster arm,
614 events a second for 71 minutes (2.6 million events, 69% of the events of 20 hours of the slow arm), grew no faster
per event. Size the disk under `ledger_root` for the estimate and twice again, and `retention` (30 days by default)
for what stays. When the ledger cannot take a line (a full disk, a quota; simulated with a file size limit) tego
stops the run rather than let it go unrecorded: the agent is killed, `tego run: the run's record is incomplete ...
[ledger]`, exit 125, and `tego status` reads `lost` because the `run_end` could not be written; what was written
still verifies. Reading the record back costs time in proportion to its size, since `status`, `measure` and `drift`
each read the whole file: on the fast arm's ledger (1950 MB, 2.64 million events) `status` took 24.7 s, `measure` 25.4
s, `drift` 25.5 s and `events --verify` 34.6 s, so a 20-hour ledger of the slow agent (3.8 million events) takes about
36 s for `status`. `events --last` reads from the end and stops at its answer (about 60 us on a 137,200-event run),
so its time is the distance from the end to the answer, not the ledger's length.

**What else can go wrong at night, and what tego does** (each measured):
- the model endpoint goes away: each call it cannot answer is a `gap what=capture why=malformed`, the agent's retries
  are events (so `stall_after` does not fire), and the run goes on; nothing is spent, so no token or cost limit trips;
- the launcher is killed (`kill -9`): the agent dies with it, the run reads `lost` until the next `tego run`, `stop`
  or `gc` sweeps it and ends it `orphaned`, exit 125; its ledger verifies, and a `gap what=record why=launcher-lost`
  says its last lines may be missing, as lines not yet on disk or still in the launcher's queue go with it;
- you stop it: `tego stop <run>` (or `tego stop --agent <name>`, every live run of that agent) from another terminal
  ends it at once, `run_end reason=stopped`, exit 143;
- the agent exits while something it started still runs (a `setsid` child, a disowned `npm run dev &`): the run ends
  `stop_grace` after the agent's exit, the rest killed and named in run_end's `detail`, with the agent's own exit
  code (`keep_descendants: true` in the contract keeps the run going as long as any of them lives, for a
  launcher that daemonizes on purpose);
- the machine reboots: the run is over, and nothing resumes it. Start the night from a unit that restarts the whole
  command (below).

**Agents that run all the time: a systemd user unit (2026-10-26).** `examples/systemd/tego-agent@.service` runs one
agent from your user registry per instance (`tego-agent@retriever` runs `~/.config/tego/agents/retriever.yaml`), each
restart a new run on the same ledger. Its exit-status keys follow `tego run`'s exit codes, checked against
`pkg/spec/identity` by `TestUnitTemplateExitStatuses`: a crash, a limit (124) or a kill by memory or pids (137) is
restarted (`Restart=on-failure`, 10 s apart, at most 12 times in 30 minutes); `tego stop --agent retriever` ends the run
143, which `RestartPreventExitStatus=143 125` keeps from restarting and `SuccessExitStatus=143` leaves inactive, not
failed; `systemctl --user stop` sends SIGTERM to tego alone (`KillMode=mixed`), which forwards it and keeps
`stop_grace`, so an agent that dies of it is 143 too; a run tego refused to start or could not record (125) is not
retried. Checked by hand on the user manager with these keys: a stop by name left the unit `inactive`,
`Result=success`, with no restart; `systemctl --user stop` the same; an agent exiting 7 with two sleeps left behind was
restarted every `stop_grace` + `RestartSec`. Not covered: an agent that ignores SIGTERM for all of `stop_grace` is
ended by `cgroup.kill`, 137, and a unit restarts that like a kill by memory, so give such an agent a longer
`stop_grace`; and an agent that catches SIGTERM and exits with a code of its own ends the run with that code (list it
in `SuccessExitStatus=`). The user manager runs only while you are logged in unless linger is on (`loginctl
enable-linger $USER`).

**A planned restart, once a day (2026-11-02).** `examples/systemd/tego-agent-restart@.timer` starts
`tego-agent-restart@.service` at midnight, which runs `systemctl --user try-restart tego-agent@<name>`: the agent's unit
is stopped as `systemctl --user stop` stops it (SIGTERM to tego, which forwards it and keeps `stop_grace`) and started
again, so the agent goes on as a new run with a new ledger, and its budgets and standing answers start over. So do its
live controls: the new run starts from its contract alone, so a `tego pause` is undone and every live block (`tego
block`, the dashboard's Block now) is dropped, and what was refused live is allowed again wherever the contract allows
it. A block that must outlast the restart belongs in the contract; with a person steering the run live, leave the timer
off.
`try-restart` leaves an agent that is not running as it is, so a `tego stop --agent` stays a stop and a failed unit
stays failed; a restart missed while the user manager was not running is not made up when it starts. Enable it per
agent, `systemctl --user enable --now tego-agent-restart@retriever.timer`; to move it, a drop-in empties `OnCalendar=`
and sets another (a second `OnCalendar=` alone adds a restart). Checked on the user manager (systemd 257) with the
template's keys and a stand-in for tego that ends 143 on SIGTERM: the restart ended the run and started a new one with
no failure counted (`NRestarts=0`), and left a stopped or a failed unit alone. Two other ways to end a run on time are
not this. `RuntimeMaxSec=` in the agent's unit stops it with SIGTERM at that limit, an agent that dies of it ends the
run 143, which `RestartPreventExitStatus` keeps from restarting, and the unit is left `failed` (`Result=timeout`, no
restart, in the same check), so the agent stays down. A `wall` in the contract's `limits` is restarted, as any limit
(124), but it ends the run with `cgroup.kill`, no SIGTERM first, and records a `limit` each time
(`examples/demo/contracts/always-on.yaml` uses `wall: 1h` so).

**Ledger space for an agent that never stops (2026-10-26).** A run's ledger is one file and one hash chain,
so tego does not rotate it while the run lives; instead the run ends at a size and the unit starts a new one. Set both
in the machine config the agents run under (the template's `TEGO_CONFIG` line, or `~/.tego/config.yaml`):

```yaml
record:
  max_run_bytes: 1GiB   # a run whose events.jsonl and blobs reach it ends: exit 124, limit which=ledger_bytes
gc_interval: 24h        # at most once a day, a tego run start removes ended runs older than retention
retention: 14d
```

`record.max_run_bytes` is checked at each line the run records (and once a second), so a run passes it by the lines
in flight: a fork loop under `record: full` at a 64 KiB ceiling ended at 65,714 bytes. Blobs, the bodies split out of
large lines and the bodies uprobe capture stores, count, each stored once however often it repeats. The run ends as any limit does, `run_end reason limit` and exit 124, which
`Restart=on-failure` restarts as a new run with its own ledger, 10 s later; at the measured 145 MB an hour of `record:
full` (lines alone: a run's blobs bring the restart closer), 1 GiB is a restart about every 7 hours, and `tego status` and `tego events --verify` on a 1 GiB ledger take about
14 and 19 s. `tego status <run>` ends with `ledger: <size> of <ceiling> (record.max_run_bytes)`, so a live run shows
how far it is from the restart (`--json`: `ledger_bytes`, `ledger_ceiling_bytes`). With `gc_interval` set, the first
`tego run` start after each interval runs `tego gc`'s pass (a unit's restart is such a start): it ends a lost run as
`orphaned`, and removes every ended or empty run older than `retention`, never one whose launcher still holds it,
however old. The same pass prunes the rule-change journal (`<ledger_root>/.rule-changes/`) to `retention`, but keeps
every line written since the oldest run still in the ledger root started, and every line that names such a run (a
live block placed on it), so an agent that runs for weeks keeps the changes its page lists and the blocks an Undo must
not lift; and each rules file keeps its newest 20 changes still standing while the file is there. A rules file the
pass cannot look at counts as there: one in a folder you cannot search, or one on a stale mount, which the pass waits
for at most 3 s and at most half of what is left of its 2 s, looking at the other files meanwhile; it prunes the rest
of the journal and logs which files it could not look at (`tego gc` says so on stderr). A pass started as root (`sudo
tego run`, as tiers 2 and 3 are) prunes the invoking user's journal as that user, looking at the rules files as that
user too: their uid and their group alone (`SUDO_GID`, else their passwd group, the group a root run's agent gets)
and no capability; a journal of any other user is left to them, which the pass logs. It spends at most 2 s and stops
between runs, and the next pass goes on from the oldest run left; a journal the budget left unpruned is logged too.
`tego gc` with no flags is the same pass and counts as one. A removed run's line stays in
`~/.tego/chain.log` (a line per run, never rewritten), so every run left still verifies, and `tego events <removed
run> --verify` says its anchored ledger is missing rather than that it never ran. Without `gc_interval` nothing is
removed unless you run `tego gc`, and with it nothing is removed while no run starts: an agent that runs for weeks
without a restart makes no pass in that time.
`examples/systemd/tego-gc.timer` runs the pass once a day whatever starts (its `tego-gc.service` is `tego gc` with no
flags, so it counts as the start's pass), and makes up a day missed while the user manager was not running
(`Persistent=true`): give the service the agents' `TEGO_CONFIG` line, then `systemctl --user enable --now
tego-gc.timer` (2026-11-02; checked on the user manager: the oneshot unit's pass removed an ended run older than
`retention`, exit 0). A machine config the pass cannot read whole (a layer it cannot open, trust or parse) removes
nothing: `tego gc` exits 125 `[config-untrusted]` naming the layer, and the unit fails, since the retention and the
ledger root it removes by may be set in that layer; it gives a layer's mode back first when an agent took it
("Modes an agent took", below). Size the disk for `retention` days of restarts: for the agent above, 3.5 GB a day.

**While it runs.** `tego events <run> --follow` prints each line as the run appends it, checking the chain as it
goes, and exits 0 at `run_end`; a launcher killed mid-run is exit 125 `[run-lost]` rather than a wait that never
ends.

**In the morning.** `tego receipt <run>` (what it did on one screen: files written, refusals by rule, asks, tokens and
cost, and what the ledger could not cover, which `--json` names by a code a script can match, such as `capture-off` or
`missed-actions`; `--verify` checks the chain too), `tego status <run>` (state, how it ended,
events, `gaps:` and `live changes:` as the record spells them, `in words:` for what they mean, the same reading as the
receipt: whether actions may be missing, what is short if not, and what a person changed, and on a lost run that its
record may stop short; the run's resources), `tego events
<run> --last` (the last refusal, gap or limit), `tego events <run> --kind refused`, `tego drift <run>` (declared
against observed, per rule, with the same `gaps:`, `live changes:` and `in words:` lines, and every exec of a program
held in memory (`fileless`) or that ran a file the run itself wrote (`dropped`: the program, its `#!` interpreter or a
binary a loader ran, listed by the exec's own path), each with whether it was allowed or refused),
`tego measure <run>` (steps, tokens, estimated cost, wall), `tego events <run>
--verify`. In these and every other command that takes a run (`stop`, `ask`, `approve`, `deny`, `block`, `pause` and
the rest), `<run>` can be four or more characters from the end of the run id that no other run under the ledger root
has (`tego receipt 28t5cy`), or its start up to four or more characters past `r-<host8>-`, which every run of this
machine begins with (`tego receipt r-1a2b3c4d-0dmk`). Like a whole id, they are never read as a directory of that
name in the current directory; `./28t5cy` names that directory, and when there is one, a command that also takes a
run directory prints a note on stderr naming both. A refused `git push` is one refusal per directory of `PATH` that
the agent's own search tried (133 for 7 pushes here), and an exec by name is one event per directory tried: count
actions from the agent's own log and the `decision` events, not from refusals.

## Finding agents that were not started under Tego (2026-10-06)

`sudo tego agents` lists the agent processes running on this machine: any process a signature names (shipped: `claude`,
`codex`, `opencode`, `gemini`, each by its program name and by its node entry point), with its pid, parent, program, arguments
and whether it runs **inside a tego run** (its cgroup is a run's `run-<id>.scope`) or **outside** every one, as an agent
started in a plain terminal does. `sudo tego agents --follow` goes on listening to the kernel's process events and prints a
line when an agent starts and when it exits, until you interrupt it (exit 0); `--children` adds each process an agent starts,
`--json` writes one JSON object per line. `--signature <rule>` adds a signature, replaces every shipped one of the same name
or, as `name=`, removes it; the rule is a program name (`mytool`), an absolute path, `name=<argv pattern>`
(`web=node .../web/cli.js`) or `name=file:<dev>:<inode>`. `--no-default-signatures` starts from an empty list.

It **only observes**. It signals, moves, blocks, traces and changes no process, writes no cgroup and no ledger, and it does not
confine what it reports: an agent started outside Tego is not protected by being listed, and a tier-1 filter, Landlock or the
environment of a running process cannot be added afterwards. Governing such an agent is adoption (next section), which
moves it into a new cgroup, since the agent shares its cgroup with your terminal. The command needs root of the initial user namespace
(`CAP_NET_ADMIN` for the kernel's process connector, and root's right to read other users' `/proc` entries); without it
the command says so and exits 125 `[privilege]`. Where the kernel's event buffer overflows (a build starting thousands of
programs a second) it reads `/proc` again and prints a `resync` line; an agent that began and ended wholly inside the gap is
missed, and one found gone only by the rescan is reported without an exit status. An agent whose main thread has exited while
its other threads run (it reads as a zombie at `/proc/<pid>`, with no program or arguments there) is read through one of
those threads, and reported, and adopted by the guard, by its process id. A process ends when its last thread exits, not
its main thread: an agent whose main thread exits while it is followed stays followed, and its end is reported then
(2026-10-17), told by the kernel's process events alone however late they are read (2026-10-19: a thread's exec, or
one that failed, no longer ends it early; 2026-10-20: an exit filled before the agent was followed, by its fork, its
exec or a listing of its tasks, says nothing). The exit status is printed only where the main thread's exit was read
and every other thread's exit read after the agent was followed carries the same code, whichever was read first, a
signal like any other code (a thread can be killed alone; a thread's exit before a later fork of the agent is left
out, as the agent ran on); so an agent whose worker threads exited on their own with another code shortly before the
end is printed with its status unknown (ADR 0055 (e), the amendment of 2026-10-20); a main thread that exited first
with 0 and a thread that ended the process with 3 could mean either (`exit_group(3)` gives 3, the thread's own `exit(3)`
gives 0), and the line says the status is unknown. `argv` is printed as the process has it, up to
4 KiB: a key given on a command line would show. The design, the limits and what was tested: docs/poc/agent-watcher.md.

## Adopting an agent that is already running (2026-10-06; ADR 0055)

`sudo tego adopt --pid <pid>` governs an agent that was started outside Tego, in any terminal or IDE. A running
process cannot be given a seccomp filter, Landlock or another environment, so this is root's and the kernel's: the
agent's own process tree, and nothing else, moves into a fresh cgroup,
`tego.slice/tego-<agent>.slice/adopt-<run id>.scope`, where tier 2's programs record from the kernel every program
it starts, every file it opens and every connection it makes, into a normal run: `tego status|events|drift <run>`
read it. The command prints whose process it is (real, effective and saved uid) and the run id, and holds the run until
the agent's tree ends (run_end `exit`). Ctrl-C, SIGTERM, `tego stop <run>` or `tego adopt --release --pid <pid>`
**release** it: the tree goes back to the cgroup it came from and runs on, unrecorded (run_end `stopped`, naming who
asked). `tego stop` and `--release` signal nothing: they leave a release request (`/run/tego/adopted/<run>.release`)
that this adoption alone answers, so a guard's other adoptions, and the guard, run on. If root moves the tree out by
hand, the run ends `stopped` and says so. A process the release finds no cgroup to put back in (the one it came from
and every one above it gone or refusing it) stays in the scope, released and unrecorded, counted by `gap
adoption-left-in-scope`; the scope and the adoption's record stay with it (the record marked released), `tego agents`
reports it governed by the ended run and the guard refuses it under `governed`, and `sudo tego adopt --release --pid
<pid>` moves it out once a cgroup takes it, then removes both. `--release --pid` acts only on a process in an adoption's
scope at its own place (`/sys/fs/cgroup/tego.slice/tego-<agent>.slice/adopt-<run>.scope`) that the run's record
names: a cgroup a user made with an adoption's name in their own subtree is refused, `[adopt-refused]`. A release request answered so is not a failure of the
adopter's: `tego stop` and `--release` say at once that the run ended and how many processes stay in the scope, and
exit 1, rather than waiting 30 s for a record that stays. The same holds when an adoption fails after the move and
before it records (its tier's Prepare, or a boundary on a box with no plane mode): what moved goes back, and what no
cgroup takes stays in the scope with the record, which the error (`tego adopt`'s, the guard's `adoption_failed`
note) names; no run exists for it, so the later release writes no run_end. An adoption **never kills** the agent. It needs root of the initial user namespace and the BPF objects (`make build`); without
root it exits 125 `[privilege]`. The design, its evidence and its scope guard: ADR 0055.

What moves, and what is refused. The agent and its descendants that are still in the agent's cgroup move, the agent
first: never its parent shell, a sibling in the same session scope, or a descendant placed in another cgroup (a
`systemd-run --scope`, a container), which is counted in the record instead. A process the agent started that was
reparented away before the adoption (its parent exited, as a daemon's does) is no longer its descendant: it is not
moved and not counted. Refused outright, with the rule named
(exit 125 `[adopt-refused]`): pid 1, a kernel thread, a thread id, tego itself, any ancestor of the command (its shell,
sudo, sshd, a multiplexer, the user manager), a systemd manager (`init.scope`), a container's process (another cgroup or
pid namespace), a process already in a tego run or adoption, and a process in the root cgroup (a release never moves
a process into the root cgroup, so it could not be given back). Only the invoking user's own process is adopted
(the user sudo ran tego for; root's when root runs it directly): another user's needs its owner named, `--uid
<uid>` (repeatable), or it is refused under `uid` with the `--uid` that would admit it; a process whose real,
effective and saved uids differ is never adopted. A process is named by its pid and its start time: right before the
move, under a host-wide lock every adopter holds while it moves (`/run/tego/adopted/moves.lock`), it is read again and
every rule above is applied again, and before each process's own move its start time is read again, so a process that
exec'd, changed its user or was adopted by someone else meanwhile, or a pid that names another process by then, moves
nothing.
While adopted, the agent is outside its session scope: a logout's `KillUserProcesses` and the session's accounting do
not cover it until it is released.

What the record holds, and what it cannot. From the attach on: execs, opens (reads too, at the default `--record full`),
file creations, removals and renames, connects. Never: what the agent did before the attach (`gap adoption-pre-attach`
names the agent and counts its processes; each one's `exec` line, `by: adoption`, carries its start time in its
`exec_id`), reads, writes and sends through descriptors it already held, and loads and stores through files it had
mapped (`gap adoption-open-sockets` counts the sockets it held; a socket keeps the cgroup it was made in), its model traffic (the forwarder needs the agent's environment),
and a process of its tree that did not move (`gap adoption-not-moved`). The window between finding the agent and the
attach is 50-75 ms when another run, or the build's linger (5 min), keeps tier 2's build loaded, and 3.5-6 s on a cold
build (measured in a 2-GiB guest); everything in it is the pre-attach gap, never silence. A busy agent loses no event
silently afterwards: a full ring is a `ringbuf-full` gap with its count. The exit status of an agent tego did not
start is read from the kernel's process events when it can be (the agent's own exit, never a later process's under a
reused pid; the end of its last thread, and only a status every compared exit code agrees on, from the listing made
of it when it was adopted on), else run_end says it is unknown. Where a fatal signal or another thread's `exit_group`
arrives while a task is between its own `exit(2)` call and the start of do_exit, the kernel's events carry the task's
own code and `wait(2)` the group's: that window, a few hundred nanoseconds, is the one case the events cannot tell
(ADR 0055 (e), "racing exit").

A boundary. `tego adopt --pid <pid> --boundary agent.yaml` holds the agent to the contract's file rules and exec allow-list
through the kernel decision plane (fs.write and the refusal of every other write, deny_read with the built-in list,
exec.allow's programs), from the attach on. The contract compiles against the agent's owner's home from the passwd
database, so `~` and the built-in lists (`~/.ssh`, `~/.aws`, shell startup files) are that user's, whoever runs tego:
the guard compiles one table per `--uid` when it starts, and a boundary for a uid with no home there is refused. What
only tier 1's seccomp filter refuses is not held on an adopted process, whatever the contract says: System V IPC (even
without `ipc: true`), socket families outside the network rules (AF_VSOCK, AF_PACKET, SCTP and the rest), io_uring,
openat2, open_by_handle_at, clone3, the terminal-input ioctls, and the mount topology: tier 1 refuses new mount and user
namespaces and `setns`, and nothing refuses them on an adopted process, so an agent that can mount (root, or through
a user namespace) can put a file where the contract's paths do not reach it (bind a directory outside every write
entry beneath one and write its files, or mount an overlay whose lower layer is a `deny_read` directory and read its
files; a bind of a `deny_read` directory or a `deny_write` target itself is still refused); the notice says so and the ledger has `gap what=enforce adoption-no-syscall-filter`; each refusal is a ledger line with `mechanism: plane`. It needs a plane mode on this
machine (`sudo tego doctor`: `decision plane: fmod_ret` or `lsm`); the fanotify fallback cannot refuse a write, so
there the adoption is refused. Every rule that cannot be added to a running process is refused before anything moves,
each one named: a `net:` section (a socket made before the adoption would not be governed, and the record could not
tell which), `fs.ask` and `ask`, `env`, `models` and `capture`, `limits`, `gate`, `mcp`, `docker`, a tier other than
cgroup, and every exec command rule: `exec.deny`, `exec.ask` and an `exec.allow` entry with argument words are decided
on argv by the supervisor, which an adopted process does not have (the plane decides which program runs, never its
arguments). A file the agent opened across a rule before the adoption stays open, and a file it mapped stays mapped
(`gap what=enforce adoption-open-descriptors` counts both, by the plane's own rows: a file held, or mapped at all,
where the plane refuses a read (any deny_read entry, the built-in list and its `.env` names included), and a file held
for writing, or mapped shared and writable or may-write, where it refuses a write: outside every write entry, or a
deny_write target beneath one, such as the repository's `.git/hooks` and `.git/config` or `~/.bashrc`. Under `/dev`
only the terminal and the byte sinks such as `/dev/null` are left out; `/dev/shm` counts; a file on one of the
superblocks the kernel mounts for itself, such as a memfd, a System V segment, the AIO ring or hugetlb memory, is no
file a rule names and never counts, told by its device, which tego learns by making one of each; any other file
counts by its path, one held from a chroot included, by every other path that reaches it through another mount
of the same filesystem, such as a bind mount of a directory above it, by the path of a rule's file it is a hard
link of, since the plane decides a file's inode under every name it has, and by its path beneath a rule's directory
its name passes through under another name (renamed since the plane was filled): of the files `/proc` lists, the
count can be high, never low; the descriptors are every thread's, a thread that unshared its own descriptor table
included). A process whose descriptors or mappings could not all be read (more than 4096, or a listing that
failed, a thread's table included), one holding a descriptor `/proc` cannot name (a file open at a path longer than
`PATH_MAX`, which `readlink` refuses) or whose open flags it cannot read, one holding an io_uring instance with registered files (they are read and written through the ring with no
descriptor `/proc` lists), and, for a boundary, a process in a mount namespace other than tego's, one mapping an
io_uring instance it holds no descriptor of (on a kernel that puts every ring on one shared inode, any ring it maps),
or one holding a file whose name is no path of it in tego's
namespace (held through a detached clone or a lazily unmounted mount, which `/proc` names from that mount's root, so
`~/.ssh/id_ed25519` through a clone of the home reads `/.ssh/id_ed25519`; or a pseudo file such as a dma-buf, on a
superblock tego does not probe), is counted in `gap adoption-descriptors-unread`. What `/proc` lists of no process
is not counted at all: a descriptor in flight in a unix socket's queue (sent with `SCM_RIGHTS`, not yet received), an
io_uring instance registered with itself and neither held nor mapped, a file another kernel object holds. The agent owner's own `~/.tego` is read-denied
under a boundary as under the owner's own launched run, while the ledger and the chain anchor are the adopter's. A
boundary adoption makes that directory first when the owner has never run tego (mode 0700, owned by the owner), so
the records of the owner's first run are denied too, and refuses the boundary when `~/.tego` is not itself a
directory (a file, or a link, even one to a directory: the link would be under no row, so an agent allowed to write
the home could swap it for a fresh directory) or cannot be made, or when another directory was renamed in at that name while tego made
it (root gives the owner only the empty directory it made); an adoption keeps its table while it runs. Before it
arms, it checks that the plane's row for `~/.tego` is at the directory the table was compiled against (the
contract's own `deny_read` of it included), and once armed, that `~/.tego` is still that directory itself, no link
to it; it fails,
giving the agent back, when either is not so (the agent removed or replaced it in the moment before the arm; adopt
again). From the arm on the agent can no longer rename, remove or replace it. An owner whose
passwd home does not exist (a service user's `/nonexistent`) gets no home made and no such deny, as no records can be
there; nor does an owner whose home it may not write by its mode (a service account's `/` or `/var/www`, owned by
root): root makes no directory there, which the owner could not have made itself (a home only an ACL lets the owner
write counts as one it may not). The guard compiles a uid's table again before its next adoption when that uid's
`~/.tego` is no longer the directory the table denies, its missing home exists now, or a `~/.tego` appeared in a
home it may not write. A
boundary write entry at or inside the owner's `~/.tego` is refused (`contradiction`). Other built-in
deny_read paths made after the guard started (a new `~/.aws`) are covered from its next start: restart the guard
after setting up a user's credentials.

The guard. `sudo tego agents --follow --adopt --uid <uid>...` adopts each agent the detector reports outside every
governed run whose real, effective and saved uid are one listed uid, as it starts (or, when the guard starts, as it
is found running). Any local user can name a program `claude`, so `--uid` is required, and root's agents are adopted
only with `--uid 0`; any other agent is reported (`adoption_refused`, with the rule) and left alone. `--boundary` and
`--record` apply to every adoption. Its lines: `adopted` (pid, uid, run, how many processes moved, `window_ms`),
`adoption_refused`, `adoption_failed` (what moved went back, unless its note says which processes stay in the scope)
and `adoption_ended` (the run's reason). Each agent is
considered once and never retried; one process is never adopted twice; at most 32 adoptions at once, past which an
agent is refused and said so. Stopping the guard (Ctrl-C, SIGTERM, `systemctl stop`) releases every agent it adopted
before it exits. It is a foreground command (ADR 0042: no daemon); `docs/poc/tego-guard.service.example` runs it under
systemd.

If the adopter dies. Its reaper, `tego __adopt-reap` in tego's `helpers.scope`, releases the agent, writes run_end
`orphaned` and removes the scope and the run's kernel state: killing the adopter leaves nothing attached and does not
kill the agent. If the reaper is gone too, nothing records the agent any more: it stays in the scope, and a boundary's
plane rows go on refusing what the contract forbids, with no ledger line for those refusals, until it is released.
`sudo tego adopt --release --pid <pid>` releases it from the adoption's record and writes run_end `orphaned` saying
who did; so does a root sweep (`sudo tego gc`), whose run_end `orphaned` has no detail and is written only after the
tree is out. Until then the ledger shows the run as lost (`tego status`), never ended: an unprivileged `tego gc`
leaves it lost and says only root can release it, and a process no cgroup takes back keeps it lost, record and scope
kept, for the next try. No sweep ever kills an adoption's scope.

Removing it as root, by hand. While a run is adopted the host holds: the scope (`/sys/fs/cgroup/tego.slice/*/adopt-
<run>.scope`), the record and a lock (`/run/tego/adopted/<run>.json`, `/run/tego/adopted/target-<pid>-<start>`, root
0600 in a root 0700 directory; a pending release request beside them; `moves.lock`, permanent and empty) and, in the build's pins, a run-set row (`/sys/fs/bpf/tego/<hash>/maps/tego_run_set`;
a boundary's plane rows too). Nothing is hidden. `tego adopt --release --pid <pid>` undoes it all; by hand: write each
id the scope's `cgroup.threads` lists into the `cgroup.procs` of the cgroup the record's `from` names (a thread's id
written there moves its whole process; the scope's own `cgroup.procs` leaves out a process whose main thread exited
outside it), `rmdir` the scope once `cgroup.threads` is empty (its run-set row goes with it), delete the two files, and
`sudo tego gc --builds` to remove an idle build.

## Host daemon sockets with no `net:` section (ADR 0070, 2026-10-25)
A contract with no `net:` section keeps every IP destination but reaches only the unix sockets the run itself bound
and Tego's own endpoints (the DNS broker's socket). Every other unix connect or addressed datagram, pathname or
abstract, is refused, `rule: host-sockets`, and the line names the socket and, for a well-known one, what it gives
(`what: the Docker daemon, root-equivalent`). What an agent may have used that is now refused:

- **git over ssh** (`SSH_AUTH_SOCK`), commit signing (gpg-agent), the `docker` and `podman` clients, the session bus
  (`notify-send`, the secret service, `systemd-run --user`) and an X display. Name the one socket the agent needs in
  a `net:` section, which then names the hosts it reaches too, since a `net:` section refuses what it does not name:

      net:
        allow:
          - "github.com:22"
          - "unix:/run/user/1000/ssh-agent.socket"   # the path SSH_AUTH_SOCK holds

- **glibc's lookups:** nscd (`/var/run/nscd/socket`), `nss-resolve` (systemd-resolved's varlink socket) and
  `nss-systemd` (userdb) are refused, and glibc falls back to `/etc/hosts`, DNS and the files, so name and user
  lookups keep working; the refused lines stay in the ledger (on a host with nscd configured, a refused connect for
  each process's first lookup).
- **Interface enumeration** (`getifaddrs`, `if_nameindex`, `getaddrinfo`'s `AI_ADDRCONFIG` source-address query;
  Node's `os.networkInterfaces`, psutil, Go's `net.Interfaces`) works, here and under a `net:` section (ADR 0128): a
  read-only `NETLINK_ROUTE` request to the kernel is relayed as the task, one allow line `dst family(16) proto raw`,
  rule `route-query`, per query. It lets the agent read the host's interface names and MAC addresses, every address,
  the routes and the neighbour table (the other machines on the LAN the host has talked to). That is always on, and most
  of it is in `/proc/net` and `/sys/class/net` anyway; ADR 0128 lists it. A message that changes the network is refused
  `route-change`. Any other netlink message (another process's port id, a multicast group, generic netlink such
  as nl80211 or ethtool) and an `AF_PACKET` socket are refused `host-sockets`. `host_sockets: true` restores them. A
  `net:` section does not: it refuses other netlink protocols at `socket(2)`, `EPROTONOSUPPORT`, so `ss` and `ethtool`
  fail there. Under `net.assurance: kernel` the C library's interface lists still fail, since `recvmsg` is refused there:
  `if_nameindex` and `getifaddrs` return `ENOSYS`, and Node's `os.networkInterfaces()` throws. `getaddrinfo` goes on, and
  Go's `net.Interfaces`, which reads with `recvfrom`, works.
- **The opt-out** `host_sockets: true`, in the top-level contract only (a profile's is ignored,
  `profile-cannot-loosen`), restores the old reach: `compile` warns at the key, naming each well-known daemon socket
  it finds here and what it gives, and run_start records `host_sockets: true`. Prefer the `unix:` entry.

At tier landlock the supervisor performs every connect of such a run on its own copy of the socket, every Fast-Open
send and every send on a connected stream socket, and every addressed datagram it can reproduce exactly. Measured with
`BenchmarkUnixOnlyRelay` on a shared development machine (i7-10870H, 4 CPUs, 5,000 calls, median of 3 runs, 2026-10-25):
an addressed UDP datagram (a DNS query) takes 56.7 µs relayed against 48.3 µs continued, +8.4 µs (supervisor 1,778 to
2,346 B and 18 to 29 allocations per call), and a TCP connect 108.7 µs against 102.7 µs, +6.0 µs (2,118 to 2,611 B, 26
to 34 allocations). A Fast-Open send, a send on a stream socket without a peer and an addressed send on a connected
stream socket (whose address the kernel ignores and no line records) are relayed at the same per-call cost as a
datagram rather than continued; an addressed send on a connected seqpacket socket stays continued (best effort), so
its receiver reads the sender's own pid. Descriptor passing is unaffected: it sends with no address. A resolver
that queries per request pays the relay per query. At tiers cgroup and bpflsm the same relay and Landlock carry the
restriction, best effort until the root tiers carry a kernel program for it (run_start `best_effort` `host_sockets/root-tier`).

## Model budgets need something to count them
A contract's `limits.tokens`, `limits.cost_usd` and `limits.repeats` are counted from the model traffic the run
captures, and `cost_usd` also from the machine's price table. A run whose contract declares one of them and has
nothing to count it with is refused, exit 125 `[budget-unmetered]`, with the cause and the fix: `capture: off`, a
machine `capture:` ceiling of `off`, no `models:` endpoint where the run captures with the forwarder (every
unprivileged run, tier `landlock`, and every `auto` contract under `record: off`), `record: off` under a contract
that pins `capture: uprobe`, or, for `cost_usd`, no price table at the
machine config's `prices:` path (or a table there that lists no model, or prices none: every entry lacks an input or
an output price). `tego compile` reports the same contract
with a `[budget-unmetered]` warning that says the run is refused. Until 2026-10-16 such a run went ahead with only an `[unenforced]` compile warning and a
`budget-unmetered` gap, so an unattended night ran with a limit that did nothing. A budget a machine `limits:` ceiling
alone imposes is not refused: the run records `gap what=record why=budget-unmetered binary=<budget>`
(limits-check-doctor-cli.md R32). For an unattended run, declare the model endpoint under `models:` and install a
price table before relying on `cost_usd` (next section).

Under `record: off` the uprobes place no probe, so an `auto` contract captures with the forwarder at every tier, and
its run refuses a direct connection to a `models:` host (`rule: models[<host>:<port>]`), as a tier `landlock` run
does: the agent reaches its model through the forwarder's base URL (`ANTHROPIC_BASE_URL` and its peers). An agent
that ignores that variable fails to reach its model rather than spend past its budget unseen. At tiers `cgroup` and
`bpflsm` under `record: summary` or `full`, a run with a model budget whose probes could not start (a capture object
the kernel refused, a spent `bpf.ring_budget`) is refused `[capture-unavailable]` even though the forwarder runs,
since that table does not refuse a direct connection; `capture: forwarder` is the fix that needs no probe.

## The price table
`limits.cost_usd` is estimated from the YAML file at the machine config's `prices:` path, `~/.tego/prices.yaml` unless
a layer names another, and a run whose contract declares `cost_usd` is refused without one (above). No table is
installed for you. `examples/prices.example.yaml` is one to start from: the Claude API's list prices for every model
Anthropic serves to all accounts, dated by its `updated:` line. Check them against the provider's pricing page and install
it where tego reads it, readable and writable by you alone. Only Anthropic responses are priced in this build: a model of
another provider (OpenAI's, for `codex.yaml`) is unmetered whatever the table says, and a run that calls one under a
`tokens` or `cost_usd` budget is ended (docs/p0/capture-derive.md), so leave the budget out of such a contract:

```sh
mkdir -p -m 700 ~/.tego
install -m 600 examples/prices.example.yaml ~/.tego/prices.yaml
```

The format (spec/config/v0's `prices`, read by `internal/runtime/limits`):

```yaml
version: 1                      # the only version this tego reads; any other is read as no table
updated: 2026-11-02             # when the prices were last checked; tego keeps it and prices nothing by it
models:
  claude-opus-5-5:              # the model name exactly as the response reports it
    input_per_mtok: 4           # USD per million tokens
    output_per_mtok: 20
    cache_read_per_mtok: 0.20
    cache_write_per_mtok: 5     # 5-minute cache writes
    cache_write_1h_per_mtok: 8  # 1-hour cache writes
server_tool_per_request:
  web_search_requests: 0.01     # USD per request, keyed as the response's usage.server_tool_use names it
```

A model's key is the `model` of its `ssl_response` lines (`tego events <run> --kind ssl_response --json`); for a
Claude model before the 4.6 generation that is the dated snapshot, such as `claude-haiku-4-5-20251001`, whatever alias
the request used. Nothing the table leaves out is charged at $0. A key the format does not name makes the whole table
unreadable, which reads as no table at all, so a misspelt price cannot read as $0. A response the table cannot price (a model it does not name, an entry
without the cache price the response needs, a server tool with no fee, a premium such as fast mode or US-only
inference) is charged at the table's dearest rate for each counter, twice that for a premium, and the run records
`gap why=unpriced-model` once per model (limits-check-doctor-cli.md R2). A table whose prices are below the provider's
lets a run spend past its budget; one above ends it early. The table follows the machine config's trust rule: owned by
you or root, not group- or other-writable, in a directory that is not either, and with one name (no hard link);
`tego compile` warns about one it does not read, and a run of a contract that declares `cost_usd` is then refused.

## Crash and cleanup
- The supervisor holds `runs/<id>/lock` with `flock(LOCK_EX)` for the run; the kernel releases it when the holder
  dies, so "live" is "lock held", with no pid file and no state file. `tego run`, `tego stop` and `tego gc` sweep:
  for a run with `run_start` and no `run_end` whose lock is free, take the lock, write `1` to `cgroup.kill` if
  `cgroup.events` says populated, append `run_end reason=orphaned`, remove the cgroup directory and
  `$XDG_RUNTIME_DIR/tego/<run>/`. `tego status` never writes: it shows `lost`.
- If the supervisor dies, the agent's main process is killed by `PDEATHSIG`; descendants keep the inherited filter and,
  with the listener closed, every notified syscall fails with `ENOSYS` while Landlock and cgroup limits persist. This is
  fail-closed by design; the sweep collects the tree.
- Programs, maps and links are pinned under `/sys/fs/bpf/tego/<bpf_hash>/` (tier 2) and, for the decision plane, under
  `/sys/fs/bpf/tego/<bpf_hash>-<mode>/` (`lsm` or `fmod_ret`; see "Tier 3 and the decision plane"); the build lock is
  `/run/tego/bpf-<bpf_hash>.lock` (root 0700 only; there is no non-root `tegod`, ADR 0042), held `LOCK_SH` by every launcher
  of that build; the last one out takes `LOCK_EX|LOCK_NB`. It does not detach (ADR 0022): it stamps the lock's mtime
  and starts the build's timer (`tego __bpf-linger`, one per build), which removes the build once it has been idle
  for `bpf.linger` (default 5m, `/etc/tego/config.yaml` only), no launcher holds its lock, and its run set names no
  live cgroup. A timer that was killed is started again by the next run of any build once its build is past the
  linger (the timer then removes it, not the run), and by any root `tego stop`. A root `tego gc` sweeps the same
  way; `tego gc --builds` removes every idle build at once. A removal returns only once the kernel has released the
  build's links (it waits at most 30 s for a program something else still holds), so `gc --builds` and a
  `bpf.linger: 0` run's exit take the kernel's teardown, a few seconds for a build with a plane, and the next run's
  load does not wait for it. A lock cannot go stale. `sudo tego doctor` lists every build (`--json`'s `builds`):
  whether a run holds it, how long it has been idle, whether its timer runs (`timer`, `timer_pid`) and so when it
  goes, the memory its programs and maps charge (`memlock_bytes`, the fdinfo `memlock` bpftool shows, each object
  once; `memlock_unreported` counts what the kernel did not report, shown as `n/a`, never 0; the run rings are
  `ring_bytes`), and why a build no launcher holds is kept, inside its linger or past it (`kept`): a run it enforces
  is alive, or its run set cannot be read (`kept_cause` says what the read met, for example a map of another layout
  pinned under its name). `gc --builds` removes neither of those; the first goes once its run's cgroup is gone, the
  second needs root to look at the pins doctor names and remove the build by hand once no run of it lives.
- The ledger is append-only and torn-line tolerant; nothing to repair.
- **Modes an agent took** (2026-11-02). An agent runs as the user who owns `~/.tego` (the config layer, `chain.log`,
  `tego.log` and the default ledger root in it), the ledger root, `$XDG_RUNTIME_DIR/tego` and its own run directory,
  and no Landlock ABI has a chmod right, so it can `chmod 000` them. `tego run` gives the owner back their rights on
  `~/.tego`, `config.yaml` and `tego.log` before it reads the config, and on `chain.log`, the ledger root, `.live` and
  `$XDG_RUNTIME_DIR/tego` before it compiles, warning `[own-state-mode]` for each; every run gives all of these back
  at its end too, and its own run and runtime directories. `tego gc` gives back `~/.tego`, `config.yaml` and
  `tego.log` before it reads the config too, and deletes nothing by a config it still cannot read whole: it exits 125
  `[config-untrusted]`, so the daily `tego-gc` unit fails and its journal says why. Only the owner's bits are added,
  since someone else could have changed what a directory others can write holds: a `~/.tego` or `config.yaml` made
  group- or other-writable still has every run refused by the config trust check, with its fix (`chmod g-w,o-w`), and
  a `$XDG_RUNTIME_DIR/tego` made so has every run that routes Codex refused, with its own fix (remove it, or export
  `XDG_RUNTIME_DIR` as an absolute directory only you can write), while the other runs go on without a runtime
  directory, so with no `TEGO_REASON` (`tego.log` says why). Each restored mode is a `gap what=record
  why=own-state-mode-restored` naming the path in the run's ledger, which the receipt and `tego status` count as no
  lost action. A root launcher restores none (it reads and writes through any mode); its agent can take the modes of
  your own state above, which your next unprivileged `tego run` restores, so if you launch only as root, restore them
  by hand for your own `tego status`, `events` and dashboard. Restore by hand too a link at one of these names (left
  alone), an earlier run's directory, the directory of a run whose launcher died, `$XDG_RUNTIME_DIR` itself (at mode
  0 every later run is refused `[run]`: no runtime directory can be made in it), a directory inside a run's runtime
  directory (its `CODEX_HOME`), which otherwise keeps that runtime directory, `auth.json` included, until you log out,
  and the files you write that tego only reads (a `$TEGO_CONFIG` outside `~/.tego`, `prices.yaml`, the profiles and
  the registry): `chmod 700` a directory, `chmod 600` a file. While a run lives, its agent can still take the modes of
  its own run directory, which keeps `tego status`, `events` and `stop` out of it until the run ends: stop such a run
  with Ctrl-C in its terminal or a signal to its launcher.
- **Another manager's cgroup programs.** A program attached to a cgroup at or above the runs' without
  `BPF_F_ALLOW_MULTI` (`bpftool cgroup attach`'s default) refuses every run's program of that attach type: a root run
  stops before the agent starts (exit 125, `ErrCgroupAttachConflict`), and `sudo tego doctor` fails the same program's
  row first. Both name the cause and `bpftool cgroup tree`, which shows the holder; detach it, or attach it again with
  `BPF_F_ALLOW_MULTI`. systemd attaches its own programs that way, so they do not conflict.

## Tier 3 and the decision plane
Tier 3 (`bpflsm`) is the kernel decision plane in LSM mode, on top of tier 2 (`docs/p0/enforce-plane.md`, ADR 0024).
The same programs also load as `fmod_ret` hooks, which is how tier 2 decides opens, execs and file mutations in the
kernel where `bpf` is not an active LSM. `sudo tego doctor` says which it is:
`decision plane: fmod_ret (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=); build 1a2b3c4d, ...`. The
build is the first 8 characters of the binary's object hash, the name of its pin directory. Where `bpf` is already
in `lsm=`, fmod_ret is the pin's doing (`bpf.plane pins fmod_ret`) or LSM mode's failed probe (`tier 3 needs LSM mode
to pass, see the lsm mode line`, whose detail and fix say why); editing `lsm=` fixes neither.

- **LSM mode by distribution.** `bpf` is already in the boot `lsm=` list on Debian 13, Fedora, RHEL 9 and 10 and
  Amazon Linux 2023: tier 3 needs no change there. Ubuntu (24.04, 25.10, 26.04) and the stock WSL2 kernel lack it.
  Doctor's `lsm` line then fails for tier 3 only (tiers 1 and 2 are not affected) and prints one fix built from the live
  list, so no LSM the machine runs is dropped: `update-grub` after editing `GRUB_CMDLINE_LINUX_DEFAULT` in
  `/etc/default/grub` on Debian and Ubuntu, `grubby --update-kernel=ALL --args="lsm=..."` on the RHEL family, Fedora and
  Amazon Linux 2023; then reboot. An Ubuntu cloud image sets that variable again in
  `/etc/default/grub.d/50-cloudimg-settings.cfg`, so there the line goes in a later file in that folder. `tego run --tier bpflsm` without LSM mode is refused with that line, never run at
  another tier.
- **`fmod_ret` and its residual.** Without `bpf` in `lsm=`, tier 2 runs the plane as `fmod_ret` hooks on the `security_*`
  functions. A refusal there skips the other LSMs' hooks for that access, so AppArmor's own check and its audit record
  of that access do not happen. A kernel built with Clang LTO, which can inline a `security_` function at a call site,
  has no `fmod_ret` mode.
- **`bpf.plane`** (`auto`, `lsm`, `fmod_ret`) is honoured from `/etc/tego/config.yaml` only, like `bpf.linger`: a
  user's layer that sets it gets a warning and changes nothing. `auto` takes the best mode that passed doctor's probe,
  `lsm` before `fmod_ret`, else the fanotify fallback. A pin to a mode that did not pass falls back to fanotify at tier
  2, said so on doctor's line; tier 3 never falls back.
- **Pin layout and gc.** A plane mode's programs, maps, links and fill filler live in
  `/sys/fs/bpf/tego/<bpf_hash>-<mode>/`, next to the build's own `<bpf_hash>/`, where `<bpf_hash>` is 16 hex characters.
  They are removed with the build: idle for `bpf.linger`, or now with `sudo tego gc --builds`. A build is never removed
  while a live run's row names it.
- **Row caps.** A run's contract becomes rows the kernel walks: at most 4096 file rows (one per keyed inode) and 1024
  exec-map entries (the exec entries, the bare names and one policy row) a run. A contract over either cap is never
  truncated, since a row left out is a rule the kernel does not apply: `tego compile` reports `[unenforced]` naming
  `bpflsm`, as an error when the contract compiled to tier 3 and as a warning when an `auto` run may land there, and
  the run is refused at Prepare. The fix is narrower `fs`, `deny_read` and `exec.allow` entries (one entry per directory
  rather than per file), or `tier: cgroup`. The built-in `.env` scan can name up to 50,000 files. Since 2026-10-27
  (ADR 0043) a table past 1,024 keyed paths drops the per-file rows of covered files beneath a write entry, which its
  name entries refuse by name (`tego compile` prints the compaction line), so a project with 4,500 such `.env` files
  stays at tier bpflsm; files that are not beneath a write entry, or have a second link, keep their rows. Name entries
  have their own caps a run: 64 entries and 64 name rows, 8 scope directories, 4 prefix lengths and 8 leads (a name's
  first eight bytes); an entry past one keeps its compile-time expansion only, which `tego compile` reports
  `[unenforced]`, and the run's `fs.deny_read.created_later` is then false.
- **Lockdown.** Under `lockdown=confidentiality` the kernel refuses the probe-read build, so only the build that reads
  through `bpf_rdonly_cast` loads: Ubuntu 24.04 and later, Debian, Fedora and RHEL 9.8 have it and load;
  Amazon Linux 2023's 6.1 has no `bpf_rdonly_cast`, so under confidentiality it has no plane mode and tier 2 decides by
  fanotify, and `--tier bpflsm` is refused. A kernel without `bpf_loop` (below 5.17 without a backport) also has none.
  Doctor's line names which condition rules the modes out.
- **Cost per open.** The plane's lookup costs about 0.2 µs an open, and LSM mode 25 to 72 ns more than `fmod_ret`. The
  budget kill test 4 holds tier 3 to, 2 µs an open, is for `record: summary`, the default. `record: full` adds the
  recorder's own cost on top, 65 to 110 µs an open in a 2026-09-30 review, which is the recorder's and not the plane's.
  While a build is attached, every open, exec, mmap and path operation on the host pays the lookup, and a host process
  is never decided. Every plane run carries the built-in `.env` name entries, so the figures above are with the name
  check on (2026-10-20, 6.17: kill test 4's excess 916 to 986 ns, Prepare's fill with 64 name rows 0.14 ms more); what
  the name check alone adds to an open (ADR 0043's 30 ns target, 1 µs for a refusal) is below what the guest perf
  suite resolves so far (enforce-plane §10.1 condition 7).
- **Cold attach.** The first run of a build attaches its programs, which holds the kernel's ftrace locks for about 1.7 to
  3.7 s depending on the kernel; removal costs the same. Linger (`bpf.linger`, default 5 m) keeps the build attached
  after the last run, so a run soon after another pays 136 to 204 ms, not the attach.
- **What tier 3 does not decide.** Bytes read through a descriptor the run received from outside it (no
  `file_permission` hook), anonymous executable memory, code mapped from a readable file outside every write entry that
  was never modified, and an interpreter's own logic. It does not touch a process outside the run, and root can list and
  remove the programs.

## Sizing the ring budget
Each tier-2 run gets its own ring buffers (ADR 0026): a record ring, and a capture ring when it captures with
uprobes, each `record.ringbuf` bytes (default 2 MiB; a `record: off` run's record ring is a fixed 256 KiB). A ring
charges its size plus its page array in memlock: about 2.1 MB for a 2 MiB ring (an 8 MiB ring charges 8,433,944 B),
so about 4.2 MB for a run that captures. `bpf.ring_budget` (default 256 MiB) caps what every live ring of every build
on the host charges together, about 60 capturing runs at the default size. A run whose record ring would pass it is
refused, exit 125, naming the budget; one whose capture ring would pass it runs without capture, and is refused
`[capture-unavailable]` when it has a `tokens`, `cost_usd` or `repeats` budget. `sudo tego doctor` shows, in its
tier-2 builds section, how many run rings there are and what they charge against the budget, per build and in all.
Raise `bpf.ring_budget` for more concurrent runs; raise `record.ringbuf` only if runs report `ringbuf-full` or
`ring-buffer-drop` gaps (the reader drains every 50 ms and is woken at an eighth full). A run that captures with uprobes needs
`record.ringbuf` of at least 128 KiB, the room for two of the largest capture chunk; below that it is refused, exit
125, naming the minimum. Both are honoured from
`/etc/tego/config.yaml` only: a user's layer that sets them gets a warning and changes nothing. A launcher killed
before its teardown leaves its rings charged until its build's next run reclaims them.

## Exec command rules
`exec.deny`, `exec.ask` and words after a command in `exec.allow` name what a program is asked to do: a whole
command, a subcommand, or an option set ([ADR 0048](adr/0048-exec-command-rules.md); the per-tool rows are in
`docs/spec/exec-command-rows.md`). `tego compile` prints each entry's exact reading, the row that read it and what
it also matches; `tego compile c.yaml --exec 'git -C . push'` shows how one command line is decided in every tier. `compile` is a
static preview: the run is authoritative and fails closed, so `compile` may print `allow` where the run refuses on a
fact it does not read — a `#!` interpreter that is missing or unreadable, an execute-only image, a dynamic loader's
program given by a bare name or reached through a symlink, a second `#!` stage, or the file-identity interpretation
(a renamed or hard-linked tool). `compile` never refuses what the run allows.

| Recipe | Contract | What it does not cover |
|---|---|---|
| Never push | `exec: {deny: [git push]}` | `git send-pack`, `git http-push`, a git library in the agent's own code, `curl` to the server: bound those with `net` rules to the remote |
| No recursive deletes | `exec: {deny: [rm -r]}` | `find -delete`, `rm` on each file, a script's own unlink: bound them with `fs.write`. Deny `rm -r`, not `rm -rf`: without a tty plain `rm -r` removes the same tree |
| No publish | `exec: {deny: [npm publish, pnpm publish, yarn publish, yarn npm publish, cargo publish, twine upload]}` | a registry write over `curl`; bound it with `net` rules to the registry |
| Read-only git | `extends: base/read-only-git` (examples/profiles) | `git config <key> <value>` and `git branch <name>`, which write by operand count; the built-in `deny_write` set refuses writes to `.git/config` and `.git/hooks`, and the `fs` rules the rest of `.git` |

A deny entry wins over every allow entry, at any specificity; there is no exception syntax. `exec: {deny: [...]}`
with no `allow` key is a deny-list: images stay unrestricted. `exec.ask` is reserved and refuses every match.
Running the dynamic loader directly, `ld-linux-x86-64.so.2 /usr/bin/rm -rf tree`, is decided on the program it loads
(`command_via: loader`); an operand the supervisor cannot read as the loader will, such as a bare name the loader
would search library paths for, is refused `loader-unresolved`, and in a run whose images are restricted the program
must be granted like any image (`loader-program-unmatched`). In a deny-list run, a linked file in the run's own
generated `CODEX_HOME`, run by its path or through a descriptor, directly or through the loader, is refused
`codex-home-exec`: the run grants that directory for writing, and a copy of a denied program written there would
otherwise run under another name. The run's `hook-state` directory, which a harness provision adds (agent-contract.md
R27), is held the same way, refused `harness-state-exec` (added 2026-10-24). It is judged where the kernel says the file lies, so a directory there that the
agent makes unsearchable does not hide one (amended 2026-10-17). A copy there that the agent opens, unlinks and runs
through its descriptor runs fileless, as a memfd copy does (R2 below). Under an allow-list contract the run admits
the harness hook a provision names with its exact argv and nothing else (added 2026-10-25, ADR 0064):
`exec.harness-hook[<tego binary>]` in `run_start.runtime_grants`; any other `tego` command the agent runs is refused
under that rule, exit 126. Compile refuses an `fs.write` entry or `fs.ask` scope at or over the tego binary, the
`tego-control` beside it, or the ones PATH finds (agent-contract R10). Keep the binary outside them by its other names too (no
bind mount of its directory into one), and give it one link, or the run drops the provision (`harness-hook-writable`)
and the agent learns of refusals through `TEGO_REASON` only. Keep it off a filesystem whose layers, image or device
lie under such an entry too: an overlay's layers, a loop device's backing file and an image the filesystem is mounted
from are checked, and a FUSE mount drops the provision (ADR 0064 D2, amended 2026-10-25); a layer reached only by
another spelling than the overlay's options give (container storage bind-mounted in elsewhere), a second mount of one
network export, and a host share's other names are not seen, so do not place the binary there. A multicall binary that re-dispatches to itself past
the matcher's depth bound (`busybox busybox busybox busybox busybox rm -r`) is refused `command-unresolved` rather
than allowed, since the applet it finally runs could be a denied one; so is an exec whose reading yields more
interpretations than the matcher keeps (32 per exec).

**Residuals, stated plainly** (ADR 0048's R1–R13). Command rules are launch rules: they see execs, not effects.
- R1: a program that does the work in process (a git library, Python or Node code, bash loadable builtins, busybox
  `sh` applets) or talks to the service directly (`curl` to the registry) is no exec of the named command. The
  boundary for effects is the `fs` and `net` rules.
- R2: a copy of a binary under another name is matched by its names; identity covers links and bind mounts of
  one-link binaries only. In deny-list mode beside `fs.write` the agent can copy git and run it, and compile warns
  (`exec-rule-coverage`); restrict images with `exec.allow` to close it. Without a write entry it can still run a
  copy from a memfd or from a deleted file (one written into the run's `CODEX_HOME`, opened, unlinked and run
  through its descriptor: `codex-home-exec` refuses only a file still linked there), recorded `allow` unmatched
  with `fileless`, and map a program's file into its own process, so compile warns on every deny-list (amended
  2026-10-16). A deny entry refuses a command, never the program's code.
- R3: rewriting from outside argv is not read: cargo, gh and aws config aliases, kubectl `kuberc` aliases, and
  environment that changes parsing (`POSIXLY_CORRECT`, `GIT_CONFIG_PARAMETERS`, `NPM_CONFIG_*`). git aliases re-exec
  and are seen; git's autocorrection is read.
- R4: rows are versioned data; a tool release can add an option, an alias or a helper. Unknown options fail closed
  for deny entries; a new helper is refused until its row lists it.
- R5: at tier 1 and the fanotify fallback an allow is the supervisor's copy of argv, and a sibling thread can rewrite
  argv before the kernel copies it again (`TestIntegrationExecRuleRaceTier1` measures it); the cell
  `exec.rules/argv` is in `run_start.best_effort`. A refusal is exact.
- R6: at the plane tiers the kernel holds a pinned run's execs to the decided facts (ADR 0048 P2) only where the
  plane's mode passed doctor's exec pin cell (`plane.exec_pin`); elsewhere, and for a run Prepare could not pin,
  they are R5's case too, and `exec.assurance: kernel` refuses such a run.
- R7: an exec whose verdict depends on argv past 8192 arguments or 128 KiB is refused, naming the bound.
- R8: the gate's `exec matches` reads names and argv only.
- R9: interpreter dispatch covers the named entry points (`python -m pip`, `node npm-cli.js`); code given with
  `-c` or `-e` is not a command.
- R10: options an allow entry does not name are free: `git push origin feature/*` allows `--force`; deny the option.
- R11: an allowed entry's helper closure admits direct use: under `allow: [git fetch]` the agent can run
  `git rev-list` itself; compile prints each entry's closure.
- R12: documented rows are not checked against a binary; compile prints probed or documented on each line.
- R13: an image whose first bytes the supervisor cannot read is refused (`image-unreadable`): its `#!` line could
  name any ruled tool. At tier 1 that means every execute-only file the user cannot read (RHEL's `sudo`, mode 4111).
  At the root tiers the supervisor reads as root, which reads every local file. On an NFS export with `root_squash`
  root reads as the export's anonymous user, and a FUSE mount without `allow_other` or `allow_root` refuses root
  outright: in a run with command rules an image there that the supervisor cannot read or reach does not run
  (`EACCES`), even in a deny-list run. Mount it with `allow_root`, export it without `root_squash`, or run the tools
  from a local copy.
  The `#!` line of every other image is read, so `#!/usr/bin/rm -rf` is `rm -rf` to the rules.

**git's layout.** git re-executes itself and its helpers from its exec-path, which is another file than the `git` on
`PATH`: `/usr/lib/git-core` on Debian and Ubuntu, `/usr/libexec/git-core` on RHEL and a source build. An
`exec.allow` entry naming git grants that directory's `git` and the remote helpers its closure needs, derived from
where the resolved binary lies, and compile prints them.

## Completing the gate's opens in the run (`gate.completion: held`)
A gate's `fs.read` and `fs.write` rules score what the supervisor copied from the syscall, and by default
(`completion: copied`) an open they do not refuse is handed back to the kernel, which reads the pathname again: a
sibling thread that rewrites it in between opens what the gate never scored. That cell is listed in
`run_start.best_effort` as `gate.fs.read/open` and `gate.fs.write/open`. `gate.completion: held`
([ADR 0041](adr/0041-race-free-supervisor-decisions.md) Stage B) closes it: the run starts an open deputy
(`tego __open-deputy`, a process of the run with its Landlock domain, cgroup and credentials, under a seccomp
allowlist and not dumpable), every open of an fs kind the gate can score to `allow` or above (*amended 2026-10-20*, ADR 0007) is pinned by the deputy, decided
on the object pinned, opened by the deputy and delivered, and its ledger line says `gate_facts: held_object`.

```yaml
gate:
  completion: held
  rules:
    - 'fs.read matches "*.env"': 90
```

What it costs and what it leaves:
- Latency: a held open took 2–4× the copied path's median in the measurements (ADR 0041 §Performance, TARGET-MISS),
  which is why it is an opt-in. Only opens of a kind the gate can escalate are held.
- The run's processes cannot make Landlock domains of their own (`landlock_*` answer `ENOSYS`): an agent that
  sandboxes its tools with Landlock finds it unavailable. `tego compile` says so in its gate line.
- A deputy that cannot start fails nothing: the run warns `[held-unavailable]`, decides those opens on copied facts,
  and `run_start.best_effort` keeps the open cells (run_start's `capabilities` row `gate.fs_open_completion` is
  false). On a host with
  AppArmor, SELinux or Smack the run warns `[unenforced]`: a held open is made under the deputy's own LSM label, so a
  process the agent execs into a stricter profile is not held to that profile for its held opens.
- Still copied: `O_PATH` opens (`gate.fs.read/o_path`), non-open changes (rename, unlink, chmod and the rest:
  `gate.fs.write/mutation`), and the completion of an `fs.ask` or `fs.ask_read` approval or an alternate, which the
  supervisor makes as the agent's credentials.
- Held opens answer as the agent's own opens would, errno for errno, except where they refuse more: a process that
  made itself not dumpable gets `EACCES` for relative names (the deputy cannot read its working directory); under Yama
  (`kernel.yama.ptrace_scope` 1, Ubuntu's default) an agent's open of its own `/proc/<pid>/mem` is `EACCES`; and an
  open without `O_DIRECTORY` of an idle automount point itself opens the empty autofs directory instead of mounting
  it. Under a read gate a file whose name was removed cannot be reopened for reading through `/proc/self/fd`.

## A secret inside a writable folder: held reads (`fs.reads`, 2026-10-25)
Landlock cannot take a read away from a folder it lets the agent write, so a `deny_read` target at or beneath a write
entry, `./.env` under `fs.write: ["./"]`, was readable at tier landlock. Since
[ADR 0069](adr/0069-held-reads-make-deny-read-true-at-tier-landlock.md) such a run **holds its reads**: the open
deputy (the one `gate.completion: held` uses) completes every open that can read, and the supervisor refuses it on
the object the deputy reached, so `cat`, `grep -r`, `cp`, `tar`, a symlink and `/proc/self/cwd/...` all get
`EACCES` with a `read-denied` line naming the entry, while every other file reads as before.

```yaml
fs:
  write: ["./"]
  reads: auto    # the default: held at tier landlock exactly when a deny_read target lies inside a write entry
  # reads: held   # always held, so a .env.local made during the run is refused too, at every tier
  # reads: direct # never held: the nested target stays readable at tier landlock (warned, recorded)
```

`tego compile` says which reads are held and why, and warns `[held-reads]` at each nested target; `run_start.fs_reads`
records `held` or `direct` and why, and the capability rows `fs.deny_read.nested` and `fs.deny_read.created_later`
are true only in a run that held them. A `.env`, `.env.<x>` (not the example files) or a name a `deny_read` glob covers
that is made during a held run, by the agent or by anyone else, is refused by the name rule.

What it costs and what it leaves:
- **Cost per open.** A held read costs about 0.05 ms more than a direct one: `BenchmarkHeldReadOpen` measured a p50
  of 52 µs and a p99 of 77 µs (supervisor R22's soft ceiling is 200 µs) on an idle 6.17 host. `grep -r` (ugrep 7.8,
  multi-threaded) over 10,000 small files took 605 ms held against 35 ms direct, the medians of seven alternated runs
  on a 16-CPU host at load 2 to 4: about 57 µs more per open, and 10 of the run's 10,170 notifications took longer
  than 200 µs. A build or a test suite that opens many files pays that per open; `fs.reads: direct`, or keeping
  secrets outside writable folders, avoids it.
- **Not caught at tier landlock:** a nested target the agent renames or hard-links to another name before reading it
  (the capability row `fs.deny_read.moved` is false there, and compile's warning says so), and a target written by
  someone outside the run that the agent then moves. The root tiers cover the first where a decision plane decides:
  tier bpflsm refuses a rename or link out of a `deny_read` tree on the inode (Landlock's `REFER` rule), tier cgroup
  does in a plane mode, and on cgroup's fanotify listener the supervisor refuses one by the copied names, best effort
  (the matrix row `fs.deny_read.moved`). No tier's kernel covers the second: a file replaced from outside during the
  run is a new inode that no row keyed at launch names (ADR 0069 D5.2).
- **Refused that a direct run reads:** device files other than `/dev/null`, `/dev/zero`, `/dev/full`,
  `/dev/random`, `/dev/urandom` and terminals (`held-unsupported`): an agent that reads a GPU or another device needs
  `fs.reads: direct` or a root tier.
- **The deputy is required.** A held run whose deputy does not start is refused before it begins (exit 125), never
  run with the target readable; its processes cannot make Landlock domains of their own (`landlock_*` answer
  `ENOSYS`); on a host with AppArmor, SELinux or Smack the run prints ADR 0041 D2's label residual as a note tagged
  `[held-label]` ("on AppArmor a file read that tego checks and opens for the agent is decided by the contract's rules;
  a tighter AppArmor profile on the agent is not applied to it"; a run whose gate holds its opens says "a file open that
  tego checks and makes"): the deputy opens under its own label, so a tighter profile or domain on the agent is not
  applied to a held open.
- `record: summary` keeps no line for an allowed held read; every refusal has its line and reaches the reason file.

## Names made after a run started beside a `deny_read` (2026-10-26)
At tier landlock an enforced `deny_read` is built from one listing, at launch, of each directory above the target:
every name there is granted, the directory itself only lists. A directory or file made in one of those directories
after the run started, and a listed file replaced by a new one (an editor's save by rename), are therefore unreadable
to the agent for the rest of the run, and so is everything beneath such a directory; a new file inside a directory
that existed at launch reads as usual, and `ls` of the new directory still works. With the built-in `~/.ssh` entry
`$HOME` is one of those directories: a top-level entry made in `$HOME` during a long run is unreadable to it.

The record says so: such a read or exec gets `EACCES` from the supervisor and a `refused` line, `read-denied`, rule
`deny-read-snapshot` (`tego events <run> --rule deny-read-snapshot`), where it said `allow` before 2026-10-26. A run
records it wherever it sees opens: `record: full`, held reads, an `fs.ask_read`, a read gate or `reason.reads: on`. Remedy: stop the run
and start it again, which lists the directories anew ; for a 24/7 agent, keep what it must read beneath a directory that exists before it
starts, or put the secret outside the trees the agent works in.

## Telling the agent why a secret read failed (`reason.reads`, 2026-10-25)
At tier `landlock` under `record: summary` or `off` the seccomp filter tells tego of no read open, so a read of a
`deny_read` file (`cat ~/.ssh/id_ed25519`) gets `EACCES` from Landlock and leaves no line, no entry in the reason file
and nothing for the Claude Code hook to say: the agent sees `Permission denied` and does not learn which rule refused
it. `reason.reads: on` has the filter tell the supervisor of every read open
([ADR 0077](adr/0077-reads-recorded-for-the-reason-channel.md)): an allowed read is let through with no line, and a
refused one writes one `refused` line, `read-denied` under the `deny_read` entry, `mechanism: landlock`, which reaches
the reason file and the hook. The agent's `EACCES` is unchanged.

```yaml
reason:
  reads: on      # record a read Landlock refuses; costs every read open (below)
  # reads: auto  # the default: off, as measured
  # reads: off
```

**Cost, and why the default is off.** `test/bench/read-notify` measured 17 µs more per open (the median; 2 µs an
open without it, a p99 of 60 µs against 3) and the offline Claude Code workload of `test/poc/interactive-claude` 19 %
slower, past the 5 % ADR 0077 allows a default, at load below 2 on a 16-CPU host; two runs on the loaded box measured
19 to 26 µs and 28 to 44 % (ADR 0077's table). `tego compile` prints a
`reason-reads-off` line with them and the opt-in, and every run's `run_start.reads_notified` says whether its reads were
told to tego and why (`reason`, `reason-off`, `held`, `record-full`, `gate`, `ask-read`, `kernel`, `records-only`,
`no-supervisor`). Turn it on for an interactive agent that should be told why a read failed; leave it off for a build
or a scan that opens thousands of files.

What it does not change:
- A run that already tells tego of reads (`record: full`, an `fs.read` gate, an `fs.ask_read` entry, held reads) records
  such a refusal whatever the key says, and `on` adds nothing there: each refused read is one line.
- A root tier records a refused read in the kernel's record (tier 2's recorder, tier 3's plane): the key is ignored
  there and no decision leaves the kernel plane. An `--observe` run refuses nothing and ignores it too.
- Under `record: off` an allowed read is activity for `limits.stall_after` once reads are told to tego.
- Still unrecorded at tier landlock (spec/reason/REASON-CHANNEL.md §2): the mount family's `EPERM`, a `bind(2)` with no
  `net.listen`, a read when reads are neither told to tego nor held, and another LSM's refusal (recorded `observed`,
  `by: other`).

## Live blocks: refuse something in a running run, now (`tego block`)

`tego block <run> exec|net|path|read|write <value>` refuses a program, a destination or a path in a run that is running, within
about a second, without touching its contract; `tego unblock <run> <kind> <value>` takes the block away again (refused, exit 1 `[governed]`, when
it runs inside a tego run: an agent cannot lift what governs it, ADR 0123; it also refuses inside a container with
its own cgroup namespace, where it cannot tell, as does a `tego rule` write that widens; run them from the host) and
`tego block --list <run> [--json]` shows the run's blocks (also for a run that has ended, where they are no longer
enforced). It is the terminal side of the dashboard's Block now: both write the same file in the run's directory
under the ledger root, which the agent cannot write, and the launcher records each change as a `gap` line
(`tego events <run> --kind gap`). An `exec` value is an absolute path, a directory ending in `/`, or a bare name
(`curl`). An absolute path is matched by name and by the identity of the file it leads to, so it refuses that file
under every name it has: a multi-call program (uutils' coreutils, busybox) is one file, and on a machine whose
`/bin/ls` is one, a block on `/bin/ls` refuses `cat`, `sleep` and every other applet too. `tego block` says so when
it places one ("Note: /bin/ls leads to …, one file with 115 names here …", from the file's link count, or a link
named otherwise that leads to it) and gives the bare name, which is matched by name only and refuses that name
alone; the dashboard's Block now says so too. `tego block` also notes a bare name no folder of its own PATH holds (a
typo, or a program not installed here) and an absolute path that is no file here now; either block still refuses
the program if it appears. A `net` value is `host[:port]`, an IP, a unix socket path or `@name`; a `path` value is an absolute path and
everything beneath it (a relative one is read against the working directory and printed as the absolute path), for
every file action; a value written through a link (`~/link/secret`, where `~/link` leads to `/data`) is resolved
once, when the block is written, and the block refuses the real path too (`/data/secret`; `tego block` and the
dashboard say so, and the overlay entry keeps it as `real`, overlay version 4). The block is in force with its value
alone first; the real path is worked out after it, by one walk with a budget (512 lookups, 250 ms), since a governed
agent can plant the links the walk follows, and added in a second write. When the budget runs out the block refuses
the value as written only, and `tego block` says so. A run whose launcher predates the real path (it makes no
`live-real` file in the run directory) gets the value alone: `tego block` names the path left uncovered and the
command that blocks it. A `read` value is the same, for reads only: an open that reads (`O_RDONLY`, `O_RDWR`, `O_PATH`), and
a rename or hard link with either end at or under it, which would give the file a name outside the block; it is
refused (exit 1, `[reads-unseen]`) on a run whose reads tego does not see, where it would refuse nothing. A `write`
value is the same, for changes only: an open for writing, a create, an unlink, a rename or link at either end, a
mkdir, a mknod, a symlink's own name, a truncate and an attribute change; plain reads go on. For every path kind a
rename of a folder above the block is refused too, so a move cannot carry the blocked files out of its reach. A `path`
or `read` block also refuses a watch of what it covers (inotify, fanotify or dnotify, which would report which of its
files are opened and changed; supervisor R36), on a run whose reads tego does not see as well; a `write` block refuses
none. A launcher older than the read and write kinds (a run whose `run_start` has `record_minor` below 24, such as one started
by an older binary) cannot read an overlay holding one: it keeps the blocks it last put in force, writes a
`live-block-unreadable` gap and ignores every later change, `tego unblock` included, until that block is removed. So
`tego block` refuses `read` and `write` on such a run (exit 1, `[launcher-too-old]`; block the `path` instead, which
it enforces), the dashboard does the same, and the Rules page offers such a run a path block for an added
`fs.deny_read` and no write block. After upgrading, rebuild `tego` and `tego-control` together and restart the runs
that should get read and write blocks. At tier 3 (a run whose `run_start` names `decision_plane` `lsm` or
`fmod_ret`) the kernel decides many file changes without asking the supervisor, so a `write` block there refuses only
the changes that still reach it; the Rules page offers no write block on such a run. A
block only tightens: removing one removes only what it added, never something the contract
refuses. A run that has ended is refused (exit 1, `[not-running]`): nothing would enforce the block; for its next run,
make it a rule of the contract (`tego rule`); `tego unblock` on such a run says its blocks ended with it, and leaves
its overlay as it ended. The dashboard's Block now and Remove make the same checks in the same words (one set,
`liveblock.CheckBlock`, which `tego lift`, `tego grant` and `tego restore` have a twin of in `CheckFence`), so a
Remove posted from a page left open across the run's end is refused too. A block
also outranks a person's answer: a held file open it covers that is waiting for an answer when the block lands is taken
back (its card leaves Approvals; `tego ask` no longer lists it) and refused under the block, and an approval that comes
back after the block landed opens nothing (SEMANTICS §6). A `net` block does the same to a held connect
or UDP datagram (a `net.ask` scope, a gate's ask, a `net.ask unix:` scope, and a first-write hold's ask): the pending
card is taken back within about 50 ms of the block taking effect (the dashboard's answer reads "Withdrawn: a live block
now refuses this") and the connect is refused `live.block[net:...]`; an approval that comes back after the block
landed connects nothing.

A `net` block is on a destination, not on how it is spelled (*since 2026-11-01*). An address is read unmapped and with
no IPv6 scope id, and a block that names this host names all of it: `127.0.0.1:P`, any other `127.x.y.z`, `::1`,
`0.0.0.0`, `::`, `localhost` (or a name under `.localhost`, with no lookup), one of this host's own addresses, or a
host name that resolved to one of these. On the block's port, every connect or send to any of those is refused under
that block, because a server bound to all interfaces answers on each of them and the kernel sends a connect to
`0.0.0.0` to loopback or to the socket's bound source address. So is a datagram to a multicast group, to
`255.255.255.255` or to one of this host's subnet broadcast addresses, which such a server hears too. It costs at most
another local server on the same port, or a group send on it, and a block with no port (`tego block net localhost`)
refuses every group and broadcast send of the run. A group or broadcast address names no host, so a block on
`224.0.0.1:P` refuses that address alone. A block on another machine stays on that machine: it does not follow a
broadcast or group datagram that machine also hears. While tego cannot read this host's addresses at all, a destination
on a block's port is refused, since either may be this host. This host's addresses are read from its interfaces and,
*since 2026-11-02*, from the `local`, `broadcast` and `anycast` routes of the kernel's routing tables its default
policy rules look up (`ip route show table local`, and those routes in tables main and default), so an address of an
AnyIP range (`ip route add local 192.0.2.0/24 dev lo`, or the same with `table main`) is one of its own, a broadcast
address set by hand (`ip addr ... brd`) is one of its broadcast addresses, and a datagram to an IPv6 anycast address
it joined (a forwarding host joins its subnets' router anycast addresses) is refused as a group datagram is; a block
on an anycast address refuses that address alone. Such a route in another table, which only a policy rule you add
(`ip rule`) or a VRF sends lookups to, is not read. Until the tables are first read the interfaces' addresses answer;
once read, the last reading stays in force while they cannot be read again. The `models[]` guard and a `net.allow`
host name's resolved-address check read this host the same way. GAPS C46 lists what the reading of this host's
addresses leaves out.

A `net` block on a host name refuses a connect the contract admits under that name by the name, and every other by the
addresses tego's own lookups of the name answered. Those are every address answered while the block stands (*since
2026-11-02*; before, the last answer alone, and no lookup between changes to the run's blocks): the name is looked up
when the launcher first reads the block, again at each later change to the run's live-block file, and again every
minute on its own, and each answer is added to the ones before; a lookup that fails or answers nothing drops none and
is tried again a minute later. A host is held with at most 64 addresses from those lookups (past that, the one
answered longest ago is dropped), besides what the lookup at the last change answered, which is never dropped. Under a
contract with no `net:` section nothing admits a connect by name, so those addresses are all a block matches: an
address the name's DNS gives the agent before tego's lookups have answered it, such as a CDN's next rotation, is not
refused until one does. A removed block takes its addresses with it, and the same block added later starts from a new
lookup. A host an Adjustable run's fence also names (ADR 0125) is held for the whole run, and looked up every five
minutes while no block names it.

A block is matched against the address the supervisor copied from the agent, so what a thread of the agent does after
that check matters (*since 2026-11-01*). While any `net` block exists, every connect and TCP Fast-Open send on an IP
socket is performed by the supervisor on that copy, whatever the contract says, so rewriting the address afterwards
reaches nothing. Two things stay as they were, and a thread racing the check can pass a block through either
(GAPS C47). An addressed datagram is sent by the kernel from its own read of the address: one whose copy the block names
is refused, and one a sibling rewrites after the check is sent there under a line that says `best_effort: true`. And
under a contract with no `net:` section and `host_sockets: true`, a connect on a socket that is not IP stays the agent's
own, with its own credentials and Landlock scope: a sibling can rewrite a unix path to one a block names, or swap an IP
socket onto the descriptor and rewrite the address. Under a `net:` section, and with no `net:` section and no
`host_sockets: true`, the supervisor performs those connects too.

What a block does to the run is said in one word, here and on the dashboard (`tego block --list` prints it beside
each block, `--json` as `state`): **in force** once the launcher has written the gap line confirming it (about half a
second after the write), **waiting** until then, **refuses changes only** for a path on a run whose reads tego does not
see (held reads, `fs.reads: held`, or `record: full` let it refuse reads too), and **recorded, not enforced** on a
`tego watch` run: a watched run refuses nothing, so a block there is written and marked on each matching line while
the agent goes on, and `tego block` says so (`recorded, not enforced: run <id> is a tego watch run`, exit 0). A
`tego unblock` from inside a run's cgroup is refused (`[governed]`): a governed agent may tighten a run, never loosen
it. A `tego block` from inside a run is refused too unless it names that same run (`a process inside a tego run cannot
change another run's governance`, `[governed]`, exit 1): an agent may narrow its own run, never another's, which it
could starve while the record showed the block as placed from a terminal. The caller's own run is read from
`/proc/self/cgroup`; a caller that looks inside a run but whose run cannot be named is refused whatever it names. A same-uid process can still write the overlay file directly; a `tego watch` agent is unconfined.

### Time limits: a block that ends by itself, and unblock for a while (ADR 0125)

`tego block <run> <kind> <value> --for D` or `--until T` places a block that ends by itself; `tego unblock <run>
<kind> <value> --for D` or `--until T` is an **unblock for a while**: the block stays in the run's overlay, refuses
nothing until the limit, and refuses again from then on. Every run has them, Locked or Adjustable.

- `--for` takes a Go duration plus the units `d` (24 hours) and `w` (7 days): `45m`, `72h`, `3d`, `1d12h`, `7w`.
- `--until` takes `17:00` (today if still ahead, else tomorrow), `tomorrow 09:00`, `Fri 17:00` (the next Friday,
  strictly after now), `2026-11-14 17:00` (this machine's local zone) or RFC 3339 (`2026-11-14T17:00:00Z`). Clock
  times follow daylight-saving changes in the local zone.
- A limit is 1 minute to 400 days ahead; both flags together, an unread spelling or a limit out of bounds is a usage
  error (exit 2) that lists the accepted forms.
- The output keeps its first line (`<run>: blocked live.block[exec:/bin/ls]`) and says the limit on the next one
  (`Time limit: until Fri 31 Oct 17:00 (in 3 days); then it ends by itself ...`). Without a limit the output is
  byte for byte what it was.
- The run's launcher records the end: `live-block-expired` when a block ends, `live-unblock-expired` when an unblocked
  block refuses again (`tego events <run> --kind gap`). The change takes effect at the instant itself; the line follows
  on the launcher's next poll, within 500 ms.
- A block only narrows: a second `tego block` with a limit never shortens a block already held (one with no end, or a
  later end, keeps it, and the output says so). Shortening a block is an unblock. An unblock whose limit is at or
  after the block's own end removes the block for the rest of the run, since it would never refuse again.
- `tego block --list` prints each block's end (`ends Fri 31 Oct 17:00 (in 3 days)`) and, for one unblocked for a
  while, when it refuses again (`unblocked until ...`, state **dormant**); a block past its end is **expired** until
  the overlay drops it. `--json` carries `until` and `dormant_until`. The dashboard's run page, Rules page, Saved page
  and line page show the same states (internal/check/livestatus `StatusAt`): a dormant or expired block is never shown
  as in force.
- These states are read on this machine's wall clock. The launcher ends a block only once its wall clock and
  CLOCK_BOOTTIME have both passed the limit, and ends an unblock for a while once either has. So after a clock change
  the run may refuse longer than a view says, never less; `--list` says so under a list that holds a limit.
- A run started by a tego without time limits (`run_start` `record_minor` below 25) refuses a limit: exit 1,
  `[launcher-too-old]`, with nothing written. Place the block without one, or restart the run.
- A limit stops new access only: what was already read or copied, open files and live connections stay.

### Adjustable runs: lift, grant, restore (ADR 0125)

A run whose contract chose `live.mode: adjustable` has a **fence**: access the kernel layers allow the run, which
Tego's live layer refuses from the run's first instruction until the operator lifts it. Inside the fence a running
run can be loosened and tightened again without a restart. A Locked run (the default) loosens only from its next run.
The two modes, and what each one's guarantee is, are compared in docs/adr/0125-locked-and-adjustable-modes.md
and docs/user/live-modes.md.

- `tego lift <run> <read|net|exec> <value> [--for D | --until T] [--yes]` allows a fence entry that is one of the
  contract's refusals; `tego grant` is the same request, worded for a fence entry that is new access.
- `tego restore <run> <read|net|exec> <value>` refuses the entry again, now. It narrows, so it needs no confirmation,
  and from inside a run it may name only that same run.
- Before a lift or a grant, the command says what the run will be able to do, for how long, and: "Enforced by
  Tego's live layer, not the kernel. A time limit stops new access; what was already read or copied, open files and
  live connections stay." An `exec` entry is best effort: a copy of the program under another name runs wherever the
  agent can write and execute.
- At a terminal the person types `lift` (or `grant`) to confirm; anything else exits 1, `[not-confirmed]`, with
  nothing asked. Without a terminal `--yes` is required; without it the command exits 2 and writes nothing.
- The limit is read again at the confirmation: a `--for` span counts from it (the new end is printed when it moved),
  and a `--until` that passed, or came within a minute, while the person typed asks nothing (exit 2).
- The request goes into the run's overlay with a MAC under the run's `live-key`; the run's launcher checks it and
  records what took effect (`live-rule-lifted`, `live-rule-restored`, `live-lift-refused`, and `live-lift-expired` at
  its limit). The command waits up to 3 s for that line and prints it (`<run>: lifted live.fence[read:/srv/billing]`),
  or `Asked; the launcher applies it within a second` when none came. It reads only the lines appended after its
  request, so a long run's ledger is not read again from the start.
- Refused, exit 1, nothing loosened: `[governed]` from inside any run (an agent can never loosen its own rules);
  `[locked]` on a Locked run; `[outside-fence]` for an entry the run's fence does not list (change the rules; it
  applies from the next run); `[not-running]`; `[no-key]` when the run's key cannot be read; `[launcher-too-old]`
  for a limit on a run whose launcher reads none; and the launcher's own refusals in brackets (`[mac]`,
  `[outside-fence]`, `[locked]`, `[until]`).
- "Permanently" is two steps: the lift, and the same change written into `agent.yaml` with Change rules or
  `tego rule` (previewed, journaled, undoable), so the next run agrees. Change rules says **Live now** on the line of
  a running Adjustable run whose fence lists the widened entry, with a link to the run's fence on the Rules page. An
  addition (`fs.read`, `net.allow`, `exec.allow`) matches only a fence entry that is new access, and a removal
  (`fs.deny_read`, a whole-program `exec.deny`, a bare name included) only one that is a contract refusal: a lift
  that the saved change would not also make for the next run is not offered as its Live now. The Saved page and the
  line page list the change under "Next run" and link to the run's fence.
- A lift does not outlive its run: a new run starts with every fence entry refused.

## Pause and resume a running run (`tego pause`, `tego resume`)

`tego pause <run>` freezes a running run where it stands; `tego resume <run>` lets it carry on. The dashboard's run
page has the same Pause and Resume beside Stop run. Both write the pause into the run's live-block file (the same
file, lock and serials as `tego block`), and the run's launcher, which owns the run's cgroup, applies it within
about half a second: it writes `cgroup.freeze` of the run's own `run-<id>.scope` (cgroup v2, kernel 5.2 or later;
nothing above the run is touched), waits for `cgroup.events` to say `frozen 1`, and records a `gap` line
`enforce: run-paused` naming who asked (`tego events <run> --kind gap`). Resume writes `run-resumed` the same way. A
freeze took about 9 ms on a looping agent, which made no progress while frozen, and works the same on a `tego watch`
run (a freeze needs no contract decision).

While paused, the run's processes neither run nor handle signals. `limits.stall_after` does not count the pause;
`limits.wall` keeps counting (keep demo pauses short: Codex's own model stream may time out after about 30 s of
silence). `tego stop` on a paused run thaws it first, so it ends as quickly as a running one (`reason=stopped`, not a
stop_grace kill); a SIGKILL still ends a frozen process. A run that ends while paused is thawed as it ends.

A run cannot be frozen while one of its requests waits for a person: the agent's thread waits inside the kernel for
the answer, where the freezer cannot reach it. So answer the request first, then pause. The dashboard offers no Pause
while a request waits, and says why. `tego pause` asked then gets `pause-failed` (the run keeps running), and the
launcher freezes the run as soon as the request is answered, unless a resume withdraws the pause first. A freeze
that lands while a held read is in flight (the open deputy answering for the agent) is thawed and tried again at
once, up to about nine times within a second. If the launcher still cannot freeze the run (a root-owned scope, a
kernel without `cgroup.freeze`), it writes `pause-failed` once, leaves the run running and tries again after 2 s,
then 4 s, and so on up to every 30 s, until a resume withdraws the pause. A resume of a pause that never took writes
`run-resumed` at once. A thaw that fails writes `resume-failed` and is tried again every half second.

`tego status` shows a paused run as `paused` in its STATE column (`pausing` or `resuming` while the launcher has not
answered yet); `--json` keeps `state` as derived and adds `"paused": true` and `pause_pending`. A paused run that has
gone quiet past `limits.stall_after` is not reported as stalled: its STATE stays `paused`, `tego status` exits 0 while
the pause lasts, and the launcher does not count the pause against `stall_after`.

A process inside a tego run is refused (`[governed]`, exit 1), for pause and resume alike, and so is a run that has
ended (`[not-running]`). A same-uid process outside every run can still write the run's `cgroup.freeze` or the
live-block file itself (ADR 0123).

Only a run whose launcher reads a pause can be paused. Such a launcher makes an empty `live-control` file in the run
directory once its live-block poll runs over a cgroup of the run's own; `tego pause`, `tego resume` and the dashboard
look for it. A run without it (one an older Tego started, an adopted run, or one with no cgroup of its own) is refused
(`[no-pause]`, exit 1) and the dashboard offers no Pause on it. This matters beyond the pause itself: an older
launcher refuses the whole live-block file once it lists a pause (`live-block-unreadable`), so every later
`tego block` and Block now on that run would stay waiting, and withdrawing the pause would not bring them back. Stop
the run instead.

An agent that keeps a request waiting all the time (it asks again as soon as each answer comes) cannot be paused,
since a waiting request cannot be frozen. Deny it for the run, or stop the run.

## Precommit modes (2026-10-28)

`scripts/precommit.sh` has three modes. The policy is fixed: **every merge to main runs the full gate**; the scoped
and docs modes are for in-between checks (an agent's run before it hands a branch over, a merge queue's early
rejection) and never replace it.

| Mode | Command | What runs |
|---|---|---|
| Full (merges) | `make precommit` | Every step on every package, as CI's build-test job. |
| Scoped (in-between) | `make precommit-affected BASE=<rev>` (or `TEGO_PRECOMMIT_SINCE=<rev> scripts/precommit.sh`) | What `tools/affected` selects for the change since the merge base of HEAD and `<rev>` (default `main`). |
| Docs (in-between) | the same command, when only Markdown changed | `rulecheck`, `check-spdx` and the tests that read Markdown. |

Markdown under a global directory (`scripts/README.md`, `tools/README.md`, `test/vm/*.md`, `.github/*.md`) takes the
full gate like any other file there: the gate's scripts may read it, and the selection does not try to tell. Only the
full gate prints `precommit: every step passed`; the scoped and docs modes end with `precommit: every selected step
passed (<mode> mode since <rev>; not a merge gate)`. `make precommit` and `.githooks/pre-commit` clear an inherited
`TEGO_PRECOMMIT_SINCE`, so a variable left in a shell never turns the merge gate into the scoped check.

**Parallel full gate.** The steps run in three phases: the static checks (gofmt, the four vets, both golangci-lint
runs, check-spdx, check-licenses, shellcheck, check-skiplists, check-exits, check-fd, rulecheck, isocheck,
bpf-objects, the script self-tests, actionlint) concurrently, the lint job (the longest) started first; then the
unit tests, followed in the same job by the tegotesthooks tests; then the integration tests alone. `TEGO_PRECOMMIT_JOBS` caps the jobs running at once; the default is
min(nproc/2, GB/2), where GB is the lower of MemAvailable and the least that any of the process's cgroups has left
(`memory.max` less `memory.current` without its `inactive_file` page cache), never below 1. Every test
pass gets `go test -p <jobs>` and `-count=1`: go test's result cache rechecks only the files the test process itself
opened, so a test whose verdict comes from a `go build` or `go list` it runs, or from a binary it built (the link
gate in internal/control, askclient's and capture's import checks, examples/supply-chain-demo,
internal/control/web/e2e and the other binary-closure suites), would replay a stale pass. The two golangci-lint runs
and the script self-tests share one job: golangci-lint refuses a second instance while one holds its lock ("parallel
golangci-lint is running", which the gate wrapper retries on), and check-fd_test.sh and check-edgelint_test.sh run
it. Each step's output goes to its own file and is printed in the fixed order, with its duration, whatever finished
first; a step that fails prints its output; a step that is killed (a signal, or its job's shell killed before it
wrote its status), or never reported (its phase never ran), is a FAIL, never ok; a step of an unknown phase is
refused and fails the run; an interrupt stops the running steps and everything they started. `TEGO_PRECOMMIT_JOBS=1` runs the steps one after another in the order they were added
(the order above); its output differs from the old serial gate's only by the durations and the "N job(s) at once"
line. scripts/precommit_test.sh holds the runner to this.

**Scoped selection.** `go run ./tools/affected -base <rev>` prints the selection and why (`-plan` adds the
directives precommit.sh reads). It lists the changed files (committed, staged, unstaged, untracked, deleted) and
classifies each:

- a global input (go.mod, go.sum, Makefile, `.golangci.yml`, `.github/`, `.githooks/`, `.goreleaser.yaml`,
  `scripts/`, `test/vm/`, `test/e2e/`, `test/*-skips.txt`, `tools/`, `internal/testutil/`, `bpf/`, `internal/bpf/`, `.gitignore`,
  LICENSE, NOTICE, THIRD_PARTY_NOTICES.txt, `LICENSES/`,
  a nested go.mod, a shell script outside a Go package, any `*_test.sh`, a test file that takes its directory on or off
  the tegotesthooks list, a file no package owns or names, a Go file of a directory no build lists): the full gate,
  with the reason printed;
- Go source: the package and every package whose build or test binary depends on it, per build (default,
  integration, tegobpf, integration+tegobpf, tegotesthooks; `go list -e -test -json ./...`, about 4 s for all five);
  a `_test.go` file: that package's tests; an embedded file: the embedding package; testdata or another file under a
  package's directory: its owner's tests (a deleted one, Markdown included: the owner's source, since it may have been
  embedded); a path a test names by literal (the leading literal arguments of a `filepath.Join` or `path.Join` call
  count as one path; a package directory above the test's own, a bare `".."`, is not a read of everything under it),
  or a known reader (`spec/record/` is `pkg/spec/record`'s, `examples/` is `pkg/spec/agent`'s):
  those tests. Scoped mode runs no script self-test, so the files they read are global inputs too:
  `internal/control/web/testdata/edgelint/`, `test/workloads/build/`, `test/workloads/python-httpx/agent.py`, and the
  two Go test files test/vm/fetch-kernel_test.sh reads tables from (`internal/platform/peer/peer_test.go`,
  `internal/runtime/enforce/landlock/integration_abi_test.go`). tools/affected's TestSelfTestFixturesAreGlobal holds
  every file a self-test names, and every fixture, to a global input. precommit_test.sh also holds two rules over the
  tree, which scoped mode keeps by going to the full gate: every `*_test.sh` is in ci.yml, and the tegotesthooks list
  in precommit.sh and ci.yml is the set of directories with test files behind that tag. Each integration build is
  listed both with `CGO_ENABLED=0`, as its tests run, and with go env's setting, as its vet runs, and the two are
  merged.

Two rules add tests whatever changed. The **source scanners** always run: tests that read the tree rather than import
the changed code (a walk, a parse of Go files, a repo-root path, `".."`), found by scanning test code and seeded with
`internal/askclient` TestLedgerTargetSingleSource, `internal/control/linkgate_test.go` and `pkg/spec/agent`
TestLiveOffGolden and `internal/runtime/capture` TestCaptureLinksNoEngine; a test the scan can name runs alone (`-run`), a read it cannot pin to a test runs the package
(benchmarks aside: go test runs none without `-bench`). The **binary closure**: a package whose tests name a module
package by its path (cmd/tego, cmd/tego-control, a test workload: `go build`, `go run`, `go list -deps`), or whose
test binary links a helper whose own code names one, runs when the change reaches that package's dependency closure
in any build (a `./...` or `.../...` pattern names every package under its directory, one the change adds included,
so a test that runs `go list ./...` over its own subtree runs when a new package there links something new), so `examples/supply-chain-demo` and `internal/control/web/e2e` run for a change anywhere under
cmd/tego. A deleted file under a package counts as that package's source (it may have been embedded), and
`test/e2e/`, where the shell self-tests live, is a global input.

When tools/affected gives no plan (a base git does not know, a tools/affected that does not build), the scoped
command runs the full gate. The scoped run then does gofmt, the vets over the affected packages per build, both
golangci-lint runs over the same affected packages (an enum value added in one package breaks `exhaustive` in an
unchanged one that switches over it), check-spdx, check-licenses (a Go-only change can link a new third-party
package), check-skiplists, check-exits, check-fd, rulecheck, isocheck, shellcheck over the changed scripts (a note
when it is not installed), and the selected tests through the same `gated-test.sh`, skip lists and `-count=1` as the
full gate; a build's test and `-run` lines share one job, and the tegotesthooks lines the unit job. What it
cannot see (a test reading the tree by a path built at run time from parts the scan does not recognise, a script a
Go test runs by a computed name) is why merges keep the full gate.

## Upgrades
See `docs/VERSIONING.md`. Installs replace by rename; a live run keeps its inode and the child stage execs
`/proc/self/exe`. Pins are keyed by `bpf_hash`, so two builds coexist during an upgrade window. Ledgers are never
rewritten; `compile --upgrade` rewrites contracts once contract version 1 exists, and until then refuses with exit 2
and says so (`limits-check-doctor-cli.md` R29).

## Logs of tego itself
`~/.tego/tego.log` (tegod instances, when a trigger builds them, log to the journal; ADR 0042), rotated at 10 MB, 5 files, `0600`, one structured
line per event with `run=<id>` when a run is involved; never the agent's data, never an event that belongs in the
ledger (dropped ring-buffer events are a `gap` event, a budget hit is a `limit` event, an orphaned run is
`run_end reason=orphaned`). Rotation takes a lock on `~/.tego` that any process of the user's uid can hold,
the agent included; while another process holds it the file grows to at most twice the limit, after which lines
are dropped, and the next rotation begins the new file with how many were. The level is `log.level` in the machine
config. `~` is the invoking user's home from the passwd database, so under `sudo` the log is the invoking user's
and the files a root run creates for it are handed to that user — only files and directories that process itself
created, never one it found already there. `$HOME` is read only by an unprivileged process without `AT_SECURE`
whose uid has no passwd entry; one with no passwd entry that runs with `AT_SECURE` or as root keeps no log.
`-v` (mirror the log to stderr) and `--log-level` are not built yet: they are global flags `cli.Main` would parse
before dispatching a command, and until it does the machine config is the only way to set the level.

## Tego's own network traffic
Past loopback sockets of its own (the self-test, the relays' listeners, the dashboard), exactly these connections and
no others: DNS lookups of the hosts named in a contract or in `tego block <run> net`, and the queries a cooperating
client sends through the DNS broker; an approved `first_write` hold's connection to the address it held; the MCP
relay's requests to a `url` server; the forwarder's upstream connections to hosts in `net.allow`, on the agent's
behalf, in a run with a `models:` list unless capture is `off` or a pinned `uprobe`.
`ask.notify: webhook:<url>` sends nothing: desktop/webhook notification adapters are not built. The machine config accepts this setting with a `config-ignored` warning; supported approval requests use the CLI broker. This setting does not configure the broker's request-timeout semantics. No update check, no
crash report, no usage metrics, no feature flags, and therefore no opt-out to set. Kill test 8 includes: with
`capture: off`, no `first_write` hold and no relayed `url` server, a packet capture over a full run shows no connections
from Tego's pids other than the configured resolver on port 53.

## Data handling (for production deployments)
Where: `<ledger_root>/<run>/`, a `0700` directory with `0600` files, on local disk only. Tego sends nothing anywhere.
What is stored: with `record: full`, every event plus the bodies of model requests and responses as content-addressed
blobs: prompts, tool outputs, and whatever the agent put in them (code, personal data, customer data). With
`record: summary` (the default), the same events without bodies; file paths, argv, hostnames and ports are still
stored. With `record: off`, `run_start`, `run_end` and every refusal (its path, host:port or argv included); advisory allow and observed events are dropped (docs/p0/record-ledger.md R12).
Never stored: `x-api-key`, `authorization`, `cookie` and other credential headers (header allow-list). `env.mask`
is not built (P2): `compile` refuses a non-empty one, so nothing is masked, and a secret passed to the agent in its
environment is recorded wherever the agent puts it (in a request body under `record: full`, in argv).
How long: `retention` in the machine config, default 30 days, applied by `tego gc` to the runs and to the rule-change
journal (`<ledger_root>/.rule-changes/`: the rules texts `tego rule` and the dashboard replaced), which keeps beyond it
what a run still in the ledger root reads (the lines since it started, those that name it) and each rules file's
newest 20 changes still standing while the file is there. `tego rule` given a run directory outside the configured
ledger root journals in that directory's parent, which no pass prunes: remove that journal with those runs.
Who can read: any process running as the same uid. `visibility` is a view filter, not access control; on shared
servers give each service its own uid and `ledger_root`, on an encrypted volume.
Teams with data-protection obligations: keep `summary`, set `retention` by policy, and tell the people whose prompts
and tool outputs a run records what is kept, where and for how long. Tego does not collect consent and cannot; the
operator is responsible for that notice.

## Threat model (the README paragraph)
Tego holds a mistaken or prompt-injected agent to its contract for files, network destinations and new processes,
enforced by the kernel below the agent's code. It does not stop what an allowed interpreter does in its own memory,
and it cannot prevent data the agent may read from leaving through any endpoint the contract allows: ordinary network grants match `host:port` and do not inspect how an opaque endpoint is used. An explicitly configured bounded `net.http` or fixed-model forwarder policy can additionally constrain the supported request facts; it is not arbitrary TLS, repository or database inspection. Data can still leave through requests and endpoints the policy permits, using the agent's credentials. Both published
exfiltrations of this shape left through `github.com:443` rather than an attacker's host (`docs/GAPS.md` A1). It is
not a sandbox: the process sees the machine, and reads are logged, not prevented, unless a path is in `deny_read`. It
never calls a model and never rewrites what the agent does; it refuses, explains and records.
