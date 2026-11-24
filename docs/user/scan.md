# Look for your agents

`tego scan` takes one snapshot of your own processes, installed program candidates,
settings metadata, configured MCP servers, systemd user units and current-folder
project hints. It saves that snapshot to
`~/.tego/scan/last.json`. It does
not start or change a process. It makes no network requests.

```sh
tego scan
tego scan --verbose
tego scan --json
tego scan --all-mine
```

The short report names the evidence: executable name, argv pattern, argv[0], comm,
a candidate path or a settings path. A process can choose argv[0] and comm. A name
is evidence of a match, not proof of a program's author or purpose. Installed
candidates need not work. A settings directory can be left over from an old
installation. Settings metadata reads no contents; the fixed MCP files below
are separate selected content sources.

`--verbose` (or `-v`) adds identity, rule and source details. It broadens no reads.
`--all-mine` lists eligible unmatched interpreters as well as their count. Tego
cannot tell whether these are agents. Descendants in the same matched session
are grouped. The footer always lists rules, read/not-read counts, unreadable
paths, limits and exclusions, even with hints disabled or output piped.
Per-source success rows are verbose only.

A process in a cgroup named for a run is labelled “in Tego run” only when the
record is live and started before the snapshot finished. Otherwise the report
says it is in a cgroup named for that run and could not be checked against the
record, with a fixed reason in the footer. This establishes neither enforcement
nor verification. Lost, ended or unreadable records and malformed bounded
start/tail reads keep
the conservative cgroup wording. A large record alone does not prevent the
check: it reads only a bounded start and tail, with writer-lock checks. Scan
pins and checks both files before opening their contents; other ledger readers
keep their prior file-open behavior.
The JSON membership field describes
only the cgroup fact; it carries no live-record assertion.

For CI, `tego scan --check` prints the report and **writes no saved result**:

| Exit | Meaning |
| --- | --- |
| 0 | No outside process match was observed, with no process gap, or unreadable programs were explicitly accepted with --allow-unreadable-programs. Configured sources do not decide this check. |
| 1 | At least one outside match was observed; this takes priority over process gaps. |
| 2 | Invalid flags, signatures or arguments; usage is printed. |
| 3 | No outside match among readable processes; some own program files could not be read, with no other process gap. The count and pids are reported. Tego cannot tell whether these are agents. |
| 125 | Refusal, unusable proc, output failure, or unknown process coverage, without a definite outside match. |

Processes that exited during reads, including zombies without a live task, are
counted under "Exited during the scan" with no detail. Kernel threads have their
own count. Neither makes check unknown. A live process that could not be
classified is a coverage gap.

Some own processes, including a systemd user manager or non-dumpable ssh-agent
and gpg-agent, do not let their program file be read. Scan says "N of your processes do not let their
program file be read" and gives only pids.
While `tego run`, `watch` or `start` runs, its own process is one of these too: it holds
secrets, so it makes itself non-dumpable, and a scan from another terminal reports it by pid among the unreadable programs, and says on stderr which of them is the launcher of a live run (`pid N is the launcher of run R`); it is still counted.
The dashboard (`tego-control serve`) holds its sign-in token and keys, so it is non-dumpable too. While it serves it holds a lock (`~/.tego/dashboard/lock`) that the scan proves the way it proves a launcher's, by the kernel's lock table and the process's start time, so a scan from another terminal does not count it among the unreadable programs and `tego scan --check` is not made exit 3 by a running dashboard. Every other unreadable program is still counted. What the lock proves is that the process holds it, not that the process is the real dashboard: a process of yours that took the lock while no dashboard ran would be left out too, so exit 0 never means that no agent runs outside Tego. A dashboard that could not take the lock (a second one, or a started-before-this-release one) is counted like any other.
Tego cannot tell whether these are agents; any program can make itself unreadable.
It shows no process name or arguments.
Default check returns 3 when this is the only uncertainty. An agent can set itself
non-dumpable to move from outside match (1) to unreadable (3), or to 0 in the
accepting mode. Exit 3 does not mean no agent runs outside Tego.
With `--allow-unreadable-programs`, exit 0 does NOT mean no agent runs outside Tego.
The explicit `tego scan --check --allow-unreadable-programs` mode
returns 0 for that case, with the same partial status, count and pids and
`check: none-observed-allow-unreadable`. Other gaps still return 125, and an
outside match still returns 1. The flag requires `--check`. JSON carries the fixed
`unreadable_programs_warning` field beside the count and pids, including when
the count is zero. Text and stderr footers repeat the warning for nonzero counts.

Without `--check`, successful partial scans exit 0 and disclose the gaps. A save
failure exits 125 and keeps the earlier saved result if replacement did not
occur. A directory-sync failure after replacement reports that disk state is
unknown. An unsafe scan directory is refused with a `chmod 700` repair; existing
permissions and ownership are never repaired automatically.

The saved file is private (0600 in a 0700 directory), bounded to 1 MiB, and
untrusted. Any program running as you can replace it. The reader rejects links,
special files, wrong owners or permissions, oversized data and invalid JSON.
At most eight distinct observed run ids receive record diagnostics. Any further
record checks become one named limit with an unknown remainder; existing process
observations remain in the partial result.
Fresh means this boot and no more than five minutes since the scan finished.
Historical evidence is never “running now”. Paths can themselves contain private
names. Argument values, environment blocks, credentials and ignored settings
values are never retained. Selected server names remain private metadata. Process environments are never opened.

The default catalog recognises the existing Claude, Codex, OpenCode and Gemini
rules. These are name and wrapper matches, not authenticity checks. Use a custom
signature when needed; matches get numbered user-rule names in the report:

```sh
tego scan --signature 'my-agent=python3 .../my-agent.py'
tego scan --no-default-signatures --signature my-agent
```

A same-name signature replaces that name's existing rules; `--signature name=`
removes them. At most 64 bounded signatures are accepted. An empty effective
rule list is a usage error. Never put credentials in a signature or a path.

Basic scope uses your real uid and the local passwd home, not HOME. Direct root
scans root's own processes only. A sudo invocation without `--advanced`, changed effective uid,
elevated nonroot capabilities, governed run or unknown/private cgroup namespace
is refused. Other users, unknown names, libraries without signatures, remote
agents, container attribution and processes outside the visible snapshot remain
excluded. Multiple or missing NSpid entries make a negative check unknown. One
entry does not prove host-wide visibility. No zero count establishes absence.

Project hints say "declares a dependency on" with a catalog id, never that it
is installed or running. Only `package.json` and `requirements.txt` in the current
folder are parsed. No parent, child, home or workspace walk is made. Fixed
`langgraph.json`, `crew.jsonc` and `config/agents.yaml` paths are metadata only.
Links and mount crossings beneath that folder are refused, including bind mounts.
A missing openat2 facility leaves F not read. Content is bounded to two files of
1 MiB each, depth 32, 4 KiB tokens, 4,096 tokens/lines and 128 entries per table.
The shared two-second deadline is checked between reads and tokens; it cannot
interrupt stalled filesystem IO. Invalid or unsupported syntax discards the
whole file's hints and lists its path as not read. Requirements includes, URLs,
options and continuations are unsupported and never followed. Files produced by
pip-compile with `--hash` or backslash continuations, and editable `pip freeze -e`
entries such as `-e git+https://...`, are refused as a whole with
"not read: unsupported". Versions, URLs,
scripts, comments, name/author fields and unknown dependencies are dropped.
[The catalog](../../spec/scan/v1/README.md) lists the exact supported names.

The permission exception is for discovery reads only. Settings, unit and project
content files must be regular, have one link and belong to you or root. Their
selected parent folders are checked too. World-writable files and folders are
refused. Ordinary 0664 files and 0775 folders made with umask 0002 can be read
only with complete local evidence: a local group entry lists no member other
than the inode owner, no other local account has that primary gid, and bounded
passwd, group and NSS reads all finish and parse correctly. Each account file
is read twice through fresh opens. Both reads must return
equal bytes, and descriptor/path identity and metadata must match within and
across passes. A difference or error refuses with accounts-unreadable; run the
scan again. There is no automatic retry. Root's in-place writes that leave
both reads seeing the same bytes are not detected, including changes undone
between passes and writes interleaved with one file's reads inside one timestamp
tick. Assuming account files are replaced
only by rename during collection, the combined evidence was true between the
two passes. Membership changed after the scan remains a limit.

This rule asks whether another, non-root user can write a discovery source.
Its account evidence comes from verified system files that only root can change.
The premise is checked, not assumed: in both passes, passwd, group and
nsswitch.conf must be regular root-owned files with no group/other write bits.
Every path component must be root-owned and exclude group/other writes,
including sticky writable ancestors. For the account-evidence collector,
root-owned symlinks are resolved by the shared config placement resolver; their
targets and target paths must pass the same checks. Symlink mode 0777 itself
grants no write authority. File bytes are read through the verified descriptors;
file and ancestor descriptors stay held through both passes and are rechecked after reads. Unverifiable placement
refuses accounts-unreadable with the account file, failed check and an
administrator repair. The shared resolver also requires readable account files
and searchable directories. System uses fixed /etc paths; test injection is
through unexported Go collection functions, never an environment variable or flag.

The account-evidence collector accepts verified links, but this does not mean
that the scan as a whole runs on linked account layouts. If /etc or /etc/passwd
is a symbolic link, the scan as a whole refuses before discovery: caller
identification rejects any link on the passwd route, even with root-owned,
verified targets. This pre-existing limitation affects store-path and
image-based distribution layouts that use those links, for example /etc ->
/usr/etc or /etc/passwd -> /usr/lib/passwd; the actual path layout decides, not
the distribution name. Text says "Read: none; scan not performed." The result
is failed, with exit 125, a meta source with reason owner and exclusion
scan-not-performed. No discovery runs and no new saved result is written. Ask
the distribution administrator whether a supported layout with a regular /etc
directory and regular /etc/passwd is available. Do not replace
distribution-managed links just to run scan. Where the linked layout is
required, scan remains unavailable; use recorded-run evidence instead. Caller
identification's refusal is unchanged.

The scan does not defend its account evidence against root editing account
files while it reads.

Both NSS account sources must be files-only. Missing entries, failed, truncated, malformed or
size-limited reads and directory-service or other non-files sources
(LDAP/sssd, or files plus systemd) refuse group write. Access ACLs or unavailable ACL metadata also
refuse this exception. Root-owned selected vendor files such as 0644 units in
/etc with 0755 parents still work without a group-membership lookup.

A shared primary group such as `staff` or `users` under umask 0002 leaves these
configured sources unread until its write bit is removed. The footer names the
refused group and the path at fault, including the parent folder when it is the
cause, and explains whether sharing, incomplete account evidence or an ACL
caused the refusal. Apply the command to that displayed path, for example:

```sh
chmod g-w -- "$HOME/.gemini/settings.json"
chmod g-w -- "$HOME/.gemini"
```

For world write, use `chmod o-w` on the displayed file or folder. For foreign
ownership, ask the owner to make an owned copy or correct ownership. Refused
sources remain not read with reason mode or owner. Account and boot metadata,
records, locks, run directories and `.tego` still refuse group or other write.
The saved scan remains 0600 inside a 0700 directory.

Even complete local evidence cannot prove nobody else could write the file.
A running process can hold retained supplementary groups after its account is
removed; membership can change after the check; a container can show host files
whose host group members its own databases omit. This evidence is only for
showing a discovery row. It cannot establish installation, start a program,
prove enforcement or prove that a configured agent is running.

`tego setup` and the dashboard Overview use the same saved-result reader and
setup-state engine. A fresh A or B observation for you with ok or partial status
says "found by scan at <time> (any program running as you can change it)" in
Find your agents. Partial status still lists unreadable sources and limits in
the not known lines. The tick states what was seen; it makes no completeness
claim. Missing, stale, zero-match, failed, other-boot, future, foreign-recipient
or invalid results leave find to do, with a reason and
"Run tego scan from your project folder." in the not known lines. Settings,
project hints and another user's items cannot tick find. A scan never changes
setup's exit code or any other step. Recorded-run evidence keeps precedence.
The dashboard starts no process.

An older c1 reader, such as an older tego-control, cannot read a c2 result.
Its guide shows the generic "invalid, unsafe or unavailable" saved-result reason
rather than a separate unsupported-catalog message. An older reader can also
reject the new mode refusal code. Use matching builds to read the newer result.

The [Agents list](agents.md) reads saved observations and remembered discoveries.

Not built yet. Pyproject.toml and the approved Agents page remain later slices.

To record an agent, fill in the command you normally start it with:

```text
tego watch -- <the command you start it with>
```

Scan never reconstructs that command from discovered input. Real vendor-layout,
privilege, namespace and syscall checks in a guest are still owed; fixture tests
cover this command's data flow and privacy.

The reproducible vendor, permission and scale checks are owed in a guest.

Configured MCP servers come only from `~/.claude.json`, `./.mcp.json`,
user/project `.codex/config.toml`, and user/project `.gemini/settings.json`.
JSON selects `mcpServers`; TOML selects `mcp_servers`. From Claude's user file,
only `projects.<current folder>.mcpServers` is selected, with scope `local`.
Other remembered project folders are skipped without retaining their paths.
A row keeps the server name, client, scope, transport, catalog program id or null,
and argument count. It never says that a configured server is running. Arguments,
environment values, headers and all URL text are dropped while parsing. URL
host remains null. Credentials disguised as server names cannot be recognised;
these names are private metadata. No include or content-specified settings path is opened.

User units come from `~/.config/systemd/user`, `/etc/systemd/user`,
`~/.local/share/systemd/user` and `/usr/lib/systemd/user`, in that order.
Scan reads bounded service/timer files and merges instance, template, dash-prefix
and type drop-ins. Directory precedence is applied before specificity among
instance, template and dash-prefix folders; type-wide drop-ins have lower priority.
Distinct filenames merge lexically. ExecStart resets and multiple commands are
supported for oneshot services. Native and Node starts use the nine inherited
catalog rules, with argument tokens discarded immediately and secret-like flag
values skipped. A measured subset of systemd ExecStart quoting, escapes, prefixes
and continuation handling is supported. The versioned differential fixtures
record systemd 257's commands, including removal of quotes inside a word and
odd/even trailing-backslash handling. They do not establish full unit-file conformance.

Program specifiers, environment expansions in any argument (unless disabled by
`:`), and launch wrappers are unresolved. The source row names the unit and says its startup could not be
determined. Shell/env/Tego wrappers and `nohup`, `timeout`, `nice`, `setsid`,
`stdbuf`, `npx`, `bunx`, `uvx`, `tmux`, `screen` and the `|` shell-launch prefix
(including combinations such as `@|`) are included. Percent specifiers
that leave a known Node script match remain unexpanded and labelled.
Aliases are resolved by unit basename and root priority only when the link
spelling stays within the selected roots. A link outside those roots is reported
and its target is not read. Wants links remain metadata only; enabled instances
use templates already found in these roots. No systemctl or command from a unit
is run. A matching unit is configured to start the named program outside Tego;
scan does not establish that systemd loaded or started it. Timers show configured
relationships, never a predicted firing.

MCP files and ordinary unit content paths refuse links, mount crossings below
selected roots, unsafe modes, special or multiply-linked files, changes during
reads and unsupported syntax. The bounded unit-alias lookup is the stated link
exception. Each file is at most 1 MiB. Ignored JSON keys, strings and nested values
are streamed without retained maps or token charges; they remain subject to the
file byte bound, depth 32 and shared two-second deadline. Only selected JSON
structure uses the 4 KiB scalar, 4,096-token and 128-server/argument bounds.
Duplicate selected keys refuse the file; duplicate ignored keys are discarded.
TOML retains its 4 KiB scalar, 4,096-token and 128-server/array-entry bounds.
It also caps the combined decoded section and key at 4 KiB before duplicate-prefix
bookkeeping.
Multiline strings, array tables, floats, dates, leading plus signs and other
numeric forms beyond plain decimal integers refuse the whole TOML file.
D/E share 6 MiB and 2,048 content attempts. Unit metadata is bounded to 1,024
directories and 4,096 charged entries total, including overflow lookahead and
names from failed or rejected listings. Each attempted listing costs at least
one entry; a directory receives only the remaining allowance. A listing that
fills that allowance is refused, so at most 4,095 names are accepted from one
directory. Enumeration stops at exhaustion. Units have a 16-hop alias resource
budget, 8 KiB physical/logical lines, 4,096 combined physical lines and ExecStart
words (including lines after the last command), 128 starts and 256 arguments. Systemd's semantic ceiling of seven alias symlinks is checked
separately.
These input bounds have at least tenfold headroom over the measured layouts.
Synthetic capacity fixtures and unchanged captured distribution files have
separate offline tests. Captured stock launch wrappers may be unresolved; they
still preserve the process-only check. This does not prove live systemd loading.
The unit input bounds and both fixture sets are documented
in [the fixture inventory](../../internal/scan/testdata/unit-layouts/README.md).
The two-second deadline cannot interrupt filesystem IO already blocked in the kernel.

A refused source says it could not be read; unresolved startup says it could not
be determined. Read and missing source rows carry neither warning. A partial
snapshot prints no negative no-match summary.
The check decides only process coverage. Unreadable or unresolved MCP/unit
sources keep partial status and named warnings without changing that check.
A definite outside process match returns 1; an unknown process check returns 125.
Other clients/formats, generated/runtime unit paths, custom XDG roots and these
unread default unit roots appear in the footer: `/etc/xdg/systemd/user`,
`/usr/local/lib/systemd/user`, `/usr/share/systemd/user`,
`/usr/local/share/systemd/user` and `~/.config/systemd/user.control`.

Catalog c3 adds D/E rows and additive configured counts and detail fields to
`tego.scan/1`, including Claude scope `local` and source reason `unresolved`.
New readers still accept c1/c2. Older readers may reject these additions; keep
the CLI and dashboard builds matched. Configured servers and units alone do not
tick the guide's Find step. Real installs and kernel behavior remain owed in a guest.


With initial-namespace root, `tego scan --advanced` also reads process facts for
every visible uid, fixed systemd user-unit paths for local passwd accounts,
system services and timers, and cron entries. It adds container ids from matched
processes' cgroup names. It reuses the ordinary scan's command and unit parsers.
Run it explicitly from the project folder you intend to inspect:

```sh
sudo "$(command -v tego)" scan --advanced
sudo "$(command -v tego)" scan --advanced --json
sudo "$(command -v tego)" scan --advanced --check
```

Advanced program-link denials are ordinary unknown A coverage, including uid 0.
The basic-only `--allow-unreadable-programs` exception does not accept them;
a negative advanced check remains 125.

Without initial-namespace root, advanced exits 125 with a fixed explanation and
a footer saying the scan was not performed. The ordinary `tego scan` still
works as your user. Root inside a child user namespace does not qualify.
There is no live follow, daemon request, container API request or adoption.
A positive `GODEBUG=containermaxprocs` override also refuses advanced before
collection. Start with `GODEBUG=containermaxprocs=0` or remove the override.
Before the command starts, Go reads kernel CPU, cgroup and huge-page metadata.
Its CPU limit path follows cgroup membership and the first matching cgroup mount.
With quota adaptation disabled it reads at most 64 bytes per file: `cpu.max` on
v2, or the quota and, unless the quota is negative, period file on v1. Both v1
files are opened first. Descriptors close before Main when both opens succeed;
if the v1 period file fails to open, the quota descriptor remains open and unread
for the process's life. Nothing in Tego reads that retained descriptor.
No setting of this build suppresses the startup open. Only where root has placed
the cgroup mount under, or mounted into the cgroup path, a directory another
account controls can that account replace a path and make a root command block
on a FIFO before Main, or have those bounded bytes parsed as numbers. Under the
binary's default, the numbers only decide an unread runtime metric; nothing is
printed, saved or logged. This applies to every Go program run as root. Tego adds
no check that could undo the read; keep cgroup mounts where distributions put
them (`/sys/fs/cgroup`). See GAPS C79 and ADR 0145's runtime amendment.
The tego binary's default CPU parallelism follows CPU affinity; it does not
adapt to cgroup CPU quota. Set GOMAXPROCS explicitly when needed. This binary
default does not change external agent executables' runtime defaults; any
explicit environment overrides still follow normal inheritance.

Generated/transient system units, `/etc/systemd/system.control`,
`/run/systemd/system.control` and `/usr/local/lib/systemd/system` are not read.
This includes `/run/systemd/generator`, `.early` and `.late`.

The additional system unit roots are `/etc/systemd/system`,
`/run/systemd/system` and `/usr/lib/systemd/system`, in that order. Only bounded
service, timer and applicable drop-in files are selected. Every local passwd
account contributes its fixed `.config/systemd/user` and
`.local/share/systemd/user` paths. No home is walked. Shared distribution user
roots are listed and their selected documents parsed once, with root ownership
checks. Each account gets a fresh precedence merge. Reuse checks the pinned
file, alias and directory identities; a change discards dependent unit evidence
from every account.
Successful machine files and alias metadata are counted under their fixed root.
Matched evidence and named failures retain their exact paths; capacity limits
add an unknown-remainder source. The same unit
grammar, bounded confined aliases,
precedence rules, unresolved launches and configured-only wording apply.
A configured timer relationship predicts no firing time.

Cron sources are `/etc/crontab`, direct `/etc/cron.d` files and the fixed
`/var/spool/cron` and `/var/spool/cron/crontabs` account files. Scan keeps a
matched catalog program id and source evidence, never the schedule, command
body, arguments or assignment values. It does not follow scripts, includes,
substitutions or shell bodies. A shell form it cannot classify is disclosed.
Container attribution accepts only 64 lower-case hexadecimal id bytes in
`docker-<id>.scope`, `libpod-<id>.scope`, `cri-containerd-<id>.scope` or a
`docker/<id>` cgroup component. It keeps only the validated runtime code and id. This is a cgroup suggestion, not confirmation from a container
manager. Container names, images and sockets are never queried.

Installed candidates, settings metadata, MCP settings and project dependencies
retain the recipient/project scope. Other users' arbitrary settings and project folders are not discovered or
walked. Environments and auth files are not selected. The fixed user-unit paths
above are the only other-user home content discovered by advanced. After the
drop, recipient-selected config and record paths may name readable shared files. Unknown
names, unsignatured libraries, remote agents, hidden pid namespaces and activity
between snapshots remain outside its claim. A failed source is named in the
footer as could not be read. Configured-source uncertainty keeps partial status
without deciding the process-only check. No zero count establishes absence.

For other accounts, a root scan writes down matched program paths and process
identities, configured unit and cron metadata, and container id suggestions;
only the recipient and root can read the saved result. These paths and names
can reveal private names even though arguments and values are dropped.
The fields about other accounts are:

| Where | Fields kept | Why they are needed |
| --- | --- | --- |
| Matching processes | `pid`, `ppid`, numeric `uid`, `start_ticks` | Identify the observed process and group its descendants without confusing a reused pid. |
| Matching processes | Full program path `exe` | Identify which installed program matched. The path can contain private names. |
| Matching processes | `membership`, validated `run_id` or null | Distinguish an observed run cgroup from an outside match or unknown membership. |
| Matching processes | `container.runtime`, `container.id` or null | Distinguish matching processes in different suggested containers. The id is not confirmed by a container manager. |
| Configured user units and timers | Full source `path`, numeric `uid`, validated unit name `unit`, catalog program id `program` | Identify the configured startup and the account whose unit paths were checked. A path can include an account's home name. |
| Configured user units and timers | `arguments` count, `specifiers_unexpanded`, `enablement_link`, validated related service name `triggers` or null | Explain the parsed startup, unresolved specifiers, observed wants-link metadata and timer relationship without keeping argument text. |
| Cron matches | Full source `path`, numeric `uid`, catalog program id `program` | Identify the fixed cron source and account for a configured startup. No account spelling from a cron line is kept. |
| Each observation | Generated `id`, `kind`, catalog or numbered custom-rule `name`, `evidence.rule_id`, `evidence.source_id`, `evidence.fact`, fixed `caveats` | Show why the observation is present and which source supports it. |
| Attempted sources | Generated `id`, `kind`, full `locator` or null, `state`, `read`, `not_read`, fixed `reason` | Show which paths were checked, unreadable or changed, including failed fixed unit paths beneath other accounts' homes. |
| Unreadable-program summary | `unreadable_program_pids`, `unreadable_programs_warning`, `counts.unreadable_programs` | Keep the required basic-scan warning contract. In advanced mode the pid list is empty and its count is zero; unreadable processes, including foreign ones, are coverage gaps in `sources` instead. |
| Aggregate counts | `counts.running`, `counts.in_run`, `counts.outside_run`, `counts.membership_unknown`, `counts.user_units`, `counts.system_units`, `counts.cron_entries`, `counts.exited_during_scan`, `counts.kernel_threads` | Count observed matches, configured startup and processes that ended or were kernel threads, without retaining additional personal details. Other counts cover the recipient's sources only. |
| Snapshot context | `started_at`, `finished_at`, machine `boot_id`, `status`, `check`, `not_looked_at`, `limits` | State when these observations were made and how much coverage remains unknown. |

Other accounts' process working folders are never read or recorded: `cwd` is
null, and their text rows say "folder not recorded for other accounts".
The process `unit` field is currently null; configured unit names remain in
the separate unit rows. No process argument text, process argument count,
arbitrary cgroup path, separate account-name field, environment, or ignored
settings value is kept.
Matching and process grouping do not need the working folder.

By choosing the explicit root command, the operator authorizes the result for the
invoking local-passwd user under sudo, or root for direct root. The saved path
is that recipient's `~/.tego/scan/last.json`, exactly 0600 inside a 0700 scan
directory. Only that recipient and root may read it. While root, the collector
reads only its fixed process, account, boot, unit and cron sources. It closes
those source descriptors, then permanently drops every thread's groups, gid,
uid and capabilities to the recipient. Only then does it resolve the scan's
project folder, inspect recipient programs/settings, read MCP and project files,
load config, probe records or open a destination. Check mode uses
the same drop and reads, and writes no cache. A failed drop prevents all those
recipient reads and saving, with exit 125. An unsafe destination prevents saving;
existing ownership and modes are not repaired. The saved file is still forgeable
by its owner. Live-record checks use the recipient's configured ledger after the
drop. A selected ledger can be shared; record files must belong to the recipient
or root and also be readable as the recipient. Probes cannot use the collector's
root access. The guide still counts only that recipient's fresh running or
installed evidence; the root collector uid does not hide their
installed candidates. Configured units and cron alone never tick Find.

Advanced shares 32 MiB and 8,192 content attempts across selected settings,
units and cron files. Unit enumeration shares 16,384 charged entries, 8,192 per
directory and 4,096 directories across all accounts and system roots. Local
passwd input is bounded to 1 MiB and 4,096 accounts. That is a parser bound,
not a promise to cover 4,096 accounts. Acceptance covers 100 accounts with the
last home's agent beside 3,000 system services and the stock machine user units.
Capacity depends on unique files and entries, matched items and named failures;
shared machine input spends its byte, attempt and enumeration allowance once.
At a limit the result is partial, with a named limit and an unknown remainder.
Physical/logical unit lines are bounded to 8 KiB; each file stays at 1 MiB. Existing process and final result
bounds remain unchanged: 8 MiB process input, 32,768 pids, 256 KiB/process,
2,048 sources, 512 items and 1 MiB serialized output. Advanced has a shared
ten-second best-effort deadline. The separate process/content/link byte
allowances total less than 224 MiB, including config and bounded record probes. This is not a global counter for
every kernel metadata byte or a promise about process memory. A cap leaves an
explicit unknown remainder, never a negative finding. Filesystem IO already blocked in the kernel can overrun the deadline.
Stock distribution measurements and exact fixture limits are recorded in
[the scan design](../adr/0145-tego-scan.md#measured-advanced-input-bounds).
Fix round 1 passed the credential, hostile-source, canary, directory-change
and destination regressions on full Fedora 44 with kernel 7.0.14 and AlmaLinux
9.8. The fixture uses matching stand-in programs and a real Tego run. Remaining
namespace/mount variants, live container-manager attribution, live cron behavior
and vendor-install comparisons are owed in a guest.
These measured rows do not establish those unrun cases.

Unit-alias link text spends the same configured-input byte allowance. Each
read reserves up to 4,097 bytes, including failed and repeated reads. Reaching
that shared limit is disclosed; it never becomes a negative finding.

An unmatched interpreter from another uid receives no G-only cgroup or cwd
read. Matched processes across uids retain cgroup membership and container hints.
Only the recipient's matched processes retain a working folder.


The measured WSL 3.0.5 private cgroup namespace has no new scan exception: its normal user could not read the
service manager's namespace identity, so outside membership remains unproved. The scan is now handed the command
line's own answer to "is this process outside every run?" and admits its caller only on a proven yes; the rule
that can prove it outside the kernel's first cgroup namespace is switched off on WSL in this build, so
`tego scan` still refuses there. Setup's optional placement
rehearsal does not confer scan authority or move the scan. A diagnostic tier and the kernel's WSL version do
not prove process visibility or containment.
