# ADR 0145: What `tego scan` reads, says and never claims

Status: **proposed 2026-11-11; accepted after the second reading's amendments**.
This records B2-0 and the implemented B2-1a/B2-1b basic command and guide. Guest
validation is owed. B2-2 D/E and B2-3 advanced now have fixture implementation;
A4-1 remains separate. It extends
[ADR 0142](0142-setup-state-and-the-stored-check.md), decision 1 and its find step.

## Context

A scan goes from minimum knowledge to full detail. The plan puts
the command before its dashboard page. Its first build includes A, B, C and G. F follows in B2-1b.
D and E follow. Root scope follows them.

`tego agents` currently requires initial-namespace root even for one snapshot.
Without root it exits 125 and names `tego watch`. With root it uses the watcher.
With `--follow --adopt --uid`, matches can cause adoption. Thus adding a name to
`sig.Default` can change which processes the guard adopts. It does not change a
contract's rule evaluation by itself. With `--adopt --boundary`, selection
decides whether a Contract is applied at all.

The watcher keeps argv and reads a matched process's initial environment. It
ignores cgroup read errors before deciding whether the process is outside Tego.
Its skipped count is not an account of every failed source read. Reusing its
current report unchanged would break this scan's privacy and coverage rules.

The guide already decides the setup steps for both surfaces. Before B2-1b it found
agents only through runs. Its commands have an in-memory mark that decoded JSON
cannot carry. Scan must feed this guide. It must not create another setup chooser.

`internal/maze/scan` is an unrelated setup-tool package.

File two existing `tego agents` defects separately: a cgroup read error reads
as outside, and zero matches prints "no agent process is running".

The source-reading audit is retained in commit `ce70ab5c7`. It checked the
watcher, signatures, guard selection, guide, stored check, command dispatch,
invoking-uid rules and the plan against base
`2a1b255df30f00244fbe0ff3865837a0585889db`. These are design decisions,
not executed scan or guest proofs. Numeric bounds are chosen limits; the
implementation checkpoint below says what has actually been built.

## Decision

### 1. One explicit, bounded look

`tego scan [--advanced] [--json] [-v|--verbose] [--check [--allow-unreadable-programs]] [--all-mine]`
also accepts repeatable `--signature` and `--no-default-signatures`.
`--advanced` requires initial-namespace root and follows decision 5 and the
B2-3 amendment below. A refused advanced request never becomes a basic scan.
There are no prompts.
There is no `--follow` in this design. Live events stay with `tego agents`.

Collect `--signature` with `fs.Func`; parse bounded spellings in Run. On
rejection print fixed text, never the rejected spelling. Usage errors exit 2
and print usage, without the footer. Keep local recovery around scan collection
and parsing: fixed bug text, no panic value or stack and no own-log write.
Fatal runtime failures, an early process privilege guard, a killed process or
an unwritable output can prevent footer delivery.

Basic scope is the caller's real uid. Require real and effective uid to agree,
with no elevated capabilities for a nonzero uid. Direct root with no
`SUDO_UID` may retain its ordinary root capabilities and scans uid 0 only,
labelled "root's own processes only". Under sudo without `--advanced`, refuse.
Advanced help is public; basic sudo calls still refuse.
Check the caller's pinned `/proc/<self>/ns/cgroup` inode against
`runscope.InitCgroupNS`, and require an nsfs handle. A private or unreadable
cgroup namespace cannot rule out a hidden governed ancestor. This namespace handle is metadata only.
Refuse inside a governed run, or when that cannot be ruled out, before reading
or writing results.

The scan starts no program. It makes no network request, name lookup, daemon
request, D-Bus call, model call or container API call. It never runs a found
program, even with `--version`. It never adopts, signals, traces or moves a
process. Its only persistent write is its result and the temporary file used to
replace it. The opening sentence must mention that write. It must not say
"changes nothing."

The source policy is closed. Anything not named here is excluded. Metadata
sources are a bounded local /etc/passwd read for uid/home lookup and
/proc/sys/kernel/random/boot_id for boot identity. Never invoke an NSS helper.
Account for these reads too. Refuse an unresolved recipient instead of guessing.
For the live-record wording only, the CLI also resolves the three Tego machine
config layers through the existing trust/merge rules, with a scan-specific
1 MiB limit per layer. It uses the already resolved local-passwd home and the
secure-exec rule. It never prints loader input or raw diagnostics. At most eight
distinct typed run ids get a pinned, no-follow run-start read of at most 64 KiB,
plus a bounded ledger tail check and writer-lock checks. Record size does not
limit a live-record claim. The tail is needed because the writer can append
run_end while still holding its lock. These are record checks, not arbitrary
tool settings reads. Input byte allowances, including failed reads and repeated tail windows,
are below 196 MiB: processes 8 MiB, config 3 MiB, record probes 168 MiB
(21 MiB per bounded start/tail probe), B link text 1 MiB, D/E 6 MiB,
F 2 MiB, and account collection 6 MiB. These sum to 194 MiB. Caller passwd
adds at most 1 MiB plus one byte, boot id 65 bytes, and PATH spelling 64 KiB;
config/F limit probes add at most five bytes. Descriptor account walks add at
most 768 KiB of symlink text: each of six walks has a 128 KiB allowance,
with fixed 4 KiB readlink probes, including failed and truncated probes.
The sum, 205,324,359 bytes, is below 196 MiB,
not the former 192 MiB. The six account reads are passwd, group and
nsswitch.conf in pass one, then passwd, group and nsswitch.conf in pass two;
each consumes at most 1 MiB and reaching that limit refuses. Accepted
account file payload is less than 6 MiB, plus the bounded link text above. Only pass one's bytes are retained
(less than 3 MiB of payload); pass two compares as a stream with one fixed
4 KiB buffer, refusing length differences. This is input-byte accounting,
not a heap or RSS bound: ReadAll growth, parsed maps, strings, result objects
and runtime overhead are not bounded by that sum.
Record input is transient and never enters observation fields. An ended or lost
record, an unsafe path, malformed start or tail, probe cap or deadline retains
cgroup-name wording and the fixed reason for the unsuccessful record check.
A record that ended after the snapshot but before the probe also retains that
wording. This is a current record check, not verification of its chain. The final probe
also compares the current events.jsonl name with the pinned record inode and trust metadata, allowing
ordinary append growth. Directory mtime/ctime alone cannot establish that identity: replacement within
one filesystem clock tick can leave both unchanged. A replaced name retains cgroup-name wording with
the fixed changed reason, even if the old pinned descriptor remains readable.

| Kind | First build and exact reads | Reason and later work |
|---|---|---|
| A. Running processes | B2-1a. Enumerate numeric `/proc` entries. Fstat directory ownership first; for owners neither the caller nor root read only the uid line of `status` (the owner is the effective uid, so a setuid program the caller ran shows another owner): none of the four uids the caller's skips the process as another user's, any of them makes it uncertain (basic check 125), and a denied read is uncertain too (a mixed process whose proc owner and effective uid are both root is the exception, since sudo and su have the login's real uid and effective root: when root scans it is read and judged like any other, as root reads every process, and sudo and su are the parent of every scan run through sudo; when anyone else scans it is root's process, another user's like every process of root's, and skipped; a mixed process with another non-root effective uid, a setuid copy, stays uncertain); never read their `stat`, `cmdline`, `exe`, `cgroup` or `cwd`. Read the uid fields of `status` for eligible directories. For this uid, read `stat` before and after, `exe` by readlink, and bounded `cmdline` for signature matching. Read executable device and inode before and after only for a file signature. Read `cgroup` and `cwd` only for matches, plus G's unit test. Read boot id for snapshot identity. Use `stat`'s terminal number for G. | Build bounded identity reads and wrapper grouping above the watcher; its current enumeration and silent argv truncation are insufficient. Account separately for exited processes, kernel threads, unreadable own program links, and live coverage gaps. Do not call its current environment reader. Do not read another uid's cmdline in basic scope. An unreadable uid is unknown scope, not an own-process nonmatch. |
| B. Installed program candidates | B2-1a. Stat catalog basenames in absolute PATH directories and catalog install paths. Count and exclude empty or relative PATH entries. Use only catalog globs with fixed depth, including `./.venv/bin` under the current directory. Require a regular executable file. Read symlink targets and stat them, with the limits in decision 7. Read no executable bytes. | A basename is evidence of a candidate file, not proof it works or is authentic. Show its observed path and target. A generic name needs the catalog's specific second fact. |
| C. Settings metadata | B2-1a. Lstat only the catalog's fixed home paths, such as `~/.claude`, `~/.codex` and `~/.gemini`. Require caller ownership. Keep path, file type and mtime only. Do not descend into these folders. A symlink is listed as not read. | An abandoned folder is still only settings metadata. It cannot establish installation or a running process. |
| D. MCP settings | B2-2: only catalog files and documented MCP subtrees. Retain catalog program/client ids, scope and transport; drop args and values while parsing. Host stays null in v1. | Configured is never running. Unsupported formats get not-read entries. New format claims need install fixtures. |
| E. User units | B2-2: fixed systemd user directories in home, `/etc/systemd/user` and `/usr/lib/systemd/user`; bounded service, timer and drop-in files, ExecStart, Unit and precedence metadata only. Wants links are metadata. | Share a bounded ExecStart parser with advanced. Unsupported shell, expansion, specifiers or merge rules are unresolved. A Tego command is configured to start Tego, never proof of membership. |
| F. This project | B2-1b. In the current folder only, stat fixed marker paths `langgraph.json`, `crew.jsonc` and `config/agents.yaml`. Do not read their contents. Parse dependency names only from `package.json` and `requirements.txt`. Do not follow includes, URLs, scripts, plugins or lockfiles. | Keep only exact catalog dependency names and the manifest path. Say "declares a dependency on". Do not infer that it is installed, loaded or running. Never read `agent.py` or other source code. `pyproject.toml` waits for B2-2. |
| G. Other interpreters | B2-1a. From A's uid-filtered reads, count unmatched interpreter processes with a terminal or recognized user-unit cgroup. Basenames: `python*`, `node`, `bun`, `deno`, `java`, `ruby`. Exclude descendants already grouped under a matched session. | Print one count by default. `--all-mine` includes their rows. They increase only `counts.other`. The heading always says "Tego cannot tell whether these are agents." |

Amendment 2026-11-12, B2-1b: F selects the current directory only. It never
walks parents, children, workspaces, home or git roots, and never enumerates
arbitrary filenames. The two exact manifest names above override the earlier
requirements glob for this slice. Three fixed markers remain metadata only.
Pin the selected current directory by a no-link component traversal; this
explicitly selected root may itself be a mount. Beneath that root, use
`openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV` for each
fixed path, including `config/agents.yaml`. Mount ids, rather than device ids,
are the boundary, so bind mounts are refused too. If openat2 is unavailable,
list F as not read; do not fall back to a weaker walk. No link at any component
is followed. Content requires the regular, single-link, owner and mode checks
in decision 7 before reopening the pin. Recheck inode metadata and the path
after parsing; discard the file's evidence on change. Stop between reads and
parser tokens at the shared basic deadline. At most two content files, 1 MiB
each, and three metadata paths are selected. The footer always names project
parents, child folders, alternate manifests and includes as not walked.

Catalog c2 adds only dependency rules: npm `@anthropic-ai/claude-code`,
`@openai/codex`, `opencode-ai`, `@google/gemini-cli`, `@langchain/langgraph`;
Python `langgraph` and `crewai`. Their ids are `dep-claude`, `dep-codex`,
`dep-opencode`, `dep-gemini`, `dep-langgraph-js`, `dep-langgraph`, `dep-crewai`.
Marker rules are `marker-langgraph`, `marker-crew`, `marker-agents`. These are
declaration or metadata hints, never new process signatures. Readers retain c1
support. The npm tables are dependencies, devDependencies, optionalDependencies
and peerDependencies. Requirements accept normalized distribution names,
extras, version specifiers and environment markers; unsupported directives,
includes, URLs, continuations and editable installs make the whole file not
read. Comments and values are streamed and dropped. A later syntax error
discards earlier declarations. No generic provider SDK implies an agent.

Kinds and path examples above come from the ground study and final spec.
Their present-day vendor accuracy was not checked here. Catalog inclusion needs
the install check in decision 6.

A process that disappears during reads is counted as `exited_during_scan`,
with no pid, path or other detail retained. A zombie with no live task is also
counted there; it is not labelled gone. A zombie leader with a live thread uses
that thread's program facts. PF_KTHREAD tasks have no program file by nature:
count them as `kernel_threads`, without details. Neither category makes check
unknown. A coverage gap is a live process the scan could not classify.

Amendment 2026-11-12: own processes can be non-dumpable, as ssh-agent and
gpg-agent are in ordinary login sessions. When all four status uids equal the
caller and directory ownership is the caller or root, an EACCES program-link
read is reported separately after identity rechecks. Keep only its pid, with
`counts.unreadable_programs` and `unreadable_program_pids`. Say exactly
"N of your processes do not let their program file be read", list pids, then say
"Tego cannot tell whether these are agents; any program can make itself unreadable."
Never show the kernel process name, argv or environ, and do not classify the hidden program
from those inputs. Default check reports this uncertainty: it returns distinct code 3
when this is the only process uncertainty and nothing outside was found among
readable processes. Any process can set itself non-dumpable, so an outside agent
can move from exit 1 to exit 3. Exit 3 does not establish absence. The named
`--check --allow-unreadable-programs` mode instead returns 0 for this case,
retaining the count, pids, partial status and an explicit check code. Other
live gaps still return 125 and definite outside matches still return 1.
Neither mode classifies unreadable own programs.
With `--allow-unreadable-programs`, exit 0 does NOT mean no agent runs outside Tego.
Exit 3, and 0 with --allow-unreadable-programs, do not mean no agent runs outside
Tego: an agent can make its program file unreadable.

Never open `environ`, `.env`, auth files, token stores, shell history, process
memory, `maps`, `fd`, socket tables or arbitrary project files. A's `cmdline`
may contain credentials. Use it only as a bounded stream of match input. Keep no
raw argv in a result, watcher session, log, debug line or error. No flag enables
raw argv. Retain a rule id and the fixed fact "argv pattern matched", not the
arguments that matched. Drop custom signature text after compilation too; the
result carries its bounded name and rule id, not its tokens.

D and F need parsers that select keys while scanning. Bytes of ignored values
can pass through a bounded input buffer. Do not materialize a whole document or
decode an ignored string. Do not keep value maps or file copies. Discard scalar
values from `env`, `headers`, `http_headers`, auth and unknown subtrees.
No error includes input bytes or a parser's raw excerpt. The truthful promise is
"Tego keeps the name, never the value." It is not "Tego never reads a value."

Names and paths are private metadata. An attacker can put a credential in a file
name, server name or hostname. A fixed parser cannot identify every such string.
The design must not promise to remove secrets hidden in names. Keep the
result private. Omit text containing control or bidi characters from retained
metadata, and report the omission. Do not turn omitted text into a different path. Preserve observed link paths,
including a trailing ` (deleted)`. That spelling can also be a literal name;
retain independent argv0/comm facts and mark identity coverage unknown instead
of stripping it to manufacture an exe-name match.

### 2. Evidence, words and the footer

"Found" means a named rule matched a named source. Every row must show the
evidence, including both facts for a generic name. Say "program named codex",
"settings path exists", or "manifest declares langgraph". Do not say that a
basename proves authorship or purpose. Guesses stay out of found rows. G is a
separate list of programs whose purpose is unknown.

For A, retain pid, uid, parent pid and start ticks with the snapshot's boot id.
Cgroup membership has three states: `in-run`, `outside-run`, `unknown`.
Use `runscope.GovernedBy` on a successfully parsed unified cgroup path.
Missing, malformed or raced cgroup data is unknown. Never negate a missing
boolean. A matching cgroup permits "in Tego run <id>" only when a reader finds that run
in the ledger, started before `finished_at`, with a held writer lock before and
after a bounded start/tail check that found no run_end. Otherwise say
"in a cgroup named for run <id>; could not be checked against the record",
with the fixed reason in the footer. Amendment 2026-11-12, fix round 2: scan
pins and checks the events and lock files locally before any data open, then
lends both to the ledger's bounded state reader. State probes the same independent
lock descriptor before each tail read. The start is bounded at 64 KiB and state
is checked before and after it. Ordinary ledger opens keep their prior
O_RDONLY, O_NONBLOCK and O_NOFOLLOW behavior with a regular-file check after
open; they gain no /proc reopening dependency from scan. Only scan's local
pin-and-reopen path uses /proc/self/fd. Root, hidepid and container behavior for
this scan path is owed in a guest. Failure to check never establishes that
the run is absent from the record. A user can build that shape
(runscope/governed.go:28-32). Collection derives typed run ids from cgroup observations and never imports
the ledger. Rendering receives current live-record answers only from the CLI,
which performs the record probes. Never claim enforcement,
verification, safety or a tier. A recorded-only run is still a run.
The claims ceiling distinguishes record-only from enforced runs.

Human output starts with uid, scope, scan time and catalog revision. Show running
matches, installed candidates, settings-only evidence, configured servers,
units, project hints, then G's count or list. Empty sections can be short.
Say "No match among the rules and sources read." For B never use the heading
"installed, not running"; a missed A row does not prove it is not running.

`-v` adds rule ids, uid, start ticks, source paths, counts, caps and reasons.
It never broadens reads or reveals dropped values. Default text and verbose
text must both show evidence and limitations. JSON does not depend on verbosity.

Print a footer after every scan, including privilege, IO and save failure.
Usage errors print usage instead. On failures before discovery say "Read: none; scan not performed."
For human output it goes on stdout after the rows. With `--json`, limitations
are required fields in the sole stdout object. Also print a short scope footer
on stderr, including in `--check` mode. `TEGO_HINTS=off`, a pipe and
`--all-mine` never suppress it. An unwritable output can prevent delivery;
then exit 125 and attempt the footer on stderr.

The footer names effective rule names, counts read and not read, exclusions,
exited and kernel-thread counts, and unreadable own program counts and pids.
Every unreadable count includes "Tego cannot tell whether these are agents".
Default text has one row per observation and the footer. Per-source success
rows and paths are verbose only; failed-source reasons remain in the short
footer. Always name other users in basic mode, D and E when deferred,
container attribution when excluded, unreadable own processes, unknown
ownership, agents under a name no rule knows (`unknown-names`), unsignatured libraries,
remote agents and processes that ended before
or during the snapshot. Never imply an exact count of invisible processes. Read `/proc/self/status`'s
NSpid; more than one entry adds `outer-pid-namespace` and makes a negative
`--check` unknown (125). Failure to establish namespace visibility also makes
that check unknown. The initial entry alone is not proof of host-wide visibility: a nested PID namespace's own fresh `/proc` shows one entry, so the scan also reads its own PID namespace inode through `/proc/self/ns/pid` and treats anything but the initial namespace's fixed inode (or an unread one) the same way. Time, uts, ipc and mount namespaces do not change which processes `/proc` lists and are not judged.
A denied file is listed by path as "not read", with a fixed reason code.
A cap says what stopped and how much remains unknown. A known missing path is
"missing", not "not read". Missing is evidence about that path at that time only.

A `next:` hint is optional; the footer is not. The generic command is
`tego watch -- <the command you start it with>`. Give it as a template to fill
in. Never reconstruct a launch command from process argv, config, PATH, a unit,
cron or a saved string. Do not offer a raw discovered path as an executable
command. A dashboard "Record it" copy block uses this template. Show the evidence
beside it so the user can choose their command. This sacrifices automatic replay
to prevent both credential disclosure and a copyable command chosen by a hostile
file.

### 3. JSON and CI

One object and a newline on stdout, never JSON lines. The schema name is
`tego.scan/1`. Persist the same object that stdout JSON uses. There are no stored
commands, HTML, raw argv, full URLs or free-form error messages. Fixed UI words
are derived from codes. All fields below are required unless stated otherwise.
All objects are closed. Null means unknown or inapplicable, never false.

The structural schema is [spec/scan/v1/schema.json](../../spec/scan/v1/schema.json).
Format checks and the semantic rules below are mandatory decoder checks.
String bounds apply to UTF-8 bytes as well as characters.
No field holds text copied from argv, file content or a URL, except typed paths.
Item names are catalog or numbered user rule names, dependencies are catalog ids,
and evidence text is derived only from `rule_id` and `fact`. G carries no command
or copied name: its only string observations are the typed exe and cwd paths.
Unit names are validated, at most 256 bytes; run ids follow `identity.RunID`.
Reserved D's hostname proposal conflicts with the no-copied-text rule; v1 keeps
`host` null. A later design must resolve it before D ships.

| Field | Contract |
|---|---|
| `schema`, `tego`, `catalog` | `tego.scan/1`, producing version, revision `c<integer>` (first `c1`). |
| `started_at`, `finished_at`, `boot_id` | UTC timestamps, optional canonical boot UUID; freshness uses `finished_at`. |
| `mode`, `as`, `project` | Scope, collector/recipient uids and privilege, typed current directory. |
| `status`, `check`, `counts` | Closed status/check codes; running, in_run, outside_run, membership_unknown, installed, settings, project, other, exited_during_scan, kernel_threads, unreadable_programs counts. |
| `rules`, `items` | Effective rule ids/names/origins; typed details, evidence ids/facts, closed caveats. |
| `sources` | Generated id, kind, typed locator, state, read/not_read counts, fixed reason. |
| `unreadable_programs_warning` | Required fixed text: "Tego cannot tell whether these are agents; any program can make itself unreadable." Always present beside counts, including zero. |
| `unreadable_program_pids` | Unique pids of own processes whose program link returned EACCES after stable identity checks; count equals unreadable_programs. No names or match input. |
| `other_listed` | Whether G's optional detail rows are included. |
| `not_looked_at`, `limits` | Required exclusions and any bounds reached, from closed tables. |

Decoder semantic rules:

1. Reject duplicate JSON keys, unknown keys, trailing data, invalid UTF-8, unknown
   code strings and invalid types. No coercions. Require RFC 3339 UTC times with
   `started_at <= finished_at`. Boot id must be a canonical UUID when present.
   Decimal start ticks must fit uint64. Paths must be absolute and printable.
2. Ids are unique and generated by the scanner, not copied from input.
   Every evidence source id resolves to a source actually read. Its fact must fit
   that source kind. Rule ids resolve to this catalog revision or to a numbered
   custom rule. Custom means user-supplied evidence, not a trusted catalog rule.
   `rules` lists every effective signature and path/dependency rule by id,
   name and origin, after overrides and removals. It keeps no pattern values.
   Every evidence rule id must occur there, even with zero matching items.
3. `counts` counts rows by kind: running (A), installed (B), settings (C),
   project (F) and other (G). Running is the sum of in_run, outside_run and
   membership_unknown. Settings and project evidence never count as matches.
   Each process session is one A item. Group only matching agent names with the
   same known membership and run id; preserve independently classified children
   across membership or agent-name boundaries. G descendants group only when
   their known membership and run id agree with the matched ancestor. G rows exist only with `other_listed`;
   the number equals other unless an item limit shortens it. Counts are observed
   lower bounds after a cap, never a statement of absence. Exited and kernel-thread
   counts are separate from items. Unreadable program pids cannot also be items;
   each has one A source with state unreadable-program, reason permission and
   null locator. Their status is partial even in the explicit accepting mode.
4. An `in-run` process needs a valid run id and cgroup evidence from this read.
   Other memberships require null `run_id`. `unknown` requires a not-read or
   partial source entry. Missing boot identity makes process identity unknown.
   All process uids in basic mode equal `as.uid`; collection in basic has
   equal caller and recipient uids and `root` true only for uid 0. Advanced collection
   has initial-namespace root. In advanced, G covers only the recipient uid.
   `as.root` describes the collector before the privilege drop separating fixed
   source collection from recipient-controlled reads and saving.
   A pre-collection refusal still reports actual privilege and requested mode.
   It has no items or read sources. Thus an advanced refusal without root
   can be valid failure JSON. Unresolved recipient uses the caller uid in
   this failure object only; it must not write a saved result.
5. File and config paths cannot be null. Program candidates have
   `file_type: executable`. MCP program ids must be catalog ids, never commands.
   Host remains null in v1 until D has a design consistent with the privacy rule.
   Stdio has null host; HTTP and SSE have null program. Unknown transport has
   both null. Unit program is a catalog id or null. Cron never stores its command
   or schedule; timer `triggers` is only a validated unit name.
6. Codes in `limits`, `caveats` and `not_looked_at` come from a closed table
   given in the schema. `unknown-names`, `between-scans`, `libraries` and `remote-agents`
   always remain. Include `scan-not-performed` on pre-collection failure.
   Catalog revision changes cannot redefine a code.
7. Count only reads that satisfied that source's required fields. Count each
   failed attempted entity once in `not_read`; additional reasons may have
   separate zero-count entries. Aggregate source rows cannot be counted again
   as individual rows. Sources with unknown total size say so with `limit`
   or `permission`, never an invented missed count.
8. `status: ok` means all selected, supported sources were read or missing.
   Deliberate exclusions and deferred kinds still appear. Partial means a denied,
   malformed, changed or bounded source. Failed means no valid process scan, a
   privilege or usage refusal, or a result save failure. Status is never
   "complete". A failed result is emitted but never replaces a good saved file.

The code tables and schema are one versioned contract. B2-1 must commit the
machine-readable schema, the code tables and valid examples beside its reader.
New fields, codes or catalog revisions that a strict old reader cannot handle
produce an unsupported result there, never a quiet default. A change to a field's
meaning requires `tego.scan/2`.
The current guide renders an older reader's unsupported result as the generic
"invalid, unsafe or unavailable" reason; a c1 reader does not distinguish a c2
catalog refusal on that surface. The added fixed source reason mode likewise
requires an updated reader.

| Exit | Without `--check` | With `--check` |
|---|---|---|
| 0 | Snapshot ran and was saved; partial sources are disclosed. | No matched process was observed outside a run, and A's enumeration, ownership, identity and membership checks had no gaps. This is scoped to this snapshot and its rules. With allow-unreadable-programs, reported unreadable own program files alone are accepted; Tego cannot tell whether these are agents, so 0 does not establish absence. |
| 1 | Unused. | At least one matched process was observed outside a run. It takes priority over A gaps, but not a fatal error. |
| 2 | Invalid flags or signature. | Same; allow-unreadable-programs requires check. |
| 3 | Unused. | Nothing outside found among readable processes; N own program files unreadable, with no other A gap. Tego cannot tell whether these are agents. |
| 125 | No usable `/proc`, identity/privilege refusal, governed caller, output or save failure. | No usable `/proc`, refusal, output failure, unknown A coverage or unknown membership when no definite outside match exists. No save is attempted. |

`--check` never writes `last.json`; save failure cannot change its answer.

`check` is `not-requested` without the flag. Otherwise it is
`outside-observed`, `none-observed`, `unreadable-observed`,
`none-observed-allow-unreadable` or `unknown` by that table.
A fatal refusal makes it unknown when check was requested. Without the flag
it remains not-requested. B through F parse failures do not decide the
process check, but remain partial sources. G never creates a finding. Optional cwd or unit detail failures remain in
the footer but do not make process identity or membership unknown.
"No observed outside match" makes no absence, safety or enforcement claim.
CI must consume the scope footer too. A process can end between reads.

### 4. The saved result is an untrusted snapshot

Write `~/.tego/scan/last.json`, at most 1 MiB. Make `scan` 0700 and the
file exactly 0600, owned by the recipient uid. Resolve the home from that uid's
local passwd entry, not a project file, HOME or an output path in JSON.
Open home and `~/.tego` as `guide.openState` does, including its existing link
resolution for `~/.tego`. Pin that directory, then use no-follow opens for
`scan` and `last.json`. Refuse foreign owners or unsafe scan modes; print the
`chmod 700` fix for a wrong scan-directory mode. Existing scan
directories must also be exactly 0700. Do not chmod, chown or repair an
existing foreign or wrongly protected path. Create a fresh exclusive temporary regular
file in `scan`, set its mode, write, sync, rename and sync that directory.
Never follow the old `last.json`; replacing a link replaces the link itself.
Refuse a directory there. Remove only this invocation's temporary file on failure.
The check file already uses descriptor-based opens and atomic replacement.
 This scan needs its own limits and owner checks.

The reader first pins an entry with O_PATH and no link following. Fstat it
before any data open. Reopen only that pinned regular inode for reading, then
fstat again. Use checked descriptors with `O_NOFOLLOW|O_NONBLOCK` for normal
directory-relative opens. The pinned-fd reopen is the only proc-fd link
exception; never accept a link found in input. Never data-open a device to
discover its type. Require a regular, single-link file, exactly 0600, with
the expected owner. Reject more than 1 MiB both from stat and a limit-plus-one
read. Check identity, size and mtime again after reading. Do not block on a FIFO,
device or socket. Strictly decode only after these checks.

Fresh means the same boot and no more than five minutes since `finished_at`, with no future
timestamp. Missing boot id or unavailable current boot id means unknown
freshness. The guide uses this freshness rule in decision 6. Freshness does not
promise a process is still running. Even a fresh row says "seen at <time>",
never "running now" when read later from disk.

| Read result | Agents page and guide behavior |
|---|---|
| Missing | "No saved scan. Run tego scan from your project folder." Independently remembered Agents discoveries remain with their last-seen time. Find remains driven by recorded runs, else todo. |
| Stale, another boot, future time or unknown freshness | Show a stale or unknown-time notice and scan time. Valid rows may appear only in a historical fold. The guide uses the freshness rule above and decision 6; this scan cannot tick find. Show the command to rescan. |
| Too large, wrong owner/mode/type, link, changed during read, invalid schema or broken invariants | Discard this result's rows. Say the saved scan could not be read and give the fixed reason. Independently remembered Agents discoveries remain, with their last-seen time; no malformed prefix is salvaged. Find stays Todo unless independent run evidence decides it; add the reason to NotKnown lines. |
| Structurally valid forgery by the same user or root | It cannot be detected by ownership, a digest or the schema. Treat it as untrusted reported evidence. It can mislead find, not prove enforcement or select executable text. |

The final row is a residual, not a tamper-detection claim. The claims ceiling
allows the launching user and an unconfined same-user process to rewrite their
files. There is no signature here.  A valid advanced result owned by the
user is not proof that root produced it.

On save failure, print today's result with a failed result-source entry and exit
125. Keep the prior file if replacement did not occur. Say the dashboard still
has that earlier result, or that its state is unknown if rename succeeded but
sync failed. Never imply the disk and stdout are equal after an IO failure.
No reader launches a scan to repair any of these states.

### 5. Advanced scope (B2-3 only)

Require `config.InitNSRoot`, including the initial-user-namespace check.
Direct root uses root's own local-passwd home. Under sudo, resolve the recipient
by the invoking-uid rule; it is a destination choice, not authentication.
An unprivileged advanced request refuses with 125 and the no-reads footer.
The advanced flag is explicit; there is no implicit elevation.

Advanced adds other uids' A matches, fixed user-unit paths in local passwd
homes, system units in `/etc/systemd/system`, `/run/systemd/system` and
`/usr/lib/systemd/system`, `/etc/crontab`, direct `/etc/cron.d` files and fixed
spools in `/var/spool/cron` and `/var/spool/cron/crontabs`. No home walk, NSS,
cron shell body, substitution or script execution. Unsupported forms are
unresolved. Timers show configured relationships, never a predicted firing.
Container attribution uses fixed cgroup patterns and validated ids only; it is
a cgroup suggestion, never a runtime-confirmed name. No engine socket or
namespace entry. Host visibility does not imply every pid namespace is visible.

While root, the collector reads only fixed process/account/boot/unit/cron sources, then closes
their descriptors and retains sanitized observations. Permanently drop every
thread's supplementary groups, gid, uid and capabilities to the recipient before
recipient-controlled settings, project metadata/content, config, ledger probes
or destination opens. Check mode uses the same boundary. No helper. A missing
or failed drop means no recipient reads, no save and 125. Never open a
user-controlled output directory while privileged. Initial root
cannot promise all reads succeed: every denial remains visible. Guest proof
must cover privilege drop, child-namespace refusal and crafted destinations.

### 6. Catalog, guide, dashboard and imports

Create `internal/scan/catalog`. It owns names, rule ids, evidence descriptions,
install paths, settings paths, format keys, dependency names, second-fact rules,
false-hit caveats and fixture provenance. Use the pure `sig` matcher grammar.
Do not add or update `sig.Default` for scan. The production call to
`sig.Default()` in agents feeds both observation and adoption.
Selection can decide whether a Contract is applied at all with `--adopt --boundary`.

B2-1's catalog is exactly the nine `sig.Default` rows and their fixed install
and settings paths, with a test that each default has a catalog row. Keep their
existing selection; guest validation remains owed before release. `sig` gains
fact reporting (`exe-name`, `argv0-name`, `comm-name`, `argv-pattern`, `path`,
`file-id`) with a test that `Match` and guard selection are unchanged.
New rows require a real install checked in a guest. Record version,
layout, exact evidence and a negative collision fixture. The ground study's
vendor statements, including changed package names, are leads, not proof of a
working signature. Cursor's bare `agent`, a generic interpreter or a provider
environment name can never be a built-in basename rule. A generic `goose` or
`copilot` needs its specific second fact. User signatures may name arbitrary
programs; label their matches user-supplied. Do not grow the enforcement-facing
defaults through this catalog.

Put collection in `internal/scan`, a product layer above watcher and catalog.
Put the result types, strict decoder and file reader in `internal/scan/result`.
That read package must not import collection, watcher, sig or the catalog.
`internal/guide` imports this result reader and remains the sole setup chooser.
The Agents page imports the same reader for rows and the guide for step state.
Neither `tego setup` nor a page calls collection. Only `tego scan` writes
`last.json`. Existing setup probes and check storage remain ADR 0142's job.

Amendment 2026-11-12, B2-1b fix round 1: independent recorded-run evidence
retains its current precedence. Otherwise a valid result with status ok or partial
and A or B evidence for the recipient uid ticks find under the freshness rule in decision 4.
Its fact is "found by scan at <time> (any program running as you can change it)".
A partial scan cannot make that positive observation false. Its unreadable sources and limits remain in NotKnown lines;
neither a tick nor these lines claim the scan was complete. A normal systemd
login may have an unreadable own program link and partial status, while an
independent running or installed candidate still ticks find. Settings alone,
a project dependency, G, a configured MCP server or a unit alone cannot tick
find as a running or installed agent. Only items whose uid is the recipient's
count, and the recipient must be the reading user.
A zero-match, failed, stale, other-boot, future, foreign-recipient or invalid scan
leaves find Todo, with its reason added to NotKnown lines. A scan never sets a
step to NotKnown, so it never changes `tego setup`'s exit code. This supersedes
the earlier ok-only requirement and the second reader's conflicting "at any age"
clause. Old installation evidence does not establish current setup progress.
Nothing in scan ticks record, contract, enforce or verified.
Do not auto-link a scan row to a run by a shared basename or folder. A4-2 must
define and show that identity evidence separately. No raw argv is available.

Add these depguard rules in B2-1, with layout and import fixtures:

1. `scan-imports`: collection may import standard library, x/sys/unix,
   `internal/platform/{proc,sys}`, `internal/runscope`, `internal/watch/{watcher,sig}`,
   `internal/scan/{catalog,result}` and the needed spec leaves only.
   Deny runtime, policy, BPF, doctor, ledger, guide, control and CLI.
2. `scan-result-imports`: result reader may import standard library,
   x/sys/unix, platform/sys and spec identity only. Catalog is standard library
   and sig only. Neither package may import collection.
3. `engine-never-imports-scan`: deny `internal/scan$`, `internal/scan/catalog` and `internal/scan/result` from
   `internal/runtime/**`, `internal/policy/**`, `internal/bpf/**`,
   `internal/watch/**`, `internal/runscope/**` and `pkg/**`.
   CLI is a caller above the engine, not an exception for runtime.
4. Keep `guide-never-imports-engine`. Add collection, watcher and sig to the
   guide's denies, with only `internal/scan/result` allowed. Deny collection,
   watcher and sig from control too. Do not deny the result reader with an
   accidental parent-prefix rule. Use the depguard v2 `internal/scan$` plus
   child-prefix form. Add `internal/scan` to rulecheck's governed list.

Existing depguard rules hold the guide away from engine packages, but do not yet
establish these scan boundaries. They must land with B2-1.
Imports alone cannot stop a standard-library syscall. Add forbidden-call rules
and import fixtures for process starts, sockets, DNS and network clients in scan
and its result reader. Keep dashboard checks for these calls too.

The Agents page never starts a scan or any process, on GET, refresh, a timer or a
POST. "Scan again" is fixed copyable text `tego scan`, with instructions to run
it from the intended project folder. Advanced command text waits until B2-3. No execute endpoint exists. The page renders values only through
escaped templates. It never copies a stored command. This closes the path from
a hostile settings file or forged result, through an authenticated dashboard
request, to execution as the dashboard user. It also prevents page refreshes
from becoming repeated privileged or expensive discovery.
The earlier ground-study button proposal is superseded.

A4-1 shows no "all under Tego" summary. Its self-only viewers are the recipient
and a dashboard principal explicitly permitted that recipient's private view;
shared views must omit exe/cwd paths. Label the cache "written by tego scan at
<time>; any program running as you can change it". Never place a last.json string
in `Next.Command`.
A4-1 must label fresh rows "seen at" and retain the coverage footer. Setup and the page
must invalidate cached guide data when the result changes, using its checked
file identity and a short reuse bound. A page reload must re-evaluate freshness
labels and find eligibility under the same rule in decision 4. The shared
Overview guide cache includes scan identity and freshness.

Preserve agents stdout, JSON lines, flags and exit codes. B2-1 adds only two
stderr disclosures: the no-root scan pointer and the current rule names plus the
watch template after zero matches. Today's refusal already has a watch line and
today's snapshot already has a next hint. Append to those; do not duplicate or
replace them.

### 7. Hostile files and finite work

A repository's manifests and MCP settings are untrusted input. The same is true
of PATH entries, a process's names and argv, and another user's files in advanced
mode. No parser follows a directive, include, script or plugin. Links in
content-source paths, at any component beneath the selected root, are not read,
except for the bounded E unit-name alias resolution in the amendment below.
Pin directory descriptors. B2-1a does not enforce a mount-boundary refusal;
a path can cross a mounted filesystem even with every component pinned and
links refused. D/E must specify their content roots and mount policy before
their readers are built. Do not claim that no-follow traversal prevents mount
crossings or stalled filesystem IO.
Pin entries with O_PATH, check the inode type, then data-open that same inode.
Require regular, single-link content files owned by the selected uid or root.
D, E and F use the strict discovery policy described in the scan-permissions
amendment below. Other-write is always refused.
Do not data-open a device or FIFO first.
Never use a path from file content as a new read target. E may resolve an alias
by basename among already enumerated unit roots, under the amendment below. Pre/post fstat must agree on identity, size and mtime; a detected
change discards that file's evidence.

Amendment 2026-11-12, scan permissions, fix round 1: supersedes the B2-1b
primary-gid-only F rule and the earlier broad shared-helper amendment. The
purpose is discovery reads only: fixed vendor settings for configured agents
and tool servers, their selected parent folders, user unit directories, unit
files and drop-ins, and F project declarations. A wrong answer can produce a
false found row. No found row establishes installation, a running process,
enforcement or authority to act.

`internal/grouptrust` supplies a separate strict discovery policy. It loads
complete local passwd, group and nsswitch files, checked by two read passes,
with bounded reads of less than 1 MiB each, only when a selected inode is
group-writable. No name-service
identity lookup is made. Acceptance requires both passes over all three files to succeed and
parse completely, files-only passwd/group NSS sources, an entry for the inode's
group in the local group database, no listed member other than the inode owner,
and no other local account with that primary gid. Missing group entries,
failed, truncated, malformed or size-limited reads, unknown member accounts and
directory-service or other non-files account sources refuse, with the group
and the reason. There is no primary-gid fallback for discovery. Local files
plus systemd or sss NSS sources do not establish complete local evidence.

Amendment 2026-11-13, scan permissions, fix round 4 (supersedes round 2's
metadata-only collection check): read all three account files, each through one
descriptor with the existing caps, then read all three again through fresh
opens. Retain only the first pass's bytes; compare the second pass as a stream
with a fixed 4 KiB buffer, refusing length differences. Keep descriptors alive
until comparison finishes. In each pass, open
all files before reading; compare baseline facts with final descriptor and path
facts after all reads. Accept only if every file's bytes are equal across the
two passes and device, inode, size, mtime and ctime match within and across
passes. Metadata comparisons remain an additional refusal, never proof of equal
contents. Any difference or stat, read, open or close error refuses the whole
collection with accounts-unreadable (size caps retain accounts-limit). There
is no retry; run the scan again for fresh evidence.

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

Account tools replace these files by rename; replacement between or during
passes changes file identity and is refused. An in-place change that alters
bytes read in either pass, size or observed timestamps is refused. Root's
in-place writes that leave both passes reading the same bytes are not detected:
a change undone between passes, or writes interleaved with one file's reads
inside one timestamp tick. Under the assumption that each file is replaced
only by rename during collection, the combined evidence was true at the
moment between the two passes.
Membership changed after the scan remains a limit.

This is local membership evidence, never a statement that nobody else could
write the file. A running process can hold retained supplementary group
credentials after its account is removed from the group; membership can change
after the check; a container can show host files whose host group members are
absent from its own databases. These limits apply even when every local read
passes both byte and metadata comparisons, subject to the stated collection
limits. Same-user and root writers can also forge observations.

World write and foreign ownership refuse. A group-write exception also requires
absent access ACLs on the pinned inode; an ACL or failed ACL query refuses with
the group named. Parent metadata is checked before and after content reads.
A parent refusal preserves that parent folder's path, so its repair targets
the offending parent rather than the selected leaf. The descriptor checker
admits only Getxattr's synchronously resolved pathname argument; its attribute
name remains outside the borrowed-path allowlist. Metadata-only B/C observations
retain their type/executable tests without a content trust claim.

Account and boot metadata, record events, record locks, run directories, `.tego`
and the saved result's parent retain the base's exact group/other-write
refusals. The saved directory and file still require exactly 0700 and 0600.
The product's binary-location checks and their existing membership fallback
remain unchanged in `internal/selfbin`; their incomplete-membership limit is
separate follow-up work to revisit with measured layout and lookup costs.

A mode refusal has reason mode and a repair in the footer. At every discovery
call site a group refusal names the group in optional `writable_group` (or
`gid N` if a bounded local name is unavailable), with no settings values. The
reader accepts it only on not-read/partial mode sources and validates its
grammar. Optional `group_evidence` records a bounded reason code:
accounts-unreadable, accounts-limit, accounts-malformed, directory-service,
owner-not-local, group-missing, shared-primary, other-member or access-acl.
It is valid only with a group-labelled mode refusal. The footer renders the
reason in plain words, including directory-service, rather than treating all
failures as known sharing. The footer says `chmod g-w -- <quoted path>` for
the offending file or parent. World-write refusals say `chmod o-w`;
foreign-owner refusals ask for an owned copy or corrected ownership. Matching
readers are needed for the optional source field; older strict readers may
refuse these newer snapshots.

The following acceptance table is measured by `TestDiscoveryOrdinaryLayouts`
using injected account facts. Root ownership is checked separately with injected
inode facts; the root-vendor collector row uses test-owned files at vendor modes,
not actual /etc files or a privileged chown. It is fixture evidence, not a
measurement of installed distributions or their actual NSS defaults. Each layout selects one
MCP source, one unit (including a drop-in) and one project declaration. Ordinary
UPG fixtures explicitly use files-only NSS. Every group-writable selected file
is 0664 and selected directory is 0775 unless the row says otherwise.

| Layout and account evidence | Retained MCP / unit / project rows | Read or refusal |
| --- | --- | --- |
| Ubuntu-shaped default user-private group, complete files-only local evidence | 1 / 1 / 1 | All three selected sources read; local group exists with no other listed or primary-gid member |
| Fedora-shaped default user-private group, complete files-only local evidence | 1 / 1 / 1 | All three selected sources read under the same strict rule |
| Shared primary group (`staff` or `users`), second primary-gid account without a listed member | 0 / 0 / 0 | All three group-writable sources refuse mode, naming the group and sharing reason |
| Domain-joined layout, files plus sss NSS | 0 / 0 / 0 | All three group-writable sources refuse mode for incomplete directory-service evidence; primary-gid equality cannot override it |
| Root-vendor mode fixture for selected /etc sources, files 0644 and directories 0755 | 1 / 1 / 1 | All three selected sources read without group-membership lookup; root ownership decision is checked separately |

A local UPG layout whose NSS also enables systemd, sss or another provider
refuses group-writable discovery sources until `chmod g-w` removes their write
bit. Non-group-writable owned files remain readable without loading account
facts. Complete fresh-login vendor and actual second-principal acceptance is
**owed in a guest** and remains a merge condition.

B's glob directory metadata must agree before and after enumeration. Discard
its names on a change or read failure. B's link exception is metadata only:
at most eight link hops. Resolve components
with pinned descriptors. Never open or execute a target's contents. A special
file target is not an installed program. Never apply this installed-program metadata exception to D, E, F
or the saved result. E has its separate bounded unit-name alias rule below.

These are initial bounds, to be measured rather than advertised as fast:

| Resource | Limit and result on reaching it |
|---|---|
| Process enumeration | 32,768 pid entries, sorted; 256 thread entries per process; 256 ancestor links per candidate. Invalid or deeper ancestry retains independent evidence and makes grouping unknown. Incremental bounded enumeration, not unbounded ReadDir followed by a cap. Overflow is partial A and unknown for a negative check. |
| Per process | 256 KiB across leader and fallback tasks, charged for failed reads too; 64 KiB cmdline, 4 KiB each status, stat, cgroup and link text; 256 argument tokens. A partial token never matches. Oversize required data means not read, not a negative match. |
| Install discovery | 64 KiB PATH spelling, 64 absolute PATH entries, 256 entries per catalog glob directory, 2,048 candidate paths in total. No recursive walk. Count and report excluded relative entries. |
| Content | 1 MiB per file, including passwd, limit-plus-one even if stat reports less; 196 MiB basic total input with the allocations in decision 1. F reads at most two content files; D/E use the measured attempt bound in the amendment below. Advanced uses the B2-3 measured allowances below. The separate allocations bound input, not process RSS. |
| Custom signatures | At most 64 rules, 4 KiB per spelling and 256 tokens total. Reject oversized input as usage. Never print a rejected spelling. |
| Parse shape | Depth 32, token length 4 KiB, 4,096 keys/tokens per file, 128 entries per selected table. D JSON applies token/entry bounds only to selected structure; ignored keys/values use file bytes, depth and deadline alone. Reject duplicate selected JSON keys; ignored JSON duplicates are discarded. F and TOML retain duplicate checks. No YAML aliases, anchors or tags. Unsupported JSONC/TOML/requirements syntax is not read. No include resolution. |
| Retained result | 512 items, 2,048 source entries, eight evidence facts per row. One MiB serialized maximum. Reserve space for coverage before collecting items. Never trim JSON bytes or omit the footer to fit. |
| Time | Two seconds total basic; ten seconds advanced. Check cancellation between reads and tokens. A deadline produces partial sources and unknown A coverage if A did not finish. This is not a hard IO deadline on a hung filesystem. |

Process-budget measurement (fixture, 2026-11-12): 1,000 processes with 1.5 KiB
status, 512-byte argv and identity rechecks consumed 4,019,786 bytes. The 8 MiB
allocation gives 2.09 times that measured input. This measures fixture input,
not desktop performance or a guest. Directory-owner filtering costs no content
bytes for other nonroot uids. Each process shares a 256 KiB allocation across
its fallback tasks; exhaustion leaves a stated live coverage gap and collection
continues where possible. Total exhaustion emits an unknown-remainder source,
partial status and unknown negative check, rather than failing the whole scan.
The matching 1,000-process guest measurement is owed in a guest.

When an individual source fails, remove all evidence derived from that file.
Retain independent evidence. List its path and a fixed reason in sources and the
text footer as "not read". Do not echo the bad value. If source entries themselves
hit the cap, retain one reserved limit row per kind naming the unexpanded scope;
stop that kind. Do not pretend every failed file can still be listed. A source
omitted by the cap must be accounted for as unknown remainder. Maintain an
encoded-byte budget for both source and item insertions. Reserve 64 KiB of
the one MiB result for fixed failure and coverage rows. If either insertion
would exhaust its budget, stop that kind and emit its reserved limit row.
Evidence with no room for its source cannot be retained.

Unsupported syntax is a visible refusal to classify. Do not fall back to regex
over raw files or to invoking another tool. B2-1b needs bounded JSON and requirements dependency readers.
B2-2 adds pyproject TOML without a new dependency. B2-2 needs one fuzz target for each settings
format adapter and the shared ExecStart parser. Use current dependencies only.
A format that cannot be safely supported within them waits, with a not-read
entry. A timeout on local work cannot guarantee timely return from a remote
mount or a stalled kernel read; avoid claiming a hard runtime bound.

### 8. Acceptance

- Fake proc/home tests cover identities, races, ownership and denied reads.
- Canary secrets never reach retained data or output; environ is never opened.
- Every found row names its fact; footer and check reflect unknown coverage.
- Schema and strict decoder reject unknown codes, duplicate keys and forgery tricks.
- Private atomic storage rejects unsafe paths and files; same-user forgery stays explicit.
- Plan rows and fixtures hold fuzz, race, vet and guest proof owed.

## Rejected

- Current agents/Sighting output: it retains argv and loses read failures.
- Adding discovery names to guard defaults: selection can decide whether a Contract applies.
- Home walks, code, memory, provider keys and addresses: they cannot establish purpose.
- Saved commands or executable paths as copy actions: quoting cannot make them safe.
- Dashboard collection or elevation: a request must not become a discovery or execution endpoint.
- A signed or checksummed display cache as trust: its owner can forge it.
- Check success after unknown A coverage, or cgroup membership as verified enforcement.

## Consequences

The intended UI exposes evidence and limits without requiring signature syntax.
Usability has not been measured.

The result can contain sensitive metadata even without argument or credential
values. Its owner and an unconfined same-user process can forge a valid report.
A snapshot cannot prove absence or describe activity between reads.
Under no circumstances does scan claim a machine is safe, an agent is authentic,
or a run was enforced or verified.

Environment reads and dashboard execution remain excluded unless a later ADR
changes this decision.

## Plan split after the second reading

| Row | Delivered scope | Deferred to the next row |
|---|---|---|
| B2-1a | A, B, C, G; human output, JSON, check; result writer/reader; catalog; depguard/rulecheck; agents stderr. | No F, guide wiring or guest. |
| B2-1b | F (package.json, requirements only), guide wiring, Ubuntu guest. | pyproject.toml. |
| B2-2 | D, E, pyproject.toml. | Advanced. |
| B2-3 | Advanced scope. | Dashboard belongs to A4-1. |

The rows are not a claim that implementation fits any particular time.

## Implementation checkpoint

B2-1a now registers `tego scan` for A/B/C/G, short and verbose text, JSON,
check, private atomic storage and strict saved-result reading. Fixture tests run
the whole command entry point in every output mode with markers in argv[0],
other argv, comm, cgroup/unit names, environment blocks and settings-file keys,
and check the written cache. A stand-in
proc read audit and an inotify tripwire cover environment/content opens. JSON
from the actual command is checked against the published schema. The agents
additions preserve legacy output except for the two additive stderr lines.

The reader supports c1/c2 and c3 with A/B/C/D/E/F/G and advanced-refusal objects.
Reserved later kinds and catalog revisions are rejected as unsupported until
implemented. Same-user forgery remains possible. A record probe establishes
recorded liveness only; it checks no enforcement, tier or chain authenticity.
The shared deadline checks work between reads, not a hard kernel IO deadline.
B2-1b adds F and the shared setup/Overview guide, with state, exit-invariance
and replacement-cache fixtures. F parsers each passed a single 60-second fuzz
run; source/refusal and privacy mutations fail at runtime. The exact guest recipe
includes F, setup and mount refusals but has not
been run. D/E and advanced have later amendments below; pyproject remains
deferred. The A4 amendment below supplies saved Agents data and minimal fallback
handlers; the approved page integration remains A4-PAGE.
Vendor layout, root/permission, namespace and syscall proof in a guest is owed.

## Amendment 2026-11-12: B2-2 configured servers and user units

D selects six catalog paths: user `.claude.json`, project `.mcp.json`, user and
project `.codex/config.toml`, and user and project `.gemini/settings.json`.
JSON selects `mcpServers` and only Claude's `projects.<current folder>.mcpServers`,
with scope `local`; other remembered project folders are streamed and discarded.
The project-path comparison is transient; no remembered path enters a row.
TOML selects `mcp_servers.<name>`. The catalog adds no client or process signature. Opencode's
MCP format and clients outside the catalog remain unknown formats. These are
configured observations, never evidence of a running server. Coincident home/project
paths are read once, retaining their user scope. Vendor evidence
and the exact real-install checks remain owed in a guest.

Streaming JSON and TOML grammars validate ignored values as well as selected
fields. Each file has a 1 MiB limit and depth 32. JSON ignored subtrees retain
no keys, values or duplicate-key digest maps and incur no selected token or
entry charge. They are bounded by file bytes, depth and the shared deadline.
Selected JSON structure has 4 KiB scalars, 4,096 tokens and 128 servers/arguments;
duplicate selected keys reject the file. Duplicate ignored JSON keys are
accepted and discarded. TOML retains 4 KiB scalars, 4,096 tokens and duplicate
checks, with a new 4 KiB combined decoded section/key bound including separators
before prefix bookkeeping. This bounds repeated prefix hashing independently of
a long section name. TOML multiline strings, array tables and unsupported primitive spellings (floats, dates, non-decimal forms
and leading plus signs; only booleans and plain decimal integers are accepted)
refuse the file rather than salvage its prefix. Environment, arguments, headers, URL text and unknown values are
dropped while scanning. Commands resolve only to the four existing native catalog
program ids, or null. Argument counts survive. URL host stays null; no URL text
is shown. This is stricter than the ground study's proposed host display.
The added server name is printable metadata, at most 256 bytes. This explicitly
amends decision 3's prohibition on copied names. A credential hidden in a server
name remains private metadata; the parser cannot identify that disguise.

D selects home and current directory as content roots. E selects only
`~/.config/systemd/user`, `/etc/systemd/user`,
`~/.local/share/systemd/user` and `/usr/lib/systemd/user`, in that precedence
order. Pin roots without following links. Below each selected root use openat2
with BENEATH, NO_SYMLINKS and NO_XDEV for ordinary content paths.
A selected root itself can be a mount.
No fallback weakens the mount policy. Pin a regular single-link file, check
owner (caller or root), size and the strict discovery mode rule above, reopen that inode, then
check metadata and pathname again. Changed input discards its observations.
D/E share 6 MiB of charged content reads and 2,048 content attempts. These
are input and retained-structure bounds, not a process RSS guarantee. The
deadline is best effort between reads, not a hard bound on stalled kernel IO.

E enumerates at most 4,096 names per selected directory, 1,024 directories and
4,096 charged entries in total (cached across units). The total includes raw
names from rejected or failed listings and overflow lookahead. Each attempted
listing spends at least one slot, including empty or failed listings. A listing
receives only the remaining allowance, with one slot reserved for lookahead; a
listing that fills it is refused. At most 4,095 names can therefore be accepted
from one directory. Exhaustion prevents further enumeration. Absent folders
cost no directory budget. Content reads select service, timer and applicable drop-in files only. Unit collection caps retained source and item
arrays at 400 KiB and 450 KiB before the shared result budget, reserving a limit
source. Repeated failed entities count once; extra reasons carry zero counts.
The first main file by precedence wins.
For same-name drop-ins, directory priority precedes instance/template/dash-prefix
specificity within each root. Type-wide folders are searched last across roots.
Distinct filenames merge lexically. Canonical-name drop-ins precede alias-name
drop-ins, with competing alias names sorted; live parity for those conflicts
remains owed in a guest. Empty ExecStart resets previous commands. Multiple ExecStart lines
remain separate configured observations for oneshot services; other service
types with multiple starts are refused as unsupported. The user_units count counts these
observations plus timer relationships, not distinct filenames. The parser accepts
a measured subset of systemd ExecStart single/double quoting, including quotes
within words, C escapes, odd trailing-backslash continuations and executable prefixes `-`, `@`, `:`, `+`, `!` and `!!`. It drops all argument text. Native and Node-wrapper
starts use the nine inherited catalog rules. Wrapper tokens are matched one at
a time; values after secret-like flags are skipped, and only the catalog id
survives. The four unit rule groups appear even with zero findings. Units allow
256 arguments plus the program and optional `@` argv0 override.
The override is excluded from the argument count. Percent specifiers stay
unexpanded; their presence is shown. A program specifier, environment expansion
in any program/argument position, or a launch wrapper is unresolved. `:` disables
argument environment expansion and `$$` is literal as in systemd. A Node script
specifier may remain classifiable when its fixed text matches a catalog suffix.
Shell/env/Tego wrappers plus nohup, timeout, nice, setsid, stdbuf, npx, bunx, uvx,
tmux and screen, and the shell-launch prefix `|` (alone or combined with
other prefixes), are unresolved. Their failed E source has fixed reason
`unresolved`, names the unit path and says startup could not be determined.
Malformed or unsupported syntax still says could not be read. Verbose read and
missing rows carry neither failure phrase. The negative no-match summary is
printed only for complete (`ok`) snapshots, so it cannot undercut unresolved
source warnings even when no numeric limit was reached. No systemctl, D-Bus, environment
expansion or discovered command is run.

A unit alias link is classified by its normalized spelling, then resolved by
basename under the selected roots' ordinary priority. Only in-root link spellings
qualify; outside links are reported without reading a target. Alias traversal
has a 16-hop resource budget; systemd's semantic limit of seven symlinks is
checked separately. Link-owner and pre/post identity checks apply. Selected-root,
drop-in-directory and regular-content checks enforce their applicable modes.
A symlink's ordinary 0777 mode does not grant data access. Ordinary content paths
and drop-ins
keep the no-link rule. This amends decision 7's blanket E link refusal, to match
systemd's alias-name semantics while confining all content to selected roots.
Wants links are metadata only; targets are never followed. Enabled instance
names resolve through already catalogued template files. Instance drop-ins win
over less specific folders within the same root; root priority still applies. Timers retain only
validated configured service relationships when that service matched.
Runtime/generated unit directories and custom XDG roots remain excluded.
The footer explicitly lists omitted default roots `/etc/xdg/systemd/user`,
`/usr/local/lib/systemd/user`, `/usr/share/systemd/user`,
`/usr/local/share/systemd/user` and `~/.config/systemd/user.control`.
Configured startup does not prove that systemd loaded or started a unit.

The supported unit grammar is informed by upstream [systemd.syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html),
[systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
and [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).

Catalog c3 and `tego.scan/1` add optional nonzero counts `mcp_servers` and
`user_units`, config detail fields `server` and `arguments`, and unit detail
fields `unit`, `arguments` and `specifiers_unexpanded`. Existing fields retain
their meaning. New readers retain c1/c2 support. Older readers refuse c3.
D uses the reserved mcp-key evidence; E uses exec-start. Neither ticks Find.
D/E read failures and unresolved startup keep partial status and named source
warnings. They do not decide the process-only check in decision 3. Definite
Outside process findings keep priority 1; unknown process coverage remains 125.
Pyproject remains deferred in this D/E package; advanced follows in B2-3 below.


### Fix round 1 (2026-11-12)

The process-only check rule is restored for D/E, as for B/C/F. Ordinary stock
IBus shell/env launchers remain unresolved; they cannot turn a completed process
check into 125. Source failures remain partial and are never absence evidence.
Ordinary distribution-shaped
fixtures must finish all selected content without spending budget on absent
drop-in folders. The fixture inventory records measured units, aliases, folders,
entries and line lengths; input caps provide at least tenfold headroom over its
largest measured shape. Fixture acceptance is not live desktop evidence.
The inventory is in
[the measured unit fixtures](../../internal/scan/testdata/unit-layouts/README.md).
Ubuntu 24.04.4 Desktop measures 94 units, 1 alias, 5 drop-in folders, 20 folders
including the two roots, 218 entries, 167 names in its largest root and a
162-byte longest line. Fedora 44 Workstation measures 112, 6, 41, 54, 288, 221
and 136 respectively. Debian 13.7 GNOME measures 86, 2, 5, 18, 202, 159 and 200.
Largest content is 1,826 bytes/file and 77,247 bytes/tree; largest unit has
63 lines plus ExecStart words, 14 command words and one ExecStart. The input
caps above, 4 KiB physical/logical lines, 4,096 combined physical lines and
ExecStart words (checked on every line, including trailing comments), 128 starts
and 256 arguments provide at least tenfold headroom over those observations.
Retained-result byte/item/source caps remain the separate bounds in decision 7.

The versioned differential table in
`internal/scan/testdata/systemd-execstart.json` records actual commands from
systemd 257. Its ExecStart parser removes quotes inside words, including
`co"dex"`; quotes are not literal in that oracle. Even trailing backslash runs
do not join the next line; odd runs do. The table also covers comment/blank-line,
EOF, CRLF and prefix cases. These cases support a subset, not full systemd
conformance. Distribution unit load equivalence, alias/drop-in precedence in a
running manager, permissions, namespaces and syscall tracing remain owed in a guest.


### Fix round 2 (2026-11-12)

The directory allowance is charged before parsing, inode rechecks or error
handling can discard names. It includes failed/overflow listings; reaching it
stops enumeration. The combined unit budget counts physical lines and ExecStart
words even after the last command. These correct the earlier implementation,
which could enumerate rejected lists for free and accept trailing comments over
the combined cap. Directory payload is at most 4,096 names, or 1,044,480 bytes at
255 bytes/name; D/E content reads remain at most 6,291,456 bytes and 2,048 attempts.

The installed systemd.service(5) manual identifies itself as "systemd 257.9"
(package 257.9-0ubuntu2.5). Its COMMAND LINES table lists `@`, `-`, `:`, `+`, `!`
and `!!`. Tests cover each, permitted combinations, argv0, quoted paths, escapes,
literal dollars, environment/specifier uncertainty, resets and multiple commands.
The documented escaped `\;` is a literal argument. The newer shell-launch
prefix `|`, documented by [systemd v260](https://github.com/systemd/systemd/blob/v260/man/systemd.service.xml),
is unresolved in any prefix position, including standalone `|` and `@|`.
It cannot become a clean non-match. Prefix handling classifies the executable;
it makes no claim about privileges, exit handling or actual execution.

Capacity fixtures retain their measured synthetic shapes. Separate original
public-image and permitted machine-root fixtures exercise unchanged distribution
contents. Documented upstream examples are marked separately. Their offline
parser and collection tests allow named unresolved launchers but require no
"could not be read" warning and preserve the process-only check. This proves
compatibility with those captured contents, not live manager equivalence.
Provenance and licence notices are in the fixture inventory. Live load, alias,
permission and namespace checks remain owed in a guest.

## A4 core amendment, 2026-11-12 (fix round 1)

`internal/agentid` is the shared, pure evidence projection used by setup and the
Agents data service. The row rule is one named recorded run per recorded row.
Each row carries that run's id and start time. A later run, including a live,
broken or unchecked one, has its own row. No stage combines facts from several
runs. This deliberately avoids selecting one run as a statement about an agent
in general or a process that might still be running.

For a run that passes its check, command, folder spelling, known launcher uid,
tier, contract source, ended state and verdict come from one checked record
snapshot. Unchecked metadata is a labelled recorded claim, never an established
later stage. Reading
metadata from one inode and verifying a later replacement cannot establish any
stage beyond Recorded. Verification uses the dashboard's shared chaincheck
walker over immutable bounded bytes and the current file-chain anchor head.
The projection budgets 32 runs and 32 MiB per load, at most 8 MiB per run; Agents
also sets a 20-second context. The guide cache holds at most 256 entries for 15
seconds, keyed by device/inode, size, mtime, ctime, full-content SHA256 and
anchor path/head. Setup and Agents share that cache; this does not reuse the
control read model's separate chain cache. A cache hit still requires a bounded
pinned record read. One pinned immutable anchor snapshot, bounded to 4 MiB,
supplies all selected heads for the load; its descriptor and path identity are
checked before and after reading. An oversized, unreadable or changing anchor
leaves every affected run not checked. A run beyond the record budget says
not checked yet.
Timeouts, missing anchors, changing records and broken records retain their
plain reason and next step in the data and in fallback HTML. None can establish
Contract, Enforced or Verified. Unknown uid remains distinct from uid 0.

Scan retains no arguments and never joins a recorded row. An outside process
observation is its own row, with its observation time and Record it. Exact
absolute program path, exact folder and known uid equality may supply only the
words "may be the same program" and the warning that the scan keeps no arguments
and cannot tell. Those words transfer no stage. There is no basename, current
PATH, symlink, folder-name or unique-native-executable join. Interpreter and
wrapper paths cannot identify a workload; the next step asks for the person's
own launch command. An observation marked inside a Tego run adds no row or
label: records already list runs, and the footer counts those observations.

Found is observation text citing scan rules, sources and time, never a stage
tick. All stage ticks belong to named recorded runs. Recorded cites this run's
run_start. Contract requires that run's checked explicit contract_source.path
and a current successful compile of that path in the same run's folder, tier,
grants and run-directory context. A similar name or another run's compile is
not evidence. A direct file outside setup's registry checks, or a new learned
contract no run names, remains unknown. Enforced requires this checked run's
explicit landlock, cgroup or bpflsm tier. Verified requires that same ended
enforcing run's affirmative chain check against its anchor. These are statements
about the named recorded run, never current kernel state. Setup exposes the
same rows as additive `agents` data in `tego.setup/1`; its existing machine-level
six steps and exit codes keep their meanings. Argument values are neither
serialized in this inventory nor displayed by it; existing setup step facts
retain their bounded command descriptions.

The `internal/control/agents` service reads the saved scan through `result.Read`,
with its existing 1 MiB, 0600, single-link, owner and freshness checks. It owns a
private leaf store at `~/.tego/agents/discoveries.json`, bounded to 256 entries
and 256 KiB, of remembered discoveries: observed program path, folder and uid,
first and last seen times, and source scan reference. Only omission from a usable
latest scan means "not seen in the latest scan". A remembered discovery remains
visible with its last-seen time until 30 days without a sighting. Historical, failed
or unreadable scans are labelled as such with a rescan instruction; they do not
establish omission. Missing or unreadable scan results do not erase discoveries.
Unsafe, oversized or unreadable remembered state is disclosed and treated as
empty for that load without overwriting it. The store uses owner checks,
no-follow opens, 0600 files and atomic replacement. Entry and byte bounds are
explicit. Overflow cannot silently evict discoveries that have not been shown;
any list truncation is stated. Unexpired existing entries stay; overflow
newcomers are omitted, so a flood cannot evict earlier discoveries. Recorded
rows come first; observation rows are ordered by oldest last-seen first. A
Forget action belongs to A4-PAGE and is not supplied by these handlers.

Stale, future, other-boot, failed and unknown-time scan observations are historical
only; observations never establish a stage tick at any freshness. The footer
retains unreadable sources and limits. This is what scans have seen, never proof that nothing else
runs. An unconfined process of the same user can rewrite both the saved result
and remembered store. Ownership, a digest and schema validation do not detect a
valid forgery. The existing own-state limit is accepted for this slice by the maintainer, not
an Agents merge blocker. The found list comes from scans. Tego refuses ordinary writes to these files, even with a whole-home grant at tier landlock; this was shown in guest row whole-home-landlock. With the anchor and ledger outside the home, a whole-home grant with direct reads can leave these files readable at landlock; that read case is derived from code and is owed in a guest. The stages shown for a run do not depend on this list.
R10 still refuses grants covering the actual anchor or ledger and direct grants
inside the compile home's `.tego`. Moving the anchor and ledger outside the home
can allow a home grant, but the nested Unenforced row is a read deny.
`builtin.tego_surface` still refuses ordinary content writes. Guest5 rows
whole-home-landlock, whole-home-cgroup and whole-home-bpflsm in gproof1 recorded
both opens refused by the seccomp supervisor; this is not direct BPF-hook proof.
Direct reads beneath the home grant at landlock and same-uid mode changes remain
separate limits. The direct-read case below is derived from code and owed in a
guest. Aliases, inherited descriptors and exposed outside services retain the
existing platform limits; this correction adds no enforcement guarantee for them.

The record count is observed refusals in the local calendar day, with an
inclusive start and exclusive next midnight, through the same deduplicating
read model as Logs. Cut, malformed or incomplete records mark it a lower bound;
refused reads may not be recorded at some tiers. It is not a claim of zero
refusals outside that record.

`/agents` and `/agents/<identity>` initially render minimal escaped HTML.
`/` shows Agents only when the shared guide's completion fact says done;
`/overview` always retains Overview. The existing loopback, same-uid, session
and CSP checks apply. No scan execution endpoint exists. The only refresh
command is fixed `tego scan`, with instructions to run it in the intended
project folder. Record it is a template with the user's own command to fill in:
`cd <quoted known folder> && tego watch -- <the command you start it with>`.
The folder must be absolute, bounded and printable without transformation;
`internal/shellword.Quote` preserves it exactly. Unknown or unsafe folders get
no copy command. An observed executable path never becomes a launch command.
The template/style integration, phone detail recovery, Forget action and browser
proof remain part of the Agents page work. Paired recorded/scan fixtures measure
ordinary launch spellings without relaxing the identity rule; their table and
matched, separate and cannot-tell counts are in the fix-round report. End-to-end
scan, state protection and kernel claims are owed in a guest.

### A4 fix round 2: own-state disclosure and record limit (2026-11-12)

The footer, package doc, GAPS C52 and Agents user page carry the corrected disclosure
above. Unreadable scan/store modes and links show the affected fixed paths and
manual repair steps. Readers never chmod or follow a planted leaf/directory link
to repair it. Every readable recorded row remains, with the same checked facts.
`TestLoadUnsafeStateShowsRepairAndKeepsRecordedRows` covers chmod 000, chmod 0644
and a symbolic link for each file and `~/.tego/agents`. These are reader tests,
not proof of kernel write denial.

P2 uses the maintainer's fallback. Compile marks write-covered read-deny targets
`FSRule.Unenforced` (`compile_fs.go`, `unenforced`); `heldReads` retains resolved
targets, covering writes and built-in status. For direct landlock reads,
`heldReadsDiagnostics` emits `CodeUnenforced`. Ordinary run_start records the tier
and only each nested target's rule string in `fs_reads.nested`. It drops resolved
targets, covering writes and own-state classification. A declared deny can replace
the built-in row, and RuleName preserves its raw spelling. A generic capability
or rule-name comparison cannot establish historical write exposure. In particular,
a nested read marker is not evidence that builtin.tego_surface permits writes. Adoption
currently requires cgroup and its start omits fs_reads; a landlock acceptance cell
must use a launched run with the anchor-outside-home compile context.

No current contract, scan timestamps or discovery-store contents substitute for
that missing recorded fact. No caution or unconfirmed-after-run fields ship in
this round. Historical own-state exposure work requires allocation of a record
minor only after its need is reassessed against the built-in write floor; this
amendment changes no record format. A write caution requires an actual exposed
write case, not the direct-read case below.
When available, the view must compare checked run intervals with scan and store
write times, carry the caution and unconfirmed state, and clear them only after
a newer scan. The page must render those fields, never derive them itself.

#### Owed in a guest: external-anchor direct-read residual

The old successful-write expectation is withdrawn. Guest5 whole-home-landlock
in gproof1 refused both ordinary writes. Its FAIL(b) was a wrong expectation;
whole-home-cgroup and whole-home-bpflsm also recorded seccomp refusals.
The following residual is derived from code and is **owed in a guest**.

1. In a disposable Ubuntu 24.04 guest with BPF LSM, use a test account with a
   real `.tego` directory, an authentic scan and a seeded discovery store.
   Save bytes, modes and recorded row ids/stages. Keep the contract, machine
   config layers, profiles, registry, binaries, actual anchor and ledger outside
   every home write grant. Merely moving the anchor is insufficient if another
   R10 target remains under the home. Do not move a real user's product anchor.
2. In a guest harness compile `fs.write: ["~"]`, `fs.reads: direct`,
   `record: full`, `WithHome(testHome)`, `WithChainAnchor(externalAnchor)` and
   the external ledger, with `.tego` present before compile. Confirm the nested
   FSDenyRead row is Unenforced and direct-read CodeUnenforced is reported.
   Confirm Builtins.TegoDirs includes that home's `.tego`. This is a launched
   run, never a landlock adoption: boundary adoption requires cgroup.
3. At landlock, read both `~/.tego/scan/last.json` and
   `~/.tego/agents/discoveries.json` using O_RDONLY from inside the run. Expect
   success with direct reads beneath the home grant. Separately attempt ordinary
   O_WRONLY|O_TRUNC writes; expect builtin.tego_surface refusal and unchanged
   bytes. A read result alone must not establish write authority or a caution.
4. Restore originals before each tier. Compile anew at cgroup and bpflsm with a
   deciding kernel plane, root launcher and test-account agent uid. Expect the
   same reads and writes refused. Check actual tier/plane, checked records and
   bytes. An unavailable tier or fallback is not a passing cell. Separately
   use held reads at landlock and expect reads refused. Capture qemu and harness
   exit statuses. These residual reads and held-read controls are owed in a guest.
5. As controls, the normal home anchor with the whole-home grant must refuse
   compile, as guest5 normal-anchor-compile and normal-cli-anchor already showed.
   Direct grants at/inside `.tego` must also refuse, even with external state.
   Outside-Tego same-user rewrites remain possible. Existing mode/link reader
   cells in guest5 establish repair notices and preserved readable recorded rows,
   not governed chmod denial. No dedicated scan/store mode restoration is added.

No per-run write caution is required for the ordinary refused writes. Any future
caution/interval/rescan acceptance first needs a demonstrated write-exposure
case and a justified historical record fact. Page/browser proof remains owed.

### A4 fix round 3: remembered relations and readable contention (2026-11-12)

Remembered observations resolve against the current load's recorded-run facts on
every load. Related run ids and relation words are recomputed, never persisted as
run authority. Observations remain separate rows with no ticks. A usable fresh,
nonfailed scan may establish an omission; historical, failed and unreadable scans
instead explain their availability and request another scan, keeping last-seen time.

A busy exclusive store lock reads the last committed snapshot with the same pinned
descriptor, owner, mode, link, size and identity checks. It performs no store write
and asks the viewer to refresh to retry. Other lock failures remain disclosed.
The fallback renders the whole Footer visibly outside collapsed details.
The approved page must preserve that visibility; template/style integration, phone detail
recovery, the Forget action and browser proof remain pending.

The warmed verification cache is covered directly by a record replacement and
extension regression. Its existing stamp, content-digest and anchor-head key remains
unchanged. These fixture checks establish no kernel mutation protection; actual
the external-anchor direct-read residual remains owed in a guest.

### A4 fix round 4: correct the protection disclosure (2026-11-12)

The compiler's nested read-deny marker was misread as a content-write exception.
`compile_builtin.go:48` includes the compile home's `.tego` in TegoDirs;
`builtin.go:154-179` applies the unconditional write floor before contract grants.
External anchor/ledger placement does not remove it. `compile_fs.go:891-923`
marks read denies only. No execution rule, refusal or record field changes here.
The footer stays visible and now distinguishes the guest-proven ordinary write
refusal from the external-anchor direct-read residual derived from code.

## Amendment 2026-11-12: B2-3 explicit root scope

`--advanced` now requests initial-namespace root through `config.InitNSRoot`,
the same root test used by `tego agents`. The scanner keeps its own minimized
process reader; it does not call the watcher's environment reader. Without
that privilege it exits 125 before discovery, with a clear fixed message and
no-reads footer. Basic scope and its no-sudo rule remain available.
No new catalog process signature or enforcement selection is added.

Advanced A selects every visible process uid. Its observed uid is the real uid.
After reading status, a stable proc directory owner may be the effective uid or
root: Linux can give root the metadata for a nondumpable process even when this
privileged caller can read its program link. An unrelated owner remains unknown.
All four uid fields and directory ownership are rechecked; the same rule applies
to fallback tasks. Basic scope retains its equal-uid and hidden-program rules.
Synthetic measured cases include root-owned readable metadata and a nonroot
effective uid, both classified; an unrelated owner remains a coverage gap.
Actual dumpability and setuid ownership behavior is owed in both guest rows.
All required identity and
membership rechecks, discarded argv, transient matching, exited/kernel-thread
counts and unknown-coverage rules still apply. Advanced program-link denials
are generic A gaps, without the basic-only unreadable-program acceptance or
pid-list exception, even for uid 0. G remains recipient-only. Unmatched
interpreters from other uids receive no G-only cgroup or cwd read. Matched A
processes retain cgroup membership and validated container hints for every
visible uid, but cwd is read only when the real uid equals the recipient uid.
B/C/D/F remain recipient/project scope. Other users' arbitrary settings,
MCP files and projects are not added to the read policy. Local account lookup
uses only bounded `/etc/passwd`, never NSS or a home directory walk.

The shared unit reader selects fixed `.config/systemd/user` and
`.local/share/systemd/user` paths beneath local-passwd homes, with the existing
machine user-unit roots. System units select `/etc/systemd/system`,
`/run/systemd/system` and `/usr/lib/systemd/system`, in that priority order.
The same service/timer/drop-in grammar, no-mount/no-link content policy and
bounded confined alias rule apply. An ordinary outside-root distribution alias
is disclosed; it neither permits a target read nor makes process-only check
unknown. A timer is a configured relationship, never a firing prediction.
Generated unit folders and omitted default/custom load roots remain excluded,
including `/run/systemd/generator`, `/run/systemd/generator.early`,
`/run/systemd/generator.late`, `/run/systemd/transient`,
`/etc/systemd/system.control`, `/run/systemd/system.control` and
`/usr/local/lib/systemd/system`.

Cron selects `/etc/crontab`, direct `/etc/cron.d` files and account files in
`/var/spool/cron` and `/var/spool/cron/crontabs`. No other spool subdirectory or
content-specified path is selected. The cron adapter drops schedule, account
spelling, assignment values and command text while parsing, retaining only a
local uid and closed catalog program id. It shares command token matching and
secret-value dropping with ExecStart, with cron's shell lexical rules and no
shell evaluation. Unsupported shell/substitution/percent-input forms are
unresolved and produce no salvaged file prefix. A malformed, changed, unsafe
or bounded source says it could not be read. A known absent source is missing.
Spool directory checks accept the ordinary root-owned sticky group-write
layout; they do not relax regular content owner, single-link or mode checks.

Container attribution reuses a matched process's bounded cgroup input. Only a
fixed runtime pattern and validated id survive: 64 lower-case hexadecimal
bytes in `docker-<id>.scope`, `libpod-<id>.scope`,
`cri-containerd-<id>.scope` or `docker/<id>`. Conflicting recognized ids are
discarded. This is a suggestion from the cgroup name. No container socket, API, image, name, environment, namespace
entry, process memory or socket table is read. A pattern cannot prove that a
container manager created the name. Invalid/unknown patterns establish no
absence and remain covered by the exclusions.

Catalog c4 keeps `tego.scan/1`. Optional `system_units` and `cron_entries`
counts, source kinds `system` and `cron`, and typed configured/container details
are additive. Existing fields retain their meaning; new readers retain c1/c2/c3
support and old strict readers can refuse c4. All new observations retain source
evidence, uid/scope and configured-only caveats as applicable. No configured
source ticks Find or decides the process-only `--check`. An outside process
match still takes priority 1; unknown process coverage still returns 125.
The footer names every failed source it can retain and an explicit unknown
remainder when its own capacity is exhausted. No zero count proves absence.

Advanced explicitly authorizes the entire cross-user result for the invoking
local-passwd uid under sudo, or root for direct root. This is a recipient
choice by a privileged operator, not authentication of the result. It preserves
decision 4's recipient-owned 0600 `last.json` in a 0700 scan directory. Only that
recipient and root may read it. While root, the collector reads only the fixed process, account,
boot, unit and cron sources. Close those descriptors, then permanently drop
supplementary groups, all gid/uid identities and capabilities on every thread.
Scan project-folder resolution, recipient program/settings metadata, MCP/project
content, all config layers, ledger-root resolution, record probes and destination
opens follow that drop, including in check mode. Use the existing all-thread capability-clearing primitive;
a thread-local clear would leave other Go threads privileged. Supplementary
groups use standard-library `syscall.Setgroups`, which broadcasts to Go
threads; `unix.Setgroups` is thread-local and is not sufficient here. A failed drop
means no recipient-controlled reads, no save and exit 125. No helper, chown
repair or privileged destination open is permitted. Check mode never opens a
result destination. Fix round 1 measured the all-thread drop, hostile fixed
sources, root-only config canary, parent replacement and crafted destinations
on full Fedora 44 kernel 7.0.14 and AlmaLinux 9.8. The broader namespace/mount,
live daemon/container-manager and vendor-install comparisons remain owed in a guest.

### Measured advanced input bounds

Raw advanced distribution captures are retained separately from this public tree.
Their original package-owned files have recorded sizes and hashes.
Only permitted machine distribution content was captured; no home or real user
crontab was inspected. Counts are offline capacity/grammar evidence, not proof
of a live manager, daemon, syscall path or worst-case RSS.

| Input | Measured ordinary maximum | Bound |
| --- | ---: | ---: |
| Local passwd bytes/accounts | 3,061 bytes / 52 accounts | 1 MiB / 4,096 accounts |
| System root listing | 471 names | 8,192 per directory |
| All three system root metadata | 843 entries / 64 folders | 16,384 charged entries / 4,096 directories shared with user units |
| Distribution system content | 419 regular files / 266,008 bytes | 8,192 attempts / 32 MiB shared advanced content |
| System file bytes | 2,833 | 1 MiB |
| Physical unit line bytes | 538 | 8,192 globally, including basic |
| Combined unit physical lines and ExecStart words | 76 | 4,096 |
| Command words including program | 14 | 256 arguments plus program and optional argv0 |
| Distribution cron file bytes / line bytes | 1,136 / 144 | 1 MiB / 8,192 |
| Cron file lines / whitespace fields per line | 23 / 24 | 4,096 combined physical lines and command words / same command bound |

Offline compatibility measured all 419 original system files: 22 parser and
22 selected unresolved sources, 17 outside-root aliases disclosed, 286 content
attempts and 319,517 charged bytes. No syntax, size, unsupported or limit
refusal occurred. Four stock cron files are unresolved shell forms and the
comment placeholder is read. All six repository unit examples match their
expected outcomes. The 100-account stock user-unit fixture retains 206 sources,
spends 101 attempts and 46,866 charged bytes, and uses 233 of 16,384 enumeration
slots. With 3,000 additional system services it still retains 206 sources,
spends 3,101 attempts and 148,866 charged bytes, and uses 3,232 enumeration
slots. Both variants observe the last home's independent agent, with no limit
or size failure.
These are concrete fixture measurements, not full-distribution guest proof.

Advanced D/E/system/cron content shares the 32 MiB and 8,192-attempt allowance,
including failed attempts and charged reads. Every unit-alias read reserves
its full limit-plus-one buffer (4,097 bytes), including failed reads and repeated
account-specific traversals. Shared machine alias text is charged once. A reduced
final buffer is charged too; exhaustion
is a named limit source. This also applies within basic's 6 MiB allowance.
Without this charge, 16,384 listed aliases with seven traversals could request
about 448 MiB of link text outside the stated input budget. Ordinary captured aliases
and the 100-account fixture remain acceptance inputs. Unit enumeration charges failed
and overflow names before discard, including minimum one-slot charges for
empty/failed listings. These larger limits do not multiply per account. Shared
machine listings, selected parsed documents and alias text are read once.
Account precedence is merged afresh using checked identities. Successful
machine source reads are counted at the fixed root; exact paths remain for
matched evidence and failures. Reuse does not spend fresh input allowances.
Basic D/E keeps 6 MiB, 2,048 attempts, 4,096 charged names and 1,024 directories;
only its physical/logical line ceiling rises from 4 KiB to 8 KiB so the new
538-byte distribution observation has tenfold headroom. The 128 starts/file,
256 arguments, 16 alias resource hops, systemd's seven-link semantic ceiling,
1 MiB/file, 2,048 final sources, 512 final items and 1 MiB serialized result
remain finite separate bounds. Existing process bounds remain 32,768 pid
entries, 256 KiB/process and 8 MiB charged process input. The separate advanced
content/proc/link byte allocations total below 224 MiB: 8 MiB process,
168 MiB record probes, 32 MiB shared content, 3 MiB machine config, 2 MiB project manifests, 1 MiB installed-program
link text and 1 MiB passwd. This is the sum of separate allocations, not one
global counter for every kernel-returned metadata byte. Stat and other metadata
operations have structural limits; the allocation sum is not an RSS guarantee.
The basic 192 MiB content/proc/link allocation sum is unchanged.
Advanced keeps its ten-second best-effort deadline. Kernel IO already blocked cannot be interrupted
by these between-read checks.

The ordinary-input acceptance table must record unchanged distribution system
files and cron entries, all six systemd examples, preset/conformance launch
forms, synthetic other-user homes and synthetic spool modes. An expected
unresolved launcher or outside-root alias is disclosed partial coverage, not a
fatal scan error. New refusal compatibility, canaries across every output
channel and exact proof commands belong in the package report. Fix round 1
measured all-thread privilege drop, hostile sources, the private config canary,
parent replacement and crafted destinations as root on full `fedora-7.0` and
AlmaLinux 9.8 (`rhel-9`). Broader namespace/mount variants, installed cron spool
mode comparisons and live container attribution remain **owed in a guest**.
The initramfs kernel row cannot substitute for full distribution unit/cron
layout checks. The separate runtime startup source exception remains unresolved.

The advanced footer explicitly excludes NSS-only home discovery and unlisted
unit/cron roots. Before recipient identity resolves, refusals report the caller
as recipient and have no saved-result destination. All 424 captured system unit
and cron config files match their installed package checksum records.

### B2-3 fix round 1: minimize other accounts' process fields

A process whose real uid differs from the result recipient receives no cwd
read, including when facts come from a surviving task. Its `cwd` is null and
both short and verbose text rows say "folder not recorded for other accounts".
Matching uses exe, comm, argv and optional file identity; session grouping uses
uid, agent name, membership, run id and container identity. Neither uses cwd.
No current later feature needs a foreign working folder. Any future proposal
to use it must return for an explicit decision; this command leaves it out.

Program paths, numeric process identities, configured unit names and paths,
unit argument counts and configured metadata, cron source paths, run ids and
validated container hints remain private metadata addressed to the recipient
and root. The user page names every retained cross-user field and its purpose.
The reserved process `unit` remains null; configured unit names are separate
unit observations. Foreign process argument counts and text are not retained.

The c4 decoder and encoder reject a nonnull foreign cwd. Existing c4 snapshots
with that field populated are discarded, rather than displayed or saved again.
The field still means a typed working-folder path when applicable; collection
and accepted advanced input now minimize its scope. Recipient and basic cwd
behavior stays the same. This is an intentional new privacy refusal within
the unreleased c4 implementation, with schema description and fixture updated.
Fixture regressions audit the attempted read itself for native, matched Node
and surviving-task processes, plus recipient behavior, JSON, short and verbose
output, and refusal to encode or decode a foreign folder.

## Amendment 2026-11-12: advanced fix round 1 credential boundary

Advanced collection must receive a credential-drop callback. A missing or failed
callback fails closed before any recipient-controlled source is inspected. The
CLI supplies the permanent all-thread drop and requires its success before
config loading, record probes or saving. This also applies to process-only check.
The callback runs after fixed source collection and descriptor closure, before
scan project-folder lookup and B/C/D/F. The collection deadline and shared input
budgets span both sides of the transition. A late failure cannot cause a return
to root or a privileged retry.

A config path, symlink target or ledger path can name another user's data. Owner
checks alone do not establish access. After the drop the kernel enforces the
recipient's actual access; a readable shared record may be probed. No other
user's ledger is discovered by enumerating homes or ledgers. The guest regression
links the recipient's config to a root-only file with a ledger-root canary and
requires that canary to be absent from every product output channel.


### Amendment 2026-11-12: advanced machine-unit reuse

The earlier 52-account measurement exposed repeated machine reads, rather than
establishing account-scale coverage. Advanced now caches each fixed machine
listing, parsed document and alias target once. The production cache accepts
only root-owned machine paths. A reused entry must match its pinned device,
inode, mode, uid, gid, link count, size and modification/change times. Roots,
visited directories, alias parents and cached documents are checked again after
each account merge. A changed machine identity discards all dependent unit
observations, including those from earlier accounts.
The cache owns no descriptors; every collection call closes its source handles.

Account-specific units and drop-ins still select precedence independently, so
an ExecStart reset in one home cannot mutate the shared parsed document or a
later home's merge. Successful machine reads are summarized at their fixed root
with a unique read count. A matching unit or timer retains its exact evidence
source, and named failures retain their exact paths. A capacity limit adds an
unknown-remainder source. This prevents thousands of
ordinary non-agent system services from consuming the final source allowance.

Acceptance combines the unchanged stock machine user units, 100 accounts, a
sentinel agent in the last home and 3,000 synthetic non-agent system services.
This is the measured practical scale, not a guarantee that all 4,096 passwd
entries fit. The 32 MiB/8,192 attempts, 16,384 entries/4,096 directories,
1,700 unit source allowance, 512 items and final result limits still apply.
Unique input, source failures, matches and the deadline determine larger
capacity. A limit is named as partial coverage with an unknown remainder;
it does not establish absence or change the process-only check.

### Fix round 1: retain evidence when record diagnostics reach their limit

The CLI appends at most eight distinct run-record diagnostics and one unknown
remainder. Further ids receive no record probe or individual source row. The
remainder sets partial coverage and source-limit without duplicating an existing
limit code. It preserves collected observations within the 2,048-source contract
and the collector's reserved output space. An oversized or nonprintable selected
record path gets a null locator and fixed syntax refusal; it cannot invalidate
the entire result. These are diagnostic admission rules, not looser record
access or evidence of a live record.

### Fix round 1: runtime startup descriptors

The first Fedora 7.0 guest trace found Go 1.27's CPU quota descriptor still open
at the drop, even with GOMAXPROCS=2. The runtime opens this before Main and
retains it when containermaxprocs is positive. No supported runtime API closes
it later. Closing a runtime-owned descriptor from scan would risk reuse and
must not be attempted.

The tego binary now sets `//go:debug containermaxprocs=0`. The runtime still
reads kernel startup sources, including self cgroup/mount metadata, CPU quota
and huge-page metadata; it closes the quota descriptor before Main. These
runtime reads are distinct from collector sources and are included in the open
audit. The CPU quota path follows this process's cgroup membership. A delegated
account can choose its cgroup leaf and quota, so this is not a fixed,
root-controlled source. No supported runtime setting suppresses that startup
read in the measured Go toolchain. Descriptor closure therefore does not meet
the whole-command fixed-source requirement. This runtime exception remains
unresolved and needs a maintainer decision or a toolchain-level correction.
*Answered by the amendment of 2026-11-13 below: the read cannot be removed from
this build; Tego adds no check against it and states the limit there.*

A positive containermaxprocs environment override refuses advanced before
source collection, in check mode too. The guard follows runtime startup's valid
signed 32-bit decimal assignments from left to right; malformed assignments
leave the earlier value. A trailing malformed value cannot hide an earlier
positive override. Set GODEBUG=containermaxprocs=0 before starting the command
or remove the override. The [Go GODEBUG contract](https://go.dev/doc/godebug)
describes binary defaults and environment overrides.

This changes tego's default CPU parallelism: it comes from CPU affinity and
does not adapt to cgroup quota. Explicit GOMAXPROCS remains honored. Other
tego commands can opt into the runtime quota behavior explicitly; external
agent executables retain their own binary defaults; explicit environment
overrides still follow normal inheritance. The actual product
binary's guest trace must prove the quota descriptor is closed; a CLI test
binary has its own runtime defaults and cannot substitute for that proof.


### Fix round 1: measured root regressions

The targeted root integration test `TestScanAdvancedDropEveryThread` passed in
full Fedora 44 / kernel 7.0.14 and AlmaLinux 9.8 / kernel 5.14.0-687.61.1.el9_8.
Each parent inspected all 101 helper tasks after dropping real supplementary
groups; traced kernel clones prove new threads inside the transition. A
`go test -overlay` control replacing broadcast group/gid/uid calls with
thread-local calls failed on stale supplementary groups in both rows.
The real CLI's eight tasks were also inspected in normal and check modes.

`test/vm/scan-advanced-guest.py` passed all 18 link/FIFO/device cases across the
fixed unit directory, unit file, drop-in, both user-crontab locations and recipient
config, plus the exact private config value canary across every output channel.
A fanotify permission event stopped a real unit data-open while every CLI task
was root, replaced its pinned parent before allowing the open, and verified a
changed-source refusal. Six hostile destinations produced the expected safe
replacement or refusal, with recipient-owned 0600 results in 0700 directories
and unrelated-user read denial. No guest was lost or skipped.

Product traces recorded 6,207 Fedora and 4,547 Alma open attempts, zero source
descriptors at the first credential syscall and zero recipient opens before
credential completion. They also show the runtime's kernel startup reads
and quota descriptor close before Main. The first Fedora run failed this close
check and exposed the runtime fix; its root-owned destination assertion also
had a wrong expected exit. The first Alma run failed on an older-Python fixture
constant before product assertions completed. Those failed rows are retained,
not relabelled as passes. The repeat rows shut down with raw QEMU exit 0.

The test used matching stand-ins and a real recipient Tego run, not live vendor
agents or a container manager. Broader namespace/mount/hard-link variants, live
cron behavior and vendor-install equivalence remain owed in a guest. Detailed
commands, hashes, statuses, raw traces and failed attempts are retained privately.

## Amendment 2026-11-13: the runtime's startup read (advanced fix round 2)

The confirm pass found that the previous paragraph's premise was too narrow: the
runtime takes the first matching cgroup mount of the mount table wherever it is,
and opens the limit file by an ordinary path lookup.

**What the pinned toolchain does** (Go 1.27.4, `GOROOT/src`). `schedinit` calls
`defaultGOMAXPROCSInit()` unconditionally (`runtime/proc.go:930`), after GODEBUG
is parsed and before the `GOMAXPROCS` variable is read (`:935`). That function
calls `cgroup.OpenCPU` first (`runtime/cgroup_linux.go:46`) and consults
`debug.containermaxprocs` only afterwards (`:52`). `OpenCPU`
(`internal/runtime/cgroup/cgroup_linux.go:54`) reads `/proc/self/cgroup`
(`cgroup.go:109`: a v1 hierarchy listing `cpu` wins, otherwise the `0::` line)
and `/proc/self/mountinfo` (`cgroup.go:232`: the first `cgroup2` mount, or v1
`cgroup` mount with `cpu` in its super options, whose root holds that cgroup),
then calls `open(mount point + relative path + "/cpu.max", O_RDONLY|O_CLOEXEC)`
(`cgroup_linux.go:96`; v1 `cpu.cfs_quota_us` and `cpu.cfs_period_us` at `:69`
and `:79`): no `O_NOFOLLOW`, no `O_NONBLOCK`, no filesystem check. With
`containermaxprocs=0`, which this binary sets, the runtime preads at most 64
bytes once per file (`cgroup_linux.go:110`; `internal/runtime/cgroup/cgroup_linux.go:118-198`:
`cpu.max` on v2, the quota file and, unless the quota is negative, the period file
on v1), parses them as numbers, and uses the result only to decide whether to count a
`/godebug/non-default-behavior/containermaxprocs:events` metric, which no Tego
code reads; it then closes the descriptors (`:70`). On v1, if the period file
fails to open after the quota file opened, `OpenCPU` returns an error without
closing the quota descriptor (`internal/runtime/cgroup/cgroup_linux.go:69`,
`:79-84`), and `defaultGOMAXPROCSInit` returns (`runtime/cgroup_linux.go:47-50`):
that descriptor stays open for the process's life, unread by the runtime, and
nothing in Tego reads from it. No `//go:debug` directive,
`godebug` line in go.mod, GODEBUG or `GOMAXPROCS` value, build tag or linker
setting skips the call. Removing the open needs a changed toolchain, which this
project does not ship. *Amended 2026-11-13 (fix round 3):* a start-of-main check
added in fix round 2 was removed; this section states the limit instead.

**The limit (the one exception to "as root, only fixed system sources").** The
open above happens in every root-run Go program on the machine, tego included,
before any of its own code. Its target is chosen only by the process's cgroup
membership and the mount table. A user can influence it only after real root has
already placed the cgroup2 mount (or v1 `cpu` hierarchy) the runtime selects
under a directory that user controls, or mounted a directory that user controls
inside the cgroup path below that mount, in the initial mount namespace; no
account can arrange either alone. On such a layout the user can rename or
replace a directory in the path between the runtime's table read and its open,
and the root command then opens the file the user chose. If it is a FIFO, the
command blocks before `main` for as long as the user keeps it unopened. Anything
else is read once, at most 64 bytes per file (one file on cgroup v2, quota and
period on a v1 CPU hierarchy), and parsed as numbers that, under the binary's
`containermaxprocs=0`, only decide an unread runtime metric; nothing is printed,
saved or logged. The descriptors are closed before `main` when both opens
succeed; on v1 a quota descriptor whose period file failed to open stays open,
unread, as above. (With a
positive `containermaxprocs` in root's own environment the numbers would set the
process's GOMAXPROCS; advanced scan refuses that override before collecting.)
Tego deliberately adds no check: a check at the start of `main` cannot undo the
read, and a check strict enough to matter would refuse ordinary namespace
layouts (cgroup-namespace roots such as `/../../..` after `nsenter -C`, chroots,
nspawn) for root commands. A toolchain that opened the file with
`O_NOFOLLOW|O_NONBLOCK` and checked the filesystem, or skipped the open at
`containermaxprocs=0`, would remove the exception. No guest has exercised the
swap; the reading above was confirmed by two independent source reviews.

**Thread test.** `TestScanAdvancedDropEveryThread` no longer depends on the
scheduler. The integration build holds `dropScanPrivileges` after each
all-thread change (groups, gid, uid, no-new-privs); at each point the test lists
`/proc/self/task`, starts locked goroutines until one runs on a thread that was
not listed (at most one more than the listed threads, since each keeps its
thread), checks the new thread is in the kernel's list, and only then releases
the drop. The parent requires new threads at all four points and reads every
task's credentials. Other builds compile the points to nothing.

### Amendment 2026-11-13: account placement premise (fix round 5)

The checks above reuse the config system-placement resolver. Configuration
keeps its metadata-only ancestor inspection and I10 open boundary. Discovery
requests retained file and ancestor descriptors from that same resolver.
No second link resolver or user-controlled account-file override is added.
Descriptor link reads use a fixed 4 KiB probe and 128 KiB per-walk allowance;
truncation and exhaustion refuse accounts-unreadable with a named repair.
Descriptor walks also cap checked path steps after the initial root at 512 and resolved path text at
4096 bytes, bounding retained ancestor handles and metadata. These limits do
not turn the input-byte allowance into a heap or RSS claim.
The scan snapshot adds optional printable `account_repair` (at most 2048 bytes)
on accounts-unreadable discovery mode refusals, retaining the existing evidence
code and group. Footer and JSON retain the file, failed check and administrator
repair. Reader validation confines it to those refusals; older strict snapshot
readers may reject the field. No run record or receipt changes.

Controlled mode/path fixtures and file/link fixtures with injected ownership facts
are local proofs. Root-owned physical files and links, actual credentials and
vendor acceptance remain owed in a guest under the merge condition.


## 2026-11-18 amendment: caller passwd uses verified account placement

Caller identification now uses the same resolver and two fresh, pinned passes
as the account-evidence collector. Linked `/etc`, linked `/etc/passwd`, and
chains are accepted only when every component and resolved target satisfies
the existing root ownership, readable/searchable placement and no group/other
write requirements, including sticky writable ancestors. Descriptor/path
identity, metadata and bytes are compared across both passes; changes refuse
without retry and say to run the scan again. This does not alter the strict
discovery-only group policy or the boot metadata reader.

An unsafe caller passwd route still yields exit 125, `meta` reason `owner`,
`scan-not-performed`, and now preserves the collector's named account-file
administrator repair. The saved-result decoder accepts that repair only for
the failed pre-discovery owner refusal, in addition to its existing discovery
shape. Fixture roots and owners are injected through Go code; production uses
root `/` and uid 0.

The extra caller pass and link-text budgets raise basic scan's disclosed input
bound from below 196 MiB to below 198 MiB. Advanced remains below 224 MiB. These
are byte-input bounds, with the same in-place-root-edit and post-scan limits
described above. Real image layouts and credential behavior remain guest proof.

### Measurement note, 2026-11-18: no private-namespace outside exception

A WSL 3.0.5 / Ubuntu 24.04.5 guest did not satisfy the proposed same-namespace service-manager proof. A normal
user connected to its own manager's private socket and obtained the correct UID, exact manager cgroup and a live
peer pidfd, but stat/readlink of the manager's namespace links returned EACCES. Its permitted capabilities included
CAP_WAKE_ALARM. Same UID alone is not namespace identity authority. The existing membership and peer refusals remain
unchanged; unknown membership cannot widen governance. A scope rehearsal is placement evidence only and grants no
peer, approval or scan authority. In particular, an ordinary WSL shell and a Windows browser do not acquire a
person-facing control exception. A Windows dashboard relay is separate work and is not implemented here.


### Amendment, 2026-11-18: the caller's answer is handed in

`scan.Caller` gains `Membership`, the caller's own run-membership answer, which the command line computes for its own
process (`peer.Self`, ADR 0100's amendment of the same day) and hands in; the scan makes no such proof itself and its
import rules are unchanged. Only an outside answer admits a caller: the zero value (inside) and unknown refuse. In the
kernel's first cgroup namespace the scan's own reads decide as before (a governed path is `governed`), and the handed
answer agrees with them. Outside it, where every caller was `privilege`, a caller is admitted only on an outside
answer; on a WSL machine an ordinary build has none, so `tego scan` still refuses there. *Amended 2026-11-19:* nor
has it one on WSL in the first cgroup namespace (`isolateDistroCgroup=false`), nor outside WSL beyond the first
namespace (cause `system-unproven`), so the scan refuses its caller in both (ADR 0100).

## Amendment 2026-11-20: the approved Agents page and Forget (A4-PAGE)

The dashboard's Agents page replaces the minimal fallback. It renders the data layer's answer and no more: rows
are recorded runs and separate scan observations, a stage is drawn as reached only where a recorded run established
it, and a scan observation never ticks a stage. Every row links to its own detail; the detail names where the
identity was recorded or seen with its folder, always shows `Relationship`, the record check and `NextStep`, and
links `RelatedRunIDs`. The state-protection disclosure, the scan and store notices with their repair steps, the
truncation warning and the governed-observation count stay in the page's visible text. The data layer's membership
words for a program a scan saw outside a run are now `Seen outside Tego at <time>`.

Forget is the one action the page adds. `POST /agents/forget` carries the row's ID (never a path or a name) and passes
the dashboard's ordinary POST checks (session, origin, token, not a governed caller). The data layer drops the entry
whose own identity matches, under the discovery store's pinned directory, exclusive lock and file-identity checks,
and writes the replacement through the store's own atomic save. A busy or unsafe store is refused unchanged; an
unknown ID changes nothing. It never reads or changes a run record, a saved scan or a contract. Forgetting does not
suppress the program: while the latest saved scan still lists it, the next page load remembers it again, and the
confirmation says so. The new POST is a new input in ADR 0153's inventory.
