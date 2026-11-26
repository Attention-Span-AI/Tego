# ADR 0123: Who may change governance from the dashboard

Status: **accepted 2026-10-27**; built; the one-time open code was built later the same day (see "What this does not cover"); amended 2026-11-19 for the Windows browser relay ("A browser on Windows").

## Context

`tego-control serve` can now change what a running agent may do: answer its asks, stop it, place and lift live
blocks, widen or narrow its contract, undo a change. That makes it a target. Three questions had the answer "yes"
before this record:

- Can a form post widen the contract without the person seeing it? The old Rule page's `POST /rule` wrote a widening
  with no acknowledgement and on no previewed base; every other write took the acknowledgement as a boolean
  (`ackwiden=1`), so a post with a valid form token and base could carry a wider change than the one previewed.
- Can the watched agent approve its own asks? Every agent tego runs or watches is the serving user. The peer check
  (`peer.go`) refuses other uids only; the sign-in token sits in the browser opener's command line, which the
  agent can read; with it the agent signs in, reads a form token and posts.
- Can a rule from one event hand out a system folder? A write to `/dev/null` previewed `fs.write += /dev/`.

## Decision

1. **`POST /rule` is retired.** It answers 410 Gone with a link to the line's page and writes nothing. `GET /rule`
   keeps redirecting to the event page. Every rule is made on the event page or on Change rules, through the rule
   service (`internal/control/rules`).
2. **No folder-level Allow of a write outside the run's folder and home.** `internal/check/rule` refuses it with "the
   folder of X is a system folder: name the file"; Allow of the file itself stays; Block and Ask keep the folder (they
   only take away). An Allow of a read grants nothing new: it only lifts an entry the file spells at exactly that
   folder (the planner's `narrow`), which the person wrote, so it keeps its folder.
3. **The acknowledgement is bound to the preview.** The rule service holds a 32-byte key made at start that never
   leaves the process. Event actions and History Undo retain
   `Ack = HMAC-SHA256(key, "tego-ack-v1" | ref | base | sha256(new text))`, each field length-prefixed.
   Their ref names the kind and target (`line:<run>#<seq>`, `revert:<journal id>`). A write that is not a narrowing
   plans again and requires its matching Ack; an event/history narrowing needs no explicit acknowledgement.
   Amended 2026-11-12 (ADR 0146, builder fix round 1): every builder save, new or existing, uses the shared
   `reviewAck`/`reviewOK` reviewed-write vocabulary. It binds the exact restored draft bytes, destination kind and
   canonical path, directory device/inode, each profile/preset/config layer's digest and the compiled result,
   plus the old base for a change and a fresh system-random 192-bit review identity for every save-eligible Preview. Even builder narrowings carry it in a hidden field. Wider and unclassified
   families require an explicit checkbox. Save recomputes it and refuses a mismatch using constant-time compare.
   The publishing descriptor must match the reviewed directory; source bytes are checked again before publication.
   These checks do not freeze dependencies against a later edit or give hostile same-user directory CAS.
   Event/history acknowledgements remain deterministic for their live regions. Each save-eligible builder Preview is a separate
   review: the form value carries its random identity with the MAC, and the retained proposal is keyed only by
   that identity. Identity and MAC are checked in constant time. Its 30-minute lifetime starts at creation and
   is extended by nothing. Save atomically consumes it after validation and before publication, so a replay
   refuses. A publication failure needs another review. Insertion at capacity evicts that session's oldest entry
   first, otherwise the global oldest, using insertion order for ties; eviction cannot redirect an acknowledgement. A free edit's Save appears only after a compiling Check; text changed after Check must be reviewed again.
4. **A governed agent cannot post.** A governed or uncertain reader's fresh-source Preview renders the same redacted change with saving unavailable, minting no review identity or acknowledgement and never accessing the source/review store; retained composition handles are refused before lookup.
   A governed request also cannot make the person's own checks miss their deadline by using the machine up (2026-11-19, amending the slots kept for the person, ADR 0144): the helper started for it runs at the lowest CPU priority the system allows an unprivileged process (nice 19 and the idle scheduling policy where the kernel permits it, set on the launcher's thread so the worker and the compiler children it starts descend from it), and its compilations never take the one compiler slot kept for a person's check; a person's helper keeps normal priority. Nothing is raised, which needs privilege; a governed program that is itself unprivileged cannot raise the helper either. Holding a slot was not enough: with 24 governed Previews running on one shared CPU the person's Save waited out its compile budget or its admission.
   For every POST and for the `?t=` sign-in, the dashboard asks the kernel which
   cgroup the client's socket was made in (`internal/platform/peer` `TCPSocketCgroup`: a `SOCK_DIAG_BY_FAMILY` lookup
   of the exact 4-tuple, whose answer carries `INET_DIAG_CGROUP_ID`), finds the cgroup directory with that inode by a
   walk of the whole cgroup2 hierarchy, and asks `runscope.GovernedBy` whether its path is a run's cgroup or below
   one (`tego.slice/tego-<agent>.slice/{run,adopt}-<id>.scope` at the cgroup2 root or under a user manager, Docker's
   `tego/<agent>/<id>`). A match is 403 "a governed agent cannot change its own governance (run <id>)", which tells
   the person to open the dashboard from a terminal outside any tego run. A socket that cannot be found, no cgroup2
   mount, or a cgroup id the walk does not find refuses the change (fails closed): a cgroup removed after the socket
   was made in it (a child of a run's own scope included), one outside this process's view of the hierarchy, or one
   past a part of the tree the walk could not read or passed over for its bounds (65536 cgroups, 32 deep). Only a
   cgroup found, and found outside every run, lets a change in, and that verdict is remembered by id: cgroup v2 has
   no rename and kernfs does not reuse ids, so it cannot go stale, and the browser's later requests walk nothing.
   GETs are answered: reading is not governance. A kernel that answers no TCP socket lookup at all (`inet_diag` and
   `tcp_diag` modules not loaded and not loadable on demand) answers the lookup ENOENT, as for a closed socket; an
   empty dump of the family tells the two apart, and that refusal names the modules (`peer.ErrNoTCPDiag`; *amended
   2026-10-27*: the root suites' guests, which have no modprobe, refused every sign-in "no socket for the tuple").
   Amended 2026-11-13 (builder fix round 6): a response is served from the shared cache only to the peer class
   it was rendered for. Every region request decides the peer class before consulting shared renders or
   unchanged-region memos. Governed and uncertain peers neither read nor write shared cache state; they render
   fresh. Person responses keep the ordinary cache. Builder previews carrying a review identity or acknowledgement
   are never stored; both `/rules/new` and `/rules/change/preview` bypass shared caching for every peer.
   Earlier GETs did not render differently by peer class; this branch introduces the first such GETs.
5. **The CLI writers refuse a caller inside a run.** `tego unblock` and a `tego rule` write that is not a narrowing
   refuse when `runscope.InRun` says this process sits inside a run's cgroup (or cannot tell: outside the initial
   cgroup namespace it fails closed, so inside a container with a private cgroup namespace, Docker's default on
   cgroup v2, both refuse), with the same sentence and `[governed]`. `tego block` and narrowings stay open:
   they only take away. `runact.SelfGoverned` (with `runact.ErrGoverned`) is the same answer for the dashboard's
   own writers; this change adds it and calls it nowhere yet: `runact.Block`'s unblock and a later resume
   are to refuse with it (`tego pause`, `tego resume` and `runact.Pause` refuse a caller inside a run
   both ways, since a pause stops a run's work and a resume restarts it; a same-uid process outside every run can
   still write the run's `cgroup.freeze` itself). `tego approve` and `tego deny` were already refused by `ask.sock`'s peer check
   (`internal/platform/peer`, `run-member`).
6. **A listener proves it is this dashboard without being given the link** (*added 2026-11-16*). `GET
   /_tego/identity?challenge=<64 hex digits>` answers `HMAC-SHA256(sign-in token, "tego-dashboard-v1\n" | challenge |
   "\n" | scope)` in hex, where the scope is the SHA-256 of the effective machine configuration after every
   layer (built-in, `/etc/tego/config.yaml`, `~/.tego/config.yaml`, and `TEGO_CONFIG`), including provenance, and the
   cleaned absolute served ledger root with directory links resolved (`internal/setup.DashboardScope`), so equivalent
   served-ledger spellings match. The loaded snapshot retains its own ledger setting even when `--ledger` overrides
   the served root. Serve computes the scope from the exact loaded snapshot passed to the server, without rereading
   configuration files. `tego dashboard` and `tego start` send a fresh 32-byte challenge
   to the address in `~/.tego/dashboard.log` and reuse or print that link only when the answer is the one they
   compute from the logged token and their own ledger and configuration (`internal/cli/dashboard.go`: constant-time
   compare, no proxy, no redirect followed, 300 ms); otherwise they start a new dashboard. They reuse it as current
   only when the program line in its log, which the dashboard writes itself at start (`tego program sha256:` and the
   SHA-256 of its own bytes, read once from `/proc/self/exe`), equals the hash this build pinned for tego-control, the bytes a
   new dashboard would run (2026-11-19, amended the same day: the first identity, a file's device, inode, size and
   times, named a fresh sealed memfd on every launch and never matched, so every `tego dashboard` restarted the
   dashboard and signed out open tabs; the same bytes are the same program whatever the inode, memfd or time). A dashboard of other
   bytes, one whose log has no such line (an earlier tego's) and a build that pins nothing are restarted once, the
   last with its reason. The request carries no
   secret, so a program that took the port after a dashboard ended is not handed the link, and a dashboard started
   for another configuration or ledger is not reused. The endpoint answers any local caller that names the
   dashboard's own address, a governed agent included: the answer is not a credential the dashboard accepts, and
   with a token of 128 random bits it does not help find one.

## Why the socket's cgroup and not its holder

The spec first asked for a scan of the run's processes' `/proc/<pid>/fd` for the client's socket inode. That misses
every non-dumpable process (`prctl(PR_SET_DUMPABLE, 0)`, which hardened agent CLIs set on themselves): `/proc`
hides their descriptors from their own uid. Failing closed on such a process would refuse every dashboard button
while such an agent runs, and skipping it would let exactly the processes that hide pass. The cgroup a socket was
made in is the kernel's record (`sk_cgrp_data`, set at creation from the creating task's cgroup and never moved), no
process can hide it, and the lookup is one hash probe with no caps to race. The id is the inode of the cgroup's
directory, checked against `stat` in `TestTCPSocketCgroupIsTheMakersCgroup`.

## What this does not cover

- **A process of the serving user outside every run is out of scope.** It can drive the person's browser or read
  the terminal that printed the sign-in link, sign in and post exactly as the person does. It can also write a run's
  `live-block.json`, a contract, or a run cgroup's `cgroup.freeze` directly. The dashboard is no boundary against the
  user who owns it; the peer check stops other users only.
- **An agent that left its run's cgroup** before it made the socket (an unconfined watched agent can start
  `systemd-run --user --scope …`, or write its pid into another cgroup of the user's delegated subtree) is outside
  this check, as it is outside every cgroup-based one. A Landlock-enforced run is held to its contract besides.
  The dashboard's walk refuses an id it cannot find, so a socket made in a cgroup that was removed afterwards (a
  child of the run's own scope included) is refused; making one needs write access to the run's cgroup subtree,
  which only an unconfined agent has, and that agent can leave the run outright.
- **The acknowledgement binds the write to the preview; it does not stop a same-user process** that can fetch the
  preview and read its Ack. It stops a post that changes the edit after the person looked.
- **The one-time open code is built.** `--open` gives the opener `?o=<32 hex>`, which signs
  in once within 60 s and is then burned (`web/opencode.go`); the reusable `?t=` link is printed on stdout only. A
  process that reads the opener's or the browser's command line finds a dead code. It does not change the line
  above: a same-user process can still drive the browser or read the terminal, and a `?t=` link the person pastes
  into a command line is readable there. A governed agent may not sign in with either (the same cgroup check).
- **A kernel without `INET_DIAG_CGROUP_ID`** (before Linux 5.10, or built without `CONFIG_SOCK_CGROUP_DATA`) refuses
  every dashboard change (fail closed); the terminal commands still work.

## Consequences

- A browser started from a terminal that is itself under `tego run` or `tego watch` can look but not press a button;
  the 403 says why.
- Every widening form posts `ack=<hex>` instead of `ackwiden=1`/`ackfree=1`; `TestNoBooleanAckInTemplates` holds the
  templates to it. A dashboard restart makes a new key, so a preview left open across a restart asks again.


Amended 2026-11-03 (dashboard correctness M3/M4/M8): a watched run may borrow a
contract reference only from the same recorded workspace and nonempty agent
identity, with the same harness and program. Missing identity preserves its warning.
Leak descriptions must associate particular successful reads with particular
successful outbound events; run-wide counts cannot establish those associations.
Time/sequence proximity remains a heuristic, not proof of transferred content.
Browser region refreshes distinguish received from rendered revisions and retry
failures with bounded backoff even while a run is quiet awaiting approval. These
read-side corrections make no change to the authority/process model in ADR 0100.

The standalone learner uses the same successful-pair condition (M8), with a bounded
recent-send fold and capped associations. A confirmed witness preserves each
withheld destination if the detailed association list fills; incomplete names are
reported. It cannot borrow the dashboard's contract reference.


Amended 2026-11-12 (v0.2.0 dashboard shell, A1-1; historical palette and phone layout superseded
by A1-1b below): the shared shell uses the website's paper and navy palette,
orange only for a waiting request, and red for refusals, protected reads that went through and broken records. State
words and icons remain. Semantic tokens keep the old names as aliases while page packages migrate. The top bar,
side navigation, page head and theme switch share the new stylesheet; old page markup uses a temporary compatibility
section and mvp.css. Short screens keep the top bar and navigation in the flow. The waiting band stays in the flow
at every width, with scripts on or off. Phone links and controls have targets at least 44 px high.

One subset of Anton (OFL 1.1) ships inside the binary, with its licence and modification notice. System text faces
remain the fallback. The existing Lucide sprite gains upstream symbols under the same ISC and Feather MIT notices;
no package or build dependency is added. The CSP, form actions and authority checks are unchanged. Every asset is
same-origin; print uses light tokens even after a dark selection. Copy feedback uses a polite live region with fixed
words, never the copied text. Tests cover asset serving, literal colour lint, both themes, wordmark font failure, print,
scripts-off layout and copy feedback. The waiting band's placement and polite announcement are included here;
A1-3 still owns its pages' interiors.

Amended 2026-11-12 (A1-1 fix round 1): a waiting request is the first block of the main column, above the page head.
It uses the full band on Overview and the compact band elsewhere. Approvals supplies its own selected request to the shared compact sentence;
Run uses the outer band once. The band never floats or reserves room, and no script scrolls the page for it. Browser scroll
anchoring keeps the reader's place when it arrives above the viewport. Desktop bands keep absolute asked-at times and a snapshot of the held duration with the give-up/refusal note.
Phone timing and give-up explanations remain on Ask detail. Desktop ages do not tick every second, while the
give-up note still changes at its threshold. A named region holds the controls; a separate polite live region
signals newly pending requests without repeating an unchanged set on navigation.

At this revision only an unanswered request used the orange waiting chip; A1-1b below supersedes that palette. Contract effects, modes, widening or
mixed changes, historical asks, setup progress and other non-request states use quiet chips with words and icons.
Allowed own-login reads stay neutral; other allowed protected reads are crimson. The loading bar uses ink;
feedback for new list rows uses neutral `--c-sunken`, including reduced motion, rather than the waiting-request tint. The request band
and its rows keep their own background and text colours on arrival, without that highlight. The public export selects
the exact Anton WOFF2 path and exempts only that path from its font-size deny
rule; content checks still apply to it, and other font paths remain refused. These presentation changes do not
change a decision, form action, acknowledgement, CSP or the authority checks above.

Amended 2026-11-12 (A1-1 fix round 2): below 861 px the shell explicitly sizes its navigation row to its content and
gives the remaining height to main, so short pages do not distribute unused height below navigation. Phone table
compatibility rules restore Logs' dedicated three-column card grid and hide its labels with selectors that win
over generic table rules; its What cell spans the full width. At every width the What text wraps without a line
clamp, with fallback breaks inside names, and automatic table layout keeps room for that column. The 1 KiB rendered
text limit remains; titles and the expanded row expose longer values. Ellipsized facet and record-line agent labels carry their
full values in their own titles. The side nav retains the base's rail widths: a 64 px icon rail from 861 to 900 px,
with accessible labels retained, and 216 px above 900 px. This preserves the inherited page-content budget;
the old Overview overflow remains page work. Other legacy tables keep the shared
label/value layout. A compact request band defers
its merge while hovered or while it contains keyboard focus, until both leave, without a timer override. This
preserves the request being acted on when another request becomes first in the queue. Below 641px the band's
action buttons use intrinsic sizing, 12px horizontal padding and non-wrapping labels; the control row can wrap
between buttons. `TestAskBandButtonLabelsInChrome` checks actual text fragments and containment in both bands.
The held-duration snapshot
and give-up/refusal note are restored in both band variants. Browser regression checks remain behind the `chrome`
build tag and require an explicit manual run; neither CI nor the private `make precommit` gate includes that tag.
Round 1's aggregate distinct-finding counts did not establish the absence of per-page, per-width regressions.

Further compatibility corrections in fix round 2 let a legacy record tile's value wrap without clipping when
automatic tile sizing fits another column. A line page's prefilled Logs search uses an ellipsis for a subject wider
than the input and gives the full rendered subject as its title; the underlying input value remains editable.
These narrow presentation rules do not close the other page-interior clipping and overflow findings. Their
Chrome checks are `TestShellLegacyTileValueInChrome` and `TestShellEventSearchValueInChrome`. The round-2
fixture audit completed all 38 pages at 22 configurations (836 pairs) with base `70a9e8c56`, but its horizontal
scroller check could suppress outer clipping. Its zero-regression conclusion is withdrawn. Other metrics remain
separate: Overview's single desktop-light CLS sample rose from 0.003977 to 0.012309 and needs causal follow-up.

The final page compatibility corrections give Overview's ellipsized waiting-row metadata a title containing its
displayed label, full run ID and absolute timestamp. Logs' native-clamped Rule labels expose their complete
displayed words and raw key, when present, in the title. Detections names its Investigate column directly on the
header, so positioned hidden heading text cannot enlarge the document outside its table scroller; the existing
wide inner table remains page work. `TestShellWaitingMetadataInChrome`, `TestLogsRuleTitleInChrome`,
`TestLogsTruncationHasFullValue` and `TestShellDetectionHeaderInChrome` cover these narrow corrections.
The combined font-failure Chrome check now verifies that the wordmark requests Anton before testing its painted
fallback; its former object-heading selector already used the system face and did not establish that property.

The round-2 hostile review also bounds announcement state to the last observed pending request set. Initial
requests and unchanged sets stay quiet; a request observed to leave and later return is announced again. A
temporarily absent navigation strip preserves the last set, and arrivals during script loading are still caught.
A request first observed on view entry is announced; unchanged entry and the following live merge do not repeat it.
`TestPlaceBootstrapKeepsEarlyAskAnnouncements` checks these transitions and repeated arrival/removal cycles.

Amended 2026-11-12 (A1-1b phone shell): at 600 CSS px and below the in-flow
56 px header shows the brand and page name. One existing navigation tree becomes
five bottom destinations, 64 px plus the safe inset. More has a native `/more`
destination; the single theme switch and help are available there. Native
Actions and Run details disclosures retain page-head controls and metadata
without exposing all of them in the phone head; desktop controls remain exposed. The page
reserves 80 px plus the inset and scroll padding reserves 96 px. At heights of
480 px or less navigation returns to flow. The 601 px and wider layout keeps the
approved shell geometry, including the existing tablet strip and rail boundaries.
This task's explicit tablet constraint takes precedence over the design drawing's
proposed 160 px tablet rail. The page column wraps unbroken names at all widths;
this prevents long agent text enlarging the document without changing rail widths.
The shared request target grid has an explicit zero-minimum column so a long
final filename in Details wraps rather than widening the mobile viewport.

Both palettes now reserve orange for requests waiting for a person. Refused is a
dashed red outline; protected read allowed uses a filled red chip. Routine actions
and current navigation use navy or neutral ink. Legacy token names retain those
meanings by value. Forced colors use system colors and state shapes, without
forcing brand colors. The color lint still rejects literals outside tokens.css.

On phones the band shows the oldest request as a single ellipsized sentence that
includes the target, two equal native POST answers, and Details linking to the full
Approvals request. Other request rows and timing remain in the desktop markup but
are hidden on phones. Request identity, CSRF, Origin checks, polite announcements
and the pointer/keyboard merge holds remain unchanged. Approvals uses its selected request in the shared compact sentence and decision row. Run uses the outer band once.

Runs asks “What is running?” and retains the result count/time frame in its
polite view-change announcement. It is the first page using the shared
80 px single-link phone row: who, one
state chip, age. Its existing keyed table rows and live tbody regions remain.
Filter enhances a native GET destination with a modal dialog, Escape, focus return
and Tab containment. Query, state, time frame and paging survive in the URL.
Compare and log export remain reachable from More options in the sheet. These
presentation and read-only filter changes grant no new authority. Relative row
ages keep their exact datetime and a `data-started` clock source, tick locally,
and remain outside live hashes so the clock does not replace a row.

Amended 2026-11-12 (A1-2 page interiors): Overview asks whether a request needs
a person, separately from what the record proves. Its record summary preserves
Broken, Checking and Not checked, scopes verification to the newest ended runs,
and never treats verification as evidence that actions were harmless. Running
and refused-today counts link to the corresponding records and expose incomplete sources as
described in fix round 2 below. Desktop adds named
last-three-run refusal bars with action units; the existing detection and secret
counts retain their own scopes and qualify incomplete retained windows individually. Phone
summaries defer those figures to Runs,
Logs, Detections and the Receipt.

Run keeps its result before the selected tab. Native details retain the complete
name, identity, command, folder, protection explanation, contract and activity.
The phone timeline, grouped refusals and processes use one link per row; Event
retains the exact target and deciding rule. Tablet Event uses one column below
1100 px and puts the full facts before the action panel. A protected read that went through
uses the receipt's filled warning meaning. Write-only opens are not called reads.
The Run's routine result says only that no secret read or unexpected send
was recorded when the relevant sources are complete, with the file-recording limitation
retained; an incomplete source reports unknown needs. A broken record leads
with verification failure instead. Its full mismatch and the unverified saved
result remain in Record details; routine phone statistics defer to Run details
and Receipt.

The existing outer request band also serves Run, so there is one keyed request
and its shared focus/pointer hold. On phones the name alone ellipsizes; the action
and a short target remain on one line. The accessible sentence and Details retain
the full name and target. Native forms, methods, CSRF, Origin checks, exact-copy
sources and server decision behavior are unchanged. Native disclosures and links
remain usable without scripts. These changes add no authority.

Amended 2026-11-12 (A1-3 page interiors): Logs and Detections use the shared
single-link summary row below 1100 px. Each retains its keyed rows and table
headers; full event or investigation destinations retain targets and rules.
Logs group summaries have native GET detail destinations for their counts,
first/last times and complete grouping value. Filters enhance native GET pages
with the shell's modal sheet; advanced queries, facets, exports and grouping
remain available there. Routine Logs rows no longer reduce text opacity.
Allowed protected reads use the red Read allowed chip, except allowed own-login reads,
which stay neutral. Observed protected reads use Read, not refused. A write-only
or failed open does not become a read.

Approvals selects the oldest pending request by default and lists the queue as
rows. A query selects an exact run/request pair, and an answered pair shows the
recorded outcome and person. At phone widths the queue's primary request is
compact; Details opens the full request. Every request link supplies both run and request query parameters. A fragment alone
cannot select a request. A supplied pair that is missing or incomplete renders no
decision controls for another request, including without scripts. Exact target,
rule explanation, age, timeout consequence and all original answer modes remain
available. The two equal primary POST answers stay above phone navigation while
long details scroll. Their form fields, CSRF and Origin checks are unchanged.
The existing live merge hold now includes the queue and detail controls, so a
request cannot change under a pointer or focused button.

Compare stacks each question's A and B outcomes below 1100 px. Charts and run
metadata remain in a named native disclosure; Investigate keeps its exact target
and result first, with process context and related detections in named questions.
These changes add no execution or decision authority and do not change records.
The page package's direct Chrome measurements are independent of the shared
audit tool. Browser guards still require explicit `chrome` test invocation.

The comparison summary now reports recorded sensitive-file touches or stopped
attempts. It no longer uses an absent leak verdict to say “0 left” or “no attempt
on a secret seen”. Incomplete read coverage stays explicit. Request ages and
late-agent notes pause while the decision is hovered or focused, then catch up;
their text cannot move the held answer controls. Intentional Details navigation
still replaces the queue immediately.

### Amendment, 2026-11-12: contracts and recovery page interiors (A1-4)

The default Contracts page is a list of recorded contract files. Existing `?c=` and `?run=`
addresses keep selecting the same file and run. `?run=<id>&rule=<key>` is a read-only
rule detail: the sentence, effect, exact target, source, enforcement limitation and
matching events come from the same InForce view as the contract table. An unknown
key is a 404. The old `/rule` GET redirect and retired POST remain unchanged.
Secret environment values stay redacted in both exact-text disclosures.

On phones the list and rule tables use the shared three-fact row. Full names and
technical values remain in detail pages and native disclosures. Edit preview, saved,
lift, MCP, model-route and vault forms retain their actions, methods, identity fields,
CSRF and acknowledgement values. No preview substitutes for a server decision.
The content live region remains on Contracts and saved edits.

This machine reports recorded evidence rather than claiming a new readiness probe.
Its first screen directs the person to `tego doctor`, including when there is no run,
a watched run or unreadable evidence. Historical use does not prove current readiness.
Glossary search is a read-only GET and old anchors remain. Errors have one main heading
and a recovery destination. Signed out retains its isolated CSP, with one constant
hash-authorized style and only the public favicon; it needs neither authenticated
fonts nor a newly public asset route. The style hash changes with its approved palette.

Live blocks use the same phone link row. Their rule detail retains the original
Remove endpoint, CSRF, kind and value, with a validated back destination to the
parent contract. The button uses a native page POST so that removing a block
returns to a current contract rather than leaving its former detail open.

Amended 2026-11-12 (A1-1 fix round 3): audit reachability must be checked for each clipping ancestor and each
axis. An inner scroller does not establish that its visible box can be reached through an outer clipping box. A
full value needs a scrolling route that reaches it or a disclosure the audit verifies, such as a matching full-value
title with a visible truncation signal or an expandable control opened by the audit. The reusable audit and its fixture
self-tests are kept in the development tree. The corrected replay and remaining page findings are
recorded privately. Browser checks still require manual invocation; CI and the private
gate do not run the Chrome-tagged guards (the manual browser-coverage limit). This audit correction does not change an enforcement
decision or a record.

Further fix-round-3 verification includes direct text fragments that extend beyond an element's fixed box on
visible-overflow axes. Per-value reachable endpoints let a middle value scroll through a smaller outer opening;
ordinary own-text scrollers use the same per-value projection, while selected control/media candidates retain
their required boxes. A title's truncation signal must survive the client clipping bounds, including borders. Fixture pages exercise these cases, both axes, RTL, root/body
overflow propagation and visible, hidden or still-clipped disclosures.

The opt-in audit-package checks also reject reused result directories before any output write, require navigation
and skip-link resets to reach the expected loaded fixture with a successful response, and prove cleanup after a
browser exits by signal. These checks protect the measuring tool. They do not change product permissions, record
formats or page layout, and do not establish exhaustive keyboard or spoken-output coverage. Keyboard walks stop
at 220 stops; operation probes inspect at most 45 DOM candidates per page/view and check selects only for focus.

Ordinary text candidates use their own rendered text fragments, so inaccessible empty layout space and a child’s
overflow do not establish loss of that value. Selected control/media candidates and the explicit Logs content
container remain conservative box measurements. Vertical scroll fixture preconditions require actual text beyond
the scroll viewport, in addition to a nonzero scroll range. Local clipping, scrolling and disclosure signals
require an applicable formatting box. Non-replaced inline boxes ignore overflow, and `display:contents` has
no principal box; their rendered direct text still faces all applicable outer clippers. Fixture controls retain
native inputs and inline-block clipping.

Two shared selectors also restore intended masked text boxes: card-caption padding no longer enlarges hidden
native captions at 640 px and under, and decorative padding/borders no longer enlarge hidden Soon labels in
the 861 to 900 px icon rail. Chrome checks retain the native table and navigation accessible names and compare
visible table/navigation edges. These are hidden-box containment repairs, with no phone density or layout redesign.

The corrected replay also found a shell typography conflict in the legacy Logs record-line agent labels at 200% text size.
At 768 px and up, those labels now use normal font line metrics rather than the compact shared table leading,
while retaining horizontal ellipsis and full-value titles. `TestShellLogsAgentTextSizeInChrome` checks rendered
text fragments on Logs and search at 768, 861 and 1280 px in both themes, with normal-size and 600 px controls.
The phone rule is unchanged.

The same normal-line-metrics repair covers run command subtitles in the legacy Overview and Runs tables
at 768 px and up. `TestShellRunCommandTextSizeInChrome` measures their direct text fragments at enlarged size
in both themes, retaining the horizontal ellipsis and command tooltip. The shared compact leading had clipped
those blocks vertically too.

### Amendment, 2026-11-12: dashboard integration (A1-5)

The merged pages use one shared summary row and responsive table adapter. The
Contracts rule tables and Runs now use the same adapter as Logs and Detections.
The compact header keeps the explicit page type when provided, otherwise its
fixed label. Summary ages have matching server and live units; exact timestamps
and event sequence numbers remain reachable. Process refusals use Refused.

Desktop Overview keeps its running and refusal ledger tiles. The record card's
count links appear below desktop width; the heading does not repeat those counts.
Stop uses a fixed question followed by the full agent name. Keyboard focus moves
transient messages into document flow rather than allowing them to cover controls.
These presentation changes alter no authority, form fields, request identity,
CSRF/Origin protection or recorded outcome.

Page-owned styles are delivered with their pages. Explanatory shared-asset notes
move to developer documentation to keep CSS, scripts and the font within the
first-load budget. Executable script statements and CSP stay unchanged by that
source reduction. Chrome tests own and close their pages, enforce four at most,
and synchronize diagnostic reads. Additional live pages are exercised in batches;
this does not claim seven simultaneous rendered pages on the shared host.

Screenshot fixtures use neutral machine/login values and task-local descriptor
paths. A capture fails if visible text contains the host or account identity.
The shared audit runs on the actual authenticated test documents beside independent
text-fragment measurements. Raw intentional ellipses remain in its evidence;
closed native details, actual recovery and keyboard order are checked separately.
Manual browser coverage remains outside CI and the private gate (DASH-G16).

Browser chrome uses the same background token as the page. Theme metadata follows
the saved Light or Dark choice as well as Auto; media-specific fallback metadata
continues to work with scripts off, including the isolated signed-out document.

Long state chips wrap within their containing block when text spacing is enlarged.
Page-only legacy Logs, Compare and machine rules join their owning stylesheet;
Runs loads the shared comparison rules for its existing comparison picker.
The compact page label also wraps when spacing needs more room; its static phone
header can grow instead of cutting the page identity. Its usual height stays 56 px.
The expanded Locked/Adjustable comparison uses one explicit phone column, so
increased text spacing does not inherit the generic two-column table adapter.
Phone navigation labels also wrap within their equal targets under enlarged
spacing. The bar grows with those labels; its usual 64 px height remains.
Full request-path disclosures wrap at every width, including the 640 px reflow
viewport; they do not use the summary path shortener in a complete detail.
Waiting-band Details uses the queue's exact run/request query selection, with
a fragment only for scrolling after the exact query selection. Summary path ellipses are accepted
only when their exact fragment is present in that link's accessible full sentence;
browser checks follow the real link and compare the complete agent and target.
Desktop run names use anywhere wrapping in the shared primary table link. Unlike
break-word, this also reduces an unbroken name's intrinsic table width, preventing
a sixty-character name from creating a horizontal table scroller.
The proposed-contract code panel wraps at every width while keeping the exact
text and download. Its named scroll region has explicit keyboard focus.
Receipt print hides the live editor and navigation/actions. Print disables motion
so changing from the dark screen palette cannot leave a transition between a dark
control background and the light print foreground. Receipt details remain visible.
The printed receipt precedes the full run metadata; both remain in the document,
with number tiles and metadata label/value cells kept together across page breaks.
The Run tab scroller has inline scroll padding. Native keyboard focus then brings
the whole late tab into view, including with scripts disabled; normal one-line
touch navigation stays the same. Mode-change captures wait for actual animation
completion before recording the restored normal palette.
Waiting live-restriction chips use a still mark and their existing confirmation
words; they no longer pulse indefinitely. Settled-page audits reject autoplay.

Script-free live views offer a native Refresh now link to the current URL, after
the request band. They do not reload automatically: a three-second meta refresh
was observed replacing a long timeline during its full keyboard cycle and
discarding focus and open details. Explicit refresh preserves the current query;
scripted live updates keep their existing region and focus-hold behavior. A
browser check keeps focus beyond the former five-second maximum before following
the actual refresh link and verifying that filters survive.

The Overview heading says Record needs attention when a checked record is broken
and the waiting list is complete with no request waiting. An incomplete waiting list keeps its
unknown state first. A pending request keeps its heading and action band;
the broken-record summary still follows. A broken record must not sit below an
all-clear heading. The existing record checks and detail recovery are unchanged.

Runs loads its comparison stylesheet in the head after the shared phone styles,
preserving the cascade and asset bytes. Loading that sheet in the body let Chrome
paint only the shell while parsing paused for CSS. The document was then too short
to restore a saved scroll position. A compositor capture confirmed the partial
paint; the unchanged reload/Back assertions pass with the sheet in the head.
This changes initial loading only. The native links, filters, live regions and
in-place view behavior remain the same, with scripts enabled or disabled.

The complete browser rerun still found a partial first frame under load after
the sheet moved. Runs therefore also marks its existing deferred live script
`blocking="render"`, so the page finishes parsing before its first paint. This is
the declarative [HTML script blocking mechanism](https://html.spec.whatwg.org/multipage/scripting.html#attr-script-blocking),
not a timed hide or a scroll correction. The source and script order stay the
same; no CSS or JavaScript bytes are added. Other pages keep their original tag.
Script-disabled and blocked-script views must still render and offer native GET
filters. The original zero-top-frame reload/Back assertions are unchanged.

### Amendment, 2026-11-13: dashboard fix round 1

Every request destination carries its exact run and request. Approvals fails closed
on missing or incomplete explicit selection. The decision POST continues to validate
both fields against the pending request; a form for B cannot answer A.

Overview and Run use one attention order: waiting request, record verification
failure, recorded leak, sensitive read, then qualified quiet states. Headline and
body come from that classification, including the incomplete inputs added in fix round 2. No saved-record or not-seen result implies
that the actions were safe.

The daily refusal count uses full incremental run totals only when the earliest
and latest counted refusal timestamps fall in the named day. Those two bounds
survive window truncation and eviction, and do not assume timestamp ordering.
For a run crossing a day boundary, the retained window supplies a lower bound.
An incomplete number says at least, explains the missing window and links to the
complete Receipt. This is a read-model aggregate, not a record-format change.
Malformed record lines make that count a lower bound with the reason; an events file that
could not be read shows could not read instead of a smaller count, including when no
refusal was decoded. Their recovery links download the complete record because
a strict Receipt cannot parse a damaged line.

The signal result cache includes its events-file identity and version. A live
fold is reused only while that same file grows. Equal run ids, local revisions
and line marks from another ledger cannot supply its protected-read context.
An older Event window rejects source replacement or rewriting before and after
its read, rather than mixing new events with old run context and totals. Ordinary
appends remain valid; the read model retains its stated append-only limitation.

A single protected-read classifier takes run and contract context across Logs,
Event, Run and Receipt, including historical Run timeline windows; row classification never
depends on an index of the newest window. Allowed own-login reads retain their neutral Allowed
exception;
contract-defined sensitive reads use Read allowed or Read, not refused. The dashboard
passes contract path context to the streaming Receipt builder, including for
older reads outside the retained window. Its activity list can add custom protected
paths beyond the terminal receipt's ledger-only classification. Contract entries
and their working directory are part of the receipt cache key. Recorded totals
and receipt sentences still use the same builder. Failed
and write-only opens do not become reads, including failed syscall returns whose
record has no separate errno. Contract summaries carry the existing
newest-start aggregate, including aliases, instead of rescanning runs per contract.

Logs query warnings stay beside results while Filter is closed. Runs retains its
Filter entry and count/time frame on desktop. Phone rows show at most who, one
state and age; exact technical values are in native details or linked detail pages.
Long names ellipsize on one line. Approvals uses the compact shared request band;
only Overview permits its sentence two lines. Semantic browser assertions supplement
the geometry audit at 360 and 390 px in both themes. The earlier geometry-only
zero-finding result did not establish these content rules. Browser checks remain
explicitly invoked, outside CI and the private gate; guest enforcement is owed in a guest.

### Amendment, 2026-11-13: dashboard fix round 2

The round-2 inventory contained 187 definitions, but its delivered walk saw only
128 rows, omitted shown/spoken attributes and fragments, exempted whole styling
classes and logged unseen rows. It did not establish the earlier claim that every
number a page could deliver was registered. Fix round 3 replaces that limited
check with the source, page-catalog, exclusion and delivered-markup checks described
in DASHBOARD.md. The current private inventory has 278 rows, including zero forms,
shared title/badge quantities, Compare, Event and preview/configuration surfaces.
An unknown helper ID refuses rendering; direct unmarked markup is caught by the
fixture walk. Each exclusion names one source element/field and a reason; unused
rows and exclusions fail. Exclusions never suppress traversal into child elements.
No styling class exempts its contents. Configuration and record identities are
excluded individually or explicitly inventoried as exact for their named scope.

Known run-directory presence alone cannot establish absence of a protection tier, MCP declaration or model route after a metadata decode failure.

Ordinary quantities keep their source's completeness through full pages and
fragments; `numbersOf` refuses a missing scope. Record-reader failures suppress ordinary
prefix counts from those records, while malformed lines and retention bounds qualify affected
counts. Zero-derived absences, including rule hits, say none was seen in the
retained source, with the reason and complete-record recovery. Missing record
files are failures when the store previously observed that source, including an empty file whose later contents are unknown, or last-refusal files or configured chain heads establish recorded lines. A remembered run remains a failure if its entire directory disappears; a file observed as a read begins preserves evidence if it disappears before publication. Polls retain the immutable prefix without waiting for that decoder, and known requests survive a non-regular-file failure as well. Unreadable chain evidence leaves recorded history unknown without becoming positive evidence. Without surviving disk evidence after restart the dashboard
cannot distinguish a formerly recorded run from an empty new one (GAPS C77).

A retained run failure is distinguished from an unlisted candidate failure. The former keeps known presence and qualifies that run’s sources; an unlisted failure takes priority for global uncertainty, even if another listed failure was encountered first (`TestApprovalsEndedMissingRecordCannotHideWaiting`, `TestUnknownCandidateAfterListedFailureCannotClearQueue`).


One waiting-state derivation supplies the badge, document title, spoken text and
page sentence, including live updates. The Approvals Waiting tab uses its compact form, retaining the full sentence in the accessible label and title; the browser check rejects a document widened by the unknown form. Known actionable requests cannot be hidden:
with N known and a cut or unreadable source the visual form is N+ and the words
say “at least N waiting: <reason>”; with none known and an incomplete source the
visual form is ? and the words say “could not tell whether a request is waiting:
<reason>”. Shared chrome uses the global run list and queue, independently of a
page's local scope. The central page renderer refuses missing global scopes, including on New contract and retired-form responses. An unreadable root recovery page also keeps both global scopes unknown; it cannot say Nothing running. The mixed Compare summary scopes its zero-derived clauses to what was retained.

Approvals depends only on completeness of sources capable of holding an actionable
waiting request. History's “at least” does not qualify its headline because
`runState.take` in `internal/control/ledgerview/cache.go` maintains unanswered
identities independently of event-window truncation, eviction and the capped
answer history. `TestWaitingSurvivesHistoryAndWindowBounds` puts a waiting ask
older than those bounds and then answers it; no case is skipped. A cut waiting
list, malformed live records, omitted runs or a reader error can hide a request
and therefore require the unknown/lower-bound waiting form. An unreadable retained ended
record alone cannot hide a waiting request (`TestApprovalsHeadlineUsesOnlyWaitingSources`).
`TestWaitingReaderFailureCanHideRequest` proves a cold unreadable source can hide
an actual unanswered ask. DOM and actual tab-order checks compare both band
answers with the first queue link, including a queue moved ahead of the band and
a positive tabindex that moves it ahead in keyboard order.

Run timeline rows use the displayed historical window's own run and contract
context. `TestHistoricalProtectedReadParity` places a sensitive read before 33,000
routine events and checks the older timeline against Event and Receipt for both
own-login and custom-contract paths. The protected-read parity statement therefore
applies across windows.

Refusal date bounds use the refusal count as a separate seen state. The decoded
RFC3339 zero date remains a valid bound; invalid or missing timestamps become
unreadable lines rather than date values. `TestDailyRefusalsDecodedZeroTimestamp`
checks the minimum and maximum, calendar totals and incomplete forms before and
after truncation. These are read-side changes; no saved-record field or decision
authority changes. Desktop disclosures hide their summaries only when the engine
supports `::details-content`; otherwise the native keyboard control remains.
`TestNativeDisclosureFallbackInChrome` simulates the unsupported selector against
the shipped styles; it does not establish another browser engine. Browser proof
remains explicitly invoked. Kernel enforcement is owed in a guest.


A surviving live-index entry associates a vanished run directory with this ledger root; together with a positive chain head it retains the missing recorded run and its count (`TestColdIndexedChainKeepsMissingRun`). An unreadable live index or an indexed run with a vanished directory can hide actionable waiting requests and therefore prevents the Approvals all-clear; known requests remain a visible lower bound. A cold absent index is also incomplete beside unfinished or omitted records, while a fresh ledger or complete ended history cannot hide a waiting request. A vanished ledger root previously read successfully, even empty, is an unlisted source failure even if all remembered runs ended; the lost root could hide other runs. `Snapshot.LiveError` is separate from record failures: it qualifies running and waiting status and status-dependent filters, while readable record, history and credential totals remain readable. Unknown run status is not labelled lost or offered as finished. Index recovery clears the error and moves row revisions even without another record line.

### Amendment, 2026-11-17: receipt identity overflow

The terminal receipt, watch footer and dashboard use the receipt builder's separate
identity and overflow-attempt units. `connections_more` and `programs_more` count
retained identities omitted from the top list. `connections_overflow_attempts` and
`programs_overflow_attempts` count attempts beyond the identity budget, which cannot
establish a number of distinct places or programs. The JSON fields are optional;
`receipt_v` remains 1. An older overflowed JSON receipt can disagree with corrected
recomputation. Receipts whose identities all fit the displayed lists retain their units and wording.

Warm root read failures, including permission errors and a root replaced by a file, preserve the published request prefix under a global read-failure scope. The known requests remain actionable and their shared quantity stays a lower bound.

Quantity exclusions apply only to the named element's own text and shown attributes. The collector always visits its children; path tokens, request agent names, line hashes and policy reason codes have their own leaf exclusions. Every registered exclusion is also tested with an unmarked child quantity.

The full-record receipt's zero-ask, zero-write and zero-sensitive-file sentences carry the same quantity sources as their positive counts. The inventory includes an empty full-record receipt fixture and explicitly rejects an unmarked "never asked" sentence. A request status such as "never answered" labels an individual request, not an empty collection.

Run details preserve the unknown live state in both Ended and Asks when the live index is absent or unreadable. Expanded details explain that source failure rather than claiming the run or its requests were lost.

Phone recovery uses the existing waiting-state derivation, with a short presentation of its reason. The full diagnostic and extra recovery links remain in a closed disclosure. A local waiting explanation suppresses the shared phone repetition; desktop retains its fuller form.

Zero forms include unavailable derived artifacts, empty configuration lists and unchanged configuration comparisons. Each names the complete result or configuration scope it describes. Unknown contract declarations are stated as unknown rather than as zero unused grants.

A running dashboard pins the record directory by device and inode. If that pathname names a different directory, including through a link, it says the record folder changed and retains known requests under a global read failure. The replacement live index cannot retire those requests. Putting the original directory back recovers the view. After a dashboard restart, either a link or a real replacement directory becomes the new root: the process reads that directory and cannot remember requests from the moved original. Restarting after the original is restored reads its surviving record normally.

The quantity audit also walks every delivered template's parse tree without choosing a fixture branch. It visits both arms of if, with and range, preserves separate HTML source contexts through shared suffixes, and examines literal text and shown or spoken attributes. Each literal must inherit a quantity source or have an exact-text no-quantity registration with a reason in testdata/no_quantity_texts.json. Missing and stale registrations fail the normal web tests with the template, line and text. The rendered-page collector remains an independent check of dynamic output. Configuration fence absence, complete usage results and watch-mode non-enforcement now carry their sources, including the first-run instructions.

On phones, missing-request recovery during a root failure uses the same single short uncertainty sentence as the waiting list; technical paths remain in closed recovery details. An answered request exposes Answer details as its primary action and keeps Next waiting request under More. These three request-detail states join the light/dark, 360/1280 browser matrix and height comparison.

The public no-quantity registry is extended by the private pages through their existing export hooks. Both registries receive the same stale-text check; dropping the private layer drops only its registrations. No missing-template exemption is used.

The source audit's initial exact-text registrations were reviewed for zero assertions as well as digits. Record-field absence, process-tree coverage, unavailable recovery, pause defaults and fixed policy guarantees now name their sources. The rendered fixture catalogue includes every corrected literal branch, including incomplete process scope and pause states.

Decision cards and waiting rows display the complete agent name and requested target. Long hosts, paths and commands wrap after dots and slashes, with a break inside a long segment when needed. Command whitespace is preserved. Waiting rows size to their text rather than a fixed first track. Desktop request banners keep their home and working-directory path display and no longer shorten a long target.

Request sentence forms (this supersedes the previous paragraph's rule for banners and waiting rows). A person is never offered Allow once beside a request they cannot read in full there. A waiting request's sentence (who, what, the target) has two forms. FULL shows every character, wrapped after dots and slashes and never clamped. LONG is used where the sentence passes a bound: the server cuts the target once in the middle with one ellipsis character, keeping what a decision turns on (of a network target its first label and the end of the host with the port, of a file the leading folders and the end with the file name, of a command the program and first arguments and its last characters; each name of a rename is cut on its own), and cuts the agent's name in the middle only when the name alone passes its own bound. Where a banner shows the LONG form it offers one action, Review request, which opens the request's own card on Approvals; that card always shows the FULL form, the exact target whole whatever its length, with Allow once and Deny. The waiting row on Approvals follows the same two forms. The accessible names carry the whole sentence in both forms.

The bounds count characters and are decided by the server (request_forms.go): 112 for a phone and 150 for a wide screen, with 40 and 60 for an agent's name. They were measured in headless Chrome by filling the real banners with host, path and command sentences of every length from 60 to 320 characters under two agent names and counting line boxes: at 320 px the phone banner's 16 px sentence stays within four lines up to 112 to 126 characters, and at 1280 px the wide sentence within two lines up to 166 characters on a page's banner and 154 on Overview's. The markup carries both answers and the style sheets pick by width at 600 px (phone-only, desktop-only); when only the phone form is LONG the quick answers carry desktop-only and Review request phone-only. Between 601 and 1279 px the FULL form can take more lines and never hides text. At 320 by 640 px a FULL sentence of four lines with its one action row makes the banner 174 px high, 27% of the screen: the earlier phone ceilings of a quarter of the screen and of 160 px give way there to this four-line limit, and the earlier one-line banner sentence and one-line waiting row give way to the two forms. TestNoQuickActionsBesideLongRequest walks every template branch: each Allow once is either in the request cards' own form or inside the branch of a requestView's Quick with its QuickClass, and the three banners render the answers only where the same width's sentence is FULL. The safe answer does not depend on a style sheet loading. The phone's cut sentence carries the hidden attribute in the markup whenever the phone form is LONG, and phone.css only reveals it at 600 px and under (.banner-ask .ab-summary[hidden] with !important, which outweighs app.css's [hidden] rule by specificity); the quick form is in the markup only where the wide sentence is FULL, and at 600 px and under phone.css hides it when the phone form is LONG. With phone.css missing, or with no style sheet at all, the cut sentence is therefore not shown, and no Allow once form sits beside a cut sentence at any width; the same holds in the accessibility tree. TestFix7SafeAnswerNeedsNoStyleSheetInChrome loads the pages with phone.css blocked and with every style sheet blocked at 320 and 1280 px and checks the DOM and the accessibility tree. The cut itself never splits a letter from its combining mark (a kept tail drops marks it would start with), a port is at most five digits, a rename's half without a slash is cut as plain text, the accessible name is built from the visible text (control and bidi characters as their U+ literals), and FuzzRequestForms holds all of it against arbitrary agent text.

## Integration amendment, 2026-11-17

The dashboard identity scope hashes `config.Machine.Snapshot()`, including the
private baseline entries, unknown state and layer-source digests, rather than
JSON of `Machine`, which omits those private fields. CLI dashboard opening and
reuse refuse an unknown configuration layer: an unreadable or untrusted input
cannot establish configuration equality. Manual dashboard serving remains an
observation load and keeps its unknown-layer diagnostics. Source-layer identity
is selected during the load and is never reread to construct the scope.


### Measurement note, 2026-11-18: no private-namespace outside exception

A WSL 3.0.5 / Ubuntu 24.04.5 guest did not satisfy the proposed same-namespace service-manager proof. A normal
user connected to its own manager's private socket and obtained the correct UID, exact manager cgroup and a live
peer pidfd, but stat/readlink of the manager's namespace links returned EACCES. Its permitted capabilities included
CAP_WAKE_ALARM. Same UID alone is not namespace identity authority. The existing membership and peer refusals remain
unchanged; unknown membership cannot widen governance. A scope rehearsal is placement evidence only and grants no
peer, approval or scan authority. In particular, an ordinary WSL shell and a Windows browser do not acquire a
person-facing control exception. A Windows dashboard relay is separate work and is not implemented here.


### Amendment, 2026-11-18: the three-valued answer behind item 5

Item 5's refusals of a governance change "when `runscope.InRun` says this process sits inside a run's cgroup (or cannot
tell)" now read the three-valued answer of ADR 0100's amendment of the same day (`peer.Self` through
`runact.SelfGoverned`): a change is made only on an outside answer, and inside and unknown both refuse. In the
kernel's first cgroup namespace nothing changes outside WSL. Outside it, an outside answer needs the rule's proof, and
on a WSL machine an ordinary build withholds it (cause `wsl-launcher-unproven`). *Amended 2026-11-19:* on WSL the
answer is withheld in the first cgroup namespace too (`isolateDistroCgroup=false`), and outside WSL beyond the first
namespace (a container, a nested system) it is unknown, cause `system-unproven`, as before the rule (ADR 0100). The dashboard's own check of a connection
(the cgroup a client socket was made in, item 4) is unchanged, and a Windows browser is still refused by it: the
relay for a Windows browser is separate work. The answer is the refusal an honest tego gives; a same-user process
outside every run remains out of scope, as this record already says.

## A browser on Windows (amendment, 2026-11-19)

On Windows, Tego's dashboard runs inside Tego's own WSL distribution, on `127.0.0.1:<port>` as everywhere. WSL's
own forwarding cannot reach it as the person: its connections are made by WSL's relay, so the peer check above
answers 403, and in mirrored networking there is no Linux client socket at all. The Windows `tego.exe` therefore
carries the person's browser in itself. No check of the dashboard changes: the Host check, the peer check, the
governed check, the token, the cookie and the POST checks apply to every request as before.

**What listens where.** `tego dashboard` (and `tego serve --open`, and the end of `tego start`) on Windows starts or
reuses one hidden `tego.exe __relay <port>`: no console window, outside the caller's console, process group and,
where Windows allows it, job. It listens on Windows `[::1]:<port>` only, the dashboard's own port, so the browser's
Host `[::1]:<port>` is one the dashboard already accepts. It binds with `SO_EXCLUSIVEADDRUSE`, never `127.0.0.1`
(WSL's `wslrelay.exe` binds it with `SO_REUSEADDR` in NAT mode), never a wildcard. If that bind fails it does not
pick another port and does not share: it says in one line which program holds the port (or that WSL's mirrored
networking reserves it) and exits non-zero; the browser is not opened.

**Who can connect (R2).** Every accepted connection is checked before one byte is forwarded: the owner of the client
socket, read from Windows' TCP table (`GetExtendedTcpTable`, `AF_INET6`, `TCP_TABLE_OWNER_PID_CONNECTIONS`, the row
whose local end is the client and whose remote end is the listener, established, exactly one), must run with the
relay's own token user SID. An owner that cannot be determined (no row, two rows, pid 0 or 4, a process or token
that cannot be opened) is refused (`internal/platform/winpeer`). This is the Windows counterpart of the Linux peer
check and is defence in depth: the dashboard still checks the Linux socket.

**One pipe, the person's socket.** All admitted connections ride one long-lived child
`wsl.exe --distribution tego --user tego --exec /usr/local/lib/tego/windows-entry --relay`, started with redirected
standard handles (binary-safe), carrying a framed multiplex (`internal/relaymux`: stream id, open, data,
half-close, close, a 256 KiB window per stream and direction, so one slow stream holds back only itself). The guest
entry enters `systemd-run --user --scope` as every Windows command does, then runs `tego dashboard-relay serve`,
which makes each `connect()` to `127.0.0.1:<port>` itself: the dashboard's peer check sees the person's uid and its
governed check a socket made in that scope, outside every run. The Linux end dials only the dashboard's own address
and port, read from the dashboard's private log and accepted only after the listener proves it holds that log's
token (`/_tego/identity`); the Windows side never names a target. It refuses to start inside a tego run.

**Sign-in (R4).** No reusable secret reaches a Windows command line. `windows-entry --dashboard-open` runs
`tego dashboard-relay open`, which asks the dashboard for a one-time open code over the dashboard's own loopback
listener: `POST /_tego/open-code` with the sign-in token as a bearer credential, answered only after the Host, peer
and governed checks (`web/opencode.go`). It prints the port, the code and a fresh identity challenge with the proof
the person's dashboard gives for it, on a pipe only `tego.exe` reads. `tego.exe` opens
`http://[::1]:<port>/?o=<code>` in the default browser; the code signs in once within 60 seconds, as `serve --open`'s
does. Before reusing a running relay, a second `tego dashboard` checks that the recorded relay is alive with its
recorded creation time, runs this `tego.exe` as this user and is the only listener on the port, and that the
challenge sent through `[::1]:<port>` comes back with the expected proof; otherwise it stops its own relay and
starts one, once.

**Why Linux processes cannot reach `[::1]:<port>`.** Measured (M2 below): no process in Tego's distribution (its
user, another uid, root) or in a second distribution (a user, root) connected to the Windows listener at `::1`,
`127.0.0.1`, `localhost`, the gateway, the host's or its own addresses, in NAT or in mirrored networking. After the
Windows bind, a Linux listener on `[::]`, `0.0.0.0`, `127.0.0.1` or `[::1]` at the same port, in either
distribution and as any user, received none of 50 Windows connections to `[::1]` (M1).

**Why a governed agent cannot use the relay.** It cannot reach the listener (M2), it cannot start Windows programs
(interop is disabled in Tego's distribution and a run is refused Windows executables, the N2 rows of the WSL
rule), and anything it sends through a dashboard it can reach on its own is still refused
by the governed check.

**Lifetime (R6).** While the relay runs, its `wsl.exe` child keeps the distribution, and so the dashboard unit, alive
past WSL's idle stop. The relay ends at logoff, when the distribution stops (its child ends; it records why in
`%LOCALAPPDATA%\Tego\relay.log`, and the next `tego dashboard` starts a new one), on `tego dashboard --stop`, when
the dashboard stops or moves to another port (the Linux end says so and ends), and before the installer replaces
or removes `tego.exe`.

*Amended 2026-11-26 (public issue 94).* The relay is not the only thing that keeps the distribution: the dashboard
command starts the dashboard with `systemd-run --user --unit=tego-dashboard --pipe`, and that client process lives in
the WSL session of the command that started it until the unit ends, so after the relay was ended Tego's Linux stayed
Running (measured, WSL 3.0.5.0: still Running 75 s later; Stopped 15 s after only that client was killed; the unit, the
`/bin/login -f` session and the entry scopes were not holders). `tego dashboard --stop` therefore also runs `tego
dashboard-relay release` in Tego's Linux: it stops the unit when `tego session list` shows no run going, so that Tego's
Linux can stop by itself, and with a run going (or a count that cannot be made) it stops nothing and says so, since
Windows stopping the distribution ends a run. It starts no Linux that is stopped. The relay's own authority is unchanged:
`release` is a hidden mode of the same command and stops one named user unit. It is admitted as `serve` and `open` are (the
in-run guard, then `outsideRuns` with the dashboard's own governed check for an answer that cannot be told, before it counts or
stops anything) and refuses when `$TEGO_CONFIG` is set, so a caller cannot choose the ledger root the count reads; the
Windows launcher's call sets none. A unit that is not running is released without a count. The count is the invoking user's
ledger root's: a run of root or another account, a run with its own `--ledger` and a scheduled agent between its runs are not
counted, and Linux may then stop under them (said in the install guide's Known limits).

**Not claimed.** Programs of the same Windows user are the person's own trust domain, as same-uid programs are on
Linux: they can connect to the relay, drive the browser, or read the open link while it is unused. Root in any WSL
distribution is root over the shared kernel (WSL-IDENTITY). Mirrored networking: WSL reserves the dashboard's port
on Windows for every address while the dashboard listens, so the relay cannot bind and says so (measured, M1);
the browser dashboard needs WSL's default NAT networking. A Linux program that listens on `[::]` or `[::1]` at the
dashboard's port before the relay starts makes WSL hold Windows `[::1]` at that port, and the relay then refuses
and names it (a denial, never a share).

**Measured before it was built** (2026-11-19, a Windows 11 Enterprise evaluation guest under KVM on the developers'
machine, build 26300.9457, WSL 3.0.5.0, kernel 6.18.58.1-1; logs under the job's `measure/` folder):

- M1, NAT: with the dashboard-like Linux listener on `127.0.0.1:P`, Windows bound `[::1]:P` with
  `SO_EXCLUSIVEADDRUSE`, before and after that listener existed. After the Windows bind, Linux listeners on `[::]`,
  `0.0.0.0`, `127.0.0.1` and `[::1]` at the same port (Tego's distribution as its user and as root, a second
  distribution as a user and as root) all started, and all 50 Windows connections to `[::1]:P` reached the Windows
  listener in each case; only `127.0.0.1:P` was forwarded to Linux. A Linux `[::]` or `[::1]` listener that exists
  first makes `wslrelay.exe` hold Windows `[::1]:P`, and the exclusive bind then fails (WSAEADDRINUSE).
- M1, mirrored: a Linux listener on `127.0.0.1:P` makes the exclusive Windows bind of `[::1]:P` fail, and after a
  Windows bind every Linux listener on that port fails with EADDRINUSE; all 50 connections reached Windows. The
  two never share; they exclude each other, which is why the relay cannot serve the dashboard's port in mirrored
  networking.
- M2: no Linux process (Tego's user, another uid and root in Tego's distribution; a user and root in a second
  distribution) reached the Windows `[::1]:P` listener at `::1`, `127.0.0.1`, `localhost`, the gateway, the
  host's addresses or its own, in NAT or in mirrored networking; the listener logged no connection until the
  Windows positive control.
- M3: connections from headless Edge 157 resolve to `msedge.exe` running as the person's SID and are admitted; a
  PowerShell client run as a second, standard Windows account resolves to that account's SID and is refused.

**Proved end to end** (same guest build, 2026-11-19, a fresh install from this branch's release-shaped assets,
`ce3d07846`): `tego dashboard` typed in Windows PowerShell 5.1, PowerShell 7.7.0 and cmd in the logged-on
desktop opened Edge on the Overview at `http://[::1]:8484/`, signed in by the one-time code; one relay served all
three (the later two checked it and reused it); Edge's network-service process was admitted as the person, a
PowerShell client of a second, standard account was refused (`open process: Access is denied`, fail closed), and
no Linux process of either distribution reached the relay. With only the relay's `wsl.exe` as a client, Tego's
Linux and the dashboard stayed up for 10 minutes. `tego dashboard --stop`, `wsl --terminate tego` (the relay
ended within 2 s, saying so) and `tego uninstall -Yes` each left no relay, record or listener; a cold
`tego dashboard` after the termination started everything again. Defender real-time protection stayed on with
no detection. M4, one `wsl.exe` child: 64 MiB each way bit-identical, 20 concurrent streams intact; the Overview
with its 25 assets loaded through the relay in p50 1870 ms / p95 3563 ms (time to first byte 804 / 1373 ms)
against 830 / 1075 ms (491 / 791 ms) for the same client inside the distribution, on a loaded nested guest.

**Not working on Windows yet, and not the relay's:** a browser POST through the relay passes the Host, peer,
Origin, CSRF and governed checks, but answering a held request is then refused by the run itself ("unauthorized
peer"): the run's ask socket refuses every peer while the launcher is outside the initial cgroup namespace, which
WSL always is (the same socket refused `tego ask` in the terminal, "ask: unauthorized peer"). It shares its cause with the guide's
refusal (GAPS WSL-GUIDE).

## Root-only local approval floor (2026-11-12, ADR 0154)

With the trusted system `local_roles: owner_only` setting, a qualified root-launched
non-root run accepts once answers only from initial-namespace root outside every
governed run. A same-user dashboard session or outside-scope terminal cannot
answer, including Deny. A valid session, CSRF and Origin do not supply root
identity. The shared broker enforces this for the direct socket and terminal too.
Unknown kernel identity/cgroup facts and private user namespaces refuse without
consuming the request. Run the approval as root from a terminal outside any
governed run. There is no root browser requirement or shared dashboard.
Personal mode and the other limits above remain. This floor restricts answers;
it does not protect personal contract publication or completed user-owned records.
The real dashboard handler reaches a real managed broker in the non-root host
witness; a stub refusal alone proves only wording. Answer identity requires the
run's profile revision and full answer validation. Displaying the root-only
activation floor also requires complete run_start validation at its exact revision.
Managed approval badges say
"Approval recorded" and keep operation completion separate. Policy drift reports
"the approval policy file changed since this run started" with the root stop and
relaunch remedy in the user guide. Root/kernel operation qualification is
**owed in a guest** and remains a merge blocker.
