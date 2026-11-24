# The Tego dashboard

`tego-control serve` starts a small, read-only web dashboard over the ledger that `tego run` writes. It shows runs,
what each agent did, what Tego refused and why, and which approvals are waiting.

Its known gaps are in [GAPS.md](GAPS.md). The footer of every page
names the ledger root; its tooltip says the record is hash-chained and verified.

It checks the ledger's hash chain with the code `tego events <run> --verify` runs, against the same chain anchor
(`~/.tego/chain.log`, named by the rule tego anchors by, `ledger.AnchorPath`), and reads the result as that command
does (`ledger.VerdictOf`: where it exits 0, 1 or 125 the page says verified, broken or not checked): a run page shows
"Verified" with its line count, "Record broken at #N" with the reason when line #N's own bytes, link or schema fail,
"Record broken after #N" when the chain holds through its last line, #N, and the anchor disagrees with it or bytes
follow run_end, "Record broken" with no line when there was none to read (the run's ledger gone while chain.log
anchors it) (each in red, with an alert), or "Not verified"
with why (a live run still being written, a run too long for the dashboard, an anchor it cannot read). The overview's Ledger tile checks the newest 20 ended runs and says "Verified"
or names the first broken run; right after `tego-control serve` starts it may say "Verifying…" with how many runs are
still being checked, and it updates by itself when they are done. For an audit, `tego events <run> --verify` stays the check of record.

## Start it

```sh
tego dashboard
```

This is the usual way. It starts the dashboard as a service of your user (`tego-dashboard`), so it keeps running after
the terminal closes, and prints its sign-in link; on a Mac it also opens the link in your browser. Run again, it reuses
the running dashboard, and restarts it once after Tego is updated. `tego start` does the same at the end of the guide.

To choose the address, the ledger or the preview pages, start the dashboard yourself instead, with `tego serve` (which
hands off to `tego-control serve`) and these options:

```
tego-control serve [--addr 127.0.0.1:8484] [--ledger DIR] [--open] [--preview]
```

- `--preview` also lists MCP tools and Model routes (empty unless a run uses `capture` or `mcp`) in the nav. Without
  it they are left out; their addresses still answer.

- `--ledger` defaults to the `ledger_root` tego writes runs to: the machine config's (`TEGO_CONFIG`, else the layer
  files), else `~/.tego/runs`.
- It prints one line on stdout, `Tego dashboard: http://127.0.0.1:<port>/?t=<token>` (the address `--addr` names:
  `http://[::1]:<port>/...` under `--addr [::1]:<port>`), and serves until Ctrl-C or SIGTERM. Open that link.
  `--addr 127.0.0.1:0` picks a free port.
- On stderr it then says what it serves, so a dashboard showing another ledger is seen at start:
  `  ledger: <root> (from TEGO_CONFIG <file> | <layer file> | --ledger | default), N runs`, then
  `  chains: checked against <chain.log>` or `  chains: no anchor found (<why>); runs show as unverified`, then each
  machine-config diagnostic as `  config: ...`. A `TEGO_CONFIG` that tego skipped (missing, untrusted or invalid)
  stops serve before it listens, exit 125, with the layer's code (`[config-untrusted]` or `[config-invalid]`) and the
  fix, because it would otherwise show the default ledger instead of the one that file names; with `--ledger DIR` the
  ledger is named outright and serve starts.
- `--open` also opens the dashboard in your browser, signed in, once it listens: the first command of `$BROWSER` (a
  colon-separated list; `%s` stands for the URL, else the URL is appended), then `xdg-open`. The opener is a detached
  child with no standard stream of ours. It is not given the printed link: it gets the same address with `/?o=<code>`,
  a one-time code that signs in once, within 60 seconds, and is then gone, because a browser keeps its arguments in
  its command line for as long as it runs. The token stays on stdout only. If the browser takes longer than a minute
  to start, or the code was used, the page says to open the printed link. The URL is printed either way, and a
  machine with no opener gets one line on stderr saying so while the dashboard keeps serving.
- It listens on a loopback address only, `127.0.0.1` (the default; `localhost` reads as it), another `127.x.y.z`, or
  `[::1]`, and refuses any other `--addr` (`0.0.0.0`, `[::]`, a LAN address, any other host name).

The token in the link is swapped for a browser cookie (HttpOnly, SameSite=Strict) on the first visit; a request
without it gets 401: a browser asking for a page gets the sign-in page ("Sign in · Tego": "Open the dashboard from
your terminal", and `tego dashboard`, run in a terminal on that computer, to open it signed in; under its own CSP with
one hashed style, no script, nothing from the request reflected), every other client the plain line. A one-time open
code (`?o=`, 32 hex) that was used or has expired, or was never minted, gets the same page led by "This one-time open
link was used or expired; run tego dashboard to open a new one". The plain line says "this dashboard needs the link it
printed when it started (it carries ?t=<token>); tego dashboard opens it". `tego dashboard` reuses the dashboard
`tego start` left running, so the tabs open on it stay signed in; only a dashboard that is not running is started. An open tab whose next poll, stream or region
fetch gets 401 (each `serve` prints a new token) stops following and shows "Signed out: open the link from your
terminal"; the top bar reads "signed out". It checks `/status.json` once every 30 s and, once the browser is signed
in again (the link opened in another tab sets the same cookie), takes the banner down and follows again. The favicon
(`/static/favicon.svg`, also at `/favicon.ico`, which a browser asks for on a page that links no icon) is the one file
served without the cookie. The cookie is named per port (`tego_dash_<port>`), so two dashboards on one machine do not sign
each other out. The `Host` header must be the loopback address and port, so a web page cannot reach the
dashboard through DNS rebinding. The builder invariant is: a GET or HEAD request never creates, changes or
removes anything on disk. Every preparation or write, including registry-directory preparation by Preview,
runs behind the same guarded POST as Save: governed peers are refused, and Origin and CSRF are checked.
Actions (Allow, Deny, Stop, live blocks, rule changes, Undo and new contracts) use those POST guards.
Every response has a strict Content-Security-Policy (no inline script or style,
`frame-ancestors 'none'`), `nosniff` and a same-origin referrer policy. Agent-written text is always escaped.

A request must also come from a socket the user who started the dashboard owns. A token can reach a command line
(a link you paste into `google-chrome <link>`, say), which other local users can read, so before it looks at the
token or the cookie the
dashboard finds the client's socket in `/proc/net/tcp` (or `tcp6`, for a v4-mapped client or one on `[::1]`) and
compares its owner with its own effective uid. Another user's request gets 403 and one sentence saying to open the
dashboard as that user or start their own; so does any request whose owner it cannot find (fails closed). Opening it
as `localhost` instead of `127.0.0.1` or `[::1]` makes no difference to the check. It listens on the one address
`--addr` names: `[::1]` reaches only a dashboard started with `--addr [::1]:<port>`. A socket's owner never changes,
so the check runs once per connection: the browser's later requests on the same keep-alive connection reuse the
answer.

A change must also come from outside every tego run. Every agent tego runs or watches is your own user, so for each
POST and for the `?t=` and `?o=` sign-ins the dashboard asks the kernel which cgroup the client's socket was made in (sock_diag)
and finds that cgroup in the machine's cgroup tree: if it is a run's (`tego.slice/tego-<agent>.slice/run-<id>.scope`
under your user manager or the root, an adoption's `adopt-<id>.scope`, Docker's `tego/<agent>/<id>`, or any cgroup
below one), the request gets 403 "a governed agent cannot change its own governance (run <id>)" and is told to open
the dashboard from a terminal outside any tego run. A request whose cgroup cannot be found (it was removed after the
connection was made, or lies outside the dashboard's view) is refused the same way (fails closed), and so is every change
on a kernel that answers no TCP socket lookup, whose refusal says the `inet_diag` and `tcp_diag` modules are not
loaded (`sudo modprobe tcp_diag` loads both; a kernel loads them on demand unless module loading is off; `tego machine check`'s
`dashboard:` line says whether this machine has them, before any button is pressed). A cgroup found
outside every run is remembered, so the browser's later requests cost nothing. Pages still load for it: reading is not governance. So a browser started from a terminal that is
itself under `tego run` or `tego watch` can look but not press a button; the demo opens the dashboard from a plain
terminal. `tego unblock` and a `tego rule` write that is not a narrowing refuse a caller inside a run the same way,
and `tego block` refuses one unless the block names the caller's own run.

**Threat model.** Other local users are refused by the peer check above. Governed agents (anything inside a tego run's
cgroup, a watched run included) are refused by cgroup membership: they can read pages, never post. An enforced run's
connections are held to its contract's network rules besides (whether a given contract lets it reach
`127.0.0.1:<port>` at all is that contract's to say), and one that reaches the port is still refused. A process of your
own user outside every run is out of scope: it can drive your browser or read your terminal, and it can also write a
run's `live-block.json` or a contract itself; so can an agent that left its run's cgroup (`systemd-run --user`, for
one) before it connected. `--open` keeps the reusable token out of the browser's command line (the opener gets a
one-time code that is dead after its first use or a minute); a link you paste into a browser's command line yourself
is still readable there (`/proc/<pid>/cmdline`). The acknowledgement of
a widening binds the write to the preview it confirms (below); it does not stop a same-user process that can fetch
that preview. `docs/adr/0123-dashboard-threat-model.md` has the reasoning.

## Pages

| Page | What it shows |
|---|---|
| `/` Overview | The headline and body share one priority: waiting request, record verification failure, recorded leak, sensitive read, then the qualified quiet states when its sources are complete; an incomplete waiting list, record or signal count keeps what is known and says what remains unknown; tiles for Needs you (approvals waiting), Running now, Refused (the complete run refusal aggregates when readable, with a qualified routine count from retained events and a trend line over the last runs) and Record (the ledger check); then **Detections**, a table of refused actions by severity and channel, and **Secrets** (see Charts); the running runs; Waiting on you; the newest runs that are not running (Recent runs, with a **Compare** link; a running run is under Running now) with their Secrets verdict and protection level; and "Newest High and Medium", the newest retained refused actions that matter, with a link to Detections; an empty retained list does not establish that earlier history has none. Run lists give a start time from today as the clock alone, and an older one with its day: "Yesterday 21:43", "Oct 26 21:43". It changes in place while a run is live (Live updates): seven regions, so a new line resends only the parts it moved. **Set up, step by step** (added 2026-11-11, ADR 0142) shows the six steps `tego setup` prints, from the same object (`internal/guide`) in the same words (`guide.State.Words`): each step's state in words beside its badge (Done, To do, Waiting, Blocked, Skipped, Not known) and the fact that decided it, the one next step with its command in a copy block, and the not-known lines. With no run yet it is the page's empty state ("No runs yet"), and under it, unfolded, **The first step for any agent**: `tego watch -- <the command that starts your agent>`, which records and refuses nothing, with where its run goes next (left out when the guide's own next step is that one, `record-todo`, so it is not shown twice); with runs it sits under the headline, folded to one line ("Set up: every step is done") once the last step is done. The page never checks the machine itself: the check step reads the check `tego setup` stored in `~/.tego/state/check.json` for this boot and this build, and with none it says "not checked since this machine started", with `tego setup` as the next step. The build is that of the tego a person types (the first `tego` on the dashboard's PATH, else the one beside `tego-control`) with this release's version and commit, so a check stored by a tego of another release or another file is not used. The dashboard has no working folder, so a contract only in a project registry (`.tego/agents` of a folder) is not seen here, where `tego setup` run from that folder sees it. Every fact is shown as text (a stored fix sentence is text a process of your user chose, ADR 0142 (4)); of the guide's text, only the next step's command, which the guide built (`guide.Next.Built`), is offered to copy. The guide is computed again when a run starts or ends, `check.json` changes or the tego a person types is another build (a reinstall), and at most every 15 s otherwise, so a contract just saved can take that long to show. It is computed within the page request with at most 20 s; leaving the page cancels its helper work. Cancelled or failed guides are not kept for the next viewer. tego-control started without a guide (a test) keeps the earlier empty state: one next step for any agent, `tego watch -- <the command that starts your agent>`. The empty Runs page has that one too, and names no file the installer does not install (overview_test.go holds it). |
| `/detections` | Runs whose secrets left first, in the run page's banner and whatever the filters say; then the retained refused actions that are not routine, High first, then newest. Counts from incomplete windows say at least; a reader failure says could not read with its reason. Filters by severity and by channel (Files, Programs, Network) are links, so a view is a URL. Low folds under the list. Live: see **Severity and Detections** below. |
| `/runs/<id>/investigate/<seq>` | One detection in four parts, always in this order: What, How it got there, What else (same run, within 10 s of any of it, so a key read in the middle of a scan is on the scan's page), What now. Allow from now on opens the line page's preview, so nothing changes until Confirm. Keep refused · Next marks it in this browser only (`static/review.js`) and moves on; it records nothing. The address is the group's first line, so it stays good as a live run adds to the group. A row of many ports lists them under What, with a Logs view of each (`group=target`). |
| `/refusals` | Refusals by hour (C111): one bar for each local hour of the last day (`?span=day`, the default) or week (`?span=week`), from `ledgerview.Snapshot.RefusalBuckets`, the reader behind the Overview's "refused today", so the counts of one day are one number. A bar with refusals links to that hour in Logs; the same hours are a list for the keyboard. A run whose retained events omit part of the period makes the counts "at least" and links its complete record. Reached from Detections' Actions. |
| `/severity` | A person's own severity rules, above the built-in ones, first match wins. Sorting only: see **Severity and Detections** below. |
| `/glossary` | One line per word the dashboard uses, with a link to where it shows. Contract and Refused keep the anchors of their older words (`#policy`, `#blocked`). |
| `/contracts`, `/contracts/new`, `/contracts/change` | 303 to the same page under `/rules`, the query kept: the pages are named Contracts, and their addresses stay `/rules`, where every link, form and printed line points. |
| `/runs` | Every run read: the running ones first, then the others newest first, 100 to a page with an **Older runs** link (`?before=<run id>`, and **Newest runs** back; status, today and match counts cover the runs read and say at least if the run list is incomplete), with status (Running, Exit N, Stopped, Lost, or the reason the run ended), a kind label (below, Interactive and Deployed only), its Secrets verdict, start, duration, line, refusal and ask counts and protection level. Chips filter by status, and paging keeps the filter. The Compare chooser lists the newest 50 runs and the pair it starts on. |
| `/runs/<id>` | A header line under the status (who started the run, at what time, and its rules version and contract file; a run with no contract file, as under `tego watch`, says "Watched only: nothing was enforced" and links Least privilege); the verdict sentence and the Highlights card (below); on a live run, Pause beside Stop run (it freezes the agent where it stands within a second; until the run's launcher answers, a banner says "Pause asked at 12:03; waiting for the run to confirm it" and the button reads Cancel pause; once the launcher writes its `run-paused` line the status reads Paused, a banner says "Paused by you, from the dashboard at 12:03" and the button becomes Resume; while a request of the run waits for an answer Pause is greyed out with "Answer the waiting request first" under it, since a waiting request cannot be frozen; a pause the launcher could not apply says "The pause did not take", that Tego keeps trying at most 30 s apart until it takes or the run is stopped, and offers Withdraw pause, since the agent is still running; Stop run ends a run within the stop grace (`stop_grace`, 10 s by default); a run whose launcher cannot read a pause (one an older Tego started, an adopted run, or one with no cgroup of its own) offers no Pause at all; Runs and Overview rows read Paused too), Block now above them (a head button jumps to it; kinds Program, Destination, File or folder; it applies to the next action and leaves the contract file unchanged), each block named in words, its path shortened like the rest of the page ("Reads of ~/.config/telemetry" under the run's home, the full path in the value's title), with its state now as a badge and a plain line beside it: "Waiting for the run…" until the run's launcher writes the line confirming it (about half a second), then "In force since line #N"; "Changes refused since line #N" for a path on a run whose reads tego does not see (reads still go through); on a `tego watch` run the panel and its head button read "Mark (recorded only)" and every block "Recorded, not enforced", since a watched run refuses nothing (the panel is its own live region, `r-run-live`, so the badge changes without a reload); a live-blocks file the panel cannot read is said in plain words after "The run's live blocks could not be read:", as the Rules page says it (`rulesview.LiveErrWords`), never Go's error with the run's folder; the run's details folded under one summary line (agent, contract, tier, command, start, end and exit) and its timeline, newest first: one row per refusal (a refused action's mirror line is not shown again), identical refusals folded into one row with a count, paths with their file name kept (bold, `~/` for the run's home), people named instead of `uid:1000 pid:…`, credential-looking command-line values masked, here and on every other list of refusals and answers (a waiting ask's card keeps the text as written; the line page masks its headline, its What line and the rows around it, and keeps the line exactly as written in a closed fold), rows in words ("Run started: <command>", "Asked to read <path>", "Allowed once by alice after 27 s: <path>", "Model traffic not recorded (no model capture for this agent)", "Run paused: the agent is frozen", "Run resumed", "Run ended, exit 0"; a command run through a shell's `-c` reads from the shell on, "… /bin/bash -c <script>"), each under the chip Logs and the line page give that line (an ask **Asked**, an answer the person's **Denied** or **Allowed**, a neutral **Timed out** or **Withdrawn** when no person denied it, or **Answered** when it does not say which, a line nothing decided **Recorded**), and the "record no-price-table" gap left out (Logs keeps every line). The timeline shows 200 rows at a time; "Older rows" pages back by line number (`?before=<seq>`). A live run's timeline adds its new rows at the top (see Live updates). |
| `/runs/<id>/refusals` | Grouped by default: one row per rule and destination host on any ports, program or path, with its count; the ones that matter first (secrets, contract entries and live blocks, sends next to a secret), the routine ones folded under "Routine (N refusals in M groups: system lookups, retries)". "Every line" (`?view=lines`) lists each refusal with identical ones folded. With nothing refused, both views say the receipt's sentence for the run (`receipt.RefusedSentence`, the one `tego session show` prints under Refused actions): "Nothing was refused.", or, for a run whose refused reads leave no line (`run_start.reads_notified` false at an enforcing tier), "No recorded action was refused; this run does not record refused reads (see Sensitive files read)." |
| `/runs/<id>/processes` | The run's processes as a tree, rebuilt from each exec line's `exec_id` and `parent_exec_id` (`ledgerview.ProcessTree`): tego's launcher at the root, the agent under it, each process under the one that started it. Each shows its program and command (credentials masked, a shell launcher elided), pid, start time, lines, reads, writes and connects with the hosts it reached, its refusals in red, how many processes are under it, a link to its exec line and to Logs (`run=<id>&where=pid:<pid>`, which counts the same lines); a process that ran several programs, or tried one that was refused, lists each exec on one line ("ran …", "tried … refused ×2 at /usr/bin/x, /bin/x"). The launcher, the agent and its children are open, and so is every branch with a refusal in it; three or more like processes of one parent that started nothing (Codex's `git` calls, refused `lsb_release` calls) fold into one closed line with their count, opened when one of them ran and had something refused. A process that forked and never started a program writes no exec line, so the record does not say who started it: it hangs from the launcher, marked "forked, no exec recorded", and no parent is guessed. A page shows at most 600 processes, breadth first, and says how many it leaves out. The count above the tree reads "N processes · N actions · N refusal notes · N refused": the actions and the refusal notes (the kind=refused line beside each refused action) add up to the run's lines in its header. A live run's tab updates in place, laid out at most once every 5 seconds (`procsHold`), so a busy run's tree is not sent again each second; opened branches stay open. |
| `/runs/<id>/receipt` | The run's receipt on one screen, with recorded totals from the same builder as `tego session show <run>` (`internal/check/receipt`); the dashboard also includes custom sensitive paths from the run's contract copy in its sensitive-read activity list: how it ended and the time it took; tiles for files written, refusals, times it asked, model tokens (and the estimated cost when a price covered them); refusals by rule as bars (tego's built-in refusal of `setsockopt(TCP_ULP)` has a bar of its own, `built in: kernel TLS`, as `tego run`'s summary names it, and the refused list names it so too; a run that does not record refused reads says so there, as `tego session show` does, not "Nothing was refused.", and its Refused tile reads "refused reads not recorded"; each sentence about connections and refusals is the receipt's own, `NoConnectionWords`, `RoutineAlsoWords`, `RefusedWords` and `NoneOverTime`, which `tego session show` prints too) and refusals per minute as a sparkline ("None to show." with none); stall minutes; the refused actions (the first 12) and the files it created, wrote, deleted and renamed (the first 40; a write to `/dev/null`, `/dev/tty` or a pseudo-terminal is no file and is not listed); each ask with its answer; and "What this receipt can vouch for", the fields the ledger could not support in full (a tier that does not record allowed writes, capture off, gap lines that may have lost actions, capture gaps that make the token counts a floor, unpriced responses; a pause, a resume, a live block or a mode tego gave back to the owner of one of its own files is a gap line too but loses nothing, so it is not listed) and, under it, the "Frozen at launch" line naming the directories a `deny_read` froze (`run_start.deny_read_frozen`, GAPS A12; no gap, added 2026-11-11), then the receipt's notes as `tego session show` prints them ("Note: …": an anomaly the pass met, such as a second `run_end`, or how many of its own files' modes tego gave back, whose Logs rows name each file). The dashboard loads no price table, so its cost shows only for responses a table priced in the ledger's own terms: none today. The builder also gives the run's connections, the programs it ran and the sensitive files it read (JSON keys `connections`, `connection_tries`, `system_lookups`, `routine_sockets`, `programs`, `sensitive_reads`; a routine system lookup such as nscd, and a socket call that names no place (an AF_UNSPEC connect, the kernel's netlink socket, which the verdict folds by the same `syslookup.NoPlace`; a refused one counts as a refusal only), are counted apart, never as a place), which `tego session show` prints and this tab shows as Sensitive files read (crimson "Read, not refused" on a watched run), Connections and Programs run, each with what happened to its tries. |
| `/runs/<id>/lines/<seq>` | One ledger line, explained (`ledgerview.Explain`). The headline names the action and its object: "The agent tried to read ~/.config/telemetry/token", "The agent connected to 127.0.0.1:8802", "The agent ran ls" (a path masked, the run's home as `~/`, cut near 80 characters with the whole value in its title; "Line #N: <kind>" on a line no rule is made from). Under it, the line's chip, the one its timeline row and its Logs row show (an ask line **Asked**, an answer line the person's **Denied** or **Allowed**, or **Timed out** or **Withdrawn** when no person denied it), and the line in one sentence with its verdict ("curl (pid 357136, child of sh) tried to read ~/.curlrc; Tego refused it: a read the rules refuse, and the agent got ENOENT"). **What happened**, under the same chip: the action (an exec's whole command from its blob in a fold), the time to the millisecond (UTC in its title), how far into the run and how long after the line before, the run and its contract. **The decision**: the verdict and, on its own row, who decided (a read a person denied reads "Refused: a person said no", decided by that person and the rule that asked; a question nobody answered, "Refused: nobody answered in time"; none on a line recorded as observed under the authority rule, which record v1 names on every action: nothing decided it. A person or a gate such a line names stays: a held open a person allowed is recorded as observed when the object it reached had no name), the rule in words with the contract file and line it is written on, linked to the Rules page group, and its state (enforced, best effort, watched only; "built into Tego" for the secret list; "watched only" on every observed line of a watched run, whose rule is the contract entry it would have matched, and which reads "Watched only · <rule>", or "Watched only" for unmatched, where no contract line is found), the reason, the error the agent got, the refusing mechanism and the tier. **The question** (an ask, its answer, or the action it decided): when it was asked, who answered after how long, the outcome and any file given instead, with links to the ask, the answer and what followed. **Who did it**: the program (path, masked command, pid · tid · cgroup, the line that started it), the programs above it from the run's root ("tego launcher → sh → curl", each linked to its exec line; a process that forked without starting a program reads "forked, no exec recorded"; a deeper chain shows the nearest six and "… N more", linked to the Processes tab), and a Logs link for every line of the process (`run:<id> pid:<pid>`). **Every field**: each key after the envelope, labelled and in words, masked (the authority rule, which record v1 names on every action, reads "no one: recorded only" on a line recorded as observed, which nothing decided; its raw value is in the title; a person or a gate stays as named); a masked value has its own "show unmasked (contains a secret)" fold; a blob field says its size and whether it hashes to its name, shows its text (masked, at most 256 KiB) and offers **Download the exact bytes** (`?blob=<sha>`: only a sha a blob field of this line names, 64 lower-case hex digits, re-checked against its hash before it is sent and again as it streams, so a blob changed in between ends the download short and never arrives whole; streamed as an `application/octet-stream` attachment with `nosniff`; anything else is 400 or 404); a body stored as a splice reads "stored as a splice; not shown here". **Integrity**: "Line #N of M", the line's hash, the line before linked with whether its hash matches, and the run's chain verdict (the run page's cached check); on a run whose chain breaks at a line, a line before the break says it and every line before it hash correctly and where the chain breaks, and the break line says its bytes do not match its id. **The line as written**: one closed fold with the exact bytes and a Copy button (copy.js; without JavaScript the text is plain and selectable), and the terminal twin with its own Copy. Then the lines around it (masked, in the words Logs uses: "Asked to read <path>" under Asked, "Denied by somebody after 77 ms: <path>" under Denied) and the same file, program or destination across runs. The **What to do about this** panel (see "Making a rule from a line") is not shown on run_start, run_end, gap, limit and answer lines. |
| `/runs/<id>/least-privilege` | On an enforced run, the smallest change to its contract: the entries granted but never used (`tego drift`), to remove, and the deny and ask entries, always kept; `tego rules learn`'s from-scratch proposal (which keeps none of them) is folded below. On a watched run, the `tego rules learn` proposal. On a run whose verdict is a leak (secrets read next to a send that got through), a red notice tops the tab, and the proposal, on the page and in Download contract, never allows where the secrets went: each such `net.allow` address is a `# NOT allowed: "tcp://...": first reached next to a secret read, so secrets may have gone there` comment, a list left empty reads `allow: []`, and a `# WARNING` line opens the file. A line that names its host and holds its address is matched by the address, for every address the name reached. A destination recorded only by host name cannot be matched to an address entry; the notice then says the proposal may still allow it. |
| `/logs` | Retained lines across the runs read, newest first. The matched, refused, asked, group and facet counts say at least when runs or event windows are incomplete, with a reason and complete-record recovery; a reader failure says could not read. Filters (plain GET form): run (the newest 50 runs and the one selected; older runs through the Run facet), agent, kind, verdict, free text, and "hide system lookups". The free text (`q`, which the topbar search and the line page's "All in Logs" links send) is a literal substring, never parsed. A **query** (`where`, the Query box) narrows further in the query language: `verdict:refused kind:exec host:chatgpt.com path:~/.ssh rule:fs.deny_read* pid:4242 run:<id> agent:<name> source:kernel since:15m until:2026-10-27T01:00`, plain words and "quoted phrases" as text, `-` in front to leave a term out (kind, verdict, rule, host, run, agent and words), the same key twice for either value; `kind:change` asks for the rule changes (a change, an undo, a new rules file) as rows of their own, with no event line unless another kind is named too (`kind:change kind:exec`), and shows none beside a term about lines (a verdict, a word); a search that narrows only by run, agent and time shows them without it, and a window with no event line shows the changes made in it; `path:` is a file or folder and what is in it, by whole names (`path:/a/b` holds `/a/b/c`, not `/a/bc`; ending in `/`, only what is in it); a key it does not know stays a word, and a term it cannot read is left out and named above the chips. Each term is a chip with ×. Beside the rows, **facets** count the matched lines by verdict, kind, host, rule, run and program (top 10 each, "and N more"): a value adds its term (on the query already, it removes it) and its − leaves it out; each count is what the search plus that value matches, and the verdict and run counts each add up to the header's total (the Kind counts also count, under Refused lines, the refusal notes `kind:refused` lists, and the Program counts leave out lines whose program is unknown). `kind:refused` lists the refused lines, the refusal notes (the kind=refused line written beside each refused action) included, as the Kind select's "Refusals" does. The Verdict facet calls a line with no verdict (a run's start and end, a note) "Recorded", as its row's chip does, and the Rule facet counts tego's built-in refusal of kernel TLS (`setsockopt(TCP_ULP, "tls")`) under its own value, "built in: kernel TLS", as the receipt counts it, never under "Not in contract", and `rule:` queries it by that value, while its row's line under the text is the receipt's sentence, not "not on the allowed hosts" (acceptance 2B, 2026-11-11); the Rule facet calls a rule seen only on watched runs (tier observe) "Watched only" ("Watched only · <rule>" for a rule other than unmatched), as their rows do, not the contract's words ("default deny"); a rule seen on watched and enforced runs alike is one value in the rule's words, which By rule splits. Time presets (5 min, 1 hour, 24 hours, Latest run, Any time) replace the time range. A time range set as a span back from now (`since:1h`, a preset or typed) is pinned when it is set: the address is answered with the times it means (`since:2026-10-27T09:05:00`, and `span=1h@…` so the preset stays marked), the page says it in absolute times ("From 2026-10-27 09:05:00 until now") and offers **Move to now**, the same length of time ending now; a refresh, a reload and a copied link show the window that was set. The rule-change rows follow the rule-change journal's revision (`crev` in `/status.json` and `/events`), so a change appears without waiting for a new line. **CSV** (`/logs.csv`) downloads the matching lines in the page's words (its Verdict, Action and Why are the row's, from one set of line words that a test compares for every kind of line; Rule in words is the rule as the row words it: "Watched only, not enforced" on a watched run's observed line, "Blocked live at … by …" on a live block's refusal; paths in it are written in full), masked as on the page, with a cell that a spreadsheet would read as a formula prefixed by '; **Record (JSONL)** (`/logs.jsonl`) downloads the matching ledger lines byte for byte, not masked (your own ledger, secrets included, as the button says). For one run and no other narrowing it is that run's events file itself, the refusal notes included, so its chain checks; any other search leaves the refusal notes out (unless it asks for kind refused), and the button's title says so and that the download is then not a chain anything can check. Both are oldest first (`order=newest` for the page's order), behind the same checks as the page, and stop at 1,000,000 lines with a last note row. Paged by a cursor ("Older lines"). The header is one sentence: how many lines ("matching lines" when filtered) from how many runs, how many rows they fold into after identical refusals fold, how many a page shows, then the refused and asked counts. An ask line counts as asked (it carries no verdict of its own; it is the line that says Tego asked a person), so Logs and Approvals agree. Desktop rows: What wraps between path pieces or words, with breaks inside a name when needed, without a line clamp (the file name in bold, the full path in the title, the reason in words under it with its code in a title). Below 1100 px the summary row keeps who, one outcome and when; its Event destination retains the full target, rule and process context. On desktop, the Rule column (a path in the rule's words under the run's home reads ~/…, "Never read: ~/.ssh/", the key in its title, as in the run timeline; a watched run's observed line reads "Watched only, not enforced"); and the Line column, "<agent> #N", which opens the line page. An exec line whose argv the ledger moved to a blob shows the command from the blob (see "Read model"). The text search also looks in an ask's or an answer's target and its ask id. Each refusal counts once: the refused action line is shown and counted, its kind=refused mirror is not (the Kind filter "Refusals" lists the mirrors themselves). The Overview can use complete refusal aggregates even when this page's `?verdict=refused` count is a lower bound from retained windows. A **Process** column names the program the line's process was running and its pid (read from the run's exec lines, see "Read model"; "pid N" alone when no exec line names its program); the program narrows the search to `prog:<name>` and the pid to `pid:<n>`, and a **Program** facet counts them. **Lines / By process / By target / By rule** (`group=`) shows the matched lines gathered: a process is a pid and the program it ran in one run, a target or a rule gathers across runs; By rule keeps the lines that name a rule it did not decide (verdict observed, as every action of a watched run) apart from the lines it decided, as "Watched only · <rule>" ("Watched only" for unmatched) when they are all of watched runs and "Observed · <rule>" otherwise; each group has its lines, its refused lines, its first and last time and its newest line, most lines first (the 200 with the most), and its count opens its lines (a target opens a literal search for it, so it can match a longer target too; a rule opens `rule:<key>` in place of any rule the query asks for (one it leaves out stays), with `verdict:observed` for the lines it only names, and with `-verdict:observed` for the lines it decided when the rule's lines are in two groups). **Views**: Refused only, Refused connections, Secret files, Commands and Asks are links; "Save this view" keeps the page's address under a name in this browser only (localStorage), so a view is its link. With JavaScript (static/logs.js) the page also: follows new lines itself, putting them at the top while you are there, or, lower down, in an "N new rows" pill that brings them in and takes you to the top, where the next lines come in on their own (more than a page of them loads the newest page instead), with a refusal that folds into a shown row moving that row up with its whole count (`GET /logs/rows?<search>&after=<cursor>`); loads older lines in place under the rows, on its own as the Older lines link scrolls into view for up to 10 pages, then on a click (`&before=<cursor>`); opens a desktop row in place (its chevron, a click on the row, or Enter) with the line in a sentence, when, the process and what started it, the verdict, rule (a watched run's observed line "Watched only · <rule>", or "Watched only" for unmatched) and reason, the question it belongs to, its place in the ledger and every other field in words as the line page words them, masked as rows are, with "Open line N" and "Copy the line (JSON)" (exactly as written, secrets included, as its title says; `GET /logs/line?run=<id>&seq=<n>`, built on the line page's `ledgerview.Explain`); and takes `j`/`k` to move through the rows, Enter to open one here, Escape to close it, `o` to open its line page and `/` to go to the query. Without JavaScript the page is the same GET form, links and Older lines page. |
| `/compare?a=<run>&b=<run>` | Two runs side by side: two stat blocks read from each run's verdict (red "A · Watched, 2 secrets left the machine, id_rsa, token → 127.0.0.1:9821"; "B · Enforced, 4 attempts stopped" with an explicit recorded-refusal label) with the one-line summary muted under them, each run's header (agent, observed or enforced, started by, rules version, chain), then one table of secret files, destinations, programs and approvals merged by target with each run's verdict in its own column ("Got through" and "Stopped" in distinct labelled warning shapes; a refused connection that was no send next to a secret, which the run's verdict does not count, reads "Refused", so its words distinguish it from the sends in the summary's count), each column head naming its run and mode, the attack first (a secret read next to a send, an off-list destination next to a secret, in either run). When each run sent to its own attacker address, those rows merge into one "Where the secrets went" row, each cell naming its run's address. DNS, system sockets and port-65535 probes are counted, not listed; routine rows and each run's background destinations sit behind "Show all"; the summary says what each run read and sent, then its verdict with the run's own count ("2 secrets left (id_rsa, token sent to …)", "Tego refused 4 attempts (2 secret reads and 2 sends to …)"), the number its banner and Runs chip give; each run head gives its refusals and, of them, the ones "against secrets". The Runs page has a two-run chooser, the Overview a link to the last watched run and the enforced run of the same program that started closest to it (else the newest enforced run), and every run page a Compare button that sets the run against the run of the other kind and the same program that started closest to it (`ledgerview.PairOf`, the same run its reference and the Overview name), else the newest run of the other kind (the watched run goes on the left); with no watched run in the ledger the chooser opens on the newest run against the one before it, never one run twice. A watched run's column is read against the enforced run's contract (see Highlights), so its own API is not marked as the attack nor counted as an off-list connection. With fewer than two runs the page says "Compare needs two runs" with the `tego watch` and `tego run` commands instead of the chooser. |
| `/rules/new` | **New contract** (below): a project folder, a name and presets (or a finished run to start from), a preview of the rules in sentences with compile's verdict, then Create writes `<dir>/agent.yaml`; a draft from a run is saved by default to the user registry instead (`~/.config/tego/agents/<name>.yaml`, where `tego rules learn --save` saves it). |
| `/rules` | One run's **Rules in force** in plain sentences (below). `?run=<id>` picks the run (the run page's "Rules version → see the rules" opens its own), `?c=<ref>` a rules file by an opaque ref (the rule service's, the one Change rules takes; an older link's 64-digit ref is redirected to it) and shows its newest run; with neither, a list of contract files and the agents that used them. |
| `/machine` | This machine: the highest protection level any run here used ("Up to Basic (Landlock)") or "Watched only so far"; each level with its tier number and the newest run that used it ("Basic · tier 1 · Landlock", then "Last: codex · 07:03", from the snapshot, no ledger read) or what it needs and the command to get it; `tego machine check` to check now; what the newest run's run_start recorded in words, the raw capability ids under a closed "Capability flags (for auditors)". |
| `/approvals` | Pending asks (an ask line with no answer, in a live run), each a card: "Let codex read this file?", the path read against the run's home (`~/.config/telemetry/token`), how long ago it came and how long the agent waits ("asked 8 s ago · Codex gives up at about 30 s"; past 30 s "Codex has likely given up; Tego refuses it at 5 m", the run's `ask.timeout`), the agent's exact text, the request's line ("line #10", its id in the title), the rule that asked in words ("Your rules ask before any read under …"), **Allow once** and **Deny**, and under **More choices** Allow for this run and Deny for this run (`--always`: later requests for the same operation and target, until the run ends; the contract is not changed), a stand-in file for a held file open, and each answer's terminal twin (`tego approve|deny [run] <ask_id> [--always]`, `tego alternate … --file`). A held open under `fs.ask` asks to write. A held change of a name in an `fs.ask` scope (ADR 0047) says what it changes, with the recorded operation in the words' title: "Let codex delete this?" (unlink: a file, or an empty folder, which the record names the same way), "create a folder at this path?" (mkdir), "rename this?", "make a symbolic link at this path?" (symlink) and "make a hard link of this file?" (link). A rename, a link or a symbolic link shows both its names, each shortened as a path cell is, never cut where one ends: `./src/a.tmp → ./src/a` (a hard link's file, then its new name; a symbolic link's own path, then where it points, as written), in the banner, Waiting on you, Highlights and Answered recently too. Below: **Answered recently** (at most 200 of the newest answers by people; its history and session totals say at least if this cap or retained windows omit answers, and could not read with the reason after a reader failure: who, what, when; a request nobody answered in time is a neutral "Timed out", not "Denied"; Tego's automatic repeats of a "for this run" answer are left out) and **Never answered** (the open asks of runs that were lost; nothing holds them, so they are not waiting). |

Verdict: above Highlights every run page says in one sentence what happened to its secrets
(`ledgerview.RunVerdict`, read from the same Signal): red "Secrets left: id_rsa, token sent to 127.0.0.1:45805" when
a secret was read (observed or allowed) next to a send that got through to a destination off the contract; a refusal-labelled
"Protected: 2 secret reads and 2 sends to 127.0.0.1:43437 refused" when Tego refused a secret read or a send
next to a secret (each count with its own destination; with several, "3 sends (to A and 1 more)"; the routine lookups
it also refused are named in the second line only, "4 routine lookups"); otherwise qualified ("No secret read or unexpected send recorded" only when the relevant sources are complete, or on a watched run that read a secret
with no new destination next to it, "Watched only: 1 secret read, no new destination next to it", whose second line counts the destinations the run did reach:
a send more than 5 s or 16 lines from the read, or to a host the run already talked to, is not next to it, so the banner never says nothing was sent). Overview and Runs rows carry the same verdict in a Secrets column
("2 exposed" and "2 protected" with distinct state words and shapes: both count distinct secrets, and the protected chip's title names the
refusals behind it, "2 secrets kept (id_rsa, token); 2 secret reads and 2 sends to … refused"), and Compare's summary
and run heads print the verdict's refusal count, with the completeness qualification of each page's source. On a watched run whose
secrets got through or were read, the timeline marks the lines the verdict names: a protected read uses the same Read, not refused or Read allowed chip as Event and Receipt, including the neutral Allowed exception for an allowed own-login read; a send to where the secrets went "Sent out", in red; its head says once "Watched only, not enforced", and its
quick filter is "Secrets and sends" (`?verdict=leak`) instead of "Refused only". A system lookup socket (nscd, userdb, resolved, the D-Bus buses) and a resolver (a line the engine named `net.resolver`, in any tier, or port 53 on this machine)
are routine whatever their lines say: never next to a secret, never a send the verdict counts, never where it says
the secrets went. A real agent asks nscd for each name it resolves, right next to the reads.

Highlights: every run page opens with a card read from the run's retained lines. Its event-derived totals, including secret touches, destinations, approvals, programs and routine activity, say at least with a reason and complete-record recovery if older events are omitted; reader failures say could not read. **Secrets**: each sensitive path touched
(a path under a `deny_read` or `ask_read` entry of the run's contract (an `fs.ask` entry is a folder whose writes
ask first, not a secret), or a well-known secret path by name,
`ledgerview.IsSecretPath`, the one detector Highlights and Compare share: under `.ssh/` (not a `.pub`), `.aws/`,
`.gnupg/`, `.kube/`, `.azure/`, `.password-store/`, `.config/gcloud/`, a `confidential` or `secrets` directory, a
`.env` or `.env.*` file, `auth.json`, `.netrc`, `.git-credentials`, `.pgpass`, `credentials`, `.config/<app>/token`,
or a private key file such as `*.pem` or `*.key` outside the system certificate directories) with how often it was
refused, asked, allowed or observed. A secret touched within 16 ledger lines and 5 s of a connection outside the
contract is marked "Followed by a connection" and listed first, so the key read right before the attacker send leads. **Outbound**: destinations by
host:port (by name when the line names the host) with their counts; the ones not in the contract first, those whose
first contact is within 16 ledger lines and 5 s of a secret touch marked "After a secret read" and listed first (never a
destination the contract allows, nor a resolver or a system lookup socket: those are where the agent is meant to
talk, or the C library's own lookups; port 53 of a server the engine did not name a resolver is a destination like any other), the contract's own
marked "In contract" (not on a watched run, which has no contract in force), and routine destinations (system lookups, DNS, the agent's own probes) folded
into one counted "Routine" line. On a watched run what was observed next to a secret is a red "Got through". A watched run
has no contract, so it is read against the contract of the enforced run of the same program that started closest to it
(`ledgerview.ReferenceRun` and `PairOf`, `RunSignal.Against`; a later Block now take is not its pair): a destination that contract allows (its `net.allow` entries, or a
line of that run allowed by one) is "Allowed in the enforced run", never next to a secret nor part of the verdict,
and the card names that run. With no enforced run of its program, only the destination the verdict names is red; any
other send next to a secret is "Not on a list". **Approvals**
(what was asked, in the ask card's words, answered how, by whom and after how long, pending), **Live blocks** (actions each block refused, each block named by its kind and a path shortened like the others: "read ~/.config/telemetry", the rule in the link's title) and
**Programs refused**. Every item links to its lines in Logs. Allowed reads are in the ledger only under
`record: full`, so a run recorded in summary shows a secret read only when it was refused or asked.

Paths: every path cell (Overview, Highlights, Compare, the timeline) keeps its end: the file name in bold, the
folder muted and elided in the middle, `~/` for the run's home, the full path in the cell's title. Logs shows the whole
path and wraps it between folder names. The run's HOME is
not recorded, so "home" is a display rule: a folder named `home` beside the run's working directory tree when the run
touched a path under it (a demo's `with/home` next to `with/proj`), else `/home/<the user who started the run>`.

Background refusals: a refusal group is background when the contract's default decided it (rule `unmatched`,
`host-sockets` or `held-unsupported`: no entry names it), it touches no secret, its first refusal is not next to a
secret touch, and it is a system lookup, a DNS lookup (port 53 on this machine: a resolver the run has is allowed, so a refusal on port 53 of another address is a refused connect), a connect to a remote (not loopback) host the run also reached that no net live block or restored live fence of the run named (by name or address, whatever the port, whatever scope id its connects carry and whenever in the run: a block leaves a refusal the contract already makes under the contract's rule, so the next try on another port of a blocked host says `unmatched`, and it stays a real row), a route probe
(UDP to port 65535 of a remote host, read from the refused `net` line's protocol: the connect musl's `getaddrinfo`
makes to each address a lookup returns, to sort them, which sends nothing; a TCP connect to port 65535 is not one;
each probe target is a group of its own, so a real connect to the same host still counts), or a terminal or standard
device (`/dev/tty`, `/dev/null`, `/dev/pts/…`). How often a group repeats is never one of these: severity comes from
place and operation, so a refused connect repeated 50 times stays High. In the supply-chain demo this folds Codex's
~450 probes to Cloudflare addresses (port 65535) and the held reads' `/dev/tty`, and leaves the SSH key and the two
sends to 127.0.0.1:8802 on top.
A burst of refused connects reads as one row on Detections, the Overview and the run page: one host's ports, however far
apart its connects come in the run, then the addresses one rule names (a live block on chatgpt.com refuses every address
the name resolves to) or one network range (/16, or /32 for IPv6) (`ledgerview/burst.go`). The row says how many ports it
holds and Times how many attempts, Investigate lists the ports with a Logs view of each, and each line keeps its page. It is
a display fold too: each address and port keeps its line, its Outbound row and its own severity, a row of one host reads at
the highest severity it holds, and a connect next to a secret read keeps its own row and mark. A group on this machine is
one port (a rule can name one, and port 53 is a lookup), so `TestPortScanReadsAsOneRow` holds those; a remote host's group
always held its ports.
Background is a display fold only: it does not remove a refusal from its retained group or the complete run refusal aggregate. Logs and Highlights counts remain lower bounds when their event windows are incomplete. Overview and
Highlights call it "routine" (the word "Background" is also a run's origin); a system lookup or DNS group is never next
to a secret, so it always folds when the contract's default decided it.

Refusal noise: identical refusals (same run, kind, rule, reason and target) fold into one row with a count.
Refusals of system lookup sockets (nscd, systemd's userdb and resolved, the D-Bus system bus, a user's D-Bus session
bus `/run/user/<uid>/bus`) are tagged
"system lookup" and shown with less emphasis; the logs filter can hide them; they stay in the complete run refusal aggregate, while event-derived counts cover the retained windows.
A netlink destination (`family(16)`) is shown as "netlink".

## Live updates and waiting approvals

While an ask waits, every page shows it: the count is on the Approvals nav item and in the tab title ("(1) Overview
· Tego"), and a banner names the agent and what it asked for (the path read against the run's home), with Allow once
and Deny, the same form posts as the Approvals page (session token and Origin checks). The waiting band is the first
block of the main column, above the page head, in the page's flow at every width, with scripts on or off. It has the
full request on Overview and the first waiting request in a compact band on other pages; More opens Approvals and
shows the known total when more than one request waits. A cut or unreadable waiting source keeps known requests as at least N with its reason; with none known it says it could not tell whether a request is waiting. With an incomplete source, the compact Waiting tab uses N+ or ? with that full sentence in its accessible label and title. The waiting band is not rendered
on Approvals, nor on a run page that shows its own ask card. No floating copy, reserved room or startup scroll hides
the page head. The browser's scroll anchoring keeps the reader's place when a request arrives above what they are
reading. A separate polite live region announces a newly arriving request once; opening another page does not
announce a request that was already waiting. An error page (an
address with no page, a run or line that is not in the ledger) shows the banner, the count and the top bar's Live
word too, as they were when the page was rendered: it does not follow the live state (a reload shows it again). If it cannot read the ledger, it shows the reason and keeps global running and waiting coverage unknown. Overview's Running
now and Waiting on you keep the height of one row each when empty. The full ask cards say how long a request is held: "asked 8 s ago · Codex gives up at about 30 s" on a
Codex run (run_start's harness), "some agents give up after about 30 s" on any other; once 30 s have passed, "Codex has
likely given up; Tego refuses it at 5 m" (the run's `ask.timeout` from its contract copy, 5 m by default). `live.js`
ticks those cards' ages every second and swaps in the late words when their time comes. Above 600 px both bands show an absolute
asked-at time, a snapshot of how long the request has been held, and the wait note; Overview names the oldest request
when several wait. Band ages are not rewritten every second, but the give-up note still changes when its time comes.
The compact band keeps its request while the pointer or keyboard focus is inside it and updates after both leave;
no timer overrides that hold. At 601 to 640 px the controls can wrap between buttons while each action label stays on
one line. At 600 px and below they use one three-column row; timing stays on Approvals. A new
answer's notice replaces the one before it. Only a live run's asks wait: a run that crashed with an open ask shows no banner and no count
(`/status.json`, Approvals), its page says the request was never answered, and its Highlights say "Never answered
(run lost)".

## Actions and the line they leave

Allow once, Deny, Allow or Deny for this run, a stand-in file, Block now, Remove, Pause, Resume and Stop post a form (session cookie,
CSRF field, the dashboard's own Origin) and answer 303 See Other back to the page the form was on (its Referer, checked
to be a page of this dashboard; Approvals or the run's page otherwise). That page shows one line once, kept in memory
under a random id for a few minutes: "Denied: read of ~/.config/telemetry/token" (a path under the run's home as ~/, as the ask card shows it), "Allowed once: write to …",
"Blocked ls on run r-…bzf. It is refused from the next try on." (on a `tego watch` run: "Marked ls on run r-…bzf: recorded, not enforced, since this run is only watched."), "Stopped loop-agent (r-…bzf).", "Pause asked of loop-agent (r-…bzf). It says Paused here once the run confirms it, usually within a second.". A Deny on a run
with a contract file adds "Make it permanent: Never allow", a link to the ask's line page, when the dashboard can change
contracts (it has the rule service, as `tego-control serve` does; without it the line page says contract editing is off,
so no link is offered). A change that was not made
says why in plain words ("Not done: the run is not running, so nothing holds this request any more."). Block now and
Remove refuse what `tego block` and `tego unblock` refuse, in the same words (`liveblock.CheckBlock`): a Remove posted
from a page left open across the run's end says "Not done: the run is not running: its live blocks ended with it, so
there is nothing to remove." and leaves the overlay the run ended with as it was. A block on a program whose file has
other names here, as a multi-call program's applets do (uutils' coreutils, busybox), adds that the block refuses each
of them ("It matches the program's file, which has 115 names here …"), since the launcher matches the file's identity,
as `tego block` notes too. A reload
posts nothing, no ledger line is shown raw (the line page has it), and every form works without JavaScript. Stop waits
2 s at most: a run still ending says "Stopping …", and its page shows Stopping until `run_end`. The line sits in the
layout's waiting-ask banner region (`r-banner`, below), so the page that shows it is live like any other; a region
request (below) carries the page's `?flash=` but never takes the line again. With JavaScript on, the same forms are
posted in the background and the line comes back as JSON instead of the 303, said once, in a toast (see below).

*Make a rule* links on timeline and Logs rows appear only on a run that names its contract file (a `tego watch` run has none)
and only on refused or asked rows; any row's line number opens the line page. A refusal of a live block reads
"Blocked live at 21:50 by somebody, from the dashboard" instead of the contract's reason.

A page never reloads itself: it changes in place, only where the ledger changed. `static/live.js` (small, no
dependency, CSP `script-src 'self'`) follows the live state, `{"live":N,"pending":N,"sig":"…","rev":"…"}`, over one
Server-Sent Events stream per page, `GET /events` (a `state` event each time the state changes, checked every second
against a state the streams share; a heartbeat comment after 15 quiet seconds; each stream ends after 10 minutes and
the page opens another; at most 4 streams, a page past that polls). A browser opens only 6 HTTP/1.1 connections to
one address and a stream holds one, so a tab that is hidden closes its stream and polls every 5 s (the title count
keeps up) and opens the stream again when it is shown, and the bound of 4 leaves connections for fetches, form posts
and page loads however many windows are open. When the stream fails the page polls `GET /status.json` every 2 s and
reopens the stream with backoff (2 s doubling to 30 s); when the dashboard cannot read the ledger the stream sends a
`lost` event and ends. The topbar's Live word says "reconnecting" while neither answers. Both go through the same Host and session-cookie checks as every page; the
stream lifts the server's read and write timeouts for its own connection only and ends at shutdown. `sig` changes
when the set of waiting asks does; `rev` is the read model's revision (`Snapshot.Rev`, below), which moves when any
run writes a line, a run starts, ends, is found lost (its launcher gone) or leaves the ledger, or an ask comes or goes.

On a change the page fetches its own address again with the header `X-Tego-Regions: <region>:<hash>,…` and gets back
only the live regions whose HTML changed (`web/regions.go`), rendered server-side by the page's own templates (the same
escaping, no client-side templating), at most once a second. The regions: on every page the topbar's Live word, the
side nav with the Approvals count, and the waiting-ask banner; the Overview's headline, tiles, Running now, Waiting on you, Recent runs and Newest High and Medium; the whole Approvals page; the Runs heading,
its running rows and its other rows (two `<tbody>` of one table) and its paging line; a run's header and ask cards, its Block now panel (`r-run-live`), its Highlights, details and tab counts, and its Refusals, Processes, Receipt,
Least privilege and Unused tabs; Logs' heading and its facets (its rows follow the run themselves: static/logs.js, see `/logs`; live.js tells it the ledger moved with a `tego:moved` event and re-renders the rows region only where logs.js is not running, at the top of the first page). live.js
merges each fresh region into the page node by node (rows matched by their key), so the scroll position, focus, open
`<details>`, a text selection (the region waits until it is gone) and a form you are filling in (left as it is) stay.
The compact request band also waits while hovered or focused. New list rows fade in from a neutral surface tint
(a still tint with `prefers-reduced-motion`). The request band and its rows keep their own background and text
colours on arrival, without that highlight. A polite announcement signals newly pending requests; the initial set
stays quiet, and an unchanged set is not repeated on navigation. A request observed to leave that set and later
return is announced again. Requests first seen after a filter or tab change are announced too; entering an
unchanged set stays quiet. The announcement state retains only the last observed pending keys. The tab title
carries the waiting
count, "(1) Overview · Tego", even in a background tab. A live run's timeline fetches only
`GET /runs/<id>/rows?after=<seq>`, the rows after the last line it has (HTML, gzip when the browser takes it), and
puts them at the top, keeping the newest 200; when the run ends it stops following and drops the rows' *Block this* links.
Measured on a busy isolated run (~120 lines/s, 55,000 lines) before this change: the page is 161 KB once, then about
3.8 KB of rows every 2 s (a whole-page refresh was 28 MB).

A clock that follows the wall clock rather than the ledger, a running run's duration so far or a full ask card's
"asked 8 s ago", is marked `data-ck`, so a region's hash leaves its text out. Outside the request band, live.js
rewrites these clocks every second from `data-since` or `data-ago`; a region whose only change is that clock is not
sent again. The band's held-duration snapshot also uses `data-ck` to leave its text out of the hash, but does not
tick; the band's asked-at time stays absolute. A full page renders each
region once: the layout places the HTML it rendered for the hash. A response is served from the shared cache only
to the peer class it was rendered for. Every region request decides the peer class before consulting either
shared renders or unchanged-region memos. Governed and uncertain peers neither read nor write shared cache state;
their handlers render fresh. Person responses keep the one-second cache for the same address, regions and live
state (`web/regioncache.go`). Builder previews carrying a review identity or acknowledgement are never stored:
`/rules/new` and `/rules/change/preview` bypass shared caching for every peer. This branch introduces the first
GET rendering that differs by peer class. Every POST through the dashboard drops shared renders, and a run
page's answer is also keyed by the files beside its run that the 204 key below hashes (its live blocks and
pause request, the launcher's pause mark, its stop marker, the rule-change journal). A change no revision covers (a rules file edited outside the dashboard) can be missing from an answer rendered up to a second before it,
until the page's next update. Measured with one live.js-like viewer per page on a 41-run ledger with
a run writing 5 lines a second: the Overview sent about 25.5 KB per update, now 4.5 KB (median; 12 KB
when a refusal moves Newest High and Medium); Runs 66 KB, now 1.7 KB. With 2,000 runs, Runs is 174 KB and 12 ms warm (was
3.5 MB and about 220 ms).

A person's run page (its Timeline, Refusals and Receipt tabs) that asks again with the hashes of its last answer gets
`204 No Content` without its handler running while nothing it shows has moved: its run's lines and live state, the
enforced run a watched run is read against, the waiting asks, whether anything runs, its live blocks file (which also
holds a pause or resume asked), the launcher's mark that it reads a pause, its stop marker, the rule-change journal
(the timeline's change rows), and the chain anchor (`web/runkey.go`); its duration so far ticks in the browser, so no
clock is in the key. So another
agent's busy run no longer re-renders it once a second (on a 20,000-line run, 1.06 ms per ask became 0.09 ms).
Other pages, and Least privilege and Unused (they also read the machine config and the contract source), are always
answered by their handler.

Allow once, Deny, Allow or Deny for this run, a stand-in file, Block now and Remove post in the background with the
header `X-Tego-Inline`, and the action answers the line it would leave on the next page (above) as JSON,
`{"ok":…,"text":"Denied: …","link":…,"link_text":…}`, keeping no flash: live.js says it in a toast in the corner, with
its "Make it permanent" link when there is one (an error, or a line with a link, stays until dismissed), and refreshes
the page's regions in place, so the line is said once and the page does not load again. Stop's confirm page does too,
then opens the run page with the toast. A refusal before the action ran (a bad session token, an error page) reads
"Not done: …". The forms are the same form posts (session token and Origin checks), so without JavaScript they post
as before and return to the page with the line, and pages keep their meta refresh inside `<noscript>`. "Make this a rule" and the line details' "Act on this" still post as
plain forms. `go test -tags chrome -run TestLiveInChrome ./internal/control/web` drives headless Chrome over
`--remote-debugging-pipe` and checks that the Overview and a live run's page keep their window (no reload) while the
run writes lines, an ask comes and is answered, a Deny reports in a toast, and the run ends.

## Read model, bounds and speed

The pages read the ledger through a cache that lives as long as `tego-control serve` (`internal/control/ledgerview`,
its doc.go). Per run it keeps the events file's identity (device, inode), size and mtime and the offset of the last
whole line read: an unchanged file is not opened, a grown one costs only its new lines, and one that got shorter or
was replaced is read again from the start. Each change makes a new read-only version of the run that every request
shares; the timeline, the refusal groups, the Logs fold, the Logs text index and the "Similar" counts are built once
per version. A kind=refused line that mirrors a refused action is marked as it is read (`ledgerview/pair.go`: by the
envelope it copies, among the last 4 lines, else the line just before it; the rule `tego measure`, `tego drift` and
the receipt pair by too, `internal/check/mirror`), and every count and list takes the one
rule `Event.Refusal` from that mark, so a run read as it grows counts what one read of the whole file counts. Logs folds each run where it lies and builds only the rows of the page shown. Chain verdicts of ended
runs are kept by the events file and by the anchor's answer for the run (what `tego events --verify` reads for it in
chain.log), so the overview no longer re-hashes its newest 20 runs on each load: a look costs one lstat of chain.log
while it is unchanged, and one read of it after any change and at least every 10 minutes, shared by every run and
every check (no check reads chain.log for itself). That read holds no lock: a look that needs it waits for the one in
progress, and a look that does not need it waits for nothing.
Another run's end, which appends its line, leaves the kept verdicts standing; a changed events file, or any change to
chain.log that its stamps (device, inode, size, mtime, ctime) show and that changes the run's answer (its line
rewritten in place, a second head for it, a malformed line anywhere, its line gone), is checked before the page
answers. A write the stamps do not show (one within a tick of a coarse clock, on a kernel before 6.13, or one through a
shared mapping's already dirty page) is seen within 10 minutes. In chain.log, the first look once the dashboard's
reading of it is 10 minutes old reads it again and checks a changed answer before the page answers. In the events file,
once a kept verdict is 10 minutes old it is still shown while the same run is checked again in the background, the
events file read from disk. A check that finds another verdict than the one kept, at a look or in the background,
redraws open pages, though an edit of chain.log writes no ledger line. The line details page reads its line from the offset the cache recorded,
and so does its Act on this panel: the rule service reads run_start and that one line, after checking that the file is
the one the cache read (device, inode, no shorter) and that the line there has the seq asked for, and falls back to
reading the run from its start otherwise; a confirmed change still reads the line from the start. The run page's
Least privilege, Unused permissions and Receipt tabs keep each run's result (the newest 64 runs viewed) while the
run's events file (device, inode, size, mtime, a digest of its last 4 KiB, live or not) is the same, and for Least
privilege and Unused also the chain anchor, the run's `contract.yaml` copy, the machine config and `PATH`; every
result at most 5 minutes, so what lies outside that key (a program installed, a dated entry that expired) shows by
then. A live run's result that took over 0.25 s is reused, as lines arrive, for at least 2 s and twice its cost after
it was finished, and while another request computes the next one; a cheaper one (any run at the demo's scale) is
never shown stale. On a 100,000-line run a repeat view of these tabs or of a line page takes 3 to 6 ms (it took 0.4
to 1.9 s).
A command too long for its line (an exec's argv, run_start's command) is in the run's `blobs/` directory, named by
its sha256 (`argv_blob`, `command_blob`). The cache reads that blob once, as it takes the line: read-only,
`O_NOFOLLOW|O_NONBLOCK`, a regular file of at most 256 KiB whose content hashes to its name (the ledger's own blob
reader does not re-check). Rows and the Logs search get at most 8 KiB of it, ending "… (N bytes more, on the line
page)"; the line page shows its start and the whole command in a fold. A blob that fails a check leaves the program's
path and the row says "(command in blob could not be read)". The line page's terminal twin,
`tego events <run> --json | sed -n '<seq+1>p'`, prints the line byte for byte (seq counts from 0).
Each version carries a revision (`Snapshot.Rev`, `Run.Rev`, `Run.LastSeq`, `Snapshot.Changed`) that the live-update
layer uses to tell what changed.

A run's Signal (the highlights and grouped refusals every verdict is read from) is kept per run version. While the run
is live, the pass that built it is kept too, so the next version folds in only the lines it gained: on a 100,000-line
run writing 10 lines a second, a live update of the run page takes about 22 ms and of the Overview about 19 ms (133
and 157 ms before). Whether a line's paths name a secret
(`secretpath.Is`) is decided once, when the line is read. A page reads each run's Signal once however many of its
parts ask, and the Rules page keeps a run version's scan of the ledger.

Bounds: a request covers at most the newest 100,000 runs (by their ledger file's change time) and 5,000,000 lines
(`MaxRuns`, `MaxLines`). Full-run summary counters continue beyond the presentation bound. Each displayed number names its scope and is qualified individually when its source is incomplete; a page-wide banner alone does not establish the meaning of an exact-looking number. Decoded lines are
kept under an estimated 512 MiB (`MaxResidentBytes`), with space reserved for derived views and indexes.
Amended 2026-11-03 (M2): decoding itself retains at most 32,768 recent events and 128 MiB estimated per run
(further limited by `MaxLines`), including active runs. The reader stops at the file size it observed and discards
oversized lines with bounded buffers. The estimate charges all retained strings, including envelope fields absent
from the payload and long values excluded from interning. Full-run counters and start/end metadata update incrementally outside the
window; the Signal, searches and process details cover retained windows. The page labels these limits, including
partial verdicts. Root pages do not rehydrate every evicted window; a single run page can reload its bounded
interval by byte offset. Older timeline windows scan earlier disk history with bounded retention. Whole-run ledger
JSONL downloads stream the complete file observed at open without the filtered-export line cap;
reverse downloads may rescan earlier bytes for each window. These are
allocation/retention bounds, not a process RSS limit: concurrent requests can hold older immutable versions.
More than 32,768 simultaneous pending asks or 8 MiB of estimated pending-request state are labelled as
truncated. That estimate charges every retained ask string, including `Hold` and `Op`, after event-window
rotation. Full-history incremental Signal and a
persistent historical offset index remain unimplemented.

### What each number covers

The [number inventory](../internal/control/web/inventory/number_inventory.json) names
278 quantities, including zero-form sentences, tooltips, spoken labels and the
waiting count in the document title. There are 26 Overview rows, 10 Runs, 108 Run
and tab rows, 20 Logs, 9 Detections, 5 Approvals, 9 Contracts, 17 Compare,
21 Event, 7 Investigate, 9 editor/transaction rows, 7 machine-readiness rows,
5 MCP, 4 model-route rows, one Glossary, one Severity and 12 shared rows.
The Vault layer registers its seven rows where that layer is built. Each row names
its label, source and incomplete form. `quantity`, `quantityWords`,
`quantityText` and `quantityZero` refuse an unknown inventory ID. Literal markers
are checked against the same inventory; these helpers alone cannot detect an
unmarked number written directly into a template.

Sources are eligible run candidates from directories or remembered missing records (`candidates`, exact despite a display cap but unknown after a scan failure), the run list (`runs`), running status (`live`), status-derived groups (`status`), the active run filter (`selection`) and its non-running remainder (`remaining`), decoded full-run counters (`aggregate`),
run categories that require decoded metadata (`metadata`), retained events (`window`), historical unanswered identities (`unanswered`),
one run's actionable waiting requests (`pending`) and the global queue (`queue`),
answer history (`history`), newest-run credential usage (`vault`), strictly
streamed MCP counts (`mcp`), daily refusal aggregates (`daily`), and the streamed
Receipt with its own identity limits (`receipt`). `exact` names a complete list,
configuration value or the explicitly labelled contents of one record. Counts
within a run row or comparison side follow that run. Even the recovery page for an unreadable ledger root keeps run presence and waiting unknown. Shared top-bar and navigation
counts always use the global run-list and queue scopes, independently of a page's
local source. Known directory presence cannot establish that a run lacks a protection tier, MCP declaration or model route when its metadata could not be decoded; those category absences use the decoded-record scope. The central page renderer refuses missing global scopes; New contract and the retired rule receipt use the same global derivation. A sub-template taking a numbers scope must receive it explicitly:
`numbersOf` refuses a missing scope, including in live-row responses. Complete-record recovery links use the standard button target, including on unreadable-root error pages.

An ordinary quantity is exact for its stated scope, or reads “at least N” with a
reason and complete-record recovery. Truncation, eviction, omitted runs,
malformed lines and bounded history/list retention qualify their affected
sources. An unreadable source replaces ordinary prefix counts from that source with “could not read”. Live-index failures qualify running, waiting and status-dependent selections without suppressing readable event, history or credential counts.
An absence derived from zero, including Contract and rule hit statements, says
none was seen in what is retained when its source is incomplete (including the mixed Compare summary), with the same
reason and recovery. It cannot establish complete absence.

A retained run failure is distinguished from an unlisted candidate failure. The former keeps known presence and qualifies that run’s sources; an unlisted failure takes priority for global uncertainty, even if another listed failure was encountered first (`TestApprovalsEndedMissingRecordCannotHideWaiting`, `TestUnknownCandidateAfterListedFailureCannotClearQueue`).


Known actionable requests remain visible after a read failure. One `waitingOf`
derivation supplies the badge, document title (including live updates), spoken
text and page sentence. Three known requests with a cut or unreadable source
read `3+` visually and “at least 3 waiting: <reason>” in words. With none known
and an incomplete source, the badge/title use `?` and the sentence says “could
not tell whether a request is waiting: <reason>”. A complete empty queue alone
permits “Nothing waiting”. Failures of retained, known ended runs do not qualify that
headline: they cannot hide an actionable request. Waiting identities are kept by
`runState.take` in `internal/control/ledgerview/cache.go`, separately from the
retained event window and the 200-answer history; their own budget, malformed
live records, omitted runs and reader failures still qualify the queue. An unreadable live index preserves previously known waiting requests as a lower bound; a listed run whose directory vanished also prevents an all-clear. After a cold start, an absent index beside unfinished or omitted records keeps waiting unknown; a fresh empty ledger or complete ended history alone does not. Losing a ledger root previously read successfully, even empty, is a global read failure even when its remembered runs ended, because other runs could be missing. Unknown running status is shown as unknown, rather than lost, and those runs are not offered as finished runs. Recovery changes the row revision without requiring another record line.

A missing record is a read failure with reason “its record file is missing” when
the store previously observed the record file, even empty (it could have gained lines before it vanished), or a last-refusal file or configured
chain entry supplies evidence of recorded lines. This evidence survives summary
eviction and removal of the run directory for the store's lifetime. It retains one run ID per observed record source, outside the decoded-window byte budget. An indexed run last known live retains its known waiting requests after its directory and held lock become unreachable; a missing lock in an existing directory still means the run is lost. After restart only the surviving disk evidence
is available; GAPS C77 records the indistinguishable case. The account-wide chain has no ledger-root field: a chain ID alone cannot locate a vanished, previously unknown run directory in this root. A surviving live-index entry supplies root membership for a vanished directory: a positive chain head then retains that missing recorded run and its count. An account-wide chain ID with no root association still supplies no membership. A genuinely new run
without such evidence has recorded nothing yet. Unreadable chain evidence leaves recorded history unknown; it is not remembered as positive evidence. Polling a missing file keeps the last immutable prefix without waiting for an active decoder. Non-regular record files also retain a known prefix as a read failure. Chain evidence for missing candidates is read in one batch per scan. Failed candidates are retained ahead of readable candidates at the run-list cap; the banner says “up to”, without promising the newest selection.

Clocks, durations, identifiers, ports and configuration examples have individual
source-element/attribute exclusions with reasons in the inventory (private Vault
exclusions live with its test layer). No styling class is exempt. The source test
requires each exclusion to identify exactly one element/field, and the rendered
walk fails if an exclusion or inventory row renders nowhere. Exclusions apply only
to their own text and attributes; child quantities are always inspected. Exit codes and several exact record/configuration
values are themselves inventoried; no category is silently exempted.

`TestNumberInventoryMatchesTheSource` checks IDs and exact-scope call sites.
`TestNumberInventoryQualifiesEverySource` checks every row's helper forms.
`TestNumberInventoryRenderedPages` walks real page, live-region, live-row and
line-panel responses over complete, truncated, evicted, malformed, unreadable,
omitted-run and cut-queue fixtures, supplemented by real-template boundary
fixtures. It inspects text and shown/spoken attributes: title, aria labels and
descriptions, alt, placeholders, visible input/output/meter/progress values and
bounds, and deferred visible text. `TestNumberInventoryPageCatalog` requires a
fixture for each standalone page in the server's page catalog. These are fixture
and source checks, not a proof of every possible data value or branch.
`TestNumberCollectorNegativeControls` includes unmarked monospace text, a tooltip
and a zero-form sentence, plus spoken/value and split-text controls. The P4–P8
regressions exercise missing files, fragment scopes, global chrome, the independent
waiting state and both DOM and keyboard order. Chrome checks remain explicitly
invoked and do not establish human screen-reader speech or another browser engine.

Daily refusal totals use the complete run aggregate only when its minimum and
maximum refusal timestamps fit the named day. The refusal count tracks whether
these bounds were seen separately from their values: the RFC3339 zero date is a
valid timestamp. Invalid or missing timestamps are unreadable records, including
after window truncation, and are never used as date bounds.

The following performance numbers predate this amendment.

Measured 2026-10-26 on an isolated ledger written by the real ledger writer with a valid chain (`go run
./tools/dashgen`: 300 ended runs of 500 lines, one ended run of 200,000 lines and 107 MB, one live run; 350,800
lines, 185 MB), `curl -w %{time_total}`, median of 5 warm requests after one cold one, same machine, before and after:

| Request | Before | After |
|---|---|---|
| Overview `/` | 0.54 s | 5 ms |
| Runs `/runs` | 0.16 s | 23 ms |
| Run page, the 200,000-line run | 0.45 s | 12 ms |
| Run page, a 500-line run | 0.17 s | 13 ms |
| Logs, no filter | 0.53 s | 10 ms |
| Logs, text search (`q=tool3`) | 0.30 s | 21 ms (160 ms the first time a term is searched) |
| Logs, refused lines of one run | 0.18 s | 12 ms |
| `/status.json` | 0.16 s | 1.3 ms |
| Approvals | 0.19 s | 1.3 ms |
| Live rows `/runs/<id>/rows?after=` | 0.28 s | 0.8 ms |
| Line details, line 100,000 of the big run | 1.31 s | 0.85 s |
| Resident memory after the run | 708 MB (peak 981 MB) | 456 MB |

The first request after start reads every line once; see "Cold start" below for how that is now shared and spread
over cores. The line details page is still
slow deep in a huge run: its "Act on this" panel asks the rule service, which walks the run with the engine's own
reader up to the line (`internal/rulefile.FindIn`), outside the read model.

Logs' facets are counted in the filter's own walk, and each run's counts are kept per run version and filter, so a warm
page pays only the walk (measured once with the former env-gated `TestQueryBudget`, which `go test` now runs on a seeded ledger and holds by counting allocations; on the same 350,499-line ledger,
query plus facets, in-process, GOMAXPROCS=4): no filter 38 ms the first time, 0.7 ms again; one filter (verdict, kind,
host, rule prefix, pid, source, a time range, a path under `~`) 10 to 28 ms first and 10 to 19 ms again; the first text
search of the ledger 104 ms (it builds each run's text index once), later words 9 to 37 ms. A warm `/logs` with its
facets on the 19,528-line demo ledger took 17 to 19 ms when measured once on a copy of it; `TestLogsWarmBudget` now runs in every gate on a seeded ledger and holds that by counting: a warm page of the budget set allocates the same objects and bytes on 9,000 lines and on 36,000.

The program a line's process ran is one forward pass over the run's exec lines (`ledgerview/program.go`), kept per run
and continued where it stopped when a live run grows, so a live page pays only its new lines. Groups are counted in the
filter's own walk and kept per run version, filter and grouping like the facets (`ledgerview/group.go`). On a copy
of the 19,528-line, 5-run demo ledger (measured then by the env-gated form of `TestLogsWarmBudget`, warm, best of 5, GOMAXPROCS=4,
before and after measured one after the other on 2026-10-27 over the same copy, twice each; the copy is not kept):
`/logs` 19 ms (15 ms before the Process column, the program facet and the row panel's hooks; the page is 212 KB, from
157 KB, most of it the per-row program and pid links), `?verdict=refused` 21 ms (16.5), By process 14 ms, By target of
the refused lines 7 ms, By rule of `prog:codex` 3 ms, and the live tail's fragment for a full page of new rows 9 ms.

The rule service lists the rules files the runs here ran (`rules.Service.Contracts`) for the Rules page, Change rules
(three times a request: the list, the form's guarded read of the file, its history) and every plan, and the run pages'
rule-change rows read the same runs. It reads each run's first line once and keeps the ledger root's listing while the
root's device, inode, link count, size, modification and change times stay as they were, read through the opened root
(an NFS client refreshes a directory's attributes on open): a run started or removed is seen on the next request, a
run directory whose first line is not written yet is read again on every request until it is, and a root that changed
less than 2 s before a listing is listed again on the next request (file times move in clock ticks). Whether a run is
running is asked anew each time. On a generated root of 5,000 runs of 25 rules files (`BenchmarkContracts`,
`BenchmarkChangePage` in `internal/control/rules`, 2026-11-02, GOMAXPROCS=3, medians of 9 interleaved runs before and
after) a listing with nothing changed takes 0.31 ms (6.8 ms before), the first after a run starts or ends 3.6 ms, the
first after the dashboard starts about 0.3 s, and the service's part of a Change rules request 1.0 ms (21 ms).

### Cold start

`tego-control serve` warms itself as it starts: it reads the ledger once, starts checking the overview's chains and
builds the overview once, unseen, so its Signals and folds are kept. Runs are decoded outside the cache's lock, on up
to four cores, and a page that needs a run another request is reading waits for that read instead of reading it again.
The live state that `/status.json` and `/events` give never waits for a read in progress: it is the state last
published, and the read moves its revision when it lands. A chain still being checked shows as "Verifying…" on the
overview rather than holding the page.

Measured 2026-10-27 on a test ledger, A (22 runs: 10 watched and 10 enforced runs of 5,000
lines, one of 100,000 and one of about 100,000 marked live; 190 MB, valid chains), `-tags tegotesthooks` builds with
GOMAXPROCS=4, `curl -w %{time_total}` against a freshly started server, files in the page cache, before and
after:

| Request | Before | After |
|---|---|---|
| Overview right after start (cold) | 5.15-5.24 s | 1.45-1.59 s |
| Overview 3 s after start | 5.19-5.24 s | 4-6 ms |
| `/status.json` during the cold read | 2.69-2.71 s | 2-3 ms |
| First `/events` state during the cold read | 3.0 s | 13-22 ms |
| The 20 chain checks | inline, about 2.5 s of the first Overview | in the background, done about 2.9 s after start |

The cold Overview is now bounded by the largest run (about 100,000 lines decode on one core in about 1.5 s); a run is
not split across cores. The same way on a second ledger, B (2,000 runs of 60 lines): cold Overview 1.52 s to 0.65-0.69
s, Overview 3 s after start 1.50 s to 24 ms, `/status.json` during the cold read 1.02 s to 8 ms. At demo scale (ledger
C: 40 runs of 300 lines and a live run): cold Overview 0.23-0.26 s to 0.05-0.07 s; the Ledger tile there may read
"Verifying…" for about a fifth of a second if the page is opened the moment serve starts.

## Look and feel (v0.2.0 design system)

The shared design system uses the website's brand: `static/tokens.css` holds the colour, size, spacing,
radius and duration tokens (a test rejects literal colours in the other stylesheets), and `static/app.css` holds
the shell and components. Legacy page and compatibility rules still contain literal dimensions. Until each
page is rebuilt on the system, `static/mvp.css` keeps today's page rules, scoped to the old markup, and app.css's
section 19 fits that markup into the new shell; each rule there names the package that removes it.

- **Shell.** Desktop keeps the approved top bar, side rail and ledger geometry. At 600 px and below the
  in-flow 56 px bar shows the logo and page name. Bottom navigation has Overview, Runs, Approvals with its waiting
  count, Logs and More. More opens a native page with Agents, Contracts, Detections, This machine, Guide, Glossary
  and the theme switch. Navigation is 64 px plus the safe inset; the page reserves its space. At heights of 480 px
  or less it returns to flow. From 601 to 860 px the existing top strip remains; the 861 to 900 px icon rail and
  wider 216 px rail retain their content budgets. Runs uses three-fact phone rows and a Filter sheet with a native
  GET fallback. The shared page column wraps unbroken names without changing rail widths. The page packages share their responsive interior components.
- **Type.** The system text faces; page titles and the wordmark in Anton, the website's headline face, served from the
  binary (`static/fonts/anton.woff2`, OFL 1.1, 11 KB, a cut of the site's file to Basic Latin, Latin-1 and common
  punctuation); a title that is data (an agent, a path) stays in the text face. With the font blocked, the wordmark
  falls back to the system stack. Figures are tabular everywhere.
- **Surfaces.** Paper and stone grounds, hairlines, one radius; panels lift by a faint shadow. A record tile's value
  can wrap when the available width changes, including when another tile fits on the same row.
- **Live updates.** On a desktop the scrollbar gutter is reserved, so a page that grows past one screen as lines
  arrive does not shift sideways.
- **Contrast.** Every text token clears WCAG AA (4.5:1) on `--c-bg`, `--c-surface` and `--c-sunken` in the light theme
  and both dark blocks, the focus ring 3:1 (theme_test.go, a11y_test.go).

The development tree's shared geometry audit, which has saved fixtures, a configuration
matrix and per-clipping-ancestor reachability checks, uses rendered text fragments and applicable clipping
boxes rather than counting empty layout space or ignored inline overflow as lost content.
The round-2 zero-regression conclusion is withdrawn because
an inner horizontal scroller could hide outer clipping. Corrected replay results and remaining page findings are
recorded privately. Hidden native captions and icon-rail Soon
labels retain their tiny masked boxes and accessible names. Legacy Logs record-line agent labels at 768 px and up also keep
room for enlarged text while retaining horizontal ellipsis and full-value titles. Legacy Overview and Runs
command subtitles at those widths also retain room for enlarged text and keep their command tooltips.
These repairs do not redesign phone layouts.
The geometry comparator does not establish completeness of the separate full-audit behavior and screenshot records. Chrome checks require an explicit manual run; CI and the private gate
do not run the Chrome-tagged guards.

## Signal, approvals and live pages

- **Signal over noise.** Every run page opens with Highlights; the Refusals tab groups by default with the background
  folded. On the supply-chain demo's enforced run 26 of 482 refusals stay in front and 456 fold as background; the
  SSH key (marked "Followed by a connection") and 127.0.0.1:8802 (marked "After a secret read") are the first rows.
- **Approvals you cannot miss.** A waiting band above the page head, in the page's flow at every width, on every page but
  Approvals and the asking run's own page (which shows the ask in full); the count in the tab title and on the nav item;
  Allow once and Deny in one click. Above 600 px the band is full on Overview and compact elsewhere. On phones it shows only the oldest request: who wants what, including the target, Allow once, Deny and Details. Timing and the full target remain on Approvals.
- **Light live pages.** `static/live.js` follows the live state and a live timeline fetches only its new rows (see
  Live updates); no page reloads whole: only the changed regions
  are swapped in place.
- **Compact rows.** Timeline and Logs rows carry *Block this* (on a live run's allowed program, destination or file:
  a file row fills in kind File or folder with its absolute path, a rename's or a link's first name as the line holds
  it) and *Make a rule* beside the verdict (the run page's Block now panel shows its terminal twin, `tego block <run> <kind> <value>`, which `static/twin.js` fills in with the form's kind, value and time limit as they are typed or picked, each word quoted as `internal/shellword` quotes one and a value that starts with `-` after `--`, and leaves as placeholders for a path that is not absolute or a value holding a control or an invisible character); desktop Logs' What text wraps without a line clamp; phone summaries keep who, one outcome and when, with exact technical values at their Event destination; ellipsized facet and record-line agent labels have their full values in titles; the Unused permissions tab says "unknown here" instead of a false "Not in the
  contract" when the contract cannot be recompiled; when the copy does not compile at all (its folder is gone) it
  counts the entries the copy's text declares and says so in one line.
  The line page's prefilled Logs search signals a subject wider than its input with an ellipsis and keeps the full
  rendered subject in its title. The input remains editable, with its full value reachable by moving the caret.
  Overview's Waiting on you rows give ellipsized run/time metadata a title with the displayed label, full run ID and
  absolute timestamp. Logs' clamped Rule labels keep the complete displayed words and raw rule key, when present,
  in their titles. Detections names the Investigate column on its header itself, keeping hidden heading text from
  enlarging the document outside the table's scroller.
- **Compare.** `/compare?a=&b=` puts an observed run beside an enforced one.
- **Colours and a dark theme.** The shared shell and state chips use the design's meanings (`static/tokens.css` holds
  the story): orange means a request waiting for a person. Refused is a dashed red outline; a protected read that
  was allowed is filled red with explicit words and a warning icon, except allowed own-login reads, which stay
  neutral. Routine actions and current navigation use
  navy or neutral ink. Routine allowed and passed-through actions and verified states stay neutral and do not
  claim safety.
  Light uses paper, white and cool grey; dark uses three navy surface levels. Text and control boundaries are
  checked against their actual grounds in both themes. Auto follows the device; Light and Dark override it.
  On phones the single switch is on More; on larger screens it remains in the header.
  `static/theme.js` (loaded in `<head>`, so there is no flash) sets `data-theme` on `<html>` and keeps the choice in
  `localStorage`. Without script the switch is hidden and the system setting rules. Print is always light.

## How a run was started, Stopped, and the keyboard

- **Kind label.** The run page labels each run Interactive, Background or Unknown (Overview and Runs show the
  label only for Interactive; a Background run's status says "Started without a terminal" in its title), from
  what `run_start` recorded and nothing else (`ledgerview.Run.Origin`).
  Interactive: `stdio.stdin` was a terminal.
  Background: stdio was recorded and its stdin was not a terminal. Unknown: the record says neither, an older ledger
  or a descriptor that could not be examined; the label never guesses.
- **Stopped.** A run ended by `tego session stop` or the dashboard's Stop says Stopped (from `run_end` reason `stopped`; the
  run page adds who asked when the line names a principal). Other ends say what happened, not the code: Exit N,
  Ended by SIGHUP, Out of memory, Too many processes, Hit a limit, Could not start, Orphaned, Tego error; Lost is a
  run with no end line whose launcher is gone (its badge explains): the live index (`<ledger_root>/.live`) does not
  list it, or it does and no process holds the run's lock any more, as when the launcher was killed or crashed before
  writing run_end. A listed run is running only while its lock is held, as `tego status` reads it: the dashboard probes
  the lock as the ledger's readers do (`ledger.LockHeld`, `ledgerview/livelock.go`), never waiting and taking nothing
  a launcher holds, and keeps each answer 2 s, so an open page shows a launcher's death as Lost within about 3 s (the
  live state is checked every second).
- **Keyboard and screen readers.** The main journey (Overview, a run, a line's "Act on this", Approvals Allow and
  Deny) is checked by `web/a11y_test.go`, with what "Act on this" adds on a live run: "Also apply now" (a box that
  can be ticked and one that cannot) and the Saved panel's Undo with its acknowledgement and "Also lift". The skip
  link is the first tab stop and leads to `#main`; every link, button and field has a name (a bare count or "Run"
  link carries an `aria-label`); a group of boxes is a `<fieldset>` whose first child is the `<legend>` naming it; no
  positive `tabindex`, no autofocus. The waiting band is a named region after the top bar and navigation in the page's
  tab order; a separate `#ask-say[aria-live="polite"]` announces when newly pending requests appear. Initial requests
  stay quiet; an observed removal and return counts as another arrival. Allow comes before
  Deny, and each of those boxes before the button that sends it; a visible focus ring (`--c-focus`, 3:1 or more on
  every surface, light and dark) is never removed.
  `web/journey_chrome_test.go` walks it in headless Chrome with Tab and Enter alone, at 390,
  768 and 1440 px wide, light and dark: the Overview's skip link and the nav to Approvals, Allow once there, a run's
  Stop run and its confirm, Deny on the run's waiting request and its Receipt tab, a line's page and a Logs row
  opened in place. Every stop must come after the one before it, sit in the window with its focus ring and not lie
  wholly under another element (the sticky top bar, the approvals banner); no page reached
  may scroll sideways, log a console error, an uncaught exception or a failed load, or break the Content Security
  Policy; and at 390 px every button-like control must be at least 24 by 24 px (WCAG 2.5.8; the toast's × is now a
  24 px square). The skip link leaves `<main>` just under the sticky top bar; phone content and focus reserve space above the
  fixed safe-area bottom navigation, which returns to flow at short heights. A toast can still lie over a control near the bottom right (across a phone's width, above navigation)
  for its 6 s: the test logs that and does not fail it. `TestReceiptTabInChrome` holds the Receipt tab
  of four runs to the same at every width and theme. Chrome-tagged tests are in neither CI nor the private
  `make precommit` gate. They run by hand today (`go test -tags chrome
  -run 'TestJourneyByKeyboardInChrome|TestReceiptTabInChrome' ./internal/control/web`); the shell's band checks use
  `-run '^Test(Shell.*|AskBand.*|AskBanner.*|CompactAskHolds)InChrome$'` with the same tag and package. No real screen reader and no
  person has run this journey yet.

## Rules in force

`/rules` says what one run's agent may read, change, run and reach, at the run's tier, as `rulesview.InForce` builds
it from the run's contract compiled as `tego` compiled it. A chooser picks a rules file a run of this ledger recorded
(named by the rule service's opaque ref, never a path, so a file recorded through a linked folder and through the
folder itself is one entry; a file no longer at its path reads "file gone", and its runs still show the rules they ran)
and one of its runs: its newest 40, and the run shown when that is older (one reached by `?run=`). Each group (Can
read, Can change, Asks you first, Never
reads, Never changes, Programs, Network, Settings it gets, Limits, Always on) is one table: the rule's sentence, its
effect (an allowed rule's chip is neutral, not green), how it is enforced when that is an exception (best effort in
a quiet chip, held by tego, not enforced; a rule the operating system enforces in full leaves the cell empty, as the column
head says), its hits in this run linking to Logs filtered to its
ledger rule key (a program entry's key is the name the run's lines give the file it resolved to, so every entry
naming one file, such as `python3` and the `python3.13` it links to, shows that file's hits; an entry with words
such as `git status` counts every allowed run of `git`, not only its own words; and every entry naming `git` also
counts the runs of the helper images compile grants git, its exec-path `git` and dashed helpers, which an allowed
`git commit` re-runs for its maintenance; the row of a command that is a script counts the runs of the interpreter
its `#!` line was granted, such as the `node` of a `#!/usr/bin/env node` command), and its source (`agent.yaml:12`, or "run copy line 12" when the rules file no longer
loads to the rules the run ran, or "built in"); what the rules do not name is the group's last line. The Programs and
Network last lines count the run's lines they decided (an exec, or a connect, datagram, bind or listen, that no rule
named: rule `unmatched`) and link to them in Logs (`rule:unmatched kind:exec`, `kind:net`); a file line no rule named,
whose kind does not say whether it read or changed, counts only in the page's total of lines decided by defaults. Limits are the
compiled ones, each clamped to the machine config's ceilings as the page compiles them: a limit a ceiling lowers reads
"Is stopped after 1 hour, this computer's limit; its rules ask for 2 hours", and one only a ceiling sets is a row of
its own whose source is "machine config". `net.http` entries ("Can send POST requests to api.anthropic.com under
/v1/messages") are Network rows with the rule key the model proxy's lines carry (`net.http[i]`), and `net.ingress`
sources are Network rows with none, since no line names one (a packet the kernel refuses only adds to run_end's
network counters), so they read No hits; the gate's scored rules are listed where each one's score alone puts an
action it matches (above the ask threshold among the refusals of its kind, from the allow threshold among the
questions, a command among the refusals since tego cannot hold one to ask, and below it as what it adds, among the
questions, a command's among the Programs), with a note saying how the scores add up; a question says tego holds the
action until you answer, and both a question and a refusal are best effort where the run lists a best-effort cell of
the rule's kind. At tier landlock every `net:` section's Network table also lists "Cannot send datagrams anywhere it
may not connect" as best effort, whatever its entries admit: tego lets the agent's own call send each datagram it does
not refuse, one that names no address included, so a racing thread can change or write in the address after the check
(supervisor R13b), and every such run may open a UDP or local datagram socket. At tiers cgroup and bpflsm the kernel's
programs decide a UDP datagram's destination and the row is not listed, though below Landlock ABI 9 a local socket's
datagram to a relative name, or to a name that leads elsewhere, stays best effort there, as does every one on a kernel
before 6.7 where no decision plane decides it (enforce-cgroup-observe §5): the page does not show that yet. A last
line that leaves the agent
wide open (any address on the network, any program, every variable of the shell) carries a quiet Open chip with a warning icon and a
"Narrow this" link to the Change rules form's section (the YAML editor for the environment). Two or more terminal
device rules (`/dev/null`, `/dev/tty`, `/dev/ptmx`, `/dev/pts/`) fold into one row, "Can change terminal devices
(4)", whose expander keeps each rule with its line and hits (`rulesview.FoldDevices`). A running run's live blocks come first,
each with Remove and its state now in the "how it is enforced" column ("In force: tego refuses it until the run ends",
"Waiting for the run to put it in force", "Refuses changes now; reads are not seen in this run", or on a `tego watch` run
"Recorded, not enforced: this run is only watched", where the sentence reads "Marked now (recorded, not refused): …"). The
group's heading and last line follow its rows: "Blocked live now" while at least one block refuses something, "Marked
live now" (marks record what matches and refuse nothing) on a watched run, "Blocking live" while every block still waits.
An ended run's live blocks refuse nothing, so no table lists them and none offers Remove: a note counts them and says
only that ("The run has ended, so its 2 live blocks refuse nothing now"; on a watched run "its 2 live marks record
nothing now"), and a collapsed row under it, "This run's live blocks" ("live marks" on a watched run), says what each
one did while the run ran, with who added it and its hits (`rulesview.InForceView.EndedLive`): "Was blocked: cannot
run curl" for a block the run put in force (its launcher confirmed the add that made it; a path block on a run that
did not see its reads says "Was blocked: cannot change /p/data (reads went through)"), "Never put in force: …" for one
the run ended before putting in force, and "Was marked (recorded, not refused): …" for a watched run's mark.
A live-blocks file the page cannot read lists nothing and says why in plain words after "The run's live blocks could
not be read:": damaged or written by a newer Tego, not trusted and why ("live-block.json is a symlink"), not readable
by this user, or the system's own words for any other error, never Go's error with its prefixes and the run's folder.
When the rules file changed after the run started, a notice says "Saved · from the
next run" with each change's sentences from the rule-change journal (a change undone since, and its undo, are left
out; an undo of an older change reads "Undid: Can never read ./confidential/"), or the time of an edit made outside
Tego. A file that loads to other rules than the run ran when neither the journal nor its time dates a change (a profile
it extends changed, or the run started from another version of the file) gets the banner too, headed "Rules file
differs · from the next run", with one line saying so and no change or time; a file that could not be compared with the run gets it only when something dates a change, and
says Not compared. The terminal twin is `cd <run cwd> && tego rules check <rules file>` (the rules file, not the ledger copy, whose compile
warns falsely about tego's records) and `tego block --list <run>`. The raw copy and its compile table sit behind a
closed toggle, every `env.set` value replaced by `(value hidden)`, and a text whose values cannot be found line by
line (one that does not parse, holds a second YAML document, is not UTF-8, or ends lines other than in LF or CR LF)
hidden whole; no page shows an environment value. Change rules
opens the form below for the run's rules file. The old `/rule?run=&seq=` link redirects to
the event page's "Act on this", the one place a rule is made from a line; the old Rule page's Confirm form (POST
`/rule`) is retired and answers 410 Gone with a link to the line's page, writing nothing.

## New contract

`/rules/new` (the Contracts page's "New contract") writes a new agent's rules file without a
terminal. The form takes the project folder (a full path or `~/...`), an agent name (empty: made from the folder's
name) and either the presets (`no-secrets`, `no-prod`, `repo-only-writes`, ADR 0068) with optional folders it may
write, hosts it may reach and its command, or a finished run of this ledger whose least-privilege proposal (`tego
learn`) becomes the draft; after a preview, what the command's agent needs past a chosen preset's promise (`api.anthropic.com:443` under *Only hosts I list*) stands beside that preset's label; when that run leaked secrets, the draft leaves the destinations out as the Least privilege tab does, and a red notice above the preview says which (the server reads them from the run's verdict; no form field sets them). The Preview form uses a guarded POST to prepare a missing registry destination before review. Read previews show the rules in plain sentences (every preset
laid in, no enforcement claim: the run's tier decides that), what `tego rules check --offline` says in that folder, the
folders Create makes and the YAML (`env.set` values hidden). The folder must exist, be yours, not be writable by every
user unless sticky, and not be or sit inside the ledger root or `~/.tego`; one that already holds `agent.yaml` is
refused, never overwritten. Create (an authenticated form POST carrying the preview's acknowledgement)
compiles again and refuses any change to the reviewed bytes, destination kind and canonical path, directory
device/inode, profile/preset/config dependency digests or compiled output. It makes the retained setup folders
beneath the checked project folder without following a link. The contract publisher checks the reviewed directory
identity against its final descriptor, writes and syncs a temporary file there, publishes `<dir>/agent.yaml`
(mode 0644) without replacing an existing name, then syncs the directory. It rechecks inherited source bytes
before publication. `internal/rulefile.Create` adds one `op: create` journal line. One folder may be made outside the project: for a `claude`
command whose writes are restricted, Claude Code's socket folder `/run/user/<uid>/cc-socks/` when it is missing,
beneath its nearest existing parent, whose path is resolved once with its links followed. When anything after the
folders fails, Create removes the ones it made, only while empty and the same way, never through a link
(`setup.Remove`). The page then shows
`cd <dir> && tego run agent.yaml`
(the contract holds the command, so the line never hands the typed text to the shell) and links to the new file on the Rules page, whose chooser lists it as "not run yet" with its rules,
compile verdict and start line until its first run. `.gitignore` is not touched: the page names the lines to add.

**From a run** (2026-11-11; until then the run page had no link to New contract). The run page's Tighten tab of an
ended run has **Make a contract from this run**, a link to `/rules/new?mode=run&from=<run>`, which previews at once
with the run's own folder. A draft from a run is saved by default where `tego rules learn <run> --save <name>` saves it:
**Your agents**, the user registry's
`~/.config/tego/agents/<name>.yaml` (the machine config's `registry:`), where `tego run <name>` typed in the run's
folder and the `tego-agent@<name>` unit find it. It goes through `registry.Save`, the one writer both use: the name
must be an agent id that does not start with `-` and be free from the run's folder (a name a registry already
resolves, or a file of that name in the folder, is refused with "give another name"), the file must not lie inside one
of the draft's own `fs.write` entries, the draft is compiled as that file, and the file is created 0600 (its folder
0700) by the shared descriptor-relative publisher: every directory component including `agents/` is opened
without following a link. The complete temporary file is synced and published without replacing a name, then
the directory is synced. An `agents/` link is refused even when it points within the registry. The entry is then resolved from the run's folder as
`tego run <name>` will, and removed if that would refuse it. The preview runs the same checks and shows a refusal in
its problems banner; a save refused at the write goes back to the preview with one line that leads "Not saved" and
names what failed and where. The saved page shows `cd <run folder> && tego run <name>`. Such an entry is in no change
record: the Contracts page lists it from its first run. **The project folder** keeps the write described above. For
the same run the saved file is byte for byte the one `tego rules learn <run> --save <name>` writes (both write `name:`
double-quoted), but for one header line: learn's proposal says under "Left out" what its own leak rule found
(`leaks: ...`), while the dashboard judges leaks by the run's verdict (the destinations it withholds above), so its
draft has no `leaks:` line (`TestLearnSaveAndTheDashboardSaveTheSameFile` in `internal/cli`). For a run that leaked
secrets the two files differ in more than that line, and can allow different addresses (read in the code; acceptance
B measured 10 differing comment lines and equal rules on AlmaLinux 9.8, 2026-11-11): learn writes its own warning
(`# WARNING: this run opened <secret> for reading, or tried to, next to a send to <destination>, ...`) and lists each
destination it withheld under `net.allow` as `# observed, not allowed: ...`, counted in `connections not proposed:
<n>`; the dashboard writes `# WARNING: secrets may have gone to <destination>: first reached next to a secret read.
...` on top, turns each withheld item into `# NOT allowed: "<entry>": first reached next to a secret read, so secrets
may have gone there` in place, and does not count it in `connections not proposed:`. **Show refused reads (slower)** adds `reason:
{reads: on}` (ADR 0077) and says what it costs: each read open about 17 µs more, the offline Claude Code workload
19 % slower. From a run it is on by default, as `--save` records them unless `--reads off`, and takes learn's own
rendering of the proposal; from presets it is off by default, as `tego rules create` writes no `reason:` block, and the
composed draft gets the same block after its command. Each `net.allow` entry of a draft from a run that is an address
says beside it: "Tego saw an address, not a name; the next run may reach another address of this site. Write the host
name." Saving is a form POST through the same checks as Create (the session token, the dashboard's own Origin or
Referer, no cross-site `Sec-Fetch-Site`).

## Change rules

`/rules/change?c=<ref>` changes one rules file a run of this ledger ran, one entry at a time. It has one panel per
list a change may touch (Can change, Asks you before it changes, Asks you before it reads, Can never read, Can never
change, Programs it may run, Can connect to, Asks you before it connects to), each listing the entries the file
spells with Remove (and Never allow on an ask entry) and an Add field with a hint for that kind; an entry the file
spells more than once is listed each time, and Remove or Never allow on it takes every copy, since a copy left would
keep the rule (the preview's "Why" says so). Limits, command, inherited profiles and tier are editable in Full;
new environment assignment values require a terminal.
Every button is a GET to the preview, which writes nothing: the change as Before and After sentences with one
Narrows, Widens or Mixed chip in the panel head (a Mixed change marks each row too). The chip is the compiled
comparison's (ADR 0156, 2026-11-21): both texts are compiled and each family of the two tables is ordered, so a pure
refusal narrows, an entry a profile the contract extends also grants says "No change: the compiled contract allows the
same", a family the comparison cannot order makes the change Mixed (never Narrows), and a change that cannot be
compared is not previewed; "Why it narrows" names the families that decided it. "Applies from the next run of
this rules file" is followed, while an "Apply now" box is ticked, by
"in force on r-… within about a second" (once none is ticked, "Runs going on now keep the rules they started with"),
for a narrowing a **Running now** box with "Apply now to r-…" per running run of that file (ticked; each change
on that run as **Applies now** with the live block it places, **Recorded only (watched run)** on a `tego watch` run,
or **Next run** with why it has none: an ask added, a read ask removed, a pattern, a command entry, a widening, or
another entry that still allows it; under such a run "This run keeps the rules it started with. The change is in force
the next time the agent starts: stop this run, then start the agent again" and the line that starts it, `tego run
<contract> -- <command>` from the run's record; the block is journaled as begun before it is placed, and none is placed
when the journal cannot show it), the YAML diff and the list changes in keys ("Why it narrows: …") behind a
toggle, and the terminal twin (the edit by hand, `tego rules check`, and `tego block` for each live block). A widening (or a mixed change) shows newly granted rule-family entries and any family whose direction Tego
cannot classify, followed by a required checkbox and a quiet Save button. Other families may still refuse a
new family grant. The checkbox posts that preview's acknowledgement: its unique review identity followed by an HMAC binding
that identity with the reviewed bytes, destination, directory identity, dependency sources and compiled result,
under a key that never leaves the dashboard. Narrowings carry the same binding in a hidden field. A Save that carries another
preview's value, or none, writes nothing and shows the change again. Saving (POST `/rules/change`) goes through the rule service and
opens the Saved page with the result in one line (the flash line): the sentences, each live block with its state on
its run now, the `.bak`, the diff, and Undo (POST `/rules/revert`, acknowledged when undoing widens). The Several changes at once form (C125) is the same preview and Save for up to 16 edits (`rules.MaxEdits`): the preview address repeats `op`, `key` and `v` once for each edit (`batch=1` skips a row with no entry), the Save form carries every edit, the service checks them as one text and writes all or none, and the journal holds one entry, so one Undo takes them all back. The two raw editors (Change rules, and Full in New contract) show line numbers beside the text, the cursor's line and a "Line L of N, column C" status, and a diagnostic's "line N" link puts the cursor on that line (C126, `static/lines.js`; a phone shows the status and no gutter). The Saved
page's headline is "Saved · live now on r-… and from the next run" once every block "Also apply now" placed is in
force, "Saved · from the next run; putting it in force on r-… now" until then, and "Saved · applies from the next
run" when nothing was applied now; its **Running now** list says, per block, **Live now** on r-… since line #N (the
launcher's confirming line), **Putting it in force**, **Recorded only** (a watched run) or **Ended** (the run ended),
and **Next run** with why for each change no block applies now or whose run's box was not ticked. The page is its
live region, so it turns from Putting it in force to Live now with no reload (about a second, measured 1.1 s). A
confirm made on other text than the preview showed writes nothing and goes back to the preview planned again on the
file as it is now (its address carries no base, so its form carries the file's base and acknowledgement now and
the next Save lands); a second POST of a change already written (a double click) says the file already has it.
Save and Undo post as plain forms even with JavaScript (`data-page`), so a refused one always answers with that page
read again; a stale Undo goes back to its page, whose history offers Undo only on the change the file holds now. The page's History lists the journal's changes and undos
of the file, newest first (an undo as what it undid: "Undid: Can never read ./confidential/"), with Undo on the one the
file still holds, each entry with the live blocks it placed ("live on r-…") or lifted ("lifted on r-…"). "Advanced: edit YAML" opens a textarea with the
whole text: Check compiles it as the next run would and lists the compile's problems with links to their lines,
or shows the diff with the confirmation box and Save; Save writes it as a free edit, which cannot be read as
narrowing or widening, is always confirmed like a widening (the box is bound to the text that was checked, so a text
changed after its Check is checked again before it can be saved). Its Check (and the saved page, and the one-entry preview)
names every compiled family the text moves, each with the direction the family comparison ordered it in ("What the
compiled contract changes"; a family it cannot order says so and is never called narrowing), and the journal's summary of
a free edit is those families ("free edit: filesystem narrowed, destinations widened"). A rules file edited outside Tego
is compared the same way with the rules the run ran (`CompareSource`), which the Rules page's banner shows. Its Check also lists the edit's list changes (each
entry of an editable list the old text has and the new one lacks, or the other way) in the same "Also apply now" box,
so an edit that removes a program or a write folder can apply now to a running run. In a rules file that sets environment values (`env.set`) the
editor shows each value as `(value hidden)`, and saving puts each back from the file; a free edit may remove a
variable, but one that adds a variable or changes a value is refused, so no page shows or carries a value (set it in a
terminal); every diff hides them. An `env.set` written with anchors, aliases, merge keys, a flow mapping or nested
values, and a file that may hold one but is not one YAML document (it does not parse, or holds a second document
after `---`, which no contract may), get no editor. The
pages work without JavaScript; with it, the lists, the history and the Saved page update in place like every page's
live regions (the YAML editor's text sits outside them), and nothing reloads. A file the guards refuse (below) is listed with the
reason and no form.

## How a rule change is written

The event page's "Act on this" and `tego rule` write a contract through one path, `internal/rulefile`. The contract
must be a regular file of yours with one link, writable by no other user (by its group only when that group is your
private group, as a 0664 file under umask 0002 is), at most 1 MiB, in a folder that is yours or root's and not
writable by every user unless sticky, and outside the ledger root and `~/.tego`; otherwise the page says which check
failed and how to fix it. The folder is pinned once, so a folder swapped for a symlink mid-write changes nothing; the
write takes a per-contract lock, lands only when the file still holds the text the change was made from ("changed
since it was read" otherwise), keeps `<file>.bak` and replaces the file in one rename. Each change is a line in
`<ledger_root>/.rule-changes/journal.jsonl` (format in `internal/rulefile/doc.go`), with the old and new text kept
under `blobs/`, so a change can be reverted while the file still holds it and undone step by step back through every
change the journal holds. Retention prunes the journal with the runs (`tego gc`, and a `tego run` start once per
`gc_interval`), and a line goes only when nothing on these pages can still need it: a line older than `retention`
stays while a run still in the ledger root started before it (that run's "Changed since this run started" and Apply
now list it) or names such a run (a live block it placed, which an Undo of another change must not lift while this
one stands), while a revert left undid it, and, while the rules file is there, while it is among the newest 20
changes still standing and everything after them. The old texts no line names go with it, so History and Undo reach
back at least that far. Moving the ledger root moves the journal with it. The Change rules page shows the history and
offers Undo, and the event page offers Undo right after a change it saved (below); no command lists the history yet. A `tego rule` change is journaled as the page journals the same change (`via: cli`, with its sentences and
direction), so the history says it in words and undoing it goes the other way: undoing a block widens, and is
acknowledged.

Behind the pages, the rule service (`internal/control/rules`) compiles every change as tego rules checks a run
of that contract: the machine's profiles (`internal/profilesrc`, the engine's own source, so a contract that
`extends:` a profile can be changed), the tier the run ran at (an `auto` contract is not judged at this machine's
highest tier), the run's command grant, your home, chain anchor and runtime folders, and the folders of the programs
the run started when the dashboard's own PATH lacks them (a dashboard started as a service). It compiles offline,
with no DNS: a host name is resolved when the next run starts. The host names a change adds to `net.allow` or
`net.ask` (the first eight) are then looked up once, all at once and for at most 2 seconds, and the preview (Check
the change, the YAML editor's Check, the event page's step 3) names each that does not resolve here with why ("no
such host", or no answer in time): a warning, never a refusal, since the next run, unless started with `--offline`,
does not start while a host of its contract fails to resolve. Saving does not look them up again. `tego rule`
compiles through the same code (`internal/nextrun`) in the same run context, so the two give one verdict on one
change, and prints the same host warning on stderr. A free edit that pins another tier than the run's is
compiled at that tier, as tego would. A contract whose folder symlink now points elsewhere than the runs here ran is
not written. The service can change only a contract a run under this ledger root
ran, or one "New contract" created here (its journal line names it) that no run ran yet (`Contracts`, each named by an opaque ref, never a path from the browser), refuses a confirm whose base is not
the text the preview showed, asks for an acknowledgement of anything but a narrowing (a free edit of the whole text
always), journals each write `via: dashboard`, and for a narrowing can place the matching live block on running runs
of the same contract ("Also apply now": a removed program or destination; a write folder or a write ask removed
(Never allow on an `fs.ask` entry) or a never-change entry added, as a **write** block that refuses changes there and leaves reads alone; a folder made never-readable, as
a **read** block, on a run that holds its reads). A removal another entry still covers (a folder above or inside it, a
program by its other spelling, a host by another port) offers none, since the new rules still allow it. A removed
program's block refuses what the run's contract grants under that entry: the file at the path the entry led to when
the run started, by any name that reaches it there. On a machine whose core utilities are one multi-call file under
many hard links (Ubuntu 25.10 and 26.04), removing `/bin/ls` leaves `/bin/sleep` running where the new rules keep it
(ADR 0124, amended 2026-11-11). Where a kept entry leads to the same file at the same path (busybox's links all lead
to `/bin/busybox`), the block refuses it there for both, as before. On a run started by an older tego it is the
whole-file block Block now places. A run started by an older tego (its launcher has no read or write blocks) is offered what it can enforce: a
never-readable folder as a block of the whole path (reads and changes), and no write block ("Next run: this run was
started by an older tego…"); a tier 3 run, whose kernel decides file changes itself, is offered no write block either.
Each offered block is said in words ("Changes to ./tmp (reads still go through)", "Reads of ./data/secret.txt",
"Running uname"), its key (`write:/…/tmp`) in the tooltip. The Change rules pages and the event page (below) call it.

### Changed since this run started

On a running run whose rules file changed after it started, the Rules page's notice becomes the **Changed since
this run started** panel. Each change says what it is on that run now: **Live now since line #N** (every live block it
placed is in force: the launcher's confirming line), **Requested** (placed, not yet confirmed: it turns within about a
second, with no reload), **Recorded only (watched run)**, or **Next run** with why. A change saved without "Also apply
now" that still maps to live blocks offers **Apply now** (POST `/rules/change` with `do=applynow`, the change's
journal id and the run): the rule service reads the change's text before and after from the journal, maps it against
the file as it stands now (a change a later one took back, a removal or an addition, offers nothing), places only
blocks not yet on the run and journals them after the change. A change whose live block was removed from the run since
says so ("Its live block was removed from this run; the next run gets the change"). For a file whose rules differ
from the run's with nothing to date the change, the panel is headed **Rules file differs from this run** and lists no
change: one line says so, not live on this run. The
panel ends with **Stop this run** and the line that starts the next run with these rules
(`tego run <rules file> -- <the run's command>`, each word quoted exactly as the run had it); add the options the run
was started with, such as `--tier` or `--record`, which the line does not repeat. Restarting from the dashboard is not
offered.

### Undo and live blocks

Undoing a change gives the rules file its old text, which reaches only the file's next run. When the change placed
live blocks ("Also apply now", or Apply now later) that still hold on runs of the same file that are still running,
every Undo form (the line page's Saved panel, the Saved page, each History row) carries a ticked box, **Also lift the
live block it placed** with the block and its run. With the box the rule service lifts exactly those blocks
(`runact.Block` with add false, as the run page's Remove does) and journals each on the undo with `"lift": true`; a
block another change still standing also placed on that run (however old that change: retention keeps every journal
line that names a run still in the ledger root), a block removed by hand, and a block on a run that ended are never
lifted. Lifting lets the running run do more at once, so it wants the Undo's acknowledgement whatever the
Undo's direction. The answer says what happened ("The live block it placed is being lifted: within about a second its
run may do that again", or which block stays and why). Measured twice on an isolated run (a stand-in agent running `cat`
once a second): the launcher's "block on cat removed" line came 0.20 s and 0.46 s after the Undo's journal line, and
the agent's next `cat` ran 0.29 s and about 0.5 s after it.

### Rule changes in Logs and the timeline

The rule-change journal lives beside the ledgers, so its entries are not ledger lines. Logs and a run's timeline show
each one as a row of its own at its time (the rule service's `Feed`, read again only when the journal or the set of
runs changes): the change in plain words ("May run cat → Cannot run cat", "Undid: Cannot run cat", "Set up the rules
file"), its direction, where it was made and the line it was made from, the live blocks it placed or lifted, "undone
later" when it was, and **History**, the rules file's Change rules page with Undo. Logs shows them while the search
narrows only by run, agent and time (any term about ledger lines, such as a kind, verdict, text, rule, path or host,
leaves them out). A run's timeline shows the changes of its rules file made while it ran (it kept the rules it
started with; the next run of the file gets them), the ones made from its lines, and the ones that placed or lifted a
block on it, on its unfiltered pages; a live timeline's update brings a new one with the new rows. The line page does
not list them yet.

## Making a rule from a line (the event page)

A line's "Act on this" panel (`/runs/<run>/lines/<seq>`) leads with the one action that fits. On a line an ask entry
decided (asked, then denied, approved or timed out) it opens on that entry's own scope with **Never allow** first:
the ask entry becomes a refusal with the same spelling, so the next run refuses without asking. Otherwise the first
possible narrowing leads. A read a `deny_read` entry or the built-in secret list refused leads with **Already refused
by: <the rule in words>** ("Nothing needs changing: the next run refuses this too"), and the options, which can only
widen, fold under **Change this rule** (marked Widens; it opens when one is picked). An ask line says a question is
not an action and names the line its answer decided; a line whose contract file is gone says "the contract file has
moved since this run". Actions that cannot be made at the scope fold under "Why not the others", and paths read as
the contract writes them (`./…` under the run's folder, `~/…` under your home, and either folder itself `./` or `~/`);
only a whole path is shortened, never a folder of the same name inside another path (`/srv/<the run's folder>/x` stays
as it is). Picking an action previews the
change as sentences, before and after ("Asks you before it reads ~/.config/telemetry/" → "Can never read
~/.config/telemetry/"), marked **Narrows**, **Widens** or **Mixed**, with "Applies from the next run"; a widening
also gets a quiet notice with a required checkbox naming what the next run will be able to do (the service refuses the
write without that preview's acknowledgement), and its confirm is never the primary button. Allow at a folder level
is not offered for a write outside the run's folder and your home ("the folder of /dev/null is a system folder: name
the file"); Block and Ask keep the folder. A
narrowing offers **Also apply now**, one checkbox per live run of the same contract, ticked where the live block can
enforce it (a read block only on a run that holds its reads) and disabled with the reason where not; on a watched run
the row says "recorded only (watched run)". The confirm
carries the base hash of the text the preview showed, so a contract changed since is refused, not overwritten. After
the write the panel shows in place what changed: the sentences, each live block placed with its state on its run
("Putting it in force on this run…" until the launcher's confirming line, then "Live now on this run, in force since
line #N", over the panel's live update, with no reload; "Recorded only" on a watched run), the change to the file (in a
toggle), the `.bak`, and **Undo this change**, which puts the old text back while the file still holds the change
(undoing a narrowing lets the next run do more again, so a required checkbox above the button names what comes back);
while a live block placed with it still holds on a running run, a second box, ticked, also lifts that block (see
"Undo and live blocks" below); unticked, the block stays until the run ends or is removed on the run page. Block now, for a live run, names the scope picked: the folder, the
whole host, or (for a command) the whole program, which the panel says; on a watched run it reads **Mark … (recorded
only)**. When a live block of the run already covers the line (one an Undo kept, or one placed on the run page), the
panel says "Blocked live on this run since line #N" with a link to remove it on the run page, instead of offering
Block now again. The notice after Confirm says what was saved and that the panel shows its state on the run; it never
says the block is being put in force, since it stays on screen after the panel says Live now. While "Also apply now"
is ticked for this run, step 3 adds "and on this run within about a second". The panel sticks beside the facts under
the topbar on a wide screen and scrolls on its own when a preview is taller than the window; picking an action (or a
scope chip once one is picked, or the Deny notice's link below) opens the page at step 3, **Check the change**, so the
preview and its Confirm are in view without scrolling inside the panel. A preview opened again after its change was
saved (a reload, a second tab) says so calmly: "reads of files under ~/.config/telemetry/ are already never allowed:
this file refuses them (fs.deny_read[…])", and offers no Confirm. It says so only when that deny_read is what decides the read:
under a nearer write or ask_read entry the read is still open, and the preview offers the narrowing. Without JavaScript, a
Confirm that saved nothing (the contract changed meanwhile) opens the page at its "Not saved: ..." line, with the
preview again in the panel.

After a **Deny**, the answer's line (its toast, or the flash line) links **Make it permanent: Never allow** to the line that answer decided: the
refusal under the ask's rule that names what it asked about. A connection is matched by its address and protocol (the
ask names `192.0.2.1:443`, or `udp://…`, where its refusal reads `host (192.0.2.1:443)`), so with several asks pending
under one `net.ask` entry each opens its own refusal, never another's; any other ask takes the refusal naming its
target, else the first that names no other ask's. The refusal can follow the answer by a moment, and until it is in
the ledger the link shows the ask's line with "look again in a moment". `TestDemoNeverAllow` (`internal/control/web/e2e`)
drives this over a real run.

## Locked and Adjustable, lift and time limits (ADR 0125)

Every run's Rules page names its mode under the chooser: **Mode: Locked** or
**Mode: Adjustable (live both ways)**, read from run_start's `live_mode`, with ADR 0125's comparison of the two modes
behind "What this means" (one shared template, `livemodes`, that New contract shows too). An Adjustable run's
page adds the panel **Live contract inside the fence** (`#live-fence`): each fence entry in a sentence ("Read
~/billing-exports", "Connect to api.stripe.com:443", "Run /usr/bin/psql", the last marked best effort), whether it is
new access or one of the contract's refusals, and its state as the launcher applied it (`ledgerview.FenceRows`, folded
from `live-rule-lifted`, `live-rule-restored`, `live-lift-expired` and `live-lift-refused`): Refused, "Lifted until Fri
17:00" or "Lifted for this run" (a grant, new access: "Granted until Fri 17:00", "Granted for this run"). A lift that was given a note shows it on its row ("Note: ..."), in the words `tego lift` prints (`record.LiveNoteShown`); the lift's confirm page has one optional text input for it. A lift asked but not yet applied still shows Refused; a lift whose limit has passed by
the page's clock shows Refused before the expiry line arrives. Refused rows have **Lift…** (a contract refusal) or
**Grant…** (new access) with a time limit; lifted rows have **Restore**. The run page shows an "Adjustable" chip beside
the run's state; a Locked run's page has none. A line under a fence entry (`live.fence[<kind>:<value>]`) reads "Rule in
the fence: <value>" in the Overview's Newest High and Medium and in Logs' Rule column; the key stays in the title.

Lift… and Grant… open the preview (`GET /runs/<run>/lift?kind=&value=&for=&span=&until=&tz=`, which writes nothing): "This
run will be able to read ~/x now, until Fri 31 Oct 17:00 (in 3 days)", always "Enforced by Tego's live layer, not the
kernel. A time limit stops new access; anything already read or copied, files still open and live connections stay.",
for a program "A copy of this program under another name is not covered.", the required checkbox "I understand this
run gets this access now" and the terminal twin (`tego lift|grant <run> <kind> <value> --for 3d`); a live-blocks file it
cannot read is said in the same plain words as on the run page and the Rules page, with no confirm. The confirm (`POST
/runs/<run>/lift`) carries the absolute limit and the rule service's acknowledgement (`rules.Service.LiveAck`), which
binds the run, the entry, the limit, the permanent choice and the overlay's serial at preview time: a confirm after any
other live change of the run, or with another limit, writes nothing ("this run's live rules changed since the preview.
Preview again."); so does one without the checkbox, or whose limit has passed. It then asks `runact.Lift(...,
"dashboard")`, which refuses a caller inside a run, a Locked run and an entry outside the fence, and writes a lift
MAC'ed under the run's key; the flash says it was asked, and the panel shows it once the launcher recorded it.
`POST /runs/<run>/restore` asks `runact.Restore` and needs no acknowledgement, since it narrows. Both POSTs pass the
session, CSRF, Host and governed-peer checks every change passes.

Every live change takes a time limit: 2 minutes, 4 minutes, 15 minutes, 30 minutes, 1 hour, 1 day, 3 days, 1 week,
for the rest of this run (Block now's default), for… (any duration typed in the `span` field, in `--for`'s syntax:
`45m`, `4m`, `72h`, `3d`, `1d12h`, `7w`, read by the parser `--for` uses, `liveblock.ParseDuration`; a bad one says
so in plain words and names the syntax), until… (a date and time, read in the dashboard's zone unless the request
names `tz`), or "permanently (then save it in Change rules)". The server turns a fixed or typed span into an end at
the moment the request that names it arrives, to the nanosecond (`untilOf`, `forSpans`): Block now's POST, or the lift
preview's GET, whose end the confirm then carries under the acknowledgement, so a lift's span runs from the Lift… or
Grant… click and a 2-minute preview confirmed more than a minute later is refused (its limit is then under the 1
minute floor). until… takes a whole minute ("until 20:33" picked at 20:31:51 lasts 69 s); the short spans are for
limits it cannot say exactly. The bounds stay 1 minute to 400 days. Permanently makes the change with no end and then opens Change rules for the run's rules file, with
the line saying what to change there (its own preview and confirm); the dashboard does not write `agent.yaml` by
itself, so the change reaches the next run only once that edit is saved. Block now calls `runact.BlockUntil`; a run
started by a tego without time limits refuses a limit in plain words. The Rules page and the run page judge each
block's limit on the page's clock: a timed block says "until Fri 17:00"; one past its limit (the overlay keeps it a
day) says "ended at" and offers no Remove, and is not called in force; one unblocked for a while says "unblocked until
X, then refused again". The line page offers Block now again for either. The lift preview shows its terminal command
only for an entry it could confirm, and a lift's acknowledgement check and write run under one lock with restores.

New contract asks "How its rules change while it runs": Locked (checked) or Adjustable (live both ways), with the
comparison, and for Adjustable three lists (paths it may be allowed to read, destinations, programs). The rule service
writes a `live:` section only for Adjustable, writes `tier: cgroup` in place of a `tier: landlock` line, and compiles
the draft again, so compile's own fence diagnostics show as they do for every draft. A Locked run's run page and Rules
page are byte-identical to before except for Block now's time select and the Mode line
(`TestLockedPagesUnchanged`, goldens captured on the base).

## MCP tools

`/mcp` (nav "MCP tools" with `--preview` only) is the MCP tools page of ADR 0126 §6, served by `internal/control/mcpact`: per declared server, the tools seen, a live Allow / Ask / Deny switch per tool and its
calls, refusals and asks from a complete streamed run. A reader or payload error shows could not read with its
reason instead of the counted prefix. On a Locked run a switch looser than the contract's decision is refused, on the flash and on the
preview (which then has no Confirm and no "until you confirm" line, only a link back to MCP tools): "Not done: this run
is Locked: loosening applies from its next run." (ADR 0126, "Amendment 2026-11-11: Locked runs"). The preview puts
"Not done: " before every refusal it shows, as the flash does. A run whose `run_start` cannot be read yet (its first
seconds) is refused such a switch, a lift, a restore, a route and a timed or read or write block with "Not done: this
run is still starting, so what it takes while it runs is not known yet: try again in a few seconds.", never the Locked
words, as `tego mcp`, `tego lift` and `tego route` say `[starting]` (acceptance 2B, 2026-11-11). A run whose first
record line is there and is not a run_start this tego reads (a damaged line, another kind of line, or one a newer tego
wrote) gets "Not done: this run's first record line is not one this tego can read, so what it takes while it runs is
not known.", with no "try again", as the commands say `[start-unreadable]`.

## Model routes

`/routes` (nav "Model routes" with `--preview` only, beside MCP tools) is the model routes page of
[ADR 0127](adr/0127-model-routes.md), served by `internal/control/routeact`; the page never opens the route overlay
itself. A run picker lists the runs whose contract declares a route, running ones first.

- One card per `models[]` endpoint: its `host:port` and provider, a "Rerouted" badge when it is off `direct`, the line
  "Next request goes to `<backend>` by route `<name>`", with who set it and when.
- One row per route, `direct` first: its name, backend, "TLS, certificate checked" or "Plaintext, this machine", the
  requests that went by it (from the run's `ssl_request` lines), and **Send here** (a route not in use) or **Back to
  direct** (primary, when the endpoint is rerouted); "In use" marks the current one. An endpoint without routes says
  how to declare them. "Changes in this run" lists the `model-route-changed` lines.
- **Send here** goes to `/routes/preview`, which says where the prompts will go and that the request's headers go with
  them, so a key the agent holds itself goes there too, and a Confirm form carrying the preview's acknowledgement (an HMAC over the run, the
  endpoint, the route and the overlay file's sha256): a confirm against an overlay that changed since, or for another
  route, writes nothing. **Back to direct** applies at once. Whether a change widens is decided again under the
  overlay's lock, so a **Send here** to the route already in use (no acknowledgement) that someone else's revert turns
  into a widening is refused rather than written.
- Every POST (`/routes/set`) is refused from a socket made inside a run (ADR 0123), and the service refuses every
  change from a process inside a run; an undeclared route or endpoint is never written. On a Locked run **Send here**
  is refused, on the flash and on the preview (which then has no Confirm and no "until you confirm" line, only a link
  back to Model routes): "Not done: this run is Locked: loosening applies from its next run."; **Back to direct** still
  applies (ADR 0127, "Amendment 2026-11-11: Locked runs"). No
  live regions: a reload shows new counts. `TestModelRoutesInChrome` holds it at 1920x1080 and 390x844, light and dark.

## Severity and Detections (2026-11-01)

Severity says what to look at first. It sorts and colours; the contract decides what is refused, and nothing here changes
that. It is read from where an action happened and what it was, never from how often: a refused connect repeated 50 times
is High, as one is (`ledgerview/severity.go`, `TestRepeatsKeepSeverity`).

- **High**: a secret, a send next to a secret read, a connection the contract does not allow, a program that reaches out
  (ssh, curl and the like), a shell startup file or git hook, and a change to a file that runs code later, for any agent,
  its own or another's: settings that name hooks and MCP servers (`~/.claude/settings.json`, `.claude/settings.local.json`,
  `.mcp.json`, `~/.claude.json`, `~/.codex/config.toml`), an agent's hooks and commands folders, an editor's tasks, git's
  config (`laterFiles`, the reasons the engine's built-in `deny_write` set holds them; `TestLaterFilesHoldTheEngineSet`
  fails when a file name of that set, `agent.BuiltInDenyWriteNames`, would not read High, or when `laterFiles` names no
  file inside a folder of the set; a refused write to such a folder itself, or to a file in it `laterFiles` does not
  name, reads Medium, since the folder also holds what an agent writes for itself on every run). A rename or a
  link onto one is a change to it, and its row says where it was going. Reading one runs nothing and stays as any other
  read.
- **Medium**: another program, a change outside the project, any other change in an agent's folder (its session logs, its
  own program), anything in another agent's folder.
- **Low**: the run's own agent reading its own files or writing its own caches, and system network information. The
  run's agent comes from its command (`CommandAgent`), so Codex touching `~/.claude` is not "own".
- **Routine**: the background rule above. Counted, never listed.

A leak is not a refusal, so no refusal group holds it: Detections reads each run's verdict and leads with it. An all-watched
ledger whose secrets left shows the banner and "No refused actions", never a check mark and "Nothing refused". A watched
run that read a secret takes the check mark away too, and the Overview's headline reads "1 run read secrets", not "All
quiet". The header's "Routine N" counts refused lines, so with only those the page reads "Only routine actions refused".

Logs' **By severity** reads each run's Signal with the Sensitive every page uses (`Snapshot.Group`), so it agrees with
Detections and shares the run's cache slot. A watched run's lines are their own Observed group: nothing allowed them, and
its key reads and sends are not "allowed". Asked holds the asks and the actions held for them, Answered a person's
answers, a no as much as a yes, Allowed what a rule allowed, and Recorded the lines nothing decided: notes, a run's start
and end, limits. The groups that stay in Logs narrow the current view, and each one's link shows the lines its row counts. Routine has no link: no search holds routine lines alone, and `verdict:refused`, the nearest, lists the High lines too.

**A person's rules** live in `~/.config/tego/severity.json`, mode 0600, and are not part of the record: a change leaves no
ledger line, and the page says so. A rule matches a group's subject or rule by substring, so `/prod-config/` is the form
that matches (`~/work` is read as `/work`). A rule can raise a secret touch or a send next to one, never lower it, and
routine stays routine. A file that cannot be read never stops the dashboard: anything but a regular file of at most 64 KiB
(about a thousand rules) counts as one too, since every page reads the rules. The built-in rules apply, Severity and
Detections say so, a change is refused rather than written over the file, and a file fixed by hand counts from the next
visit to Severity. A rule that would take the file past the limit is not saved. The rules reach the read model with each run's `Sensitive`; ledgerview holds none.

Both pages are live regions (`pageRegions`), with rows keyed by the group's first line. `review.js` marks reviewed rows again
after a filter click and after a live update (`TestDetectionsInChrome`).

**Ask before reading** on New contract pins the whole contract to tier landlock, the one tier where a read can wait for a
person, so the form and the preview say it runs at Basic. With Adjustable, which needs a stronger tier, these reads are
refused without asking, and the preview says that instead.

**Contract and refused** (2026-11-11, the shared vocabulary of the command line and the dashboard, decided
2026-11-10). The dashboard says contract for the rules file and refused for what a rule stopped, as every command, the record, the run summary and the receipt do; it said policy and blocked
before. The nav item, the page titles, New contract and the Glossary use the new words; Go identifiers, JSON fields and
addresses do not change. "Block" stays where it names the live control (Block now, `tego block`, a live block, Blocked
live), which is another thing than a rule's verdict.

**Protection levels and tiers.** The dashboard says Basic, Plus and Max. The terminal, the docs and contract files
say tier: Basic is tier 1 (`tier: landlock`, no admin rights), Plus is tier 2 (`cgroup`, root) and Max is tier 3
(`bpflsm`, root and BPF LSM at boot). A run that only watched is "Watched only". The Glossary's "Protection level"
entry and the Machine page's levels give both names; a line page's Enforcement row reads "Basic (tier 1): Landlock and a
system-call supervisor, no root". Words that stay as the terminal writes them: the `tier:` key in a policy file, the
`--tier` flag, and a policy's raw capability ids under "Capability flags".

## Charts (2026-10-27)

Small server-side SVG charts tell the story at a glance; every one is laid out in Go (`internal/control/web/charts.go`,
`ovcharts.go`, `cmpcharts.go`) and written by the `chart` template (`templates/charts.tmpl`, so html/template
escapes every word), with no script and no library, coloured by the chart tokens (`static/tokens.css`, `--ch-*`) with labels distinguishing
refused attempts from actions that went through, and hidden from the accessibility tree with its words beside it
as screen-reader text (the page's svg rule). Each has a fixed height, so a live update never shifts the page. Words
(legends, end values, counts) wear the text tokens, never a series colour.

The chart tokens are one palette per theme. The earlier manual OKLab measurements
predated this palette and do not establish its current colour distinction. Labels
and the refused shapes retain the outcome without relying on hue alone.

- **Overview.** The Refused tile carries a sparkline of refusals in each of the newest 12 runs (oldest left): the
  line has no axis, so the oldest value sits at its left end, the newest, stronger, at its right with a dot on the
  last point, and a caption names what it counts. With fewer than two runs there is no line, only "Trend after 2
  runs" (a flat line through one point read as a trend). Under the tiles, **Detections** is a table of refused actions
  by severity and channel, each number a link to that part of the Detections page, and beside it **Secrets** is
  protected against exposed, each named explicitly, with a sparkline of secrets protected per run ("Protected, last N runs",
  hidden under two runs). Where that panel is narrow (a third of the row, 641 to about 1100 px wide) the caption's
  words wrap and the line goes under them, so it never runs past the panel (at 768 px it made the page scroll
  sideways). Both sit in the tiles' live region.
- **Compare.** Three bar pairs under the stats, one scale per pair: secrets reached and sends off the list (red),
  attempts stopped (the refusal mark and the stats' number). Each row is the run's letter and agent on one line (cut with an
  ellipsis, the full name on hover), then its bar and count, so a long agent name never wraps beside the bar.

The run page has no chart: its "What happened when" strip and the Overview's "Refusals by kind" bar were removed on
purpose when severity came in (2026-11-01), and the table above took the bar's place. Golden SVGs:
`internal/control/web/testdata/charts/`.

## Not built yet

- Remote access: the dashboard answers on this computer only, for the person at it.


Correctness amendment (2026-11-03): automatic watched/enforced comparison requires
the same recorded workspace, nonempty agent identity, harness and program; without
that reference a watched warning stays. Separate demo workspace copies are not an
automatic trusted pair. Leak highlights use particular successful read/send pairs
within both proximity bounds, including later contacts to an already known host;
refused operations cannot supply a successful pair. Region refresh tracks received
and rendered revisions separately and retries a failed fetch from 1 s up to 30 s,
even without new state, resetting after success and stopping after sign-out.

The receipt records a hard link's newly created `path2` and a symbolic link's `path`.
Its unanswered ask total includes requests after the 1,000-item presentation cap.
The receipt separately bounds pending identities at 32,768 / 8 MiB estimated
(128 bytes per entry plus ID bytes); answers release capacity. A ledger prefix
exceeding either limit produces an explicit error on the Receipt tab and no
partial receipt. Counts in successfully computed receipts remain exact beyond the
presentation cap; no disk-backed identity index is provided.
New refusal pairs append without interleaving; older displaced mirrors remain an
ambiguous historical counting limit (record v1 writer clarification).

### Phone component contract

At 600 CSS px and below, page packages share `static/phone.css`. A list uses `.phone-list` and a single
native `.phone-row` link, at least 80 px high. `.phone-who` is one line with an ellipsis and the full name in
its accessible link text; its destination exposes the full value. One `.b` state chip and `.phone-when`
make the second line. Time elements keep `datetime`; relative start ages use `data-started` and `data-ck`,
which live.js updates with `Intl.RelativeTimeFormat`. Do not put a second link or button inside the row.

Runs is the first converted page. Its heading asks “What is running?”; the result count and time frame are
visible beside Filter and announced politely after a view change. Its original table, headers, keyed rows, and both live tbody regions remain.
At phone width `.phone-run-cell` provides the one row target; the legacy cells stay on larger screens.
Tables must become rows rather than horizontal scrollers. Hide supplementary summary facts with
`.desktop-facts` or `.desktop-only` only when their real detail destination retains them.

Page heads retain existing controls inside native `.head-more` disclosures labelled Actions. Run metadata
is inside `.head-details`, labelled Run details. These are compact on phones and expose the original layout
on larger Chrome screens. Browsers without `::details-content` keep usable native disclosures. Form fields,
request identity and CSRF values are unchanged. Phone helper sentences are hidden; Runs retains its running
and started-today line. Closed native detail content is excluded by actual visibility, not box size alone. The shared request target
grid uses a zero-minimum column so Details retains a long final filename without enlarging the viewport.

A `.phone-filter-control` link uses `data-filter-open` and a native GET fallback. `dialog.filter-sheet`
is the enhancement, labelled by its heading, opened with showModal, closed by Escape or a
`data-filter-close` button, and returns focus to the opener. Keep the form's existing server field names,
chosen values and URL parameters. Runs uses `q`, `state`, `period` and `before`; `filters=1` is the native
filter page. More options links to compare and log search/export. Do not replace real decision POST forms
with filter or preview GET requests.

The shell owns navigation, header, theme placement, waiting band, page padding, tokens, and system modes.
Page packages own their interiors and remove their old phone label/value and multi-fact summary rules as
they convert. The merged Overview, Run/Event, Logs, Detections/Investigate, Approvals, Compare, Contracts,
machine, glossary, recovery and preview interiors use the same row, filter and disclosure primitives.
The later agent/setup guide and contract builder packages retain their own scope. Scripted and script-free
browser proofs cover reachability, long data, target sizes, live merges and exact values.

## Logs and decisions on a phone

Logs shows what happened, one outcome and when. Tap a row for its full target,
rule and process context. Filter contains search, time ranges, outcomes, grouping,
facets and exports. A grouped row opens Group details with its exact value,
counts and first/last times. Filter also works as a normal page without scripts.

Approvals starts with the oldest waiting request and lists the queue in order.
Details shows the exact target, who asked, why the rule asks, its age and what
happens when it expires. Allow once lets that request through; Deny refuses it.
Both buttons stay above phone navigation when a long detail scrolls. More choices
contains answers for the rest of the run and a stand-in file where supported.
An answered request shows the recorded outcome and person in place of its buttons.

Compare stacks Run A and Run B under each action. Change the runs contains the
selectors, and Run details and charts retains the supporting context. Investigate shows the full noticed target first; Detection details retains its
rule, channel and precise times; the other questions retain the process chain
and related detections. Both themes use the
same words and state shapes, including explicit severity words.


Contracts opens a list of contract files and the agents that used them. Open a contract
for the rules used by its selected run. Each rule can open its full sentence, exact target,
source, enforcement limits and matching events. Contract details keeps the full file
location and other runs; the exact file and compiled rules stay in native disclosures.
On a phone the list shows an agent, one state and the age of its latest run. Rule rows
show the sentence, effect and age of the run whose rules they describe.

This machine shows what past runs recorded. It does not probe the machine: start with
`tego machine check` to check current readiness. Tap a protection check for its meaning and
next step, or open Full recorded machine details for complete technical values.
Glossary has a native search and a term index; its links and all detail disclosures work
with scripts off. Edit confirmations retain their original server forms and safeguards.


## Dashboard consistency

Summary lists keep one native link with who, one state and age. The shared
responsive table adapter applies below 1100 px, including Runs and contract rules.
Full exact values remain on their detail destinations. Summary ages use the same
units before and after enhancement; absolute timestamps remain in the record.
The Run timeline retains its sequence and clock because it describes ordered events.
Desktop auto-expansion hides a native disclosure summary only when the browser
supports `::details-content`; otherwise its summary remains available to open by keyboard.

Overview shows running and refused counts in the desktop ledger tiles. The record
card keeps those links below desktop width. The heading does not repeat the counts.
Stop asks a short question and prints the complete agent name in body text.
Keyboard focus moves transient messages into document flow so they cannot cover
another control. The request identity and answer protections do not change.

Feature styles load with the page that uses them. Detailed implementation notes
are in the development tree's `docs/development/dashboard-assets.md`; the shipped
styles and scripts retain their readable declarations and statements. The font,
its licence and the same-origin CSP remain unchanged.


Dashboard review corrections, 13 November 2026: every waiting-request link carries
its run and request. If that pair is no longer waiting, Approvals shows the outcome
or says it cannot find it, with no other request's controls. Overview and Run put
waiting requests before record failures, recorded leaks and sensitive reads. Quiet
wording describes what was not seen when the relevant sources are complete; an incomplete source keeps unknown needs explicit and never claims that nothing waits or needs the person. The daily refusal
number uses complete run totals when all refusal timestamps fall today. Missing
windows across a date boundary or omitted runs produce an at least count with a reason and links
to the complete records. Unreadable record lines show could not read with the reason instead of a smaller count. A record with unreadable lines links to its exact JSONL download; other run links open Receipts. Logs warns beside its results when part of a query was left
out, even with Filter closed. Runs retains Filter and the scoped count on desktop.
Phone summaries keep who, state and age; technical values stay in details. Only
Overview permits the compact request sentence two lines. Protected-read chips use
the same run, contract and row context on Logs, Event, Run and Receipt, including older timeline windows. `TestHistoricalProtectedReadParity` covers an early sensitive read followed by 33,000 routine events for own-login and custom-contract paths. Signal caches
include the events-file version and reuse live folds only from that same file.
Older Event windows reject a replaced or rewritten source before and after
reading, keeping new events out of an older run context; ordinary appends work.

The Receipt tab supplies the run's contract paths to the streaming receipt builder.
Its sensitive-read activity can therefore include a custom protected path even if
the event did not name a deciding read rule. The ordinary terminal receipt uses
ledger names and rule keys alone. Recorded totals and receipt sentences use the
same builder. Contract entries and their working directory are part of the
dashboard receipt cache key; this adds no field to the saved record format.

Receipt identity overflow: the terminal receipt, watch footer and dashboard separate
listed places/programs, other retained identities and attempts beyond the identity
budget. JSON `connections_more` and `programs_more` count other retained identities;
`connections_overflow_attempts` and `programs_overflow_attempts` count attempts.
Repeated attempts to one untracked identity never establish more distinct places or
programs. The optional fields keep `receipt_v: 1`; old overflowed receipts may fail
comparison with corrected recomputation. Receipts whose identities all fit the displayed lists retain
their units and wording.

A root that becomes unreadable or ceases to be a folder keeps requests already read, with the global read-failure reason and the same lower bound in the page, badge and title.

Number-inventory exclusions never exempt descendants. A request card is not an identity field: its individual names, targets and times are audited separately.

Empty receipt activity is audited too: "never asked", "It wrote no file", and the sensitive-file absence sentence have the same source markers as their nonzero forms.

On phones, a complete Approvals count uses the headline and tab. Incomplete waiting status uses one short reason. Full source diagnostics and supplementary complete-record links are in a closed Details and recovery disclosure; desktop retains the fuller presentation.

Zero-branch fixtures also exercise unavailable receipts and proposals, empty rule and configuration lists, unchanged configuration comparisons, empty credentials and uses, setup with no runs, and verification with no lines read. Unknown contract declarations keep their reason and do not become zero unused entries. Static policy instructions and absent individual identity fields are distinct from counted collections.

The short phone reason is also present on Approvals History and Overview. An empty running-state panel on Overview is hidden on phones when the same live-index failure is already explained above; retained running rows remain visible.

Watch-mode sentences that assert zero enforced refusals carry an exact policy source, independent of retained record completeness.

A running dashboard pins the record directory by device and inode. If that pathname names a different directory, including through a link, it says the record folder changed and retains known requests under a global read failure. The replacement live index cannot retire those requests. Putting the original directory back recovers the view. After a dashboard restart, either a link or a real replacement directory becomes the new root: the process reads that directory and cannot remember requests from the moved original. Restarting after the original is restored reads its surviving record normally.

The quantity audit also walks every delivered template's parse tree without choosing a fixture branch. It visits both arms of if, with and range, preserves separate HTML source contexts through shared suffixes, and examines literal text and shown or spoken attributes. Each literal must inherit a quantity source or have an exact-text no-quantity registration with a reason in testdata/no_quantity_texts.json. Missing and stale registrations fail the normal web tests with the template, line and text. The rendered-page collector remains an independent check of dynamic output. Configuration fence absence, complete usage results and watch-mode non-enforcement now carry their sources, including the first-run instructions.

On phones, missing-request recovery during a root failure uses the same single short uncertainty sentence as the waiting list; technical paths remain in closed recovery details. An answered request exposes Answer details as its primary action and keeps Next waiting request under More. These three request-detail states join the light/dark, 360/1280 browser matrix and height comparison.

The public no-quantity registry is extended by the private pages through their existing export hooks. Both registries receive the same stale-text check; dropping the private layer drops only its registrations. No missing-template exemption is used.

The source audit's initial exact-text registrations were reviewed for zero assertions as well as digits. Record-field absence, process-tree coverage, unavailable recovery, pause defaults and fixed policy guarantees now name their sources. The rendered fixture catalogue includes every corrected literal branch, including incomplete process scope and pause states.

Policy guarantees, duration choices and completeness claims carry sources too; being independent of a measured record count is not a reason to register them as no quantity. Registrations describe navigation, ordering, identity placeholders or example syntax. The audit report distinguishes literal text sites from audience attributes.

Decision cards and waiting rows display the complete agent name and requested target. Long hosts, paths and commands wrap after dots and slashes, with a break inside a long segment when needed. Command whitespace is preserved. Waiting rows size to their text rather than a fixed first track. Desktop request banners keep their home and working-directory path display and no longer shorten a long target.

Request sentence forms (this supersedes the previous paragraph's rule for banners and waiting rows). A person is never offered Allow once beside a request they cannot read in full there. A waiting request's sentence (who, what, the target) has two forms. FULL shows every character, wrapped after dots and slashes and never clamped. LONG is used where the sentence passes a bound: the server cuts the target once in the middle with one ellipsis character, keeping what a decision turns on (of a network target its first label and the end of the host with the port, of a file the leading folders and the end with the file name, of a command the program and first arguments and its last characters; each name of a rename is cut on its own), and cuts the agent's name in the middle only when the name alone passes its own bound. Where a banner shows the LONG form it offers one action, Review request, which opens the request's own card on Approvals; that card always shows the FULL form, the exact target whole whatever its length, with Allow once and Deny. The waiting row on Approvals follows the same two forms. The accessible names carry the whole sentence in both forms.

The bounds count characters and are decided by the server (request_forms.go): 112 for a phone and 150 for a wide screen, with 40 and 60 for an agent's name. They were measured in headless Chrome by filling the real banners with host, path and command sentences of every length from 60 to 320 characters under two agent names and counting line boxes: at 320 px the phone banner's 16 px sentence stays within four lines up to 112 to 126 characters, and at 1280 px the wide sentence within two lines up to 166 characters on a page's banner and 154 on Overview's. The markup carries both answers and the style sheets pick by width at 600 px (phone-only, desktop-only); when only the phone form is LONG the quick answers carry desktop-only and Review request phone-only. Between 601 and 1279 px the FULL form can take more lines and never hides text. At 320 by 640 px a FULL sentence of four lines with its one action row makes the banner 174 px high, 27% of the screen: the earlier phone ceilings of a quarter of the screen and of 160 px give way there to this four-line limit, and the earlier one-line banner sentence and one-line waiting row give way to the two forms. TestNoQuickActionsBesideLongRequest walks every template branch: each Allow once is either in the request cards' own form or inside the branch of a requestView's Quick with its QuickClass, and the three banners render the answers only where the same width's sentence is FULL. The safe answer does not depend on a style sheet loading. The phone's cut sentence carries the hidden attribute in the markup whenever the phone form is LONG, and phone.css only reveals it at 600 px and under (.banner-ask .ab-summary[hidden] with !important, which outweighs app.css's [hidden] rule by specificity); the quick form is in the markup only where the wide sentence is FULL, and at 600 px and under phone.css hides it when the phone form is LONG. With phone.css missing, or with no style sheet at all, the cut sentence is therefore not shown, and no Allow once form sits beside a cut sentence at any width; the same holds in the accessibility tree. TestFix7SafeAnswerNeedsNoStyleSheetInChrome loads the pages with phone.css blocked and with every style sheet blocked at 320 and 1280 px and checks the DOM and the accessibility tree. The cut itself never splits a letter from its combining mark (a kept tail drops marks it would start with), a port is at most five digits, a rename's half without a slash is cut as plain text, the accessible name is built from the visible text (control and bidi characters as their U+ literals), and FuzzRequestForms holds all of it against arbitrary agent text.

### Optional setup tour

Open Guide beside help on a desktop, or from More on a phone. Guide opens at the
first step whose fact is neither Done nor Skipped, using the same stored machine
check, recorded runs and compiled contracts as `tego setup`. When all steps are
done or skipped it opens Enforce. All steps shows each fact, its source and its
tour name. Selecting a step never completes it. Pick completes when the first run
is recorded. With a saved contract it points directly to Enforce for that first
run. Watch and Recorded share that run's verified ended-record fact; a skipped
Watch points to Enforce too. An unknown recording opens Watch's diagnostic step.

Check says to run `tego setup` in your terminal, then reload the stored result.
Run terminal commands yourself; the page starts no process. A command form with
marked parts to fill in has no Copy button. Replace each part with the value it
names; for the watch form, use the command you normally use to start your agent.
Watch says Step 4 is ready when an ended recording verifies. With scripts on it
announces a move, waits about two seconds, then moves on; it stays put while focus
is in the guide. With scripts off, use Reload to check for the run and open the
next step yourself.

Recorded and Review lead with recorded programs (or the starting command), file
changes and connections. These short rows point to What the run recorded for full
values and coverage limits. The first record disclosure opens when the list is
short. Review describes the action shown: Create contract and a learn command
create a contract from the run; a compile command checks an existing contract that needs
fixing, while Create contract can make another. A saved, compiling contract
offers Enforce its rules without a terminal command. The builder keeps Review
through both mode links, including the selected mode, preview and save. After
saving, the facts refresh and Enforce its rules opens the next step. Enforce first
shows the command, then the ended record and each refusal's line. If a request
waits for you, the tour shows its count and opens Approvals first, including after
a contract save. Return through Guide after answering; no decision form is
duplicated in the frame.

Leave the guide opens the same product page without its frame. Guide returns to
the current fact-based step. Hide for good is a browser preference submitted with
the normal form protections; it does not alter any machine fact. Show the guide
again is available in the frame, More and This machine. A blocked or unknown step,
or an incomplete machine check, keeps the Overview checklist visible even while
the preference is hidden. A finished machine receives no Start the guide offer.
On phones the frame shows the current question, instruction and action; All steps
holds history and sources, and the named product disclosure holds the full page.
The scanned agent picker arrives separately.

## Agents evidence

`/agents` reads the saved scan and remembered discoveries, and starts no discovery process. Each recorded row describes one named run, with its id and start time. Checked stage facts and their displayed run fields come from the same checked record; unchecked metadata remains a labelled recorded claim. Unchecked, broken, timed-out or anchor-missing records stop at Recorded and say why and what to do. Contract, Enforced and Verified never transfer from another run. These are facts about that recorded run, not a process running now. `/agents/<identity>` recovers one complete row. `/` uses this view when setup is done; `/overview` always opens Overview. The page is the approved Agents page (`templates/agents.tmpl`): it sits in the main navigation ahead of Overview, each row is one link to its detail, and the guide's Pick step opens it. A row says who (name, and from 601 px up the command identity and folder), how far (the stage word, and for a recorded run the five-stage strip, drawn reached only where that run established the stage) and when. The phone shows those three facts only and puts the list before the scan panel; the other programs, settings and history are folds there. Its three live regions (`r-ag-head`, `r-ag-main`, `r-ag-more`) merge through `live.js`; with scripts off every part is in the page. The detail shows `Recorded run <id> at <time>` or `Seen outside Tego at <time>` with the folder, the command identity and a note that a PATH search, relative path, link or wrapper can spell the same program differently, `Relationship`, the record check and next step always, `RelatedRunIDs` linked, each stage with its fact, source and what cannot be told, and copy buttons for the scan, next and record commands.

Outside scan observations have separate rows with "seen at" time and Record it, and no stage ticks. Matching program path, folder and known uid allow only "may be the same program" words: scans keep no arguments, so they cannot tell. Observations marked inside a Tego run add no row or label and are counted in the footer. Only omission from a usable latest scan means "not seen in the latest scan" with last-seen time. An old, failed or unreadable scan instead explains that state and asks for another scan. Remembered relations use the current recorded-run facts on every load. A busy store lock shows the last committed snapshot without writing and asks for a refresh to retry. The page renders Footer, ScanNotice and DiscoveryNotice visibly outside collapsed details. Discoveries remain for 30 days since last seen; bounded lists state truncation and unsafe remembered state is shown as unreadable without overwriting it. A remembered discovery's detail offers Forget: a fold that is the confirm, then `POST /agents/forget` (the dashboard's session, origin, token and governed-caller checks) drops that one entry through the store's own lock and file checks, refuses a busy or unsafe store, and never changes a run record, a saved scan or a contract. While the latest saved scan still lists the program the next load remembers it again, and the confirmation says so.

Run `tego scan` from the intended project folder, then reload Agents. After five minutes, another boot, unknown freshness or a future time, the scan is historical only. The found list comes from scans. Tego refuses ordinary writes to these files, even with a whole-home grant at tier landlock; this was shown in guest row whole-home-landlock. With the anchor and ledger outside the home, a whole-home grant with direct reads can leave these files readable at landlock; that read case is derived from code and is owed in a guest. The stages shown for a run do not depend on this list. This list never proves that nothing else runs. Same-user programs outside Tego can rewrite both files, too. This is the accepted existing own-state limit in GAPS C52. Modes or links that make either file or the agents directory unreadable show fixed repair steps without changing unsafe state; readable recorded rows remain visible. The record lacks resolved historical own-state write exposure, so this slice has no per-run caution or unconfirmed-after-run state (historical own-state exposure work). Ordinary writes were refused in gproof1 guest5 whole-home-landlock, whole-home-cgroup and whole-home-bpflsm; the external-anchor direct-read case is owed in a guest; see ADR 0145 fix round 2 acceptance and the [Agents user page](user/agents.md). Record it quotes only a safe known folder and leaves your command as a template to fill in. The page never reconstructs a launch command from scan evidence. The footer names unreadable sources and limits. Refused today is an observed local-calendar-day count; incomplete records are labelled as a lower bound.

### Simple and Full contract drafts

New contract can start from a recorded run, presets, or nothing. Simple lists explicit write, program and network
grants with Keep and Drop. Name it replaces a recorded address with a host name you supply, preserving its port and
transport. Tego does not guess the name the agent used. Show refused reads states its cost beside the switch.
A blank draft starts with no grants, retaining the built-in secret refusals. Full edits the same YAML and lists the
contract keys. The dashboard remembers the view in this browser. Switching views keeps the draft.

Check choices compiles the candidate with the product compiler, no DNS, two child slots and a total deadline.
A third compile waits briefly, then says “busy, try again”. Compilation checks the file identities, executable
loaders, inherited profiles and protected paths it needs; these filesystem reads happen in the cancellable child.
Preset composition and project-folder validation use the same pool for their filesystem metadata probes.
The deadline bounds compilation and these preflight probes; Save still performs necessary destination checks
and durable writes. A busy preflight retains the edited draft for retry.
On desktop the YAML is beside the form; on a phone open YAML and changed lines. Preview retains the exact
proposal bytes and acknowledgement binding in an authenticated server draft. Save writes those reviewed bytes;
it never builds the proposal again, for new contracts, raw or structured edits, presets or proposals from a run.
It revalidates the source digests, destination kind and canonical path, directory device/inode and compilation
of those exact bytes, then rechecks source bytes at publication. A lost draft (restart, expiry, eviction or another
session) refuses with “This draft is no longer available; review it again before saving.” Source and review drafts
share a 64-entry limit, 8 MiB per serialized entry and 32 MiB total. Each entry expires 30 minutes after its own
creation, with eviction as stated below. Expired entries are removed on the next store access. Failed offline lookups
supply no resolution timestamp; authority-bearing expiry deadlines remain bound. Hostname grants and approval
entries therefore keep their review across time while the authenticated draft remains available.
If an inherited source changes, review the new preview. The final writer
checks the directory identity against its publishing descriptor. If Check reviewed B after the editor opened at A,
Save accepts that review only while both the submitted base and current source still match B. It clears the
historical A-to-B warning after validation without rebuilding; a later change to C requires another review.
New-contract Full/Simple/Save and raw Full/Simple preserve intentional leading blank lines through native HTML textarea parsing.
A missing finished-run choice stays marked even when project preflight refuses; the original refusal remains visible.
Changes to existing files also compare the loaded
SHA-256 and the old file's identity at replacement. Wider compiled families list “This will newly allow”. Changed
families the comparison cannot order say “Also review: <family> changed and Tego cannot tell whether it allows more”.
Both require explicit confirmation. This pure table comparison is not a proof of final decisions across families.
With scripts, every input invalidates earlier pending previews and disables Save. The YAML editor uses the monospace token with
wrapping off. Existing and setup-generated environment values stay hidden; new values must be set in a terminal.
Generated assignments, setup folders and the displayed withheld-destination list stay with an expiring server
draft bound to this session and destination, so Check, view switches and unchanged Save retain them. The
withheld list is derived by the server from the run, never taken from posted form fields. Empty posted Full text is refused. Diagnostics redact values from the same
merged contract that compilation used; failed inherited loads use a safe generic error followed by where each fault lies,
one line each and never the loader's words: "profile <name> · <file> · line N" for a profile the draft extends, "the draft ·
line N" for the draft (Edit YAML shows the profile, its file and its line beside each, and links the draft's line). The
contract check's 503 page ("The contract check could not finish") says which case happened, from the refusal's type: the
machine is very busy (the checker did not start in time, or was too slow), the check was still working, the checker could
not start, the request was cancelled, earlier checks are stuck on a location and hold every checker slot, or the location
does not answer; the status and the advice (reload, then review again, since a submitted save may have reached the file)
are unchanged. A malformed submitted
document retains only its parser line number, with its diagnostic message withheld. A configured registry or parent reached through a symbolic link is refused;
configure its real path instead. If a read preview finds a missing registry directory, Save is withheld until
the guarded Preview POST prepares it before compilation and binds its identity.

A governed or uncertain reader can preview fresh source with the same redaction and saving unavailable, without a review identity or acknowledgement and without accessing the source/review store; retained composition handles are unavailable from that connection.
Every save-eligible Preview mints a separate 192-bit identity from the system random source. Its acknowledgement
carries that identity and binds it with the reviewed bytes and compiled binding. Equal Previews never
replace each other. Reviews expire exactly 30 minutes after their own creation; reads, Save validation
and later Previews never extend that lifetime. Save atomically consumes the review after validation and
before publication, so a replay refuses; a publication failure also requires a new review. The retained
review is keyed only by its identity and checked against its authenticated session. Identity and
acknowledgement comparisons use constant time.
At capacity, insertion evicts the inserting session's oldest entry first, otherwise the global oldest,
using insertion order to break clock ties. Eviction only loses a review; an old acknowledgement can never
select a replacement.

Simple offers a 2-hour stop switch, a custom duration, and approval for host/port entries you name. It keeps all
other destinations refused. A blanket “ask for any new address” rule is not generated: that shorthand is not
supported by this contract compiler. Use named `net.ask` entries.

*Amended 2026-11-18:* a network fence lifted and restored during a run has the same run-wide Routine
exception as a live network block. All refusals for its host remain outside Routine, including earlier ones,
by name or by a recorded address on any port. Lifting alone does not create this exception. The run page
reads this explanation from `ledgerview.RoutineWords`.
