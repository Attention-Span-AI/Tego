# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), one section per tag, each ending in the three
lines `docs/VERSIONING.md` requires so a reader can tell what a binary speaks without pulling it: Record `v` /
Contract schema / Kernel minimums. Versions: [Semantic Versioning](https://semver.org/), `0.y.z` until 1.0
(`docs/VERSIONING.md` section 1).

## Unreleased

- The loser of two answers to one request is told the truth as the run ends. When the answer that lets a held operation finish ends the run, the run's broker closes its connections and removes its socket a moment before the launcher releases the run's lock, and a second `tego approve` or `deny` that met that moment was told `connection reset by peer [io]` (exit 125) or, for a run whose contract has an ask rule, `takes no approvals: its contract has no ask rule` (false). A command whose broker went away now says what the run's record proves: `ask: request is no longer pending` when the ledger holds another answer for the ask, `your answer was recorded on line #N` when the ledger holds this command's own and only the reply was lost, `has ended; nothing waits for an answer` once the lock is free, and otherwise that the answer may not have been delivered (a socket that is not there says it was not delivered). A launcher that has released the run's lock while a command looked at it (the ledger's close does, before the process exits and prints its summary), is exiting (its memory and descriptor table released, its flock not yet dropped) or has gone since the look began is the run having ended too: `tego approve`, `deny`, `ask` and `tego stop` said `no descriptor proves the run's flock [io]` or `lock holder is gone; the pid was reused [io]` (exit 125) for it, `tego status` called it `(launcher unknown)`, and they now say the run has ended (`tego stop`: `not running`; status: done). `no ask rule` is said only of a run whose `run_start` says its broker was not available (`capabilities.ask` false); a run that served approvals, or whose start cannot be read, is not said to have none, and `tego ask <run>` (the `--json` form too) then exits 1 instead of printing a sentence, or an empty list, with exit 0. A caller that cannot prove a run's launcher (root without `CAP_SYS_PTRACE` on a filesystem whose `/proc/locks` prints the superblock's device) is told why the launcher is hidden from it also in a root-only (managed) setup, and not that only root may answer.
- The receipt lists a run's refusals in the order the calls were received. `refusals.list` was in the order the lines reached the ledger, and the supervisor answers a call and then writes its line (R23) and keeps the order of one thread's lines only (R23a): an agent whose child process was refused an exec and which then read a secret itself could have the read's line written first, and its receipt listed the read before the exec (`TestIntegrationReceiptOfAScriptedRunAtTierLandlock`, once in a full gate run, and every time with a 60 ms delay between the answer and the line). The list is now ordered by each line's `mono_ns`, the clock reading the supervisor takes when a call arrives, and lines with the same reading keep their ledger order, so one ledger gives one list, in the order the agent made its calls whenever one call's answer led to the next. The counts, `refusals_over_time` and the receipt's fields and schema are unchanged (record m41); a run past `MaxRefusals` lines still lists the first thousand the ledger holds. The ledger is not reordered: its lines keep the order they were written in. Each listed row's `ts` is still the time its line was written, so the times beside the list may not rise: a call held for an ask and then refused is listed where it was received, with the later time it was written at.
- Model steps on the run timeline and in Logs (no new record field). The timeline groups consecutive rows of one model step under a header ("After model request N, matched by time (likely)", "Model step N (likely)", "Step 0, matched by time (likely)", "Not tied to a model step"; a line the record ties to no step, such as an ask, closes the group around it and sits under "Not tied to a model step", and a folded row has its own header), none for a run with no model capture; Logs takes `step:N` and `step:none`. `tego events --step N` and `step:N` are one reader of the record; the one difference is that Logs lists a refusal once, so the mirror line of a refused action is in `tego events --step -1` and not in Logs' `step:none`. `tego events --step 0` no longer prints the lines stamped unattributed (their step is omitted from the line and read as 0); `--step -1` prints the lines tied to no step, those included.
- A person's dashboard says why it cannot show a run launched with sudo: "run r-...: its folder is owned by root (a run launched with sudo does this), so this dashboard cannot show or change it live; run the command with sudo, or open the dashboard as root", in place of the failed system call. A run launched with sudo stays root-only for live changes.
- A launch's `run_start.applied_limits` is the limit that holds, not only the scope's own file. A run placed under a cgroup with a lower `memory.max`, `memory.high`, `pids.max` or `cpu.max` than the launcher wrote is held by the kernel to the lowest ceiling along the chain up to the cgroup2 mount, so each of those members is now the lowest (cpu.max compared by quota over period; `max` is no ceiling; `cpu_weight` is a share and stays the scope's own). The read is once, at the start. A member whose ancestors cannot all be read is left out and the log names the file, so the record never states a number that may not be the one that holds. Inside a private cgroup namespace (a container) the mount is not the real root and the pod and node cgroups above it cannot be read, so those four members are left out and the log says why. No record field changed (record minor 41); an ancestor's ceiling over a limit the run wrote none is not in the block.
- `tego adopt --release` of an agent that was alone in a transient scope puts it somewhere sound (ADR 0055 amended). An agent started with `systemd-run --scope`, or launched from a desktop as an app scope, leaves that scope empty when Tego moves it, and the service manager removes it; every cgroup above it refuses a process of its own, so the release found no place and left the agent in the adoption's scope for good (exit 125, the guard counting it governed, its limits lifted). The release now makes an empty cgroup `tego-released-<run id>` under the nearest ancestor that lets one be made (a user's `app.slice`) and moves the tree there and out of every Tego scope; only a process no cgroup takes and no place can be made for stays in the scope, counted as before. Under a user manager (the usual case: a desktop launcher, `systemd-run --user --scope`) the leaf is in the user's own part of the hierarchy, ends with a logout as the agent would have, and stays until that user manager stops. Where the origin was directly under `user-<uid>.slice` or `system.slice` (`sudo systemd-run --scope`) the leaf is root's: the user cannot remove it, a user manager's stop does not, and a logout does not reach the process in it. The origin unit's own properties (`MemoryMax`, device rules) do not follow the tree into the leaf.
- A person's own live command against a run launched with sudo says why it cannot. `tego lift`, `grant`, `restore`, `block` (add, remove, list), the `tego mcp` switches and `tego route` need the run's folder, which is root's until the run ends (ADR 0042); they said `runtime: open lock file …: permission denied [io]` and exited 125. They now say the run was launched as root and to repeat the command as root, exit 1 with the code `[root-run]`, and change nothing (the read-only `tego mcp tools` and `tego route list` keep the plain `[io]` failure). The person's own dashboard still cannot change such a run (it lists it as unreadable); that is an open design question.
- A ring's listen on an inet socket other than UDP is refused under a `net:` section with no `net.listen` (ADR 0024 amended; GAPS C44's io_uring half). The decision plane's `socket_listen` refuses a listen on an inet socket other than UDP (TCP, MPTCP, SCTP: `EACCES`, rule `net-not-allowed`) when the run has a `net:` section and no `net.listen`, so a ring's `IORING_OP_LISTEN` (Linux 6.11+), which no seccomp filter sees, meets the rule the supervisor applies to `listen(2)`; a unix listen and a UDP socket's are unchanged and a run with no `net:` section is not decided. `tego compile` and `tego run` no longer warn `io-uring` for this case, which the plane now decides. `io_uring: true` is still a compile error where a contract may land at tier `cgroup` or `bpflsm` (ADR 0113). The record minor stays 41.
- TOMOYO's facts can be read where the kernel's path is hidden (GAPS C74). Under Docker's default AppArmor profile a bind at `/sys/kernel/security` stays unreadable, so every held open refused on a host with TOMOYO active. A new machine setting `tomoyo.facts_dir` in `/etc/tego/config.yaml` (the administrator's file only; a user layer's value is ignored with a warning) names a read-only bind of the host's `/sys/kernel/security/tomoyo` at another path; Tego reads `self_domain`, `stat` and `profile` there, and accepts each only on securityfs, on a read-only mount whose root is `/tomoyo`, by the descriptor's mount id in `/proc/self/mountinfo`. Anything else (a writable bind, `apparmor/`, a tmpfs copy, a path through a link) refuses with the existing words. `tego doctor` names the path it read. No setting assumes TOMOYO enforces nothing. Nothing changes without the key.
- GAPS C30's exec limit now says what the kernel bounds. At tier landlock and on tier 2's fanotify fallback an exec is bounded by the files `exec.allow` grants: no spelling, descriptor or race runs a file outside them as the exec's image (what a granted loader or interpreter maps or reads is C31 and A2) (`TestIntegrationExecRaceStaysInsideTheGrantedSet` races a descriptor 400 times between a granted and an ungranted file: the ungranted one never ran). What a second thread or a concurrent writer can race is the supervisor's finer decisions inside that set (`exec.deny`, `exec.ask`, command rules, live blocks, the MCP gate) and a memfd received from outside the run; both are race-free only where a plane decides execs. Words only, no behaviour changed; SEMANTICS §4, GAPS A2, C30 and C31, ADR 0041's amendment.
- A route in a table a policy rule leads to now counts as this host's. Net blocks, `net to` rules, the `models[]` guard and tier 2's rows read the policy rules (`RTM_GETRULE`, both families, unprivileged) before the routes: the `local`, `broadcast` and `anycast` routes of a non-standard table count when a rule the run's own traffic can match leads to it (no `fwmark` whose mask covers it, `iif` absent or `lo`, a `uidrange` that holds the run's user; an `oif` or VRF rule counts, since an agent can `SO_BINDTODEVICE` a socket), so `ip rule add from all lookup 100` with `ip route add local 192.0.2.0/24 dev lo table 100` makes 192.0.2.0/24 this host. A table behind a mark (TPROXY's, Cilium's `local default dev lo table 2004`) is not read, and `tego doctor` names it (`note routing:`, `--json` key `routing`) and the run's log says so once. Rules that cannot be read give no table (fail closed). GAPS C46, ADR 0127's amendment.
- The reason channel gives each session its own refusals and prints a note at least once (ADR 0063 amended; GAPS C64). The supervisor lists the refused process and its ancestors (with start times) in the reason file's entry (`owners`, an additive key of reason file v1; no ledger field, record minor stays 41), and the Claude Code hook keeps one cursor for each harness (its nearest ancestor that is not a shell) plus one for the refusals nobody owns, so another session's tool or Stop hook no longer claims a refusal before its owner's. A claim takes two steps: the hook records it, prints, and then marks it printed; one stopped in between (killed, timed out, a failed output write) leaves it, and the next hook of that harness tells it again, so a note may print twice and is never lost to that. The words say printed, not received: Tego cannot see whether the harness passed the note to the model. The hook's state file is version 2 (a run's own); the hook also reads `/proc/<pid>/stat` of its ancestors and of a claimer. Refusals the root tiers' ring or the fanotify listener write carry no owners and keep the shared cursor.
- At tiers cgroup and bpflsm a read of a name made beside a `deny_read` target's ancestor after the run started is recorded as tier landlock records it. Those tiers install the same Landlock ruleset, whose listing of each ancestor is taken once at launch, so the kernel already refused such a read for the rest of the run; the root tiers' handle was not given the snapshot of that listing, so the open was continued and its line said `observed` (by `other`, errno 13) where tier landlock's says `refused`, `read-denied`, rule `deny-read-snapshot`, and under held reads no line was written at all. The handle now hands the supervisor the ruleset's own snapshot, so a read the supervisor is notified of under `record: full` or held reads, and an exec of such an image (the supervisor no longer hands that exec to the kernel plane), get the same line at every tier, and a run whose ruleset froze directories without a snapshot does not start. Under `record: summary` with direct reads no open reaches the supervisor at a root tier, and the kernel recorder's line stays `observed`, by `other`, errno 13. No record field changed (record minor 41). Proved as root in KVM guests on the host kernel (6.17) and fedora-7.0, both boots, at both tiers (bpflsm where bpf is in the boot LSM list).
- `tego status` and the dashboard read a run's pause by one rule. A pause that failed after the run was paused (a pause-failed line after run-paused, or after a resume-failed) left the run frozen, and the dashboard said paused, but `tego status`, `tego session list` and `tego stop` read only the last line and said it was not paused. Both now fold the lines through `record.PausedAfter`, and the wait for the launcher's answer ("pausing", "resuming") is one shared rule in `internal/liveblock`.
- The process that holds a secret is no longer readable by other processes of your user. `tego run`, `watch`, `adopt`, `start` and `setup` make themselves non-dumpable (`PR_SET_DUMPABLE 0`) before they read an argument, so the environment, the saved logins and the keys they unseal cannot be read through `/proc/<pid>/environ`, `fd`, `mem`, `ptrace` or `pidfd_getfd` by an agent or any other program of the same user; the forwarder sets it again before each unseal, and a process that cannot hold it starts nothing and unseals nothing (`[undumpable]`). What changes for you: a debugger of your own user cannot attach to a `tego run`; `tego scan` lists a live run's process among the unreadable programs (as it lists `ssh-agent`); `tego scan` says which unreadable program is the launcher of a live run (a line on stderr; the count and the exit code are unchanged); on a btrfs subvolume a user proves a run's launcher by the superblock's device of the mount that holds the lock file, and only a caller that cannot signal beyond its own uid may (root and `CAP_SYS_PTRACE` callers read the launcher's descriptors); `systemd-run` is started with a minimal environment, not yours. ADR 0126, "Amendment 2026-11-21: the secret-holding launcher is not dumpable".
- The dashboard is no longer readable by other processes of your user. `tego-control serve` holds its sign-in token, its CSRF and acknowledgement keys; it now makes itself non-dumpable before it does anything else and does not start when it cannot (`[undumpable]`), so an agent of a run with no Landlock domain (`tego watch` with no `--boundary`, `--observe`) on a host with Yama `ptrace_scope` 0 can no longer attach to it or read its memory, environment or descriptors. It still answers asks: the ask broker admits a peer whose cgroup namespace `/proc` hides when the kernel's own files show that the dumpable flag is the reason, and judges it on everything else (uid, pidfd, the cgroup path of every thread, whether it is inside a run) exactly as before, so an agent that makes itself non-dumpable is still refused for being inside its run. What changes for you: the dashboard is a program `tego scan` cannot read, so it holds a lock (`~/.tego/dashboard/lock`) that the scan proves as it proves a run's launcher (the kernel's lock table and the process's start time) and leaves the dashboard out of the unreadable programs; `tego scan --check` is not made exit 3 by a running dashboard, and every other unreadable program is still counted. ADR 0100 (7), "Amendment, 2026-11-22".
- `tego events <run> --cells` prints each event as one line of four tab-separated cells, seq, verdict, rule and detail, exactly as the table writes them (every control character, a tab included, escaped), for a script that wants the table's words without copying how it makes them. The supply-chain demo's proof table reads it in place of a hand-kept Python copy of the cells. With `--json`, `--verify` or `--follow` it is a usage error.
- One vocabulary and one schema for the receipt. The receipt's JSON types, its coverage codes and its binding block are defined in `pkg/spec/receipt`, and `spec/receipt/receipt-v1.schema.json` publishes the receipt, held to the types and to what the builder writes by tests. Each coverage gap now also carries a `level`, `partial` (some of the field is recorded, so a count is a floor or an estimate) or `none` (the ledger is silent on the field); `tego receipt` prints it beside the field and the Receipt tab shows it as a chip; a field with no gap is complete, and a reader never takes a gap for better than its code says. The receipt, `tego status` and the Receipt tab say the same sentence for a gap that may have lost actions ("N gaps in the record (counts are a minimum)"), for capture gaps ("token counts may be low (N capture gaps)") and for a missing price ("the cost is not estimated (no price table)"), where the receipt used "N gap lines: tego knows it missed some actions, so the counts are a floor" and the tab had its own wording; the price and live-change whys are spelled once, in `pkg/spec/record`, with their sentences. `spec/record/v1/live-fields.schema.json` publishes the live changes' fields (`live_block`, `live_control`, `live_mode`, `live_fence`) with boundary tests against `Event.ValidateAt`. The real receipt integration test now has the agent read a denied file and holds the refused read to the receipt. No record change: record minor stays 41, and the receipt stays `receipt_v` 1 (the new key is additive).
- Logs queries and groups mean the same everywhere. A query that cannot be read in full lists no lines (the page says why in words; `/logs.csv` and `/logs.jsonl` answer 400), where it used to show the lines of the part it could read as the results. `OR` between two terms of one key (`kind:exec OR kind:net`) is that key twice, a bare `AND` between terms changes nothing, any other `OR` and a mistyped key (`verdit:refused`, `program:curl`) are errors that name the fix. `prog:` takes a program's path or a folder (`prog:/usr/bin`), read as `path:` reads one, so two programs of one name in different folders can be told apart. A By target group is one identity per target (paths cleaned, hosts lower-cased, an ask and its answer by the file they name) and opens `target:<name>`, a new query key, so its link lists exactly its count. A row's program and process are buttons of one shared form instead of two copies of the whole search (a 101-row page with a nine-term query: 284,714 to 252,806 bytes). A blob download is authorized from its line's own keys instead of explaining the line again.
- Contract creation and editing say what they do. The change preview, the free editor's check and the saved page of a free edit now name every compiled family the change moves, each with the direction the comparison ordered it in ("Files it may change: the next run may do less than before", "The arguments a program may run with: changed, and Tego cannot tell whether the next run may do more"), where the preview named only the lists the form changes and a free edit showed a diff and "free edit of the whole text". The journal's summary of a free edit is "free edit: filesystem narrowed, destinations widened" and a free edit is still confirmed like a widening. A rules file edited outside Tego, or one that differs with nothing to date it, is compared with the rules the run ran (`rules.Service.CompareSource`, the same family comparison) and its banner says what the next run would do differently. A rules file recorded under two spellings (a linked folder on the way) is listed once and the page says the other spelling and that the runs are listed together; the run list pages ("Older runs", "Newer runs") past its forty. A new contract's generated state folder in a read-only project (`.tego/review/`) is on the `.gitignore` lines Tego names and `tego init` adds, each line once and none a listed folder already covers, and the preview no longer prints "Folders to make:" or "Add to .gitignore:" with nothing after it. No record or journal change.
- The MCP relay and the model forwarder hold a Locked run to its contract, and a batch is decided member by member. On a Locked run (the default, and the mode of any run whose contract has no `live.mode: adjustable`) a live MCP switch looser than the contract's decision, or a model route other than direct, that something other than `tego mcp`, `tego route` or the dashboard wrote into the run's folder is not put in force: the call is decided by the contract, the endpoint stays on its own backend, and the ledger has one `mcp-tool-changed` (decision `reset`) or `model-route-changed` (route `direct`) line saying who asked and why it did not take effect; the MCP tools and Model routes pages show the same. A JSON-RPC batch no longer fails whole for one refused call: each member is decided on its own, the allowed ones go on, each refused one with an id is answered with an error of its own and is a line of the record, an asked one is asked, requests that share an id are refused together, and a batch of more than 128 members is refused whole with one error. A `tools/list` is filtered inside a batch answer, in an event stream and when the answer's type is spelt another way, an answer with a tools list is filtered by its shape, whatever its id is spelt or says, whether the client accepts gzip, whether the event stream splits it over several lines, and whether a GET resumed the stream; the relay refuses a request whose id is still waiting on stdio; waiting asks are bounded for the whole relay. An HTTP client that hides its descriptors (not dumpable) can be asked about again: it is placed by exclusion when it is the only such process, and refused as before when it cannot be told from another. The relay places a peer with one `sock_diag` lookup instead of a read of the kernel's TCP table, and an HTTP connection searches for its process once. No record change (minor 41); an older reader reads the new lines as the reset and the revert they look like.
- One by-id history of a run's asks. The receipt, `tego status`, the dashboard and `tego ask` pair an ask with its answer by one rule: the first ask of an id opens the question and the answer pairs with it. A repeated ask line ("an ask was recorded twice") and an answer with no open ask ("an answer has no ask before it": before its ask, to an id never asked, or a second answer) are malformed: they are not counted as an ask or an answer, and every reader says so in those words (the receipt's coverage codes `ask-repeated` and `answer-unpaired`, status's ledger anomalies, the dashboard's refused lines and "Not counted" rows). The receipt's cost on the Receipt tab is priced with the machine's table as `tego receipt` prices it, a capture note links to the capture gap lines, and `tego receipt` and the run summary break long lines at a terminal's width. No record change.
- Rules in force and rule-hit counts. An `exec.allow` entry with command words (`git status`) counts the allowed lines that name it, not every exec of its program, and a constrained tool's refusal of an unlisted command (`exec.args[git]`) and the run's own harness-hook grant now have rows to count on. MCP servers (a Programs row for a stdio command, a Network row for a URL) and `exec.privileged` entries are listed, where only a note was. At tier cgroup with no decision plane the unix-datagram residual below Linux 6.7 is listed. A view read from the file's text that extends a profile states no default over rules it did not read, and the view names the profiles the run merged and where each was read. The Rules page says where the run shown started when a rules file's runs started in more than one place, and the line page lists the rule changes made from it. No record format changed.
- `stall_after` no longer counts Tego's own latency: while the forwarder holds a model request on its way out (its approval, route and credential decisions, its connect and TLS handshake, the first of which loads the system trust roots from disk), the run counts as held, as during an ask or a pause, and the clock restarts when the connection to the model is ready. A busy disk made that first load take over two seconds and ended a run with `stall_after: 2s` before its request had left Tego. A model that answers and then goes silent still stalls the run, and a connect that never completes still ends at net/http's 10 s bounds (`TestIntegrationATegoSideDelayBeforeTheRequestIsSentIsNotAStall`).
- The rule editor tells a person the compiled comparison's direction, not the file text's. A pure refusal (`fs.deny_read`, a pattern, a "never allow") reads "narrows" and needs no confirmation; a program spelled twice reads as the no-change it is; an entry a profile also grants says "No change"; a family the comparison cannot order is "mixed" and never narrowing; and a change that cannot be compared is not proposed. The comparison now orders the refusal side of the filesystem families, held to the decision engine by a property test. A "never allow" for a name that is not there yet says so before it is offered (the compiler refuses a refusal of a missing name), and one at a wider level than its ask scope is refused when a write entry beneath would still allow its subtree. A compile diagnostic in a profile names the profile, its file and the line. "Apply now" and "Also apply now" write the journal's begun line before placing a block, and place nothing when the journal cannot show it. A change that cannot apply to a running run says it is in force the next time the agent starts and gives the line that starts it. The contract check's 503 page names which case happened. A held write is a write in `tego ask` and Compare. The Change rules hints and live box use plain words. A pattern entry says it covers the files that exist when the agent starts, "Act on this" takes the compiled direction too, a sentence never says "No change" beside a family that cannot be ordered, and the restart line hides a credential-looking value in the recorded command.
- Dashboard live updates: the MCP tools and Model routes pages follow the ledger in place (a `content` live region, the existing region cache and live-state revisions, no new polling); an opened Logs row follows the state behind it from its revision (the panel's ETag, answered 304 while unchanged) and is merged in place, keeping focus, a closed field list and the reader's place; a grouped Logs view that skipped a refresh lower down catches up when the reader scrolls back to the top, and every Logs view now says what follows the record and what does not; a run timeline row's details open in place under the row (Enter or click on its link, focus into the panel, Escape, Close or Back close it and return focus to the link; the link still opens the line's page without scripts).
- Undo, Redo and live blocks. An Undo that lifts the live blocks a rules change placed now lifts only a block it can show that change made: the journal keeps, with each placement, the serial of the add that made it, and the lift is made only while the run's overlay still names that add (a block a person lifted and placed again, or held before the change asked, stays). A block placed before the journal kept serials stays too. Undoing an Undo (a Redo) now puts back the blocks that Undo lifted, by the same rules. A lift is journaled before it is made, and an Undo whose own journal line failed lifts nothing, so no lift is in force that the journal does not show. The dashboard's lift confirm is bound to the overlay serial its acknowledgement was made for under the overlay's lock, so a change made by another writer in between refuses the lift. The launcher drops a timed block's boot-time pin and its expiry mark once no block of the overlay carries the limit, so a 24/7 run's two maps no longer grow for the whole run. The journal gains optional live-outcome fields (`by`, `serial`, `held`, `pending`); the journal version and the record minor (41) are unchanged, and an older reader reads each new line as placed, not placed or lifted as before, never as allowed (`internal/rulefile/doc.go`).
- Words and labels on the run and line pages: a held write reads "write to", not "open" (one op-word source, `linewords.AskOp`); the line page's live-block labels say Program, Destination, File or folder instead of the raw key; "Decided by" is said once and the target uses the run's `~/` like the headline; a live mark on a watched run reads "Marked live at … : recorded only, not enforced" on the run page, Logs, the CSV and the line page; the line page's action panel is headed "What to do about this"; a long computer name in the header has a "Whole name" control (visible, selectable); on a phone the exact-target box of a request card is capped at about 8 lines and scrolls, and a queue row shows the start of a huge target. The receipt files an unreadable model-route overlay under its own coverage code `model-routes-kept`, not under missed actions: the routes read last stayed in force and no action went unrecorded (an older reader still reads the why as a gap)
- Logs: a time range set as "the last hour" is pinned to the times it means when it is set, shown as absolute times with a Move to now link, so a refresh no longer slides the window; the Host filter and facet find destinations that were only ever refused (a first delivery a person denied or that timed out); the CSV and the page say the same verdict, action and reason for every line (an answer line read Recorded in the CSV and Allowed or Denied on the page); `kind:change` asks for the rule changes directly; a filtered page with no event line still shows the rule changes of its window; and rule-change rows refresh when a rule changes, not only when a line arrives.
- A launch's `run_start` records the kernel limits its scope holds as `applied_limits`, read back after they were written (`cpu_max`, `cpu_weight`, `pids_max`, and new `memory_max` and `memory_high`), not only the contract's words for them; revision 41, no new revision. An adoption's block keeps its three members as written
- An MCP answer or event-stream message the relay drops for its size, and a model-route overlay the forwarder cannot read, are gap lines in the record, not only a log line: `mcp-response-oversize` and `mcp-stream-oversize` (what=record, the server, the size and the limit; at most 16 per server, then one counted line), `model-route-unreadable` (what=enforce, once per state). The receipt says so in its coverage (`messages-dropped`, `model-routes-kept`) without calling either a missed action. No new record revision
- A UDP datagram's `net` line carries `op: send`, and the receipt separates the attempts that sent from those that only connected (`datagram_sends`, each place's `sends`); a datagram to port 65535 is no longer folded as a route probe. A UDP connect has no op, as before
- When the dashboard reads more runs than it shows (the run limit), runs whose record files carry the same modification time are now left out by a fixed order (the greatest run IDs are kept) instead of the order the directory listing and the sort happened to leave them in: a kernel that stamps files written within one clock tick alike (a Debian 13 6.12 guest did) made the run with the waiting request fall outside the limit at random, so the page said it could not tell whether a request was waiting where another machine counted it. The page already refused to claim a count it could not back; the same ledger now keeps the same runs on every machine and every look.
- The dashboard's ledger reader no longer serves old lines for an events file rewritten at the same length within one tick of a coarse kernel clock (kernels before 6.13 give two such writes one mtime and ctime): a file looked at within two seconds of its last change is checked by the digest of its last bytes at the next look, and read again from the start when they changed. Found by `TestStoreRefreshRetainsEveryRefusal` in a Debian 13 guest.
- Long dashboard state chips and compact page labels wrap when text spacing is enlarged; expanded mode comparisons stay in one phone column. Waiting-band Details selects the exact request, with existing anchors retained. Long desktop run names fit their tables; proposed contracts wrap and have keyboard access. Receipts print with stable light colours and without live controls. Waiting restriction chips remain still.
- Dashboard browser chrome now follows the selected Light, Dark or Auto palette; the signed-out page retains media-based fallbacks with scripts off.
- A write entry's other names count as the same grant, and every deny rule follows the file under every name the mount table gives it: with your home or project bound somewhere else (a container volume, WSLg's `/mnt/wslg/distro`), a protected file in it (`.git/hooks`, `.git/config`, a `deny_write` entry) can no longer be written through the other name, a `.env` or a file a `deny_read` glob matches that appears during the run is refused under every name, and the record no longer says "refused" for a write the kernel allowed through the other name. `tego block` covers the other names a blocked path has when you add the block. A contract tego cannot keep is refused at compile with the file and the other name: one under `fs.reads: direct` whose denied file is readable through another name of a write entry, and any contract when the mount table cannot be read or cannot list every other name of a denied file. Mounts made after a run starts are not seen. Unit-tested; not yet run in a guest.
- Every command that reads a rules file reads it through one check of the file system it is on, so `tego run <name>` (a project's `agent.yaml`, `.tego/agents`, your registry), `tego rules edit`, `tego start`'s own-rules step and the general policy layers refuse a rules file on the Windows drive as `tego run <path>` does. A FUSE file system tego cannot look up is refused too.
- On WSL, any one sign of WSL (its kernel name, `/run/WSL`, its interop registration) is enough for tego to hold readiness and refuse WSL's launcher; a relaxation needs two. A distribution with interop turned off shows only its kernel name and is now held, where it was taken for ordinary Linux. Not yet run in a WSL guest.
- A TOMOYO update counter moved without any policy being activated no longer refuses every held file open at the root tiers (cgroup and bpflsm): their launcher reads TOMOYO's profile between two reads of the update line and admits a held open when no mode in any namespace, profile or category is `enforcing`; a profile it cannot read or parse, one that enforces, and a policy written while it read still refuse (the proof is tried again up to three times when the update line moved while it read, and reads only from securityfs). Tier landlock, whose launcher is the invoking user and cannot read the profile, keeps the refusal and the message now says why. `tego doctor` says which proof admitted.
- On a run whose kernel decision plane decides file changes (tiers cgroup and bpflsm, `decision_plane` `lsm` or `fmod_ret`), a live `path`, `read` or `write` block is now put in force in the kernel too, not only by the supervisor, which never saw the write opens, creates, deletes, renames, truncates, attribute changes and reads the plane decides: the launcher keys rows in the plane at the objects the block's path names when it lands and refuses each action at or beneath them, under the block's own rule (ADR 0124, amended 2026-11-21). Such a block reads "in force" again, a read block may be placed on such a run, and the Rules page offers write blocks there. On such a run a block follows the file: a hard link made before a block on that file stays blocked, the rename or removal of a folder or link its path runs through is refused, a read block also refuses deleting or replacing the blocked file, and a block on a path that does not exist yet refuses making it (and its first missing folder). A block the plane cannot hold whole refuses its whole class of action instead. A descriptor opened for writing before the block keeps writing, as at every tier.
- Under `net.assurance: kernel`, a run that holds its opens (`fs.reads: held`, or `gate.completion: held`) no longer keeps the filter's `ENOSYS` for every `recvmsg`, so its interface lists work too: the plane passes the open deputy's control receives by its thread-group id and start time, which the launcher writes into the run's slot before the run is armed, and refuses every other task's (`EACCES`, rule `socket-import`). `tego compile --test` says the same for both.
- `net.assurance: kernel` no longer breaks the C library's interface lists (`if_nameindex`, `getifaddrs`, Node's `os.networkInterfaces()`) where a decision plane runs the run (tiers cgroup and bpflsm): the plane refuses a receive on a unix socket that carries a control buffer in the kernel (`EACCES`, rule `socket-import`, one ledger line) instead of the seccomp filter answering every `recvmsg` `ENOSYS`; a UDP or TCP control receive passes, so a route socket's reply is read and no descriptor or pidfd can be received. `recvmmsg` and `pidfd_getfd` stay `ENOSYS`; a run with no plane, and a run that holds its opens (`fs.reads: held`, or `gate.completion: held`), keep the filter's answer, and `tego compile --test` says so. The guard covers `SCM_RIGHTS` and `SCM_PIDFD` receives; `getsockopt(SO_PEERPIDFD)` is outside it. A refused control-bearing `recvmsg` now returns `EACCES`. New plane hook `socket_recvmsg` (31 hooks), slot flag `TEGO_SLOT_IMPORTS_DENIED`; the committed BPF objects are regenerated.
- On a run whose kernel decision plane decides file changes (`decision_plane` `lsm` or `fmod_ret`), `tego block <run> write` and `path`, `tego block --list` and the dashboard no longer say a block is "in force": they say it is partly in force and name what it does not cover (the file changes the kernel decides, which never reach the supervisor that applies a live block). The block is placed as before and still refuses what reaches the supervisor.
- The dashboard's Agents page is finished: it is in the navigation ahead of Overview and the guide's Pick step opens it. Each recorded run and each program a saved scan saw is a row that opens its own detail (where it was recorded or seen with its folder, first and last seen, `Relationship`, the record check and next step, related runs linked, each stage with what is and is not known, copy buttons for the commands), and a stage is shown as reached only for a recorded run, never from a scan. The scan's notices and repair steps, the store warnings and the limits stay on the page, the phone shows the list first and less per row, and with scripts off every part is in the page. Forget removes one remembered discovery from the page's memory after a confirm; it never changes a run record, a saved scan or a contract.
- The Agents page uses plain words: its notices, section titles and times are short sentences with the time shown as a local time, "1 day ago" has the right singular, and "Refused today" says "At least 4 refusals today" once with its caveat in one line below.
- The Agents page words the scan's limits and Tego's own-files caution in plain sentences (the `tego scan` command keeps its operator wording; both read one table), each recorded run's row shows how many actions were refused in it (the number its run page shows, at least when its record was read only in part), its lists are announced as lists in Safari, and its styles keep to features Firefox and Safari have.
- `tego uninstall` now removes Tego on Linux and macOS (Windows already had it). Before this there was no command and no removal steps for either, and `tego start` and `tego dashboard` left user units behind. It lists what it will remove and asks once (`--yes` for scripts): the `tego-dashboard` unit and the clean-up timer, the installed `tego` and the `tego-control` beside it (each checked by name and content, a build in a source checkout is left), the line `tego start` added to `~/.bashrc` and the installer's `PATH` line (only that exact line, with a backup beside the file), and the dashboard's own files. Your records (`~/.tego`) and contracts (`~/.config/tego`) stay unless you answer yes to a second question, and your `tego-agent@` services unless you answer yes to a third; both default to no and have their own flags (`--delete-records`, `--stop-agents`), so `--yes` never deletes proof or stops an agent. Records are not deleted while a session runs. A system-wide install is never touched: the command prints the exact `sudo` lines (a unit file name outside systemd's usual characters is quoted in them). On a Mac the installed command runs the removal on the Mac (command, `PATH` line, dashboard tunnel, Tego inside the VM) and deletes the VM, with the records inside it, only after its own question. The Mac steps are tested against stand-ins for Lima and SSH, not a real Mac. The install guide, README and commands page have a Remove Tego section.
- `tego scan --check` no longer answers "none observed" when it cannot see every process. A scan inside a nested PID namespace (`unshare --pid --fork --mount-proc`, a container) listed only that namespace's processes and exited 0: its fresh `/proc` shows one `NSpid` entry per process, so the namespace line proved nothing. The scan now reads its own PID namespace through `/proc/self/ns/pid` and, unless it is the initial one (or cannot be read), answers unknown (exit 125) with the `outer-pid-namespace` exclusion, in basic and advanced scope. And a process the basic scan cannot attribute to one uid is now uncertainty, not absence: a setuid program run by the caller (real uid the caller's, proc owner another's) was skipped as another user's because only the owner was looked at; the scan now reads that process's four uids (no other file of another user's process), counts any mix that includes the caller's as unknown (exit 125, the process named as a `status` source with reason `owner`), and treats a denied uid read (hidepid) the same way. Two kinds of mixed process are not uncertain, because they are root's: `sudo` and `su` run with the login's real uid, effective root and a proc directory root owns, so a scan run as root reads and judges one like any other (an agent among them is listed), and a scan run by anyone else counts it as another user's, as it does every process of root's ("Not looked at: other-users"). A mixed process another user owns, and one whose effective uid is another non-root user's (a setuid copy), stay uncertain. The scan guest checks' table now says a writable `/etc` refuses on the passwd route (exit 125, `scan-not-performed`), as its passwd paragraph and the product do. The two guest rows are owed again.
- The dashboard's live refresh no longer takes away what a person is using: a block that grew in front of the answer controls of a waiting request (a late note, another line) made the merge hand the controls' place to the wrong block, so an open "More choices" closed and a click on "Allow for this run" or "Deny for this run" could land on nothing. Blocks without a name are now matched to the same kind of block (its class) before by position, so open disclosures, typed text and focus stay on every page that follows live. A click on a request answered or ended in the meantime still says so in a plain line. The setup guide's Ready panel now also says what to type if the dashboard did not open (`tego dashboard`, on Windows in PowerShell or cmd).
- A very busy machine no longer reads as "a disconnected or stuck mount". The five seconds a location check had started counting before Tego's checker process existed, so starting the checker on a loaded machine used them and the page said `cannot tell: this location does not answer (a disconnected or stuck mount?)` about a place nobody had asked. The checker now has its own 30 seconds to start and report that it is ready, and the five seconds start when it does. A checker that does not start in time says `cannot tell: Tego's checker did not start in time (the machine is very busy); try again`. Nothing was changed, and asking again is safe. A location that really does not answer still says the old words after five seconds.
- Compiling a draft no longer spends the five seconds of a location check, and a draft compile that did not finish no longer says "the new contract does not compile". The checker stops the five seconds while it compiles, the compile has its own 30 seconds to start and then its own three, and one that runs out of time says `cannot tell whether the new contract compiles: the check did not finish in time (the machine is very busy); nothing was written; try again`. A checker that could not start at all says `cannot tell: Tego's checker could not start:` and why, a caller that gave up says `cannot tell: the check was cancelled before it finished`, and when every checker slot is held by checks that are stuck on a location the next check refuses at once and says how many are stuck, rather than waiting and blaming a busy machine.
- A busy machine no longer reads as "a disconnected or stuck mount". When a checker's five seconds at a location run out, Tego reads the checker's own scheduler counters: a checker that spent at least half of the window waiting for a processor is given another five seconds, while it stays starved, up to 20 seconds in all for a check or a page, and one that is still starved then says `cannot tell: Tego's checker was too slow to finish (the machine is very busy); try again`. Only a checker that was blocked says the location does not answer, and one whose counters cannot be read (a kernel without `schedstat`) says `cannot tell: the check did not finish in time (a stuck location, or a very busy machine)`. The draft compiler's child gets the same treatment, and a compile that could not run (a full compiler slot, a compiler that could not start or died) now says so instead of "does not compile". A checker that was running on a processor for most of the window, a long operation of its own, is treated the same way and, past the cap, says `cannot tell: the check was still working when its time ran out; try again` instead of blaming the location. A checker that is blocked waiting for this computer's own disk or journal (a disk that is very busy or nearly full) is given the same extra time as a starved one (up to 20 seconds in all, since a slow disk answers in the end) and then says `cannot tell: this computer's disk did not finish writing in time (the disk is very busy or nearly full); try again`, from a fixed table of what the kernel says the checker waits in; a wait in a network or user-space filesystem, or one Tego cannot read, keeps the stuck-location words. A dashboard page whose checks waited for a free checker slot (all 32 held by other commands' stuck checkers) used to wait the whole 30 seconds and have its connection closed with no response; a page's checks are now bounded together by the server's write deadline less five seconds, so the page is answered with the words of what happened. When all 32 slots are held by other commands' checkers and every one of them is older than any check can live (115 seconds), they are stuck by definition: the next command or page is refused at once with `N earlier checks are still stuck on a location that does not answer`, not after the wait; a younger holder, or one whose age cannot be read, keeps the wait.

### Security

- Root-only local approval now relies on v0.1.3's mount-identity refusal of write and ask grants reaching
  cgroup filesystems under any visible name. Before enabling `owner_only`, stop and restart every run
  started before v0.1.3. Activation cannot establish host-wide live-run versions across configurable ledger
  roots and does not check them. Mounts made later by host root remain outside this claim. Synthetic
  alias regressions cover compilation; kernel compile/run-start proof is owed in a guest.

- A run that passes its ledger size limit (`record.max_run_bytes`) now says by how much: the lines already queued when the limit trips are all written (a refusal is never dropped to keep the size), so the record ends with one gap line, `what=limits`, `why=ledger-ceiling-overshoot`, `count` the bytes past the limit, just before `run_end`. The limit line still says what the ledger held when it tripped.
- A machine with `gc_interval` set now gets the retention pass without a `tego run` start: `tego start` and `tego dashboard`, when they start the dashboard, also make a daily user timer, `tego-gc` (`tego gc` with no flags, the start's pass, the machine's own retention, never a run whose lock is held), made up after a day missed. A timer that is already active, including your own copy of `examples/systemd/tego-gc.timer`, is left alone. An agent that runs for weeks no longer waits for a start to be pruned around.
- The Unused permissions tab no longer shows a contract as not compiling for up to five minutes after the program it names was installed on the dashboard's PATH (or compiling after it was removed): each PATH folder's identity and times are in the cache key. A live block's time limit that passes now moves a run page's live regions at the next refresh; the page used to say "nothing changed" until a ledger line or a file moved.
- The Rules list no longer keeps showing a contract as editable after a folder above its own became a link (its writes are then refused): the list's memo of each contract is keyed on every folder above the file, not only the file and its own folder. Every plan and save still reads the file through the write guards.
- Where the kernel has no TCP socket lookup (`tcp_diag` not loaded), connections that arrive together now share one read of `/proc/net/tcp` instead of each reading it whole: 64 connections against a table of 100,000 sockets took 2.35 s before (64 reads) and 0.15 s after (2 reads). Nothing is kept between reads, so a new connection is never answered from an old table.
- The Linux installer's last line, the next command (`tego setup` or `tego doctor`), now names `tego` by its full path while the install folder is not on the PATH of the shell the installer ran in, quoted when a shell would split or expand the path; the installer cannot change that PATH, so a bare name printed right after the install was `command not found` until the export line was typed. With the folder on PATH the line stays the bare name, and the export line is still printed.
- `tego receipt` no longer prints the reader's home as `~`: a receipt read later, by another user or on another machine, showed a folder that was never the run's as `~/...`. The text receipt folds `~` only under the home the run recorded (its machine baseline evidence's owner home) and, when the record names none, prints every path whole and says so in one line. The JSON receipt is unchanged.
- Live Logs now follows new lines by an append cursor instead of the newest row's sort key: a line appended to a run whose recorder lags another's, stamped earlier than the newest row on the page, was never brought in until the page was reloaded. The page carries the read model's revision and each open run's newest line (`data-tail`), and `/logs/rows?tail=` returns the rows with a line appended since. With more than 64 open runs the sort-key cursor remains the fallback.
- `tego run` (at its start) and `tego gc` (not `--dry-run`) give the owner's rights back on the run directories of your live, orphaned and earlier runs, each with its `events.jsonl`, lock file and `blobs/`, when an agent took them with `chmod` (owner bits only; a group or other bit is never touched; another user's directory is left). `tego status`, `events`, `receipt` and the dashboard, which change no mode, now say the path, its mode and the one command that fixes it, `chmod -R u+rwX '<run directory>'`.
- The Logs Host facet and a host filter now tell apart the same IPv6 address on two links (`fe80::1%2` and `fe80::1%3`): the host keeps its zone, a filter naming a zone holds that link's lines and one naming the bare address holds it on every link. A live block is still by address, whatever the zone, so a block on `fe80::1` covers both and nothing a block covers is shown as routine.
- A refused connect to an address the run reached only under a CIDR entry (its line names no host) is no longer shown as routine (`the run also reached this host`) while a live block names a host: the block is enforced on the addresses its name resolved to, which the record does not keep, so the group is kept and carries a plain sentence saying the name is unknown.
- A background job-group interrupt (`kill -INT %1`, or a group-directed INT) no longer reads as two interrupts for a run started in a user scope with piped input: the outer process forwarded the INT to the launcher that had already received it, and the launcher's double-interrupt rule escalated at once. The two processes now count the INT and QUIT arrivals each saw over a private socket and the launcher takes the larger count since its last question, so one person's Ctrl-C, whichever way it was sent, is one interrupt and a deliberate repeat is still two (no time window; ADR 0142). Two deliberate sends to two different processes within microseconds count as one. The real-launcher result is owed in a guest.
- A boundary adoption's run_start now records the kernel limits it wrote into its scope as `applied_limits` (`cpu_max`, `cpu_weight`, `pids_max`, as written; record minor 40): the limits block carried budgets only, so a reader could not tell which ceilings the agent was held to. A record-only adoption and a launch keep their revision and bytes; a reader that predates minor 40 does not read such a ledger, as with every earlier revision.
- Every run now writes record revision 41 from its first line (ADR 0157): a live network block can come at any time after `run_start`, which declares the revision, so no run waits to see whether one happens. The revision includes everything 39 and 40 allow. It records two more things. A live or restored network block by name now names, on its gap line, the addresses it was enforced on (`live_block.addrs`, at most 32, and `addrs_more`): the dashboard says that a refused connect to one of them is that host (its row shows the blocked name), and keeps "name unknown" only for a block whose lookup answered no address, an older ledger, or a list past its cap; `tego receipt` lists each block with its addresses. And `run_start.home` is the home directory the run resolved, so a receipt folds `~` for every new run, not only a run with a machine baseline. Older ledgers read as before; a build that predates revision 41 does not read a ledger a newer build writes, as with every earlier revision. The addresses are those enforced when the line was written; a later lookup of the name may add others.
- A lift or a grant of an Adjustable run's fence entry can now carry a note: `tego lift ... --note "text"` and one optional text input on the dashboard's lift confirm. The note is at most 200 bytes of printable text, signed inside the lift's MAC (so it cannot be changed after the lift was signed), written by the launcher on the `live-rule-lifted` line as `live_block.note`, and shown, never acted on, by `tego lift`, the Rules page's fence row and `tego receipt`. It is part of record revision 41, which no release has carried, so there is no new revision. A run whose launcher does not say it reads a note refuses the note in words and asks nothing; a lift with no note is never refused for that.
- `tego rules history <agent | file> [--json]` and `tego rules undo <agent | file> [<id>] [--yes]` now exist: the dashboard's change history and its Undo, from a terminal, through the same rule service, so a terminal and the page list the same entries in the same words and offer Undo on the same entry. An undo that only narrows needs no confirmation. One that lets the next run do more (undoing a widening, a mixed change or a free edit) prints what it does and asks for `undo` to be typed at a terminal; with no terminal it needs `--yes` and exits 2 without it, a wrong word is exit 1, a file that changed since the change was written is exit 1 "changed since", and from inside a run such an undo is refused (exit 1). A guard or I/O failure is exit 125. The journal says the undo was made through `cli`. An undo from a terminal does not lift the live blocks the change placed on running runs: it lists them with the `tego unblock` command that ends each.
- `tego dashboard` and `tego start` now reuse a running dashboard: it was restarted on every call, signing out open tabs, because the dashboard recorded its program as the inode of the sealed copy its control binary runs from, which is new on every launch. The dashboard now records the SHA-256 of its own bytes and a new one is started only when the program it would run has other bytes (or the running one is an earlier tego's).
- The Windows installer's closing hint now works in the shell the person is in: it says to open a new terminal and type `tego start`, then gives a PowerShell line (with `&`) and a cmd line (without it), the shell the installer was started from first.
- A cold `tego start` on Windows that does not confirm Linux's user scope in time now says to type the same command again (nothing was changed by the try) and, if it fails twice, the command that shows why, instead of pointing at `wsl --status`.
- On Windows, the run's start line no longer prints a dashboard link that does not work from a Windows browser; it says to open it with `tego dashboard`. The held-label note is shown once for a machine state, not on every run (WSL printed it each time). The guide says `python3 bot.py` is only an example and names the command that works on the test project. An approval given in the dashboard is recorded and shown as answered in the dashboard by the signed-in person (through its relay from a Windows browser), not as the dashboard's own process; the answer line's `by` gains a word after the uid and pid, as it already could for `always`, and no record field changes.
- The install guide, README, quickstart and tiers pages say what the Windows walkthrough of the ordinary build proved (all six beginner steps, Allow once in the browser, PowerShell 7 and cmd) and what it did not (a real keyboard and mouse, a signed executable, a real HTTPS release, ARM64, Windows 10, PowerShell 7 and cmd on a PC with no WSL, real agents).

- On WSL, the run-membership rule is on in ordinary builds where WSL shows two of its marks (the kernel release, `/run/WSL`, a `WSLInterop` entry): `tego setup`, `run`, `watch`, `test` and `machine test` proceed from an ordinary WSL shell through a user scope they open for each run, and `tego doctor` no longer lists the four containment checks as unproven or returns finding status 1 for them. The four rows passed in a Windows 11 guest first (WSL's program launcher refused inside a run, the home folder's second name, the Windows drive, the GUI and audio sockets). A distribution that shows only one mark (interop turned off shows its release alone) keeps every hold and restriction. Not proven: a guest run of the released build with the rule on, the rule where `/proc/self/ns/cgroup` is a FUSE file, the shell of a terminal window, and mirrored networking for the Windows browser.

- A machine config location that is not a place (a `TEGO_CONFIG` value with a control character, a `..` or a relative form) is now named by the variable everywhere it could still show: `tego doctor --json`, the dashboard's baseline banner, the "baseline is UNKNOWN" compile error and the rules that protect the file, and a folder on the way to it that fails the trust check is called "a folder on the way to the file $TEGO_CONFIG names" instead of being printed. `tego dashboard` reuses a running dashboard only when it runs this very program file, now also by its change time and read from the running dashboard itself; when Tego cannot read its own file it starts the dashboard again once and says why. A page that waits on a contract check no longer starts the check's helper as a caller nobody classified. A bare command name searched along a `PATH` folder you may not search, an exec entry you may not stat and a git folder you may not search are now reported to the root-tier prediction as unknown instead of as not found.
- A timed live block is no longer dropped early when the wall clock is stepped forward by more than a day: its boot-time deadline is kept in `live-block.json` with the boot it was made in (`boot`, `until_boot`), and both the run and every writer end the block by the same two clocks. A wall clock stepped back keeps a block in force longer, never shorter.

- Timing checks exclude uncharged time from nonblocking measurements and log disturbed CPU samples while retaining blocking waits.

- Scan accepts verified root-owned account-file links during caller identification and names the account-file repair when that placement cannot be verified.

- Commands to run as root or another account are withheld when an installation folder has a writable group whose membership cannot be established, or that can be joined with a group password Tego can read; the refusal names the folder, group, cause and `chmod g-w` repair. A group password set only in the shadow group file is not visible to a normal user. The check reads local account files only, within two seconds, and asks no directory service.

- `compile --test --tier cgroup,bpflsm` includes future-file name rules when run by a normal user. Where a folder that user may not list or search hides part of what root would read while compiling any part of the contract (a pattern's matches, a link's target, a `.env` file, a row's own path, where a write or exec entry leads, the folders and git configs the protected-file search reads, the host IPC folders, the built-in socket paths, the loaders' and a tool's helper folders), the root-tier answer is `cannot tell without root` (exit 125) instead of an allow; `compile --exec` prints the same answer and exits 125 in that case. The native-code scan, which only warns, names a folder it could not list.
- `compile --test` and `compile --exec` no longer answer `cannot tell without root` for every file-backed row of a root tier because one folder only root can read was met (a stock Ubuntu cloud image's `/run/user/<uid>/systemd/inaccessible/dir`, a server's `/run/podman`). A folder of Tego's own built-in lists leaves unknown only the rows about a path at, beneath or above it, a loaders' or a tool's helper folder only the exec rows; the other steps keep every file-backed row unknown, since what root finds there can name any path. The compile now names each such folder once on stderr, says which rows that leaves unknown, and prints the one command that gives root's answer.
- A message never prints the value of an entry of the agent's environment (the contract's `env` entries, harness entries, credentials, another process's environment), whatever its length: it names the variable, or the entry's position when the entry has no name to tell from its value.
- A value that failed validation is not echoed either: the message names the variable, says what is wrong and how to print it. A folder or file Tego resolved from a location variable (the settings file `TEGO_CONFIG` names, the runtime folder) and a validated run id are printed where the message is about them.
- `tego rules edit` says why the editor did not finish (not found, permission denied, its exit status, the signal that ended it) and no longer blames `EDITOR` for the `vi` it tries when no editor is set.
- The rule table names a `PATH` inherited from the caller's environment instead of printing it; the JSON form carries the value. `tego agents` reports an observed `TEGO_RUN_ID` only when it is a run id.
- Executable paths that hold a space are one program on the dashboard: the Block action, the comparison and the agent recognition read the recorded path and arguments.
- Executable refusal groups use the program name, including recorded executable paths containing spaces.
- Restored live fences keep their refused hosts outside the dashboard's Routine fold; its explanation names the live-block and restored-fence exceptions.
- Mixed watched and enforced Rule facets identify watched lines explicitly.
- Built-in socket contradiction advice names the runtime directory that matched the socket.
- Learn withholds suspicious sockets with a conditional built-in warning when the recording lacks enforcing context, and explains how to check on the agent's machine.
- Unverified single-file memory backing emits the same unknown-backing warning as other unsupported backing.
- Record-only notices and learn advice describe the rules in force and the limits of recording.
- Older product descriptions use rules terminology and include all AI agents.

### Fixed

- Under the system `local_roles: owner_only` floor, a launch the floor cannot admit (a `setuid` contract, recording off, a launcher that is not initial-namespace root) is now refused by the preflight, with exit 125 and the floor's words, before the kernel probe; it used to wait behind a cold BPF probe and teardown that took 20 to 38 seconds on a fresh machine. Whether the selected tier enforces is still checked when the run starts.

- Root-only local approval (`local_roles: owner_only`) review fixes: the floor binds only runs launched after it is set (a run already live keeps same-user approvals until it ends, so stop every live run first), and `tego doctor` lists the running runs of the selected ledger root that started without it; an answer is shown as root's, and accepted by the record verifier, only in a run whose run_start carries the floor (every answer of such a run says who decided it, and no answer of another run carries an actor or a system cause); the dashboard refuses to start when its real or saved user id is 0, not only its effective one; and a root answer that names a `via` is refused before it is selected instead of failing the record append and ending the run.

- `tego start` accepts executable absolute program paths; relative program paths ask for a program name or full path, and invalid paths get an accurate message.

- The dashboard keeps four of its 32 contract-check helper slots for checks that do not come from a governed program, so a burst of a governed program's Previews (or `tego contracts` run inside a run) on a busy machine no longer makes the person's own Save answer "The dashboard is busy". A governed burst alone is still refused as before.
- A governed program's Previews can no longer make the person's own Save miss its deadline by using the CPU up: the helper started for a governed request runs at the lowest CPU priority an unprivileged process may take (nice 19 and the idle scheduling policy where the kernel allows it), the person's helper keeps normal priority, and governed compilations never take the one compiler slot kept for a person's check (the Save answered "busy, try again" when governed compilations held both). Found as `TestBuilderGovernedPreviewsCannotEvictPersonsReview` failing when the machine was loaded; the test now runs the Save under 24 governed Preview loops on one shared CPU.
- A run started with sudo prunes the rule-change journal again when a directory above the ledger root may be searched but not listed by the invoking user (mode 0711): the directory walk opened every directory above for reading, so the prune and `tego gc` stopped with `open-directory ...: permission denied` and left the journal as it was. The walks to a contract's folder, the `--status-file` directory, the dashboard's remembered discoveries and doctor's probe cache had the same requirement; every one now needs only search permission on the directories above, as opening the whole path does.
- On kernels that list TOMOYO as active with no policy loaded, including stock Debian 12 and 13, v0.1.3 refused every held file open (`held-label-unavailable`): approvals on file reads, held reads and the dashboard's demo did not work there. They now complete while TOMOYO is unused. Any TOMOYO policy update since boot (including initializer domain creation by a container or local user in another mount namespace), a domain other than `<kernel>`, unreadable TOMOYO files or a kernel built with `CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER` still refuse (GAPS B14, C74, C75).

- Mac installer messages explain Lima and Homebrew, give the installer retry command, and put opening a new Terminal window first in the next step. Dashboard and socket messages give clearer next steps.

- The Mac installer restores saved terminal settings on failures and interrupts as well as success, preserving the exit status.

- The Mac VM template has only digest-pinned images for Apple silicon and Intel. Failed image downloads explain
  removing the incomplete VM before retrying; only a not-found error suggests updating the installer.

- `tego shell` on a Mac reports usage when given extra arguments instead of silently ignoring them.

- The Mac command reads the dashboard port from its link. If another process holds a nondefault port, it explains
  that Lima forwards VM ports to the Mac itself and Tego's own tunnel is set up for 8484. Use 8484, or stop the VM,
  run `limactl edit tego`, add `- guestPort: PORT` with `ignore: true` under `portForwards`, then start the VM again.
  Other dashboard ports have not yet been verified on a Mac; Lima's other forwarding rules are unchanged.

- On a Mac, a dashboard tunnel or browser failure after the guide prints a retry command and still opens the project shell. A failed guide keeps its exit status.

- Rerunning the Mac installer refreshes the Mac command first, then offers a verified guest update or repair when
  the release supports it. Unsupported releases leave the guest alone and finish normally. Replacing a newer
  guest with an older release defaults to no. Existing runs finish with their old executable; projects, contracts
  and records stay in place.

- `tego run` (and every command that loads rules) refuses a rules file, or a file it extends, on a file system whose owner and permissions it cannot rely on: WSL's Windows drive (`/mnt/c`), 9p and virtiofs shares, FAT, exFAT and NTFS disks, and SMB shares. Any Windows program, or anything that writes such a disk outside Linux, could change the rules between runs. The line says so and says to keep the rules file in your Linux home; a project on the Windows drive with its rules file in the Linux home still runs.

- A file a contract denies is refused under every name the mount table gives it, not only the name the contract uses. Before, at tier 1 (landlock) a denied file stayed readable through a second name on the same filesystem beneath a readable folder: a bind mount of the home or of a part of it, a btrfs top-level volume mounted beside its subvolumes, or WSL's `/mnt/wslg/distro`, which shows a WSL distribution's whole root filesystem a second time (measured in a WSL guest: `~/.ssh` refused, the same file read through `/mnt/wslg/distro`). Compile now adds each such name to the same refusal, with the same rule name in the record. Unit-tested; the WSL guest row and the Linux bind-mount conformance cells are to be rerun.

- A shell outside your user manager's cgroup (an SSH login, an ordinary WSL shell) is no longer a blocker for `tego setup` and `tego start` when the commands you run next open a user scope themselves: setup rehearses that entry from your shell, and when it works the "Check this machine" step is done, saying "this shell is outside your user manager's cgroup; tego run, watch and test open a user scope for each run (checked)", and setup exits 0. When the rehearsal fails, the step stays blocked with the reason, and the next step is the one fix (`systemd-run --user --scope bash`). `tego doctor`'s last line and the installer's line over SSH say the same. A shell already inside the user manager sees no change.

- Run membership has three answers. A command that only a process outside every run may use (a change to a run's rules, an approval, `tego setup`, the start of a run from a shell beside the user's session) now proceeds only on a proven "outside"; "inside a run" and "cannot tell" both refuse, and the refusal says which: "a governed agent" only when the process's own cgroup shows a run, otherwise the reason it cannot be shown to be outside. On ordinary Linux, in the kernel's first cgroup namespace, the answers do not change. Where the machine's cgroup namespace is not the kernel's first one, a rule that can prove "outside" is built and unit-tested (ADR 0100, amended 2026-11-18 and 2026-11-19), and **this build holds its "outside" back everywhere it has not been proven**: on WSL in every configuration, `isolateDistroCgroup=false` included, because a run's refusal of WSL's own program launcher has no passing guest proof yet; and outside WSL in a container or a nested system, where the answer stays "cannot tell", as before the rule. So on WSL these commands still refuse, now with that reason, and a run's approval socket there serves no other window. This is not WSL support.

- `tego doctor` prints the shell's own run-membership answer on a `run membership` line wherever that answer is not "outside" or was made outside the machine's first cgroup namespace, with the seccomp mode it read there (recorded, not judged: a guest showed WSL putting a filter on every ordinary shell under mirrored networking). On ordinary Linux, outside any run, nothing new is printed.

- On WSL, a contract that would give a run WSL's Windows launcher is refused at compile with "a run cannot be given WSL's Windows launcher: a program started through it runs outside the run and its rules", naming the entry: a `unix:` allow or ask, or an `fs.write` or `fs.ask` grant, that names `/run/WSL`, a path beneath it or one of its sockets by another name. Unit-tested; not yet run in a WSL guest.

- The filter that every run's processes carry also refuses a new cgroup namespace and a new process-id namespace (`unshare`, `clone`), as it refuses a new mount or user namespace. Only a process that holds `CAP_SYS_ADMIN` reaches these, which a root-level run with `setuid: true` can give its agent; the unprivileged level was already refused them by the kernel. Unit-tested; the refusal inside a real root-level run is not yet proven in a guest.

- A process that connects to a run's approval socket is identified by the cgroup of every one of its threads, and refused when its first thread has exited. Unit-tested, including a real process built that way; the case with an adopted process is not yet proven in a guest.

- Doctor warns separately about four unproven WSL containment checks and withholds readiness; the measured kernel tier remains visible. Setup does not store a ready tier from that report. (Where WSL shows two marks the rule is on and these warnings no longer print: the first entry of this section.)

- User-scope re-entry accepts `machine check` for rehearsal and `machine test` for execution, with the same validation as their direct command forms.

- Doctor, setup and start can rehearse user-scope placement while reporting in the original shell. Doctor and setup accept `--no-scope`; the existing outside-run guard still applies.

- Doctor excludes root tiers before functional probes in a private or unreadable process-id namespace. Auto selection can use landlock; explicitly selected root tiers refuse. Compile and run diagnostics name this namespace precondition instead of suggesting another build.

- Built-in host IPC refusals include WSL interop and GUI/audio servers; enforcing environments omit `WSL_INTEROP`. Unit coverage is present; WSL guest containment acceptance remains open.

- `tego --version` and `tego -V` print the same version banner as `tego version`, including its JSON option.

- Windows installation now uses a checksummed native `tego.exe`, explicit removal consent, registry-preserving
  PATH edits, conditional repair restarts and a stable pinned Ubuntu image. Other WSL2 distributions of the same
  Windows account share its kernel, loopback and numeric identities; root in them remains root over that kernel.
  The guide still refuses the measured default WSL cgroup namespace; installation reports that blocker and
  leaves the verified diagnostics/removal command. **`tego dashboard` on Windows now opens the dashboard in
  your browser** (PowerShell 5.1, PowerShell 7 and cmd, measured in a Windows 11 guest): the native `tego.exe`
  runs a small hidden relay on `[::1]` at the dashboard's port that admits only your own Windows account's
  programs and carries their connections into Tego's Linux as your Linux user; the dashboard's checks are
  unchanged (ADR 0123, "A browser on Windows"). `tego dashboard --stop` ends it. WSL's mirrored networking is
  not supported for the browser dashboard: there `tego dashboard` says why and opens nothing. Answering a
  held request from the browser is still refused by the run in WSL's private cgroup namespace, as the guide is,
  and the terminal's `tego ask` gets the same refusal.
  A detached supervised user unit was stopped by WSL within 23.21 seconds without an attached Windows client;
  unattended lifetime remains open. Windows guest coverage is stated precisely in the install guide; no hosted,
  ARM64 or physical-PC result is claimed.
- Enforcing starts print a `[startup-wait]` note on stderr after about one second while kernel checks and
  program preparation are pending. Fast starts print no wait note. Contract and caller prerequisites, status-file
  eligibility and the chain anchor are checked before probing; the runtime retains its selected-backend checks.
  Cold root BPF starts still pay for actual-program verification and kernel link release; OPERATIONS.md describes
  the answer cache and separate loaded-build linger. Initial five-sample cold medians in two-vCPU, 3-GiB
  kernel guests were 13.746 s at cgroup on Ubuntu 6.17 and 8.207/8.846 s at cgroup/bpflsm on Fedora 7.0
  (host one-minute load 0.98 to 2.24). This cost already shipped in v0.1.3.

- Scan refuses a record whose events name changed during its probe, even when directory timestamps did not advance.

- Retention keeps the busy-lock explanation when its budget expires while reopening a contended journal lock.

- Validate immutable submitted-refund bundle pins in contracts with the native business v1 decoder.
  Run start, adoption and doctor explicitly report activation unavailable until the trusted worker, exclusive route
  and durable admission owner exist. Business-bearing servers refuse legacy relay and HTTP entry.
  CLI run refuses after compilation, before backend selection, cleanup of existing runs or records,
  anchor probing or capture construction. Machine configuration and state-directory setup precede compilation.
  Business declarations no longer trigger the ordinary MCP advice to remove an explicit exec grant.
  This preflight work does not provide an operational refund cap or a receipt of capped submissions.

- Specify business restrictions for one pinned Square refund adapter, including closed validation stages,
  canonical bytes, owner-authenticated state epochs and handwritten expectations. ADR 0151 selects Go inside
  the live relay and an independent Rust evaluator, browser preview and standalone checker; both must pass every
  vector and disagreements must fail the build. The pure evaluators and private kept differential are implemented.
  Browser preview, approval protocol, default build integration and a qualified positive relay path remain open.

- CI receipts can now be signed through a second reusable workflow after complete ended checks. The receipt
  workflow requests no OIDC permission; unsigned callers need contents/actions read only. Only the optional
  second signing call delegates id-token write, with explicit consent
  to permanent public repository/workflow disclosure. Exact receipt and manifest bytes receive detached
  Sigstore bundles; the manifest binds the record digest. Tools, trust roots and release checksums are verified.
  The receipt verifier checks both bundles against independent expectations and pinned trust. The reader must
  authenticate release checksums separately. Root on the earlier runner can still fabricate evidence.
  Disabled signing makes no eligibility API requests; API uncertainty keeps auto unsigned and refuses eligible
  explicit signing. Real GitHub permission delegation, certificate mappings and guest lifecycle acceptance remain
  open; no acceptance row is closed.

- Add binding 2, machine-readable run teardown status for enforcing runs, ended-only receipt checks and a local CI consistency verifier. Receipt checks name edited fields and distinguish unavailable inputs from mismatches; the verifier states that it did not authenticate the checksums file and labels unestablished identities. Binding 1 remains readable without a receipt checksum; the unsigned workflow requires every product check to pass, the seven baseline checks for binding 1 and also `binding` for binding 2. Missing or unknown binding versions and duplicate object keys anywhere in the check file are refused. The receipt workflow now collects teardown status; a separate optional signer adds detached bundles. Guest lifecycle checks and hosted acceptance remain open.
- Add an unsigned CI receipt workflow for all AI agents, with separate run and comparison jobs, fixed collector tools and HOME, a pre-run action copy checked by digests and exact inventory, refusal of declared tool/startup/Git-configuration write grants (including HOME/XDG, system, worktree and pre-launch include files), capped displays and retained diagnostics. Collection keeps the private ledger configuration across child steps and rejects runtime-added filesystem writes overlapping its saved refusal list before issuing a receipt. This check happens after launch and cannot undo earlier effects. Keep the agent job to the agent; later steps consume the workspace it left behind. The fresh job gates from checked files, names the event commit and supports rerunning only that job. Separately authorized comment integrations replace stale comments on check failure; the reusable workflows disable comments. Copied bytes can be compared; an unconfined runner user or root can fabricate matching evidence. Signing uses a second reusable workflow behind explicit permanent-log consent; hosted acceptance remains open.
- The receipt workflow always preserves the checked agent exit and refusal policy after comparison upload,
  including when signing is selected without a downstream signer. Optional signing can still retain
  signatures for checked failed or refused runs.


- Add an optional dashboard tour from the stored machine check to a verified enforcing run. Guide opens at the first step that is neither done nor skipped, shows its evidence and reuses the real product page. Check names the terminal action; command forms with placeholders have no Copy button. Watch announces an ended recording before advancing and waits while focus is inside the guide. Recorded and Review lead with recorded programs, files and connections; Review distinguishes creating, compiling and an already saved contract, and keeps the guide through both mode links, preview and save on the existing contract builder. Hide for good has a Show the guide again control, and blocked or unknown steps stay visible on Overview. Finished machines receive no Start the guide offer. Script-free pages offer a reload link and never promise an automatic move. Unknown guide steps are checked again on refresh, including when a recording ends before its chain anchor is published. Missing anchors remain unknown and corrupted records remain blocked.

- Fix contract-name validation in browsers that use the current regular-expression mode for form patterns. Valid hyphenated names remain valid and invalid names are rejected.

- New contract has Simple Keep/Drop decisions and a Full YAML draft editor, including a blank starting point.
  View changes preserve edits and setup-generated environment assignments without exposing their values.
  Save binds the reviewed bytes, destination, directory identity, inherited source digests and compiled result.
  Save uses the proposal held at Preview, including dated structured comments, and recompiles those exact bytes.
  Governed and uncertain readers see previews with saving unavailable, without retaining or evicting reviews.
  Live-region updates render builder previews fresh, so another peer's cached form cannot supply review
  credentials or remove Save from a person's form. Ordinary person pages keep the shared render cache.
  Every save-eligible Preview has its own random review identity bound into its acknowledgement, even for identical input.
  Reviews expire 30 minutes after creation, extended by nothing. Save consumes the review before publication;
  replay, expired, evicted, restarted or foreign-session reviews ask the person to review again. A publication
  failure also needs another review. Drafts share limits of 64 entries, 8 MiB per serialized entry and 32 MiB total.
  Insertion evicts its session's oldest entry first, otherwise the global oldest; insertion order breaks clock ties.
  Eviction never makes an acknowledgement select another review.
  Check after an external file edit can be reviewed and saved against that current base; a further edit still
  refuses and asks for review again. Save clears only the historical warning after validating the retained review.
  New-contract Full, Simple and Save forms and raw Simple edits preserve intentional leading blank lines.
  A missing finished-run choice stays marked alongside project-preflight refusals.
  Failed offline hostname lookups leave no timestamp to invalidate an available review; expiry deadlines remain bound.
  Registry-directory preparation uses the guarded Preview POST. Read previews leave disk unchanged and ask
  for Preview before Save when the destination is missing. Drafts retain server-derived withheld destinations,
  so an unchanged form from a leaking run saves without losing its review.
  Malformed YAML keeps its parser line number while diagnostic values stay hidden.
  Wider compiled rule families and changed families Tego cannot order both require explicit review. Draft checks
  are bounded, cancellable and use no DNS; older preview responses cannot enable Save after another edit.
  Contract files share a synced temporary-file publisher, so readers see a complete file. Registry saves refuse
  symbolic links in every directory component, including an agents link that points within the registry.
- Never offer Allow once beside a request that cannot be read in full there: a request sentence longer than its width's bound is cut in the middle, keeping both ends, and its banner offers Review request, which opens the request's own card with the exact target whole beside Allow once and Deny.

- Keep complete agent names and requested hosts, files and commands readable on decision cards and waiting rows, with wrapping instead of ellipses.

- Keep missing-request diagnostics and supplementary answered-request recovery inside closed phone disclosures.

- Source absence statements across configuration, usage, process, recovery and policy views; audit literal text in every template branch.

- Keep known approval requests visible when the record folder is replaced, and recover when the original returns.

- Reduce phone recovery clutter with short waiting reasons and closed technical details.

- Keep unknown run state explicit in expanded Ended and Asks details.

- Audit empty receipt activity, unavailable derived artifacts and empty configuration lists with the same quantity sources as their nonempty forms. Keep unknown contract declarations explicit.

- Keep known waiting requests visible when a dashboard record root becomes unreadable or is replaced by a file.

- Dashboard waiting badges and live document titles keep known requests as `N+` with the same reason and spoken/page text; an unreadable source with none known uses `?`. A surviving index entry and chain head also retain a missing recorded run after restart. Cold index loss beside unfinished records and loss of a previously read ledger root (even empty) also keep waiting status unknown. Readable record/history/credential counts stay readable; unknown run status is not called lost or offered as finished, and recovery updates rows without another record line. The compact Waiting tab retains that count and full spoken sentence without widening phones. Shared chrome keeps global completeness even on a readable run page or unreadable-root recovery, New contract or retired-form page. Missing global scopes refuse rendering. A retained ended-run failure does not qualify the actionable queue, while a later unlisted source still does. Waiting requests survive bounded event windows and history; incomplete waiting sources, including the live index and vanished indexed directories, cannot produce an all-clear.

- Compare summaries and Contract/rule zero-hit sentences disclose retained-only coverage and complete-record recovery. Live timeline fragments preserve their source scope. Model-route counts report read failures instead of exact prefix totals. Numeric and zero-form inventory checks now include shown/spoken attributes and page/fragment fixtures, with individual, checked exclusions.

- Receipts and watch summaries distinguish listed places and programs from attempts beyond the identity limit. JSON reports other retained identities separately from `connections_overflow_attempts` and `programs_overflow_attempts`.

- Dashboard: a missing run record is a read failure when the store observed its record file (even empty), or its last-refusal file or chain show recorded lines. Known requests remain visible with the failure reason, including non-regular record files. A file lost during an active read retains its evidence without blocking live polling.

- Keep Runs at its scroll position during reload by loading its comparison styles before the shell can paint.

- A broken record on Overview now leads with Record needs attention when no request is waiting.

- With scripts off, live dashboard pages keep focus and open details until you choose Refresh now; the current filters remain in the address.

- Dashboard browser chrome follows the chosen Light, Dark or Auto palette. Long state chips and compact page labels wrap when text spacing is enlarged; expanded mode comparisons stay in one phone column. Waiting-band Details selects the exact request, with existing anchors retained. Long desktop run names fit their tables; proposed contracts wrap and have keyboard access. Receipts print with stable light colours and without live controls. Waiting restriction chips remain still.

- Unify dashboard phone and tablet rows, filters and detail recovery across the redesigned pages. Remove repeated Overview counts, keep long Stop confirmations readable, and prevent transient messages from covering keyboard controls.

- Rebuild Contracts, rule details, This machine, Glossary and recovery pages for phones and both themes. Keep full authorization values reachable and wrap MCP and model-route previews at narrow widths.

### Added

- Overview now leads with requests, the record state and running agents on phones. Run tabs use readable event rows, and Event keeps the full target and deciding rule. Full metadata and activity remain in native details. Long request names no longer hide the action and short target.

- Logs and Detections have clear phone rows and native Filter pages. Approvals shows the oldest request and a
  queue, with full targets, timing and equal decision buttons on request details. Compare stacks outcomes on
  phones, and Investigate keeps process context and related detections in named disclosures.

- The dashboard phone shell has five bottom destinations, a compact waiting-request band and a quiet header.
  Runs has single-target rows and a Filter sheet that also works as a plain GET page. More carries help and theme
  settings. Both themes reserve orange for waiting requests; refusals and warnings for protected reads use red.
  Allowed own-login reads stay neutral.

- The dashboard has a new look, in the website's brand: a themed top bar with the Tego wordmark, a side nav that marks
  where you are, page titles in the website's headline face (Anton, shipped inside `tego-control`, 11 KB, SIL Open
  Font License 1.1, listed in `tego-control licenses`), and shared state chips with the design's meanings: orange
  for a request still waiting for you, red for refusals and protected reads that went through, and quiet neutral
  chips for routine and other states. An allowed read of a protected path is crimson too; historical
  asks and contract modes are quiet chips. Links are ink with an underline. On a phone five fixed bottom destinations leave content clear above them.
  The waiting request uses the orange waiting palette above the page head
  in the page's flow at every width, full on Overview and compact elsewhere; a new request is announced once in a
  polite live region. A request that leaves the waiting list and later returns is announced again. Requests first
  seen after a view change are announced too. Above 600 px both bands show
  the asked-at time, a snapshot of how long the request has been held, and the
  note about when the agent may give up and Tego will refuse it. A compact band keeps the request while hovered or
  focused and updates when both leave. At 601 to 640 px controls can wrap between buttons while each label stays
  intact on one line. At 600 px and below they use one three-column row; timing stays on Approvals. New list rows use a neutral surface tint; the request band keeps its own
  contrasting colours on arrival without that highlight. Short pages start directly
  below the compact phone header or tablet navigation. Logs' What text wraps without a line clamp at every width; on phones it
  keeps the full row width, and ellipsized facet and agent labels keep their full values in titles.
  Record tile values can wrap when another tile fits on the same row. A line page's prefilled Logs search signals
  a shortened subject with an ellipsis and keeps the full rendered subject in its title; its value stays editable.
  Overview's shortened waiting-row run/time metadata and Logs' clamped Rule labels expose their complete values in
  titles. Detections keeps its Investigate column named without hidden heading text adding horizontal page overflow.
  A Copy button's "Copied" is now
  in a polite live region too. The pages inside the shell keep their present layout for now. Nothing is loaded from
  outside `tego-control`, and shell navigation and plain request forms remain available with scripts off.


- `tego scan` now verifies account-file ownership, modes and all path components in both discovery-evidence passes, including symlink targets. Unverifiable placement refuses group-writable discovery sources with accounts-unreadable and a named administrator repair. The snapshot may include optional bounded `account_repair` text. The account-evidence collector accepts verified links, but caller identification still rejects any link on the passwd route: linked /etc or /etc/passwd makes the whole scan refuse before discovery with exit 125, meta reason owner and scan-not-performed. This affects store-path and image-based layouts using those links, even with verified root-owned targets; scan remains unavailable there while the layout is required.

- Scan can read 0664 discovery settings and 0775 unit folders when complete bounded local account evidence, checked by two fresh read passes for equal bytes and matching identity/metadata, identifies a private group. Differing account bytes or metadata refuse without retry; run the scan again. Root's in-place writes leaving both passes reading the same bytes are not detected (undo between passes or fragmented reads within one timestamp tick), and membership changed after the scan remains a limit. Shared primary groups, directory-service membership and incomplete account reads refuse group write. Refusals name the group and the file or parent folder to repair. Account metadata, records and saved-result parents retain their prior permission refusals.

- Root recovery commands name the running Tego binary by its checked, quoted absolute path, including
  the adopt privilege refusal and lost adoptions. Detected foreign ownership or unsafe write permissions
  give no command and explain how to install safely; sticky directories protect trusted children. Default
  0775 private primary group installs and empty local groups such as Debian staff are accepted. When bounded local account checks cannot
  establish membership, only the effective user's primary gid by id is accepted with a root/user-owned folder;
  an unseen directory-service sharer cannot be ruled out. Known foreign members and non-sticky access ACLs refuse.
  Static docs resolve the installed copy in the reader's shell before sudo. The service template sets an explicit PATH including
  the account's own installation; a contract must pass PATH for the agent to receive it.


- Contracts shows the trusted general contract source and its digests before the locked machine baseline. Profile graph inspection has aggregate resource and cancellation bounds; exhausted reads show UNKNOWN. Private relative and absolute source symlinks use the resolved descriptor-bound parent checks. This is read-only source inspection. Production parser checks cover the listed selectors. The private source graph and registered command dispatch have additional boundary guards; the rewritten public tree needs separate build verification. No production general launch selector exists. The accepted launch design now lists engine-only environment names and requires trusted system or built-in prices for finite system cost limits; user prices cannot supply system authority. Missing model pricing must refuse with preflight guidance. General launch, that environment and pricing enforcement, and per-agent customisation still require later implementation and guest proof. Existing own contracts keep their behavior.
- Validate raw baseline evidence before UTF-8 repair in serialization, ledger writes, receipt, replay, metadata and dashboard readers. Dashboard refresh retains positioned refusals for rejected complete lines; an exact-key run start or unclassifiable line clears earlier baseline hashes. Window reload revalidates and skips unchanged retained refusals without recounting them, so the run page still shows them after eviction; newly refused or changed refused bytes still report damage. JSONL and CSV downloads report refused lines as notes with the run, offset and reason. Pause/resume polling reports damage with exit 125, alongside a later valid confirmation when present. The source inventory conservatively checks JSON decoder selectors and calls in baseline-bearing, generic and untyped contexts, including aliases and decoder function values. This conservative syntax guard is not a proof of arbitrary data flow. Baseline records use `MinorBaseline`; reserved revisions from other branches are refused. Legacy writer byte comparison covers launch/adoption `run_start` and `run_end` only. A missing baseline block makes no baseline claim; existing human receipt bytes stay unchanged.

- Baseline record validation and the effective contract copy now prepare before adoption moves
  any process. Current configuration bytes and identities still recheck under the migration lock.

- Baseline records now retain source and effective hashes, consulted layers and per-entry coverage for validated historical replay. Receipts explain baseline scope and recorded refusals. Enforcing launches with a nonempty baseline remain blocked pending guest proof.

### Added

- Agents data and authenticated minimal pages describe each named recorded run with its id/time and same-run checked stages. Scan observations remain separate and have no stage ticks; unchecked records say why. The data layer remembers discoveries for 30 days since last seen: only omission from a usable latest scan means not seen this time; old, failed or unreadable scans keep last-seen time and ask for another scan. Remembered relations reflect current recorded runs. A busy store lock shows the checked last committed discoveries without writing and asks for a refresh. Bounded lists disclose truncation. The list is what scans have seen, never proof that nothing else runs; same-user programs outside Tego can rewrite its files. The visibly unfolded footer reports ordinary scan/store writes refused by builtin.tego_surface, including guest row whole-home-landlock. An external anchor and ledger with a whole-home grant and direct reads can leave the home state readable at landlock; this narrower read case comes from code and is owed in a guest. Recorded run stages remain independent. Unsafe scan/store modes and links show manual repair steps and keep readable recorded rows. A per-run caution needs a missing historical own-state exposure fact and a maintainer-allocated record minor; it is deferred. Observed refusals today remain a count from readable records, labelled as a lower bound when incomplete. Agents becomes home after setup is done; Overview remains at `/overview`. Approved page templates and Forget follow separately. Setup JSON shares the run facts; no scan is started by a page and no discovered executable is offered to copy.

- Documented a limit shared by every Go program run as root: before `main`, Go opens the CPU limit file under the first cgroup mount by an ordinary path lookup, which no build setting prevents. Only where root has placed that mount under, or mounted into the cgroup path, a directory another account controls can that account make a root tego block before it starts or have up to 64 bytes per file read and parsed as numbers (one file on cgroup v2; quota and, unless negative, period on v1); nothing is printed, saved or logged. Tego adds no check for it (GAPS C79).

- The tego binary closes Go's startup CPU quota descriptors before command execution when both opens succeed. On cgroup v1, a failed period-file open leaves the quota descriptor open and unread for the process's life. Its default CPU parallelism follows CPU affinity without adapting to cgroup quota; explicit GOMAXPROCS remains honored. Advanced scan refuses a positive containermaxprocs override before collecting sources. Go still reads the membership-selected quota as root at startup, including for delegated cgroups; the whole-command fixed-source requirement remains unresolved for this runtime read.

- Scan keeps its observed processes when record checks exceed eight distinct run ids or a selected ledger path cannot fit the result contract. The partial result names a limit or invalid source instead of losing all observations.

- Advanced scan reads shared machine unit listings and documents once, checks identities on reuse, and merges each account independently. A 100-account fixture with 3,000 system services keeps the last home's agent visible. Successful machine reads are counted at their roots; matched evidence and named failures keep exact paths, with an unknown remainder at a limit. Limits still report partial coverage.

### Added

- `tego scan --advanced` adds explicit root discovery across visible users, fixed user and system service/timer paths, cron sources and validated container ids from cgroup names. It reuses the scan parsers, drops secret values and discloses unreadable sources and unknown coverage. Other accounts' process working folders are never read or recorded; their rows explain the omission, and the user page names every retained field. The private result is addressed to the invoking local-passwd user under sudo or root for direct root, after a permanent all-thread privilege drop before recipient-controlled metadata, MCP/project content, config/ledger reads or destination opens, including check mode. Root collection reads only the fixed process/account/boot/unit/cron sources; failed drops prevent recipient reads and saving. Root credential, hostile-source, config-canary, parent-change and destination regressions passed on full Fedora 44 kernel 7.0.14 and AlmaLinux 9.8. Remaining namespace/mount, live daemon/container-manager and vendor-install comparisons are owed in a guest.

- `tego scan` lists configured MCP servers from fixed Claude, Codex and Gemini settings, and configured systemd user services/timers. Large ignored JSON subtrees are streamed; Claude local settings select the current folder. Unit reads charge failed listings and overflow lookahead within the aggregate bound, enforce the combined line/word cap through the final line, resolve aliases within selected roots, and handle measured systemd quoting and continuations. The `|` shell prefix is explicitly unresolved; escaped semicolon arguments are accepted. Separate tests cover unchanged captured distribution contents and synthetic layout capacity. Unreadable sources and unresolved expansions/launchers remain explicit; the check decides process coverage. Verbose success rows carry no refusal warning, and partial snapshots omit the negative no-match summary. Real-install checks are owed in a guest.
- System-only `local_roles: owner_only` restricts a qualified root-launched non-root run to once answers from initial-namespace root outside every governed run. Same-user terminal and dashboard answers, Deny without authority, always and alternates refuse without consuming the request. Only exact `off` and `owner_only` selector values load; invalid or unreadable system policy refuses launches. A policy change gives a distinct stop/relaunch remedy after broker contact; strict Approve loading first refuses an unreadable system file and requires its readability repair. Required durable actor records precede release, then a decision-time namespace, scope and real UID snapshot bound to the packet credentials and pidfd checks equal pinned-policy readings and the monotonic deadline before delivery. Incoherent or exited senders keep the operation held at its original deadline, with a fresh ask ID if a selection was already recorded. Later changes the sender makes to itself do not revoke a completed snapshot. Managed approvals are labeled recorded selections; operation completion needs its own evidence. Authenticated attribution requires the run revision and a valid complete answer; the authority display requires a valid complete run_start payload. Root and kernel qualification with the built fault adapter is **owed in a guest** and remains a merge blocker. Personal record and approval bytes are unchanged; only a run under the floor carries the local approval fields, valid from record minor 37 on (37, or the later revision its launch already writes). Shared roles, protected publication and business caps need later slices.

- Automatic user-scope entry is built for `tego run`, `tego watch` and `tego test`; SSH and console validation is
  **owed in a guest** on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44. Keep the existing manual path available:
  `systemd-run --user --scope bash`. Process tests cover inherited descriptors, raw stop propagation, cooked
  group stop/fg without a repeated parent stop, one foreground interrupt with piped stdin, child signal status
  and parent-death SIGTERM; they do not prove real login or manager behavior.
  A failed handoff starts no run and keeps the existing advice; cancellation exits 130 without that advice.
  Tego never enables lingering, and `tego run --service` keeps its service unit. Parent death requests normal
  `stop_grace`; an unresponsive launcher has no additional forced-kill timer in the waiting parent.
  Known limit: a background `kill -INT %1` with piped stdin can be delivered twice and escalate immediately.
  For one graceful background interrupt, target only the launcher pid.
- `tego contracts` lists known contracts, offline check findings and their newest recorded runs.
  `tego contracts show <name|path>` shows rules with sources; both offer versioned JSON. This read-only view adds no rule.
  The command carries a 60-second deadline and stops waiting after 5 seconds per contract or registry scan;
  separate check helpers keep recorded-path filesystem waits outside the command process. Interrupted checks
  stay incomplete. Initial selected config and ledger loading remain synchronous. The comparison header says `SAME TEXT AS LAST RUN`; malformed recorded hashes are omitted and
  unknown tiers are labelled `unknown`.
- Built-in `tego/ci` records refused read opens at tier landlock by default, denies named CI token variables and blocks ordinary `.github/` writes; CI is opt-in in the dashboard. Hyphenated token inputs, runner file-command paths and stdout workflow commands need action checks; a retained denial beneath a write grant with kernel assurance fails compile at tier landlock. See the CI limits in the presets guide before signing.
- The receipt and dashboard's Receipt tab say when this run's contract records that `tego learn` withheld a
  destination whose connect is now refused, and name the conditional `tego rule <run> <seq> --allow` step. This
  editable history is preserved by compile and never changes permission; editing only the history changes
  `contract_hash`. The match needs the same protocol, address and port and a default-deny connect refusal (a
  missing network operation means connect); bind, listen, sendmsg and accept get no such sentence. Stdin and
  generated contracts record no source and get no sentence. A malformed hand edit stops contract loading with
  the file, line and fix.
- `tego scan` reads current-folder project dependencies from package.json and requirements.txt, including ordinary 0664 files in your primary group. Other-write is always refused and refused modes are named in the footer. Setup and Overview tick Find your agents from fresh own running or installed evidence even with partial scan status, while retaining unreadable-source reasons and labelling the saved result as changeable by any program running as you. Setup exit codes do not change.
- Add `tego scan`: a private basic snapshot of own-uid process matches, installed candidates and settings metadata, with evidence, coverage, JSON and a no-save CI check.
  Exited processes and kernel threads have separate counts. Unreadable own program files are reported with count/pids and check exit 3; an explicit accepting mode is available. Tego cannot tell whether these are agents; any program can make itself unreadable. With `--allow-unreadable-programs`, exit 0 does NOT mean no agent runs outside Tego. Exit 3 has the same uncertainty. Record checks read bounded starts and tails, so record size alone does not prevent live-run wording. Stricter file opens stay local to scan and add no shared ledger /proc reopening dependency.

### Changed

- The Claude Code reason hook reports pending refusals at session start and states whole-run scope in every note.
- Record validation now strict-decodes a present `run_start.contract_source` at every minor, including older
  ledgers: null, case variants of `contract_source` or learn-history keys, wrong types for known fields, repeated
  members and unpaired surrogates inside that object are refused. Raw invalid UTF-8 still receives the scanner's existing U+FFFD repair. A valid
  older source without learn history remains accepted.
- Generic `tego receipt --check` now returns `cannot-check` with exit 125 for a missing or unreadable record,
  rather than mismatch with exit 1, unless a separate check failed.
- A config layer that is present but unreadable, unparsable, or has the wrong owner or mode now stops commands
  that decide what an agent may do, including launch, compile and rule-check commands. Commands that observe or
  stop keep working, reporting an UNKNOWN baseline and the cause. The system layer requires root-owned placement
  without group/other write authority and a file readable by governed users, normally 0644. While config is
  unknown, `tego gc` deletes nothing and exits 125; `tego machine check --json` includes the baseline state and reasons.
  Compilation now applies baseline refusals once, preserves the contract hash and provides
  `tego rules check --effective` output. JSON adds an effective hash only for nonempty applied baselines;
  empty/absent baselines retain their existing compile JSON output. Contradictory compiled grants, including home
  and relative spellings, protected sockets and launch environment entries refuse compilation. Conflict checks
  cover known aliases; separate filesystem instances showing the same data remain outside alias recognition.
  Enforcing launches with a nonempty baseline remain refused until their effective
  record/receipt support and per-mechanism guest proof are complete.
  Long-running automatic adoption guards reload trusted config and compile each new boundary adoption, and
  require restart when ledger or chain-anchor directories change resolved placement or device/inode identity.
  Checks preserve ordinary creation of initially absent record directories and name the changed location.
  Strict configuration loading after Tego creates its own directories preserves first-use adoption.
  Preparation and final admission share a table of named admission checks. After the host-wide migration-lock
  wait, final admission runs every check in the table marked rechecked, including the chain-anchor file probe
  and selected-layer identity, exact-byte and baseline-digest comparison, including emptiness. A failed
  rechecked entry cleans up and refuses before any process moves. Snapshot entries retain compiled
  contract choices, selected mechanism/probe results/prepared descriptors, immutable boot facts, and the
  recording-only target home because it admits no file boundary. The run-directory contract check derives
  from the compiled snapshot; the skip-counter baseline stays fixed to count skips during the lock wait.
  The selected plane mode checks live admission before arming and again under the migration lock. Already adopted runs retain their snapshots.

### Fixed

- Implicit compiler home lookup retains the release's process-cached real-uid context and first lookup error,
  ignoring `SUDO_UID`, `USER` and `HOME`. Initial disagreement with trusted passwd data refuses; later compiles
  preserve the established protections. Without a passwd home it retains the release refusal. Library callers may supply a nonempty
  `WithHome`; CLI callers with a selected config-owner home explicitly supply it.
- Contract listings and dashboard rules pages use bounded helpers for recorded and user-supplied locations.
  An unavailable entry stays listed with a cannot-tell reason and disables changes and trust-dependent actions.
  Every source/profile diagnostic keeps this state even when metadata answers or another error came first.
  The Rules page receives its recorded view before checking the source, with two exchanges on one worker and
  one overall deadline. If that source read times out, the received rules, redacted YAML and recorded hits
  stay visible at copy positions with the refusal reason; source comparison is absent, and source edits and
  trust-dependent actions stay disabled. The ledger and recorded text must answer. The fallback makes no
  fresh compilation or enforcement claim.
  Caller-selected runtime bases, identity, homes, IPC paths and config snapshots cross explicitly; workers retain
  an empty environment. Feed, link-reference and guide-bootstrap checks share the page request and one worker.
  Evaluation time is carried explicitly too. Caller-specific resolver settings that cannot be reproduced give
  added hostnames a cannot-tell preview warning; the next run resolves them independently.
  The shared limit is 32 workers per effective
  uid/network namespace, including abandoned workers, plus at most 32 transient launchers. This avoids the
  four-worker limit refusing 16 simultaneous healthy commands. Late replies are discarded; no handler waits
  for mount recovery. A submitted change with a timed-out reply has uncertain outcome until recovery.
  Actual stopped-FUSE CLI/dashboard return, exhaustion/recovery and root/sudo/other-uid checks remain a
  merge blocker, owed in a guest. Host stand-ins do not establish that proof.

- Kernel-matrix checks scope missing Btrfs fixtures to RHEL 9 and require io_uring bind/listen result hooks from Linux 6.11. Concurrent-run failures have bounded diagnostics and a launcher memory-growth check. Current guest and hosted acceptance remain owed.
- Rule-change retention now checks cancellation between journal pruning operations and cleanup entries.
  Its two-second automatic budget is checked before taking the journal lock; once held, reading, filtering
  and rewriting finish as one operation, even after expiry, so short passes can commit progress. Temp cleanup
  precedes that lock. Other filesystem operations already in progress finish, and a blocked call can delay return.
  The journal remains consistent and later passes can finish cleanup.
  Startup logs describe a deadline stop as incomplete, including when some pruning already completed, and
  retain the error's own cause: a busy lock is named alongside the deadline.
- Uprobe capture now attempts a live tail call into an empty array to avoid a kernel private-stack collision, and the loader requires that call in instructions read back from the kernel. Released v0.1.x could select this capture through an omitted `capture`, `capture: auto` or `capture: uprobe` at either root tier. Exposure needs the private-stack feature, a supporting JIT and a preemption mode that lets concurrent tasks interleave in one probe on one CPU; one agent can suffice. Fedora's measured lazy default was exposed; Ubuntu 6.17's measured voluntary default was not. Upstream kernels before 6.13 lack the feature. Symptoms include missing or corrupt model exchanges, a budgeted run ending `error` (exit 125), or a kernel fault that kills a task and leaves later doctor calls or probe removal hung. A host fault can also affect runs using another mechanism. If the loaded call cannot be confirmed, uprobe capture is unavailable: auto keeps the forwarder available under existing budget checks, explicit uprobe capture with recording enabled is refused with the reason and doctor reports it. All eight x86-64 rows passed loading, read-back and availability with a disclosed dump-only test overlay; the stock dump exporter is corrected for translated helper offsets, with 64 authentic fixtures tested on the host. Corrected stock reruns on RHEL 9 and Fedora 7.2 and arm64 acceptance remain owed in a guest. Live-call stress passed 9/9 Fedora 7.0 lazy and 6/6 Ubuntu 6.17 full rounds, totaling 25,200 exchanges with zero kernel faults or capture losses; measured incremental BPF-runtime cost is within noise. Other documented capture losses remain.
- Host hardening is respected when capture instructions cannot be read back. On Fedora 7.0.14, `net.core.bpf_jit_harden=2` together with `kernel.kptr_restrict=2` withheld instructions even from root after successful program loads. Uprobe capture became unavailable; doctor reported the restricted sysctls and unavailable capture while required enforcement hooks stayed available. Explicit recording-enabled `capture: uprobe` refused before agent start (exit 125). With a declared endpoint and no model budget, automatic capture started the forwarder and recorded a count-zero `capture/mechanism-unavailable` gap. Use `capture: forwarder` with a `models:` endpoint, or relax the blocking setting only if the host owner accepts the tradeoff. Tego never bypasses host hardening; raising the ring budget does not cure this restriction. See [operations guidance](OPERATIONS.md).

- A run ending with reason `signal` or `stopped` after being asked to stop (`tego stop`, or SIGINT, SIGTERM or
  SIGHUP to `tego run`) and then killed by Tego, because `stop_grace` ran out or a second SIGINT came within two
  seconds, now records the signal that started the stop in `run_end.signal`, with `escalated: true`. It recorded 9,
  the kill's own signal. `tego receipt` says "ended
  by signal 15, then killed by Tego". Runs recorded before this release keep 9; the `tego_version` of `run_start`
  identifies the writer, while `escalated: true` alone does not distinguish old and new records.
  The record does not say which of the two causes escalated the stop. No record key or record minor changed.
- In a `--observe` run, a send (`sendto`, `sendmsg`, `sendmmsg`) whose address has the family `AF_UNSPEC` is let through, as
  before: an attempted send whose destination and result the record cannot establish. Its line now carries the rule
  `net.unspec-send` (it said `unmatched`, like a refusal), and `tego receipt`, `tego watch` and the dashboard list it as
  a connection to "unread address, AF_UNSPEC send", observed. They counted it with the routine socket calls that name
  no place (a `connect` with `AF_UNSPEC` that only drops a socket's peer), and the dashboard's verdict left it out. A run
  that enforces still refuses such a send, with the same line as before.
- The dashboard's approval card shows the request's id in its Request row, beside the record line (for example
  `q-late · line #1`). It is the id `tego approve <run> <ask_id>` takes and the record holds. It was only in a
  tooltip and a hidden field. It is in the page itself, so it shows with scripts off.

- `tego compile` refuses a `net.ask` entry for a `unix:` socket that a built-in refusal always refuses (the session
  bus, the user manager, Tego's own sockets), as it already refused the same entry under `net.allow`: such an entry
  never asked anyone and the socket was refused outright. The dashboard's "Act on this" no longer offers Allow or Ask
  for a refused line of such a socket, which wrote a contract that then failed to compile; the page says why instead.
  Checked by unit tests and a page test.
- `tego learn` over one recording now gives the same warnings and counts every time. When two of the places the run
  reached stood for one address (one by the host name a line carried, one by the bare address), which of them the
  exclusion of that address was reported under followed the order Go reads a map in, so the same recording listed
  other addresses as "not allowed" and counted a different number of leaks on each run. The addresses the proposal
  keeps and the ones it leaves out were the same every time. The first contact the run made now owns such an address,
  so reading one record again writes the same contract text, warnings included; a test runs it 200 times. The
  warning also says that which addresses are left out comes from the recording alone: a site that answers from other
  addresses, in another order or at another time, gives another set the next time the agent is recorded.

- Setting up a service account from an administrator's shell (a fourth guest walk; run in one AlmaLinux 9.8 guest. Unit
  tests check the wording and the formatting of the lines; how a real `su` or `sudo su` shell, zsh, or another distribution
  behaves is not proven):
  - A Tego command in a `next:` line now begins with `sudo -u <account>` when `tego` was started from another user's
    shell through `sudo` or `su`. After the account was set up, setup run as svc through sudo ended with `next: tego receipt
    <id>`, which the administrator typed in their own shell, where it read their record and failed. It is now
    a receipt command with sudo's svc option and the checked path of the running binary, and step 2 no longer says
    that command opens a shell. In the account's own shell the lines stay bare.
  - Those `sudo` lines name the running `tego` by its full path, quoted. A command that runs in a folder uses a shell
    as the account to change folder and execute that checked binary. Before, a bare Tego program name after sudo's
    svc option was "command not found" where
    sudo's `PATH` has no `~/.local/bin` (Ubuntu, Fedora) or `/usr/local/bin` (AlmaLinux), and the `cd` ran in your
    shell and failed when the account's home was closed to you. If the running `tego` cannot be named, or the account
    cannot run it, the `next:` line says so and gives no command. The same holds for the `sudo` lines in `tego doctor`'s
    fix lines and hints and `tego agents`, which no longer fall back to a bare program name after sudo or a lookup
    of `tego` in your `PATH`:
    a path that is unreadable, no longer the running file, holds a control or invisible character or is not executable
    gives no command. The file and resolved ancestors must be owned by root or the process's effective account and
    refuse group and world writes to the file. Non-sticky folders refuse world write; group write follows the
    private primary or empty local group rule and the primary-gid fallback above. A sticky directory is allowed
    when the next child has a trusted owner, since other users cannot rename it there. Otherwise no command is shown; install in a folder only root or you can write.
    The `sh -c` form needs a sudoers grant that lets you run a shell as the account; the line says it may be refused. A service account needs its own copy of `tego` (docs/INSTALL.md, "A service account"); the
    installer says so.
  - `tego learn --save` and the other `next:` lines no longer print a changed version of a name from the record. A
    recorded folder whose name holds a newline was shown as a folder with a backslash and an n in its name; the line now
    gives no command and says the folder name cannot be shown safely.
  - The words for a shell that `sudo su` opened now say "if you are in one, type exit first".
  - Before linger, `tego run`, `tego watch` and `tego test` end with the `sudo loginctl enable-linger <user>` block
    that `tego setup` and `tego doctor` print, not only a `fix:` text inside their error line.
  - When the account's user manager runs but keeps no socket under `/run/user/<uid>`, the `fix:` line no longer names a
    `sudo -u` command that fails there; it and the `next:` line say no command opens a shell in that manager from yours.

### Record `v`
1 (`spec/record/v1`, record minor 41)


### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

### Fixed

- A stall limit in v0.1.2 and v0.1.3 could stop a run that was still making progress if the supervisor
  was delayed between reading activity and checking the time. The watcher now reads the time first, so
  that delay cannot turn a live run into a reported stall. Runs with no activity still reach their stall limit.

### Added

- `tego start` sets up a first-time user in four steps: the agent (Claude Code, Codex or another program), its login, a project (a test project with a harmlessly poisoned dependency, or their own) and its rules (Base development, Read-only review, rules picked one by one, or their own rules file). It opens the dashboard and ends with the command that starts the first session. On a Mac, the one-line installer sets up Lima and Tego's VM, and `tego start` and `tego dashboard` work from the Mac's terminal.
- Commands in git's noun-verb shape, over the existing ones: `tego rules create|edit|check|learn`, `tego session list|show|stop|pause|resume`, `tego machine check|test`, and `tego dashboard`. `tego help` lists the common commands and `tego help -a` every one. Every existing command keeps its name, flags and exit codes; only `-h`'s layout changed. Guidance and dashboard pages now name the noun-verb commands, such as `tego session show`; the compatibility exception for `tego run` is listed below.
- `tego start` asks before using a saved login ("Use your saved Claude Code login?"), and logging in again replaces it. The Mac installer's last line says how to use `tego` in the same terminal (`exec zsh`).
- Sessions have names (`tego-sample-dzfa`) that every command taking a run accepts.
- One dashboard per configuration: `tego dashboard` and `tego start` reuse a running dashboard only after it proves it
  holds its sign-in link and serves the same ledger and machine configuration (every layer of it); otherwise they
  start a new one. Its log and a saved agent login are private files (mode 0600) from the moment they exist: a
  link at their name is replaced, never written through, and a copy that others can read is not used.
- The setup guide shows an agent's own install command and where it comes from before it asks to run it. As root
  it works as for any user, except that it does not run an agent's installer: it shows the line to run. Read-only
  review keeps the project's content read-only: the agent can write only its own state folder under `.tego/`,
  which also holds its temporary files, and a project in which that folder is a link is refused.
- The guide keeps one reader on the terminal from its first question to its last: a key pressed as a step appears
  is not lost, and Ctrl-C ends the guide at any point, during an agent's installer included. It works with a home
  reached through a link and with a `~/.bashrc` or `~/.config` that a dotfile manager links.
- Leaving the guide (Ctrl-C, a terminal that closes, or a signal that ends it) ends every program it started,
  an agent's installer and the dashboard it was starting included, puts the terminal back as it was and says
  `Stopped` instead of `Ready`. Keys that follow a pasted key or a sign-in are dropped, so the rest of a paste
  cannot answer the next question. A terminal with `TERM=dumb` gets numbered questions that end the same way.
- The guide's Next steps list a `PATH` line when the agent was installed to `~/.local/bin` and the shell that
  started the guide does not search it, and a line that removes the variable (`unset`, or `set -e` in fish) when
  that shell still exports the login you just replaced. A rules file of your own is checked against the project
  you chose, as `tego run` will read it there.
- `tego run` uses a login saved by `tego start` (`~/.config/tego/agent.env`) for each variable that is not already
  set in its environment, so the first session works in the terminal the guide ran in. An exported variable wins;
  a saved file that is not your own private file is ignored with one line that says why.
- The Mac installer checks the VM template and the VM's installer against the selected release before it uses
  them, installs that same version in the VM and binds the VM's binaries to the checksums it verified
  (`TEGO_CHECKSUMS_SHA256`), opens the dashboard only after a tunnel that belongs to you is confirmed, and adds
  `tego` to fish's PATH in fish's own configuration. Pinning a version on a Mac (`TEGO_VERSION`) needs a release
  whose template takes the pin: this one or later; an earlier release is refused before the VM is created.
- On a Mac, `tego dashboard` keeps its tunnel's socket at one path in the VM's folder: a leftover socket of your
  own is replaced there, so the next command reuses the tunnel, and a socket folder that others can write, or a
  socket that is a link or someone else's, is named in one line and nothing is started.

### Changed

- The Linux installer's last line is `tego start` when the installed `tego` has it, else `tego setup` or `tego doctor` as before. The README's quickstart is four steps (install, set up, run, see what happened) and a table of everyday commands; the install details and what each system was tested on moved to `docs/INSTALL.md`, which now records the Mac runs.
- `tego run` keeps coverage gaps and same-file refusal explanations in the full summary; its short success line appears only when no disclosure qualifies the blocked-action count.
- `tego session list` reports an unreadable ledger and exits with an error instead of saying there are no sessions.
- `tego help` says what `tego dashboard` does on each system: it prints the link on Linux and opens the browser
  on a Mac.

- `tego setup` in a terminal now opens the setup guide; `--json` and `-v` keep the checklist.
- Next-step fields and `fix` fields in JSON output now name the new commands: `tego machine check`,
  `tego rules check`, `tego session show` and `tego rules learn`. Consumers comparing those command strings
  must accept the new names; the old commands still work.
- `tego run` in a terminal prints a start line with its session name, rules file and dashboard page, and an end
  line with the number of actions blocked. The rules file's setup name is shown as a file comment alongside its
  path. Accepted risks and failed checks remain visible; incomplete or unverified records, record-off runs,
  abnormal endings and read-count limitations retain the full summary without a success check mark.
  Terminal mode is selected by stderr being a terminal, with no `-v` or `--cmd`; piping stdout alone keeps this
  mode. Piped or redirected stderr and `-v` retain the previous run output, including the older command names.
- The Lima VM template (`examples/lima/tego.yaml`) shares no Mac folder with the VM. It used to mount the Mac
  home read-only and `/tmp/lima` writable; projects now live in the VM. `docs/INSTALL.md` says how to share one
  folder on purpose and what an agent can then read. A VM made from the older template keeps its mounts until
  it is edited.

- The dashboard's clipping audit checks reachability at each clipping ancestor. The earlier zero-regression
  conclusion is withdrawn: an inner horizontal scroller could hide outer clipping. Legacy Logs record-line agent labels at
  768 px and up retain room for enlarged text without losing horizontal ellipsis or full-value titles.
  Overview and Runs command subtitles at those widths also keep room for enlarged text and their command tooltips.
  Chrome checks still require manual invocation and are outside CI and the private gate.

- The dashboard uses the website's navy and headline face, with local assets only. Orange means a request
  waiting for a person. Refusals, broken records and warnings for protected reads use red. Allowed own-login reads
  and ordinary allowed and passed-through actions stay neutral. At phone widths five destinations sit at the bottom.
  List rows show who, state and age; exact paths, hashes and identifiers remain in details. The shared
  request band has one sentence, two equal answers and an exact-request Details link. Overview may use
  two lines; other pages use one. Approvals uses that compact band for its own selected request.
  Every request link selects its run and request. A missing selection offers no other request's controls.
  Overview and Run summaries prioritize waiting requests, record failures, recorded leaks and sensitive reads,
  then qualified quiet states when the sources are complete. Incomplete waiting lists, unreadable
  records and lower-bound signal counts keep unknown needs explicit. A verified record never implies
  safety. Displayed numbers use complete aggregates where available; incomplete windows, omitted
  runs, malformed lines and capped approval history say at least, explain why and link complete
  records. A record file that cannot be read says could not read with its reason instead of
  showing prefix counts. MCP propagates stream errors. Refusals today use decoded date bounds,
  including the valid zero timestamp. Invalid timestamps remain unreadable records.
  Query errors remain visible beside Logs results. Runs retains Filter and scoped counts at desktop widths.
  Run, Event, Logs and Receipt share protected-read classification across historical timeline windows, including own-login and contract context.
  Its caches keep results and live folds tied to their source record file. Older Event windows reject changed sources.
  Contract latest-start summaries reuse the aggregate rather than scanning every run for every contract.
  Full authorization values wrap on detail pages. Native navigation, Filter pages and decision forms work
  without scripts. Native disclosure controls remain available when desktop auto-expansion is unsupported.
  Pointer and keyboard holds retain request identity during live updates.

### Removed

- maze is no longer built or released. The release has 13 files instead of 22; the last release with maze is v0.1.3.
- The component notes under `docs/p0` are no longer part of this repository. The repository's checks require the
  seven public specifications under `spec/` instead; the few checks that could only read those notes are skipped
  by name in the skip lists under `test/`.

## v0.1.3 - 2026-11-13

This security release fixes file and command rules, record verification, and the handling of skipped kernel checks.
If you use Tego v0.1.0, v0.1.1 or v0.1.2, upgrade and restart your runs.
The v0.1.1-rc.1 prerelease is affected too.

### Security

- Denied reads at tiers cgroup and bpflsm: a host could already show a denied folder, or part of it, at another
  readable place on the same filesystem. A read through that place could miss the denial. This affects v0.1.0
  through v0.1.2. The fixed build refuses to start where the selected mechanism cannot hold the denial through
  those names. A decision plane still handles whole-folder names on the same filesystem where supported.
  Different filesystem instances that show the same data remain a limit. So do later host mounts, ancestor
  renames and rules that protect names rather than existing paths. Tier landlock keeps its stated alias limit.
  Hosts that already show a home or project folder at a second place, such as Fedora Atomic, toolbox and
  distrobox hosts, can meet this refusal where the selected mechanism cannot hold that second place;
  `tego doctor` names the places it found.
- Protected writes: in v0.1.0 through v0.1.2, a write or ask grant could reach kernel control files or Tego's own
  files through another existing mount. A user-writable Tego binary with another hard link was also exposed.
  An agent could change another run's controls or a binary used by a later run. Compile and run start now refuse
  grants that reach these protected places within the mount analysis's stated limits. Mount changes after compilation, separate
  filesystem instances and backing storage whose identity is not known remain limits. Keep that storage outside
  every write and ask grant. Processes outside Tego still have their ordinary rights.
- Command rules in v0.1.0 through v0.1.2 could miss some subcommand entries in `exec.deny` and `exec.ask` for
  systemctl, go, npm, pip and aws. It matters when the program may run and the contract relies on a subcommand
  entry. These command forms now match; some other tools refuse more commands where their parsing is
  uncertain. Whole-program refusals, file rules, network rules and ordinary OS privileges applied throughout.
  `exec.ask` is still reserved and refuses; it does not ask a person.
- Option-specific npm refusals could be missed, and some npm argument combinations could be admitted under
  an allow entry for another command. Command rules now check the command and options npm reads, including
  value assignments, option spellings and shorthands. Existing conservative refusals remain in place.
- AWS options written as assignments remain options when a preceding option needs a value. Missing values
  refuse constrained command rules; uncertain spellings retain conservative readings.
- Command entries containing an option terminator follow the tool's command, default command and argument
  boundaries. Unknown tools keep literal argument regions. Unestablished allow meanings and unsupported
  separator spellings fail to compile. Refusals of the compared inputs remain (the known limits below name
  one exception), and allow entries retain their prior limits.
  An allow entry does not admit its command when the command line puts `--` before the subcommand; write the command without it.
- This release decides command rules with two readings of each entry and command line: the corrected reading
  and a retained earlier reading kept as a floor. A deny or ask entry applies when either reading matches. An
  allow entry for a constrained program admits a command only when both readings do, and an allow entry the
  retained reading cannot interpret fails to compile, naming the entry. So some commands that an allow entry
  would admit under the corrected reading alone stay refused in this release.
- Known limits of command rules in this release. The reading that `tego compile` prints for a command entry
  is one of the two readings the decision uses; where they differ the decision is the stricter one, so
  the printed reading can show more than is allowed or less than is refused. An entry whose option word
  has an empty name is read as written; earlier versions could read it as a command's only long option, so a
  deny or ask entry written that way no longer matches that option, and compile does not warn:
  write the option's name. The comparison with the released matcher covers generated single-entry
  contracts and pinned cases, not every contract ([GAPS C72](GAPS.md)).
- Since v0.1.0, some Git command entries could miss a built-in run under one of Git's alternative names.
  Deny or ask entries naming `add`, `init`, `fsck` or `blame` were affected, as were entries for commands found in
  Git's helper directory but absent from Tego's command table. The fixed build applies those entries to the
  affected names in Tego's table and helper list. If you rely on these Git command rules, upgrade.
- Ledger roots outside `~/.tego`: versions v0.1.0 through v0.1.2 (including v0.1.1-rc.1) checked the ledger root's
  parent when deciding whether a write grant was inside a run's folder. With such a configured `ledger_root`, a
  grant inside an existing run's folder was not refused and could change that run's record and control files.
  Compile now checks the ledger root itself and refuses these grants, including through another mount of the same
  filesystem within the [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  This defect alone did not let the agent write its own newly created run folder: run start separately
  refuses a direct grant covering that folder. Upgrade if you use a ledger root outside `~/.tego`, and review write
  grants that reach existing run folders.
- Record verification in v0.1.0 through v0.1.2 could accept a record only as far as the line before an altered
  final line. This required write access to the record and no populated anchor entry for that run. Verification
  now checks a closed final JSON value and rejects malformed trailing content. An intact populated anchor
  remains necessary to detect a removed tail. An integrity check does not prove who made a record or that the
  actions in it were allowed.
- Kernel checks at root tiers: in v0.1.0 through v0.1.2, some preempting kernels could skip a program that should
  decide an action, without recording that loss. LSM checks were exposed before Linux 6.2, or before 6.1.54 in
  the 6.1 series, when kernel code could be preempted. The measured distribution defaults did not expose that
  older case. Exec pins were exposed on measured Linux 7.0 configurations. Listener cleanup could skip on
  preempting kernels. A run now reads the relevant skip counters. A detected
  decision skip ends a governed run with reason `error` and a gap saying its rules may not have held. An adoption
  reports the gap without ending the agent. Doctor withholds unsafe LSM modes and kernel exec assurance on the
  affected configurations. Exec pins and listener cleanup can still be skipped. Detection does not undo an
  action. Shared counters can end an unrelated run, and unmeasured vendor kernels remain a limit.

### Added

- In a terminal, `tego doctor`, `test`, `watch`, `learn`, `run`, `adopt` and `agents` end with a `next:` line on
  stderr that names the one command to type next. `TEGO_HINTS=off` turns these lines off, and `TEGO_HINTS=on`
  turns them on where stderr is not a terminal; they are never printed with `--json`. No stdout line changes:
  `tego doctor`'s Ready or Not ready line is on stderr, after its report.
- `tego learn <run> --save <name>` writes the proposed contract, compiled first, to the user registry, so
  `tego run <name>` finds it. It refuses a name that `tego run` would not find alone from the working directory
  or from the run's folder, a name that starts with `-`, and running under sudo for another user. The contract
  it saves has `reason: {reads: on}`, so a read the contract refuses is recorded at tier landlock too and a
  newcomer sees the refusal on every run; one line says what it costs (each read open about 17 µs slower), and
  `--reads off` leaves it out. The printed proposal, `--out` and contracts already saved do not change.
- `tego learn --allow-host <host>[:<port>]` (repeatable, at most 8) names the service a watched run reached at
  some of its addresses. Tego looks the name up now and writes `tcp://<host>:<port>` (`udp://` for UDP) in place
  of each address the run reached that the name resolves to. A later run is then allowed the addresses Tego's own
  lookups of the name return during that run, not only the one this run reached. An address no name may stand for
  (loopback, link-local, cloud metadata, or a range in the machine config's `denied_resolved_addresses`) stays an
  address. It writes nothing and exits 1 when the name does not resolve within 2 s, covers no address the run
  reached, resolves to a private address the run did not reach, or resolves to an address learn withheld after a
  secret read. It never chooses a name itself. When a proposal still allows addresses, stderr names them, and the
  `next:` line after `tego watch` and `tego learn` adds `--allow-host <host>`. The machine's resolver is never
  counted as an address to name (see Changed).
- After a run whose refused reads were not recorded, a `reads:` line on stderr says so, and
  `tego receipt --json` carries `reads_notified`.
- `tego setup` checks the machine from your shell and lists the six steps from install to an agent held by its own
  contract, each with the fact that decided it, then the one command to type next. It asks nothing, starts no
  program and needs no root; `--json` prints one object (`tego.setup/1`) and `-v` says where each fact was read. It
  stores its check in `~/.tego/state/check.json`, used only on the same boot with the same tego build; `tego doctor`
  still writes nothing. The installer ends with the one next command: `tego setup` when the installed tego has
  it, else `tego doctor`. `tego status` with no runs names `tego setup`.
- `tego receipt --json` adds a `binding` block: the run, its line count, its last line's id, whether it ended,
  the size and sha256 of `events.jsonl`, the tego that made the receipt (`receipt_by`) and its limits. No other
  key changes; a script that compares two receipts of one record across tego versions sees `receipt_by` differ.
  Binding checks every line as `tego events --verify` does, so on a long record `--json` takes 2.5 to 3 times
  as long (20,002 lines: 0.6 s against 0.2 s); the text receipt does not bind.
- `tego receipt --check <receipt.json> <run folder>` compares a kept receipt with a copy of its record on any
  machine, without chain.log: exit 0 match, 1 mismatch, 2 usage, 125 could not check (an older receipt, or a
  tego other than the one in `receipt_by`). It does not show that the record is complete or who made it, and
  anyone who can write both files can make a pair that matches.
- Dashboard: a finished run's Tighten tab has "Make a contract from this run". New contract, From a run, saves
  the draft where `tego learn <run> --save <name>` saves it (`~/.config/tego/agents/<name>.yaml`), through the
  same writer and with the same refusals, so `tego run <name>` in the run's folder and the `tego-agent@<name>` unit
  find it; "The project folder" still writes `agent.yaml` there. For the same run the file is the one
  `tego learn --save` writes, but for the header's `leaks:` line: the dashboard judges leaks by the run's verdict,
  not by learn's rule, so it has no such line, and for a run that leaked secrets the two can allow different
  addresses. A "Show refused reads (slower)" switch writes `reason: {reads: on}`: from a run it is on by default,
  as `--reads on` writes it; from presets it is off by default. Each address in a draft from a run says to write
  the host name. The dashboard now says the command line's words: Contracts, not Policies (nav, page titles, New
  contract, the Glossary), and Refused, not Blocked, for what a rule stopped, on the line page, in the built-in
  rules' names and in screen-reader labels too; Block now and live blocks keep their names. Addresses stay
  `/rules`, and `/contracts` leads there.
- At tier landlock a `deny_read` lets the agent read only the names each directory above the target held when the
  run started, so a file or directory made directly in one of them later cannot be read until the run ends; with
  the built-in `~/.ssh` entry, a new top-level entry in `$HOME` is one. Nothing said which directories those were.
  Now `tego run` prints one `note:` line naming them before the agent runs, `tego compile` prints the same note,
  `run_start` records them as `deny_read_frozen` (record minor 30), and `tego receipt` and the dashboard's Receipt
  tab name them under Coverage. What is refused does not change. A reader that does not know the field ignores it.
- `tego compile` notes an exec entry whose program file has more than one hard link, or is busybox, toybox or
  coreutils (`[exec-multicall]`, once per file, naming the entries that share it and its link count). On Ubuntu 25.10
  and later most coreutils commands are one such file, and an entry for one name can admit more than that name: at
  tier landlock, the file by any name to an agent that wins the exec race; on busybox, every applet at every tier.
  It changes no rule, exit code or `--json` table, and `tego run` prints it only with `-v`. `tego doctor` adds a
  `multicall` line on such a host, read from the file's link count and name. `docs/GAPS.md` C63 says what was
  measured.
- The dashboard's Overview shows the steps `tego setup` prints, in the same words: each step's state and fact,
  the one next step with its command to copy, and what is not known. It never checks the machine itself: it reads
  the check `tego setup` stored for this boot and this tego, and says "not checked since this machine started"
  without one. The dashboard also says what `tego receipt` says: the Receipt tab prints its sentences about
  connections and refusals word for word, a run's Refusals tab with nothing refused says the receipt's sentence
  (for a run that does not record refused reads, "No recorded action was refused", not "Nothing refused"), and a
  run's timeline, Refusals tab, Logs and Detections name tego's refusal of kernel TLS `built in: kernel TLS`, not
  "Not in contract". On the Logs page such a line says the receipt's sentence, not "not on the allowed hosts", and
  the Rule facet and By rule count it as `built in: kernel TLS`, as `tego receipt` does; a `rule:unmatched` query no
  longer lists it.

### Changed

- Compile and a root tier's run start now read the mount table through one strict reader. Compile reads the table
  twice and refuses one that changes while it is read, and it refuses a table whose mounts do not form one graph
  with a single root mount at `/`, as in a chroot whose root is not a mount point: every write and ask grant is then
  refused. Compile and `tego doctor` explain that the kernel does not show the filesystem under that root and give
  the remedy: bind the folder onto itself before entering it, or run Tego outside that root. A chroot whose root
  is a mount point, `pivot_root` containers, bubblewrap and `systemd-nspawn` retain ordinary grants. The kernel's
  unlinked-root marker is accepted only with a clean absolute prefix. Unlinked directory mounts remain uncertain:
  reaching write and ask grants refuse, and read-denial startup retains their alias uncertainty. Unlinked file
  mounts retain live protected-file identity checks under both files' snapshot mount IDs. An identity read error,
  failed holding-mount lookup, mount-ID mismatch or missing identity refuses reaching grants; established absence
  or a nonregular protected target needs no file comparison. An unplaced protected target keeps the backing warning.
  Several top candidates at the same mount point remain unknown before live selection, including mounts with the
  same parent and point, so affected grants and listener-decided denied reads retain their refusals.
  All captured and modelled tables in the compatibility inventory lack such siblings and keep their contract
  counts under replay; execution of the merged enforcement path remains owed in a guest.
  At run start, mount lookups are checked against the kernel's own mount ids, and overlay layers with a `..`
  component or an ambiguous `upperdir` or `workdir` spelling are not named there either.
- Record timestamps now follow the documented RFC 3339 profile. Newly refused forms are a comma fraction,
  a one-digit hour, offset hour 24 and offset minute 60. Every released Tego writer uses UTC with `Z` and an optional `.`
  fraction, so its records remain readable. A final chunk whose first top-level JSON value has closed is checked
  in full, including its suffix: non-whitespace suffixes are `line-malformed`; permitted JSON whitespace is
  complete and remains covered by the digest, so appended whitespace with a stale id fails. A refused timestamp
  is `line-malformed`, even without the final newline or with a stale digest; a suffix cannot hide it. Reader
  iteration, event views and receipt construction stop with a malformed-record error; receipt checking fails its
  chain step. The dashboard cache counts a terminated malformed line in `Bad` and continues. Its unterminated
  last bytes remain pending until a newline arrives, for valid and invalid timestamps alike.
- Tego v0.1.0 through v0.1.2 share a final-record framing flaw: a record whose last line was altered can verify
  only as far as the preceding line when no populated anchor for the run exists. An intact anchor entry detects
  the resulting head mismatch. Verification now checks a final chunk once its top-level JSON value has closed
  and rejects malformed trailing content.
- At tier cgroup without a decision-plane mode, a `setuid: true` contract with a `deny_read` or protected-name rule
  is now refused before the agent starts. The built-in secret list adds these rules, so ordinary contracts using it
  are refused in this combination. A setuid program can regain mount privileges and reach copied mounts outside
  the listener's marks. Remove `setuid: true`, or use a decision plane only where it holds the whole contract.
- Command patterns preserve option-name dashes beyond the usual one or two. Deny and ask entries keep the
  matches they had in the released build, except for an option word with an empty name (the known limits
  under Security), and also match the literal spelling; allow entries use only the literal
  spelling. Compile warns on more than two leading dashes or one dash before a long option name where the tool
  does not accept that spelling. Tool-defined single-dash long options and short words do not warn, including
  `go build -race` and `go test -run Test`. Tools without a known row keep literal single-dash option words,
  including `find -name file` and `java -jar app.jar`. The warning shows the entry and the ordinary spelling it
  probably meant. Use that spelling now; a later minor version will reject warned entries.
- Allow patterns cannot name selectors the command table discards, such as a Cargo toolchain or a gcloud release
  track. Remove the selector only when every variant may run. Deny and ask entries still cover every variant.
- Unique negated long-option abbreviations now keep their negation. The allow entry `git add --no-f` is now valid;
  a contract containing it previously failed to compile. No shipped example or preset uses these spellings.

- `tego learn`'s proposal opens with a `# WARNING:` line when it allows addresses, since a later run can be
  refused a connection this run made, and writes an entry by host name where the run's record holds the name an
  entry allowed. YAML keys are unchanged.
- `tego learn` no longer lists the machine's resolver in `net.allow` when the proposal has another TCP or UDP
  entry: port 53 of an address where every line of the run's record says `net.resolver`, such as
  `udp://10.0.2.3:53` on AlmaLinux 9.8. A comment under `net:` names what was left out. A run under the contract
  still reaches its resolver, because Tego allows the run's own resolver (from `/etc/resolv.conf`, or the machine
  config's `resolver:` list) before it reads `net.allow`. The entry was not needed where the contract was learned,
  and copied to another network it allowed whatever answers at that address. With no other TCP or UDP entry (a run
  that only looked names up), learn keeps the resolver as before, with a note: without any such entry the kernel
  layer opens no port 53, and from Linux 7.2 (Landlock ABI 10) it may refuse a lookup the run sends over UDP. TCP
  lookups pass, because Tego makes the allowed connect itself (measured at Landlock ABI 4 and 6). A run is now
  refused that address where it was allowed before only when learn left it out and the run's resolver is a different
  one (another network, a changed `/etc/resolv.conf` or `resolver:` list) or the contract sets `net.dns.mode: off`
  or `broker`. Port 53 of an address with any other line in the record is still proposed.
  `--allow-host` with a name that stands only for the resolver now exits 1 and writes nothing.
- `tego adopt --boundary`, and a boundary guard, applies a `cpu`, `cpu_weight` or `pids` limit (the machine config's
  ceiling, or the contract's own) to the agent's cgroup before it moves the agent: the agent is throttled, and a fork
  or a new thread past `pids` fails with `EAGAIN`. The kernel ends no process for them, though a program that cannot
  start a thread may end itself. `tego adopt`'s notice before the adoption says them; a guard does not. It is refused
  (exit 125, `[adopt-refused]`), with nothing moved, when the machine's cgroup root does not enable the controller
  (`cpu` on a stock RHEL 9: the message names the setup), and when the agent's tree holds as many tasks as `pids` or
  more, since its next fork would fail at once: the message gives the count and the limit. A `memory`, `memory_high`,
  `wall` or `stall_after` ceiling still refuses it, named at its file and line: every `tego run` gets that ceiling,
  and an adoption cannot hold it. A budget ceiling (`tokens`, `cost_usd`, `repeats`) does not refuse it: one
  `[unenforced]` warning per budget, and the run records that the budget was not metered. A record-only adoption
  applies no limit, goes on, and warns once for each ceiling. The record does not yet say which limits an adoption
  applied.
- Dashboard: the `landlock-topology` refusal reason reads Run boundary, not Sandbox boundary. The reason code is
  unchanged.
- The sentence that tells an agent about a `landlock-topology` refusal says "it reaches a process outside this run",
  not "a process outside this run's sandbox". The reason code is unchanged.
- `tego doctor`'s capability row `deny read of secret paths` at tier landlock now says that held reads, the
  default, refuse a target under a writable parent, and that `fs.reads: direct` leaves it unenforced. It said
  only "unenforced under a writable parent", which held reads made untrue before v0.1.0. What a run does is
  unchanged.
- Released command rules missed some name interpretations of a multicall program (one file under many names,
  such as uutils coreutils on Ubuntu 25.10 and 26.04). v0.1.3 expands `exec.deny` and `exec.ask` matching to the
  names such a program can pick its behaviour from; `docs/spec/exec-command-rows.md` ("Multicall applets by
  name") states what the matcher reads. Build-specific limits remain: Ubuntu 26.04.1's patched uutils
  refused the affected interpretations (measured); upstream uutils, read from its source, supports them.
  `exec.allow` does not read these names. A deny entry still wins over an allow entry, so a contract
  that denies a utility name may now refuse an exec that an allow entry admits, when one of the exec's names reads
  as that utility.
- A Locked run (the default, and the only mode at tier landlock) is no longer loosened by a live MCP tool switch
  or model route. `tego mcp allow` or `ask` past the contract's decision, `tego route set` to any route but
  `direct`, and the same changes on the dashboard's MCP tools and Model routes pages are refused with `[locked]`
  (exit 1) and the words a lift of a Locked run gets. A tightening, `tego mcp reset` and `tego route clear` still
  apply, and both kinds of change still loosen live on an Adjustable run. The relay and the forwarder do not check
  the mode themselves, so a change written into the run's folder another way still applies
  ([GAPS C39](GAPS.md)). The sentence every Locked refusal prints, `tego lift`'s included, now reads "`<run>` is
  Locked: it keeps to its contract while it runs, so nothing loosens until its next run"; it named the kernel,
  which holds neither a tool switch nor a route. The dashboard's preview of a refused change says "Not done: ",
  as its flash does, and links back to the page.
- In large Docker images and rootless Podman with FUSE, the optional Claude Code refusal hook may not be set up.
  The run continues with a `harness-hook-refused` warning. Refusals remain available through the reason file.
- A command rule's decision uses more memory. An exec of a program that command entries name is now read by two
  readers, the corrected one and the one earlier releases used (see Security above). Against v0.1.2's code on a
  hosted CI runner, the bytes allocated per decision rose by 10.5% for a script, 16.2% for a command with 16
  arguments and 17.4% for one with 128. An exec of a program no command entry names is unchanged, and a decision's
  time stays inside its documented budgets ([BENCHMARKS](BENCHMARKS.md)).

### Fixed

- Refuse root-tier runs whose compiled `deny_read` path entries have an existing mount alias on the same
  filesystem instance that the tier cannot hold. At tier cgroup where the fanotify listener would decide reads, a run
  now refuses to start when a denied folder, or part of it, is visible under such another name. No flag
  overrides this. A selected decision plane still holds whole-folder aliases on that same instance; a part
  mounted outside its denied folder refuses at bpflsm and at cgroup after fallback. The error names the first
  matching paths and places, counts the rest, and gives remedies. Doctor names visible second places for home
  or other built-in protected targets and the affected mechanisms. When an unlinked directory or unclassifiable
  root prevents a complete alias answer, doctor names the mount and says it cannot tell whether the folder is
  visible under another name. Known alias warnings remain, without assurance for the uncertain tree.
  A different filesystem instance showing the same data, such as a second network mount of one export, a FUSE
  mirror or a loop image, is not recognised at any tier. Deny the other path too, or avoid mounting the
  same export twice where agents can read it. For
  recognised network mount types, the same source string on different filesystem devices produces a warning,
  not a refusal. Name-entry scopes receive no alias check. Later host mounts and ancestor renames are not
  tracked (docs/GAPS.md C68).

- Compile and run start preserve carriage returns at the end of overlay layer options. The previous reader
  silently changed those names and could admit write or ask grants through a backing alias when a decoy path
  without the carriage return also existed. The snapshot size bound now counts actual input bytes.
  Binary overlay layers with a parent (`..`) component or ambiguous backslash quoting in `upperdir`/`workdir`
  now refuse write and ask grants, rather than compare a changed path. Use absolute layer paths without those
  ambiguities or install Tego on a plain filesystem. These kernel layouts are owed in a guest.

- Compile's mount analysis now follows the precise [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  Same-point stacks use parent relationships and supported live checks, including when a mount moved onto another
  appears earlier in mountinfo. Ambiguous visibility refuses affected write and ask grants and names the mount point.
  An unreadable mapped overlay layer candidate refuses rather than disappearing. Malformed mount rows refuse the
  table. Unknown protected or grant identity and binary candidate inspection errors also refuse with a named remedy.
  Ordinary host, CI overlay and workspace-volume fixtures each retain 19 accepted contracts, with exactly 11 volume
  warnings; project-with-chroot retains 17. Privileged moved-mount checks are owed in a guest.

- Compile now holds any `tego` or `tego-control` in `~/.local/bin`, `/usr/local/bin`, `/usr/bin` and `/opt/tego/bin`,
  beside the running and PATH binaries. Alias and binary overlay layer coverage is exactly the
  [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  A binary with a second hard link refuses every write entry on its filesystem, unless only root may write it and
  the agent is not root. Install a fresh copy with one name outside every write entry and run that one. An absent
  host layer alone refuses no grant, regardless of merged ownership. Relative overlay layers and unnamed FUSE,
  eCryptfs, aufs or shiftfs backing have the same stated limit; closure bounds still refuse grants. A write entry over
  a PATH folder searched before tego stays a `path-shadow` warning.
- A paused run whose launcher died (killed, crashed, out of memory) read as plain `lost`. `tego status` now says its
  last recorded state was paused and reads its scope for what is true now: STATE `lost, frozen` only when the scope is
  frozen, and the line under the table says when it is not (a stop thaws a run before it signals, so a launcher killed
  during a stop's grace leaves a run whose record says paused and whose processes run). `--json` adds
  `launcher_gone` and `scope_now`. `tego pause` and `tego resume` refuse such a run (`[lost-paused]`), and Tego never
  thaws it. `tego stop` attempts cleanup with `cgroup.kill`, reads the scope again and says what is left. For this
  lost-paused case it succeeds (0) only after record closure and a final scope read confirming absent or empty.
  Remaining frozen/running processes give `[lost-paused]`, 125; an unreadable final scope says "cannot tell" and
  uses the same status. The dashboard shows "Lost,
  last recorded paused". At tier cgroup and bpflsm the run's reaper already ends such a run at once. A launcher is
  judged gone by its lock and its pid's start time, never by the pid alone; one whose identity cannot be read is no
  longer taken for gone by `tego stop` and the sweep, and an exited launcher not yet reaped is. Sweep also keeps an
  unreadable scope, failed cgroup-id read or failed events read unknown, retaining its record and retry entry until
  cleanup can be confirmed. Retention reclassifies each run through its locked directory before choosing cleanup,
  including a run that started and lost its launcher after an empty sample. Unknown ledger state also keeps the
  record for retry even with a free lock; restore access or repair the record, then repeat GC.
- **Behaviour change:** compile now reads the mount table, and refuses a write entry or ask scope that reaches a
  kernel interface filesystem (proc, sysfs, cgroup, bpf, mqueue, resctrl and the others the docs list; devpts allowed
  only at `/dev/pts`)
  by its mount type, or an alias of one of Tego's own places or a directory read on its path walk, including names
  before `..`, within the [compile-time mount boundary](adr/0059-no-run-writes-what-a-later-run-loads.md#compile-time-mount-boundary).
  Terminal opens through aliases outside `/dev` are also refused by device identity. It read only the usual mount points by name, so a bind
  mount or a second mount of the cgroup filesystem inside a write entry let a run change other runs' cgroups, a
  paused one's freezer included. Ordinary triggers: a container's or chroot's root with its own `/proc` inside the
  granted folder, and a grant on `/dev` itself (`/dev/mqueue` is mounted there). A mount table compile cannot read
  whole and parse strictly refuses every write and ask grant. A FUSE type alone adds a mount advisory;
  identified protected source places and aliases still refuse.
  An absent host layer path (ENOENT or ENOTDIR), a relative overlay layer, or unnamed FUSE, eCryptfs, aufs or shiftfs
  backing alone refuses no write or ask grant. Ordinary grants compile in large Docker image, Podman FUSE and
  encrypted-home layouts. Tego never guesses where a relative layer lives; visible absolute layers and binary names
  remain protected. When a FUSE or eCryptfs filesystem holds a protected regular file, its existing absolute source
  directory joins the protected closure with its visible aliases: grants at, over or inside it refuse. Source text
  cannot establish FUSE backing identity; eCryptfs also keeps its backing warning because live lower-directory identity is not established.
  `..` and ambiguous upper/work quoting still refuse. With any of these backing limits, compile
  emits one `overlay-backing-unknown` warning per write or ask entry that reaches another visible storage mount. For
  relative layers and unnamed backing, another binary's device can still hold the backing folders; only the affected
  filesystem's own device is excluded. All cases exclude the shared inventory's kernel interfaces and memory
  directory storage; regular-file binds established by live checks can still warn on memory filesystems. The absent-only rule also
  excludes discovered binary overlay devices. Runtime storage on a memory filesystem mounted at a writable
  directory gives no warning (GAPS C65). A single-file mount is exempt only for absent or relative overlay backing,
  after live snapshot-bound mount ID, type, size and protected-file difference checks. FUSE/eCryptfs binds never get
  this exemption: stored bytes can differ from visible bytes. Nonempty byte-identical protected-file aliases still
  refuse, executable or not. Two empty files prove neither identity nor difference and warn without a byte-alias
  refusal. Agent fixtures keep Docker's `/etc/resolv.conf`, `/etc/hosts` and `/etc/hostname` binds quiet in the overlay
  classes with replayed `statx` IDs; runtime silence is owed in a guest. Captured Podman FUSE project grants reach
  no file bind; grants reaching one warn once, including empty `/run/.containerenv`. Unreadable protected files and
  unknown or changed mount points get no file-bind exemption. The warning names the grant, mount and each
  protected file directly on unnamed backing, including a config layer or a contract on sshfs even when Tego
  itself is on ext4: Tego cannot
  tell whether that mount shows the folders holding protected files, with the relative-base or filesystem reason. Keep
  runtime storage and the whole host filesystem out of writable places. For unnamed backing, keep the folder that
  stores the encrypted or mirrored files out of every write grant. No such grant and mount
  means no backing warning; a separate mount advisory may still print. A differently spelled alias may remain
  uncorrelated. Runtime fixtures now replay 2026-11-12 captures from Docker 29.1.3, containerd 2.2.1 and rootless
  Podman 4.9.3 with fuse-overlayfs 1.13 on Ubuntu 24.04, kernel 6.8.0-147-generic. They cover mixed relative lowers
  and absolute upper/work, real option tails and `fuse.fuse-overlayfs`. The alternative `fuse.overlayfs` remains
  synthetic. Capture runs used older head `69541c0706dd39125a004cc60f7ec046898e63be`; this branch's container
  reruns are owed in a guest.
  The dashboard describes historical paused orphan ends as record closure; those ledger lines alone do not prove
  which cleanup method ran. Stop output also reports record closure without claiming a kill, then reads the scope
  again and says what it shows after the sweep. Record closure alone does not make a lost-paused stop successful:
  processes remaining or an unreadable final scope give `[lost-paused]`, 125.
  "Why compile now refuses my grant" in `docs/user/built-in-refusals.md` explains the warnings and refusals.
  A run whose launcher cannot be judged now reads `(launcher unknown)` in `tego status`, with what
  to do, instead of plain running or paused.
- `tego doctor`, and a run's tier check where it probes the decision plane, could now and then fail a plane mode's
  known answers with "hold /proc/<pid>/root/.../x/xd: no such file or directory" and so not offer that mode. The
  probe's child makes its own mounts on the thread its main is locked to, and doctor sees them through
  `/proc/<pid>/root`, which shows the main thread's mounts only; when Go had moved the child's main off that thread
  first, the mounts were not there. The child now always runs on its main thread, and refuses to start, with the
  reason, if it is not. Seen once in a KVM root suite; a guest test showed the cause by forcing the child off its
  main thread. v0.1.1 has the same flaw (read from the code).
- Over SSH and on a console login, the `next:` lines no longer loop (`tego setup` named `tego doctor`, which named
  itself). Such a login starts outside your user manager's cgroup, where Tego starts no run, not even `tego watch`.
  `tego setup`, `tego doctor`, `tego run`, `tego watch` and `tego test` now say so and name the command that opens
  a shell inside it, `systemd-run --user --scope bash` (your login shell when it is bash, zsh, fish, sh, dash, ksh,
  mksh, tcsh or csh and on `PATH`), and then to run `tego setup` or the command again there. `tego learn --save`
  and `tego agents` do the same where their next step would start a run: they say that command, to type in the
  new shell. Tests check, from an SSH login, a console login and such a shell, that no `next:` line names the
  command that printed it or one that fails from that shell (see the next entry for two more places). `doctor` no
  longer says such a shell "can only record", and `tego test` no longer says "Nothing got through" when no run
  under Tego started. After a reboot, `tego setup` says which place is not checked since the machine started.
  With several contracts, step 5 names the one your newest enforced run used. `tego learn`'s refusal of an
  `--allow-host` name ends with the command without it, and the learn step names `--allow-host` only when no
  secret of the run may have gone to an address it reached, on `tego watch`, `tego learn` and `tego setup` alike.
  Saved contracts call themselves a contract in their header. The dashboard's "Make a contract" opens New
  contract from that run in one click, and its sign-in text names `tego serve`.
- Four more things a new user met (a second guest walk on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44):
  - `tego learn` for a run that read a secret and then connected out withholds that destination, and its warning
    still said `Name each with --allow-host <host>`, which learn then refuses for that host. The warning now says
    which destination was withheld and why, and the two ways that work, both your own choice: write the host's
    name under `net.allow` in the saved file, or, after a run under it is refused that connection,
    `tego rule <run> <line> --allow`. Nothing re-admits it by itself.
  - On Fedora 44, `sudo "$(command -v tego)" agents` typed inside a `systemd-run --user --scope` shell sent you to open that shell
    again, since sudo there opens a session of root's own. Tego now reads the cgroup of the shell you typed sudo
    in (the nearest parent outside root's own sessions), so from inside the scope it names the step itself, to
    type without sudo. Unit tests check this; it has not yet been run on Fedora.
  - A user with no user manager running (a nologin service account reached with `sudo -u` or `su -s`) was told to
    enable systemd user delegation, and `tego setup` and `tego doctor` named each other. Both now say no user
    manager runs for the user and name `sudo loginctl enable-linger <user>`, with the user's name from the passwd
    database (or the uid, when loginctl would read the name as an option or a uid). On Fedora 44, after that
    command, `tego setup` in the user's scope said `ready: tier 1 (landlock)`. Once the manager runs, a shell that
    has no `XDG_RUNTIME_DIR` (after `sudo -u` or `su`) is no longer left with no command: when `/run/user/<uid>`
    is the user's and holds its manager's socket, the `next:` line is
    `XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`. Unit tests check these lines; they have not
    yet been run in a guest.
  - For the few seconds before a run's first record line is written, `tego mcp allow`, `tego lift`, `grant`,
    `restore`, `route set`, a timed or read or write `tego block`, and the same dashboard actions said the run is
    Locked (or was started by an older tego). They now refuse with `[starting]`, "... is still starting ...; try
    again in a few seconds", and write nothing; the same command worked seconds later. A first record line that
    is there but is not one this tego can read (a damaged line, or one a newer tego wrote) is refused with
    `[start-unreadable]` instead, with no "try again", since waiting does not change it.

  Tests now also check `sudo "$(command -v tego)" agents` from an SSH login and from inside the scope, and the user with no user
  manager, before and after linger: no `next:` line names the command that printed it, a shell inside the user
  manager is not sent to open one, and `tego setup` and `tego doctor` do not name each other. The `sudo` cases are
  built from the cgroups the guests logged; on Fedora 44 only the command's own cgroup was logged, so the cgroups
  of sudo and of the shell it was typed in are assumed from how sudo opens root's session. Places outside those
  tests are not covered.
- Two more lines for a service account (a third guest walk on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44):
  - After `sudo loginctl enable-linger svc`, `sudo -u svc -H sh -lc 'exec "$(command -v tego)" setup'` named `XDG_RUNTIME_DIR=/run/user/<uid>
    systemd-run --user --scope bash` and did not say to run it as `svc`. Typed by the administrator in their own
    shell, it opened the administrator's own shell (where `tego setup` then said ready, for the wrong user) on Ubuntu
    and AlmaLinux, and failed on Fedora. When tego was started from another user's shell through `sudo` or `su`, the
    line is now `sudo -u svc XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`, the name from the
    passwd database and the uid as a number, and the words say to type it in your own login shell and that it opens a
    shell as `svc`, not in yours. `tego doctor`'s `fix:` line and the error line of `tego run`, `watch` and `test`
    name the same command there; before, they named the bare `systemd-run --user --scope bash`. Tego tells that from
    the session's login uid and the owners of the processes above it, not from `SUDO_UID`. Typed by `svc` in its own
    login, the line is as before. A passwd name that starts with `#` (which `sudo -u` reads as a uid) or `+` is
    written as the uid. `tego setup --json` adds `as.scope_as`. That `sudo -u` command, with `tego setup` in place of
    the interactive `bash`, was run in the guests and ran `tego setup` in `svc`'s user manager, ready at tier 1. The
    new words and the choice between the two lines are checked by unit tests; a root test in a guest also ran the
    `fix:` line's choice over the real `/proc`, for a process started by one of another uid, not through real `sudo`.
  - For an account whose name systemd refuses (digits only, such as `4242`, among others), linger starts no user
    manager, and `tego setup` named the same linger command again. `tego setup` and `tego doctor` now say that
    systemd runs no user manager for this account's name, name no `next:` command, and say to run the agent as an
    account whose name starts with a letter. `tego setup --json` gives that step the new `next.rule`
    `check-no-manager-name`. The rules for names are systemd's (systemd.io/USER_NAMES). The digits-only case was run
    in a guest before this change; that the other refused names get no user manager is read from those rules, not
    run; the new lines are checked by unit tests only.
- `tego learn` writes the contract's `name:` in double quotes, as `tego init` does. An agent name that YAML reads
  as a number, a bool or a null (`123`, `true`, `null`) was written bare, so `tego learn --save 123` failed with
  "name must be a string" and `--save null` with "name is required"; both now save.
- `tego receipt` and `tego watch`'s `seen:` line no longer count glibc's `connect(AF_UNSPEC)` resets and the
  kernel's netlink socket as places the run connected to: the first watch of a Python fetch said `most: unspec`.
  They are counted apart as routine socket calls that name no place, as the dashboard already folded them, and
  the dashboard's Receipt tab shows the count. `tego receipt --json` adds `routine_sockets`, and `connections` and
  `connection_tries` no longer count these calls. A refused one, such as a send to an `AF_UNSPEC` address, is
  still counted and listed as a refusal.
- `tego run`'s summary, `tego receipt` and the dashboard's Receipt tab say that the refusal of OpenSSL's
  kernel-TLS probe (`setsockopt(TCP_ULP, "tls")`, refused under every `net:` section) is built in
  (`built in: kernel TLS`), not "not allowed by any rule": no rule can allow it. It still counts as a refusal,
  and `--json` is unchanged.
- `tego receipt` and the dashboard's Receipt tab no longer say "Nothing was refused." for a run that does not
  record refused reads (tier landlock with `reason.reads` off): they say no recorded action was refused and that
  refused reads are not recorded. `tego receipt --check` on a receipt whose `receipt_by` names no tego build says
  so, in place of blank version words; it still exits 125.
- `tego doctor` says when a machine limit ceiling uses a cgroup controller that is not enabled, so that every
  `tego run` is refused at start (for example `limits.cpu` on a stock RHEL 9 host). It names the ceiling, its
  file and line, and the fix. The tier it reports does not change.
- `tego doctor` on RHEL 9 (and Alma or Rocky 9): the kernel line no longer lists Landlock ABI 2 to 6 as missing
  when the kernel answers ABI 6. Its Landlock entries now come from the ABI the kernel reports, as the `landlock`
  line does, and it says "below the upstream tested floor 6.1.0". On a kernel without Landlock it lists every
  Landlock entry. As root, its `cgroup connect_unix` entry follows what the programs check found. For a user whose
  cgroup is not offered cpu, the cgroupv2 line and a refused run's message now start with the administrator's
  steps and say why the user cannot add `+cpu` alone. The tier doctor reports and its exit code do not change.
- The dashboard's Receipt tab of a running run shows its time taken as a clock in all three places (the top
  line, the tile and the chart's axis); the top line and the axis stood still while the tile ticked, and the tab
  was sent again for a change of seconds only.
- Tiers cgroup and bpflsm: a look at a build's lock (the linger timer's, a sweep's) let the lock go by closing
  the file, so a child that the same process started in that moment could hold it until its own program started.
  The timer could then find the build still held and wait one more `bpf.linger` before removing it. Each look now
  lets the lock go explicitly.
- A process reaped while Tego read its `/proc/<pid>/stat` is read as gone, not as a malformed file. The kernel
  writes that line with process group -1, which Tego refused as malformed since v0.1.0: `tego adopt --pid` then
  printed `read process <pid>: ... malformed stat line: pgrp "-1"` `[io]` where it prints `no process <pid>`
  `[adopt-refused]`, and tiers cgroup and bpflsm kept the slot of a launcher reaped during the check until the
  next one. The kernel writes the same line for a live process when a thread other than its leader runs `execve`,
  so the line alone does not say the process is gone. Tego reads the file again: no file means gone, and a live
  line is used. A line that stays this way after three reads is still refused. The stat parser also refuses pid
  0, which no kernel writes.
- The MCP relay and the HTTP ask hold also read `/proc/<pid>/stat` again when its line has process group -1, as
  above. While a thread other than the leader of the process ran `execve`, an MCP relay shim could be refused at
  admission or when its server started, and a held HTTP request could be refused with `ask-unavailable`. A gone
  process, and a line that stays this way after three reads, are still refused.
- The Claude Code hook sometimes told a refusal one request late (once on a CI runner, where the reason file still
  did not list it more than 70 ms after its ledger line). The reason file the hook reads was written after the run
  directory's copy, under one lock, so a slow write there could hold it back; it is now written first. What held it
  back on that runner was not measured, so this may not remove every case. A refusal can still reach the hook one
  request late, at every tier on a busy machine, because its ledger line can be written just after the agent saw the
  refusal; it is then told by the first later hook that finds it in the file, still once. A script that reads
  `$TEGO_REASON` right after a refused call should wait for the refusal to appear.
- On a machine whose core utilities are one program file under many names (Ubuntu 25.10 and 26.04, about 115
  names), the dashboard's "Also apply now" after removing a program such as `/bin/ls` from `exec.allow` refused
  every other name of that file in the running run too, `/bin/sleep` among them, though the new rules still allowed
  them. That block now refuses only what the run was granted under the removed entry: the file at the path the entry
  led to when the run started, by any name that reaches it there. Where a program the rules keep leads to the same
  file by the same path (busybox's links all lead to `/bin/busybox`), it still refuses that file, as before. A block
  you place yourself (`tego block <run> exec /bin/ls`, Block now) still refuses the whole file, and `tego block` now
  names a few of the other names it refuses and how to block one name. When a block refuses another name of its file,
  `tego run`'s summary, `tego receipt` and the dashboard say so: "/bin/sleep: refused, same program file as /bin/ls,
  which is blocked". Runs started by an older tego keep the old block until they end; restart them to get the new
  one. A tego older than this release cannot read such a block's file (overlay version 5): its `tego block` and
  dashboard say the file is invalid and change nothing on that run.
- At the root tiers a run now ends with reason `error`, a `bpf-decision-skip/shared-build` gap and a receipt that says
  its rules may not have held (`rules-uncertain`) when the kernel skips a program that decides its actions, which
  before went unnoticed; a run with no skip is unchanged. An adoption first reports after run_start, then at most
  once a minute plus polling and scheduling delay, without ending. Partial report retries keep only unwritten
  lines, and observed outage openings and recoveries are retained in order, even between reports.
  `tego doctor` no longer offers the plane's LSM mode (tier 3) on a kernel before 6.2 (6.1.54 in the 6.1 series) that
  preempts kernel code, whose BPF trampoline can skip LSM programs too, and on a kernel that preempts kernel code
  (every 7.0 kernel) it says exec rules on argv are best effort, so `exec.assurance: kernel` is refused there
  ([GAPS C53](GAPS.md)). It also warns that listener cleanup can still be skipped on affected or unproven kernels:
  skips are detected, and a detected shared skip ends launched runs relying on it; adoptions report without ending.

### Record `v`
1 (`spec/record/v1`, record minor 30)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.2 - 2026-11-11

This patch fixes one flaw in how command rules read long command lines. It changes no other code.

### Security

- Command rules (`exec.deny`, `exec.ask`, and `exec.allow` entries with words after the program): Tego decides a long
  command on its first part (32 arguments, or fewer when they pass 8 KiB) when the rest cannot change the answer. In
  three forms the rest could still change it, and the command was decided on its first part anyway, so it ran though
  its whole command line is refused:
  - python's `-m` as the last argument of the first part, with the module after it: an entry on the module, such as
    `deny: [pip install]` or a bare `deny: [pip]`, was not applied;
  - cargo's `--config` or gcloud's `--flags-file` after the subcommand: `--config` can define an alias that runs
    `cargo publish` under another name, and `deny: [cargo publish]` was not applied to it; under `allow: [cargo build]`
    such a `cargo build` ran, which Tego refuses because it cannot tell which subcommand runs;
  - options after the `-c` of sh, bash, dash, zsh or ksh, or after the `-e` of perl or ruby, enough of them that the
    whole command line cannot be resolved (more than 16 ways to read it), which Tego refuses.

  Present since v0.1.0: the new tests fail on trees of v0.1.0 and v0.1.1 (unit tests, not run in a guest). The file
  and network rules, and which programs `exec.allow` lets run at all, were not affected. If you rely on command
  entries in `exec.deny`, `exec.ask` or `exec.allow`, upgrade to v0.1.2. These commands are now read to their end,
  or until no later argument can change the answer. A command that would have to be read past 8192 arguments or
  128 KiB of argument text to be decided is refused (`args-unreadable`), where before it could be decided on its
  first part.

### Record `v`
1 (`spec/record/v1`, record minor 29)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.1 - 2026-11-11

This patch tightens the built-in refusals around an agent and checks the file identities and security labels
used for approvals. Receipts and the dashboard give more reliable results for long runs, `tego rules` brings the
rules view to the terminal, and release automation adds signed container images alongside the binaries. MCP tool
rules remain a preview, with the limits below.

### Security

- Tiers cgroup and bpflsm, on overlayfs: on kernels that have `file_operations.fop_flags` but keep FMODE_BACKING at
  bit 25 (RHEL 9.8, RHEL 10.0 to 10.2, Linux 6.10 to 6.13, and 6.12 stable before 6.12.105), the decision plane did
  not recognise an overlayfs backing file. An agent could map a file under a write entry readable and `mprotect` it
  executable, which lets it run that file's machine code although no `exec.allow` covers it. A direct executable
  `mmap` was still refused. Present since v0.1.0. The plane now recognises a backing file whether FMODE_BACKING is
  bit 24 or bit 25, which covers every kernel checked from 5.14 to 7.1. Measured on AlmaLinux 9.8 and 10.2 for a
  file already on the overlay mount: the old build allowed it and the new build refuses it. The other kernels in
  the list are read from their headers.
- Syscall outcome hooks refuse loading or adoption unless tracefs proves an eight-byte return at offset 16.
  Doctor and run tier selection withhold root tiers on unverified layouts and retain the reason.
- Enforcing runs refuse protected host IPC, Tego control surfaces and other terminals before grants. Own
  runtime, fixed SSH-agent exceptions, inherited terminals and policy-checked own PTYs work; exact
  container-daemon socket grants warn of escape authority. Root tiers add native Unix peer checks and reject
  `io_uring: true`. Limits remain for inherited descriptors, new outside FIFOs, unlisted server paths and
  datagram/copied-path cases without native checks.
- Held opens require matching complete AppArmor labels with proven root namespace visibility, or matching
  SELinux contexts and `fscreate` for potential creation. Smack refuses: another task's rules cannot be queried.
  Unknown facts refuse approvals and alternates. An unprivileged syscall discovers LSMs behind masked
  securityfs. Containers need them; hidden AppArmor namespace depth gives `EACCES` / `held-label-unavailable` by
  default. Administrators can waive only unreadable depth with `fs.apparmor_assume_root_namespace: true` in the
  top-level contract, accepting hidden-ancestor risk; compile warns and `run_start.best_effort` records it.
- Held reads track protected identities through renames, hard links, replacements and moves, including
  denied-directory descendants. Approvals (including write-only) and alternates recheck opened identities. Lost
  mutation history or unsupported filesystems refuse held reads; new name matches outside the launch snapshot
  and mount changes undone between reads remain limits. Held writes recheck live blocks.
- Record, lock and anchor writers reject hard links for everyone. Owners can still alter records; historical
  readers and garbage collection gain no link-count checks.
- Stdio MCP starts pin the admitted shim's exact child before exec, refusing preexisting children; failed
  registration refuses. `mcp relay *` grants use an authenticated private stage, honoring denies/asks without
  permitting other children or subcommands. Protocols v1/v2 refuse: rebuild launcher and shims together. MCP
  stays a preview (`tego serve --preview` exposes its dashboard link): ptrace/socket-copy authority can bypass
  decisions and their record; alternate command spellings need separate exec rules ([GAPS C50](GAPS.md)).
  Hardening remains [proposed in ADR
  0126](adr/0126-mcp-tool-rules.md#proposed-amendment-2026-11-03-preview-or-security-boundary).
- Boundary adoption arms its empty destination before moving processes. The agent cannot use `CAP_SYS_ADMIN` in
  any user namespace, covering mount changes and mount-namespace installation; missing hook proof refuses
  adoption. Record-only adoption stays unrestricted. Earlier changes, operations past capability checks, outside
  processes, inherited descriptors/mappings and pre-attachment actions remain outside protection. Adoption
  refuses network contracts (`net:`); it cannot enforce them.
- Node rules scan config and dotenv options wherever Node scans them. Expanded parsing needs exact standalone
  Linux x64 builds 20.19.4 or 22.21.1; others keep bounded parsing plus these scans. Unknown builds may miss
  code-loading options; external `NODE_OPTIONS` preloads remain unread.
- The release is built with Go 1.27.4, which fixes GO-2026-6859 in net/http: an HTTP/1 server could crash when a
  handler reads a request body limited by `MaxBytesReader` while response headers are written on another goroutine.
  tego-control's dashboard is an HTTP/1 server on 127.0.0.1 and limits form posts with `MaxBytesReader`; it reads
  each form in the handler's own goroutine, before writing a response.

### Fixed

- On RHEL 9 (AlmaLinux 9.8 tested), systemd turns on the memory and pids controllers by default, but not cpu.
  `tego doctor` failed on that and found no tier, so every enforced run was refused, including runs with no
  limits, for a user and for root. Now only a run that sets `limits.cpu` or `limits.cpu_weight` is refused, at
  start, and doctor and the refusal give the one-time setup that turns cpu on (`docs/TIERS.md`, GAPS B15). A
  `limits.cpu` ceiling in `/etc/tego/config.yaml` gives every `tego run` a CPU limit, so with one they are all
  refused, although `tego doctor` still reports tier landlock for a user. Memory and process limits apply. For
  root, doctor's fix now names a CPU weight on system.slice instead of user@.service, because a hand-written
  `+cpu` in the root cgroup does not last under systemd.
- RHEL 9 root-tier runs with `net.listen` can attach their required bind/listen outcome hooks. Bind, listen
  and exec outcomes use the individual syscall event's BTF context; v0.1.0's listener preparation failed on
  the tested RHEL 9 5.14 layout. No required hook or enforced property is dropped.
- Root-tier recording samples shared tracing skips from the programs executing through active links.
  Receipts and views report `bpf-trampoline-miss/shared-build` as shared skipped executions, with incomplete
  coverage, rather than known lost events. Missing, changed or unreadable attachments/counters report uncertainty;
  skips may belong to other runs or ungoverned tasks, and overlapping runs may count the same skip. Preemptible
  kernels can still lose records (GAPS C53).
- Built-in `.env` rename refusals and `tego learn` explain root-tier pip's name-coverage limit (C55) and its
  measured contract/cwd remedy in [OPERATIONS.md](OPERATIONS.md#directory-moves-and-protected-names-c55).
  Write entries alone add no name coverage; pip's copy fallback can exit 0 while recording rename refusals.
- Kernel-matrix guests prepare delegation and authenticated Unix diagnostics/loop modules; doctor-only checks
  accept combined remedies. Automount tests use the same kernel's native result, and conformance releases
  compile-only fixture trees before kernel tests. The 6.1 plane retains its probe reader and kernel minimum.
- Protected host-server paths that the invoking user cannot traverse no longer prevent startup; reachable
  objects remain pinned and unexpected identity errors still refuse launch. Compiled built-in entry names stay
  the same when host servers are installed or removed.
- Native Unix peer checks use the correct kernel-memory reader, and protected-name walks keep the original
  verifier instruction budget across kernels.
- Permitted overlay copy-up can use kernel-installed filesystem credentials without granting the agent
  CAP_SYS_ADMIN; task-initiated mount changes and trusted xattr operations, including through an io_uring
  personality, remain refused. Missing kernel bind/listen metadata is explicitly disclosed instead of inferred
  from a copied attempt. Frozen bind lookup errors keep supervisor ownership and one observed result with their
  actual errno.
- Interactive Claude examples use short private session socket paths, check the complete path at launch and
  refuse an overlong path with a fix. PTY peer delivery checks filesystem policy, live blocks and gates without
  changing the supervisor's controlling terminal.
- Developer correctness tests synchronize with observed readiness, lock state and peer admission, and bound Unix
  socket fixture paths. Fast-path timing tests retain their original uninstrumented budgets in
  `scripts/timing-budgets.sh`, with separate instrumented unit/race ceilings; production limits are unchanged.
  The VM matrix, run by hand before a release, requires live SELinux/Smack policy fixtures without skips;
  per-PR CI omits these proofs.
- Dashboard event windows, indexes and pending asks have bounded retained state, with partial-history labels and
  explicit truncation. Full-ledger receipts report a limit error rather than an incomplete unanswered-ask count.
  Historical reads may rescan disk; these budgets are not a process memory cap.
- Dashboard live regions retry after a failed refresh even if no new event arrives. Watched-run comparisons
  require matching workspace and agent identity, preserving warnings when that identity is absent or different.
- Receipts, dashboard verdicts and learned rules keep successful read/send pairs together; an unrelated refusal
  no longer creates a leak warning. Proximity remains a heuristic. Newly written refusal/mirror pairs are
  contiguous, and created-link and unanswered-ask totals agree across views; older displaced mirrors can remain
  ambiguous.
- Fresh agent setup generates explicit, portable Claude print-mode and Codex contracts without seeding
  credentials. Codex settings-source notes appear in compile and verbose output, keeping ordinary starts quiet.
- Agent selection with `tego status --agent` uses the newest matching run; `--all` lists every matching retained
  run. Last-run selection skips directories with no ledger file while still refusing unreadable or corrupt
  records. Run abbreviation verification includes anchored runs whose directories have been deleted.
- Suggested block commands quote paths and option-like program names safely. Exec summaries expose fileless and
  dropped-program facts. Service-mode intentional stops return 143 after escalation while preserving actual
  ledger exit status; OOM/process limits and record errors keep their distinct exit codes.
- Demo commands mask Claude OAuth tokens and Anthropic API keys in printed environment assignments while
  preserving their exact argument bytes. Demo resets and developer cleanup require ownership markers and reject
  protected or unmarked paths, including newline-only entries and failed listings. Old unmarked demo state needs
  manual relocation or a fresh path; shell markers guard accidental cleanup, not concurrent hostile path
  replacement. Source builds use a fresh marked BPF toolchain cache and leave the old unmarked cache untouched.
- Release publication preserves the tagged changelog section. The publisher checks the draft against the
  same-run notes artifact immediately before publication, then reads back the body and public status even if
  editing fails. After editing, an error, mismatched body or unverified state fails publication and triggers an
  attempt to restore draft status; a failed restore needs manual inspection.
- A contract string that the YAML writer stored as a block starting with a tab or a line break (a multi-line
  `command` entry, for example) is now saved double-quoted in the run's `contract.yaml`, so the saved copy loads
  back as the same contract when `tego drift` reloads it. Such a contract's hash changes; no other contract's bytes
  or hash change.
- Docs: Microsoft's WSL kernel lists `bpf` in its boot LSM list from 6.18.54.1 (WSL 3.0.3), so tier 3 no longer needs a
  boot change there. INSTALL.md also now says PowerShell must be opened as administrator, and covers Lima's menu, the
  read-only Mac home mount and `--mount-none`.
- A YAML anchor or alias used in `gate:`, `ask:` or `docker:` (a gate rule repeated as `*name`, for example) is
  expanded before the contract is saved, so the run's `contract.yaml` loads back for `tego drift`, and two contracts
  whose gates score differently never share a contract hash. Such a contract's hash changes. Contracts generated by
  `tego watch` and `tego adopt` now load for any program path, including one that starts with a space, a tab or a
  line break.
- Release: the signing step stages each checksummed asset from goreleaser's artifact list and the checksum globs, and
  refuses a missing, duplicate or changed file, so a tag's release job no longer stops on a raw binary or an extra
  file that goreleaser leaves outside `dist/`.
- `tego compile` refuses a `net.allow` `unix:` entry that a built-in refusal always refuses, such as the session bus
  or the systemd user manager, as a `contradiction` naming the entry and the rule (such a contract now fails at launch
  with exit 125 instead of running with an entry that never applied), and notes that `host_sockets: true`
  beside a `net:` section has no effect; `tego learn` no longer proposes such a socket, and
  `docs/user/built-in-refusals.md` shows a one-verb helper for an agent that must restart a service.
- The user service template `examples/systemd/tego-agent@.service` sets `Delegate=yes`. On RHEL 9, once an
  administrator has added cpu to `Delegate=` of `user@.service`, this makes the user manager turn cpu on for the
  service, so its runs can use `limits.cpu`. An interactive run there needs the setup in `docs/TIERS.md` for CPU
  limits (GAPS B15).
- A rule change from the dashboard or `tego rule` on a contract whose text has a lone CR, NEL, LS or PS line break
  looked for each node after that break on the wrong line: it could panic, and a removal could take a comment on the
  next line with it. Such a contract is now written from its YAML tree, as is one in UTF-16.
- A YAML file where a merge key (`<<`) applies to a mapping with a list or a mapping as a key, such as `{<<,[]}`,
  made the YAML decoder panic instead of failing to parse. In the price table it stopped `tego run` and
  `tego measure` with an internal error, and in a contract, a registry entry, a run's saved `contract.yaml` or a
  workspace file it stopped the command or dashboard request that read it. Such a file is now read as one
  that does not parse: a price table is reported as unreadable, and cost is not estimated.
- The reader of `/proc/<pid>/stat` took a line that starts with a negative pid, such as `-1 (a) S ...`, as a process
  with that pid, where it already refused a negative parent pid, process group or thread count. Such a line is now
  refused as malformed. Linux does not write one.

### Added

- The `tego rules` command shows the same rules-in-force view as the dashboard, with text and versioned JSON,
  sources, hits, enforcement details and live state. Before a first run, `rules --last` explains how to start.
  Like the dashboard, this command requires a non-root user.
- Inventoried Node builds resolve ordinary option-heavy commands without spending the ambiguity budget on script
  arguments. A bounded executable-digest cache avoids rehashing stable builds. Numeric names such as `node-22`
  now use the Node row. `--stack-trace-limit` is no longer accepted as a command-rule predicate because the
  inventoried versions disagree on its arity; this does not ban the option itself.
- Release automation publishes `ghcr.io/attention-span-ai/tego` for Linux amd64 and arm64 with the exact
  reproduced `tego`/`tego-control` release binaries, keyless cosign signatures, provenance and an index digest
  in the release notes. Stable releases update version, major.minor and latest image tags; prereleases update
  only their version. Signing alone can request OIDC tokens and runs without checkout, project code or build
  hooks, verifying assets and the image digest first. Publication waits for reproduction, vulnerability scanning
  and signing; exported CI tests check these boundaries. The container base is not claimed reproducible; signing
  failure can leave an unsigned registry image while the GitHub release stays a draft. The install guide covers
  verification and use.

### Record `v`
1 (`spec/record/v1`, record minor 29)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 and 10, as AlmaLinux 9.8 and 10.2, with what ran where in `docs/TIERS.md` (tier 1: ABI 1 is unsupported,
and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.1-rc.1 - 2026-11-10

This is a release candidate for v0.1.1, with the changes listed under v0.1.1 in docs/CHANGELOG.md. It exists to
rehearse the release run: signed binaries, the container image and the published notes. Use v0.1.0, or wait for
v0.1.1, unless you are testing the release itself.

### Record `v`
1 (`spec/record/v1`, record minor 29)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 (tier 1: ABI 1 is unsupported, and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
Syscall outcome hooks require readable tracefs event formats with an eight-byte `ret` at offset 16; unsupported
or unverified layouts withhold root tiers. The kernel version minimum is unchanged.

## v0.1.0 - 2026-11-03

The first release. Tego runs an AI agent under a contract you write, a YAML file of rules for files, programs
and network hosts, and enforces it from outside the agent: the Linux kernel and Tego's supervisor refuse what the
contract rules out, can hold an action until you answer, and keep a hash-chained record of every run. Tego runs on
Linux (amd64 and arm64); on macOS and Windows it runs inside a Linux VM. It sends nothing home and never calls a model
itself.

### Install

- Linux: `curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh` installs
  `tego` and `tego-control` into `~/.local/bin`, checks them against the release's checksums, and checks who published
  them when `cosign` or a logged-in `gh` is on `PATH`.
- macOS: `limactl start --name=tego https://github.com/Attention-Span-AI/Tego/releases/latest/download/tego.yaml`
  starts an Ubuntu 24.04 VM with Tego installed (`brew install lima` first).
- Windows: `wsl --install -d Ubuntu-24.04`, then the Linux line inside Ubuntu.
- From source: `make build` (Go 1.27). `docs/INSTALL.md` has every route and what each was tested on.

### Added

Contracts

- `tego init` writes a starter contract, from the built-in presets `no-secrets`, `no-prod` and `repo-only-writes` with
  `--preset`; `tego compile` checks one and prints its rule table, and `--test` asks what each tier would do with an
  action; `tego learn` proposes a contract from what a finished run did. Revision 1 of each preset is frozen from this
  release on.
- Rules for files (`fs`), programs (`exec`), network hosts and ports (`net`), environment variables and limits (tokens,
  cost, time, stalls, repeats, memory, processes). A run that passes a limit ends with exit code 124.

Three enforcement tiers, all in the release binary

- Tier 1 (`landlock`), no root: Landlock and a seccomp supervisor. The kernel refuses writes and programs outside the
  contract; Tego's supervisor decides network hosts.
- Tier 2 (`cgroup`), root: BPF programs attached to the run's cgroup, and fanotify. Hosts are decided in the kernel.
- Tier 3 (`bpflsm`), root, on a machine with `bpf` in the boot LSM list: BPF LSM hooks.
- `tego doctor` says which tier a machine gets and prints a fix for each gap; `tego test` shows four harmless actions
  refused at that tier, with no root and no agent.

Live rules and approvals

- An `ask` rule holds a file open or a connection until you answer with `tego approve` or `tego deny`, or in the
  dashboard. Held file reads (`fs.ask_read`) are tier 1 only; `exec.ask` is reserved and refuses.
- A running run can be paused, resumed, stopped and blocked (`tego pause`, `resume`, `stop`, `block`, `unblock`), and
  `tego rule` turns something a run did into a rule. A run in the Adjustable live mode (tiers 2 and 3) can also be
  loosened while it runs (`docs/user/live-modes.md`).
- MCP tool rules: a relay allows, holds or denies single tools of an MCP server, and `tego mcp` changes that live.

The record

- Every run writes a hash-chained record, anchored in `~/.tego/chain.log`. `tego receipt` summarises a run, `tego events`
  prints it and `tego events <run> --verify` checks its chain, `tego drift` compares what was allowed with what was
  used, and `tego measure` counts steps, tokens, cost and time. What the record holds depends on the tier: by default
  tier 1 records programs, writes and connections, and no file reads (`record: full` records reads).

The dashboard

- `tego serve --open` serves a dashboard on `127.0.0.1:8484` for one person: runs, logs, refusals, held requests to allow
  or deny, each run's rules, and stop, pause and block. It runs as `tego-control`, which refuses to run as root.

The agent watcher

- `tego watch` runs any command as a black box and records what it does. `tego agents` lists the agent processes
  running on the machine and `tego adopt` moves one that is already running into a governed run; both need root.

Supported agents

- `examples/agents/` has contracts for Claude Code (print mode and the full-screen interface), OpenAI Codex (API key
  through Tego's forwarder, or a ChatGPT sign-in), a Python agent on the Claude Agent SDK, one on the Anthropic Python
  SDK, a Python retriever with one MCP server, and an agent of your own left to run unattended. Any other agent is an
  ordinary process: write a contract for it, or start with `tego watch`.

Release

- Static binaries for Linux amd64 and arm64, with the tier-2 and tier-3 BPF objects built in. The checksums file is
  signed with cosign (keyless, by this repository's release workflow at this tag) and every file it lists has a build
  provenance attestation; the binaries are built again from the tag on a fresh runner and must match byte for byte
  before the release is published. `install.sh` and the macOS template `tego.yaml` are release assets too, in the same
  checksums file, and the one-line installs take them from the latest release. `tego_0.1.0_licenses.tar.gz` holds the
  licence texts, and `tego licenses` prints them.

### Security

Fixed since the source was first published on 2026-11-02.

- At tier landlock an agent could open a `deny_write` file such as `.git/config` for writing through a symlink whose
  body goes through its own `/proc/self/task/<tid>` and climbs back out. The supervisor now resolves such a link the
  way the agent's own lookup does, and the open is refused.
- A run with a `net:` section can no longer source-route around its contract: `setsockopt` of `IP_OPTIONS`,
  `IPV6_RTHDR`, `IPV6_2292RTHDR` and `IPV6_2292PKTOPTIONS` fails `EPERM`, and a datagram whose control message routes it
  is refused with a `relay-source-routed` line (GAPS C34).
- The built-in `deny_read` list also refuses the desktop keyrings, `~/.my.cnf`, `~/.mylogin.cnf`, `~/.s3cfg`, `~/.boto`,
  rclone's config, the RubyGems and Composer credentials, `~/.m2/settings-security.xml`, and the doctl, hub, glab,
  flyctl, Supabase and OCI CLI stores.

### Fixed

Since the source was first published on 2026-11-02.

- Set up a new agent takes a long form and keeps a comment on the name line; removing an entry listed twice removes
  both; `tego rule` changes read in words in the dashboard's history and undo the right way.
- `tego gc` and the retention pass prune the rule-change journal, keeping everything a run in the ledger root still
  reads and each rules file's newest 20 standing changes.
- The Block now terminal line fills in what the form holds, quoted, and keeps a selection.
- A run can no longer watch what it may not read: inotify, fanotify and dnotify watches of a `deny_read` target are
  refused.
- Live blocks, gate rules and the model guard read this host the same way, local routes included (AnyIP ranges,
  hand-set broadcast and IPv6 anycast addresses).
- `tego init --preset` makes a preset's folders with no link followed, and works inside a tego run.
- An agent that runs `chmod 000` on tego's own files no longer makes its run fail or refuses the runs after it; tego
  gives the owner back the rights it needs, and `tego gc` deletes nothing by a config layer it cannot read.
- The dashboard reads a run whose launcher died as Lost within a few seconds, re-checks a cached chain verdict, and
  keeps a live host block's addresses fresh.
- tego block notes a program whose file has other names (a multi-call coreutils or busybox) and a bare name on no
  PATH folder; the dashboard's Remove on an ended run is refused as tego unblock is.
- The CLI's record views count a refusal once when its mirror line is not next to it, as the dashboard does.
- tego rule and the dashboard's previews warn when a host a change adds does not resolve.
- tego help marks the commands that need root; `tego-control serve --addr` takes [::1]; error pages keep the live
  chrome; file rows offer Block; `compile --test` says which tiers auto leaves out and why.
- tego run's end line names the tier, and every command that takes a run accepts a unique abbreviation of its id; a
  bare short name is no longer read as a local run directory (use ./name).
- The Rules page lists the machine's limit ceilings, net.http, ingress and gate rules and the tier-1 datagram residual,
  counts what the defaults decided, and counts every name of a program's file, git's helpers and a script's interpreter.
- Logs and the line page say "Watched only" for a watched run's lines.
- The line page streams a blob download instead of holding it in memory.
- The demo kit runs under a pyenv or asdf python3 shim and says when a run did not start; the supply-chain demo's proof
  reads `tego events --json`, and its reset never deletes a folder it did not move.
- tego watch and tego adopt name themselves in the run path's messages.
- Logs: the `path:` query key matches whole names, so `path:/a/b` no longer lists `/a/bc`.
- The dashboard words six refusal reasons it showed as bare codes (MCP tool blocked, Sandbox boundary, and the
  credential and model-route codes).
- Never allow from a Deny on a connection opens that connection's own refusal; Make it permanent is offered only where
  the dashboard can change contracts; the Act panel shortens the run's folder and home only as whole paths.
- The dashboard's rule service keeps its listing of the ledger root while the root is unchanged (a Change rules request
  on 5,000 runs: 1.0 ms instead of 21 ms).
- The receipt, the Receipt tab, tego run's end line and tego watch's footer no longer count writes to /dev/null or the
  terminal as files written, and the tile agrees with the end line; `tego receipt --json` codes each coverage gap.
- Approval cards say what a held delete, mkdir, rename or link changes, in words, with both names whole.
- An adoption's reaper and `tego adopt --release` / `tego stop` no longer recreate files in a removed run directory.
- The dashboard's run timeline and line pages chip an ask Asked and an answer Denied, Allowed, Timed out or Withdrawn,
  as Logs does, instead of "Recorded".
- The Rules page says when a run's rules file loads to other rules than the run ran even when nothing dates the change,
  and no longer calls the file of a run that recorded no contract hash changed.
- Compare paints a green Stopped only for what the run's verdict counts; any other refused connection reads Refused.
- `tego doctor` gives its answer first: a `summary:` line names the tier and what each higher tier needs.
- `examples/systemd` ships a daily retention timer and an opt-in daily restart for always-on agents.
- The dashboard's empty pages give commands that run interactive Claude Code and Codex.
- The Rules pages never show an `env.set` value from a broken file or a file of more than one YAML document.
- A run no longer adopts TLS capture probes left over from before the build's BPF maps were re-created, which lost
  that library's capture with no gap; it places its own, or reports a gap while another run still holds the old ones.
- `tego licenses` and `tego-control licenses` print the licence texts and third-party notices each binary embeds.
- `tego drift` lists every exec of a program held in memory or that ran a file the run wrote, with its verdicts.
- `tego compile` warns when `io_uring: true` meets a `net:` section with no `net.listen` at a root tier, where a ring's
  listen goes unrefused.
- `examples/prices.example.yaml` is a price table to start from (docs/OPERATIONS.md "The price table"), every example's
  header names its setup, and the examples compile on a fresh machine after it.
- An empty string is not a default. `tego watch --boundary ""` and `tego adopt --boundary ""` ran the command record-only,
  with no rule, and now refuse to start; `tego receipt ""`, `tego init ""`, `tego compile ""` and `tego run ""` are usage
  errors too, so an unset `"$VAR"` never gets a result for something else.
- `tego run`, `tego watch` and `tego adopt` keep going when the reader of their output leaves: `tego run agent.yaml | head -1`
  no longer replaces the agent's exit code with 141 or ends the supervisor under a live agent.
- A run started from a directory reached through a symlink names its real directory in `run_start`, so `tego learn` and
  `tego receipt` read its writes as inside the workspace.
- `tego events` and `tego receipt` print each time in the zone it happened in, and `--until` in an hour a clock change
  repeats is the next time the clock reads it, in every form. `tego learn` measures a run's length on the monotonic clock.
- A limit below what a run's own start takes is caught at compile: `limits.pids` under 6 is refused, and `limits.memory`
  or `memory_high` under 8 MiB, or a machine ceiling that sets one there, gets a warning.
- The agent keeps the soft `RLIMIT_NOFILE` it was started with.
- `record.max_run_bytes` counts a run's stored bodies as well as `events.jsonl`.
- A message the MCP relay refuses unread, or a line past its size bound, is on the record as a refused `mcp` line.
- Dashboard: a proposal made from a run that leaked never allows the address behind the leak's host name; a refused
  connect to a live-blocked host, or one carrying an IPv6 scope id, is no longer folded away as Routine; and a rule made
  from an IPv6 line is one a contract can hold.
- `tego drift` says what its gaps mean, as `tego status` does, and the dashboard's Rules page says that every run
  can read the machine's network setup (interfaces, addresses, routes and nearby machines).
- The git exec row knows `git reflog write`, `git hook list` and `git multi-pack-index compact`, which git added after
  2.51.0.
- The container image works for any `TEGO_UID`: its home is 0755, so the entrypoint, which runs as root without
  `CAP_DAC_OVERRIDE`, can reach `~/.tego`.
- The open deputy that serves held reads no longer dies under concurrent requests in a tego built with cgo (a plain
  `go build` with a C compiler): glibc's CPU-count read is refused instead of killing it. The release and `make build`
  binaries are static and were never affected.
- A held open in flight when the open deputy is gone is refused `held-unavailable`; it no longer gets the deputy's socket
  error (`ECONNRESET`, `EPIPE`) as its own errno.
- A run's reaper reads only the unified line of `/proc/<pid>/cgroup`, so on a host that also lists a cgroup v1 hierarchy
  a zombie in a sub-cgroup is no longer charged to `limits.pids`, which could end a healthy run as `reason=pids`.

### Tests

- The suite holds on GitHub's hosted runners: kernel 7.0, which refuses an IPv4 source route to an unprivileged task
  itself (CVE-2026-53249), arm64, git 2.56 and the race detector's pace.

### Known limitations

See `docs/GAPS.md`. The ones most likely to matter on the first day:

- Every destination a contract allows is a way for data to leave (A1), and an allowed interpreter can do anything inside
  its own memory (A2).
- At tier 1, under the default `record: summary`, a read that `deny_read` refuses is still refused but leaves no line,
  so a clean receipt says nothing about reads; `record: full` records them. A record-only run (`tego watch` with no
  `--boundary`, `tego run --observe`) has no Landlock rules, so its agent can rewrite its own record.
- Tier 3 needs `bpf` in the boot LSM list, which Ubuntu and the stock WSL2 kernel do not have by default (B1).
- `tego serve` is for one person on one machine. It listens on loopback and refuses to run as root.
- Piping the installer into `sh` runs it before anything can check it (B11); `docs/INSTALL.md` shows how to check it
  first.
- The macOS template and the Windows script have not been run on those systems yet.

### Record `v`
1 (`spec/record/v1`, record minor 29)

### Contract schema
0 (`spec/agent/v0`; the field set may change without notice before v0.2.0, `docs/VERSIONING.md` section 3)

### Kernel minimums
Linux 5.14 with Landlock ABI 2 or newer, which is Linux 5.19 or a backport such as RHEL 9's 5.14; tested from 6.1 and on
RHEL 9 (tier 1: ABI 1 is unsupported, and features are gated per ABI, see `spec/backend/CAPABILITIES.md`;
tier 2 needs root and cgroup v2; tier 3 needs root and `bpf` in the LSM list). A unix socket under an `fs.write` path is
admitted without a `unix:` entry only with the kernel's socket diagnostics for `AF_UNIX` (`CONFIG_UNIX_DIAG`, built in
or the loadable `unix_diag` module); without them such a socket is refused `unix-origin-unread`, and `tego doctor` says so.
