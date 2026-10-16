# ADR 0057: fs.ask_read and alternates: what the record says, where an alternate may come from, and how ask_read meets write entries and the built-in list

Status: **accepted 2026-10-16**; D1 to D5 implemented 2026-10-16.
Amends nothing: it decides what the 2026-10-06 POC of `fs.ask_read` and alternates (SEMANTICS §6, agent-contract R22)
left open.

The POC of 2026-10-06  built `fs.ask_read`, a read
held for a person at tier landlock, and `tego alternate`, a third answer that completes a held file open on another
file. It left five decisions open. This record takes them.

## Decisions

### D1. What the record says of an alternate

The answer line keeps `approved: false` and no `answer_reason`, and that is the record's truth: `approved` answers
whether the operation as asked (the line's `target`) was granted, and it was not; nothing was refused. What was done
instead, and on whose authority, is in the same line: `alternate` (the file delivered, by the path the supervisor
read from the person's descriptor), `alternate_dev` and `alternate_ino` (its identity when the person named it, added
here), and `by` (the person: `uid:<uid> pid:<pid>`, or `standing:<ask_id>` for a later answer from a standing
alternate). The open it completed is its own `fs` line, `authority: human`, `verdict: allow` on the file delivered,
`alternate_for` the target (now a typed field of `record.FSPayload`). Its gate fields, when the contract's gate scores
such an open, are the gate's decision on the file delivered (*amended 2026-10-16*: they were
the held target's score and outcome, written on a line whose `path` is the alternate, so the record said the gate had
scored the alternate 0, `ask`, where it would have refused it at 90; the record README says gate fields are attached
to the action line they describe). `internal/runtime/supervisor`'s
`TestDeliveredAlternateLineCarriesTheAlternatesGateDecision` pins both directions (a target scored and a stand-in not,
and the reverse).

A standing alternate's later answer lines repeat the three fields of the answer that set it:
their `alternate` is the path recorded when the person named the file, which the agent may have renamed since. The
file is the one `alternate_dev` and `alternate_ino` name, fixed by the descriptor the run keeps, and the path it had
when delivered is the `fs` line's `path`; `TestAlwaysAlternateDeliversTheSameFileForTheSameKeyOnly` pins that the
standing answer carries the first answer's path and identity. Rejected: reading the path again for each standing
delivery and writing that into the answer line (a second read of the same descriptor, made before the delivery's
own, would still race a rename, so the two lines could still differ, and the `fs` line already names the path at
delivery).

Every reader takes it the same way (each has a test): `tego events` writes an answer as its outcome, then who gave
it (`alternate <path> (not the file asked for) by <who>`, `approved by ...`, `refused ask-denied by ...`; a line older
than `approved` says only who); `drift` counts the `fs` line in the rule's own `alternate` count (a new column and
key; `Total` includes it, so the buckets still partition the ledger) and never as an `allow` of the rule that held it;
`measure` counts the answer lines as `alternates` (a row and a key), neither refusals nor approvals, read off the
answer lines because the delivered open's line is not written under `record: off`; `learn` proposes nothing from such
an open, for the file asked for or the file given, and says how many there were.

Rejected: `approved: true` with the alternate beside it (every reader that does not know alternates would read a grant
of the target: the ledger would say something other than what happened); a fourth verdict, `alternate`, on the `fs`
line (the v1 verdict set is closed, and the agent's open did succeed, on the person's file, which `allow` with
`alternate_for` says exactly); an `answer: alternate` field (it says nothing `alternate` does not); counting the
alternate as `ask` in drift (that column counts lines whose verdict is `ask`, a held action, and the open was
completed).

### D2. Where an alternate may come from, and who opens it

**Who opens the file, and when.** The POC's supervisor opened the person's path itself, once when the person answered
and again at delivery, with the agent's credentials but outside the agent's Landlock domain (at tier 1 the agent and
the person share a uid, so those credentials are the person's whole identity). Between the person's command and those
opens the agent can rebind the path: rename a directory on the way, or swap a symbolic link into it. The supervisor
then opens a file the agent's own domain could never reach and no protected-path list names: a file created after
launch beside a `deny_read` target (its parent directory gets `READ_DIR` only), or, for a held `fs.ask` write, a
dotfile in the home directory the agent could then write. That is a confused deputy.

Decided: the file's identity is fixed when the person names it. `tego alternate` opens the path in its own process,
`O_PATH|O_NOFOLLOW`, with `openat2` `RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`, so no symbolic link and no `/proc`
magic link is followed anywhere on the way (a link is refused, and the refusal names the path it resolves to, for the
person to check and name). It passes that descriptor to the run's broker over the socket (`SCM_RIGHTS`; an answer
with an alternate carries exactly one, every other packet none, or it is a protocol error). The broker and the
supervisor never look the path up again: every check is made on the descriptor (regular file, one link, no kernel
pseudo filesystem, the kernel's path for it names the same inode in the supervisor's view and lies outside every
protected tree), and the delivery reopens the descriptor through `/proc/self/fd/<n>` with the agent's credentials and
the held open's flags. A standing (`--always`) alternate keeps the descriptor for the run and repeats the checks per
delivery. Tests: `internal/runtime/ask`'s `TestOpenAlternateFileRaceNeverReachesTheSwappedTarget` (a directory flipped
between a real directory and a link to a secret while the command opens; it fails without `RESOLVE_NO_SYMLINKS`),
`TestAlternateIsTheFileThePersonNamedNotWhatThePathNamesLater`, and `internal/runtime/supervisor`'s
`TestAskReadAlternateDeliveredIsTheFileNamedNotThePathRebound` (the path rebound between the answer and the delivery;
the agent gets the file the person named).

**What is refused.** Whatever the person types, never an alternate: tego's own state (the ledger root and every run
directory beneath it, the chain anchor's directory, `~/.tego`, `/run/tego`, the price table, the profiles directory,
and `$XDG_RUNTIME_DIR/tego`, which the launcher adds since the compiled table does not know it); the contract file's
directory, but for a file beneath a write entry; every `deny_read` target, declared or built in; every `fs.ask_read`
entry; every implicit entry; every file a declared `deny_read` glob names, and every path of the built-in `deny_read`
list under the home directory, or a file beneath one, whether or not it existed when the table compiled and whatever
`deny_read` says (`RuleTable.DenyReadPatterns`, matched also ASCII case folded: a glob's rows are only the files that
existed then, and compile skips an absent built-in path, so `~/keys/new.pem` or a `~/.netrc` written during the run
would otherwise pass); and any file whose name is one the built-in `.env` list protects (`.env`, `.env.*` but its
example files), wherever it lies, so a mistyped `.env.example` never hands the agent the secret, even one created after
the table compiled. For a write, also: a file of a built-in `deny_write` class by its names alone, wherever it lies
(`agent.WriteAlternateClass`: a `hooks/` file, `config` or `config.worktree` beneath a `.git`, a `.git` file, a file
beneath `.husky` or `.githooks`, anything beneath the harness and editor settings names of R20, a shell startup name,
`fish/config.fish`, `.gitconfig`, `git/config`); every `deny_write` target; and every file outside every write entry and
`fs.ask` scope. Not refused: a file beneath a write entry, the project's included (R10 keeps the contract file out of
every write entry). Its identity is fixed when it is named, and its bytes are the agent's own already.

*Implementation note 2026-10-20 (agent-contract R26).* The user registry's `agents/` and
`skills/` (the machine config's `registry:`) are refused for a write alternate, from their own list,
`RuleTable.OwnReadable`, not from tego's own state above: a run may read them, so a read alternate there is one like
any other, and an `fs.ask_read` entry beneath them, or a held read there, is no different from anywhere else. Kept
in `RuleTable.OwnState` for a day, they made compile refuse such an entry as lying where "no run may read", and the
supervisor refuse such a held read `read_denied`, while a plain read of the same file was allowed. Rejected: keeping
them in `OwnState` with a reworded refusal (it refused a hold a person could safely answer, for skills, the
registry's intended home, and the ledger's `read_denied` would still name a deny no plain read meets).

*Implementation note 2026-10-20 (ADR 0059).* The machine config's layer files a Load consulted (`config.Machine.Layers`)
are in `RuleTable.OwnReadable` too, as written and resolved: ADR 0059 made each an R10 target, and a person's write
alternate there would hand the agent what R10 keeps every write entry off.

*Amended 2026-10-16.* As first implemented, a write alternate was refused only by the compiled
`deny_write` sets, which hold what compile found beneath a write entry or an `fs.ask` scope: a git hook of another
repository, harness settings outside the scope, `~/.bashrc` in a home that is no write entry all passed, and the
supervisor reopened them with the agent's write flags, `O_TRUNC` included (a test run put agent code in
`otherrepo/.git/hooks/pre-commit`). And the contract directory's refusal came before anything about write entries, so
every stand-in beneath `./out/` was refused, against the "not refused" sentence above. Both are fixed as stated above,
with the declared-glob and absent-built-in gap, and tested by `internal/runtime/supervisor`'s
`TestWriteAlternateLiesWhereTheContractLetsTheAgentWrite` and `TestAlternateRefusedByADenyReadPatternCreatedLater`,
`pkg/spec/agent`'s `TestDenyReadPatternsNameWhatDidNotExistAtCompile` and `TestWriteAlternateClassByName`, and
`internal/runtime`'s `TestIntegrationAskWriteAlternateWritesIntoTheStandIn` (a hook refused, a stand-in in `./out/`
written) and `TestIntegrationAskReadAlternateRefusedFromTheRuntimeDirectory` (the launcher's `$XDG_RUNTIME_DIR/tego`).

*Amended 2026-10-16.* The contract's `gate` was never asked about the alternate: it scored
only the held target, so with `fs.read matches "*.pem": 90` the agent's own `cat keys/x.pem` was refused `fs-gate` and
`tego alternate --file keys/x.pem` handed the same file over, and under `fs.write outside worktree: 90` a held write
was answered with a file outside the worktree the agent's own write to which was refused. A gate refusal is the
contract protecting a path as surely as a `deny_read` entry, so it is now on the list: the alternate's resolved path
is scored as the agent's own open of it would be (`fs.read` predicates for a held read, `fs.write` for a held write;
the floor is `ask`, since the open reaches the agent through a person's answer), and a `refused` verdict refuses the
alternate at answer time (the person sees `refused by the contract's gate (<rule>, score <n>), which no answer lifts`,
the request still pending) and again at delivery (`ask-unavailable`), as `alternateGate` in
`internal/runtime/supervisor`. A score at or below the `ask` threshold leaves the person's choice standing; that is
what an `ask` is for. Tests: `TestReadAlternateIsPutToTheGate`, `TestWriteAlternateIsPutToTheGate` (both fail without
the check) and, end to end at tier landlock, `internal/runtime`'s `TestIntegrationAlternateIsPutToTheGate`; at tier
cgroup and bpflsm, `internal/runtime/enforce/cgroup`'s `TestPlaneRunWriteAlternateIsPutToTheGate`. Rejected: scoring an
`O_RDWR` write alternate with the read predicates as well (stricter than the agent's own `O_RDWR` open of the same file
and than the held target, which the gate scores as a write alone; a separate question of the gate, not of alternates);
refusing a gate `ask` too (the person answering is the ask).

*Amended 2026-10-16.* The rejected clause above rested on the gate
scoring the agent's own `O_RDWR` open as a write alone, and that was the gate's own hole, recorded nowhere but here:
under `fs.read matches "*.pem": 90` the agent's `open("out/x.pem")` was refused `fs-gate` while `os.open("out/x.pem",
O_RDWR)` beneath a write entry read the bytes. The gate now scores a write open that also reads (`O_RDWR`, or
`O_RDONLY` with `O_CREAT` or `O_TRUNC`) with the read predicates as well, the stronger verdict kept (gate.md R1,
`scoreOpen` in `internal/runtime/supervisor`), for the agent's own open, a held `fs.ask` write's target and a write
alternate alike, so a held `O_RDWR` write answered with `out/x.pem` is refused at answer time and at delivery. The
clause is withdrawn: the alternate is scored exactly as the agent's own open of it, which is what D2 asks. Tests:
`TestGateReadMatchesScoresAReadingWriteOpen`, `TestGateReadAskHoldsAReadingWriteOpen`,
`TestReadingHeldWriteIsPutToTheReadGate`, the `read gate read-write` case of `TestGateFilesystemFaultScope`; at the
root tiers, `internal/runtime/enforce/cgroup`'s `TestPlaneRunReadGateScoresAReadWriteOpen`.

Rejected: letting the supervisor resolve the path and re-check an inode the person's command reported (the window
between that stat and the supervisor's open stays, and the command would report what it does not hold); resolving with
`RESOLVE_BENEATH` a root the agent cannot write (no such root holds every legitimate stand-in); refusing every file
the agent could write (it removes the common case and buys nothing once identity is fixed); refusing only declared
`deny_read` targets (a built-in one is the likelier typo); following links in the person's command and showing the
resolved path afterwards (the agent swaps the link between the person's look and the open); refusing write alternates
by name class alone, anywhere (outside the agent's domain the supervisor would hand over a writable descriptor of what
no list names: a crontab, an autostart entry, `~/.ssh/authorized_keys`, a directory on `PATH`); exempting an `fs.ask`
scope in the project from the contract directory's refusal (an ask scope can lie above a file that steers the next run,
a profile the contract extends, which R10 keeps out of write entries only); leaving a declared glob's and an absent
built-in path's later files as accepted residual (a typo there is exactly the harm this decision is for).

### D3. An fs.ask_read entry inside an fs.write entry, and how asks meet write entries

One rule for both kinds of ask: an ordinary grant takes precedence over an ask (SEMANTICS §6), so an ask at or beneath
a write entry is never asked. What that costs decides error or warning:

- An `fs.ask` scope at or beneath a write entry loses only a question the write grant already answered; nothing is
  less protected than its author granted. `compile` now warns (`redundant-rule`, "the scope never asks") and the
  table compiles (before, it compiled silently). The supervisor allows such a write by the write entry, unchanged.
- An `fs.ask_read` entry at or beneath a write entry would lose the protection itself: the entry is also the
  `deny_read` that keeps a secret, and Landlock unions grants, so the agent would read the file outright. `compile`
  refuses it (`unenforced`), as the POC did.
- A write entry nested strictly inside an `fs.ask_read` entry (or an `fs.ask` scope) has a meaning, nearest wins: it
  decides beneath itself, unheld, and the rest of the entry is held.

Test: `pkg/spec/agent`'s `TestAsksBeneathAWriteEntry` (and `TestAskReadConflictsAreDecidedAtCompile` for the nested cases). Rejected: one
error for both (an `fs.ask` scope beneath a write entry weakens nothing; refusing it would break contracts over a
redundancy); one warning for both (an `fs.ask_read` entry would compile unenforced, a listed secret readable without
a hold, against "an `fs.ask_read` entry never compiles unenforced"); letting the ask take precedence over the write
grant (Landlock cannot withhold an access beneath a grant at tier 1, so it could not be enforced where it mattered).

### D4. An fs.ask_read entry that relaxes a built-in deny_read entry

Allowed from the top-level contract, and disclosed twice. Compile's warning (`unenforced`) names the built-in entry it
relaxes and how: `relaxes the built-in deny_read entry <path>, which it replaces` for an entry at the built-in's path
(the built-in entry is dropped), `..., inside which it lies` for one beneath it (the rest of the built-in tree stays
refused). And every run of the table says so in its record: `RuleTable.AskReadRelaxes` lists `{Rule, BuiltIn, How}`,
written as `run_start.ask_read_relaxes` (absent when there is none; `record_minor` 9). From a profile it stays a
`contradiction`.

Why allowed: it relaxes a refusal to a question, never to an allow. Every read is still held for a person, who sees
the path; the author of the contract file asked for exactly that; and a top-level write entry may already lift a
built-in `.env` entry the same way (ADR 0043 D3). Rejected: refusing it (no way would remain to be asked for one's own
`~/.aws/credentials` short of removing the built-in protection by hand); a warning alone (compile output is not the
record, and a ledger read later must say the default was weakened); allowing it from a profile (it would lift a
built-in protection for every contract that extends the profile).

### D5. record_minor 9

The POC added record fields (an ask's `op: read`, an answer's `alternate`, an `fs` line's `alternate_for`) and took no
`record_minor` revision, on the argument that an absent `alternate` means "no alternate" in every ledger. That is true
of `alternate` but not of what `record_minor` exists to say (record.go): what the absence of an optional field means
at that revision. A reader of a revision-7 ledger cannot tell a POC writer that knew alternates from one that did not,
and from this record on an alternate answer also carries `alternate_dev` and `alternate_ino`, whose absence must be
readable. Decided: revision 9 (`record.MinorAskRead`): at 9 or later every alternate answer carries all three fields
and every held read's ask `op: read`, and an absent `alternate` means none; below 9 a ledger may carry `alternate`
alone. `spec/record/v1/README.md` says so, `pkg/spec/record`'s frozen key test lists `alternate_for` and the
`AnswerAlternate` keys, and `TestRecordMinorCoversHeldReadsAndAlternates` pins the revision. The same revision covers
`run_start.ask_read_relaxes` (D4): at 9 or later its absence means no built-in entry was relaxed. Rejected: leaving 7
(the reason above); a new record version (every field is optional and additive, which is what a minor revision is
for).

*Note 2026-10-16 (integration):* D5 was decided as revision 8. ADR 0048's `run_end.supervisor.exec_missing`
(supervisor R16b (0)) took revision 8 first, so this decision is revision 9
(`record.MinorAskRead = 9`, after `record.MinorExecMissing = 8`); nothing else in D5 changed.

*Amended 2026-10-20 (ADR 0007's second 2026-10-20 note).* The note above scores a write open
that also reads with the read predicates as well, "the stronger verdict kept". Both kinds now score it as one action,
their matching rules' scores summed (`scoreOpen`), for the agent's own open, a held `fs.ask` write's target and a
write alternate alike, so an alternate is still scored exactly as the agent's own open of it.

## Consequence

- `tego alternate` now opens the file itself and refuses a path with a symbolic link anywhere in it (a usage error
  naming where it leads, the request still pending); a person names stand-ins by their real paths. The broker's
  protocol gains one descriptor on an alternate answer and refuses descriptors anywhere else.
- A standing alternate holds one descriptor per key for the run (at most `MaxStanding`, 256), closed when the broker
  closes; a decision holds its own duplicate until the supervisor delivered or refused it.
- The record's readers changed visibly: `events`' answer summaries now lead with the outcome, `drift`'s table has an
  `ALTERNATE` column and its JSON an `alternate` key per rule, `measure` an `alternates` row and key. Ledgers below
  `record_minor` 9 read as before (an old answer line says only who answered).
- Residual, accepted: the person's command checks nothing but shape and file type; every protection is the
  supervisor's, on the descriptor, so a stale or hostile command can pass only a regular file the person could open,
  which the supervisor then judges. Between the person reading a stand-in and running the command, a stand-in beneath
  a write entry can change its bytes; those bytes are the agent's own, so nothing leaks, but the person should create
  stand-ins where the agent cannot write when the bytes matter to them.
