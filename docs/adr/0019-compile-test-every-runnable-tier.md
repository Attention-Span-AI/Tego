# ADR 0019: compile resolves auto as run does, from unprivileged facts, and compile --test answers for every tier the run could get

Status: accepted 2026-09-24 (implemented); (2)'s plane columns amended 2026-09-29 (one column for tier cgroup with a plane and tier bpflsm, note below). Closes limits-check-doctor-cli R33.
Amended in part by ADR 0048 (accepted 2026-10-06): `compile --test` cells gain `command_rule`, `command_match` and `argv_facts`, exec rows take `script_arg:`, `compile --exec` evaluates one command line, and the exec best-effort warnings are scoped per tier.
Amended in part by ADR 0044 (accepted 2026-10-16, not built): `compile --test` cells gain the optional, additive `completion` field (`trace` for an exec ask cell) beside `completion_unsupported`; the document stays `v: 1`.
Amended in part by ADR 0041 (D7, built 2026-10-16): `compile --test` cells gain the optional, additive `best_effort` list, the ids of the best-effort cells a column's answer rests on, and the text line names them; the document stays `v: 1`.

Implemented as (2026-09-24): the set is computed from the build alone (`enforce.Buildable`), with no kernel fact read. A fact could only remove a tier this machine lacks, and answering for one errs toward reporting a difference, which is the direction this ADR's security argument allows; the header says where the set came from. The JSON form is `--json` with `--test`, the flag compile already had, not a new `--format json`. There is no fanotify-fallback column: tier 2's decisions are Evaluate's at `cgroup`, and ADR 0028 S3 is where the fallback's semantics would diverge. Step (5) was already true: a pinned tier the build lacks is refused with doctor's reason, which names the build. Condition: when ADR 0024's decision-plane modes differ, each mode becomes a column.

Amended 2026-09-29 (ADR 0017's conformance suite found compile --test disagreeing with the kernel on five cells): compile --test resolves each row's path through the real filesystem when it exists, with the kernel walk compile resolves its entries with, and evaluates the path the kernel would reach (an open or an exec follows a final symlink; an unlink, mkdir or rename resolves only the directory), so a row through an undeclared symlink is decided on its target and an exec of a symlink to a granted binary on that binary (a hard link stays itself, refused). A row whose path does not exist is evaluated as written; the output names each resolved path that differs. Evaluate stays pure: the resolution is TestTable.RunResolved's, in the CLI layer, and the resolver endpoints a run snapshots are read by the CLI and passed in (decide.EvaluateIn), so a connect to one on port 53 is net.resolver by the supervisor's own lookup (decide.IsResolver). compile --test therefore reads the filesystem and /etc/resolv.conf (under resolver: auto); it still makes no kernel call beyond read-only file I/O.

Decision: (1) compile resolves tier: auto with the derivation run and doctor use (enforce.Buildable, the machine ceiling, doctor's kernel derive), never to a tier this binary does not contain. It uses only facts an unprivileged process reads: Buildable, the ceiling, the kernel release, BTF presence, the active LSM list, the lockdown mode and the Landlock ABI. compile never loads a program, attaches a link, creates a fanotify group or runs a functional probe, even as root. (2) compile --test evaluates each row in every tier of that set, in each decision-plane mode once ADR 0024 lands if modes ever differ, and in a fanotify-fallback column while the fallback's semantics differ from the plane's (until ADR 0028 S3). It prints a verdict per column and fails a row whose expected verdict does not hold in all of them; a row's own tier: narrows the set. (3) --tier <t>[,<t>] replaces the derived set, so a contract can be checked for the machine it will run on; the output header names the machine facts the set came from. (4) --format json emits a versioned document (v: 1) with one object per row and column; the text form is for humans. (5) enforce/select.go says 'not built in this binary' when Buildable is the reason and 'not available on this machine' only for a machine reason (NotBuiltError).

Why: [documented, code] pkg/spec/agent compile.go:428-433 maps an unbounded or auto ceiling to TierBPFLSM, which internal/runtime/enforce/buildable.go:98 reports as not implemented. [measured] On this machine compile prints bpflsm, and 2 of 2 probe rows came back refused while the real run at tier landlock allowed both; select.go then blames the machine.
[documented] doctor.ForRun at reach bpflsm runs D6's functional LSM probe and D7's program loads: 0.65-1.2 s the first time, then 75-330 ms, host-wide, and only as root. Reusing it would attach programs and make answers depend on privilege.
[inference] The reachable set is computed on the compiling machine; --tier and the header make that visible.

Security argument: Authors cannot certify a refusal that the tier which will run does not make: a row passes only if it holds wherever the contract can land, so compile --test errs only toward reporting a difference. compile has no kernel side effect, so running it as root attaches nothing host-wide.

Options considered: Rejected:
- Default to the highest tier the build contains: still answers for a tier the machine may not run.
- Default to the caller's current tier: answers would depend on sudo.
- Keep bpflsm as the default: a tier not in the binary.
- Probe as doctor does when root: attaches host-wide and makes answers depend on privilege.

Consequence: compile --test output gains a column per tier (and a fanotify column for a while). Tables written for one tier may start failing where tiers differ, which is the point. Scripts that parse the text move to --format json.

Implementation plan:

- internal/doctor: a pure fact reader with no loader import; internal/cli (the composition root) derives the set and passes it to the evaluator (the core after ADR 0028; Evaluate before).
- A test builds compile with a fake prober that fails the test on any probe or load call; the same test runs as root in GUEST.
- Golden tests of text and JSON output per tier set; select.go message split with NotBuiltError.
- ADR 0017 checks compile --test per tier and mode.
Docs: ADR 0019; limits-check-doctor-cli (R33 closed, output format, --tier, --format json); agent-contract's compile --test section.

*Amended 2026-09-29 ((2), ADR 0024 as accepted; T1, TIER3-PLAN §5 and §11):* once ADR 0024's plane is built, tier
cgroup with a plane mode and tier bpflsm share one `compile --test` column. Both are the core's root model (ADR 0028:
the plane's walk intersected with Landlock), the row compiler and the column come from the same function (ADR 0028
S4), and the plane's two attach modes (lsm, fmod_ret) run the same hook bodies, so a column per tier or per mode
would print the same verdict twice. They split into separate columns only when an ADR 0017 cell records a kernel
verdict that differs between them; the PR that adds such a cell adds the column and names the cell. The fanotify
fallback keeps (2)'s own condition: a column only while its semantics differ from the plane's, which ends with
ADR 0028 S3 and ADR 0021 (5). Until the plane is built, tier cgroup's column is today's tier 2 (Evaluate at
cgroup: the root walk for reads, Landlock's union for modifications), as the 2026-09-24 paragraph states, and it
differs from bpflsm's.

Changes:
- 2026-09-29: amended, compile --test resolves row paths through the filesystem and answers the resolver exception (the amendment paragraph above).
- 2026-09-29: T10 built the shared column's bpflsm half: its fs and exec answers come from the plane's rows (`decide.PlaneEvaluator`), the header names
  the source and `decision_plane lsm`, and each `--json` bpflsm cell carries `mechanism: plane` and `decision_plane: lsm`. Tier cgroup keeps today's
  column until a plane is built for it; no ADR 0017 cell differs between lsm and fmod_ret, so there is no mode column.
- 2026-09-30: one column, decided again on exec/exec-unlisted-script. The kernel refused it at cgroup@lsm and
  cgroup@fmod_ret where the column said allow (four baseline entries). The difference was not the plane's: the plane
  passes the `#!` stage, and the Landlock floor every tier installs refuses the unlisted script first. The column is
  the root model, the plane intersected with Landlock (the amendment above), so `decide.PlaneEvaluator` and
  `Evaluate` at bpflsm now ask the floor under a script (`decide.ScriptFloor`) and the cell expects refused; no
  column is split and the baseline entries are deleted.
- 2026-10-16 (ADR 0017 (b)): "an answer for every runnable action" holds for the
  actions conformance cells take: `fs.link`, `fs.attr`, `net.socket`, `net.send` and `exec.anonymous` rows, each
  answered in every column by the matcher the run decides it with (limits-check-doctor-cli R28's amendment). The bpflsm
  column reads `fs.link` (path_link: the new name, then REFER) and `fs.attr` (the attribute hooks' protected rows) from
  the plane's rows, with `mechanism: plane`; the socket allowlist, the send's connect decision and the anonymous image's
  `exec.anonymous` bit are the policy model's, the predicates the plane's slot header carries. No column is split.
- 2026-10-17: the plane intersected with Landlock (the 2026-09-29 amendment) now holds
  for a hard link and a rename as it holds for a script: the bpflsm column and `Evaluate` at bpflsm compose the
  Landlock floor's `REFER` (`decide.LandlockLinkRefusal`, `decide.RenameGains`), and the landlock and cgroup columns ask
  a link of its ends' directories, as the kernel does. The run's lines were corrected to match (supervisor R17,
  enforce-cgroup-observe R9), so the column did not move away from the run; no column is split.
- 2026-10-17: a rename's `REFER` in every column, and the run's line with it, is
  `hook_path_rename`'s: nothing compared within one directory, the new name's directory against the moved object across
  directories, never a rule on the name it replaces, file rights only for an object that is no directory. The rule had
  compared the two names, so a replace of an `exec.allow` file entry inside a write entry answered `refused` in all
  three columns and on the run's line while the kernel allowed it; the conformance cells
  `refer/rename-onto-exec-file-entry*` now hold the compile column to the kernel.
- 2026-10-17: a rename's, a link's and a delete's ends are the names the
  syscalls act on, never followed, in every column; the bpflsm column and `Evaluate` at bpflsm compose the floor's
  directory rights for a rename and a delete as for a link. The run's line also follows the inodes the Landlock
  builder granted once the agent moves them (supervisor R17, S1), which a row answered against the starting tree cannot
  see; the conformance cells that act on a moved tree say so (`NoCompile`). No column is split.
- 2026-10-17 (C1): "a row whose path does not exist is evaluated as written" (the
  2026-09-29 amendment) now holds only for a row whose directory does not exist either. A row's final name that does
  not exist lies in the directory the kernel's walk reaches, since the kernel follows every component but the last
  whatever the syscall does with the last; a rename's or a link's new name almost never exists, so a move or a link
  through an undeclared symlink into an `exec.allow` directory was answered `allow` at the symlink's spelling while
  the kernel answered `EXDEV` and the run's line said `refused`. A row through the `exec.allow` entry's own declared
  link (`./out/bl/`, `out/bl -> realbin`) is resolved the same way, to `realbin`. Pinned by
  `TestCompileTestSymlinkedNewNameDirectoryGolden` and the conformance cells `refer/*-through-symlink-*`. (The
  decision core's ends were also made to follow an `exec.allow` directory entry's declared link, `canonicalEnd`'s
  `execDir`; withdrawn by the next note.)
- 2026-10-17: a path reaches the decision core's rename,
  link and unlink answers in one of two forms, and one string cannot carry both. Asked by name (a hand-built row, an
  `Evaluate` caller), it may spell a link the table declares. Landed, it is where the kernel's walk left the name, every
  component but the last already followed: the supervisor's walk of the notified pathname, the recorder's `d_path`,
  and a `compile --test` row once it is landed (`resolveRowPath` then, `supervisor.Land` since an earlier note). A landed path spells a declared link only once the agent
  replaced the link with a real directory, which carries none of the rules Landlock put on the link's target, so a
  rewrite by a declared spelling is wrong on a landed path exactly when it fires. The earlier rewrite by an
  `exec.allow` directory's link did that on the run's ends: after `rm out/bl; mkdir out/bl`, a move and a link into
  `out/bl` were recorded `refused` while the kernel allowed them; since REFER's no-gain rule came to the run, an fs entry's link rewritten by `Canonical` did the same for a write entry linked to an `exec.allow` directory,
  and the recorder blamed Landlock for an unlink in a directory that replaced a non-write entry's link. Decision: every
  entry point the run calls with ends (`RenameGainedBy`, `LinkGainsBy`, `LandlockRenameRefusalBy`,
  `LandlockLinkRefusalBy`, `LandlockDeleteRefusal`, and the table forms that wrap them) takes them landed and rewrites
  nothing (`landedEnd`), the exec grants answered by the inodes the builder held (`HeldExecGrants`); the core follows no
  `exec.allow` link by its spelling, and the table's own answer (`landlockExecGrant`, what a run that holds no inode
  and a question asked by name get) compares an entry at its target only, where the builder's grant is, not at a
  declared spelling that resolves elsewhere, beneath which it had granted `EXECUTE`; `compile --test` lands its rows
  itself (`resolveRowPath`), and kept the earlier answer only where a row's new name's directory existed when compile
  ran (corrected by the next note: beneath a directory the agent makes later its answer turned `allow`). Only
  `Canonical`'s rewrite by an fs entry's declared link (R15) stays, for questions asked by name (`canonicalEnd` in
  `Evaluate` and the plane evaluator). Rejected: (a) keeping the exec rewrite for questions with no held grants, since
  nil grants are also what a run passes when it holds no inode (images unrestricted, nothing stat'ed) and the core
  still could not tell a spelled path from a landed one; (b) keeping it for `compile --test` alone, which already lands
  its rows, so it would answer nothing compile asks; (c) rewriting only while the tree still holds the link, an lstat
  inside the pure core (I6) that races the agent's own changes. Condition (disclosed, not built): outside these entry
  points the run still matches an fs entry by its declared spelling as well as by its target (`ruleSteps`, the
  supervisor's advisory tables, `GrantName`'s naming, `Canonical` in the `Evaluate` calls the supervisor and the
  recorder make for an open), so after the agent replaces a declared fs link with a real directory, a decision beneath
  it can be made, or a line named, by an entry Landlock bound to the target's inode; closing that needs the fs
  entries' inodes held as `HeldExecGrants` holds the exec entries', a change to every fs decision rather than to
  `compile --test`. Pinned by `TestRunEndsAreAskedWhereTheyLanded` (fails with either rewrite),
  `TestEvaluateTakesAnExecDirectoryLinkAsItLands`, and the conformance cells `refer/*-replaced-exec-link` and
  `refer/*-replaced-write-link`, which hold every axis's line to the kernel.
- 2026-10-17: the part of a row's path that does not exist yet is evaluated beneath
  its deepest ancestor that exists, as that resolves (`walkExisting`, the answer `realpath -m` gives), no longer as
  written once its directory is missing too: a directory the agent makes later is reached by the
  kernel's walk through every existing component, links followed. With `./out/bl/` declared in `exec.allow` and
  `out/bl -> realbin`, a move or a link into `out/bl/sub/` (`sub` absent when compile ran) reached the core still
  spelled through the link, and since the table's exec grant is compared at each entry's target only (previous note)
  every column answered `allow` while the kernel refused it `EXDEV` and the run's line said `refused`; the same row
  through an undeclared link (`out/u/sub/`) had answered `allow` before this note. Rejected: comparing the declared
  spelling again for compile's rows (the previous note's (b)), which would still miss the undeclared link. Compile's
  own entry resolution (`resolvePath`) and the Landlock builder's (`resolveTarget`) keep the one missing level they
  resolve: a write entry is created only as a leaf, and one whose parent is missing too is `path-missing` (E9 of
  `docs/p0/agent-contract.md`) and refused at run start, so no entry is deeper. Pinned by rows 08 to 11 of
  `TestCompileTestSymlinkedNewNameDirectoryGolden` and by `TestResolveActionFollowsAsTheKernel` with and without
  `/proc`, which fail without the change. (`walkExisting` stopped at a dangling link, which `realpath -m` follows, and
  the row was cleaned before it was walked; both withdrawn by the next note.)
- 2026-10-17: earlier fixes took
  one spelling at a time, because `compile --test` and the run each had their own idea of where a path lands; that
  left a dangling link taken as itself, a row cleaned before it was walked, and in the run a
  destination looked up by its cleaned spelling, which found the source's walk for `out/lk/../x`. Decision: one
  resolver, the run's own walk. `compile --test` and `compile --exec` land each row's path with `supervisor.Land`,
  FSTarget's walk (supervisor R15b) made in compile's own view: the path as the agent's syscall spells it from the
  table's directory, uncleaned; each `..` physical against the directory reached so far; every symlink on the way
  followed, dangling or not, with the kernel's limit of 40; the final one only where the syscall follows it. Asked before
  the agent runs, a component that does not exist yet is a directory the agent makes later (`pathQuery.predict`): the
  names after it lie beneath it, a `..` climbs back out of it, and the walk goes on physically once it is back in the
  existing tree, so a row is evaluated where the run's walk lands once the missing directories exist. A walk that fails
  as the agent's own lookup fails leaves the row as written, the spelling the run's line keeps; one compile cannot make
  (no `/proc`, `EMFILE`) does too and says so on stderr, since that answer rests on the spelling alone. `walkExisting`,
  `resolveRowPath` and their `filepath.EvalSymlinks` fallback are deleted. In the run each end of a rename or a link is
  decided where its own walk landed it, the walk found by the end's query (`walkOf`), never by its spelling, and a
  non-followed end's parent is looked up as a directory, as `filename_parentat` does, so a name beneath a file is
  `ENOTDIR`, not a landing beneath the file. Contract entries keep `Compile`'s own resolution (`resolveProbe`, the
  kernel's open of the path, which is the kernel's walk for a path that exists). Rejected: (a) another spelling fix in
  compile's own resolver, the approach every earlier fix took; (b) a new resolver in `pkg/` that both import, which would move
  the run's walk (procfs, magic links, automount, search checks) out of the supervisor every run's line relies on, or
  leave the two to drift; (c) refusing rows with `..` or a dangling link, which leaves paths agents write unanswered.
  Pinned by `TestCompileLandsWhereTheRunLands` (over generated trees, compile's landing, the kernel's own once the
  missing directories are made, and the run's walk of the same syscall agree for every row),
  `TestResolveActionFollowsAsTheKernel`, `TestLandRefusesAsTheKernel`, `TestRunResolvedAsksTheWalkOfEachPath`,
  `TestCompileTestLandsAsTheKernelGolden` (9 of its 14 rows fail at the previous resolver),
  `TestMoveEndsAreLandedByTheirOwnWalk`, and the conformance cells `refer/*-dangling-link*` and `refer/*-dotdot-*`
  (18 compile disagreements at the previous resolver, none now).
- 2026-10-19: the note above landed filesystem and exec paths,
  and left a `net.connect` or `net.send` row's unix pathname to its spelling, while the run decides such a name twice:
  on the name, then on the socket it reaches in the agent's view (supervisor R11, R11a, SEMANTICS §5 as amended
  2026-10-16). A datagram or a connect through a symlink in a write entry to a socket outside every entry read `allow`
  in every column, and the run refused it (`EACCES`, rule `unmatched`). Decision: the same walk lands the name
  (`Action.Landed`, `connect(2)` and `sendto(2)` following a final symlink), and the decision core decides the name and
  then the landed socket, matched as the supervisor's `decideResolved` matches it, a `unix:` entry by the path
  `Compile` resolved it to (`NetRule.Resolved`, `FSRule.Resolved`'s rule) and the nearest filesystem entry by its
  resolved path alone; a relative name joins compile's working directory, as the run joins a relative `sun_path` to the
  agent's cwd (as `getcwd(2)` reports it: the next note). So the claim is: compile and the run land every row path with
  one walk (FSTarget's, which `TestCompileLandsWhereTheRunLands` now also holds to the supervisor's unix walk,
  `unixTarget`; the next note lands a unix name with that unix walk itself), and decide what that walk reaches with one
  decision core; they agree by construction on where a path lands, and on the verdict where the run decides on nothing a
  row cannot carry. What a row cannot carry stays stated: which process bound a socket (R11a's `unix-foreign`), the
  inodes the run held before the agent started (R17), and, for a name the walk cannot land, the run's refusal of a
  datagram (`unix-absent`, `path-unreliable`) where compile answers the spelling, a send that fails in the agent's own
  lookup either way (answered as the run answers it by the next note). Declared `unix:` entries are resolved by `Compile` here and by the supervisor's
  `resolveDeclared` when its loop is built, before the agent runs, both by `FSRule.Resolved`'s rule. Rejected: deferring
  the name's landing to the net conformance cells, which would leave the package's agreement claim false for every unix row. Pinned by
  `TestCompileTestUnixLandsAsTheRunGolden` (5 of its 10 rows fail without the change),
  `TestEvaluateUnixDecidedWhereTheNameLands`, `TestResolveActionFollowsAsTheKernel`,
  `TestRunResolvedAsksTheWalkOfEachPath`, `TestUnixEntryCarriesResolved`.
- 2026-10-19: the note above landed a
  unix name with FSTarget's walk, which follows a procfs magic link as compile itself, while the run walks the name with
  `unixWalk` (`RESOLVE_NO_MAGICLINKS`, a landing on procfs refused, a connect that only the component walk lands
  refused): a send or a connect through a link to `/proc/self/cwd` read `allow`, and the run refused it
  `path-unreliable`. So "one walk" did not hold for unix names. It also answered a name that walk cannot land on its
  spelling, where the run refuses a datagram (`unix-absent`, `path-unreliable`) and a connect through a loop or a magic
  link (`path-unreliable`); it joined a relative row to `$PWD`, which spells compile's directory through a symlink when
  the shell came through one, where the run joins the agent's name to `readlink /proc/<pid>/cwd`, and the name step
  matches `unix:` entries by spelling; and the root columns left the kernel programs' refusal of a datagram name not
  spelled canonically unanswered. Decision: compile lands a connect's or a datagram's name with
  `supervisor.LandUnix`, which is `unixWalk` and `unixPlaceOf` in compile's own view, and classes what it met by the
  run's own two answers to a failed walk (`unixLandedRefusal`, `unixWalkOutcome`) into `agent.UnixWalk`
  (`Action.Walk`); the decision core answers each class as the supervisor does (`unixLanded`): a magic link, a loop or
  procfs `path-unreliable`; for a datagram `unix-absent` for a name that names nothing and `path-unreliable` for another
  failed lookup, for a connect the name's verdict, the line of a connect that fails in the agent's own lookup; a socket
  only the component walk reached refuses a connect and decides a datagram. A socket that does not exist when compile
  runs is taken as the one the agent finds there when it calls, its missing directories made and a dangling link
  followed (`predictUnix`: the premise fs rows are asked under, `pathQuery.predict`, with every magic link refused, each
  link held to what the kernel's lookup holds it to, and a missing name on procfs, where nothing is made, naming
  nothing: a false premise the next note corrects). A bind's walk stays FSTarget's, the one `bindUnix` decides on, and
  one that fails is refused `path-unreliable`, as `bindUnix` refuses it (under a listener policy only: the next note).
  A row joins `getcwd(2)`'s directory. The `cgroup` and `bpflsm` columns
  refuse, rule `unmatched`, an admitted datagram whose absolute name is not canonical (`agent.UnixCanonical`, moved
  from the supervisor so that its `kernelRefusal` and the decision core ask one function). Rejected: answering a socket
  missing at compile as absent, the run's answer only when nothing makes it before the call, so that every row naming a
  socket the agent's own server binds would read refused; stating the magic-link gap rather than walking as the run
  walks; and modelling a `cgroup` column below 6.7, which would need the kernel the run will get. Stated: a socket still
  missing when the agent calls gets the run's absent answers (a connect's `ENOENT` with the name's verdict, a
  datagram's `unix-absent`), not compile's; compile walks with its own credentials, the agent's at tier `landlock`,
  while tiers `cgroup` and `bpflsm` walk a datagram's name as root; a `cgroup` run below 6.7 outside a plane mode
  admits a datagram name not spelled canonically. Pinned by `TestCompileTestUnixWalkAsTheRunGolden` (8 of its 13 rows
  fail without the change), `TestCompileTestUnixJoinsThePhysicalCwd` (2 of its 3), `TestEvaluateUnixDecidedOnWhatTheWalkMet`,
  `TestResolveActionFollowsAsTheKernel`, `TestRunResolvedAsksTheWalkOfEachPath`, and `TestCompileLandsWhereTheRunLands`,
  which now holds connect and datagram names, magic links and procfs among them, to `unixWalk`, and the ones it
  refuses to the run's answer once what the name passes through is made.
- 2026-10-19: three answers of
  the note above were the run's in one arm only. A bind whose walk fails was refused `path-unreliable` in every column,
  but the run reaches `bindUnix` only under a listener policy; with none it continues every bind with no line and the
  kernel answers it, so compile now answers that row with the creation floor on its spelling, as a filesystem row whose
  walk fails. `predictUnix` answered a name whose missing part lies on procfs as naming nothing, on the premise that
  nothing is made there; but `/proc/<pid>/fd/N`, `/proc/<pid>` and `task/<tid>` appear as the agent opens descriptors and
  starts processes and threads, each a magic link or a procfs directory, which the run's walk refuses
  `path-unreliable`, and compile's own `/proc/self/fd/N` is not the agent's, so the answer changed with compile's own
  descriptor table. Decision: such a name is `path-unreliable`, the premise every other missing part is taken under
  (it is made), and a name climbing back out of that part with `..` too. Rejected: dropping only the procfs answer and
  walking on, which would land a climb back out of a made `fd/N` outside procfs where the run's walk meets the magic
  link; and a list of which procfs names appear, which no kernel interface states. And `predictUnix` dropped a
  trailing `/` or `/.` beyond what exists, so a datagram to `out/new.sock/` read `allow` where the run answers
  `unix-absent` whether the socket is missing (`ENOENT`) or bound (`ENOTDIR`); such a name now names nothing
  (`ENOTDIR`), unless the walk itself went beneath that part (`a/b/..`, or a link's body that walks into the name it
  later ends on), a directory the run's walk lands on once it is made (both replaced by the design note below: such a
  name ends on the directory the agent makes, which the run refuses `unix-foreign`).
  `TestCompileLandsWhereTheRunLands` makes, for a
  refused name, the socket its name leads to (a node no lookup takes for a directory) beside its directories, and takes
  the name's directory uncleaned, as the kernel walks it: `path.Dir` cleaned `n/../m` to `m` where `n` is a link.
  Pinned by `TestCompileTestUnixWalkAsTheRunGolden` (rows 14 to 20 and a listener policy's L1, L2; 6 fail without the
  change), `TestEvaluateUnixDecidedOnWhatTheWalkMet` (both bind arms), `TestResolveActionFollowsAsTheKernel`, and
  `TestLandUnixStepwise`, which makes `LandUnix` answer a link `fs.protected_symlinks` refuses (Stepwise) as the run's
  component walk does, unprivileged with another follower's facts and, as root, through the kernel's own refusal.
  `compile --exec` and a table run with no cwd join `getcwd(2)`'s directory (`TestCompileExecJoinsThePhysicalCwd`,
  `TestRunResolvedJoinsThePhysicalCwd`).
- 2026-10-19: earlier fixes took `compile --test`'s unix names one shape at a time (a missing socket, a name
  on procfs, a trailing `/`, a part the walk went beneath), and a datagram to `out/x/y/..`, `out/d/`
  or `out/d` (a directory) still read `allow` where the run refuses it `unix-foreign` in every state of the tree, and a
  `bpflsm` bind still answered with a line its run never writes. The cause is shared: the walk was one, but the premise it
  was asked under and the decision on what it reached were not. (a) The tree the agent calls in was never stated once:
  each missing-part shape was mapped to an answer by hand (`missingDir`'s `ENOTDIR`, `madeOnProcfs`, `virtDir`).
  (b) Whatever the walk reached was decided as the socket the agent binds, while the run's write entry admits only a
  socket a process of the run bound (R11a's `boundByRun`), which no directory and no file that is not a socket is.
  (c) Which part of the run decides a bind was taken to be the supervisor in every column, where the `bpflsm` column's
  plane takes the bind over (`bindHandoffReady`). (d) The property test compared landings, so a right landing with a
  wrong verdict passed. Decision, one model: compile answers a connect's or a datagram's name on the tree the agent
  calls in, which is the tree as it is when compile runs, with every directory the name's walk needs made (the premise
  every filesystem row's missing part is answered under, now including a name's final part when the name ends in `/`,
  `/.` or `/..`, in its spelling or its final link's body, and a part the walk went beneath before it ended on it), and,
  at a final name that names nothing yet and that nothing needs as a directory, the socket the agent binds. What is
  there is what it is: a socket is taken as the run's (R11a cannot be asked before the run: stated, as before), and a
  directory, made or already there, or a file that is not a socket is none (`agent.UnixLanding.NoSocket`,
  `Action.NoSocket`). What the walk reaches is decided as the run decides any landing (`decideResolved`): a `unix:` entry
  resolved to it admits it, the write entry's implicit admit refuses no socket `unix-foreign`, and anything else is
  `unmatched`. `predictUnix` loses its `ENOTDIR` answer for a missing name ending in `/` or `/.` (the previous note's),
  which held only in the state where a socket sits at that name, and `missingDir` becomes `madeDir`. A pathname bind is
  decided, column by column, by the part of the run that decides it (`decide.bindUnixDecides`): with no listener policy,
  and in `observe`, by none, the kernel answering it under the creation floor; under one, in the `landlock` and `cgroup`
  columns, by the supervisor's `bindUnix`, which refuses a bind whose walk fails `path-unreliable`; and in the `bpflsm`
  column by the plane, at `path_mknod`, which a bind whose lookup fails never reaches, so the row is answered on its
  spelling there, as R15 answers every row whose walk fails (the run's line is the kernel recorder's, `observed` or, for
  `EACCES`, `refused` `path-unresolved`, with the kernel's errno and no rule). The run's own decision steps are now
  functions the run and the property test both call (`decideUnixName`, `landedVerdict`, `unixAdmit`,
  `unixConnectLine`), and `TestCompileLandsWhereTheRunLands` holds every generated connect and send row's verdict
  (decide.Evaluate of what compile landed before the agent ran) to the verdict those functions give once the tree is
  made as the premise says, R11a answered as the premise answers it; its trees now hold sockets already there, link
  bodies and names ending in `/`. So the claim is: compile and the run agree by construction on where a unix name
  lands and on what decides it, and on the verdict wherever the tree the agent calls in is the one stated. Rejected:
  (1) answering every name that must end on a directory as naming nothing (`unix-absent` for a send, the name's verdict
  for a connect): it holds only where a socket sits at the name's last part, contradicts a
  directory already there, where the run refuses `unix-foreign`, and needs a second premise beside the filesystem
  rows'; (2) taking a directory already there at a plain name as a socket the agent puts in its place: a bind over a
  directory fails `EADDRINUSE`, and servers remove a stale socket file, never a directory; (3) keeping the `bpflsm`
  bind's `path-unreliable` and stating it: a verdict that run's line never carries; (4) a verdict `observed` for that
  row: compile's verdicts are `allow`, `ask` and `refused`, and the row would then answer differently from every other
  row whose walk fails; (5) making the premise tree in a scratch copy of the real one and asking the run there: compile
  has no side effect (this ADR's security argument), and the tree can be large. Stated: where the tree the agent calls
  in is another (a socket still missing at the call, one already there that no process of the run bound, a directory
  made or removed after compile), the run's line is that tree's. Pinned by `TestCompileTestUnixWalkAsTheRunGolden`
  (rows 17 to 29 and L1, L1c, L1p: 13 fail without the change), `TestEvaluateUnixLandedOnNoSocket`,
  `TestEvaluateUnixDecidedOnWhatTheWalkMet` (the three bind deciders), `TestResolveActionFollowsAsTheKernel` (10 cases
  fail without it) and `TestCompileLandsWhereTheRunLands` (72 verdicts disagree without it at its seed, none at it or at
  ten more seeds). The tests that build socket names now take a directory that fits `sun_path` whatever `TMPDIR` is, and
  `TestLandUnixStepwise`'s root branch turns `fs.protected_symlinks` on for itself.
- 2026-10-19: the note
  above took the `bpflsm` column's bind answer from the run's half, `TestPlaneRunBindLookupFailureIsTheKernels` (a
  decision-plane run binding beneath a regular file: the kernel's `ENOTDIR`, one kernel-recorder line, `observed`,
  `unmatched`, no `path-unreliable`), but that test declared its listener beneath the file itself
  (`unix:<project>/out/file/b.sock`). A decision-plane run holds each declared listener's directory at prepare (the
  Landlock fill's `planeListenParents`) and refuses to start when one is not a directory, so the run exited 125 before
  the bind in every arm on both boots and the claim was never pinned. The test now declares `out/b.sock` and binds the
  undeclared `out/file/b.sock`, and passes in every arm (`cgroup@lsm`, `bpflsm@lsm`, `cgroup@fmod_ret`) on both boots;
  it is in `test/vm/root-must-pass.txt`. The golden's `listen.yaml` had the same contract, so L1p answered for a run
  that cannot exist: it declares `out/b.sock` alone now, and L1, L1c and L1p ask the undeclared bind beneath the file
  (`path-unreliable` at `landlock` and `cgroup`, as before; at `bpflsm` its spelling, which no entry names, `refused`
  `unmatched`), so each column describes a run that starts. No decision changed. Rejected: a `compile` warning for a
  `unix:` listener whose directory is not one when compile runs: the run's prepare already refuses that contract, fail
  closed and naming the entry, and the directory may be made between compile and the run.
- 2026-10-19: the run's
  decisions are unchanged; this is how its lines name an end spelled with `..`, which the conformance column
  compares by verdict only. Chosen: the physical walk of the end's directory (as `filename_parentat` looks it up)
  joined with its final component as spelled (supervisor `lineName`, `nameQuery`), made before the answer, for every
  line that names such an end whatever its verdict, and an MCP start matched on that name or on the image's identity
  (inode and resolved path, as a file entry's grant). Rejected: naming at the fully followed walk (the rule before this fix),
  which named a final symlink's target and lost the `mcp` line of a server whose `command[0]` is a link; naming by the
  image only when the clean and the walk reach different inodes, which needs a second walk on every `..` end and still
  names a link's target when they differ; and keeping the cleaned spelling with a disclosure, which leaves a line
  naming a file the syscall did not reach. Tests: `TestFSLineNamesWhereADotDotSpellingLands`,
  `TestRefusalLinesNameWhereADotDotSpellingLands` (one case per refusal site), `TestKernelRecorderNamingOfADotDotSpelling`,
  `TestExecLineNamesWhereADotDotSpellingLands`, `TestExecOfADeclaredMCPServerByAnotherSpellingEmitsMCP` and a
  tier-landlock probe as `TestIntegrationMCPStartThroughADotDotSpelling`.
- 2026-10-19: the name of
  a `..` end comes from the walk that decides it. The first fix walked an end the syscall follows (an open, an exec, an
  attribute change) a second time for its name (`nameQuery`), so a symlink the agent moved between the two walks had a
  line name a file its verdict and rule were never taken on, and an exec name the declared MCP server's file while it
  ran the agent's own (an `mcp` line for a server that never started). Chosen: the component walk keeps the name as it
  passes the directory of the final component (`execWalk.named`), so `FSTarget` answers it with the landing it decides
  on, `ExecImage` with the image, and every line reads the decision's memo; an end no decision walked (a refused move's
  new name) is walked once, and that walk is the end's; an ask's refusal made once the open is held names it by the
  pin's walk, on whose object it was decided (`askLineName`). An MCP start is matched on the image's identity (inode
  and resolved path) before the name. Rejected: keeping the second walk and checking it against the decision's (a
  mismatch still needs a name, the decision's own, which the walk already passes for nothing; and a recheck is one more
  lookup on every `..` end); and naming such an end at its full landing (a final symlink's target, the rule before this fix).
  Compile's question (`Land`, `predict`) names nothing. The race between the walk and the kernel's own lookup stays as
  R16b of the supervisor spec discloses it. Tests: `TestFSLineNameIsTheDecisionsWalk` (the tree changed after every
  walk the loop makes), `TestTheWalkNamesADotDotSpelling`, `TestExecLineNameIsTheImagesWalk`, refusal cases with the
  link moved during a person's wait and before the pin, a hard-link case for the MCP identity, and a
  tier-landlock flip probe as `TestIntegrationDotDotLineNamesTheFileItsVerdictWasTakenOn` (1500 opens; about 240 lines
  named a file their verdict was not taken on before the fix, none after).
- 2026-10-19: the run
  decides a `..` end where `compile --test` lands it. The supervisor's R15c and R15d matched every end as spelled first,
  so `out/lk/../.git/config` was refused under the target `out/.git/config` while compile, which lands the path before
  it evaluates, answered `b/.git/config` unmatched. Chosen: an end named by its walk is matched, decided and scored by
  that name or its landing, never by the lexical clean (supervisor R15b, R15c), so the run and compile agree by
  construction; a held open with such a spelling takes the loop's walk before its pin. And the shared resolver
  (`FSTarget`) walks an unfollowed final `.` or `..` as `path_lookupat` does: only the name-making families refuse one
  before a lookup (`pathQuery.parent`; compile's `Land` set it for every row it did not follow, a link's old name
  included, until the next note), so an `AT_SYMLINK_NOFOLLOW` attribute
  change of `out/lk/..` is decided where it acts. Rejected: naming such a line by its spelling when the rule came from
  the spelling, which keeps a decision on a file no mechanism reaches and keeps the run apart
  from compile. Tests: `TestADotDotEndIsDecidedWhereItIsNamed` (tiers landlock and cgroup and the held open; a target
  the walk reaches; a failed walk; the gate; an fs.ask scope), `TestAnUnfollowedFinalDotIsWherePathLookupLands`
  (five attribute syscalls and an `O_NOFOLLOW` open, with a plane's `deny_write` refusal), `TestExecIsDecidedWhereItIsNamed`.
- 2026-10-19: earlier fixes changed how one end is landed, decided or named one site at a time, because each site
  restated for itself which of the kernel's lookups the end makes and which place stands for it. An earlier fix taught the
  run's walk the kernel's third lookup (a whole-path lookup that does not follow a final symlink still walks a final
  `.` or `..`; only the syscalls that make, remove or rename a name refuse one before a lookup), but compile's `Lander`
  took one `follow` bool, which `Land` read as "not followed" and "name-making" at once, and
  `TestCompileLandsWhereTheRunLands` wrote the run's queries out by hand, so compile still asked a link's old name as a
  name-making end and answered `out/lk/.` on the symlink `out/lk`, `allow`, where the run and the kernel act on where
  it leads (`refused`, `EXDEV`), while the note above said compile set that bit only where the run does. Decision: the
  lookup an end makes is one value, `agent.Lookup`: `LookupFollow` (`path_lookupat` with `LOOKUP_FOLLOW`),
  `LookupCreate` (an `O_CREAT` open, a dangling final symlink followed to the name it creates), `LookupNoFollow`
  (`path_lookupat` without `LOOKUP_FOLLOW`: a final symlink is the end, a final `.` or `..` is walked) and
  `LookupParent` (`filename_parentat`, `filename_create`: a final `.` or `..` refused before a lookup). It is stated
  once per row kind (`ActionKind.Lookups`; an `fs.link` row's `path` is `LookupNoFollow`, its `dest` `LookupParent`)
  and once per syscall in the run (`openLookup`, `followLookup`), the walk's query is built from it in one place
  (`pathQuery.as`) that `Land` builds compile's question with too, and the two statements are held together by test:
  `TestEveryRowEndIsWalkedAsItsSyscall` drives the run's own handler of the syscall each row kind stands for and
  compares the lookup it walks each end with to the row's, and the property test takes its compile and run questions
  from the table and covers every lookup against the kernel's own landing, a link's old name included. The other half
  of the class, a name or a scope taken at each refusal site, keeps the previous notes' model (one walk per end, read
  by `lineName`, `landed`, `memoName` and `askLineName`); what was missing was proof that every site reads it, so each
  of the 33 such sites was reverted to the spelling in turn and the supervisor's unit tests and unprivileged
  integration probes run. Nine survived, each a site no test reached: the fs.ask scope match made when an open's pin
  fails (`PrepareAskOpen`, the branch a real run reaches); the gate's score of an
  unlink and of a rename's new name in `settleFS`; R15c's match of a landing that differs from the end's name but
  equals its lexical clean (`matchEnds`); the listener's question whether Landlock lets an open through
  (`listenerRefuses`); the kernel recorder's key for a continued open that follows a final symlink (`handOver`); a
  held open's copied-name score (`heldOpen`); the name of a delivered held open of a nameless object, now one helper
  with an undelivered one's (`heldName`); and the recorder's key for a new name (`handOver`'s `name2`), which is
  equivalent, since a new name's final component is never followed and is its spelling's wherever the kernel lets
  the move run. Each of the others now has a test that fails with its site reverted
  (`TestEverySiteTakesTheEndWhereItsWalkPutsIt`, the `TestADotDotEndIsDecidedWhereItIsNamed` subtest when the pin
  fails); none hid a wrong answer. Rejected: (a) a second bool beside `follow`: the same lookup stated in two more
  places, which drift the same way at the next distinction; (b) one table keyed by syscall in the supervisor that
  compile imports: a row is no syscall (it carries no flags), and `pkg/spec/agent` may not import the supervisor
  (depguard), so the rows' table lives in `pkg/` and the run is held to it by test; (c) replacing `pathQuery`'s
  `nofollow`, `create` and `parent` bits with the enum: every walk, the open deputy's pin included, reads the bits,
  and they hold nothing the enum does not, so `as` and `lookup` leave the walk's code as it is. Tests:
  `TestEveryRowEndIsWalkedAsItsSyscall` (fails for `fs_link` with either the row's table or the handler's lookup
  reverted), `TestLookupBitsRoundTrip`, `TestResolveActionFollowsAsTheKernel` (a link's old name ending in `/.` and
  `/..` after a symlink), `TestLandRefusesAsTheKernel`, `TestRunResolvedAsksTheWalkOfEachPath`,
  `TestCompileLandsWhereTheRunLands` (now with `fs.link`, `fs.attr` and `fs.mkdir` rows),
  `TestCompileTestLandsAsTheKernelGolden` rows 15 to 17 (15 and 16 fail at the previous tip), and the fs.ask subtest
  of `TestADotDotEndIsDecidedWhereItIsNamed` when the pin fails.
- 2026-10-19: `LookupParent` is also the lookup of an end ending
  in `/`. `filename_parentat` strips the slash and the syscall looks the name up in its directory without following it
  (`lookup_one_qstr_excl`): `mkdir("lk/")` is `EEXIST`, an `rmdir`, an `unlink` and a `rename` onto it `ENOTDIR`, and
  Landlock's `rmdir` and `rename` hooks are asked at `lk` in its own directory. The shared resolver (`FSTarget`) took
  the whole walk for every end ending in `/`, a rule of `path_lookupat` ends (an `O_NOFOLLOW` open of `lk/` opens where
  `lk` leads), so compile's prediction followed a dangling `out/dl/` to the target it takes as made later while the
  run's walk failed `ENOENT` and fell back to the name, and both decided `out/lk/` on the link's target: compile and
  the run disagreed on one query, and the run's line read `refused, unmatched` for an `rmdir` the `out/` entry grants
  (and `allow` for one of `ro/lk/` that Landlock refuses at `ro`). Chosen: a name-making end is its directory's walk
  joined with the name, slash or not, in `FSTarget`, which `Land` and every handler ask, so compile and the run agree
  by construction, and the syscall's own `ENOTDIR`, `EEXIST` or `ENOENT` follows. Rejected: (a) stopping only the
  prediction from following the dangling link: the run and compile would agree, on a place the kernel never acts on;
  (b) refusing such an end path-unreliable: a refusal no mechanism makes, where Landlock decides the name and the
  kernel answers the syscall itself. Tests: `TestNameEndEndingInSlashIsTheNameInItsDirectory` (the kernel's answers,
  then `Land` and `FSTarget`), `TestResolveActionFollowsAsTheKernel` (an `fs.mkdir`, `fs.delete`, `fs.rename` and
  `fs.link` end with a slash, and an `fs.write` control that still follows), `TestCompileLandsWhereTheRunLands` (a
  fifth of its filesystem rows end in `/`, half of those on one of the tree's links; 16 such rows land on a symlink,
  12 disagreements at the previous tip), `TestEveryRowEndIsWalkedAsItsSyscall` with each end also spelled with a
  slash, `TestCompileTestLandsAsTheKernelGolden` rows 18 to 21 (all four fail at the previous tip), and the conformance
  cell `fs/rmdir-symlink-spelled-with-slash-into-write-entry` (6 compile disagreements at the previous tip).

*Implementation note, 2026-10-19:* the landed match the notes of this date
name, a `unix:` entry by `NetRule.Resolved`, is against `NetRule.UnixResolved`: the unix ask work gave pathname unix entries
and `net.ask` scopes that place (`agent.ResolveUnixPlace`, which the run's `resolveUnixDeclared` also asks), so one
field holds the place compile and the run both match, and `NetRule.Resolved` is gone. With both merged, a name whose
walk lands at a scope's place is answered as the run answers it, `unix-ask-scope` or the scope's own refusal
(agent-contract R15, limits-check-doctor-cli.md R28); before, compile --test admitted it through the write entry
around the scope (`TestEvaluateUnixLandedAtAnAskScope`). No other decision changes.

*Amended 2026-10-20 (ADR 0029 (4)):* the Landlock floor's rename rule the
2026-10-17 note names as `decide.RenameGains` is `decide.RenameGainedBy` with `decide.ReferRefuses`, which the
bpflsm column and the run ask; `decide.RenameGains`, which only decide's tests called, moved into decide's test
files. `decide.LandlockLinkRefusal` stays production code, classified `test-api` for the recorder's tests. No
column changed.

*Amended 2026-11-02 (implementation note, (3)'s header):* since 2026-10-26 the set of an `auto` contract is
`doctor.AutoTiers`, which reads besides the build whether this process is root and whether bpf is in the active LSM
list (limits-check-doctor-cli.md R28, agent-contract.md R14), so the 2026-09-24 note's "computed from the build alone"
no longer holds. The header kept saying `tier auto: every tier this tego builds`, and a normal user of a tegobpf build
read `tiers landlock (tier auto: every tier this tego builds)`, a landlock-only build. It now names each tier the
build constructs and the set leaves out, with the precondition it lacks: `tiers landlock (tier auto: every tier this
tego builds but cgroup and bpflsm, which need root)` for that user, `... but bpflsm, which needs bpf in the LSM list`
for root on a kernel without it; `--json`'s `from` and `compile --exec`'s tiers line carry the same text. No column
changed. Pinned by `TestCompileTestHeaderNamesWhatAutoLeftOut`, `TestCompileTestHeaderNamesTheBuiltTiersAutoLeftOut`
(under `-tags tegobpf` as a normal user it fails at the previous tip) and doctor's `TestAutoTiers`.
