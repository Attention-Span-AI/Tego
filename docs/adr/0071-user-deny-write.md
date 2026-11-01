# ADR 0071: A contract's own fs.deny_write list refuses writes inside a write grant, race-free where a plane decides and best effort at tier landlock

Status: **accepted 2026-10-25**.
Implemented 2026-10-25 (see Implementation notes). Amends SEMANTICS §1 and §2, agent-contract R5 (the merge table) and
R20, supervisor R15c, CAPABILITIES (a row for the list) and the record (minor 19).

## Context

A contract that lets an agent write a repository (`fs.write: ["./"]`) lets it rewrite the repository's CI
configuration: `.github/workflows/`, `.gitlab-ci.yml`, a `Jenkinsfile`. Those files run with the CI system's secrets
the next time anyone pushes, outside every boundary the run had. The built-in `deny_write` set (R20) answers the same
kind of file for git hooks, harness settings and shell startup files, but it is a fixed list: a contract could take a
target out of it (a write entry at the target's own path), never add one. The `tego/repo-only-writes` preset
needs to add the CI files, and a user without root needs a guard rail for the files of their own
project that must not change.

What the tiers can do is already settled by ADR 0041 D8: a kernel decision plane (tier cgroup with `lsm` or
`fmod_ret`, tier bpflsm) refuses a modification beneath a write entry race-free, keyed on the inode, a hard-link alias
included where the alias's inode has a row of its own (a file entry's does, and decision 6 keys the linked files
beneath a directory entry); at tier landlock and on tier cgroup's fanotify listener only the seccomp supervisor's check of the copied
pathname stands (supervisor R15c), which a racing agent can pass, and held write-opens alone buy nothing there, since
the same race plants the file with a rename.

## Decision

1. **The key.** `fs.deny_write` takes literal files or directories, spelled as every `fs` path is (`~`, relative to
   the run's directory). A glob character (`*`, `?`, `[`) is a schema error with a fix: the tiers key the entry on the
   inode it names, and a file a glob would match later has none. Each entry beneath a write entry compiles to a rule
   of its own in `RuleTable.DenyWrite`, beside the built-in targets, `FSRule{Kind: deny_write, BuiltIn: false}` with
   the declared text (`FSRule.IsDeclaredDenyWrite`), named `fs.deny_write[<entry as declared>]` (a built-in target's
   rule keeps its resolved path in the brackets).
2. **What it refuses.** Every modification at or beneath the entry, the set a built-in target's refuses: a write-open,
   a create, a truncate, an unlink, an rmdir, a rename at either end (and of a directory above the entry), a link, a
   symlink, a mkdir, a mknod, and, where a decision plane decides, a chmod, chown or xattr change (SEMANTICS §1: no
   tier refuses an attribute change elsewhere). Reads are not changed.
3. **Nearest wins.** A write entry strictly beneath an entry reopens its own subtree, as a deny_read nested in a write
   entry does the other way round: `fs.write: ["./", "./deploy/tmp/"]` with `fs.deny_write: ["./deploy/"]` lets the
   agent write `deploy/tmp/` and nothing else of `deploy/`. The reopening write entry is no redundant entry (E10). A
   rename of a directory above the entry still reaches it, since it moves the whole entry. The reopening write entry's
   own name in the entry's directory stays the entry's, as the plane keys it: a rename of
   `deploy/tmp` at either end (away, onto it, an exchange) and a create of the name (a mkdir, a mknod, a symlink, an
   exclusive create, a hard link's new name: `RuleTable.DenyWriteNameTarget`) are refused at every tier, so the agent
   cannot put an object of its own at `deploy/tmp`; what it names stays writable, and removable, under the write entry,
   since the plane decides a write and a removal on the object's own row. Residual at tier landlock and on the
   fanotify listener: an `O_CREAT` open that makes the name anew after the agent removed it is a write of an existing
   file to a pathname check, and is continued (a regular file the write entry grants anyway); a plane refuses it, since
   the new name's walk starts at the entry's directory. A built-in target is never
   reopened: a write entry inside one grants nothing beneath it, as the code has done since R20 shipped (R20's text said
   "nearest wins" there; it is corrected), and only a write entry at the target's own path lifts it.
4. **Placement.** An entry is placed at where it leads and, when its own name is a symlink, at the link's place too:
  a link beneath a write entry can be replaced whatever it leads to, so it is held at its name (the
   rule's path is the link's own place) even when it leads out of every write entry. An entry at a write entry's own
   path is a contradiction, from any file. An entry outside every write entry (and every `fs.ask` scope) at both of
   its places refuses nothing that is not refused already: `redundant-rule` from the top-level
   file, silent from a profile, which cannot know its users' write entries. An entry that does not exist has no inode
   for any tier to hold, and the agent could create it: `path-missing` from the top-level file, an `unenforced` warning
   from a profile (a preset names CI files a repository may not have). An entry each of whose places beneath a write
   entry lies beneath another entry with no write entry between is `redundant-rule` from the top-level file (a link
   whose own name lies outside that entry is not). An entry at a built-in target's place never removes the target:
  both are rules, the entry's just before the target's, so a refusal the entry reaches names it as
   declared, while the target, never reopened and holding its own link spelling, refuses what a write entry inside the
   place reopens of the entry and what the entry's spellings do not reach. An entry that only an `fs.ask` scope covers
   joins `RuleTable.AskDenyWrite`, so no approval opens it.
5. **Across extends** the key is a union (merge class `union`, ADR 0065): every file's entries, the profile's first,
   and no file removes another's. `fs.deny_write: []` contributes nothing and never removes the built-in set; ADR 0041
   D8's rejected option (b), where `[]` removes it, stays rejected, and removing a built-in target stays R20's
   top-level write entry.
6. **Enforcement and the label.** The entries ride every path the built-in targets ride: the plane's inode rows at tier
   cgroup with a plane mode and at tier bpflsm (race-free, a hard link made before the run included: a file entry's
   own inode is keyed, and so is each regular file beneath a directory entry that has another hard link when compile
   runs, `RuleTable.DenyWriteLinked`, since a write through the other name walks from that name's
   directory and would reach only the write entry; the plane keys one fs row per inode, so the search keys one name
   per file and none for a file whose every name lies beneath a deny_write place or whose inode another row the plane
   keys refuses modifying, a file entry's for one, while a file another row grants writing is a `contradiction`; the search adds at most 256 rows to the plane's 4096 (`decide.PlaneRowsMax`, past which tier cgroup
   decides the table on the fanotify listener and tier bpflsm refuses it, as for any table) and reads at most 32768
   directory entries, 16 levels deep, in 2 s, and a search a bound cuts warns at the entry at every tier, and is a
   compile error under `fs.assurance: kernel`, which a file the search did not reach would make untrue, and the
   supervisor's copied-name refusal at tier landlock and on the fanotify listener (best effort, where no other name
   is seen). There the cell is `fs.deny_write` in run_start's `best_effort`, apart from `deny_write/default`, and
   `fs.assurance: kernel` refuses such a run as it does for the built-in set (a compile error at a pinned or held tier
   landlock, exit 125 otherwise). Compile warns once per entry, "best effort at tier landlock", and prints the entry so
   marked. Every user-facing sentence about the list says: **blocked for ordinary commands; not race-free at the
   no-root tier** (`agent.UserDenyWriteLabel`; `tools/rulecheck` holds docs/user to it).

## Rejected

- **A Landlock split of write rights beside the entry** (granting the write entry's rights on each sibling instead of
  on the parent). It refuses creating any new file beside the entry, since a new name has no rule of its own, and a
  file written elsewhere in the grant can still be renamed in, which Landlock's REFER right allows within one grant.
- **Held write-opens alone at tier landlock.** ADR 0041 D8: the supervisor's refusal of the non-open mutations is still
  on copied names, so a raced `rename(tmp, deploy/ci.yml)` plants the file anyway, and every write-open of the
  commonest contract would pay the held cost. The race-free tier-landlock version holds every mutation.
- **Calling the tier-landlock refusal a guarantee.** It is not one: a sibling thread rewriting the pathname between the
  supervisor's check and the kernel's lookup, a symlink swapped in that window, or a hard link made before the run
  reaches the entry. The label, the warning, the printed mark and the `best_effort` cell say so.
- **Reopening built-in targets by a nested write entry too.** It would loosen the built-in set for contracts written
  today, which R20's tests and every tier refuse; the declared list is new, so its semantics can be the nearest-wins
  ones authors expect.
- **Accepting a missing entry silently, or refusing creation in its parent.** The first protects nothing the agent can
  create; the second refuses the write entry itself.

## Implementation notes

- 2026-10-25: `FSSection.DenyWrite`, the schema (`checkDenyWritePath`, agent.schema.json), the merge
  row, `compileDenyWrite` and `warnUserDenyWrite` (pkg/spec/agent/compile_userdenywrite.go), the predicate
  (`RuleTable.DenyWriteTarget` with `DenyWriteReopens`), the best-effort cell `BestEffortUserDenyWrite`, the printed
  mark, and the two indexes that answer the predicate for the supervisor and the plane rows
  (internal/policy/decide/userdenywrite.go). The supervisor names a refusal through `FSRule.RuleName` and needed no code
  of its own (a naming function was expected). Record minor 19 (`MinorUserDenyWrite`, since 17, which
  ADR 0073 and then ADR 0069 took first when the three were merged on 2026-10-25), fixture
  `user-deny-write.jsonl`. Tests: compile_userdenywrite_test.go, userdenywrite_test.go in decide and in the supervisor,
  `TestIntegrationUserDenyWriteAtLandlock`, and in the KVM guest `TestPlaneUserDenyWrite` (tier cgroup per plane mode
  and the fanotify contrast, tier bpflsm where lsm passes). Conformance: the user entries' cells in denywrite.yaml (and
  its held and kernel variants), the hard-link alias in denywrite-alias.yaml.
- 2026-10-25, open item found by the KVM conformance run: under `gate.completion: held` the open deputy's open of a
  hard-link alias meets the plane's EACCES, the agent gets EACCES and nothing is written, but the open's one line keeps
  the floor's verdict, allow under the write entry, with `syscall_ret` -13: the supervisor explains a kernel EACCES by
  the path model alone (heldKernelErrno), and the kernel recorder writes no line for the deputy's open (supervisor
  R7a). The same holds for an alias of a built-in file target made before the run. The alias cell therefore has no
  held variant (denywrite-alias.yaml) until the held path explains such a refusal by the object's identity. Tracked
  as [GAPS](../GAPS.md) C38, owned by the engine, and disclosed in SEMANTICS §3's
  held-completion text.
- 2026-10-25: an entry at a built-in target's place removed the target from
  the set (`userDeclares`), and the entry that replaced it could be reopened by a write entry inside the place, did not
  carry the target's link spelling, and, from a profile at a dangling-symlink target, was itself dropped, so adding an
  entry loosened R20 (out/.claude/projects/x written at tier landlock and in every plane cell). The target now stays
  (`beforeBuiltInAt` puts the entry just before it). `TestUserDenyWriteKeepsBuiltInTarget` holds each of the three
  shapes to the refusals of the contract without the entry, `TestUserDenyWriteBesideBuiltInTarget` the indexes and plane
  rows, and `TestPlaneUserDenyWrite`'s `write-builtin-reopened` the kernel.
- 2026-10-25: an entry was placed by where it leads alone, so `out/ci -> ../ext/ci`
  beside `fs.write: ["./out/"]` was dropped with a redundant-rule message saying it lay outside every write entry, while
  the agent could remove the link and put its own directory there; and an inner entry whose link lay outside the entry
  covering where it leads was dropped as covered. An entry now has two places (`userDenyWrite.places`), is kept where
  either lies beneath a write entry, is covered only where each place that matters is, and is spelled by the link's own
  place. R20's search had the same shape (`enclosingWrite(writes, res)` alone) and holds a built-in target that is a
  link leading out of every write entry at its name too (`probeLandingName`; agent-contract R20).
  `TestDenyWriteHoldsLinkName`, `TestUserDenyWriteLinkLeadingOut` and `TestPlaneUserDenyWrite`'s `unlink-link-entry`
  and `rename-link-entry` hold it.
- 2026-10-25: the index's nearest-wins walk collected the shadowed positions in a
  slice, one allocation per question in a reopened subtree, which is the supervisor's per-notification path; it now
  looks a candidate's shadow up again on the levels below it and allocates nothing
  (`TestUserDenyWriteQueryAllocations`, FSIndex and the Evaluator). The held open's floor and the write gate asked the
  table's scan, which builds the reopen list per entry it reaches; they ask the index (`compiled.denyWriteTarget`).
- 2026-10-25: the predicate counted the reopen spelling itself as reopened,
  so at tier landlock the agent renamed `out/deploy/tmp` away and renamed its own symlink `tmp -> .` into its place,
  while the plane refused the second step (the write entry's row moved with its inode), and compile --test answered
  allow where the plane refused. Now a rename of the reopen spelling reaches the entry (`DenyWriteTarget` with
  ancestors, so the plane row's rename question at that name is refused too) and a made name does
  (`DenyWriteNameTarget`, asked by the supervisor for a mkdir, a symlink, an exclusive create or mknod and a link's new
  name, by Evaluate for a mkdir and a link's new name, and by the plane column, whose walk for a create there starts
  at the directory, `PlaneEvaluator.madeAt`). `TestUserDenyWriteReopenName`, the supervisor's cases in
  `TestUserDenyWriteRefusedBySupervisor`, the conformance cell `rename-reopened-name-away` and `TestPlaneUserDenyWrite`'s
  `rename-reopened-away` and `rename-onto-reopened` hold it.
- 2026-10-25: the plane keyed rows at a directory entry, its chain and file entries
  only, so a write through out/a-alias, hard-linked to out/deploy/a before the run, walked from out/ to the write entry
  and was allowed in every plane cell (`allow source=kernel rule=fs.write[./out/]`, out/deploy/a then read "pwned"),
  while this ADR said the plane refused a hard-link alias. Compile now records the linked files beneath each directory
  entry (`denyWriteLinked`, bounded as decision 6 says, not for a table held at tier landlock) and `CompilePlane` keys
  each at its inode. `TestUserDenyWriteLinkedFiles`, `TestPlaneRowsUserDenyWriteLinked`, the conformance cell
  `write-linked-in-dir-entry` (denywrite-alias.yaml) and `TestPlaneUserDenyWrite`'s `write-linked-in-dir-entry` hold
  it. An alias made during the run is the entry's own refusal (a link out of it is refused); one another process makes
  during the run is outside the run. The class's instance in R20: a built-in directory target (`.git/hooks`, `.vscode`)
  had the same gap and is searched the same way, with no subtree skipped (`TestBuiltInDenyWriteLinkedFiles`,
  `TestPlaneUserDenyWrite`'s `write-linked-in-builtin`).
- 2026-10-25: `TestIntegrationUserDenyWriteReviewAtLandlock` holds these at tier
  landlock through the real binary, unprivileged: the write beneath out/.claude/projects/ refused under the built-in
  target's rule, the link out/ci neither removed nor replaced, out/deploy/tmp neither renamed away nor replaced.
- 2026-10-25, KVM (host kernel 6.17, both boots): `TestPlaneUserDenyWrite` passed at cgroup/lsm,
  cgroup/fmod_ret, cgroup/fanotify and bpflsm/lsm on the lsm=...,bpf boot and at cgroup/fmod_ret and cgroup/fanotify
  on the default boot, with every cell of the review (the aliases refused exactly where a plane decides, and
  continued on the listener, the disclosed residual), and every denywrite conformance cell of `TestConformanceKernel`
  passed on both boots (64 subtests, the new `rename-reopened-name-away` and `write-linked-in-dir-entry` among them).
- 2026-10-25: the linked-file search deduplicated by path, not by file, so two names
  of one file beneath a directory entry (`ln deploy/a deploy/a2`, a pnpm store, `cp -al`), two hooks linked to each
  other beneath `.git/hooks` in a contract with no `fs.deny_write` at all, or a file there that another keyed row
  already names (an `fs.deny_write` file entry, a built-in file target) were each keyed, and the plane, which keys one
  fs row per inode, could not hold the table: in the KVM guest, with `deploy/a2`, tier cgroup ran it on the fanotify
  listener and tier bpflsm refused it with exit 125 (`two fs entries the plane keys are one file under two names`). The search
  (`searchDenyWriteLinked`) now counts each file once by device and inode, and `keyDenyWriteLinked`, a pass after
  every fs entry is in the table, keys one name per file and none for a file whose every name the search met beneath a
  target (each refuses by its path) or whose inode another keyed row refuses modifying (`planeFileRows`, with
  `planeModifyGrant` answering as decide's `compileRow` does); a file another row grants writing is a `contradiction`.
  `TestUserDenyWriteLinkedOneRowPerFile`, `TestPlaneHoldsLinkedFilesOfDenyWrite` (cgroup, `PlaneHoldable` over the
  compiled rows), the conformance cell `write-linked-pair` with the fixture's new links (a second name beneath the
  entry, a name there of the file entry's file, which every plane cell of the fixture then holds) and the new names in
  `TestPlaneUserDenyWrite` hold it.
- 2026-10-25: a search a bound cut warned under `fs.assurance: kernel` too, so the
  run went ahead at a plane tier with a file the search missed writable through another name. Under that setting the
  cut is now a compile error at the entry (`linkSearchCut`); by default it stays a warning
  (`TestUserDenyWriteLinkedSearchCutUnderKernel`). The repository search R20 runs to find its targets still warns where
  a bound cuts it under either setting: it names targets, and the setting is about holding the ones named.
- 2026-10-25: the held-completion open item
  above was tracked, not fixed, and the linked files keyed at their inodes widened it to files beneath directory
  entries. Where a plane decides the run (`Options.PlaneAttrs`), `heldKernelErrno` now also explains the deputy's
  EACCES by the opened object's identity: `planeKeyedAt` maps each regular file the plane keys at its own inode (a
  deny_write target beneath a write entry, a linked file, an fs entry) to the path it keys it at, and the model's
  answer there names the refusal, so the alias's line is refused under `fs.deny_write[...]` with `syscall_ret` -13, as
  the plane's own line is without held completion. `TestHeldOpenKernelErrnoExplainedByIdentity`; denywrite-alias.yaml
  has its held variant back (its `write-hard-link-alias` and `write-linked-in-dir-entry` cells under held completion).
- 2026-10-25, KVM (host kernel 6.17, both boots): `TestPlaneUserDenyWrite` passed at cgroup/lsm,
  cgroup/fmod_ret, cgroup/fanotify and bpflsm/lsm on the lsm=...,bpf boot and at cgroup/fmod_ret and cgroup/fanotify
  on the default boot with the names above in place (`out/deploy/a2`, `out/deploy/c2`, `out/.vscode/launch.json`),
  so run_start named the plane mode and the bpflsm run exited 0, where measured `decision_plane`
  fanotify and exit 125; `TestConformanceKernel` passed on both boots (475 and 285 subtests), denywrite-alias and its
  held and kernel variants at every axis among them.
