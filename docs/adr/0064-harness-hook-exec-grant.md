# ADR 0064: The harness hook's exact-argv exec grant

Status: **accepted 2026-10-25** (a technical decision). Implemented 2026-10-25:
the grant (`agent.WithHarnessHook`, `execmatch.ExactPattern`), the launcher's decision (`runtime.AdmitHook`), the drop
reasons, `run_start.harness.hook` and the `exec.harness-hook[<tego binary>]` runtime grant at record minor 20,
compile's harness hook line, and learn's note. The pinned decision at a plane tier is proved on the compiled table
here; no guest run of it is recorded. Amends agent-contract R10a and R27, supervisor R16b, enforce-landlock R5 and
ADR 0062; adds record minor 20.

## Context

ADR 0062 made the launcher the harness provisioning point. A provision names the hook its harness runs on every tool
call, for Claude Code `tego hook claude-code --reason <run's last-refusal.json> --mode json`, and the launcher drops
the whole provision when the run's exec rules do not admit that exact argv: provisioned, the hook would be a refused
exec on every tool call. Under an allow-list contract no rule the user wrote names the tego binary, so every such
provision was dropped (`why: hook-not-granted`), and the agents of the contracts that restrict the most learned of
their refusals only through `TEGO_REASON`.

What the code already does, read before deciding:

- The open deputy's grant (`internal/runtime/enforce/landlock/exec.go` `deputyGrant`, ADR 0041 D2) is the Landlock
  domain's `EXECUTE|READ_FILE` on tego's own inode, so the child stage can exec the deputy after
  `landlock_restrict_self`. No exec rule names it: the agent's own exec of the binary is still the supervisor's to
  decide (supervisor R16b), against the contract's exec rules, and it refuses one no rule matches.
- The supervisor decides a command rule on its copy of argv (ADR 0048 (3)). At tier landlock and on tier cgroup's
  fanotify listener that copy is a copied fact: a sibling thread can rewrite argv between the copy and the kernel's
  (ADR 0048 R5). A decision plane that pins execs holds the exec to the vector decided (ADR 0048 (3) P2).
- An exec.allow pattern's generic reading is a token prefix (ADR 0048, the generic fallback): `tego hook` would admit
  `tego hook anything`.
- `exec.assurance: kernel` refuses before the child starts every run whose tier cannot pin execs, whether or not its
  table holds a command rule (`requireExecAssurance`; ADR 0048 (3): a run with nothing to pin claims the tier's
  ability).

## Decision

**D1. The grant.** When a provision's hook is not admitted by the run's own exec rules under an allow-list contract,
the launcher grants it on its own authority, as it grants the hook-state directory (agent-contract R10a): a copy of
the compiled table (I4) that admits the tego binary with the hook's exact argv and no other vector
(`agent.WithHarnessHook`, called by `runtime.AdmitHook` from `provisionHarness`). Two rules carry it, both named
`exec.harness-hook[<tego binary>]`:

1. An image rule (`ExecRule.Runtime` `harness-hook`) for the binary by its absolute path, with its `PT_INTERP` loader as
   any binary's, so Landlock's `EXECUTE` and the plane's exec row admit the file; none is added when an exec rule of
   the table already names the file.
2. A runtime command rule (`execmatch.ExactPattern`) on the binary's tool, keyed by its name and by its identity like
   every command rule (ADR 0048 (2)): it admits an invocation only when the whole vector equals the hook's, argv[0]
   included, element for element and byte for byte, read to its end, with no glob and no trailing argument, and only
   as the exec's own image (never through a `#!` chain, a loader's program or a dispatcher). The tool is then
   constrained to it, so every other vector of the binary is refused `exec-not-allowed`, unlisted, under the same
   rule. Such a refusal is drift like any other: `tego drift` skips a runtime grant's bucket only for what the grant
   allowed (limits-check-doctor-cli R25, amended 2026-10-25). A contract's own allow entries for the tool keep admitting what they admit beside it, and an unlisted refusal
   then names `exec.args[<tool>]` as before.

   *Corrected 2026-11-12:* an applet derived by removing a dispatcher's argv[0] prefix has multicall provenance,
   including through a supplied identity mapping or a shebang stage. It receives no direct argv[0] and cannot
   satisfy an exact grant. A stage's invoked-as reading keeps shebang provenance too. Earlier code marked the
   stripped applet as argv0 and could satisfy an already supplied exact grant. Matcher regression tests cover the
   direct and staged forms; no live admission route was established. Live validation is owed in a guest.

The grant is the exact full argv, so no question of trailing-argument matching arises, and the reason path is part of
it: `tego hook claude-code --reason <another file>` is refused. `run_start` records it: `runtime_grants` lists
`exec.harness-hook[<tego binary>]`, and `harness.hook` is `{argv, granted: true}`. A hook the contract's own rules
admit (no exec section, a deny-list, or an allow entry naming the binary) is provisioned with `granted: false` and no
grant.

**D2. No grant, no provision.** The launcher never grants a binary the agent could rewrite, nor a grant that would
admit more than the hook's argv; then the whole provision is dropped, the run carries on unprovisioned, `run_start`
says `provisioned: false` with why, and the run and compile warn `harness-hook-refused` naming the rule:

- `harness-hook-writable`: the binary, or its ELF loader, by the spelling the hook names, where it resolves, or any
  other place the mount table shows it (a bind mount of a directory above it), lies at or below a write entry or an
  `fs.ask` scope (declared, or a grant the runtime made). An entry over any directory above the file covers the file,
  so it covers every rename that could put another file at its path. A loader there would also refuse the whole run in
  the Landlock builder (enforce-landlock R5). Landlock's rights are path-based, so every name of the file counts: a
  binary or loader with more than one link is never granted (a hard link's other names cannot be listed, and one under
  a write entry would let the agent rewrite the inode the grant executes), nor one whose mount table the launcher
  cannot read (*amended 2026-10-25*), nor one the table shows no mount holding: a file's bind-mount names
  are the binds of its device whose root lies above its place within the filesystem, and that place is its holding
  mount's root joined with its path below the mount point, so without that mount no bind the table lists can be
  matched to it (a chroot whose root is no mount point skips the mount above it, yet lists the binds beneath; *amended
  2026-10-25*).
  What lies beneath the filesystem holding either is held to the same entries, since the agent could rewrite the file
  through it while the Landlock rule and the `(dev, ino)` identity, the filesystem's own inode's, stay unchanged
  (*amended 2026-10-25*): an overlay's layer directories as its options spell them (`upperdir`,
  `workdir`, each `lowerdir`, `lowerdir+`, `datadir+`), the places the mount table shows a layer or part of one, the
  backing file of each loop device at or beneath its block device (the device itself, a partition's disk, the devices
  a device-mapper or md device is built on, from sysfs), and an image file or tree its source names; each to three
  filesystems deep. A write entry or `fs.ask` scope at or above such a layer, or beneath it, refuses the grant: which
  file of a layer the filesystem shows is the filesystem's to decide (an overlay's redirects and metacopy files lead
  to another path of the layer). A stacking filesystem that names no layer the launcher can place (FUSE, eCryptfs,
  aufs, shiftfs, an overlay naming a relative layer or none), and a block device sysfs does not show, are names the
  launcher cannot see, and are not granted either. A layer spelling no file of the launcher's mount namespace is
  reached by (missing or unsearchable: a container's overlay names the host's paths) is held as spelled, and nothing
  more is learned from it.
  *Residual (disclosed, not enforced):* names that neither the table, the overlay's options nor sysfs give are not
  seen: a layer this namespace reaches only by another spelling than the overlay's options (container storage
  bind-mounted in at another path), a second superblock of one network export (NFS or CIFS mounted twice with
  different options) or a host share's other names (virtiofs, 9p), and the raw device node beneath the filesystem.
  OPERATIONS says to keep the tego binary off a filesystem whose layers, image or device the agent can write.
- `hook-refused`: the binary or its loader lies at or below a `deny_read` entry (the grant's `READ_FILE` would open
  what the entry denies, since tier landlock unions the two, and a loader there refuses the run); or the granted table
  still refuses the hook by the decision compile --test's exec row uses: an `exec.deny` or `exec.ask` entry naming it,
  or the gate scoring it to refused or ask.
- `hook-not-granted`: the hook names another program than the tego binary the launcher runs as (it grants its own
  binary only), or the grant cannot be exact (`agent.ErrHarnessHookGrant`): the binary is no ELF file the launcher
  can resolve and read, it has a set-id bit, its loader leads through `/proc`, or a bare `exec.allow` name or an
  implicit grant (the command, an MCP server, the run command) keeps the binary's name at any arguments, so a grant of
  the file would admit every argv.

**D3. Where the grant holds.** It holds as every command rule holds at the run's tier. At tier landlock the decision
reads the supervisor's copy of argv: the grant makes the table decide execs on copied facts, so `run_start.best_effort`
lists `exec.rules/argv`, and compile prints `harness hook: exact argv; best effort against a racing thread at tier
landlock (ADR 0048 R5)`. At a plane tier the grant is a command rule like any other: the table now decides execs on
copied facts (`ExecFactsDecided`), so Prepare asks for the run's execs to be pinned, and the decision reads the whole
vector (`K` = the vector's length), which the pin then covers. The compiled table and the loop's pin are tested here
(`TestWithHarnessHookGrantsTheExactArgv`, `TestHarnessHookGrantIsPinnedOverTheWholeVector`); no guest run of it is
recorded.

**D4. The residual adds nothing beyond the boundary.** At tier landlock a racing thread can run the tego binary with
another vector (ADR 0048 R5). What that process can do is what the agent can already do: the binary is no set-id file
(D2 refuses one, and the run's `no_new_privs` ignores the bit anyway) and runs under the run's own Landlock domain,
seccomp filter and supervisor, in the run's cgroup. The ledger root is read-denied (agent-contract R6a), so `tego
approve` inside the run cannot open the run's lock, and the ask broker refuses a peer in the governed cgroup
(`Options.Authorize`, `askPeerAuthorize`): the ask stays pending until the person answers it from outside. A nested
`tego run` fails closed (exit 125): the kernel allows one seccomp listener per filter chain, and the run cgroup's
parent is not writable. A deny-list contract, which admits the binary with any argv today, shows this directly
(`TestIntegrationTegoInsideADenyListRun`, which holds each refusal to its cause: approve to the lock file's
permission denied, the nested run to the kernel's EBUSY for a second listener). The acceptance's "refused by the
broker" is met in two layers: R6a refuses `tego approve` first, end to end, and the broker's peer check behind it is
shown on approve's own call (`ask.AnswerFor`) from a process in the run's cgroup against a broker built as the run
builds it (`TestAskBrokerRefusesTegoApproveFromTheRunsCgroup`: unauthorized, the ask still pending; *amended
2026-10-25*).

**Departure from the first design (`harness-hook-unpinned`, not built).** The first design also dropped the provision as
`harness-hook-unpinned` when `exec.assurance: kernel` meets a tier that cannot pin execs, "since a command rule would
refuse the whole run". The code refuses that run anyway: `requireExecAssurance` reads the tier's ability for every
`exec.assurance: kernel` run, command rules or not, so at such a tier the run exits 125 before its child starts with
or without the grant, and dropping the grant could let no run run (`TestExecAssuranceKernelIsRefusedAlikeWithTheGrant`,
`TestIntegrationKernelExecAssuranceRefusesAlikeWithAHook`). The one run the grant itself can refuse is a plane tier's
whose pin request fails (`exec pins off`) under `exec.assurance: kernel`, for a contract that decides no exec fact of
its own: the launcher cannot know that before Prepare, and the run fails closed, as the key asks.

## Rejected options

- **Grant the binary with no argv constraint.** Every vector of tego would run on a non-racing call (`tego run`, `tego
  approve`, `__probe`, any verb a later release adds); the tier landlock residual would become the rule at every tier,
  pinned or not.
- **A separate hook binary.** A second binary to ship, keep under no write entry and grant; it still needs tego's
  reason-file code, and the agent could run it with any argv, so it needs the same exact-argv rule. The problem moves;
  it does not go.
- **Shell-form hooks** (`sh -c "tego hook ..."`). The grant would cover a shell and a command string, which is code a
  racing thread rewrites as easily as an argv element, and every hook would cost a shell's exec.
- **No grant** (the state before this ADR). Allow-list contracts, the ones that restrict the most, lose the hook.
- **A generic exact form in the contract's grammar.** Out of this package's scope (ADR 0048 owns the grammar); the
  runtime pattern is not writable in a contract.
- **Keying the grant by the binary's identity alone.** A grant read only by identity would not constrain an exec of the
  path whose file changed identity under it, and would differ from every other command rule; the name and identity
  keying of ADR 0048 (2) is kept, which also constrains another file of the same name the contract admits (fail
  closed).
- **Holding an overlay layer by `<layer>/<the file's path in the overlay>` only** (2026-10-25). An
  overlay's redirects and metacopy files lead to another path of a layer, so the file a layer feeds is not always at
  that path; a whole layer is held instead, and an entry beneath it counts too.
- **Refusing every binary on a stacking filesystem**. A tego binary in a container image lies on the
  container's overlay root, whose layers name host paths the container does not have; refusing there costs the most
  common container install the hook and buys nothing the layer check does not. Filesystems whose layers cannot be
  named (FUSE and the like) are refused, as are block devices sysfs does not show.

## Implementation notes

- 2026-10-25: `pkg/policy/execmatch` `ExactPattern` (runtime patterns, `Pattern.Runtime`, a
  runtime grant's rule on an unlisted refusal, `Invocation.Argv0`); `pkg/spec/agent` `WithHarnessHook`,
  `HarnessHookGrant`, `ExecRule.Runtime`, `RuleTable.HarnessHook`, `HarnessHookRule`, `HarnessHookNote`,
  `implicitGrants` (shared with compile's command rules); `internal/runtime/harness_grant.go` `AdmitHook`;
  `run_start.harness.hook` and `HarnessWhyHookWritable` at record minor 20 (fixture `harness-hook.jsonl`);
  `internal/cli` compile prints the hook line and the drop warnings; learn proposes no entry for the grant's execs and
  counts them. Tests: `execmatch` `TestExactPattern*`; `agent` `TestWithHarnessHook*`, `TestHarnessHookNote`;
  `runtime` `TestHarnessHookAdmission`, `TestHarnessHookGrantAtEveryTier`, `TestHarnessHookWritableIsNotGranted`,
  `TestHarnessHookUnderDenyReadOrDenyIsRefused`, `TestHarnessHookUnconstrainedIsNotGranted`,
  `TestHarnessHookOfAnotherBinaryIsNotGranted`,
  `TestExecAssuranceKernelIsRefusedAlikeWithTheGrant`, and at tier landlock through the real runner
  `TestIntegrationHarnessHookGrantIsTheExactArgv` (a plain allow-list and `gate.completion: held`, whose deputy grant
  holds the same inode), `TestIntegrationHarnessHookWritableRunsUnprovisioned`,
  `TestIntegrationKernelExecAssuranceRefusesAlikeWithAHook`, `TestIntegrationTegoInsideADenyListRun`; `record`
  `TestRecordMinorCoversTheHarnessHook`, `TestHarnessHookFixture`; `ledger` `TestHarnessHookFixtureFrozen`;
  `viewtest` `TestViewsReadHarnessHookFixture`; `cli` `TestCompilePrintsTheHarness`; `supervisor`
  `TestHarnessHookGrantIsPinnedOverTheWholeVector` (a pinned run's pin of the hook covers the whole vector).
- Inside the run, `tego approve` is stopped first by R6a (the run's lock is read-denied); the broker's peer check is the
  second layer, held by `TestAskCgroupBoundaryAndAdministrativeMembership`. *Amended 2026-10-25:* the
  integration scene asserted only a non-zero exit, so an approve or a nested run that failed for an unrelated reason
  passed too; it now asserts each cause, and `TestAskBrokerRefusesTegoApproveFromTheRunsCgroup` shows the broker's
  layer through the socket approve uses.
- 2026-10-25 (drift): the grant is the first runtime rule that refuses, and
  `drift.Report.Drifted()` skipped every runtime rule's bucket before it looked at refusals, so a run whose agent ran
  `tego run` under an allow-list contract reported no drift, where the same refusal under `unmatched` drifted before
  the grant. A refusal now drifts whatever rule it carries; only allowed traffic under a runtime grant is exempt
  (`TestRuntimeRuleRefusalIsDrift`, and `TestViewsReadHarnessHookFixture` asserts the fixture's refused `tego run`
  drifts). learn already counted every refusal before it read the rule, so no other view changes.
- 2026-10-25 (other names): `hookCovered` compared only the hook's spelling, where it
  resolves and the loader with the entries, and `WithHarnessHook` noticed a second link only to skip identity keying.
  A tego binary hard-linked into a write entry before the run was granted, and the agent could rewrite the inode the
  exact argv runs. D2 now holds every name the launcher can see (`hookNames`: the mount table's bind-mount places of
  the resolved binary and loader, `agent.MountAliases`) and refuses a binary or loader with more than one link, or an
  unreadable mount table, `harness-hook-writable`; `WithHarnessHook` refuses a second link of the binary itself
  (`ErrHarnessHookGrant`) and so always keys the grant by identity. The open deputy's grant (ADR 0041 D2) is the
  domain's, not an exec rule, and was not changed. Tests: `TestHarnessHookOtherNamesAreNotGranted` (a hard link of
  the binary, of the loader, a bind mount under the write entry, an unreadable mount table), `TestMountOf`,
  `TestWithHarnessHookRefusesAnInexactGrant` (a hard-linked binary).
- 2026-10-25 (the revision number): an earlier numbering put this record minor at 19 after
  17 and 18 for user `deny_write` and held reads, in an expected merge order; this build holds neither, so it wrote
  19 over a gap, and a reader rule a later build adds for 17 or 18 ("absent at 17 or later means ...") would misread
  its ledgers. The revision is the next free one of the build that holds it, 17, as the repo's earlier merges already
  renumbered (record.go: revisions 9, 11 and 13); `TestRecordMinorsAreContiguous` fails on a gap or on two constants
  of one number, so whichever package merges after another renumbers to the next free revision and regenerates its
  fixture (`go test ./internal/ledger -run TestHarnessHookFixtureFrozen -update`). spec/record/v1 README states the
  rule.
- 2026-10-25 (a table without the holding mount): `agent.MountAliases` read a mount
  table that shows no mount holding the file as one that shows no other name of it, so a chroot's table, which skips
  the mount above a root that is no mount point yet lists the binds beneath it, let a bind of the binary's directory
  into a write entry be granted. `MountAliases` now also says whether a mount holds the file (`held`), and `hookNames`
  refuses a resolved binary or loader that a readable table does not hold, or that cannot be examined,
  `harness-hook-writable` ("shows no mount holding ..."). The class: `bindExposed` (ADR 0043 D6 (f)) had the same
  premise and now counts such a scope as exposed. The other `lookup` callers (`meta`'s mount facts and warnings,
  `fsTypeOf`'s fix text, `nameScopeWarnings`) only add notes for a path the table places, and were not changed.
  Tests: `TestHarnessHookOtherNamesAreNotGranted` (a table without the holding mount, an empty table; its other
  tables now carry the root mount), `TestMountOf`, `TestBindExposedUnknownPlace`.
- 2026-10-25 (names beneath the filesystem): `MountAliases` skipped every mount of
  another device, so an overlay's layers (another device, and an overlay file reports one link) were never held to
  the entries: a tego binary on an overlay whose upper layer lay under a write entry was granted, and the agent could
  rewrite through the layer what the grant runs. `agent.MountTable.Of` (`FileMount`, formerly `agent.MountOf`) replaces `MountAliases`: a mount's
  places (`Aliases`), the binds of a directory beneath a tree (`Beneath`), an overlay's layers parsed from its super
  options (`Layers`), and a stacking filesystem it cannot map (`Unmapped`), with the device and source. The runtime's
  `hookScan` holds each layer, the backing files of the loop devices beneath the filesystem's block device
  (`blockBacking`, sysfs `/sys/dev/block`: a partition's disk and slaves included) and an image the source names to
  the write and ask entries (`beneathCovered`: at or above, or beneath), three filesystems deep, and refuses a FUSE,
  eCryptfs, aufs or shiftfs mount, an overlay it cannot place, and a block device sysfs does not show, all
  `harness-hook-writable`. D2 discloses what remains. Tests: `TestHarnessHookStackedNamesAreNotGranted` (an upper,
  `lowerdir+` and data-only layer under the write entry, a layer holding it, a bind of a layer and of part of one,
  a relative layer, no lower layer, a FUSE mirror, a loop device's, a loop partition's and a device-mapper device's
  backing file, an unshown block device, an image source; and the grant for layers and a backing file outside every
  entry; it failed in 14 cases with the scan disabled), `TestMountOf` (the earlier notes' alias test, renamed with
  the function, and now also asserting `Beneath`), `TestMountOfStackingLayers`. The same class: the other checks
  this package makes of a name (`hookCovered`'s deny_read side, `WithHarnessHook`'s link check) read the binary's own
  names, which the scan now completes; ADR 0043's `bindExposed` also skips other devices, and an fs entry on an
  overlay is already warned at compile (`meta`: rules on its layers never apply to the merged tree).
- 2026-10-25: the record minor is 20 (`MinorHarnessHook`), since this build already held 17 (run identity, ADR 0073), 18 (held reads, ADR 0069) and 19 (`fs.deny_write`,
  ADR 0071), and a revision is the next free number at merge (`TestRecordMinorsAreContiguous`). The fixture
  `harness-hook.jsonl` is regenerated at 20 with the `launcher_uid` and `fs_reads` every `run_start` at 17 and 18 or
  later carries; `TestRecordMinorsAreContiguous` admits the reserved revisions 30 to 34, declared ahead of
  their writers above `Minor` (ADR 0100), and nothing else above it.
