# ADR 0059: protect later policy loads by path walks, mount identity and loader checks

Status: **accepted 2026-10-20**; implemented 2026-10-20; record files' link counts checked for every euid since 2026-11-03 (amendment below).
Amends agent-contract.md R10 and R26,
spec/config v0 R20 (identity-config.md R20) and limits-check-doctor-cli.md §3.

## Context

A run's boundary is decided by files tego loads when the run starts: the machine config's layer files, the contract
(given by its path, or by a name the registry resolves, R26), the profiles it extends, and the price table. R10 is the
rule that keeps a run from writing them: a write entry that reaches one is a compile contradiction, because Landlock
cannot deny beneath an allow (SEMANTICS §2). If a run could write one, the next run would load what the agent wrote:
a wider contract, a profile that grants more, prices of $0, a registry or ledger root of its choosing.

Three fixes to the registry (R26) each left another way a later run's policy file could be
written by a run whose compile R10 had accepted, and each added one more name R10 compared:

| What R10 did not compare |
|---|
| the working directory's `.tego/agents/<name>.yaml`, which a user-registry contract with `fs.write: ["./"]` could plant and the next `tego run <name>` loaded first |
| the user registry's `agents/`, which nothing protected once the default moved out of `~/.tego` |
| the directory holding a symlink on the way to a protected directory (`~/.config/tego` a link into a dotfiles tree) |
| where a registry entry's own link leads (`agents/r.yaml -> ../versions/r.yaml`, inside the registry, outside `agents/`) |
| the directory of a link in the middle of the contract path's own chain (`agent.yaml -> l1/x.yaml -> l2/real.yaml`, `fs.write: [l1]`) |
| a hard link's other name (a registry entry linked into a project directory another contract writes) |

Probing the model behind them found two more of the same kind: `fs.write: ["./agent.yaml"]`, an entry at the contract
file itself, compiled (the targets were the contract's directory and the directory its path led to, compared by
ancestry, so a file inside was never one), and so did an entry over a layer of the machine config named by
`$TEGO_CONFIG` or reached through a link from `~/.tego/config.yaml`.

**The cause they share.** R10 protected *names* (paths, compared by ancestry), while the loaders accepted the file at
the end of *any* walk: through links out of the protected directory, through links in the middle of a chain, and
under any number of hard links, which no comparison of paths can see. The set of names a file can be reached by is
open; each round enumerated one more kind. The list of targets could not be completed from R10's side alone.

## Decision

The intended invariant is that a run cannot write a later policy load. R10 checks the path walk; loaders constrain
directory escapes and hard links. Mount comparisons have exactly the [compile-time mount boundary](#compile-time-mount-boundary)
defined in the second amendment below.

1. **What R10 protects is a place tego reads, by the whole walk that reaches it** (*amended 2026-10-20*). A target is either a file tego reads (the contract file, the price table, each machine config layer
   file, the chain anchor) or a directory tego reads files from or writes into (the user registry's `agents/` and
   `skills/`, the profiles directory, the ledger root's run directories, the runtime parent, the kernel and host
   state). Each is **the kernel's walk of its declared path**, not a path: one name at a time from the root, never
   cleaned, a symlink followed to where its text points whether that is there yet or not, a `..` taken from where the
   walk stands, a name not there yet kept as the directory a run could make, as `realpath -m` walks
   (`agent.walkTarget`, which reads each name with `ReadPlaceLink` and needs no `/proc`). A write entry is a
   contradiction when it is at or over **where the walk lands**, or at or over **any directory the walk looks a name
   up in**, its last name's included, whatever that name is now: a symlink the walk follows, a real directory a later
   `..` leaves (`<w>/sub/x/../../reg` with an entry over `<w>/sub`), a name not there yet, or a name of a link's own
   text. A write there lets the agent make that name a symlink, a directory or a file of its own, and so choose where
   the next walk lands. With no `..` every such directory is at or above the landing or a link the walk follows, so
   the rule refuses nothing that ancestry and the links did not; with one, it refuses exactly the entries that can
   redirect the walk. It is complete for the walk: where a walk lands depends only on the names in the
   directories it reads, on the text of the links it follows (a symlink's text cannot change in place, only by
   replacing its name, a write to the directory that holds it) and on where each `..` goes, the parent of the
   directory the walk stands in, which only a rename in a directory the walk read that directory's name in can change;
   a mount is the residual below. A target no walk places (a loop of links, a directory compile cannot search, more
   than 1024 names) refuses every write entry rather than be compared by its spelling. For tego's own directories,
   an entry strictly inside the landing is one too (unchanged). The earlier forms of this decision, each a case of
   it, compared the landing and the directories holding a symlink the walk followed (`linksOnTheWay`), and placed the
   landing by a `/proc/self/fd` probe with fallbacks (`placeTarget`). New here:
   - The contract is a **file** target, `the contract file`, in place of its directory and the directory its path
     led to: an entry at the file itself is now compared, and the walk of the whole contract path covers every link
     of its chain;
   - each **machine config layer** a Load consults, whether a file is there yet or not (`config.Machine.Layers`, in
     order: `/etc/tego/config.yaml`, `~/.tego/config.yaml`, `$TEGO_CONFIG`), is a file target, and an
     `OwnReadable` path for the alternate guard (ADR 0057 D2): no held write's alternate reaches one. A place with no
     file yet counts, since a run that created one there would decide the next run's machine config as surely. A
     layer is named by its absolute path as written, so its walk reads the links on the way as any other target's; a
  layer path that is not absolute (a relative `$TEGO_CONFIG`) is refused unread as an invalid layer
     (*amended 2026-10-20*): it names another file in every working directory, and R10 compares a run's
     entries with the one its own Load read, so a run could plant the layer of runs started elsewhere. An absolute
     layer path whose walk reaches procfs (`/proc/self/cwd/machine.yaml`, a link to it, `/dev/fd/../cwd/...`) is
     refused the same way, and so is a path setting written that way (*amended 2026-10-24*): the kernel
     resolves it against the process that opens it, so it names another file in every working directory as well.
   - **a target is placed as the loader's open walked it, never as `filepath.Clean` spells it** (*amended
     2026-10-20*). A layer, the contract path and the registry's `agents/` and `skills/` are kept as the
     loader opened them (made absolute by joining, never cleaned), and resolved and walked for links from that
     spelling: cleaning removes a `..` with the name before it, where the kernel's walk takes `..` from where a link
     before it led, so `<dir>/lnk/../machine.yaml` (read beside `lnk`'s target) was protected as `<dir>/machine.yaml`,
     a file that does not exist. A path the run records or derives a directory from (`RuleTable.ContractPath`, a
     registry entry's path, a profile's) is `agent.WalkedPath`'s spelling of it: `filepath.Clean`'s when no name is
     `..`, else the directory up to the last `..` placed by the kernel's walk. A target whose directory is not made
     yet either is placed where that walk lands once the run makes it, as `realpath -m` places it (`placePath`, whose
     last fallback is `ResolveUnixPlace`; *amended 2026-10-20*), and one no walk places refuses every write
     entry rather than be compared by its spelling. A target that is a symlink leading nowhere yet, or lies below a
     directory that is one, is placed where the link leads, since its loader's open follows it (*amended
     2026-10-20*; without `/proc`).
2. **A file read from one of tego's directories never leads out of it.** A registry entry is read through `agents/`
   itself as an `os.Root` (the project's `.tego/agents/` and the user registry's `<registry>/agents/`), so a link or
   `..` that leaves `agents/` is `registry-entry`; a profile already was read through the profiles directory
   (E7). Links that stay inside are followed: everything inside is a target.
3. **A policy file has one name.** A layer, the price table (`config.ReadTrusted`), a profile, a registry entry
   (`config.CheckTrusted`) and a contract given by its path (`config.CheckOneName`, in `agent.Load`) whose
   `st_nlink` is above 1 is refused, `config-untrusted`, naming its count and the fix (remove the other link, or
   replace the file with a copy). Spared: a file no run of the invoking user could write by any name — owned
   by someone else, not group- or other-writable, and the invoking user not root (a root-owned store that
   deduplicates by hard links, as Nix's does).
4. **The count holds while the run runs.** A run cannot give a protected file a second name: `link(2)` reparents
   a file, and Landlock grants `LANDLOCK_ACCESS_FS_REFER` only where a write entry is (and `MAKE_REG` in the
   destination), so a link out of a directory no write entry reaches is refused at every enforcing tier, all of which
   install the Landlock floor. `TestIntegrationLandlock`'s `link_in` cell pins it on the running kernel (and
   `link_inside`, within one write entry, that the refusal is Landlock's). An adoption with a boundary (`tego adopt
   --boundary`, ADR 0055) has no Landlock floor, since none can be added to a running process: the decision plane's
   `path_link` hook holds it instead, refusing a new name in a directory no write row covers
   (`write-outside-contract`) and a name that would make a file less strict (`refer`). The observe modes install no
   floor and refuse nothing (Residuals).
5. **The project registry stays protected from its own run only**, as a contract given by its path is: the
   working directory is the user's, and any run whose write entry covers it can change a file there. What keeps that
   from replacing a contract the user did not choose is R26's refusal of a name both registries hold (F1): a planted
   project entry can add a name the user registry does not hold, or block one it does, never stand in for it.

Together, (1) to (3) constrain the declared path walk and hard-link names, and (4) prevents the run creating a new
hard link from an ungranted source. Mount comparisons follow the [compile-time mount boundary](#compile-time-mount-boundary).

## Rejected options

- **Compare a target as a place, plus the directories of the symlinks on the way** (this decision's form until
  2026-10-20): a name the walk reads that is no symlink yet (a directory a later `..` leaves, a name not
  there yet) was compared with nothing, and the agent could make it one; the walk itself, every directory it
  reads a name in, is the closed set (decision (1)).
- **Keep adding names as they turn up** (what the earlier fixes did): never complete, and a hard link has no path to add.
- **At each compile, walk every registry entry and profile and protect where each leads:** an entry added after a
  long run's compile is not seen by it, every compile pays for every entry, and a hard link is still invisible.
- **Refuse every symlink on the way to a policy file** (`RESOLVE_NO_SYMLINKS`): breaks the dotfiles and stow layouts
  (`~/.config/tego` a link) that the walk of (1) handles soundly, and the profiles directory's documented relative
  links (E7).
- **Pin each entry's hash in a lock file or index:** The lock file is one more policy file to protect the same way,
  every intended edit becomes two steps, and `contract_hash` already records what ran.
- **Refuse every hard-linked policy file, no exemption:** refuses root-owned deduplicated stores that no run of the
  user can write by any name; the exemption is exactly the property R10 needs.
- **Check the link count in R10 at compile instead of at load:** a registry entry or a profile is loaded by a later
  run whose compile is not the writer's, and the writer's compile cannot enumerate them (the second option). The load
  is the one place every policy file passes.
- **Make the working directory's `.tego/` and `agent.yaml` R10 targets of every contract** (an early alternative,
  already rejected in R26): the common personal agent (`fs.write: ["./"]`) would stop compiling in every project.

## Residuals (disclosed)

- **Record files are protected by name only.** The chain anchor and the run directories record past runs rather than
  decide later ones' boundaries; R10 keeps every write entry off their names (as above), and tego creates them with
  one name, which a run cannot add to (4). A second name a person makes (`cp -al ~/.tego backup/`, a hard-linking
  backup of the ledger root) is not checked: a run whose write entry reaches the backup could rewrite those records.
  Checking the anchor's and the run files' link counts belongs to the ledger (`internal/ledger`) and is not built.
  *Closed in part 2026-11-03 (SEC07, amendment below):* the writer's and the anchor's opens (`openFileAt`:
  `events.jsonl`, `lock`, `chain.log`, the publication lock) now refuse a file with a second link for every euid.
  Still by name only: the read side (`Reader`'s `openRegular` of `events.jsonl`, blob reads), files made fresh with
  `O_EXCL` (the activity sidecar, the live index entry, blobs) once made, and gc's removal lock.
- **A bind mount is a name a link count does not show.** The 2026-11-11 amendments compare aliases within the
  [compile-time mount boundary](#compile-time-mount-boundary). A run cannot make
  one, since a Landlock domain refuses `mount(2)` and every other change of the filesystem topology (the kernel's
  Landlock documentation), and `TestIntegrationLandlock`'s `bwrap` cell shows a mount namespace refused before it mounts.
- **Another agent's contract in a directory a run may write.** A contract given by its path, or a project entry, is
  protected from its own run and from no other (5): a personal agent with `fs.write: ["./"]` run in a project can
  rewrite that project's `agent.yaml`, as it can any file there that the user later runs (a git hook, a Makefile).
  Tego keeps its own places out of every run's reach and each contract out of its own run's; it does not make a
  project read-only to the agents the user lets write it. Protecting every working directory's contracts from every
  run is R26's rejected option (above). The name such a run could add is refused where the user registry holds it.
- **A recording is not a cage.** `tego watch` with no contract (observe mode, OPERATIONS), `tego run --observe`
  with a contract given by its name or its path ("record only: no enforcement"), and `tego adopt` with no
  `--boundary` refuse nothing, so the recorded process can write any of these files, the user registry's
  `agents/`, a layer of the machine config and the contract it was given included, though that contract compiled
  cleanly under R10: R10 decides what a run's write entries may cover, and an observe run has none in force. This
  decision is about runs a contract confines.
- **A layer is protected from the runs that load it.** R10 compares a run's write entries with the layers its own
  Load consulted. `$TEGO_CONFIG` is per process: a run started without it (or with another file) whose write entry
  reaches the file a later run's `$TEGO_CONFIG` names can write that file, and so decide the machine config of every
  run started with the variable set. The same holds for another user's `~/.tego/config.yaml` a run's uid can write.
  Tego cannot know which files a later process environment will name; keep a `$TEGO_CONFIG` file outside every
  directory a contract writes. A relative `$TEGO_CONFIG`, which would name a file in every working directory, is
  refused (1).
- **A process outside tego** (an ungoverned agent, the user) can still write any of these files; R10 is about
  governed runs. Root can always see and change them.

## Consequence

- `tego compile`/`run` refuse more: an entry at the contract file, over a link of its chain, or over a machine config
  layer (`contradiction`); a registry entry whose link leaves `agents/` (`registry-entry`); and a layer, price table,
  profile, registry entry or contract with a second name (`config-untrusted`; the price table's turns into the
  no-price-table warning, as any untrusted table does). The fix names the cure each time.
- R26's "one file both registries reach" keeps its symlink forms (`registry:` set to the project's `.tego`, a link
  to it, `agent.yaml` a link to its `.tego/agents` entry); its hard-link forms are now refused by (3).
- No ledger, record or wire format changes.

## Implementation notes

- 2026-10-24: `TEGO_CONFIG=/proc/self/cwd/machine.yaml` is absolute, so the earlier fix
  refusal let it through, yet it names `<cwd>/machine.yaml` in every directory: a run in project A with `fs.write`
  over project B wrote `B/machine.yaml`, and `tego run x` started in B printed what the planted `registry:` chose.
  `parser.path` likewise took `registry: /proc/self/cwd/reg`. **Now** `config.LoadSources` refuses a layer whose
  kernel walk reaches procfs (`config-invalid`, unread), and `parser.path` refuses such a path setting at its line.
  Both use the walk compile used for exec entries (agent-contract.md R8a: `Lstat`/`Readlink` a name at a time, a
  `/proc` prefix or a directory on a procfs mount), moved from `pkg/spec/agent` to `config.ThroughProc` because
  config is a leaf of `pkg/spec` (identity-config I1) and compile, the Landlock loader check and `tego learn` now
  call it there (`TestLoadSourcesRefusesALayerThroughProcfs`, `TestPathSettingsValidated`, failing before;
  `TestThroughProc` moved with the walk). A passwd home that reaches procfs refuses the user layer under it.
  Rejected: refusing only the literal `/proc/` prefix (a link to `/proc/self/cwd` or `/dev/fd/../cwd` reaches the
  same place); disclosing the spelling (the person who sets it once hands every run the machine config of every
  other directory, as an earlier rejected option); checking the opened descriptor instead (its `/proc/self/fd` link
  names the file reached, never the spelling that reached it). A component swapped between the check and the open
  is R10's: the walk is a layer target, so no run of that Load writes a directory on it.
- 2026-10-20: a relative `$TEGO_CONFIG` was made absolute against the loading command's
  working directory, so `TEGO_CONFIG=machine.yaml` named `<cwd>/machine.yaml` in every directory, and R10
  compared a run's entries with its own directory's file only: a run in project A with `fs.write` over project B
  wrote `B/machine.yaml` (mode 600, so trusted) with a `registry:` of its own, and `tego run x` started in B ran the
  contract it planted, recording a `contract_source` in that registry. **Now** `config.LoadSources` refuses a layer
  path that is not absolute before opening it (`config-invalid`; `run` exits 125, `compile` and `doctor` warn and
  skip the layer), as `parser.path` refuses a relative path setting, and `absAsWalked` is gone
  (`TestLoadSourcesRefusesARelativeLayer`, failing before; `TestALayerIsWalkedForTheLinksOnTheWay` keeps the
  link-on-the-way case with an absolute spelling). Rejected: disclosing a relative layer as per-directory (a person
  who sets `TEGO_CONFIG=machine.yaml` once would hand every run the machine config of every other directory, and
  nothing a run could check names those files); protecting every directory's file of that name (unbounded, as R26's
  rejected option). The residual for an absolute `$TEGO_CONFIG` a run without it can write is added above.
- 2026-10-20: a layer named by a relative `$TEGO_CONFIG` was recorded as given, and
  `linksOnTheWay` walks only an absolute path, so `TEGO_CONFIG=cfglink/machine.yaml` with an entry over the working
  directory compiled and the run could repoint `cfglink` to a machine config it wrote; the same link spelled
  absolutely was refused. `config.LoadSources` now records each layer by its absolute path
  (`TestLoadSourcesRefusesARelativeLayer`, `TestALayerIsWalkedForTheLinksOnTheWay`). Every other
  R10 target was already absolute: the ledger root, the price table, the profiles and the registry are absolute or
  `~/` in the config's grammar (expanded at Load), the contract path is made absolute at compile, and the runtime
  parents and the chain anchor are taken only absolute.
- 2026-10-20: an earlier fix recorded a layer by `filepath.Abs`, which
  cleans, and the contract path (`k.abs`) and the registry's `agents/` and `skills/` (`filepath.Join`) were cleaned
  the same way, while their loaders open the path as given. With a `..` after a link (`TEGO_CONFIG=mlink/../machine.yaml`,
  `tego run clink/../agent.yaml`, `registry: <dir>/rlink/../reg`) R10 protected a file or directory nobody reads
  and an entry over the one read compiled: the run appended to the machine config, rewrote its own contract, or could
  plant a registry entry; `contract_source.path` and a registry entry's path named files that do not exist, and the
  user registry's entry was looked for at the cleaned place, so a project entry of its name replaced it. Now each is
  kept as opened (`config.absAsWalked`, `compiler.asWalked`, `compiler.registryDir`), `resolvePath` takes a missing
  path's directory as written (`splitAsWalked`, not `filepath.Dir`), `OwnReadable` and `OwnState` take both
  spellings from the walk, and recorded paths are `agent.WalkedPath`'s (the registry places its `Dir` and `User` so
  once, `registry-entry` when it cannot). Tests: `TestALayerWithDotDotAfterALinkIsTheFileTheLoadRead`,
  `TestAContractPathWithDotDotAfterALinkIsTheFileLoadRead`,
  `TestARegistryWithDotDotAfterALinkIsTheDirectoryItsEntriesAreReadFrom`, `TestWalkedPathSpellsWhereTheKernelsWalkLands`,
  `TestAUserRegistryWithDotDotAfterALinkIsTheDirectoryTheKernelReaches`, `TestAContractPathWithDotDotAfterALinkIsTheFileRead`,
  `TestDirProfilesNamesTheFileReadThroughDotDotAfterALink`, and `TestLoadSourcesRefusesARelativeLayer`
  now expects the uncleaned spelling. Rejected: tracking each loaded file by device and inode and deriving R10's
  targets from that identity (R10 must also protect places with no file yet and every link on the declared walk,
  which an identity does not name); recording the open descriptor's path (`/proc/self/fd`), which also resolves a
  final link and so moved the contract's directory, and the `.env` scan, to the link's target for every linked
  `agent.yaml`. Unchanged: the ledger root, which the ledger's own walk (`ledger.openDir`) and `identity.RunDir`
  take cleaned, so R10's cleaned spelling is the one the run writes.
- 2026-10-20: an earlier fix reached `ResolveUnixPlace` only when nothing was at the
  target and nothing at its directory, but `resolveProbe` answers a symlink that leads nowhere yet (or loops) as the
  link itself (opened `O_NOFOLLOW`). So a target that is such a link (`registry:`, `prices:`, `profiles:`, the chain
  anchor or a machine config layer linked to a place not made yet) was placed at the link's spelling, and a registry's
  `agents/` below such a link was placed beside it. A write entry over the link's missing target compiled, and the run
  made the registry entry or the price table a later run loaded through the link (reproduced: `tego run x` then ran
  the contract the agent wrote, and an unrelated run loaded the planted `prices.yaml`). Now `placePath` never takes
  the link-as-itself answer for a directory (every walk goes through a directory to where it leads), and R10's
  targets, `OwnReadable` and `OwnState` are placed by `placeTarget`, which does not take it for the last name either:
  both fall back to `ResolveUnixPlace`, which follows a link leading nowhere as `realpath -m` does, and leaves a loop
  unplaced, which refuses every write entry. `OwnState` also holds the chain anchor itself, not only its directory, so
  a link leading out of the directory is held too. `compiler.resolve` (exec paths, write entries, deny entries) keeps
  a final link leading nowhere as itself: what an exec or a rule on such a name means is unchanged, and only the
  places a loader opens follow it. Tests: `TestATargetThatIsADanglingLinkIsPlacedWhereTheLinkLeads` (each kind, a
  relative link, and a final loop) and `TestPlacePathFollowsADirectoryLinkLeadingNowhere`, failing before the change.
  Rejected: refusing a target that is a link leading nowhere (a dotfiles link to a registry or price table not made
  yet is ordinary, and R10 decides that case by place); changing `compiler.resolve` for every path (a final dangling
  link in an exec or rule entry is a different question, outside R10's).
- 2026-10-20: an earlier fix kept the registry's `agents/` and `skills/` uncleaned, and
  `resolvePath` placed a path only when it, or its directory, existed, else kept it as given: with the registry
  directory not made yet, `registry: <W>/./reg`, `<W>//reg` and `<W>/x/../reg` (cleaned before an earlier fix, so this was
  a regression), `<W>/lnk/../reg` (its own case) and `<W>/lnk/reg` (a default `~/.config/tego` with `~/.config`
  a link into a dotfiles tree, open before these fixes) were compared by their raw spelling, so `fs.write` over where the run
  then made `reg/agents/` compiled, the run planted `agents/x.yaml`, and the next `tego run x` ran it. Now
  `placePath` falls back to `ResolveUnixPlace` (the walk the supervisor places a unix socket by: one read a name,
  links followed, `..` taken where the walk stands), so every R10 target, `OwnReadable` and `OwnState` place such a
  path where the kernel's walk lands once it is made; the price table, the profiles and the chain anchor below a
  missing directory had the same gap, and so did a price table or profiles directory named relative (a machine
  config no Load expanded, as `config.Builtin()` gives `~/.tego/prices.yaml` to `Compile`'s callers), which their
  loaders open against the working directory: R10 and `OwnState` now take them against it, as the registry's
  directories are (`compiler.asWalked`). A target `ResolveUnixPlace` cannot place (a loop of links, a directory on the
  way this process cannot search, too many names) is reported as not placed (`writeTarget.placed`), and a contract
  with any write entry is refused (`contradiction`) instead of comparing its spelling. Tests:
  `TestARegistryNotMadeYetIsPlacedWhereItsWalkWillLand`, `TestTargetsBelowAMissingDirectoryArePlacedWhereTheirWalkWillLand`,
  `TestARelativePriceTableAndProfilesArePlacedAgainstTheCwd`, `TestAnR10TargetNoWalkPlacesRefusesEveryWriteEntry`, each
  failing before the change. Rejected: cleaning the
  spelling again (`filepath.Clean` reopens that fault); refusing a registry that is not made yet (the default registry
  usually is not, and a run that makes it is exactly the case R10 decides); refusing only when the write entries
  could contain the target (an unplaced target's place is unknown, so no entry can be shown not to).
- 2026-10-20: the observe residual names `tego run --observe` and `tego adopt` with no
  boundary beside `tego watch`, and (4) says which runs the Landlock floor holds and that an adoption's is the
  plane's `path_link` hook.
- 2026-10-20 (a design pass).
  **The cause these fixes share.** Each fix gave R10 a better *place* for a target (no `filepath.Clean`,
  then `realpath -m` below a missing directory, then a dangling link followed) and kept one list of other names, the
  directories of the symlinks the walk followed, while what a later run loads is decided by the *walk* of the
  declared path, which reads a name in every directory it passes. So each round found a name the walk reads that was
  neither the landing nor a link: the last was a real directory a later `..` leaves (`registry:
  <W>/w/sub/missing/../../reg`, `prices: <w>/sub/deeper/../../pt/prices.yaml`): an entry over `<w>/sub` compiled, the
  run made `missing` (or `deeper`) a link elsewhere, and the next `tego run x` ran the contract the agent wrote there
  (reproduced end to end at tier landlock). And two placements of one target could disagree: the probe answered a
  dangling link as itself where `ResolveUnixPlace` followed it, and without `/proc` the probe's
  `filepath.EvalSymlinks` fallback did the same. **Now** decision (1) is the walk: `agent.walkTarget` is the one
  placement of every R10 target and of `OwnState`'s and `OwnReadable`'s resolved spellings, and R10 refuses an entry
  at or over the landing or over any directory the walk reads a name in (`writeTarget.nameHeldBy`; a link is named as
  before, any other name as "a name on the way to"). `placeTarget` and `linksOnTheWay` are gone; `placePath` keeps
  answering the rules' own paths (a write, deny or exec entry, where a final dangling link is the name a rule pins).
  Tests, each failing before: `TestAWriteOverADirectoryTheWalkReadsANameInIsRefused` (the registry with a missing or a
  real name a `..` leaves and through a link whose text has one, the price table, the profiles, a machine config layer,
  the chain anchor and the contract path; an entry below the name, or beside, still compiles),
  `TestATargetIsWalkedAlikeWithoutProc`, `TestWalkTargetReadsEveryNameOnTheWay`. Rejected: recording only the
  directories of names a later `..` leaves (right, but a second special case beside the links,
  where one rule covers both and any kind of name a third would need); refusing a target spelled with `..` after a
  name (refuses ordinary spellings, and leaves a `..` in a link's own text and in a contract path given on the
  command line); keeping the `/proc` probe for targets that exist and the walk for the rest (two placements of one
  target, an earlier disagreement); deriving targets from the device and inode the Load read (rejected
  earlier: an identity names neither a place with no file yet nor the walk the next Load takes). R20's
  candidates are not R10 targets (a git hook is the agent's to write unless the set holds it), but they met the same
  answer: a candidate that is a symlink leading nowhere yet (`.git/hooks -> ../hk`, `hk` not made) was held as the
  link with a finding that said it held the hooks, while git follows the link to whatever the run makes at `hk`.
  Now the link stays in the set (it keeps the name from being replaced by a hooks directory where the link's
  target is outside every entry), and where the place it leads to lies beneath a write entry, `compile` warns
  `unenforced`, naming that place and the fix (make it before the run, or remove the link)
  (`TestDenyWriteCandidateLeadingNowhereIsDisclosed`). Rejected there: putting the missing place in the set (R20 keys
  every rule on an inode, which a place with nothing there has not, so it would be held by the supervisor's path check
  and by no plane, one rule with two meanings); refusing the contract (the same risk as a `hooks` not there at all,
  R20's residual, which is not refused either).

*Amended 2026-11-03 (SEC07): ledger and anchor descriptors require one link for every euid.*
`ledger.openFileAt` now requires `S_IFREG` and `st_nlink == 1` on the descriptor it actually opened, including for
ordinary-user launchers. The earlier root-only condition left a writable backup alias attached to `events.jsonl`,
`lock` or `chain.log`; a governed write entry reaching the alias could modify those bytes. The common check is used
by ledger open/resume and the anchor probe/append, so an aliased anchor refuses the run before the agent starts.
`TestLedgerRefusesHardLinkedFiles` failed on all three files as an ordinary user before the fix. The historical
record-file residual above is closed at these opens; this does not prevent the owning user or another ungoverned
process from modifying an already-open file or creating a new alias later, and bind mounts remain the disclosed
administrator-created alias. Not covered by this check (the Residuals entry above): the read side (`Reader` opens
`events.jsonl` with a regular-file check only, and blob reads), and gc's removal lock (`lockForRemoval`), which takes
an flock and writes nothing. Verified 2026-11-03: `TestLedgerRefusesHardLinkedFiles` fails on all three rows on a
copy of master (`accepted a ledger with a writable hard-link alias`, `accepted an anchor ...`) and passes on the
branch, as an ordinary user; as root it passes on both (root was already held to one link), in the KVM guest of
ADR 0069's 2026-11-03 verification.

## Amendment 2026-11-11: tego's own binaries by more of their names

*Status: accepted 2026-11-11; built (compile).* Narrows GAPS C45; what it does not close stays there as a limit.

**Context.** Since 2026-11-01 R10 keeps every write entry off tego's own binaries (agent-contract R10, `WithOwnBinaries`):
the running tego, the `tego-control` beside it, and the first `tego` and `tego-control` on the launcher's PATH, each
with the `tego-control` beside the file its link leads to. They are what a later run, or `sudo "$(command -v tego)"`,
runs outside any contract, so they belong to this record: no run writes what a later run loads. Read in the code on
2026-11-11, R10 compared names only, and four kinds of name were outside it:

- a tego this compile neither runs from nor finds on PATH: a systemd unit's `ExecStart` on another path, a second
  install (the installer's `~/.local/bin` beside a package's `/usr/local/bin`). The dashboard's rule checks name no
  running file at all (tego-control runs from a sealed copy) and search the service's PATH;
- a bind mount that shows the binary, or a directory above it, at another place;
- the layer directories of an overlay holding the binary, whose files the overlay shows;
- a second hard link, which no table lists.

What each tier enforces about a write to the binary: a write entry is a grant, and Landlock unions grants over a whole
subtree; it cannot subtract a file from one (SEMANTICS §2). So a name of the binary under a write entry is writable at
tier landlock, and the root tiers start from the same Landlock ruleset. The decision plane keys rows by inode
(ADR 0025) and could refuse a write to the binary's inode under any name, but only for an inode a row names; the
supervisor's best-effort checks see copied pathnames, not other names. A run cannot make a new name itself: Landlock
refuses `link(2)` from a directory with no `REFER` grant into a write entry and every `mount(2)` (Residuals above), so
the names that matter are the ones that exist when compile runs.

**Decision.**

1. **Known install places are targets.** Beside the running file and PATH's, compile looks in the installer's default
   prefix under the compile's home (`~/.local/bin`, `scripts/install.sh`), `/usr/local/bin`, `/usr/bin` and
   `/opt/tego/bin` (`defaultInstallDirs`), and holds every `tego` and `tego-control` there, with the `tego-control`
   beside each `tego`, as R10 holds PATH's. A unit or a second shell runs one of these far more often than any other
   place; the dashboard's checks get them too, though they name no running file.
2. **Other places established within the mount boundary are targets.** The
   [compile-time mount boundary](#compile-time-mount-boundary) governs alias identification and uncertainty.
   Each identified alias is walked as R10 walks a target; review round 1 extended this to every R10 target, the ledger
   root, the anchor and the policy files included (`aliasTargets`). Binary stacking layers are followed as a closure
   (`layerClosure`, review round 1): each named layer directory, its identified aliases and exposed subtrees within
   the mount boundary, and the layers of a stacking filesystem holding a layer, at most 64
   places and 4 filesystems deep; an entry may be neither at, over nor inside any of them. A layer no path of this
   mount namespace reaches (ENOENT or ENOTDIR: a container's, named in its host's terms) is a stated limit, not a
   reason to refuse a grant (review round 4, below). Mapping a host layer spelling through a mount root supplies a
   conservative candidate, whose identity and visibility must satisfy the mount boundary before it can be discarded.
   Ownership of the merged paths gives no exemption and no assurance about hidden
   backing directories. Relative layers and unnamed backing trees have the stated limit below. A present place that
   cannot be examined, a place the table shows no mount holding, or a closure past its bounds still refuses every
   write grant.
3. **Names compile cannot list fail closed.** A tego binary with more than one hard link refuses every write entry that
   reaches its filesystem (the entry lies on its device, or a mount of that device lies at or beneath the entry): the
   other names could be anywhere there, and a write through one rewrites what the next run runs. The fix installs a
   fresh copy with one name outside every write entry and runs that one, leaving the other names (a backup's, a
   store's) as they are. A file only root may write (owned by root, no group or other write bit) is exempt while the agent is not
   root and cannot become root (the uid it is dropped to is not 0, and the contract has no `setuid: true`): a grant
   does not override the file's mode, so no name of it is writable by the agent (a package's or a Nix store's hard
   links). A mount table that cannot be read or shows no mount holding a binary refuses every write entry, as an
   unplaced target already did. So does a table larger than compile reads (8 MiB or 32768 mounts, review round 1).
   A binary on FUSE, eCryptfs, aufs or shiftfs has the stated backing limit below, while its visible paths remain
   protected. `WithMountInfo("")` turns the mount probe off for a caller that asks (test fixtures).
4. **`tego run` checks again with the file it runs from.** Its compile names the running binary
   (`os.Executable`, obtained from `/proc/self/exe`), so the unit's own tego is held at run time even where another tego
   compiled the contract. Tego never looks its own helpers up on PATH: the reaper, the linger timer, the child stage,
   the MCP relay, the harness hook and the hand-off to `tego-control` all run the running file or the `tego-control`
   beside it (read in the code: `os.Executable` and `/proc/self/exe` at every such start). The one place a `tego` is
   found through PATH is Maze's engine check, which runs outside every run and already refuses a `tego` inside the
   project.
5. **`path-shadow` stays a warning.** A write entry over a PATH directory searched before tego (an activated
   `.venv/bin`, `node_modules/.bin`) holds nothing of tego's, and refusing it would break the commonest Python and Node
   setups. Tego itself never resolves its own name through PATH (4), so the run stays as it is; what the warning
   names is the person's next `tego` in that shell.

**Rejected.** A plane row keyed on the binary's inode at the root tiers: with (1) to (3), no name compile can see lies
under a write entry, so the row would refuse nothing compile knows of, and at tier landlock nothing could hold the
same inode. A walk of every write entry for a file with the binary's device and inode: its cost grows with the
entries' trees (a home directory), and a search a limit cuts would be (3)'s refusal anyway. Refusing `path-shadow`:
(5).

**What this does not cover.** Mount analysis has exactly the [compile-time mount boundary](#compile-time-mount-boundary).
A tego installed elsewhere than (1)'s places and neither run nor found on PATH by the compile (a unit's
`ExecStart=/srv/tools/tego`, checked by another tego) is unknown to that compile; `tego run` under that unit holds
its own binary (4). The person's own shell may resolve `tego` through a directory a run wrote (5). The harness
hook's launcher check separately reads block-device backing through sysfs (ADR 0064); compile does not.

**Tests.** `TestCompileRefusesWritesOverTegosOtherNames` (`pkg/spec/agent`): a unit's `ExecStart` at a usual install
place, a second install in the installer's prefix, a bind mount of the install directory and of the file alone, an
overlay layer, a hard link, and a mount table that cannot be read. The earlier `TestCompileRefusesWritesOverTegosBinaries`,
`TestCompileRefusesWritesOverALinkToTego`, `TestCompileKeepsWritesBesideTegosBinaries` and
`TestCompileWarnsAboutPATHBeforeTego` are unchanged. `TestPairsContractsCompile` holds the pairs harness's contracts,
whose write entry holds a hard link of the launcher, to (3): refused where its agent could rewrite the launcher, and
compiled where the launcher is root's and the agent the sudo user, as `make vm-pairs` runs them (read, not run).

**Guest check, 2026-11-11** (KVM, this box's kernel 6.17.0-41-generic, 3 GB, 4 vCPUs; `tego run`, which compiles with
the file it runs from, at tier landlock as the sudo user and at tier cgroup as root, the running tego a root-owned
copy in `/opt/t1`): a bind mount of `/opt/t1` inside the write entry, a bind mount of the binary alone there, a second
install in the user's `~/.local/bin` under an entry over `~/.local`, and a user-owned tego with a second hard link on
the entry's filesystem were each refused before the agent started (exit 125, `contradiction` naming the other name);
the same contract with each name removed ran (exit 0), at both tiers.

## Amendment 2026-11-11 (second): kernel control filesystems by what they are, not where they usually are

*Status: accepted 2026-11-11 (review round 1 of r14/pausecompile); built (compile).*

**Context.** R10 kept every write grant off `/sys/fs/cgroup` and `/sys/fs/bpf` (agent-contract R9's kernel implicits)
and off `/run/tego` by their paths. Landlock grants a write through every mount beneath a granted directory, so a
bind mount of the cgroup tree, or a second `cgroup2` (or `proc`, `sysfs`, `bpf`) mount, inside a write entry was a
grant on the same files under another name. Read in the code, and run in a KVM guest (below): at tier landlock the
user's delegated cgroup subtree holds every landlock run of the user, owned by the user, so a governed agent granted
a folder holding such a mount could write another run's `cgroup.freeze` (thaw a paused run, also after its launcher
died), `cgroup.procs`, its limits and `cgroup.kill`, and its own. A run cannot make such a mount (Landlock refuses
`mount(2)`); a person or an administrator does. Every release from v0.1.0 to v0.1.2 compiles such a grant.

What R10 protects by pathname only, before this amendment: `/sys/fs/cgroup`, `/sys/fs/bpf`, `/run/tego`, and the
targets of the earlier amendments and this record (the ledger root, the run directory, the contract, the chain anchor,
the machine config's layers, prices, profiles and registry directories, tego's runtime parents, tego's binaries).

### Compile-time mount boundary

Compile reads one bounded, strictly parsed snapshot of the mount table in the namespace where it runs. It identifies
other places of a protected file or folder only through mounts of the same filesystem instance whose position and
visibility it can establish unambiguously from mount IDs, parent IDs and live identity checks where the kernel
supports them. Printed row order is not evidence of which mount is on top.

Amended 2026-11-12 (fix round 7): rows split only at newline. Every other byte, including a carriage return
at the end of an overlay option, remains part of the value. The 8 MiB snapshot bound counts input bytes,
including delimiters; acquisition reads at most one byte beyond it to detect overflow. Compile and a root tier's
run start share this reader (`MountOf` is gone since the one-reader amendment). Path fields decode mountinfo octal escapes once in `unescapeMount`. Super options stay
encoded until values are separated, then use that same decoder once. Legacy `lowerdir` additionally applies
its own backslash/colon list grammar. Comparisons use decoded pathnames, with no whitespace trimming, case
folding or Unicode normalization. Mountpoint fields and ordinary root fields must be clean absolute paths;
the unlinked-root rule below and namespace handles on nsfs are exceptions for root fields. Layer paths use
lexical path cleaning before the existing path walk. A decoded layer with a `..` component refuses every
write or ask grant instead of cleaning away a symlink before the walk. A decoded `upperdir` or `workdir`
containing a backslash also refuses: legacy string options quote the following byte, but FD-based options
print a literal path, and mountinfo has no origin marker to choose between them. Use absolute layer paths
without parent components or ambiguous upper/work quoting, or install the binary on a plain filesystem.
Neither condition establishes an unrelated backing tree. These additional byte-audit cases are covered by
`TestCompileRefusesAmbiguousLayerSpellings` and `TestMountReadersRefuseAmbiguousLayerSpellings`.
`TestMountSnapshotPreservesPathBytes`, `TestMountSnapshotCountsInputBytes` and
`TestCompileRefusesCarriageReturnLayerAlias` cover this correction. Kernel execution remains owed in a guest.

Amended 2026-11-12 (one reader): compile and a root tier's run start (ADR 0011, ADR 0025) read the mount table
through one reader in `pkg/spec/agent/mountinfo.go`. Fix round 14 restores the earlier read-denial reader's stricter
rule for ambiguous siblings: more than one top candidate at a mount point remains unknown before live selection,
even if statx identifies one candidate. This rule applies to supplied and live tables, alongside the stricter
record, graph and alias checks below. The snapshot is read twice and compared, up to three times, so a table that
changes while it is read refuses. Besides the byte rules above, a row may not hold a NUL or a tab, a row of 1 MiB or more refuses, ids
and device numbers must be canonical decimal (a device spelled `08:01` refuses the table rather than being
normalised), and the rows must form one graph: unique ids, exactly one root mount at `/`, every other parent listed
and mounted at or above its child, no cycle. A table that fails any of these refuses all write and ask grants.
The parent-edge visibility index and its live identity checks are the one holding-mount lookup for both sides.
`TestMountAmbiguousSiblingsRemainUnknown` pins the three-row sibling table in supplied and live forms, including
unknown alias results and an unrelated path that remains placeable. All 51 raw fixture tables and all 56
compatibility layouts have no siblings with the same parent and point; replay preserves all 56 layouts' accepted
contract counts.
These measurements are unit evidence. Execution of the merged enforcement path remains owed in a guest.
For linked roots, the other places a path is shown at (`MountTable.Of`) consider every linked-root row of the device,
a hidden row or one of unknown visibility included, and keep an alias whose own name resolves elsewhere:
an alias that is not reachable only refuses more. An unlinked former name never enters this path-alias index;
`Of` for a path held by an unlinked-root mount reports its holding mount, device and source with unplaced backing,
and infers no path aliases from that old name. Compile separately checks reached unlinked regular-file roots by
live file identity, as specified below. No lenient table reader remains.
`TestCompileRefusesUnplacedProtectedIdentity` and the cycle case of
`TestCompileRefusesAmbiguousMountVisibility` hold the whole-table refusal; round 13 improves the missing-root words.
Measured on tables captured in a guest (`TestCompileCapturedChrootMountTables`, 2026-11-12): among these layouts,
the kernel lists no row at `/` where the process's root is not a mount's root (a chroot into a plain folder).
There the per-path analysis this amendment replaced refused the same 17 of the 19 baseline contracts, since `/` itself has no row and
every walk starts there; the one reader refuses the same 17. A chroot whose root is a mount point, `pivot_root` and
bubblewrap list their root at `/` and accept all 19 under both.

Amended 2026-11-12 (fix rounds 13 and 15): a final `//deleted` root marker is valid only after a clean absolute prefix.
The marker establishes that the name is unlinked, not that a directory is empty or dead. An unlinked directory
remains an uncertain alias candidate: write and ask grants reaching it refuse, and read-denial startup retains
uncertainty when the directory could show part of the denied tree. There is no directory harmlessness exception.
For an unlinked regular-file root, live nofollow statx must establish type, inode and the snapshot mount ID before
comparison with each placed protected regular file's device and inode. The protected identity is also read under
its snapshot mount ID. Established absence or a nonregular protected target needs no file comparison; an identity
read error, failed holding-mount lookup, mount-ID mismatch or missing identity refuses the reaching grant.
A protected walk across an unlinked root has unplaced backing with C65's conditional warning on the same or
another device.
A table with no row at `/` still refuses all write and ask grants, and compile and `tego doctor` explain that
Tego's root is not a mount point, the kernel hides its filesystem and the remedy is to bind the root folder onto
itself before entering it or run Tego outside that root.
The final double slash distinguishes the kernel marker from a canonical path merely containing `deleted`;
a noncanonical prefix or a marker elsewhere remains invalid, as does every other malformed row.
The captured `systemd-nspawn` table now admits all 19 baseline contracts; its unlinked file mounts remain subject
to protected-file identity and kernel-filesystem checks; the pre-existing backing classes retain their byte
comparisons and warning rules.
These are compilation checks on captured tables; running this branch in nspawn, a plain-folder chroot and a
self-bound chroot is owed in a guest.
`TestMountUnlinkedRootSpelling`, `TestCompileUnlinkedFileIdentity`, `TestCompileUnlinkedDirectoryAndUnknownType`
and `TestCompileUnlinkedProtectedBackingWarns` pin the marker, real hard-link identity, directory and uncertainty
rules, and backing warning; `TestCompileCapturedNspawnProtectedGrants` retains the protected-folder and bind-alias
refusals, and `TestDoctorExplainsPlainFolderChroot` pins doctor's words. Fix round 15 adds
`TestCompileUnlinkedPopulatedDirectory` for reaching write and ask grants, `TestUnlinkedProtectedIdentity` for
protected-side read and mount failures with absence and nonregular controls, and
`TestMountUnlinkedDirectoryUncertainty` for alias-query and scope uncertainty.

Amended 2026-11-12 (fix round 16): doctor says when it cannot tell whether home or a built-in protected folder
is visible under another name, names the unlinked-directory mount or unclassifiable root, and retains
established alias warnings without claiming the plane can hold the uncertain tree.
The known aliases and uncertainty reason come from one query; a later type read cannot erase the mount name.
`TestDoctorUncertainMountAliases` pins the uncertain text to a golden and covers detached and
whole-tree aliases, unreadable roots, regular-file roots and different-device controls.
This is diagnostic unit evidence; the enforcement refusals and alias certainty rules are unchanged.

If it cannot establish that position or visibility, it refuses the write or ask grants the uncertainty could affect.
Ambiguous stacking, an identity it cannot read and a protected place it cannot place are uncertainty, never evidence
that a mount is harmless or absent; the backing limits stated here have their own warning rule. The refusal names the mount point or path. A malformed, unreadable or over-bound
table refuses all write and ask grants.

Amended 2026-11-12 (fix rounds 9 and 12): two kinds of backing are unplaced stated limits, like an absent binary layer.
An overlay layer named relative to a folder the table does not record is never resolved against a guessed folder.
Absolute layers of the same overlay are still placed and protected. FUSE (including `fuse.overlayfs` and
`fuse.fuse-overlayfs`) and eCryptfs backing remains unplaced for every protected regular file, including a binary,
a config layer or a contract. Unnamed aufs and shiftfs backing is tracked for binaries and their layers.
For example, a contract on `fuse.sshfs user@server:/p` can warn for a grant on another disk even when Tego itself
is on ext4. The warning names that contract and its path, as well as the filesystem type. Visible protected names and mount aliases remain protected. A `..` layer component,
ambiguous upper/work quoting, an unreadable existing layer, unknown grant identity and every other uncertainty
refusal above remain refusals. The rule is: "cannot tell where a grant lands" refuses; "cannot tell what stores a
protected file's filesystem" is a stated limit with a warning. Compile and run start use the same rule.

Amended 2026-11-12 (fix round 10): the runtime fixtures now replay complete container tables captured on
Ubuntu 24.04, kernel `6.8.0-147-generic`, with Docker 29.1.3, containerd 2.2.1, Podman 4.9.3 and
fuse-overlayfs 1.13. Docker overlay2's long layout has relative `l/` lowers and relative upper/work; Docker's
default containerd store and `ctr` have relative `NNN/fs` lowers with absolute upper/work. The absolute paths
in that mixed layout remain protected without assigning the relative lowers a guessed base. Optional fields
such as `master:1` and `shared:291`, nontrivial mount IDs, masked proc/sys paths and the captured option tails
do not change the rule. The tails include `nouserxattr`, `uuid=on`, `redirect_dir=nofollow`, `userxattr` and
`fsync=volatile`, with no `index=off`. The real FUSE type is `fuse.fuse-overlayfs`; the alternative
`fuse.overlayfs` and escaped-space cases remain labelled synthetic.

Amended 2026-11-12 (fix round 12): a single-file mount is excluded from the backing warning only for absent or
relative overlay layers, whose stored bytes match their visible bytes. No file-bind comparison clears a warning
when any affected backing is FUSE or eCryptfs: encrypted storage can contain different bytes for the same file.
For overlay classes, live `statx` with `AT_SYMLINK_NOFOLLOW` and `STATX_MNT_ID|STATX_TYPE|STATX_SIZE` must identify
a regular file on the snapshot row's mount ID, and comparison must establish a difference from every affected
protected regular file. Different sizes prove difference, including when one file is empty. Equal nonzero sizes
require bounded byte reads, both files opened `O_NOFOLLOW|O_NONBLOCK`, capped at the protected file's size. Two
empty files prove neither identity nor difference: no refusal by bytes and no file-bind exemption. A nonempty
byte-identical protected-file alias refuses every reaching write or ask entry, naming the protected file and
mount, executable or not.
Unreadable protected files and failed comparisons give no file-bind exemption. Unidentified or changed mount
points give no exemption either; the memory-filesystem storage limit still applies without live file identity.
Agent fixtures replay `statx` IDs for the captured Docker `/etc/resolv.conf`, `/etc/hosts` and `/etc/hostname`
binds and keep them quiet in the overlay classes; their live runtime silence is owed in a guest. Podman's FUSE
capture places its tmpfs file binds outside an ordinary project grant, so that grant reaches none and stays quiet.
A grant reaching one of those file binds gets one backing warning, including the empty `/run/.containerenv` bind.
Memory directory mounts retain the silent storage limit below; regular-file binds established by live checks
can keep the warning.
On a container host, an unrelated runtime-storage folder is not protected by its name: R10 still compares
the grant with the installed binaries and other protected places.

Amended 2026-11-12 (fix round 11): when a protected file lies on FUSE or eCryptfs and its mount source is an
absolute path naming an existing directory in this namespace, that directory joins the protected layer closure,
including its visible aliases. Write and ask entries at, over or inside it refuse. A missing, non-directory or
relative source remains unplaced. Source text never clears a FUSE backing warning: its mounter chooses `fsname`.
This branch also keeps the eCryptfs warning because it has not established a kernel-supported identity check
proving that the source directory is the live lower directory. Linux 6.8's
[`ecryptfs_inode_set`](https://github.com/torvalds/linux/blob/v6.8/fs/ecryptfs/inode.c#L42-L49) copies the lower
inode's number. Equal inode numbers on different devices do not prove that the source path still names the original
lower directory: a replacement or overmount can reuse that number. The proposed inode-number check is therefore
insufficient, and the warning stays. A source can add refusals without removing warnings.
A visible absolute layer that itself lies on unplaced backing stays protected, and its backing gets the warning.
Directory storage on memory filesystems (`tmpfs`, `ramfs`, `hugetlbfs` and `devtmpfs`) gets no backing warning in
either backing class. Regular-file binds established by live checks keep the warning without a difference
exemption, including empty files on tmpfs. Unverified memory mounts retain the storage limit.
When the runtime's storage or the backing folder itself lives on a memory filesystem and that same filesystem
is also mounted at a directory a contract may write, Tego gives no warning. This is GAPS C65's stated limit.
`TestCompileAbsentPlusFuseBinaryGrantOnFuse`, `TestCompileRelativeLayerFileBind`,
`TestCompileProtectsEncryptedBackingSource` and `TestCompileAbsentLayersStorageOnTmpfs` pin these cases.
The separate harness-hook scan can omit its automatic exact-argv grant and provisioning on unplaced backing;
it warns and the ordinary run continues. `TestHarnessUnplacedBackingDoesNotRefuseRun` now uses the product
provisioner registry in `Run` for every harness kind, on captured relative-layer Docker and FUSE-root Podman tables.
Claude Code and auto resolving to Claude Code reach the needed-grant scan, decline the provision with
`harness-hook-refused`, and reach enforcement. The other harness kinds have no product hook provision and skip
that scan. This does not share the contract compiler's backing-warning guarantee; execution is owed in a guest.

The capture runs used older head `69541c0706dd39125a004cc60f7ec046898e63be`, before fix round 9.
Small Docker overlay2 passed recipe 6 there with one `[mount]` advisory per phase without a volume and one
backing warning per phase with it. The volume mount advisory prints at compile and is informational at run
start, where it prints only with `-v`. The capture script repeats compile lines in its final grep output. Relative-layer and FUSE ordinary grants refused on that
older head. Replaying captures verifies compilation against those bytes; this branch's runtime reruns are
owed in a guest.

This analysis does not see mounts made after compile, a different filesystem instance showing the same data, or what
another process of the same user does outside the run. Absent layers, relative overlay layers and the unnamed
backing of FUSE, eCryptfs, aufs and shiftfs are also outside the guarantee: these alone refuse no grant, and the
conditional warning in decision (4) discloses a granted storage mount whose relationship to that backing is unknown.
The overlay-layer closure follows binaries, not arbitrary policy or ledger backing trees on an overlay.
FUSE and eCryptfs source-directory protection also applies to existing R10 regular-file targets.
Host owners must keep these unseen sources of protected data out of writable grants.

**Decision.**

1. **A write grant that reaches an identified kernel interface filesystem is a contradiction.** For every
   `fs.write` entry and `fs.ask` scope, compile looks the entry up in the mount table: if the mount holding it, or any
   mount at or beneath it, is of a type `agent.KernelFilesystems` marks refused, the entry is refused
   (`mountTable.controlFS`), within the [compile-time mount boundary](#compile-time-mount-boundary). Unknown visibility
   refuses the grants it could affect. The type is what the kernel reports for the mount, so a bind mount of part of
   the cgroup tree is `cgroup2` too. `tego run` compiles at run start, so this holds at run start as well. `KernelFilesystems` is
   the one inventory of these filesystems (review round 2): the supervisor's alternate-file refusal reads it by
   statfs magic. The policy for each type, not a claim that every kernel interface is covered:

   | Type | Write grant | Reason, and what else holds there |
   |---|---|---|
   | `proc`, `sysfs`, `cgroup`, `cgroup2`, `bpf`, `resctrl` | refused | process, sysctl, cgroup and BPF state of other processes and runs; `resctrl` groups' resource controls and tasks. procfs was a `kernel-fs-write` warning by path before |
   | `securityfs`, `apparmorfs`, `selinuxfs`, `smackfs` | refused | security module policy |
   | `debugfs`, `tracefs`, `configfs`, `efivarfs`, `pstore`, `binfmt_misc`, `fusectl`, `nsfs` | refused | kernel debug and tracing, configfs items, EFI variables, crash records, binary format handlers, FUSE connections, namespace handles |
   | `mqueue` | refused | POSIX message queues of other processes (create, unlink); `mq_open(2)` itself does not use the path and Landlock does not govern it |
   | `binder`, `usbfs`, `rpc_pipefs`, `xenfs`, `functionfs` | refused | IPC and device control endpoints |
   | `devpts` | only the mount at `/dev/pts` is allowed | other mount points, including binds of a slave, refuse write and ask grants that reach them; canonical `/dev/pts` lets an agent open its own pseudo-terminals. ADR 0113's open check also identifies slave character devices by device major outside `/dev`; aliases are refused even when their device number matches the inherited terminal. `TIOCSTI` and `TIOCLINUX` are refused by seccomp |
   | `devtmpfs` and character devices | not refused | a device file is reached by its own entry (`/dev/null`); a grant on `/dev` itself is a `kernel-fs-write` warning, and on a systemd host is refused for the `mqueue` mount beneath it; what a device node allows is its mode and the seccomp filter's ioctl set |
   | `hugetlbfs` | not refused | memory-backed data files, not an interface to other processes |
   | `tmpfs`, `ramfs` | not refused by type | memory filesystems; directory storage excluded from the backing warning in both classes, as are `hugetlbfs` and `devtmpfs`; regular-file binds established by live checks can still warn. Kernel interface filesystems above are excluded; memory-backed directory storage at a writable place is C65's silent limit |
   | `overlay`, FUSE, disk filesystems | not refused by type | the [compile-time mount boundary](#compile-time-mount-boundary) defines alias and layer coverage and its limits. A FUSE type alone adds a mount advisory; identified protected source places and aliases still refuse |
2. **R10 places are compared within the mount boundary** (the first amendment's (2), extended; review round 2).
   The [compile-time mount boundary](#compile-time-mount-boundary) governs placement and uncertainty. A grant and
   each protected place are placed on the mount table by device and place within the filesystem
   (`mountTable.reaches`), and a mount beneath the grant is followed, so a grant at or over another mount of a target
   is refused as the target is, and a grant inside another mount of a directory whose inside R10 refuses (the anchor's
   directory, the owner's tego directory, the ledger root's run directories, the profiles and registry folders, tego's
   runtime parents, a layer, `/run/tego`, `/sys/fs/cgroup`), or over a mount showing part of one, is refused as one
   inside it is (`insideByPlace`, `inRunDirByPlace`). The run directory rule compared the ledger root's parent, so it
   refused nothing for a ledger root outside the anchor's directory; it compares the root (found in review round 2).
   Every directory the target's walk reads a name in is compared through mount identity too, including directories
   visited before `..` and directories holding registry symlinks. An absent host layer path alone refuses no grant.
   Candidates found conservatively through mount roots retain unreadable or ambiguous identities as uncertainty,
   regardless of merged ownership.
3. **Fail closed.** A mount table compile cannot read whole and parse strictly (malformed, unreadable, or past 8 MiB
   or 32768 mounts) refuses every write and ask grant, as the mount boundary requires. The table is read and parsed
   once per compile and shared by every check (`compiler.mountTable`). Its reader: `loadMountTable(path string)
   (*mountTable, error)`, a bounded scan (`io.LimitReader` at 8 MiB + 1, at most 32768 rows, lines up to 1 MiB); a
   malformed row is an error. Past either bound, on a malformed row or on a read error, it returns an empty table
   with `err` set, which every write and ask grant is refused on.
4. **Unplaced protected-file backing is disclosed where a storage mount matters** (review rounds 4, 9 to 13 and 15, 2026-11-12).
   If a binary overlay layer is absent (ENOENT or ENOTDIR) or relative, a binary has unnamed aufs/shiftfs backing,
   any protected regular file has unnamed FUSE/eCryptfs backing, or a protected walk crosses an unlinked-root mount,
   compile emits one `overlay-backing-unknown` warning per write or ask entry that covers, or lies under, a visible
   storage mount. All cases exclude kernel interface filesystems from the shared inventory; absent and unnamed
   stacking backing also exclude memory directory storage. Regular-file binds established by live checks can
   keep the warning on memory filesystems.
   The absent-only rule also excludes discovered binary overlay devices. For relative layers and unnamed backing,
   each affected protected filesystem excludes only its own device: a different binary's device can still hold its backing
   folders on a storage filesystem. Unlinked protected backing also warns on its own device and on memory
   directory storage, retaining the kernel interface exclusion. Unlinked directories remain uncertain and refuse
   reaching grants. The warning names the grant and mount and says Tego cannot tell whether it shows the folders
   holding protected files.
   When a protected file itself lies on unnamed backing, the warning names it and that filesystem, such as the
   contract on sshfs, a config layer or a binary. Nested layer reasons do not name an originating protected file.
   FUSE and eCryptfs backing warnings also apply to existing R10 regular-file targets beyond the binaries.
   For a relative layer it explains that the mount table does not record the folder the
   layer names are relative to; for unnamed
   backing it names the filesystem type and says Tego cannot prove which folder holds the files it shows. For absent
   or relative layers, keep the runtime's storage and the whole host filesystem out of places a contract may write.
   For unnamed backing, keep the folder that stores the encrypted or mirrored files out of every write grant.
   A character-device grant such as `/dev/null` gets no backing-storage warning. A single-file mount gets the
   exception only for overlay backing after the snapshot-bound type, mount ID, size and protected-file
   comparison described above. Two empty files keep the warning; FUSE/eCryptfs file binds get no exemption.
   Nonempty byte-identical aliases still refuse in every backing class. Without such a grant and storage mount
   there is no backing warning. Ordinary overlay
   grants can still produce a separate `[mount]` advisory. Root-owned merged
   paths give no special treatment. Other refusal conditions in (1) to (3) still apply.

**What this does not cover.** The [compile-time mount boundary](#compile-time-mount-boundary) states the mount and
backing limits. Hard links of other protected files are outside this compile comparison; policy loaders and ledger
opens have their separate checks (SEC07). A write grant is not the only way to a control filesystem: a socket or a
process another run can reach is the supervisor's and the plane's (R19, ADR 0113).

**Tests.** `TestCompileRefusesWritesReachingAControlFilesystem` (a bind of the cgroup tree, a second `cgroup2` mount,
a `proc` mount, a `resctrl` group, an `mqueue` mount, an entry inside one; `fs.write` and `fs.ask`; the canonical `/dev/pts` mount
and an entry beside a control mount compile; aliases of devpts are refused; a table past the bound), `TestCompileHoldsProtectedDirectoriesThroughMounts`,
`TestCompileAllowsUnplacedLayers`, `TestCompileUnplacedLayersIgnoreMergedOwnership`,
`TestCompileWarnsAboutUnplacedOverlayBacking`, `TestCompileMountLayoutsCompatibility` (the count below),
`TestCompileHoldsTheLayerClosure` (a bind of an overlay's upper layer; unnamed stacking backing),
`TestCompileContainerRuntimeMountTables` (ordinary write/ask acceptance, exact warnings, protected grants and both
Podman FUSE type spellings), `TestCompileEncryptedHomeMountTables`, `TestCompileMixedRelativeLayers`,
`TestCompileRelativeLayersKeepMalformedRefusals`, `TestCompileUnplacedBackingOnAnotherBinaryFilesystem` and
`TestCompileNestedUnplacedBacking`. Run-start compilation is checked by `TestRunStartContainerRuntimeMountTables`,
`TestRunStartEncryptedHomeMountTables`, `TestRunStartUnplacedLayersKeepVisibleAndMalformedRefusals` and
`TestRunStartUnplacedBackingExcludesOnlyItsOwnDevice`. The compile and run-start memory-filesystem and null-device
regressions also check that storage warnings reach real backing candidates without treating character devices as folders.
The earlier control-filesystem and placeable-layer alias regressions fail with their corresponding checks removed.
Guest, 2026-11-11 (KVM, 6.17.0-41-generic): existing mount aliases could bring another run's controls within
reach of a write grant in v0.1.0 to v0.1.2. v0.1.3 refuses grants that reach them, within the documented mount
boundary. The v0.1.2 exposure and fixed refusal (exit 125) were measured at tier landlock and cgroup, including
when the other run's launcher had died; the paused run stayed frozen with the fix (ADR 0124 holds the results).
procfs, which a write entry
only got a `kernel-fs-write` warning for, is now refused with the rest (`TestSharedWritableExecAndKernelFSWriteWarn`);
`TestRunNoticesAMountPointIsANote` now uses `/dev/shm`.

**Compatibility (review round 4, `TestCompileMountLayoutsCompatibility`).** The test asserts all 40 inputs by name
and their expected baseline result, then each layout's exact refusal set. Nineteen compile with probing off. The 21
exclusions are five non-contract YAML files, three unfilled templates, eleven missing-path cases and two
contract/write-directory contradictions. On an ordinary systemd host all 19 compile. A private proc under `/tmp`
refuses only the `/tmp/` grant; a rootless container root with proc under home refuses only `~/.local/share/`; a
chroot's proc under the project refuses `examples/agents/custom-agent.yaml` and `./work/`. The CI container fixture
actually mounts overlay at `/`, with host layer names absent in the container: the same 19 contracts compile, with
no `overlay-backing-unknown` warning when no granted path meets a storage volume. They are
`examples__agents__anthropic-sdk-python.yaml`, `examples__agents__claude-code.yaml`,
`examples__agents__custom-agent.yaml`, `examples__tests__agent.yaml`, `internal__cli__agent.starter.yaml`,
`testdata__good__bom-crlf.yaml`, `testdata__good__minimal.yaml`, `preset__no-prod`, `preset__no-secrets`,
`preset__repo-only-writes`, `variant__bpflsm-open`, `variant__cgroup-all`, `variant__deny-list-exec`,
`variant__landlock-unix`, `variant__reads-direct`, `variant__grant-devshm`, `variant__grant-home`,
`variant__grant-project` and `variant__grant-tmp`. The layout with all discovered binary directories on a plain mount
also admits 19/19. With storage volumes at each contract's `out/` and `work/`, all 19 still compile. Exactly 11 warn:
`examples__agents__anthropic-sdk-python.yaml`, `examples__agents__claude-code.yaml`,
`examples__agents__custom-agent.yaml`, `examples__tests__agent.yaml`, `internal__cli__agent.starter.yaml`,
`variant__bpflsm-open`, `variant__cgroup-all`, `variant__deny-list-exec`, `variant__landlock-unix`,
`variant__reads-direct` and `variant__grant-project`. The other eight have no such warning:
`testdata__good__bom-crlf.yaml`, `testdata__good__minimal.yaml`, `preset__no-prod`, `preset__no-secrets`,
`preset__repo-only-writes`, `variant__grant-devshm`, `variant__grant-home` and `variant__grant-tmp`.
This checks compilation against synthetic tables. This branch's actual container compile/run reruns, with and
without a granted volume, are owed in a guest: numbered guest checks.

The shipped image installs tego under `/usr/local/bin`. That binary can remain on the container's overlay when its
host layer paths are absent. Its mount analysis follows the [compile-time mount boundary](#compile-time-mount-boundary).
An external storage mount meeting a write or ask grant produces the warning in (4), subject to its exclusions,
since its relationship to hidden host layers is unknown. Keep runtime storage and the whole host filesystem out
of those grants.

### Review round 3 (2026-11-12)

The walk-name alias regression is `TestCompileHoldsWalkDirectoriesThroughMounts` (write and ask, registry symlink
and names before `..`). Review round 3 removed the unsound merged-mode exemption; review round 4 keeps ownership out
of the layer decision and replaces blanket absence refusals with the stated limit above.
`TestCompileWarnsAboutVisibleFUSEMounts` demonstrates the different-filesystem limit and the warning.
`TestCompileRefusesDevptsAliases` covers write and ask at, over and inside alias mounts, including a slave bind.
These are unit proofs. The devpts kernel proof and this branch's container reruns are owed in a guest.

### Review round 4 (2026-11-12)

The round-3 absence refusal reduced the overlay-root fixture from 19 compiling contracts to two. It is reversed:
ENOENT and ENOTDIR for a binary overlay layer alone refuse no grant. The root-owned merged-path exemption stays
removed. `TestCompileUnplacedLayersIgnoreMergedOwnership` covers that rule and the refusal of a visible writable
layer alias despite root-owned merged paths. `TestCompileWarnsAboutUnplacedOverlayBacking` covers one warning per
reaching entry, write and ask, external mounts, and the absent-only exclusions for binary, kernel and memory
filesystems.
Present unreadable layers, unknown mount identity and closure bounds still fail closed. Fix round 9 extends the
stated limit to relative layers and unnamed FUSE, eCryptfs, aufs and shiftfs backing. The remaining risk is
GAPS C65; the kernel checks and this branch's container reruns are owed in a guest.

The absent-layer candidate search and backing warning use the common lookup governed by the
[compile-time mount boundary](#compile-time-mount-boundary). A verified covering mount can exclude a mapped layer
candidate; a failed identity read cannot. Candidate collection stops one past the 64-place closure bound.
`TestMountVisibility`, `TestCompileAllowsUnplacedLayers` and `TestCompileLayerCandidatesAreBounded` cover these
checks without privileged mounts.

### Review round 5: one holding-mount lookup (2026-11-12)

Mount placement checks share one holding-mount lookup. Its guarantees and uncertainty refusals are exactly the
[compile-time mount boundary](#compile-time-mount-boundary), corrected in round 6 below. Missing target paths use
the first existing ancestor. Synthetic placement skips the host ID comparison. The single-file backing-warning
exception still requires `statx`; agent fixture tests supply replayed mount IDs through its test seam.

`TestCompileHoldsProfilesWithHiddenMountRows` covers protected and granted sides, with write and ask scopes.
`TestMountLookupVerifiesLiveIdentity` compares the ordinary live table with the kernel and refuses a stale ID.
Privileged overmount execution is owed in a guest.

### Review round 5: unknown protected identity (2026-11-12)

Before any write or ask comparison, compile requires a mount device and filesystem-relative place for every
active R10 target and every directory its walk reads. The owner's existing Tego directory is included. These
places are relevant to every grant: without identity, even a separately named visible bind cannot be proved to
reach different data. The grant also needs identity. An empty configuration path declares no target. Absent
binary overlay backing never enters this target set and remains C65; different-filesystem mirrors remain outside
this comparison. No ownership exemption applies.

An unknown place refuses the grants and names the place and remedy: use a namespace whose root is a mount point
and whose table includes its filesystem, bind-mount the chroot root onto itself before entering it, or compile
and run outside the chroot. `TestCompileRefusesUnplacedProtectedIdentity` covers a partial chroot with visible
binary and workspace binds; since the one-reader amendment above, such a table is refused whole.
`TestCompileMountLayoutsCompatibility` also asserts accepted counts explicitly: ordinary host, overlay-root
CI and workspace-volume container stay at 19, with exactly the existing 11 volume warnings. Project chroot stays
at 17, refusing only `examples__agents__custom-agent.yaml` and `variant__grant-project` for its proc mount. The
partial-root chroot keeps only the two read-only baseline contracts and refuses the other 17, all asserted by name.
Privileged partial-chroot execution is owed in a guest.

### Review round 5: binary inspection errors (2026-11-12)

Discovery preserves inspection errors for running, PATH, standard-install and beside-launcher helper candidates.
Only ENOENT and ENOTDIR establish an absent candidate. Other errors refuse write and ask grants and name the
candidate and cause; they cannot become a claim that no binary is installed. ENOENT/ENOTDIR absence still compiles.
`TestCompileRefusesUnknownBinaryDiscovery` covers every discovery source, and
`TestCompileRefusesUnsearchableInstall` covers a user-owned directory whose search permission is removed.

Post-discovery binary identity errors and failures placing a hard-link grant's filesystem also refuse with their
cause (`TestCompileRefusesUnknownBinaryIdentity`, `TestCompileRefusesUnknownHardLinkGrantFilesystem`). An alternate
chain anchor cannot disable the owner's Tego directory check: unknown directory lookup refuses grants, and an
existing directory alias of the filesystem root keeps its at/inside write refusal
(`TestCompileKeepsOwnerDirectoryProtectionWithAnotherAnchor`).

### Review round 6: uncertainty is a refusal (2026-11-12)

The [compile-time mount boundary](#compile-time-mount-boundary) replaces the earlier blanket claims about stacking
and visible aliases. A moved mount can appear before the mount it covers in mountinfo. Same-point stacking therefore
uses parent relationships, with live candidate verification where supported; unresolved visibility refuses the grants
it could affect and names the mount point. An unreadable mapped layer candidate remains uncertainty and reaches the
closure's refusal path. Only a verified covering mount establishes that the candidate is hidden. Parsing rejects a
malformed row rather than treating a partial table as complete. Privileged moved-mount and permission checks are
owed in a guest.

The boundary audit also keeps unrelated omitted parent IDs unknown (since the one-reader amendment above, a table
with an omitted parent other than the root's is refused whole before this analysis) and includes the mount point
in a protected-side ambiguity refusal. `TestMountStackUsesParentsBeforeRowOrder`, `TestCompileRefusesMovedControlMount`,
`TestLayerClosureKeepsUnreadableLiveCandidate`, `TestCompileRefusesAmbiguousMountVisibility`,
`TestCompileNamesAmbiguousProtectedMount` and `TestMountVisibilityKeepsUnrelatedOmittedParentsUnknown` pin these
cases. The shared bounded parser is also used by `MountTable.Of`; namespace-handle roots retain their kernel type but
supply no filesystem-relative place. These unit checks do not establish privileged mount execution.
