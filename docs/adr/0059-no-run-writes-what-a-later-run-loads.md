# ADR 0059: no run writes what a later run loads: R10 protects every name a policy file is read by, and the loaders read none it cannot see

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

One invariant, kept from both sides: **every name a policy file is loaded by is a name R10 keeps every write entry
off.** R10 enumerates the names of a closed walk, and the loaders refuse any file that has a name outside it.

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

Together, (1) to (3) close the walk: every directory the walk to a policy file reads a name in is one R10 protects,
every file read from a protected directory stays inside it, and the file has no name besides the one walked; (4) keeps
it closed for the run.

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
- **A bind mount is a name a link count does not show.** One the administrator makes of a policy file or of a
  protected directory, onto a path a write entry reaches, is not seen; a run cannot make one, since a Landlock domain
  refuses `mount(2)` and every other change of the filesystem topology (the kernel's Landlock documentation), and
  `TestIntegrationLandlock`'s `bwrap` cell shows a mount namespace refused before it mounts.
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
