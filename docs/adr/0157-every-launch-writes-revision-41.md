# ADR 0157: Every launch writes revision 41

Status: **accepted 2026-11-20**; built. The number is the next free one under `docs/adr`. Amends ADR 0055 (what an adoption records) and the record revision list in
`spec/record/v1/README.md`.

## Context

A run's record states, in its `run_start`, the revision of the record it follows (`record_minor`). A reader takes the
revision to mean what a field's absence means. Until now a launch wrote revision 31 and moved to a later one only when its
`run_start` itself carried a field of that revision: 39 for a machine baseline block, 40 for an adoption's
`applied_limits`.

Two facts a reader needs were not recorded for that reason.

1. **A block by name does not say what it covered.** A person's live network block (`tego block`, the dashboard) can name a
   host. It is enforced on the addresses the name resolved to. The gap line of the block named the host and none of the
   addresses, so a reader could not say that an address the run reached under a CIDR entry (a line that names no host) was the
   blocked host. The dashboard kept such a group out of "the run also reached this host" and said nothing more (A34, closed
   in part on 2026-11-20 by marking the group `NameUnknown`).
2. **A receipt could not fold `~` exactly.** `tego receipt` folds a path under the run's home to `~`. The only home a record
   held was the machine baseline evidence's owner home, which a run has only when the machine had a baseline snapshot, so a
   run without one printed every path whole (A42).

Both need a new field, so both need a new revision. The first is the harder case: a live block can arrive at any time after
`run_start`, and `run_start` is the line that declares the revision. A launch cannot wait to see whether a block happens,
because by then the first line of the ledger is written, signed into the chain and not rewritable.

## Decision

1. **Record revision 41, written by every launch and every adoption from `run_start` on.** `record.MinorEveryLaunch = 41`
   is `record.Minor`. The two writers (`runtime.launchMinor`, the baseline writer's floor) select it; a run writes it whether
   or not a block ever comes.
2. **Revision 41 includes everything 39 and 40 allow, with their rules.** The baseline block is required at 39 itself and
   carried at 41 when the run had one (`RunStartPayload.BaselineRecorded` is "revision 39 or later and the block present",
   as it was); `applied_limits` is allowed from 40 and written at 41 by an adoption that wrote a limit. A ledger at 31, 39
   or 40 reads exactly as before.
3. **At 41, a live or restored net block by name records the addresses it was enforced on.** The gap line of a
   `live-block-added` or `live-rule-restored` change of kind net whose value names a host (not an address, not a socket)
   carries `live_block.addrs`: every address the lookups of the name had answered and the live set refused it by, as
   enforced (unmapped; an IPv6 zone kept as the lookup gave it), sorted by address, at most **32**, and
   `live_block.addrs_more`, the count past the cap (more than 0 only on a full list). A block by address records nothing
   new. A name whose lookup answered no address records none, which a reader reads as "not said".
4. **At 41, `run_start.home` records the run's home directory** as the run resolved it: the passwd home of the launching
   user (never `$HOME`), or, for an adoption, of the agent's owner. It is a clean absolute path of at most 4096 bytes. It is
   left out when the run resolved none.
5. **Readers.** The ledgerview fold treats an address reached under a CIDR entry that is one of a name block's addresses as
   that host: it is a live-blocked address (never folded as routine) and its group carries `BlockName`, the name.
   `Group.NameUnknown` is kept for a name block that recorded no address (every ledger below 41, a lookup that answered
   none) and for a list past its cap, which cannot clear an address it does not name. An address no recorded list names is
   no longer held back while every name block has said its addresses. The receipt lists each name block with its addresses
   (or says the record does not say), and folds `~` under `run_start.home`, then the baseline's owner home, else prints
   every path whole with its one-line note. The dashboard's refusal row draws `NameUnknown` ("name unknown") and
   `BlockName` (the blocked name, with a title that says why); the JSON receipt is unchanged.
6. **Older builds refuse revision 41** like any revision they do not know: a build that predates it reads no ledger a
   build with it writes, and says the revision is unsupported. That is the cost of this decision and the reason it is
   taken once, for every launch, and not per field.

## Can an adoption take a live block?

No. An adoption starts no live-block poll (`adoption.startWorkers` has none; the overlay file is never read for it, and
`ControlName` is never made for an adopted run). It still writes 41: the home is useful to its receipt, and an adoption that
one day polls the overlay needs no second revision. An adoption's home is its agent owner's (`AdoptDeps.Home`), the one its
table was compiled against.

## Alternatives rejected

- **Declare 41 only for a run that has a block.** Impossible: `run_start` comes first and cannot be rewritten (the ledger is
  hash-chained), and a block can come at any later time. A revision declared late would be a second source of the revision,
  and a reader would have to read the whole ledger to know what the first line means.
- **Write the addresses at a revision a block's line carries itself.** The revision of a ledger is one number, the
  `run_start`'s; a per-line revision would be a new mechanism and every reader of absence ("none recorded" against "not
  written by a build that knew") would have to learn it.
- **Keep launches at 31 and let the viewer say "unknown" forever.** What A34 did on 2026-11-20. It errs toward showing, but it
  can never say that an address is the blocked host, and the receipt of a run with no baseline can never fold a path.
- **A separate gap line when a lookup later adds an address.** It would be exact where this is not (see Limits), at the cost of
  a new gap why and a fold that merges lines in time. Not taken here.

## Limits (stated, not hidden)

- The line names the addresses the live set refused the name by **when the line was written**. The launcher looks the name up
  again every few minutes and keeps every address it ever answered (up to 64), so a later lookup may add an address the
  line does not name. An address reached under a CIDR entry that is only in such a later answer is not shown as the blocked
  host; the refusals under the block still carry the address they refused. A name blocked while its lookup failed records
  none, and the viewer says the name is unknown, as before.
- More than 32 addresses: the first 32 in address order are named and `addrs_more` counts the rest; a reader does not clear
  an address against a list that says there are more.
- A launch at 41 accepts the reserved run_start blocks of revisions 32 to 35 that the runtime's `RunStartExtras` can carry
  (no caller fills one: the writers stay absent), where at 31 it refused them below their revision. That is the revision's
  superset meaning, not a new writer.
- Byte-compared launch fixtures moved from 31 to 41 and were re-pinned (`testdata/prebaseline/`, `run_start-no-extras.golden`).
  Nothing else in them changed; the README beside them says so.

## Guest proof owed

A real run with `tego block` on a host name: the gap line names the resolver's addresses; the dashboard row of a refusal
under a CIDR entry to one of them shows the blocked name; `tego receipt` lists the block and folds `~` under `run_start.home`
for a run with no machine baseline; an older build refuses the ledger as unsupported revision 41.
