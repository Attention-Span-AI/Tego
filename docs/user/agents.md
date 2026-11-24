# Your Agents list

Open Agents at `/agents` in the dashboard. Run `tego scan` from your project
folder, then refresh the page. Opening the page starts no scan or agent.

The found list comes from `tego scan`, which is new in v0.2.0. v0.1.3 does not have it.

The found list comes from scans. Tego refuses ordinary writes to these files, even with a whole-home grant at tier landlock; this was shown in guest row whole-home-landlock. With the anchor and ledger outside the home, a whole-home grant with direct reads can leave these files readable at landlock; that read case is derived from code and is owed in a guest. The stages shown for a run do not depend on this list.

This is the existing [own-state limit](../GAPS.md) described in C52. A program
running as you outside Tego can change these files, too. The list shows what
scans have seen; it never proves that nothing else runs. Scans keep no arguments
and their observations stay separate from recorded runs.

Each recorded row names one run and its start time. Contract and Enforced need
that run's checked record; Verified also needs that enforcing run to have ended.
An unchecked or broken record says why and stops at Recorded. A scan cannot
supply any of those ticks.

Discoveries remain for 30 days since last seen. Only omission from a usable
latest scan means "not seen in the latest scan". An old, failed or unreadable scan is described
as such, keeps the last-seen time and asks you to scan again. Related recorded
runs are explained using the current records, even after the scan is replaced.
If another dashboard holds the store lock, the page shows the last committed
discoveries without saving and asks you to refresh to retry. The list states
when it reaches its storage bound.
A valid rewrite of both saved files can still add, change or remove found rows.
The current record lacks the historical own-state write fact needed to identify
an exposed scan reliably, so the page has no per-run caution or unconfirmed-after-run
state yet. Scanning again after the run ends refreshes the observations.

If either `~/.tego/scan/last.json`, `~/.tego/agents/discoveries.json`, or the
`~/.tego/agents` directory has unreadable or unsafe modes or links, the page says
so and gives repair steps. Recorded rows whose records are readable still show.
The page leaves unsafe state unchanged. Check ownership and links first. Move
links or invalid state aside; do not chmod through a link. For your checked real
directories use `chmod 700 ~/.tego/scan` and `chmod 700 ~/.tego/agents`. For your
checked regular files with one link use `chmod 600 ~/.tego/scan/last.json` and
`chmod 600 ~/.tego/agents/discoveries.json`. If you moved a bad discovery store
aside, the page creates a new one from fresh observations. Run `tego scan` from
your project folder, then refresh.

The page currently uses minimal HTML. The approved page layout and an explicit
Forget action follow separately. The external-anchor direct-read case is
**owed in a guest**; the exact acceptance procedure is in
[ADR 0145](../adr/0145-tego-scan.md#a4-fix-round-2-own-state-disclosure-and-record-limit-2026-11-12).
