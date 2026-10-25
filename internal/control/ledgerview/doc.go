// SPDX-License-Identifier: Apache-2.0

// Package ledgerview is the dashboard's read model: a cached, read-only view of a ledger root's run directories
// (<root>/r-*/events.jsonl) as run summaries, events, refusal groups and pending asks, for internal/control/web to
// render. It opens files read-only, takes no lock and writes nothing.
//
// # The cache (store.go, cache.go, memo.go)
//
// One Store per ledger root (Open; Load and LoadRun use it) lives as long as the process. Per run it keeps the
// events file's identity (device, inode), size and mtime, the offset of the last complete line read, the decoded
// lines and the summary built from them. A request stats each events file: an unchanged one costs nothing, a grown
// one costs its appended lines, and one that got shorter or changed identity is read again from the start. Each
// change publishes a new immutable Run that concurrent requests share; the views derived from it (the timeline, the
// refusal groups, the Logs fold and text haystacks, the per-subject counts, the hits per rule key of the Rules page)
// are built once per published version, on first use. Logs (Snapshot.Query) folds each run where it lies and merges
// only the page across runs; its filter can come from a query string (querylang.go), its facets are counted in the
// same walk and kept per run version and filter (facets.go), and Snapshot.Each gives every matching line with its
// exact bytes for the downloads (export.go). Each line's program (Row.Program, the query's prog:, the Program facet)
// comes from the run's exec lines in one pass, continued as a live run grows (program.go), and Group gathers the
// matched lines by process, target or rule, kept per run version like the facets (group.go). Lines are kept in memory up to MaxResidentBytes (an estimate); past it the lines of the
// ended runs no page asked for longest are dropped, their summaries stay, and Run.AllEvents reads them again when a
// view needs them. Chain verdicts of ended runs are kept by (run directory, events file identity, size, mtime, last
// line's id, anchor identity); after ten minutes the kept verdict is still shown while the same run is checked again
// in the background, and one check per key runs at a time (chain.go). A run's Signal is kept per run version, and while
// the run is live so is the pass that built it, so the next version folds only the lines it gained (signalcache.go,
// signalfold.go); a line's paths are classified as secret or not once, as the Store takes the line (secretpath.go).
// The run page's heavy tabs keep their results per run in bounded caches (results.go: Results, StampRun): the Receipt
// here and, in internal/control/rulesview, Least privilege and Unused, each reused while the run's events file
// (device, inode, size, mtime, a digest of its last 4 KiB, live or not) and the rest of its key are the same, at most
// five minutes; a live run's costly result is reused for at least two seconds and twice its cost after it finished,
// and while another request computes the next one. LineAt hands the offset of a line it holds to the event page, for
// the rule service's read of that line. Safe for concurrent use.
//
// Runs are decoded outside the Store's mutex (store.go, bring): a request claims the runs whose file changed, decodes
// them on up to four goroutines, each owning its runState, and takes the mutex again only to publish; a run another
// request is reading is waited for, never read twice at once. LoadNow is the snapshot for callers that must answer at
// once (the live state): it waits for no one's read, shows such runs as last published and says Snapshot.Partial.
// PrewarmChain checks the overview's chains as the dashboard starts; VerifySnapshot counts a run still being checked
// in LedgerChain.Verifying instead of waiting for it.
//
// A refused action and the kind=refused line that mirrors it are one refusal: the cache marks the mirror as it takes
// each line (pair.go), so a run read in many appends is marked as one read of the whole file, and every count and
// view (Run.Refusals, RunRefusals, the timeline, Logs, FindSimilar) takes the one rule Event.Refusal from that mark.
//
// A command too long for its line (an exec's argv, run_start's command) is in the run's blobs/ directory, and the
// line names it by sha256 (argv_blob, command_blob). The cache reads that blob once, as it takes the line
// (blobargv.go): read-only, O_NOFOLLOW|O_NONBLOCK, a regular file of at most MaxBlobBytes whose content hashes to its
// name, and keeps at most MaxTargetBytes of it as the line's Target, so rows and the Logs search see the command the
// agent ran. A blob that fails any check leaves the program's path (Event.ArgvMissing); the line page reads the blob
// whole (BlobCommand).
//
// # One line explained (explain.go, proc.go, blobs.go)
//
// Explain is everything the record says about one line, for the line page: the envelope and the line's place in the
// hash chain (its prev checked against the line before, both read by offset); the program its pid was running at the
// line and that program's parents up to tego's launcher, followed through exec_id and parent_exec_id (a parent that
// forked without starting a program ends the chain as "forked, no exec recorded"; a parent is never guessed, and a
// process's own working folder is not recorded); every key of the line in written order, labelled and put in words
// by internal/control/linewords (a key it does not know is shown as written and marked unknown); each blob the line
// names (<field>_blob, blob) read back and checked as ReadBlob checks it, a request body's splice named and not read;
// the question the line belongs to (its ask, answer and the line the answer let through or refused); the refusal it
// mirrors or is mirrored by; and one plain sentence. The run's process and ask index is built once per published
// version (runMemo); a warm Explain of a 12,000-line resident run takes about 0.1 ms. The page shows VerifyRun's
// verdict beside it (ChainWords); Explain itself does not hash.
//
// # The process tree (proctree.go)
//
// ProcessTree is the run's processes as a tree for the run page's Processes tab, built once per published version
// from the same index (exec_id, parent_exec_id, run_start's launcher): each process with every exec of it (refused
// attempts of one command in a row folded, with each path a PATH search tried), its lines, reads, writes, connects,
// hosts and refusals, and the totals under it. A process that forked without starting a program writes no exec line,
// so the record does not name its parent: it hangs from the launcher marked ParentUnknown, and no parent is guessed.
// Each process's lines are what Logs shows for its pid, and they add up to the run's lines but its mirrors. On a
// synthetic 200,000-line run of 24,579 processes the index and the tree take about 37 ms cold; the commands are
// masked only when a page shows them, and remembered.
//
// # Revisions (for live updates)
//
// The Store numbers every change it sees with a revision, which only grows; it starts at the clock in microseconds,
// so a restarted dashboard never repeats a number an open page still holds:
//
//   - Snapshot.Rev is the revision the snapshot reflects. Two snapshots with the same Rev hold the same runs with
//     the same lines, live states and pending asks; a page whose Rev matches has nothing to redraw.
//   - Run.Rev is the revision at which that run last changed: lines appended, its file replaced or truncated, its
//     live state changed. Snapshot.Changed(since) lists the runs with Rev > since. A run that left the root (gc) is
//     not listed, but Snapshot.Rev moved, so compare the run ids when Rev moved and Changed is empty.
//   - Run.LastSeq is the seq of the run's newest line read, the cursor for "rows after seq"; TimelineOf(run,
//     refusedOnly).Below(seq+1) is the number of timeline rows newer than seq.
//   - Store.Rev reads the current revision without looking at the ledger; Load (a cheap stat of each events file
//     when nothing changed) brings it up to date.
//
// A Run and the slices it holds (Events, Pending, Kinds) are shared and must not be modified; RunRefusals and
// Timeline.Rows return fresh rows a caller may label.
//
// The chain check (chain.go) is the one place it reads through internal/ledger: VerifyRun runs ledger.VerifyRunDir,
// the code `tego events <run> --verify` runs, against the same chain anchor, on one run per request (the run page)
// or on the newest MaxChainRuns ended runs (the overview).
//
// The web pages read the ledger in this process, through this package.
//
// Imports: the standard library, pkg/spec/record, internal/control/linewords (the glossary and the credential mask),
// internal/ledger (VerifyRunDir; OpenReader for the receipt; LockHeld and OpenRegular for a result's stamp), and the read-side cores internal/check/receipt, measure, livestatus,
// secretpath and syslookup.
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf, internal/cli).
package ledgerview
