// SPDX-License-Identifier: Apache-2.0

// Package rulefile is the I/O half of changing a contract (internal/check/rule is the pure half): it finds one event of
// a run and the contract file the run compiled (FindIn; FindAtIn with a hint of where the line starts, which it checks and
// falls back to FindIn's scan when it does not hold), reads a contract through its guards (Read), replaces it
// with new text (Found.Write, Replace), writes a new one where there is no file (Create) and records every replacement
// in a journal that history and Undo read (ReadJournal, History, Revert, Undo) and retention prunes (Prune). `tego
// rule` and the dashboard both write through it, so the two write the same bytes under the same checks.
//
// # Guards
//
// The contract's directory is resolved once (a home reached through a symlink still works), refused when it is under
// the ledger root or tego's home, then opened through registry.OpenDirectory with no links followed and pinned.
// Every later open, rename and sync is relative to that descriptor, so a directory swapped for a symlink afterwards changes nothing here. The
// directory must be this user's or root's and not writable by others unless sticky. The file is opened O_NOFOLLOW and
// fstat on that descriptor must show a regular file owned by this user (the effective uid), one link, not writable by
// others, writable by its group only when that group is the user's private group (the process's group, with no other
// member and no other user's primary group), and at most agent.MaxContractSize bytes.
//
// # Writes
//
// A write takes the contract's lock (flock on <ledger_root>/.rule-changes/locks/<sha256 of the resolved path>.lock),
// reads the file again and compares its sha256 with the base the change was made from (ErrStale otherwise), keeps the
// old and new text as blobs, writes <file>.bak, writes the new text to a temporary file (O_EXCL, O_NOFOLLOW, the old
// file's mode, fsync'ed) through registry.WriteFileAt. That shared publisher rechecks the old device, inode and
// SHA-256 immediately before rename and syncs the directory. The owning rulefile guards also reread the file to
// catch an editor that does not take the lock. Create uses the same publisher without replacement. A dashboard
// guard can bind the directory's reviewed device and inode to the final descriptor. Then it appends the journal
// line. From its first blob to that line it holds locks/prune.lock shared, so Prune, which holds it exclusively,
// never removes a blob the line is about to name. A lock is held only once the file locked is still the one at its name, since Prune removes
// a contract's lock file under that file's flock; a writer that locked a file removed meanwhile locks the name again.
// Create, Replace, Revert and Undo reject an already-cancelled call before reading its contract or journal path.
// Their lock and final rename checks also refuse cancellation. Guard reads and temporary-file syncs may return
// after cancellation; they do not permit a later contract commit.
// A rename already submitted to the kernel cannot be undone by cancellation, so its outcome can remain uncertain.
//
// # Journal
//
// <ledger_root>/.rule-changes/ (0700, this user's, writable by no one else) holds journal.jsonl, blobs/<sha256>.yaml
// (each text a change replaced or wrote, checked against its name when read) and locks/. Moving or removing the
// ledger root moves or removes the journal with it. journal.jsonl is appended under locks/journal.lock, one JSON
// object per line, fsync'ed; a reader skips a line that does not decode (a torn last line) or has another "v". The
// fields, all but the first six optional:
//
//	v            1
//	id           "rc-<UTC yyyymmddThhmmss.uuuuuuZ>-<8 hex>", unique, sorts by time
//	op           "change" (a contract was replaced), "revert" (a change or revert was undone), "live" (what "also
//	             apply now" did for the change named by of, recorded after it), "create" (Create wrote a new
//	             contract where there was no file: no old_sha256, no bak; never undone, the file is removed by hand)
//	at           RFC 3339 UTC time of the write
//	uid, pid     the writer's effective uid and process
//	via          "cli" or "dashboard" (else the writing program's name)
//	contract     the contract's absolute path with its directory's symlinks resolved; compare a run's
//	             contract_source after filepath.EvalSymlinks of its directory
//	old_sha256   sha256 of the text before (blobs/<old_sha256>.yaml)
//	new_sha256   sha256 of the text after (blobs/<new_sha256>.yaml): the file holds it until the next line for it
//	bak          the .bak path written
//	run, line    the run and its line the change was made from
//	summary      the change in words; sentences: its rules' "before → after" sentences (SentenceLine; "(nothing)"
//	             before a rule the file did not have); direction: narrows, widens or mixed. `tego rule` and the
//	             dashboard journal all three for a change of theirs
//	reverts      (revert) the id it undid
//	of           (live) the change id the outcomes belong to
//	live         [{"run","block","ok","err","lift","by","serial","held","pending"}]: live blocks placed on running
//	             runs; "lift": true marks one an Undo lifted (removed) from its run, recorded on the revert: of the
//	             blocks the undone change had placed. The last four are optional and written only when they say
//	             something: "by" who made the block or its removal ("change", "undo", "redo"); "serial", "epoch"
//	             and "at" the identity of the add that made the block (the live overlay's serial after that write, the
//	             overlay file's id, and the instant the add was recorded), which tells the block this outcome made from
//	             one a person placed later with the same key, or from another file's block of the same serial; "held" a placement that found the block on the run already, so the change
//	             made none and owns none ("ok" is false); "pending" a lift or a placement that was begun and whose
//	             end is not recorded ("ok" is false), replaced by the line that says how it ended (Fold)
//
// # Live outcomes and older readers
//
// The journal's version stays 1 and a new tego adds no required field: every new field of a live outcome is optional
// and absent from a line that has nothing to say in it, so a line written without them is byte for byte what an older
// tego wrote, and an older tego's line reads here as "who and which serial not known". An older reader that knows only
// run, block, ok, err and lift (every release up to now) reads a new line like this, and in no case as a block that is
// lifted when it is not: a placement by a change or by a Redo (ok true) as a block placed, which it is; a block the run
// held already, a lift that failed, a lift or a placement that was begun and not recorded (ok false) as not placed and,
// for a lift, as not lifted, with the line's own words in "err", which say what happened; a lift that took effect
// (ok true, lift true) as lifted, as before. A reader that does not know "lift" either (a build from before 2026-10-27;
// no release) reads a finished lift as a block placed: it says "blocked" of a block that is gone, the restrictive error,
// never "allowed" of one that holds. The reverse also holds: a line from before the optional fields has no serial, so
// it is never read as a block this tego can prove a change made, and an Undo leaves that block in force (the rules
// service, lift.go). A tego that rewrites the journal keeps each line whole (Prune copies lines as written), so an
// older tego's prune does not drop the fields.
//
// A contract changed after a run started is "pending for the next run" when the journal holds a change or revert of
// that contract with at after the run's start (the dashboard reads it so). Revert(id) writes back the text before
// id only while the file holds id's new_sha256, so it never loses a later change; Undo reverts the newest change not
// yet undone whose new_sha256 the file holds, so repeated Undos go back through every change the journal holds.
//
// # Retention
//
// Prune applies the machine's retention (the `tego gc` pass, and a `tego run` start's once per gc_interval;
// internal/cli) to the journal, and removes a line only when no reader of the journal can need it: for every line left
// and every run still in the ledger root, History, Undo and its lift of live blocks, a run's pending changes, Apply now
// and the feed answer as before the prune. Of each contract it keeps every line from the first one on, in the journal's
// order, that was written within the retention or after the oldest run still in the ledger root started (a run's page
// lists the changes made since its start), that names a run still there (a live block it placed, which an Undo of
// another change must not lift while this one stands, or the run it was made from), that a revert left undid (the
// revert's words name it) or that undid a line left, or, while the contract's file is there, that is its KeepChanges-th
// (20th) newest change still standing (so Undo goes that far back); and, while the file is there, its newest creation.
// A live line stays or goes with the line it belongs to, and a torn line goes. It rewrites journal.jsonl under
// journal.lock (a new file renamed over it; one a crashed prune left goes on the next), then removes the blobs no line
// left names once older than the retention, and the lock files of contracts with no line left, each under its own
// flock. It lists the runs and looks at the contracts' files before it takes a lock, a few at once, waiting at most a
// few seconds, and at most half of what is left of its context's time, for a file that does not answer (a stale
// mount): such a file counts as there, its lines stay, and the prune, done with the rest, says which (ErrNotLooked).
// Cancellation is checked between stages and cleanup entries and before taking journal.lock. Once held, the
// journal read, filter and rewrite finish as one operation, even after expiry. Temp cleanup precedes that lock.
// Another filesystem operation already in progress also finishes. A blocked kernel call can delay return
// indefinitely. Completed counts are returned with the context error; the journal stays consistent and leftover
// cleanup waits for the next pass.
// Everything it touches, those looks included, it touches with the credentials of the thread that called it. A
// journal holding a line this version does not read, or two lines of one id, is left whole. A root pass prunes the
// invoking user's journal on a thread holding that user's ids (internal/cli, sys.RunAs); a journal of another user is
// ErrOtherOwner. Only the machine's ledger root is pruned: a journal `tego rule` keeps under another root (a run
// directory given by its path) is not.
//
// Imports: internal/check/rule, internal/ledger, internal/platform/sys, internal/registry, pkg/spec/agent, pkg/spec/config,
// pkg/spec/identity, pkg/spec/record, golang.org/x/sys/unix and the standard library.
// Must not import: internal/control, internal/runtime, internal/policy, internal/cli.
package rulefile
