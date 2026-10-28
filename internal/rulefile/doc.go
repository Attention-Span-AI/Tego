// SPDX-License-Identifier: Apache-2.0

// Package rulefile is the I/O half of changing a contract (internal/check/rule is the pure half): it finds one event of
// a run and the contract file the run compiled (FindIn; FindAtIn with a hint of where the line starts, which it checks and
// falls back to FindIn's scan when it does not hold), reads a contract through its guards (Read), replaces it
// with new text (Found.Write, Replace), writes a new one where there is no file (Create) and records every replacement
// in a journal that history and Undo read (ReadJournal, History, Revert, Undo). `tego rule` and the dashboard both
// write through it, so the two write the same bytes under the same checks.
//
// # Guards
//
// The contract's directory is resolved once (a home reached through a symlink still works), refused when it is under
// the ledger root or tego's home, then opened with openat2 RESOLVE_NO_SYMLINKS and pinned: every later open, rename
// and sync is relative to that descriptor, so a directory swapped for a symlink afterwards changes nothing here. The
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
// file's mode, fsync'ed), reads the file once more to catch an editor that does not take the lock, renames the
// temporary file over it with renameat and fsyncs the directory. Then it appends the journal line.
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
//	summary      the change in words; sentences: its rules' "before → after" sentences; direction: narrows,
//	             widens or mixed
//	reverts      (revert) the id it undid
//	of           (live) the change id the outcomes belong to
//	live         [{"run","block","ok","err","lift"}]: live blocks placed on running runs; "lift": true marks one an
//	             Undo lifted (removed) from its run, recorded on the revert: of the blocks the undone change had
//	             placed (an older reader that ignores "lift" reads such a line as a block placed)
//
// A contract changed after a run started is "pending for the next run" when the journal holds a change or revert of
// that contract with at after the run's start (the dashboard reads it so). Revert(id) writes back the text before
// id only while the file holds id's new_sha256, so it never loses a later change; Undo reverts the newest change not
// yet undone whose new_sha256 the file holds, so repeated Undos go back any number of changes.
//
// Imports: internal/check/rule, internal/ledger, internal/platform/sys, pkg/spec/agent, pkg/spec/config,
// pkg/spec/record, golang.org/x/sys/unix and the standard library.
// Must not import: internal/control, internal/runtime, internal/policy, internal/cli.
package rulefile
