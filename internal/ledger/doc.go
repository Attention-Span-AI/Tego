// SPDX-License-Identifier: Apache-2.0

// Package ledger is the only code that writes events.jsonl and the only store of the product: one run
// directory per run, an append-only event log, a per-run content-addressed blob store, the run lock, the
// host-wide chain anchor, a torn-line-tolerant reader and gc.
//
// Writer (Open, WriteRunStart, Append, Blob, Close) owns the run directory: 0700 dir, flock(LOCK_EX|LOCK_NB)
// on lock, events.jsonl opened O_APPEND 0600. Append stamps run, agent and ts (wall clock), stamps mono_ns
// (CLOCK_MONOTONIC) when the producer left it zero, assigns seq, prev and id, and issues exactly one write(2)
// per line; it never fsyncs. Close appends run_end, fsyncs once, and anchors the final id in the chain.log
// its caller names (the invoking user's ~/.tego/chain.log in the product, beside the ledger root for an
// account with no home; <ledger_root>/../chain.log when none is named), then, as root, hands the run
// directory to the ledger root's owner (handover.go). As root, every directory this package writes into
// is reached one component at a time and a symlink in a directory another user can change is refused;
// the Writer holds its run directory open from Open to Close and names every file in it relative to that
// descriptor, O_NOFOLLOW, so what is renamed above the run directory while it is live does not move where
// the Writer writes. A store from NewBlobRepository (a uprobe source's, beside the Writer) walks to blobs/
// by path for every blob, refusing links the same way, so after the user replaces their ledger root, or
// renames run directories inside it, during a live root run, that store's blobs land in whatever real
// directory the user's tree then names (one the user owns, or a root-owned run directory already in it),
// never through a link (record-ledger.md §3, residual). Only what a call itself creates is handed to
// another uid.
// Reopening a run directory that a dead process left behind resumes the chain, discarding a torn tail and
// recording a gap for it, so gc's orphan sweep can end the run.
//
// RedactStage and SplitBlobsStage are the pipeline stages internal/runtime composes ahead of Append: the header
// allow-list that keeps credentials off disk (R9) and the 4 KiB blob split (R10), which stores a request body's
// conversation by the hash of its elements' groups rather than whole (R11, messages.go). Append itself trusts
// its input (I2).
//
// Reader (OpenReader, Lines, Iter, Verify, State, Blob, Body) reads a run without taking the lock: an unterminated
// last line that does not decode is torn and ignored; a malformed line anywhere else is a hard error. State
// derives running, ended, lost or empty from the file and the lock alone (I7). Body returns an event's body in
// whichever form it was stored, a splice rebuilt and checked against its recorded sha256. Verify re-hashes the chain,
// holds every line to the run its directory names, and checks its head against chain.log; VerifyRunDir adds
// the anchored run whose ledger is gone (`tego events --verify`). Bind attaches a Binder to the next pass of Lines:
// it checks each line as Verify does and hashes the bytes read, so `tego receipt --json` binds the receipt to exactly
// the lines its numbers came from (Bound).
//
// Follower (Follow, Lines) tails a live run: it reads each byte once from a Cursor, checks every line as it
// arrives with the check Verify makes (runCheck), holds a half-written last line while the lock is held, ends
// after run_end once the lock is free (ErrRunLost when there is none), and keeps one buffer of at most
// MaxLineBytes. LiveWatch (WatchLive, Changes) reports runs entering and leaving the live index, following at
// most MaxLiveFollowed. Both wake on inotify with a 1 s poll backstop (wake.go).
//
// Usage is the one decode of an ssl_response's token accounting that the live budget and measure share.
//
// RunRepository, BlobRepository and ChainAnchor are the narrow contracts internal/check, internal/cli and
// internal/doctor use over a ledger_root; GC applies retention over them.
//
// Linux only: flock, O_APPEND write atomicity and CLOCK_MONOTONIC are what the design rests on.
//
// Imports: pkg/spec/record, golang.org/x/sys/unix (O_PATH and fstatat for the walk), standard library.
// Must not import: internal/runtime, internal/check, any capture/derive/enforce package.
package ledger
