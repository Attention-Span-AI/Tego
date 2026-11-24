// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorePublishesColdAndWarmReadErrors(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, obstacle := range []string{"directory", "symlink"} {
			name := "cold " + obstacle
			if warm {
				name = "warm " + obstacle
			}
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				const run = "r-aaaa-0001-readerr"
				t0 := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
				writeRun(t, root, run, line(run, "sh", 0, t0, "run_start", `"tier":"landlock"`))
				store := Open(root)
				st := store.state(run)
				before := uint64(0)
				if warm {
					r, err := store.Run(run)
					if err != nil {
						t.Fatal(err)
					}
					before = r.Rev
					appendLines(t, root, run, line(run, "sh", 1, t0.Add(time.Second), "refused", `"op":"open","target":"/private","rule":"unmatched"`))
				}
				path := filepath.Join(root, run, "events.jsonl")
				seen, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				// Freeze the directory scan's regular-file result, then replace the
				// source before opening it. No timing or permission assumption is used.
				saved := path + ".saved"
				if err := os.Rename(path, saved); err != nil {
					t.Fatal(err)
				}
				if obstacle == "directory" {
					err = os.Mkdir(path, 0700)
				} else {
					err = os.Symlink(saved, path)
				}
				if err != nil {
					t.Fatal(err)
				}
				store.mu.Lock()
				store.bring([]want{{st: st, seen: seen}}, true)
				failed := st.pub
				store.mu.Unlock()
				if failed.ReadError == "" || failed.Bad != 0 || failed.Rev <= before {
					t.Errorf("reader failure missing or counted as decoder damage: error=%q bad=%d rev=%d previous=%d", failed.ReadError, failed.Bad, failed.Rev, before)
				}
				if warm && failed.Lines != 1 {
					t.Errorf("warm failure discarded known prefix: %d lines", failed.Lines)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(saved, path); err != nil {
					t.Fatal(err)
				}
				recovered, err := store.Run(run)
				if err != nil {
					t.Fatal(err)
				}
				wantLines := 1
				if warm {
					wantLines = 2
				}
				if recovered.ReadError != "" || recovered.Bad != 0 || recovered.Rev <= failed.Rev || recovered.Lines != wantLines {
					t.Errorf("successful read did not restore complete state: error=%q bad=%d rev=%d failedRev=%d lines=%d", recovered.ReadError, recovered.Bad, recovered.Rev, failed.Rev, recovered.Lines)
				}
			})
		}
	}
}

func TestEvictedWindowReadErrorNeedsActualRetry(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaa-0001-windowerr"
	writeRun(t, root, run, line(run, "sh", 0, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), "run_start", `"tier":"landlock"`))
	store := Open(root)
	initial, err := store.Run(run)
	if err != nil {
		t.Fatal(err)
	}
	st := initial.st
	actual := st.path
	blocked := filepath.Join(root, run, "blocked")
	if err := os.Symlink(actual, blocked); err != nil {
		t.Fatal(err)
	}
	// Preserve the real file and its exact identity. Only the reader's path is
	// replaced, so an unchanged-file shortcut would falsely clear the failure.
	store.mu.Lock()
	store.resident -= st.bytes
	st.bytes, st.resident, st.b.Events = 0, false, nil
	st.path = blocked
	st.publish(initial.Rev)
	store.mu.Unlock()
	if got := store.lines(st); len(got) != 0 {
		t.Fatalf("failed window returned %d events", len(got))
	}
	failed := st.pub
	if failed.ReadError == "" || failed.Bad != 0 || failed.Rev <= initial.Rev {
		t.Errorf("window failure missing reason: error=%q bad=%d rev=%d", failed.ReadError, failed.Bad, failed.Rev)
	}
	seen, err := os.Lstat(actual)
	if err != nil {
		t.Fatal(err)
	}
	if idOf(seen) != st.file {
		t.Fatal("fixture changed the source-file identity")
	}
	// A repeat failure with unchanged metadata must stay failed, rather than
	// passing through read's no-I/O return and declaring the record complete.
	store.mu.Lock()
	store.bring([]want{{st: st, seen: seen}}, true)
	repeated := st.pub
	st.path = actual
	store.bring([]want{{st: st, seen: seen}}, true)
	recovered := st.pub
	store.mu.Unlock()
	if repeated.ReadError == "" {
		t.Error("unchanged metadata erased the error without reading")
	}
	if recovered.ReadError != "" || recovered.Bad != 0 || recovered.Rev <= failed.Rev || len(recovered.Events) != 1 {
		t.Errorf("actual retry failed to restore state: error=%q bad=%d rev=%d events=%d", recovered.ReadError, recovered.Bad, recovered.Rev, len(recovered.Events))
	}
}

func TestSnapshotDisclosesUnreadableRunCandidates(t *testing.T) {
	for _, obstacle := range []string{"directory", "symlink"} {
		t.Run(obstacle, func(t *testing.T) {
			root := t.TempDir()
			const unseen = "r-aaaa-0001-unread"
			dir := filepath.Join(root, unseen)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "events.jsonl")
			var err error
			switch obstacle {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink("absent-target", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			// A later error must not replace the first source failure.
			second := filepath.Join(root, "r-aaaa-0003-second")
			if err := os.Mkdir(second, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(second, "events.jsonl"), 0700); err != nil {
				t.Fatal(err)
			}
			const valid = "r-aaaa-0002-validx"
			writeRun(t, root, valid, line(valid, "sh", 0, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), "run_start", `"tier":"landlock"`))
			snap, err := Open(root).Snapshot()
			if err != nil {
				t.Fatalf("readable runs must remain available: %v", err)
			}
			if snap.ReadError == "" || !strings.Contains(snap.ReadError, unseen) {
				t.Errorf("candidate silently disappeared: error=%q visible=%d", snap.ReadError, len(snap.Runs))
			}
			if len(snap.Runs) != 1 || snap.Runs[0].ID != valid {
				t.Errorf("unreadable candidate became a completed run: %+v", snap.Runs)
			}
		})
	}
}

func TestWindowPrefixCannotClearSuffixReadError(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaa-0001-suffixerr"
	t0 := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, run, line(run, "sh", 0, t0, "run_start", `"tier":"landlock"`))
	store := Open(root)
	initial, err := store.Run(run)
	if err != nil {
		t.Fatal(err)
	}
	appendLines(t, root, run, line(run, "sh", 1, t0.Add(time.Second), "refused", `"op":"open","target":"/private","rule":"unmatched"`))
	st := initial.st
	seen, err := os.Lstat(st.path)
	if err != nil {
		t.Fatal(err)
	}
	// This is the state after an appended-file reader failed before taking the
	// suffix: its new file identity is known, but off still bounds the old prefix.
	store.mu.Lock()
	store.resident -= st.bytes
	st.file = idOf(seen)
	st.bytes, st.resident, st.b.Events = 0, false, nil
	st.b.ReadError = "reading appended record failed"
	st.publish(initial.Rev)
	store.mu.Unlock()
	if got := store.lines(st); len(got) != 1 {
		t.Fatalf("expected rehydrated prefix, got %d events", len(got))
	}
	if st.pub.ReadError == "" {
		t.Error("reading the old prefix falsely cleared the missing suffix")
	}
	store.mu.Lock()
	store.bring([]want{{st: st, seen: seen}}, true)
	recovered := st.pub
	store.mu.Unlock()
	if recovered.ReadError != "" || recovered.Lines != 2 || recovered.Refusals != 1 {
		t.Errorf("complete suffix retry failed: error=%q lines=%d refusals=%d", recovered.ReadError, recovered.Lines, recovered.Refusals)
	}
}

func TestSnapshotReadErrorMovesRevision(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaa-0001-validx"
	writeRun(t, root, run, line(run, "sh", 0, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), "run_start", `"tier":"landlock"`))
	store := Open(root)
	initial, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "r-aaaa-0002-missing")
	if err := os.Mkdir(missing, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(missing, "events.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	failed, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if failed.ReadError == "" || failed.Rev <= initial.Rev {
		t.Errorf("unreadable candidate did not invalidate page state: error=%q rev=%d initial=%d", failed.ReadError, failed.Rev, initial.Rev)
	}
	repeated, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if repeated.ReadError != failed.ReadError || repeated.Rev != failed.Rev {
		t.Errorf("unchanged failed scan changed: %+v then %+v", failed, repeated)
	}
	if err := os.RemoveAll(missing); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ReadError != "" || recovered.Rev <= failed.Rev || recovered.Find(run) != initial.Find(run) {
		t.Errorf("successful scan did not invalidate the failure state: error=%q rev=%d failedRev=%d", recovered.ReadError, recovered.Rev, failed.Rev)
	}
}

// TestRunWithoutEventsFileIsNotAReadError: the ledger writer creates the run directory and takes its lock before
// it creates events.jsonl. That run has recorded nothing, so the scan skips it as before instead of reporting a
// reader failure that would turn every dashboard count into "could not read" at each run start.
func TestRunWithoutEventsFileIsNotAReadError(t *testing.T) {
	root := t.TempDir()
	const valid = "r-aaaa-0002-validx"
	writeRun(t, root, valid, line(valid, "sh", 0, time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC), "run_start", `"tier":"landlock"`))
	if err := os.Mkdir(filepath.Join(root, "r-aaaa-0003-starting"), 0700); err != nil {
		t.Fatal(err)
	}
	snap, err := Open(root).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReadError != "" || len(snap.Runs) != 1 || snap.Runs[0].ID != valid {
		t.Errorf("a starting run with no events file yet: error=%q runs=%d", snap.ReadError, len(snap.Runs))
	}
}

// TestStoreSaysHowToGiveBackATakenRunDirectory (A48): a run whose agent took its directory's owner rights is listed with
// the reason, which names the state and the one command that gives the owner's rights back.
func TestStoreSaysHowToGiveBackATakenRunDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through any mode")
	}
	root := t.TempDir()
	const run = "r-aaaaaaaa-0000000000009-taken1"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, run, line(run, "sh", 0, t0, "run_start", `"tier":"landlock"`))
	dir := filepath.Join(root, run)
	if err := os.Chmod(filepath.Join(dir, "events.jsonl"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "events.jsonl"), 0o600) })
	r, err := Open(root).Run(run)
	if err != nil {
		t.Fatal(err)
	}
	want := "chmod -R u+rwX '" + dir + "'"
	if !strings.Contains(r.ReadError, want) || !strings.Contains(r.ReadError, "events.jsonl has mode 0000") {
		t.Errorf("read error %q lacks the state and %q", r.ReadError, want)
	}
}
