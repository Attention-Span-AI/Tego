// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// closedRun writes a run of n body events, closes it into anchor and returns its directory.
func closedRun(t *testing.T, n int) (string, *memAnchor) {
	t.Helper()
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, n)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dir, anchor
}

// verifyErr runs Verify against anchor and returns its error.
func verifyErr(t *testing.T, dir string, anchor ChainAnchor) (VerifyReport, error) {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	return r.Verify(context.Background(), anchor)
}

// TestVerifyAnchoredRun: an untouched closed run verifies end to end against its anchor.
func TestVerifyAnchoredRun(t *testing.T) {
	dir, anchor := closedRun(t, 3)
	rep, err := verifyErr(t, dir, anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Anchored || !rep.Started || !rep.Ended || rep.Lines != 5 || rep.Run != testRef.ID {
		t.Fatalf("%+v", rep)
	}
}

// TestVerifyCatchesATruncatedTail is I3 against the anchor: dropping run_end and the events before
// it leaves a chain that is internally intact and reads as a lost run. Verify consulted the anchor
// only for a ledger that still ended in run_end, so this truncation verified clean.
func TestVerifyCatchesATruncatedTail(t *testing.T) {
	for _, drop := range []int{1, 3, 5} {
		dir, anchor := closedRun(t, 3)
		path := filepath.Join(dir, EventsFile)
		lines := bytes.SplitAfter(readFile(t, path), []byte("\n"))
		kept := bytes.Join(lines[:len(lines)-1-drop], nil) // SplitAfter leaves one empty tail element
		if err := os.WriteFile(path, kept, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := verifyErr(t, dir, anchor)
		if !errors.Is(err, ErrUnverified) || !errors.Is(err, ErrCorruptChain) {
			t.Fatalf("drop %d lines: Verify = %v, want ErrUnverified and ErrCorruptChain", drop, err)
		}
	}
}

// TestVerifyCatchesATamperedLine: one byte changed in a middle line breaks the chain (R2).
func TestVerifyCatchesATamperedLine(t *testing.T) {
	dir, anchor := closedRun(t, 3)
	path := filepath.Join(dir, EventsFile)
	b := readFile(t, path)
	i := bytes.Index(b, []byte(`"why":"e1"`))
	if i < 0 {
		t.Fatal("no e1 gap line")
	}
	b[i+len(`"why":"e`)] = '9'
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyErr(t, dir, anchor); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify = %v, want ErrUnverified", err)
	}
}

// TestVerifyMissingAnchorIsDistinct is E29: an ended run chain.log has no line for is reported as a
// missing anchor, never as a broken chain, and a run that has not ended yet owes no anchor.
func TestVerifyMissingAnchorIsDistinct(t *testing.T) {
	dir, _ := closedRun(t, 1)
	_, err := verifyErr(t, dir, &memAnchor{})
	if !errors.Is(err, ErrAnchorMissing) || !errors.Is(err, ErrUnverified) || errors.Is(err, ErrCorruptChain) {
		t.Fatalf("Verify = %v, want ErrAnchorMissing and ErrUnverified, not ErrCorruptChain", err)
	}
	w, live, _ := openTestWriter(t)
	startRun(t, w, 1)
	defer func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()
	if rep, err := verifyErr(t, live, &memAnchor{}); err != nil || rep.Ended || rep.Anchored {
		t.Fatalf("a live run: %+v %v", rep, err)
	}
}

// TestVerifyReadErrorIsNotUnverified: an anchor that cannot be read is a read failure, which says
// nothing about the ledger, so it never wraps ErrUnverified.
func TestVerifyReadErrorIsNotUnverified(t *testing.T) {
	dir, _ := closedRun(t, 1)
	unreadable := filepath.Join(t.TempDir(), "chain.log")
	if err := os.Mkdir(unreadable, 0o700); err != nil { // a directory where the file should be: refused, not read
		t.Fatal(err)
	}
	_, err := verifyErr(t, dir, NewFileChainAnchor(unreadable))
	if err == nil || errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify = %v, want a read error without ErrUnverified", err)
	}
}

// TestVerifyBytesAfterRunEnd: a torn tail is tolerated because a writer that died mid-write(2) leaves
// one (E6), but a run that wrote run_end did not die mid-write — bytes after it were put there by
// something else, and the ledger does not verify.
func TestVerifyBytesAfterRunEnd(t *testing.T) {
	dir, anchor := closedRun(t, 1)
	f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"seq":9`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := verifyErr(t, dir, anchor); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify = %v, want ErrUnverified", err)
	}
	if _, err := verifyErr(t, dir, nil); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify without an anchor = %v, want ErrUnverified", err)
	}
}

// TestVerifyIsBoundToTheDirectorysRun: a ledger another anchored run wrote, copied over this run's
// events.jsonl, is an intact chain that its own anchor line vouches for. Verify took the run id from
// the ledger's first line, so it verified — as the other run. The run verified is the one the
// directory names; a line of any other run is ErrRunMismatch, and this run's anchor is the one read.
func TestVerifyIsBoundToTheDirectorysRun(t *testing.T) {
	dir, anchor := closedRun(t, 2)
	other := record.RunRef{ID: runID(fixedStart, "zz9zz9"), Agent: testRef.Agent}
	otherDir := filepath.Join(filepath.Dir(dir), other.ID)
	w, err := Open(otherDir, other, WithAnchor(anchor), WithClock(newStepClock(fixedStart, 5_000_000_000, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, EventsFile), readFile(t, filepath.Join(otherDir, EventsFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := verifyErr(t, dir, anchor)
	if !errors.Is(err, ErrUnverified) || !errors.Is(err, ErrRunMismatch) || rep.Run != testRef.ID {
		t.Fatalf("a swapped ledger: %+v %v, want ErrRunMismatch for %s", rep, err, testRef.ID)
	}
	// A directory not named by a run id (a copy an operator made) takes the id from the first line,
	// and still refuses a ledger whose lines do not all belong to that run.
	copyDir := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, EventsFile), readFile(t, filepath.Join(otherDir, EventsFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := verifyErr(t, copyDir, anchor); err != nil || rep.Run != other.ID || !rep.Anchored {
		t.Fatalf("a copied ledger under another name: %+v %v", rep, err)
	}
}

// TestVerifyRunDirMissingLedger: a run chain.log anchors whose events.jsonl — or whole directory — is
// gone is ErrLedgerMissing, a finding; one no anchor line vouches for is the plain not-exist error.
func TestVerifyRunDirMissingLedger(t *testing.T) {
	dir, anchor := closedRun(t, 1)
	if _, err := VerifyRunDir(context.Background(), dir, anchor); err != nil {
		t.Fatalf("an intact run: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, EventsFile)); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyRunDir(context.Background(), dir, anchor)
	if !errors.Is(err, ErrUnverified) || !errors.Is(err, ErrLedgerMissing) || rep.Run != testRef.ID {
		t.Fatalf("events.jsonl removed: %+v %v, want ErrLedgerMissing", rep, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRunDir(context.Background(), dir, anchor); !errors.Is(err, ErrLedgerMissing) {
		t.Fatalf("the run directory removed: %v, want ErrLedgerMissing", err)
	}
	_, err = VerifyRunDir(context.Background(), dir, &memAnchor{})
	if !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrUnverified) {
		t.Fatalf("no ledger and no anchor line: %v, want the not-exist error alone", err)
	}
}

// TestVerifyNamesTheRunByTheDirectoryItself: a path whose last component is no run id — "." inside the
// run directory, or a link to it under another name — names the run directory's own run, so a swapped ledger verified through
// either is still ErrRunMismatch for the directory's run, and a deleted one is still ErrLedgerMissing. The
// name was the path's last component, "." or the link's, which is no run id, and Verify then took the id
// the swapped ledger claimed.
func TestVerifyNamesTheRunByTheDirectoryItself(t *testing.T) {
	paths := map[string]func(t *testing.T, dir string) string{
		".": func(t *testing.T, dir string) string { t.Chdir(dir); return "." },
		"a link under another name": func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "latest")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			dir, anchor := closedRun(t, 2)
			other := record.RunRef{ID: runID(fixedStart, "zz9zz9"), Agent: testRef.Agent}
			otherDir := filepath.Join(filepath.Dir(dir), other.ID)
			w, err := Open(otherDir, other, WithAnchor(anchor), WithClock(newStepClock(fixedStart, 5_000_000_000, time.Millisecond)))
			if err != nil {
				t.Fatal(err)
			}
			startRun(t, w, 1)
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, EventsFile), readFile(t, filepath.Join(otherDir, EventsFile)), 0o600); err != nil {
				t.Fatal(err)
			}
			p := path(t, dir)
			rep, err := verifyErr(t, p, anchor)
			if !errors.Is(err, ErrRunMismatch) || rep.Run != testRef.ID {
				t.Fatalf("a swapped ledger through %q: %+v %v, want ErrRunMismatch for %s", p, rep, err, testRef.ID)
			}
			if err := os.Remove(filepath.Join(dir, EventsFile)); err != nil {
				t.Fatal(err)
			}
			if rep, err := VerifyRunDir(context.Background(), p, anchor); !errors.Is(err, ErrLedgerMissing) || rep.Run != testRef.ID {
				t.Fatalf("a deleted ledger through %q: %+v %v, want ErrLedgerMissing", p, rep, err)
			}
		})
	}
}

// TestVerifyARunDirectoryReplacedByALink: runs/<A> replaced by a link to runs/<B>, another anchored run,
// is A's record gone, and every path that names A verifies A — ErrRunMismatch against B's lines, or
// ErrLedgerMissing when the link's target holds no ledger — never B's anchored ledger as A's. That holds
// by path, relative to the ledger root, through "." after a cd through the link, and through a link to the
// link, where the chain stops at the first name that is a run id. Resolving every symlink before taking
// the name verified B clean for each of them.
func TestVerifyARunDirectoryReplacedByALink(t *testing.T) {
	paths := map[string]func(t *testing.T, root, dirA string) string{
		"by path":              func(_ *testing.T, _, dirA string) string { return dirA },
		"from the ledger root": func(t *testing.T, root, dirA string) string { t.Chdir(root); return filepath.Base(dirA) },
		"through . after a cd": func(t *testing.T, _, dirA string) string { t.Chdir(dirA); return "." },
		// Spelled raw: filepath.Join would clean it down to dirA before RunDirPath saw it, and the case would
		// repeat "by path". Uncleaned, the kernel resolves <A>/blobs/.. through the link to B, and the lexical
		// cleaning RunDirPath does (record-ledger.md §4) is what keeps the run A.
		"through a subdir's ..": func(t *testing.T, _, dirA string) string { return dirA + "/" + BlobsDir + "/.." },
		"through a link to the link": func(t *testing.T, root, dirA string) string {
			// A relative target, read from the directory that holds the link as the kernel reads it.
			links := filepath.Join(filepath.Dir(root), "links")
			if err := os.Mkdir(links, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(links, "latest")
			if err := os.Symlink(filepath.Join("..", filepath.Base(root), filepath.Base(dirA)), link); err != nil {
				t.Fatal(err)
			}
			return link
		},
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			dirA, anchor := closedRun(t, 2)
			root := filepath.Dir(dirA)
			b := record.RunRef{ID: runID(fixedStart, "zz9zz9"), Agent: testRef.Agent}
			dirB := filepath.Join(root, b.ID)
			w, err := Open(dirB, b, WithAnchor(anchor), WithClock(newStepClock(fixedStart, 5_000_000_000, time.Millisecond)))
			if err != nil {
				t.Fatal(err)
			}
			startRun(t, w, 1)
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(dirA); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(b.ID, dirA); err != nil {
				t.Fatal(err)
			}
			p := path(t, root, dirA)
			if got := RunDirPath(p); filepath.Base(got) != testRef.ID {
				t.Errorf("RunDirPath(%q) = %q, want a path ending in %s", p, got, testRef.ID)
			}
			rep, err := VerifyRunDir(context.Background(), p, anchor)
			if !errors.Is(err, ErrRunMismatch) || rep.Run != testRef.ID || rep.Anchored {
				t.Fatalf("A through %q: %+v %v, want ErrRunMismatch for %s", p, rep, err, testRef.ID)
			}
			if err := os.Remove(filepath.Join(dirB, EventsFile)); err != nil {
				t.Fatal(err)
			}
			if rep, err := VerifyRunDir(context.Background(), p, anchor); !errors.Is(err, ErrLedgerMissing) || rep.Run != testRef.ID {
				t.Fatalf("A through %q with no ledger at the link's target: %+v %v, want ErrLedgerMissing for %s",
					p, rep, err, testRef.ID)
			}
		})
	}
}

// TestVerifyRefusesRunStructureViolations: run_start is line 0 and only line 0, and nothing follows run_end,
// even in a ledger with no anchor to catch the head mismatch (E29).
func TestVerifyRefusesRunStructureViolations(t *testing.T) {
	dir, _ := closedRun(t, 1)
	path := filepath.Join(dir, EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	last, err := record.Decode(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{1, 0} { // a gap, then a second run_start
		e, err := record.Decode(lines[idx])
		if err != nil {
			t.Fatal(err)
		}
		e.Seq, e.Prev = last.Seq+1, last.ID
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(append([]byte{}, data...), line...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyErr(t, dir, nil); !errors.Is(err, ErrUnverified) {
			t.Fatalf("line %d's kind after run_end: Verify = %v, want ErrUnverified", idx, err)
		}
	}
	// A ledger whose first line is not run_start.
	if err := os.WriteFile(path, append(append([]byte{}, lines[1]...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyErr(t, dir, nil); !errors.Is(err, ErrUnverified) {
		t.Fatalf("a first line that is not run_start: Verify = %v, want ErrUnverified", err)
	}
}
