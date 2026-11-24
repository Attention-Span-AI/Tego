// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

func TestMissingRecordDuringActiveRead(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "warm"}[warm], func(t *testing.T) {
			root := t.TempDir()
			id := "r-aaaaaaaa-0000000000002-harmxx"
			writeRun(t, root, id, line(id, "Agent", 0, time.Now(), "ask", `"ask_id":"waiting","hold":"exec"`), line(id, "Agent", 1, time.Now(), "refused", `"op":"exec","target":"curl"`))
			s := Open(root)
			if warm {
				if _, err := s.Snapshot(); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, id, "events.jsonl")
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			st := s.state(id)
			j := s.claim(want{st: st, seen: fi})
			s.mu.Unlock()
			defer func() {
				s.mu.Lock()
				if st.reading != nil {
					ch := st.reading
					st.reading = nil
					close(ch)
				}
				s.mu.Unlock()
			}()
			_ = j // The decoder is deliberately held; a poll must publish its last immutable prefix.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			type result struct {
				snap *Snapshot
				err  error
			}
			done := make(chan result, 1)
			go func() { snap, err := s.snapshot(false); done <- result{snap, err} }()
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatal(got.err)
				}
				r := got.snap.Find(id)
				if r == nil || !strings.Contains(r.ReadError, "its record file is missing") {
					t.Fatalf("active recorded file disappeared: %+v", got.snap)
				}
				if warm && (r.Refusals != 1 || len(r.Pending) != 1) {
					t.Fatal("poll discarded its known prefix")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("poll waited for the active decoder")
			}
		})
	}
}

func TestMissingRecordsReadChainOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := ledger.DefaultAnchorPath(filepath.Join(root, "r-unused"))
	if err := ledger.NewFileChainAnchor(anchor).Append("r-aaaaaaaa-0000000000001-cleanx", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"r-aaaaaaaa-0000000000002-harmxx", "r-aaaaaaaa-0000000000003-thirdx", "r-aaaaaaaa-0000000000004-fourth"} {
		if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
			t.Fatal(err)
		}
	}
	var reads atomic.Int64
	anchorMu.Lock()
	before := anchorHeadsOf
	anchorHeadsOf = func(path string, runs []string) (map[string]ledger.AnchorHead, os.FileInfo) {
		if path == anchor {
			reads.Add(1)
		}
		return before(path, runs)
	}
	anchorMu.Unlock()
	t.Cleanup(func() { anchorMu.Lock(); anchorHeadsOf = before; anchorMu.Unlock() })
	snap, err := Open(root).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReadError != "" || len(snap.Runs) != 0 {
		t.Fatalf("empty directories acquired fictitious recorded evidence: %+v", snap)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("missing run directories read the same chain %d times, want one", n)
	}
}

func TestKnownRequestsSurviveNonRegularRecord(t *testing.T) {
	root := t.TempDir()
	id := "r-aaaaaaaa-0000000000002-harmxx"
	writeRun(t, root, id, line(id, "Agent", 0, time.Now(), "ask", `"ask_id":"waiting","hold":"exec"`))
	s := Open(root)
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, id, "events.jsonl")
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Find(id)
	if r == nil || r.ReadError == "" || len(r.Pending) != 1 {
		t.Fatalf("known waiting request was erased by a read failure: %+v", r)
	}
	r, err = s.Run(id)
	if err != nil || r == nil || r.ReadError == "" || len(r.Pending) != 1 {
		t.Fatalf("run page erased a known request: %+v %v", r, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	snap, err = s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	r = snap.Find(id)
	if r == nil || r.ReadError != "" || len(r.Pending) != 1 {
		t.Fatalf("restored record did not recover: %+v", r)
	}
}

func TestMissingRecordUnreadableAnchorStaysUnknown(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	id := "r-aaaaaaaa-0000000000002-harmxx"
	if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
		t.Fatal(err)
	}
	anchor := ledger.DefaultAnchorPath(filepath.Join(root, id))
	if err := os.Mkdir(anchor, 0700); err != nil {
		t.Fatal(err)
	}
	s := Open(root)
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReadError == "" || snap.Find(id) == nil {
		t.Fatal("unreadable evidence was guessed to mean an empty run")
	}
	if err := os.Remove(anchor); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchor, nil, 0600); err != nil {
		t.Fatal(err)
	}
	snap, err = s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReadError != "" || snap.Find(id) != nil {
		t.Fatal("a failed evidence read was incorrectly remembered as positive evidence")
	}
}
