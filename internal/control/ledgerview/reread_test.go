// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRereadRefusesChangedLine(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Split(data, []byte{"\n"[0]})[0]
	for _, tc := range []struct{ name, old, next, reason string }{
		{"null", `"plane":""`, `"plane":null`, "plane"},
		{"minor", `"record_minor":39`, `"record_minor":36`, "record_minor"},
		{"other-kind", `"v":1`, `"v":0`, "version"},
		{"other-timestamp", `"ts":`, `"ts":null,"ignored_ts":`, "timestamp"},
		{"other-syntax", `"v":1`, `"v":`, "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			var head struct {
				Run string `json:"run"`
			}
			if err := json.Unmarshal(start, &head); err != nil {
				t.Fatal(err)
			}
			run := head.Run
			original := start
			if strings.HasPrefix(tc.name, "other-") {
				original = []byte(line(run, "x", 0, time.Now(), "run_end", `"reason":"exit","exit_code":0`))
				original = bytes.TrimSpace(original)
			}
			writeRun(t, root, run, string(original)+"\n")
			snap, err := Open(root).Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			r := snap.Find(run)
			if r == nil || len(r.AllEvents()) != 1 {
				t.Fatalf("snapshot: %+v", r)
			}
			changed := bytes.Replace(original, []byte(tc.old), []byte(tc.next), 1)
			if bytes.Equal(original, changed) {
				t.Fatal("mutation did not fire")
			}
			if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), append(changed, "\n"...), 0600); err != nil {
				t.Fatal(err)
			}
			for _, order := range []Order{OldestFirst, NewestFirst} {
				for _, ledger := range []bool{false, true} {
					calls := 0
					snap.Each(Filter{Run: run, Ledger: ledger}, order, func(_ *Event, raw func() ([]byte, error)) bool {
						calls++
						b, err := raw()
						if err == nil || !strings.Contains(err.Error(), tc.reason) || len(b) != 0 {
							t.Errorf("export order=%d ledger=%t published refused line: %s, %v", order, ledger, b, err)
						}
						return true
					})
					if calls != 1 {
						t.Fatalf("export order=%d ledger=%t silently dropped line: %d", order, ledger, calls)
					}
				}
			}
			if view, err := Explain(root, r, r.AllEvents()[0].Seq); err == nil || !strings.Contains(err.Error(), tc.reason) || view != nil {
				t.Errorf("explain: %+v, %v", view, err)
			}
			if view, err := Line(root, run, r.AllEvents()[0].Seq); err == nil || !strings.Contains(err.Error(), tc.reason) || view != nil {
				t.Errorf("line: %+v, %v", view, err)
			}
		})
	}
}

func TestExportReportsMissingLedger(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaa-0001-reread"
	writeRun(t, root, run, line(run, "x", 0, time.Now(), "run_end", `"reason":"exit","exit_code":0`))
	snap, err := Open(root).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, run, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	for _, order := range []Order{OldestFirst, NewestFirst} {
		for _, ledger := range []bool{false, true} {
			calls := 0
			snap.Each(Filter{Run: run, Ledger: ledger}, order, func(_ *Event, raw func() ([]byte, error)) bool {
				calls++
				if b, err := raw(); err == nil || len(b) != 0 {
					t.Errorf("published missing file: %s, %v", b, err)
				}
				return true
			})
			if calls != 1 {
				t.Errorf("order=%d ledger=%t silently dropped unreadable file: %d", order, ledger, calls)
			}
		}
	}
}

func TestEvictedRereadReportsRefusal(t *testing.T) {
	for _, mode := range []string{"worker", "lazy"} {
		t.Run(mode, func(t *testing.T) {
			data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			var head struct {
				Run string `json:"run"`
			}
			if err := json.Unmarshal(bytes.Split(data, []byte{'\n'})[0], &head); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			writeRun(t, root, head.Run, string(data))
			store := Open(root)
			if _, err := store.Snapshot(); err != nil {
				t.Fatal(err)
			}
			defer func(before int64) { MaxResidentBytes = before }(MaxResidentBytes)
			MaxResidentBytes = 1
			appendLines(t, root, head.Run, line(head.Run, "fixture", 2, time.Now(), "gap", ""))
			snap, err := store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snap.Find(head.Run).Events != nil {
				t.Fatal("test did not evict the retained window")
			}
			path := filepath.Join(root, head.Run, "events.jsonl")
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := bytes.Replace(current, []byte(`"owner_known":true`), []byte(`"owner_known":null`), 1)
			if bytes.Equal(current, changed) {
				t.Fatal("mutation did not fire")
			}
			changed = append(changed, []byte(line(head.Run, "fixture", 3, time.Now(), "gap", ""))...)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "lazy" {
				// Root snapshots deliberately detach evicted runs. Use the actual Store
				// publication to exercise AllEvents' retained-window read.
				store.mu.Lock()
				published := store.runs[head.Run].pub
				store.mu.Unlock()
				if events := published.AllEvents(); len(events) != 0 {
					t.Errorf("published partial refused window: %d events", len(events))
				}
				store.mu.Lock()
				latest := store.runs[head.Run].pub
				store.mu.Unlock()
				if !strings.Contains(latest.StartError, "owner_known") || latest.EffectiveHash != "" || latest.BaselineSHA256 != "" {
					t.Errorf("lazy publication lost refusal: %s", latest.StartError)
				}
			}
			r, readErr := LoadRun(root, head.Run)
			if readErr != nil {
				if !strings.Contains(readErr.Error(), "owner_known") {
					t.Errorf("wrong refusal: %v", readErr)
				}
			} else if r == nil || !strings.Contains(r.StartError, "owner_known") || r.EffectiveHash != "" || r.BaselineSHA256 != "" {
				t.Errorf("rehydration lost refusal: run=%v", r != nil)
			}

			snap, err = store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			r = snap.Find(head.Run)
			if !strings.Contains(r.StartError, "owner_known") || r.EffectiveHash != "" || r.BaselineSHA256 != "" {
				t.Errorf("summary retained refused evidence: reason=%s effective=%s baseline=%s", r.StartError, r.EffectiveHash, r.BaselineSHA256)
			}
			calls := 0
			snap.Each(Filter{Run: head.Run}, OldestFirst, func(_ *Event, raw func() ([]byte, error)) bool {
				calls++
				if b, err := raw(); err == nil || !strings.Contains(err.Error(), "owner_known") || len(b) != 0 {
					t.Errorf("root export lost retained refusal: %s, %v", b, err)
				}
				return true
			})
			if calls != 1 {
				t.Errorf("root export silently dropped retained refusal: %d callbacks", calls)
			}
			if view, err := Explain(root, r, 0); err == nil || !strings.Contains(err.Error(), "owner_known") || view != nil {
				t.Errorf("root detail lost retained refusal: %+v, %v", view, err)
			}
		})
	}
}

func TestExplainRefusesChangedPreviousLine(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Run string `json:"run"`
	}
	if err := json.Unmarshal(bytes.Split(data, []byte{'\n'})[0], &head); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeRun(t, root, head.Run, string(data))
	snap, err := Open(root).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(data, []byte(`"owner_known":true`), []byte(`"owner_known":null`), 1)
	if bytes.Equal(data, changed) {
		t.Fatal("mutation did not fire")
	}
	if err := os.WriteFile(filepath.Join(root, head.Run, "events.jsonl"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if view, err := Explain(root, snap.Find(head.Run), 1); err == nil || !strings.Contains(err.Error(), "owner_known") || view != nil {
		t.Fatalf("previous line refusal: %+v, %v", view, err)
	}
}
