// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

func TestBaselineRawSummaryRefuses(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := testutil.BaselineCases(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			r := Run{Kinds: map[string]int{}, EffectiveHash: "previous", BaselineSHA256: "previous"}
			r.add(fromRecord(tc.Event))
			if r.Bad != 1 || !strings.Contains(r.StartError, tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]) || r.EffectiveHash != "" || r.BaselineSHA256 != "" {
				t.Fatalf("invalid summary: %+v", r)
			}
		})
	}
}

func TestBaselineStoreRefusal(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	good := bytes.Split(data, []byte{'\n'})[0]
	bad := bytes.Replace(good, []byte(`"plane":""`), []byte(`"plane":null`), 1)
	for _, prior := range []bool{false, true} {
		t.Run(fmt.Sprint(prior), func(t *testing.T) {
			root := t.TempDir()
			run := "r-aaaa-0001-storex"
			first := bad
			if prior {
				first = good
			}
			writeRun(t, root, run, string(first)+"\n")
			store := Open(root)
			if _, err := store.Snapshot(); err != nil {
				t.Fatal(err)
			}
			if prior {
				r, err := LoadRun(root, run)
				if err != nil || r.EffectiveHash == "" || r.BaselineSHA256 == "" {
					t.Fatalf("prior evidence: %+v, %v", r, err)
				}
				f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write(append(bad, '\n'))
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("append: %v, %v", err, closeErr)
				}
			}
			r, err := LoadRun(root, run)
			if err != nil {
				t.Fatal(err)
			}
			if r.Bad != 1 || !strings.Contains(r.StartError, "plane") || r.EffectiveHash != "" || r.BaselineSHA256 != "" {
				t.Fatalf("Store lost refusal: %+v", r)
			}
		})
	}
}

func TestStoreRefreshRetainsEveryRefusal(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	good := bytes.Split(data, []byte{'\n'})[0]
	for _, shape := range []string{"syntax", "version", "duplicate-kind", "case-fold-kind"} {
		t.Run(shape, func(t *testing.T) {
			root := t.TempDir()
			id := "r-aaaa-0001-storex"
			nonStart := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})[1]
			initial := string(good) + "\n"
			if shape == "version" {
				initial += strings.Repeat(string(nonStart)+"\n", 2)
			}
			writeRun(t, root, id, initial)
			store := Open(root)
			if _, err := store.Snapshot(); err != nil {
				t.Fatal(err)
			}
			bad := bytes.Replace(nonStart, []byte(`"v":1`), []byte(`"v":0`), 1)
			reason := "version"
			if shape == "syntax" {
				bad = append(append([]byte{}, good[:len(good)-1]...), ',')
				reason = "malformed"
			}
			if shape == "duplicate-kind" {
				bad = append(bytes.Clone(good[:len(good)-1]), []byte(`,"kind":"fs"}`)...)
				reason = "duplicate"
			}
			if shape == "case-fold-kind" {
				bad = bytes.Replace(good, []byte(`"plane":""`), []byte(`"plane":null`), 1)
				bad = append(bytes.Clone(bad[:len(bad)-1]), []byte(`,"Kind":"fs"}`)...)
				reason = "plane"
			}
			// Two complete refused lines must both survive refresh and filtering.
			body := append(append(append([]byte{}, good...), '\n'), append(bad, '\n')...)
			body = append(body, append(bad, '\n')...)
			if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), body, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			if r.Bad != 2 {
				t.Errorf("bad=%d", r.Bad)
			}
			if shape != "version" && (r.EffectiveHash != "" || r.BaselineSHA256 != "" || r.StartError == "") {
				t.Errorf("kept prior baseline: start=%q effective=%q baseline=%q", r.StartError, r.EffectiveHash, r.BaselineSHA256)
			}
			snap, err := store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			refused := 0
			snap.Each(Filter{Run: id, Kinds: []string{"exec"}}, OldestFirst, func(_ *Event, raw func() ([]byte, error)) bool {
				_, err := raw()
				if err != nil {
					refused++
					if !strings.Contains(err.Error(), "byte offset") || !strings.Contains(strings.ToLower(err.Error()), reason) {
						t.Errorf("lost position or reason: %v", err)
					}
				}
				return true
			})
			if refused != 2 {
				t.Errorf("filtered export retained %d refusals, want 2", refused)
			}
		})
	}
}

func TestEvictedRefusalRevalidatesBytes(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	good, tail := string(lines[0])+"\n", string(lines[1])+"\n"
	for _, shape := range []string{"known", "changed", "oversized"} {
		t.Run(shape, func(t *testing.T) {
			root := t.TempDir()
			id := "r-aaaa-0001-storex"
			bad := strings.Replace(tail, `"v":1`, `"v":0`, 1)
			if shape == "oversized" {
				bad = strings.Repeat("x", maxLineBytes+1) + "\n"
			}
			writeRun(t, root, id, good+bad+tail)
			old := MaxResidentBytes
			MaxResidentBytes = 1
			t.Cleanup(func() { MaxResidentBytes = old })
			store := Open(root)
			snap, err := store.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			before := snap.Find(id)
			if before.Bad != 1 || before.Events != nil {
				t.Fatal("setup did not retain refusal and evict window")
			}
			if shape == "changed" {
				// Whitespace changes the frame, but not the decoder's reason.
				changed := strings.TrimSuffix(bad, "\n") + " \n"
				if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(good+changed+tail+tail), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadRun(root, id); err == nil || !strings.Contains(err.Error(), "version") {
					t.Fatalf("changed refused bytes did not propagate: %v", err)
				}
				return
			}
			after, err := LoadRun(root, id)
			if err != nil {
				t.Fatalf("unchanged %s refusal prevented rehydration: %v", shape, err)
			}
			if after.Bad != 1 || len(after.LineErrors) != 1 || after.LineErrors[0] != before.LineErrors[0] || len(after.Events) != 2 {
				t.Fatalf("rehydration changed refusal or events: bad=%d errors=%+v events=%d", after.Bad, after.LineErrors, len(after.Events))
			}
		})
	}
}

// TestStoreSeesASameSizeRewriteWithinOneClockTick is TestStoreRefreshRetainsEveryRefusal's "version" shape on a kernel
// whose clock is too coarse to tell two writes apart (the Debian 13 guest, 6.12: bad=0, "filtered export retained 0
// refusals", while Ubuntu's 6.17 passed). The events file is rewritten in place at the same length within one tick
// of the clock, so it keeps its size, mtime and ctime; the store served the lines it had read. Every refusal the
// rewrite made must still show. The stamps are the coarse clock's own (coarseStamps), so the failure does not depend
// on the machine's kernel.
func TestStoreSeesASameSizeRewriteWithinOneClockTick(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	good, tail := lines[0], lines[1]
	tick := time.Now().UnixNano()
	coarseStamps = func(id fileID) fileID { id.mtime, id.ctime = tick, tick; return id }
	t.Cleanup(func() { coarseStamps = nil })
	root := t.TempDir()
	id := "r-aaaa-0001-storex"
	writeRun(t, root, id, string(good)+"\n"+string(tail)+"\n"+string(tail)+"\n")
	store := Open(root)
	if _, err := store.Snapshot(); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(tail, []byte(`"v":1`), []byte(`"v":0`), 1)
	if bytes.Equal(bad, tail) || len(bad) != len(tail) {
		t.Fatal("the fixture's second line does not hold \"v\":1 once")
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(string(good)+"\n"+string(bad)+"\n"+string(bad)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Bad != 2 {
		t.Errorf("bad=%d, want the 2 rewritten lines", r.Bad)
	}
}
