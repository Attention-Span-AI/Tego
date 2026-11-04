// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReferenceRequiresWorkspaceAndAgent(t *testing.T) {
	watched := &Run{ID: "watched", Tier: "observe", Command: "codex", Cwd: "/projects/a", Agent: "codex"}
	for _, c := range []struct{ name, cwd, agent string }{{"different project", "/projects/b", "codex"}, {"different agent", "/projects/a", "other"}, {"missing workspace", "", "codex"}, {"missing agent", "/projects/a", ""}} {
		t.Run(c.name, func(t *testing.T) {
			other := &Run{ID: "enforced", Tier: "landlock", Command: "/usr/bin/codex", Cwd: c.cwd, Agent: c.agent}
			if got := ReferenceRun([]*Run{other}, watched); got != nil {
				t.Fatalf("unreliable reference: %+v", got)
			}
		})
	}
	same := &Run{ID: "same", Tier: "landlock", Command: "codex", Cwd: watched.Cwd, Agent: watched.Agent}
	if got := ReferenceRun([]*Run{same}, watched); got != same {
		t.Fatal("same workspace and agent did not pair")
	}
	relativeWatch, relativeEnforced := *watched, *same
	relativeWatch.Cwd, relativeEnforced.Cwd = ".", "."
	if ReferenceRun([]*Run{&relativeEnforced}, &relativeWatch) != nil {
		t.Fatal("relative paths do not identify a workspace reliably")
	}
}

func TestVerdictDoesNotCombineUnrelatedPairs(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0901-mixedx"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "codex", 0, at, "run_start", `"tier":"observe","command":["codex"],"cwd":"/projects/a"`),
		line(id, "codex", 10, at, "fs", `"rule":"unmatched","op":"open","path":"/home/u/.ssh/id_rsa","verdict":"observed"`),
		line(id, "codex", 11, at, "refused", `"op":"net","target":"203.0.113.8:443","rule":"unmatched","reason":"net-not-allowed"`),
		line(id, "codex", 100, at.Add(time.Minute), "refused", `"op":"open","target":"/home/u/.ssh/id_ed25519","rule":"fs.deny_read[/home/u/.ssh/]","reason":"read-denied"`),
		line(id, "codex", 101, at.Add(time.Minute), "net", `"rule":"unmatched","dst":"203.0.113.9:443","proto":"tcp","verdict":"observed"`))
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	v := RunVerdict(r, Signal(r, Sensitive{}))
	if v.Kind == VerdictLeak || len(v.Exposed) > 0 {
		t.Fatalf("fabricated leak: %+v", v)
	}
}

// The run never ends: both cold decoding and repeated appends must stay bounded.
func TestNeverEndingRunHasBoundedResidentWindow(t *testing.T) {
	old := MaxLines
	MaxLines = 128
	t.Cleanup(func() { MaxLines = old })
	root, id := t.TempDir(), "r-aaaa-0902-growth"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	writeRun(t, root, id, line(id, "codex", 0, at, "run_start", `"tier":"observe","command":["codex"],"cwd":"/projects/a"`))
	markLive(t, root, id, true)
	seq := 1
	s := Open(root)
	for round := 0; round < 20; round++ {
		for i := 0; i < 200; i++ {
			kind, extra := "fs", `"op":"open","path":"/work/repeated","verdict":"observed"`
			if i%3 == 0 {
				kind, extra = "ask", fmt.Sprintf(`"ask_id":"q-%d","hold":"exec","op":"exec","target":"git"`, seq)
			}
			if i%3 == 1 {
				kind, extra = "answer", fmt.Sprintf(`"ask_id":"q-%d","approved":true,"by":"owner"`, seq-1)
			}
			appendLines(t, root, id, line(id, "codex", seq, at.Add(time.Duration(seq)*time.Millisecond), kind, extra))
			seq++
		}
		r, err := s.Run(id)
		if err != nil {
			t.Fatal(err)
		}
		st := s.runs[id]
		if len(st.askOrder) != 0 || len(st.asks) != 0 || len(r.Pending) != 0 {
			t.Fatal("answered asks accumulated outside the bounded event window")
		}
		if len(st.b.Events) > MaxLines {
			t.Fatalf("live builder retains %d lines at bound %d after %d lines", len(st.b.Events), MaxLines, seq)
		}
		if r.Lines != seq {
			t.Fatalf("incremental total=%d, want %d", r.Lines, seq)
		}
		if r.LastSeq != uint64(seq-1) || !r.Live || r.Ended {
			t.Fatalf("live summary stopped following: last=%d live=%v", r.LastSeq, r.Live)
		}
		_ = Signal(r, Sensitive{})
		_ = TimelineOf(r, false)
		_, _ = r.progs()
	}
	// A cold store must bound allocations during its first scan too.
	cold := &Store{root: root, runs: map[string]*runState{}, intern: map[string]string{}, probes: map[string]lockProbe{}}
	if _, err := cold.Run(id); err != nil {
		t.Fatal(err)
	}
	if len(cold.runs[id].b.Events) > MaxLines {
		t.Fatal("cold read exceeded the bound")
	}
	w, err := WindowBefore(root, s.runs[id].pub, 100)
	if err != nil || len(w.Events) == 0 || w.Events[len(w.Events)-1].Seq != 99 {
		t.Fatalf("older window: %v", err)
	}
	if view, err := ExplainLine(root, id, 1); err != nil || view.Raw == "" {
		t.Fatalf("old event explanation unavailable: %v", err)
	}
	// Old bytes remain reachable through the ledger, with no full decode back into RAM.
	if facts, err := Line(root, id, 1); err != nil || facts.Raw == "" {
		t.Fatalf("old ledger line unavailable: %v", err)
	}
}

func TestPendingAskBudgetSurvivesWindowRotation(t *testing.T) {
	old := MaxLines
	MaxLines = 8
	t.Cleanup(func() { MaxLines = old })
	for _, field := range []string{"hold", "op"} {
		t.Run(field, func(t *testing.T) {
			root, id := t.TempDir(), "r-aaaa-0907-askmem"
			at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
			writeRun(t, root, id, line(id, "codex", 0, at, "run_start", `"tier":"observe","command":["codex"]`))
			markLive(t, root, id, true)
			hold, op := "exec", "exec"
			if field == "hold" {
				hold = strings.Repeat("h", 64<<10)
			} else {
				op = strings.Repeat("o", 64<<10)
			}
			for seq := 1; seq <= 180; seq++ {
				appendLines(t, root, id, line(id, "codex", seq, at, "ask", fmt.Sprintf(`"ask_id":"q-%d","hold":"%s","op":"%s","target":"/work/a"`, seq, hold, op)))
			}
			s := Open(root)
			r, err := s.Run(id)
			if err != nil {
				t.Fatal(err)
			}
			st := s.runs[id]
			var retained int64
			for _, a := range st.asks {
				retained += int64(len(a.Run) + len(a.Agent) + len(a.AskID) + len(a.Hold) + len(a.Op) + len(a.Target) + len(a.Rule))
			}
			if retained > maxPendingBytes || st.askBytes > maxPendingBytes {
				t.Fatalf("pending %s strings escaped the budget after window rotation: retained=%d charged=%d limit=%d", field, retained, st.askBytes, maxPendingBytes)
			}
			if !r.PendingCut || len(r.Pending) == 0 || len(r.Events) == 0 || r.Pending[0].Seq >= r.Events[0].Seq {
				t.Fatal("expected labelled truncation with an older pending ask preserved beyond the event window")
			}
			if a := r.Pending[0]; a.Hold != hold || a.Op != op {
				t.Fatal("retained ask lost its operation or hold")
			}
			before := st.askBytes
			appendLines(t, root, id, line(id, "codex", 181, at, "answer", `"ask_id":"q-1","approved":true,"by":"owner"`))
			if _, err := s.Run(id); err != nil {
				t.Fatal(err)
			}
			if _, ok := st.asks["q-1"]; ok || st.askBytes >= before {
				t.Fatal("answer did not release pending state after window rotation")
			}
		})
	}
}

func TestLiveWindowBoundsLongTargetsAndDerivedIndexes(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0903-bytesx"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	writeRun(t, root, id, line(id, "codex", 0, at, "run_start", `"tier":"observe","command":["codex"],"cwd":"/projects/a"`))
	markLive(t, root, id, true)
	path := "/work/" + strings.Repeat("long", 2048)
	seq := 1
	for round := 0; round < 6; round++ {
		ls := make([]string, 500)
		for i := range ls {
			ls[i] = line(id, "codex", seq, at.Add(time.Duration(seq)*time.Millisecond), "fs", fmt.Sprintf(`"op":"open","path":"%s/%d","verdict":"observed"`, path, seq))
			seq++
		}
		appendLines(t, root, id, ls...)
		r, err := LoadRun(root, id)
		if err != nil {
			t.Fatal(err)
		}
		st := Open(root).runs[id]
		if st.bytes > maxWindowBytes {
			t.Fatalf("resident estimate=%d, cap=%d", st.bytes, maxWindowBytes)
		}
		sig := Signal(r, Sensitive{Entries: []string{"/work/"}})
		if len(sig.Secrets) > len(r.Events) {
			t.Fatal("signal retained events outside the window")
		}
		names, of := r.progs()
		if len(of) != len(r.Events) || len(names) > len(r.Events) {
			t.Fatal("process index grew outside the window")
		}
		if r.Lines != seq {
			t.Fatalf("summary=%d, want %d", r.Lines, seq)
		}
	}
	r, _ := LoadRun(root, id)
	if !r.Cut || !RunVerdict(r, Signal(r, Sensitive{})).Partial {
		t.Fatal("a bounded view must disclose its partial verdict")
	}
}

func TestLiveWindowBudgetsEnvelopeStrings(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0906-envelp"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	writeRun(t, root, id, line(id, "codex", 0, at, "run_start", `"tier":"observe","command":["codex"]`))
	markLive(t, root, id, true)
	f, err := os.OpenFile(filepath.Join(root, id, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Agent is an envelope field: it is absent from Raw, and long values are not interned.
	agentID := strings.Repeat("a", 64<<10)
	const total = 2100
	for seq := 1; seq <= total; seq++ {
		if _, err := io.WriteString(f, line(id, agentID, seq, at, "fs", `"rule":"unmatched","op":"open","path":"/work/a","verdict":"observed"`)); err != nil {
			// Preserve the write error; closing only releases the scratch file on this failure path.
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	var agents int64
	for _, e := range r.Events {
		agents += int64(len(e.Agent))
	}
	if agents > maxWindowBytes {
		t.Fatalf("retained agent strings alone use %d bytes under a %d-byte window budget", agents, maxWindowBytes)
	}
	if r.Lines != total+1 || r.LastSeq != total || !r.Live || r.Ended {
		t.Fatalf("live totals lost: lines=%d last=%d live=%v ended=%v", r.Lines, r.LastSeq, r.Live, r.Ended)
	}
}

func TestBoundedDecoderSkipsOversizedCompleteLine(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0904-decode"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	writeRun(t, root, id, line(id, "codex", 0, at, "run_start", `"command":["codex"]`))
	f, err := os.OpenFile(filepath.Join(root, id, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	chunk := strings.Repeat("x", 64<<10)
	for range maxLineBytes/len(chunk) + 8 {
		if _, err := io.WriteString(f, chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := io.WriteString(f, "\n"+line(id, "codex", 1, at, "exec", `"verdict":"allow","argv":["git"]`)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if !RunVerdict(r, Signal(r, Sensitive{})).Partial {
		t.Fatal("an undecodable line cannot yield a complete verdict")
	}
	if r.Bad != 1 || r.Lines != 2 || r.LastSeq != 1 {
		t.Fatalf("oversized line prevented following: bad=%d lines=%d last=%d", r.Bad, r.Lines, r.LastSeq)
	}
}

func TestUnknownKindsCannotGrowSummaryIndexes(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0905-kindsx"
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	ls := []string{line(id, "codex", 0, at, "run_start", `"command":["codex"]`)}
	for i := 1; i <= 1000; i++ {
		ls = append(ls, line(id, "codex", i, at, fmt.Sprintf("unknown-%d", i), ""))
	}
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Bad != 1000 || len(r.Kinds) != 2 {
		t.Fatalf("unknown record kinds escaped the bounded summary: bad=%d kinds=%d", r.Bad, len(r.Kinds))
	}
	// Opaque lines remain available for inspection and byte-exact ledger export.
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	snap.Each(Filter{Run: id, Ledger: true}, OldestFirst, func(_ *Event, raw func() ([]byte, error)) bool {
		b, err := raw()
		if err != nil {
			t.Fatal(err)
		}
		out.Write(b)
		out.WriteByte('\n')
		return true
	})
	if out.String() != strings.Join(ls, "") {
		t.Fatal("summary bounding dropped opaque ledger bytes")
	}
}
