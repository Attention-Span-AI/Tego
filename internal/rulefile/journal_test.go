// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// chain writes textB then textC then textA' over the fixture's textA and returns the three entries.
func chain(t *testing.T, g Guard, path string) []*Entry {
	t.Helper()
	texts := []string{textA, textB, textC, textA + "# again\n"}
	var es []*Entry
	for i := 1; i < len(texts); i++ {
		e, err := Replace(context.Background(), g, path, Sum([]byte(texts[i-1])), []byte(texts[i]), Change{Via: "dashboard", Summary: "step"})
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, e)
	}
	return es
}

// TestUndoAnyDepth: each Undo goes one change further back, to the very first text; then there is nothing to undo.
func TestUndoAnyDepth(t *testing.T) {
	g, path := fixture(t)
	chain(t, g, path)
	for _, want := range []string{textC, textB, textA} {
		e, err := Undo(context.Background(), g, path, RevertOptions{Change: Change{Via: "dashboard"}})
		if err != nil {
			t.Fatal(err)
		}
		if got := mustRead(t, path); got != want {
			t.Fatalf("after undo %s the file holds %q, want %q", e.ID, got, want)
		}
		if e.Op != OpRevert || e.Reverts == "" {
			t.Errorf("undo entry %+v", e)
		}
	}
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); !errors.Is(err, ErrNoChange) {
		t.Errorf("a fourth undo: %v; want ErrNoChange", err)
	}
	hist, err := History(g.LedgerRoot, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 6 {
		t.Fatalf("history has %d entries, want 6", len(hist))
	}
	for _, e := range hist {
		if e.Op == OpChange && e.UndoneBy == "" {
			t.Errorf("change %s is not marked undone", e.ID)
		}
	}
	// Newest first.
	if hist[0].Op != OpRevert || hist[len(hist)-1].Op != OpChange {
		t.Errorf("history order: %s … %s", hist[0].Op, hist[len(hist)-1].Op)
	}
}

// TestUndoAfterNewChange: undo, then a new change, then undo again takes back the new change and then skips the one
// already undone.
func TestUndoAfterNewChange(t *testing.T) {
	g, path := fixture(t)
	for _, step := range [][2]string{{textA, textB}, {textB, textC}} {
		if _, err := Replace(context.Background(), g, path, Sum([]byte(step[0])), []byte(step[1]), Change{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil { // C→B
		t.Fatal(err)
	}
	newer := textB + "# newer\n"
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textB)), []byte(newer), Change{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{textB, textA} {
		if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := mustRead(t, path); got != want {
			t.Fatalf("file holds %q, want %q", got, want)
		}
	}
}

// TestRevertRefusesWhenChangedSince: Revert(id) works only while the file holds what id wrote.
func TestRevertRefusesWhenChangedSince(t *testing.T) {
	g, path := fixture(t)
	es := chain(t, g, path)
	if _, err := Revert(context.Background(), g, es[0].ID, RevertOptions{}); !errors.Is(err, ErrStale) {
		t.Fatalf("revert of an older change: %v; want ErrStale", err)
	}
	if got := mustRead(t, path); got != textA+"# again\n" {
		t.Errorf("a refused revert wrote %q", got)
	}
	for i := len(es) - 1; i >= 0; i-- {
		if _, err := Revert(context.Background(), g, es[i].ID, RevertOptions{}); err != nil {
			t.Fatalf("revert %d: %v", i, err)
		}
	}
	if got := mustRead(t, path); got != textA {
		t.Errorf("file holds %q", got)
	}
	if _, err := Revert(context.Background(), g, "rc-nope", RevertOptions{}); !errors.Is(err, ErrNoChange) {
		t.Errorf("unknown id: %v", err)
	}
}

// TestRevertOfRevertRedoes: reverting a revert puts the change back, and Undo then takes it back again.
func TestRevertOfRevertRedoes(t *testing.T) {
	g, path := fixture(t)
	chain(t, g, path)
	r, err := Undo(context.Background(), g, path, RevertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Revert(context.Background(), g, r.ID, RevertOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, path); got != textA+"# again\n" {
		t.Fatalf("redo left %q", got)
	}
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, path); got != textC {
		t.Errorf("undo after redo left %q", got)
	}
}

// TestRevertChecks: a revert whose old text no longer compiles, or whose blob was altered, writes nothing.
func TestRevertChecks(t *testing.T) {
	g, path := fixture(t)
	es := chain(t, g, path)
	last := es[len(es)-1]
	_, err := Revert(context.Background(), g, last.ID, RevertOptions{Check: func([]byte) error { return errors.New("exec-not-on-path") }})
	if err == nil || !strings.Contains(err.Error(), "no longer compiles") {
		t.Fatalf("Check refusing: %v", err)
	}
	blob := filepath.Join(g.LedgerRoot, JournalDirName, BlobsDir, last.OldSHA256+".yaml")
	if err := os.WriteFile(blob, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Revert(context.Background(), g, last.ID, RevertOptions{}); !errors.Is(err, ErrGuard) {
		t.Fatalf("altered blob: %v; want ErrGuard", err)
	}
	if got := mustRead(t, path); got != textA+"# again\n" {
		t.Errorf("file holds %q", got)
	}
}

// TestJournalLineFormat: the line format doc.go documents, as the dashboard reads it.
func TestJournalLineFormat(t *testing.T) {
	g, path := fixture(t)
	f := &Found{Event: &record.Event{Seq: 49}, Run: "r-demo", Contract: path, Text: []byte(textA), Guard: g,
		Via: "dashboard", Summary: "never read ./token", Direction: "narrows",
		Sentences: []string{SentenceLine("May read ./token", "Can never read ./token"), SentenceLine("", "Cannot run curl")}}
	bak, err := f.Write([]byte(textB))
	if err != nil {
		t.Fatal(err)
	}
	if bak != path+".bak" {
		t.Errorf("bak %q", bak)
	}
	es, err := ReadJournal(g.LedgerRoot)
	if err != nil || len(es) != 1 {
		t.Fatalf("journal: %v, %v", es, err)
	}
	if err := AppendLive(context.Background(), g.LedgerRoot, es[0].ID, []Live{{Run: "r-demo", Block: "path:/x/token", OK: true}}); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(filepath.Join(g.LedgerRoot, JournalDirName, JournalFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var lines []map[string]any
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		t.Fatalf("%d lines", len(lines))
	}
	c := lines[0]
	for k, want := range map[string]any{"v": float64(1), "op": "change", "via": "dashboard", "contract": path,
		"old_sha256": Sum([]byte(textA)), "new_sha256": Sum([]byte(textB)), "bak": path + ".bak", "run": "r-demo",
		"line": float64(49), "summary": "never read ./token", "uid": float64(os.Geteuid()), "direction": "narrows"} {
		if c[k] != want {
			t.Errorf("%s = %v, want %v", k, c[k], want)
		}
	}
	// Each sentence "before → after", a rule the file did not have before said as (nothing).
	got, _ := c["sentences"].([]any)
	if want := []any{"May read ./token → Can never read ./token", "(nothing) → Cannot run curl"}; !slices.Equal(got, want) {
		t.Errorf("sentences = %q, want %q", c["sentences"], want)
	}
	for _, k := range []string{"id", "at", "pid"} {
		if _, ok := c[k]; !ok {
			t.Errorf("no %s", k)
		}
	}
	if l := lines[1]; l["op"] != "live" || l["of"] != c["id"] {
		t.Errorf("live line %v", l)
	}
	hist, err := History(g.LedgerRoot, path)
	if err != nil || len(hist) != 1 || len(hist[0].Live) != 1 || hist[0].Live[0].Block != "path:/x/token" {
		t.Errorf("history %+v, %v", hist, err)
	}
}

// TestFoundWriteStale: Found.Write keeps its message for a file changed since Find read it.
func TestFoundWriteStale(t *testing.T) {
	g, path := fixture(t)
	f := &Found{Event: &record.Event{Seq: 1}, Run: "r-x", Contract: path, Text: []byte(textA), Guard: g}
	if err := os.WriteFile(path, []byte(textC), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.Write([]byte(textB))
	if !errors.Is(err, ErrStale) || !strings.Contains(err.Error(), "changed since it was read") {
		t.Fatalf("Write: %v", err)
	}
}

// TestJournalUntrusted: a journal folder others may write is refused, so no forged line or blob can steer a revert.
func TestJournalUntrusted(t *testing.T) {
	g, path := fixture(t)
	chain(t, g, path)
	jd := filepath.Join(g.LedgerRoot, JournalDirName)
	if err := os.Chmod(jd, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJournal(g.LedgerRoot); !errors.Is(err, ErrGuard) {
		t.Errorf("ReadJournal: %v; want ErrGuard", err)
	}
	if _, err := Replace(context.Background(), g, path, Sum([]byte(textA+"# again\n")), []byte(textB), Change{}); !errors.Is(err, ErrGuard) {
		t.Errorf("Replace: %v; want ErrGuard", err)
	}
	if err := os.Chmod(jd, 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlinked journal is refused too.
	if err := os.Rename(jd, jd+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(jd+".real", jd); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJournal(g.LedgerRoot); err == nil {
		t.Error("ReadJournal followed a symlinked journal")
	}
}

// TestReadJournalSkipsTornLine: a torn last line (a crash mid-append) is skipped; no journal at all is no entries.
func TestReadJournalSkipsTornLine(t *testing.T) {
	g, path := fixture(t)
	if es, err := ReadJournal(g.LedgerRoot); err != nil || es != nil {
		t.Fatalf("no journal: %v, %v", es, err)
	}
	chain(t, g, path)
	jf := filepath.Join(g.LedgerRoot, JournalDirName, JournalFile)
	fh, err := os.OpenFile(jf, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString(`{"v":1,"id":"rc-torn","op":"chan`); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	es, err := ReadJournal(g.LedgerRoot)
	if err != nil || len(es) != 3 {
		t.Fatalf("%d entries, %v", len(es), err)
	}
	// The next line starts on a line of its own, so the torn one costs only itself.
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil {
		t.Fatal(err)
	}
	if es, err = ReadJournal(g.LedgerRoot); err != nil || len(es) != 4 {
		t.Fatalf("after the torn line: %d entries, %v", len(es), err)
	}
}
