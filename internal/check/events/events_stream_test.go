// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fsLines marshals n chained fs events the way a writer would (seq gapless, prev naming the prior id) and
// returns the stored lines. rule(i) names each event's declared entry, which is the widest column a run can
// move: kind, source and verdict come from closed sets, a rule name comes from the contract.
func fsLines(t *testing.T, n int, rule func(i int) string) [][]byte {
	t.Helper()
	lines := make([][]byte, 0, n)
	prev := ""
	for i := range n {
		e := &record.Event{
			V: record.Version, Seq: uint64(i), Prev: prev,
			TS:     time.Unix(0, int64(i)*int64(time.Millisecond)).UTC(),
			MonoNS: uint64(i) * uint64(time.Millisecond),
			Run:    "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "synthetic",
			PID: 1, TID: 1, Kind: record.KindFS, Source: record.SourceLandlock,
			Rule: rule(i), Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
			Attr: &record.Attribution{Confidence: "likely", Method: "tid"},
		}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/home/u/proj/a.txt"}); err != nil {
			t.Fatal(err)
		}
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatalf("marshal seq %d: %v", i, err)
		}
		prev = e.ID
		lines = append(lines, line)
	}
	return lines
}

// readerOf writes lines into a fresh run directory and opens a Reader over it.
func readerOf(t *testing.T, lines [][]byte) *ledger.Reader {
	t.Helper()
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func headerOf(s string) string { return strings.SplitN(s, "\n", 2)[0] }

// TestTableWidthsFreezeAfterTheWidthSample pins E10 for the human view: Table measures its columns over the
// first widthSample matching rows and then writes, so a run of any size costs the same memory. The
// observable consequence is that a row arriving after the sample cannot widen a column that is already on
// its way to the terminal — it overhangs instead. Buffering the whole run (the shape this replaced) would
// let that last row change the header, which is what this test watches for.
func TestTableWidthsFreezeAfterTheWidthSample(t *testing.T) {
	wide := "fs.read[" + strings.Repeat("x", 120) + "]"
	rule := func(i int) string {
		if i == widthSample {
			return wide
		}
		return "fs.read[.]"
	}
	lines := fsLines(t, widthSample+1, rule)

	var full, sampled bytes.Buffer
	n, err := Table(t.Context(), &full, readerOf(t, lines), Filter{})
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	if n != widthSample+1 {
		t.Fatalf("rendered %d rows, want %d", n, widthSample+1)
	}
	if _, err := Table(t.Context(), &sampled, readerOf(t, lines[:widthSample]), Filter{}); err != nil {
		t.Fatalf("Table over the sample alone: %v", err)
	}
	if got, want := headerOf(full.String()), headerOf(sampled.String()); got != want {
		t.Errorf("the row after the width sample changed the header, so the table was buffered whole\n got: %q\nwant: %q", got, want)
	}
	// Overhanging must not cost the operator the value itself, nor run two columns together (writeRow's
	// pad never goes negative).
	last := strings.Split(strings.TrimRight(full.String(), "\n"), "\n")
	if l := last[len(last)-1]; !strings.Contains(l, wide+"  ") {
		t.Errorf("the wide row lost its rule or its separator: %q", l)
	}
}

// TestTableStreamsRowsBeforeTheLedgerEnds is the other half of E10: rows reach the writer while the ledger
// is still being read. A corrupt line past the sample (E3) makes that visible — the rows before it are
// already written, where a buffered table would have produced nothing at all. It also pins §7's
// `<path>: ...` form for the table view, which reported the reader's bare error before.
func TestTableStreamsRowsBeforeTheLedgerEnds(t *testing.T) {
	lines := fsLines(t, widthSample+50, func(int) string { return "fs.read[.]" })
	corrupt := widthSample + 10
	lines[corrupt-1] = []byte(`{"v":1,"seq":` + fmt.Sprint(corrupt-1) + `,"id":"ab`) // torn mid-write

	r := readerOf(t, lines)
	var out bytes.Buffer
	n, err := Table(t.Context(), &out, r, Filter{})
	if err == nil {
		t.Fatal("a corrupt middle line must be fatal (E3)")
	}
	if !errors.Is(err, ledger.ErrCorruptLedger) {
		t.Errorf("error = %v, want one errors.Is reports as a corrupt ledger", err)
	}
	if want := filepath.Join(r.Dir(), ledger.EventsFile); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %s, the `<path>: corrupt ledger at line N` of §7", err, want)
	}
	if out.Len() == 0 {
		t.Fatal("no output before the corrupt line: the table held every row instead of streaming")
	}
	if !strings.HasPrefix(out.String(), "SEQ") {
		t.Errorf("header = %q", headerOf(out.String()))
	}
	if rows := strings.Count(out.String(), "\n") - 1; rows != corrupt-1 || n != corrupt-1 {
		t.Errorf("%d rows written and %d matched, want the %d lines that precede the corrupt one", rows, n, corrupt-1)
	}
}

// TestTableKeepsRowsBeforeACorruptLineWithinTheSample: a corrupt line before widthSample rows have been read
// found the table still holding its rows back, and the error return discarded them and the header.
func TestTableKeepsRowsBeforeACorruptLineWithinTheSample(t *testing.T) {
	lines := fsLines(t, 50, func(int) string { return "fs.read[.]" })
	lines[39] = []byte(`{"v":1,"seq":39,"id":"ab`)
	var out bytes.Buffer
	n, err := Table(t.Context(), &out, readerOf(t, lines), Filter{})
	if !errors.Is(err, ledger.ErrCorruptLedger) {
		t.Fatalf("error = %v, want a corrupt ledger", err)
	}
	if n != 39 || !strings.HasPrefix(out.String(), "SEQ") || strings.Count(out.String(), "\n") != 40 {
		t.Errorf("n=%d, output %d lines, want header + 39 rows:\n%s", n, strings.Count(out.String(), "\n"), out.String())
	}
}

// TestJSONCorruptLineNamesItsPositionInTheFile pins §7: the N an operator is sent to is the line's position
// in events.jsonl. JSON counted the lines it had *printed* instead, so any active filter — here --kind fs,
// which has matched six of the first thirty-nine lines — named a line that is perfectly intact.
func TestJSONCorruptLineNamesItsPositionInTheFile(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(src, "\n"), []byte("\n"))
	const corrupt = 40 // an fs line, far enough in that no filter's count can coincide with it
	if len(lines) < corrupt {
		t.Fatalf("fixture has %d lines, want at least %d", len(lines), corrupt)
	}
	lines[corrupt-1] = []byte(`{"v":1,"seq":39,"id":"ab`)

	r := readerOf(t, lines)
	var out bytes.Buffer
	n, err := JSON(t.Context(), &out, r, Filter{Kinds: []record.Kind{record.KindFS}})
	if err == nil {
		t.Fatal("a corrupt middle line must be fatal (E3)")
	}
	if !errors.Is(err, ledger.ErrCorruptLedger) {
		t.Errorf("error = %v, want one errors.Is reports as a corrupt ledger", err)
	}
	if want := fmt.Sprintf("corrupt line %d", corrupt); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %q", err, want)
	}
	if bad := fmt.Sprintf("corrupt line %d", n+1); strings.Contains(err.Error(), bad) && n+1 != corrupt {
		t.Errorf("error %q names the %d events printed, not the position in the file", err, n)
	}
	if want := filepath.Join(r.Dir(), ledger.EventsFile); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %s, the `<path>: ...` of §7", err, want)
	}
}
