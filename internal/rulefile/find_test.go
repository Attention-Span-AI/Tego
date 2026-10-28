// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// findRun writes run under root: run_start naming contract, with cwd, then n execs. It returns the run directory and
// the byte offset each line starts at. A contract of "" writes a run_start with no contract_source (a tego watch run).
func findRun(t *testing.T, root, run, contract, cwd string, n int) (string, []int64) {
	t.Helper()
	p := record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("0", 64), Command: []string{"sh"},
		Cwd: cwd, Kernel: "6", StopGrace: "1s"}
	if contract != "" {
		p.ContractSource = &record.ContractSource{Path: contract}
	}
	evs := []*record.Event{ledgertest.Event(t, record.KindRunStart, p)}
	for i := range n {
		evs = append(evs, ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/usr/bin/cat",
			Argv: []string{"cat", strings.Repeat("x", i+1)}, ExecID: "x/1/1"}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Authority = record.SourceSeccomp, "exec[cat]", record.VerdictAllow, record.AuthorityRule
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		}))
	}
	var buf bytes.Buffer
	var offs []int64
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	for i, e := range evs {
		e.Run, e.Seq, e.TS = run, uint64(i), t0.Add(time.Duration(i)*time.Second)
		if i > 0 {
			e.Prev = strings.Repeat("a", 64)
		}
		l, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		offs = append(offs, int64(buf.Len()))
		buf.Write(append(l, '\n'))
	}
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, offs
}

// hintOf is the hint a reader of dir's events file would hand on now for the line at off.
func hintOf(t *testing.T, dir string, off int64) Hint {
	t.Helper()
	fi, err := os.Stat(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return Hint{Off: off, Dev: uint64(st.Dev), Ino: st.Ino, Size: fi.Size()} //nolint:unconvert // Dev's type differs between platforms
}

// sameFound fails unless got is want: the same line, run, contract, folder, tier and text.
func sameFound(t *testing.T, got, want *Found) {
	t.Helper()
	gl, err := got.Event.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	wl, err := want.Event.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gl, wl) || got.Run != want.Run || got.Contract != want.Contract || got.Cwd != want.Cwd ||
		got.Tier != want.Tier || got.RunCommandGrant != want.RunCommandGrant || !bytes.Equal(got.Text, want.Text) ||
		got.Mode != want.Mode || got.Guard.LedgerRoot != want.Guard.LedgerRoot {
		t.Fatalf("FindAt found\n %+v\nFindIn found\n %+v", got, want)
	}
}

// TestFindAtReadsTheHintedLine: with a hint that holds, FindAt finds what FindIn finds, for line 0 and a later line,
// and reads only run_start and that line (a damaged line between them, which stops FindIn's scan, is not read).
func TestFindAtReadsTheHintedLine(t *testing.T) {
	g, contract := fixture(t)
	dir, offs := findRun(t, g.LedgerRoot, "r-find-0001", contract, filepath.Dir(contract), 6)
	for _, seq := range []uint64{0, 1, 4, 6} {
		want, err := FindIn(dir, seq, g)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FindAtIn(dir, seq, hintOf(t, dir, offs[seq]), g)
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		sameFound(t, got, want)
	}
	// Damage line 2 in place: the scan stops there, the hinted read of line 5 does not pass over it.
	ev := filepath.Join(dir, "events.jsonl")
	b, err := os.ReadFile(ev)
	if err != nil {
		t.Fatal(err)
	}
	copy(b[offs[2]:offs[3]-1], bytes.Repeat([]byte("x"), int(offs[3]-1-offs[2])))
	if err := os.WriteFile(ev, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FindIn(dir, 5, g); err == nil {
		t.Fatal("FindIn read past a damaged line; the test no longer shows the hinted read")
	}
	f, err := FindAtIn(dir, 5, hintOf(t, dir, offs[5]), g)
	if err != nil || f.Event.Seq != 5 {
		t.Fatalf("FindAt of line 5 = %+v, %v", f, err)
	}
}

// TestFindAtNeverTrustsAStaleHint: a hint that does not hold (another line's offset, the middle of a line, past the
// end, the file replaced, the file truncated and rewritten in place with other lines) falls back to the scan and finds
// the right line, never the line the hint pointed at.
func TestFindAtNeverTrustsAStaleHint(t *testing.T) {
	g, contract := fixture(t)
	cwd := filepath.Dir(contract)
	dir, offs := findRun(t, g.LedgerRoot, "r-find-0002", contract, cwd, 6)
	check := func(name string, seq uint64, h Hint) {
		t.Helper()
		want, err := FindIn(dir, seq, g)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FindAtIn(dir, seq, h, g)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Event.Seq != seq {
			t.Fatalf("%s: FindAt gave line %d for line %d", name, got.Event.Seq, seq)
		}
		sameFound(t, got, want)
	}
	check("another line's offset", 4, hintOf(t, dir, offs[3]))
	check("line 0's offset for a later line", 4, hintOf(t, dir, 0))
	check("the middle of a line", 4, hintOf(t, dir, offs[4]+7))
	h := hintOf(t, dir, offs[4])
	h.Off = h.Size
	check("past the end", 4, h)
	h = hintOf(t, dir, offs[4])
	h.Off = -1
	check("a negative offset", 4, h)
	h = hintOf(t, dir, offs[4])
	h.Size += 10
	check("a file shorter than the hint saw", 4, h)

	// Replaced: a new file (another inode) whose lines start elsewhere; the old hint names the old file.
	old := hintOf(t, dir, offs[4])
	tmp := t.TempDir()
	ndir, noffs := findRun(t, tmp, "r-find-0002", contract, cwd+"/longer/working/folder", 6)
	if noffs[4] == offs[4] {
		t.Fatal("the rewritten run's lines start where the old ones did; the test shows nothing")
	}
	if err := os.Rename(filepath.Join(ndir, "events.jsonl"), filepath.Join(dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	check("a replaced file", 4, old)
	got, err := FindAtIn(dir, 4, old, g)
	if err != nil || got.Cwd != cwd+"/longer/working/folder" {
		t.Fatalf("a replaced file: found %+v, %v", got, err)
	}

	// Truncated and rewritten in place (same inode, at least as long): the hinted offset lands mid-line now.
	stale := hintOf(t, dir, noffs[4])
	tmp2 := t.TempDir()
	rdir, roffs := findRun(t, tmp2, "r-find-0002", contract, cwd+"/an/even/longer/working/folder/than/before", 6)
	b, err := os.ReadFile(filepath.Join(rdir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if roffs[4] == noffs[4] {
		t.Fatal("the rewritten lines start where the old ones did; the test shows nothing")
	}
	ef, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ef.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := ef.Close(); err != nil {
		t.Fatal(err)
	}
	if now := hintOf(t, dir, 0); now.Ino != stale.Ino || now.Size < stale.Size {
		t.Fatalf("the rewrite changed the inode or shrank the file (%+v vs %+v); the test shows nothing", now, stale)
	}
	check("a file truncated and rewritten", 4, stale)

	// A hint from another run of the same root, at an offset that holds a line with the same seq there.
	odir, ooffs := findRun(t, g.LedgerRoot, "r-find-0003", contract, cwd, 6)
	check("another run's hint", 4, hintOf(t, odir, ooffs[4]))
}

// TestFindAtSaysWhatFindSays: a line the run does not hold and a run whose record names no contract fail as FindIn
// fails, whatever the hint.
func TestFindAtSaysWhatFindSays(t *testing.T) {
	g, contract := fixture(t)
	dir, offs := findRun(t, g.LedgerRoot, "r-find-0004", contract, filepath.Dir(contract), 2)
	_, want := FindIn(dir, 9, g)
	_, got := FindAtIn(dir, 9, hintOf(t, dir, offs[2]), g)
	if want == nil || got == nil || got.Error() != want.Error() {
		t.Fatalf("a missing line: FindAt %v, FindIn %v", got, want)
	}
	wdir, woffs := findRun(t, g.LedgerRoot, "r-find-0005", "", filepath.Dir(contract), 3)
	_, want = FindIn(wdir, 2, g)
	_, got = FindAtIn(wdir, 2, hintOf(t, wdir, woffs[2]), g)
	if !errors.Is(want, ErrNoContract) || !errors.Is(got, ErrNoContract) {
		t.Fatalf("a watch run: FindAt %v, FindIn %v", got, want)
	}
	_, want = FindIn(filepath.Join(g.LedgerRoot, "r-none"), 1, g)
	_, got = FindAtIn(filepath.Join(g.LedgerRoot, "r-none"), 1, Hint{Off: 10, Size: 20}, g)
	if want == nil || got == nil || got.Error() != want.Error() {
		t.Fatalf("a missing run: FindAt %v, FindIn %v", got, want)
	}
}

// TestFindAtWatchRunReadsNoOtherLine: on a run whose record names no contract file (tego watch), a hint that holds
// answers ErrNoContract from run_start and the hinted line alone, so a long watch run's line page does not decode every
// line before the one shown on each load and live refresh (r9 QG-1). A damaged line between them, which stops the
// scan with another error, proves the scan did not run; a hint that does not hold still scans.
func TestFindAtWatchRunReadsNoOtherLine(t *testing.T) {
	g, contract := fixture(t)
	dir, offs := findRun(t, g.LedgerRoot, "r-find-0006", "", filepath.Dir(contract), 6)
	if _, err := FindAtIn(dir, 0, hintOf(t, dir, 0), g); !errors.Is(err, ErrNoContract) {
		t.Fatalf("line 0 of a watch run: %v, want ErrNoContract", err)
	}
	ev := filepath.Join(dir, "events.jsonl")
	b, err := os.ReadFile(ev)
	if err != nil {
		t.Fatal(err)
	}
	copy(b[offs[2]:offs[3]-1], bytes.Repeat([]byte("x"), int(offs[3]-1-offs[2])))
	if err := os.WriteFile(ev, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FindIn(dir, 5, g); err == nil || errors.Is(err, ErrNoContract) {
		t.Fatalf("FindIn of line 5 past a damaged line = %v; the test no longer shows the scan was skipped", err)
	}
	if _, err := FindAtIn(dir, 5, hintOf(t, dir, offs[5]), g); !errors.Is(err, ErrNoContract) {
		t.Fatalf("FindAt of line 5 with a good hint = %v, want ErrNoContract without a scan", err)
	}
	if _, err := FindAtIn(dir, 5, hintOf(t, dir, offs[4]), g); err == nil || errors.Is(err, ErrNoContract) {
		t.Fatalf("FindAt with another line's offset = %v, want the scan's own error", err)
	}
}
