// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// countingReaderAt counts the bytes State's tail read actually pulls out of the file.
type countingReaderAt struct {
	f *os.File
	n int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.f.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

// bigLedger writes a run of n gap events whose payloads are ~4 KiB, the largest R10 leaves inline, so the
// ledger is megabytes of many lines: the shape gc meets in a ledger_root that has not been swept.
func bigLedger(t *testing.T, n int) (dir string, w *Writer) {
	t.Helper()
	w, dir, _ = openTestWriter(t)
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatalf("WriteRunStart: %v", err)
	}
	filler := strings.Repeat("y", 4000)
	for i := 0; i < n; i++ {
		if err := w.Append(gapEvent(filler + strconv.Itoa(i))); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	return dir, w
}

// TestStateReadsOnlyTheTail pins the cost of State. gc asks every run directory for its state on every
// `tego run` (sweepBeforeRun -> ledger.GC -> repo.State), so a State that decodes the whole ledger makes
// startup scale with everything retention has not yet removed. §4 defines the state from the last complete
// line and the lock alone, and that is all this may read.
func TestStateReadsOnlyTheTail(t *testing.T) {
	dir, w := bigLedger(t, 300) // ~1.2 MiB
	defer func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()

	f, err := os.Open(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() < 1<<20 {
		t.Fatalf("ledger too small to prove anything: %d bytes", st.Size())
	}
	c := &countingReaderAt{f: f}
	line, present, err := lastLine(c, st.Size())
	if err != nil || !present {
		t.Fatalf("lastLine = %v %v", present, err)
	}
	if max := int64(4 * tailWindow); c.n > max {
		t.Fatalf("read %d bytes of a %d byte ledger, want at most %d", c.n, st.Size(), max)
	}
	e, err := record.Decode(line)
	if err != nil {
		t.Fatalf("decode last line: %v", err)
	}
	if e.Seq != 300 {
		t.Fatalf("last line seq = %d, want 300", e.Seq)
	}
	// The same bound through State itself, measured as bytes the process actually read from the kernel.
	before := rchar(t)
	if s := stateOf(t, dir); s != StateRunning {
		t.Fatalf("state = %s, want running", s)
	}
	if read := rchar(t) - before; read > 512<<10 {
		t.Fatalf("State read %d bytes of a %d byte ledger", read, st.Size())
	}
}

// rchar is the bytes this process has read through read(2) so far; it skips the test where /proc is not
// mounted as expected rather than guessing.
func rchar(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/io")
	if err != nil {
		t.Skipf("/proc/self/io unavailable: %v", err)
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "rchar:"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				t.Skipf("rchar unparsable: %q", ln)
			}
			return n
		}
	}
	t.Skip("no rchar in /proc/self/io")
	return 0
}

// TestStateIgnoresDamageBeforeTheLastLine: the state of a run is what run_end and the lock say (I7). A line
// damaged earlier in the file is real, but it is Verify's finding to report, not a reason for gc to be unable
// to tell an ended run from a running one — the run above it ended, and retention must still reach it.
func TestStateIgnoresDamageBeforeTheLastLine(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 3)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, EventsFile)
	lines := readLines(t, events)
	if len(lines) != 5 {
		t.Fatalf("lines = %d", len(lines))
	}
	lines[2] = `{"v":1,"seq":2,"id":"` // what a power loss can leave stitched into the middle of the file
	writeLines(t, events, lines)
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("state = %s, want ended", s)
	}

	// The last complete line is the one State cannot do without: an undecodable one is ErrCorruptLedger.
	lines = readLines(t, events)
	lines[len(lines)-1] = `{"v":1,"seq":4,`
	writeLines(t, events, lines)
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := r.State(); !errors.Is(err, ErrCorruptLedger) {
		t.Fatalf("State on a corrupt last line = %v, want ErrCorruptLedger", err)
	}
}

// TestStateLineLongerThanWindow covers the widening loop: neither the decisive line nor a torn tail is
// bounded by tailWindow, and missing a line boundary would report the wrong state.
//
// Also pins record-ledger.md E12: State's backward search gives up past the same bound.
func TestStateLineLongerThanWindow(t *testing.T) {
	t.Run("run_end larger than the window", func(t *testing.T) {
		w, dir, _ := openTestWriter(t)
		startRun(t, w, 1)
		detail := strings.Repeat("d", 3*tailWindow)
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndError, Detail: detail}); err != nil {
			t.Fatal(err)
		}
		if s := stateOf(t, dir); s != StateEnded {
			t.Fatalf("state = %s, want ended", s)
		}
	})
	t.Run("torn tail larger than the window", func(t *testing.T) {
		w, dir, _ := openTestWriter(t)
		startRun(t, w, 1)
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(`{"v":1,"seq":3,` + strings.Repeat("t", 3*tailWindow)); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if s := stateOf(t, dir); s != StateEnded { // E8: the torn tail was never a line
			t.Fatalf("state = %s, want ended", s)
		}
	})
}

// TestLastLineEdges is the tail scanner's own table: the file shapes State has to survive.
func TestLastLineEdges(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 1)
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	lines := readLines(t, filepath.Join(dir, EventsFile))
	first, last := lines[0], lines[len(lines)-1]

	tests := []struct {
		name    string
		content string
		want    string // "" means: no complete line
	}{
		{"empty file", "", ""},
		{"one terminator", "\n", ""}, // an empty first line: present, and Decode will reject it
		{"one terminated line", first + "\n", first},
		{"unterminated but decodable", first, first},
		{"unterminated and torn", first[:len(first)/2], ""},
		{"torn tail after a line", first + "\n" + last[:len(last)/2], first},
		{"terminated tail", first + "\n" + last + "\n", last},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), EventsFile)
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			st, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			got, present, err := lastLine(f, st.Size())
			if err != nil {
				t.Fatalf("lastLine: %v", err)
			}
			if tc.name == "one terminator" {
				if !present || len(got) != 0 {
					t.Fatalf("present=%v line=%q, want an empty line", present, got)
				}
				return
			}
			if present != (tc.want != "") || string(got) != tc.want {
				t.Fatalf("lastLine = %q %v, want %q", got, present, tc.want)
			}
		})
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
