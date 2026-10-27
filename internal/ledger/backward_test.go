// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// backwardCase is one events.jsonl the equivalence test reads both ways.
type backwardCase struct {
	name string
	data []byte
	dir  string // a run directory to read instead of data
}

// fixtureBytes is the record fixture, a whole run of 98 lines ending in run_end.
func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// replaceLine replaces the line at index i (from 0) of data with line.
func replaceLine(data []byte, i int, line string) []byte {
	lines := bytes.SplitAfter(data, []byte("\n"))
	lines[i] = []byte(line + "\n")
	return bytes.Join(lines, nil)
}

// TestBackwardReadsWhatEntriesReads is Backward's contract: the lines Entries yields, last first, with the same
// decoding, the same torn-tail rule (a torn tail is passed over, bytes after run_end are corrupt), the same
// newer-version skipping and the same error, worded the same, for a line that does not decode or is too long, read
// in blocks small enough that lines straddle them. Where Entries stops at a corrupt line, Backward yields the lines
// after it, last first, and then the same error.
func TestBackwardReadsWhatEntriesReads(t *testing.T) {
	src := fixtureBytes(t)
	lines := bytes.Split(bytes.TrimSuffix(src, []byte("\n")), []byte("\n"))
	noRunEnd := bytes.Join(lines[:len(lines)-1], []byte("\n"))
	noRunEnd = append(noRunEnd, '\n')
	long := bytes.Repeat([]byte("x"), MaxLineBytes)
	cases := []backwardCase{
		{name: "empty", data: nil},
		{name: "a whole run", data: src},
		{name: "two runs end to end", data: append(slices.Clone(src), src...)},
		{name: "the last line lost its newline", data: bytes.TrimSuffix(src, []byte("\n"))},
		{name: "one line with no newline", data: lines[0]},
		{name: "a torn tail", data: append(slices.Clone(noRunEnd), `{"v":1,"seq":`...)},
		{name: "a torn tail and nothing else", data: []byte(`{"v":1,"seq":`)},
		{name: "bytes after run_end", data: append(slices.Clone(src), "\x00\x00\x00"...)},
		{name: "a corrupt middle line", data: replaceLine(src, 40, "garbage")},
		{name: "an empty middle line", data: replaceLine(src, 60, "")},
		{name: "a corrupt first line", data: replaceLine(src, 0, `{"v":1}`)},
		{name: "a corrupt last line", data: replaceLine(src, len(lines)-1, "[]")},
		{name: "a line too long in the middle", data: replaceLine(src, 50, string(long))},
		{name: "a line too long at the end, terminated", data: append(slices.Clone(src), append(long, '\n')...)},
		{name: "a torn tail too long", data: append(slices.Clone(noRunEnd), long...)},
		{name: "a newer version's line", dir: newerRun(t, "2")},
	}
	for _, tc := range cases {
		dir := tc.dir
		if dir == "" {
			dir = t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, EventsFile), tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, skipNewer := range []bool{false, true} {
			for _, block := range []int{0, 1, 7, 333} {
				name := tc.name + "/skip=" + strconv.FormatBool(skipNewer) + "/block=" + strconv.Itoa(block)
				forward, fskipped, ferr := readEntries(t, dir, skipNewer, block, false)
				backward, bskipped, berr := readEntries(t, dir, skipNewer, block, true)
				slices.Reverse(backward)
				// Entries stops at its first error; Backward reaches the same line from the other end, so it
				// has yielded only the lines after it. With no error both are the whole ledger.
				if ferr == nil && !slices.Equal(backward, forward) {
					t.Errorf("%s: Backward read %d lines, Entries %d", name, len(backward), len(forward))
				}
				if ferr != nil && !slices.Equal(backward, linesAfter(t, dir, ferr)) {
					t.Errorf("%s: Backward read %d lines before %v, want the %d after that line", name, len(backward), ferr,
						len(linesAfter(t, dir, ferr)))
				}
				if (ferr == nil) != (berr == nil) || (ferr != nil && ferr.Error() != berr.Error()) {
					t.Errorf("%s: Backward err %v, Entries err %v", name, berr, ferr)
				}
				if ferr == nil && fskipped != bskipped {
					t.Errorf("%s: Backward skipped %d newer lines, Entries %d", name, bskipped, fskipped)
				}
			}
		}
	}
}

// readEntries reads every entry of dir's ledger, forwards (Entries) or backwards, and returns the stored lines, the
// newer-version lines skipped, and the error that ended the read.
func readEntries(t *testing.T, dir string, skipNewer bool, block int, backward bool) ([]string, int, error) {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	r.scanSize = block
	if skipNewer {
		r.SkipNewerVersions()
	}
	seq := r.Entries()
	if backward {
		seq = r.Backward()
	}
	var out []string
	for en, err := range seq {
		if err != nil {
			return out, r.SkippedNewer(), err
		}
		if en.Event == nil {
			t.Fatal("an entry with no event")
		}
		out = append(out, string(en.Line))
	}
	return out, r.SkippedNewer(), nil
}

// linesAfter is the complete lines of dir's ledger after the one err names ("corrupt line N: ..."), the lines
// Backward yields before it meets that line. A torn tail after run_end names the tail, which Backward meets at the
// run_end line before it, having yielded nothing.
func linesAfter(t *testing.T, dir string, err error) []string {
	t.Helper()
	data, rerr := os.ReadFile(filepath.Join(dir, EventsFile))
	if rerr != nil {
		t.Fatal(rerr)
	}
	m := regexp.MustCompile(`corrupt line (\d+):`).FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("%v names no line", err)
	}
	n, _ := strconv.Atoi(m[1])
	all := strings.Split(string(data), "\n")
	if len(all) > 0 && all[len(all)-1] == "" {
		all = all[:len(all)-1] // the empty string after the last "\n"
	}
	if strings.Contains(err.Error(), "after run_end") || n >= len(all) {
		return nil
	}
	return all[n:]
}

// TestBackwardStopsReadingAtTheCallersLine: a caller that takes the newest line reads about one block from the end,
// whatever the ledger's length. A reader whose file holds a corrupt line far from the end is not stopped by it, as
// State is not: Backward never reads that far.
func TestBackwardStopsReadingAtTheCallersLine(t *testing.T) {
	src := fixtureBytes(t)
	big := bytes.Repeat(src, 200)
	big = replaceLine(big, 3, "garbage") // damage near the start
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, EventsFile), big, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	counter := &countingReaderAt{f: r.f}
	b := &backScanner{f: counter, end: int64(len(big)), block: backBlock}
	l, ok, err := b.prev()
	if err != nil || !ok || !bytes.Contains(l.data, []byte(`"kind":"run_end"`)) {
		t.Fatalf("prev = %q, %v, %v; want the run_end line", l.data, ok, err)
	}
	if counter.n > backBlock {
		t.Errorf("read %d bytes for the last line of a %d-byte ledger, want at most %d", counter.n, len(big), backBlock)
	}
	for en, err := range r.Backward() {
		if err != nil {
			t.Fatalf("Backward: %v", err)
		}
		if en.Event.Kind != "run_end" {
			t.Fatalf("first entry %s, want run_end", en.Event.Kind)
		}
		break
	}
}

// TestBackwardReadsOnlyTheSizeItStartedWith: bytes a live Writer appends after Backward stats the file are not
// read, so a line half-written then is never taken for one.
func TestBackwardReadsOnlyTheSizeItStartedWith(t *testing.T) {
	src := fixtureBytes(t)
	dir := t.TempDir()
	path := filepath.Join(dir, EventsFile)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	n := 0
	for _, err := range r.Backward() {
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(`{"v":1,"seq":99,`); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}
		n++
	}
	if n != 98 {
		t.Fatalf("Backward read %d lines, want the 98 there were when it started", n)
	}
	if _, err := os.Stat(path); err != nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
