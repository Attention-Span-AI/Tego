// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// scanIDs is the ids of the journal file's lines that decode as this version's, read straight from the file: the
// answer ReadJournal must give whatever it keeps from an earlier read.
func scanIDs(t *testing.T, root string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, JournalDirName, JournalFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.V != JournalVersion || e.ID == "" {
			continue
		}
		ids = append(ids, e.ID)
	}
	return ids
}

func readIDs(t *testing.T, root string) []string {
	t.Helper()
	es, err := ReadJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range es {
		ids = append(ids, e.ID)
	}
	return ids
}

func jAppend(t *testing.T, root, s string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, JournalDirName, JournalFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func jLine(id string) string {
	return fmt.Sprintf(`{"v":1,"id":%q,"op":"change","at":"2026-11-01T00:00:00Z","contract":"/p/a.yaml"}`+"\n", id)
}

// TestReadJournalFollowsTheFile: whatever happened to the journal file since a read, the next read gives what is
// in the file now: lines appended (also behind a torn one), the file shortened, replaced by another file, rewritten
// by a Prune, or its last line completed.
func TestReadJournalFollowsTheFile(t *testing.T) {
	g, path := fixture(t)
	root := g.LedgerRoot
	check := func(step string) {
		t.Helper()
		if got, want := readIDs(t, root), scanIDs(t, root); !slices.Equal(got, want) {
			t.Fatalf("%s: ReadJournal gave %v, the file holds %v", step, got, want)
		}
	}
	chain(t, g, path)
	check("first read")
	check("second read, nothing changed")
	jAppend(t, root, jLine("rc-a"))
	check("a line appended")
	jAppend(t, root, `{"v":1,"id":"rc-torn","op":"chan`)
	check("a torn last line")
	jAppend(t, root, "\n"+jLine("rc-b"))
	check("a line after the torn one")
	jAppend(t, root, `{"v":1,"id":"rc-c","op":"change","at":"2026-11-01T00:00:00Z"}`) // whole, but no newline yet
	check("a last line without its newline")
	jAppend(t, root, "\n")
	check("that line completed")

	jf := filepath.Join(root, JournalDirName, JournalFile)
	whole, err := os.ReadFile(jf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jf, whole[:len(whole)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	check("the file shortened in place")

	// Another file of the same length (and then a longer one) in the journal's place.
	other := []byte{}
	for i := 0; len(other) < len(whole); i++ {
		other = append(other, jLine(fmt.Sprintf("rc-other-%d", i))...)
	}
	if err := os.WriteFile(jf+".new", other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(jf+".new", jf); err != nil {
		t.Fatal(err)
	}
	check("the file replaced by a longer one")

	// A Prune rewrites the journal through a new file.
	clock(t, time.Now().Add(-60*day))
	g2, path2 := fixture(t)
	write(t, g2, path2, textA, textB)
	write(t, g2, path2, textB, textC)
	now = time.Now
	if got := readIDs(t, g2.LedgerRoot); len(got) != 2 {
		t.Fatalf("two writes, %d entries", len(got))
	}
	if err := os.Remove(path2); err != nil {
		t.Fatal(err)
	}
	ageBlobs(t, g2.LedgerRoot, 60*day)
	if _, err := Prune(context.Background(), g2.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil {
		t.Fatal(err)
	}
	if got, want := readIDs(t, g2.LedgerRoot), scanIDs(t, g2.LedgerRoot); !slices.Equal(got, want) || len(got) != 0 {
		t.Errorf("after a Prune: %v, the file holds %v; want none", got, want)
	}
}

// TestReadJournalOfAnUnchangedFileDecodesNothing: a journal read again with no line added costs what opening it
// costs, not a decode of its lines, and one line more costs that line: History and the creation check ran on every
// request and decoded the whole journal each time.
func TestReadJournalOfAnUnchangedFileDecodesNothing(t *testing.T) {
	g, path := fixture(t)
	chain(t, g, path)
	var b []byte
	const lines = 4000
	for i := range lines {
		b = append(b, jLine(fmt.Sprintf("rc-bulk-%d", i))...)
	}
	jAppend(t, g.LedgerRoot, string(b))
	if es, err := ReadJournal(g.LedgerRoot); err != nil || len(es) != lines+3 {
		t.Fatalf("%d entries, %v", len(es), err)
	}
	warm := testing.AllocsPerRun(5, func() {
		if _, err := ReadJournal(g.LedgerRoot); err != nil {
			t.Fatal(err)
		}
	})
	if warm > 200 {
		t.Errorf("a read of an unchanged journal of %d lines allocated %.0f objects", lines+3, warm)
	}
	jAppend(t, g.LedgerRoot, jLine("rc-one-more"))
	more := testing.AllocsPerRun(1, func() { // the first run reads the new line, the warm-up before it is the run itself
		if _, err := ReadJournal(g.LedgerRoot); err != nil {
			t.Fatal(err)
		}
	})
	if more > 400 {
		t.Errorf("a read of a journal one line longer allocated %.0f objects", more)
	}
}

// BenchmarkReadJournal is a read of a journal of 20,000 lines that has not changed since the last read (History and
// the creation check, once per request), and of one with a line added between the reads.
func BenchmarkReadJournal(b *testing.B) {
	b.ReportAllocs()
	root := b.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		b.Fatal(err)
	}
	j, err := openJournal(root)
	if err != nil {
		b.Fatal(err)
	}
	j.close()
	var buf []byte
	for i := range 20000 {
		buf = append(buf, jLine(fmt.Sprintf("rc-bulk-%d", i))...)
	}
	jf := filepath.Join(root, JournalDirName, JournalFile)
	if err := os.WriteFile(jf, buf, 0o600); err != nil {
		b.Fatal(err)
	}
	b.Run("unchanged", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := ReadJournal(root); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("one line added", func(b *testing.B) {
		b.ReportAllocs()
		f, err := os.OpenFile(jf, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			b.Fatal(err)
		}
		defer f.Close()
		for i := range b.N {
			if _, err := f.WriteString(jLine(fmt.Sprintf("rc-more-%d", i))); err != nil {
				b.Fatal(err)
			}
			if _, err := ReadJournal(root); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// scanEntries is the entries of the journal file's lines that decode as this version's, read straight from the file,
// as JSON: what ReadJournal must give whatever it kept from an earlier read, field for field.
func scanEntries(t *testing.T, root string) string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, JournalDirName, JournalFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.V != JournalVersion || e.ID == "" {
			continue
		}
		out = append(out, e)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readEntries(t *testing.T, root string) string {
	t.Helper()
	es, err := ReadJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(es)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestReadJournalNeverServesWhatTheFileNoLongerHolds: the memo of a journal is kept for the bytes it was decoded from,
// not for the file's name, inode, size or times, so each way of changing those bytes, in the middle of a file far
// longer than any end it could compare included, is read again and the answer is what the file holds now: an edit in
// place of the same length and one of another length, the same edit with the file's times put back, a file cut short
// and grown to its old size with other lines, a file replaced by another (also one of the same length and times), a
// line appended, a Prune's new file, and a last line that is still being written.
func TestReadJournalNeverServesWhatTheFileNoLongerHolds(t *testing.T) {
	g, path := fixture(t)
	root := g.LedgerRoot
	chain(t, g, path)
	jf := filepath.Join(root, JournalDirName, JournalFile)
	line := func(id, summary string) string {
		return fmt.Sprintf(`{"v":1,"id":%q,"op":"change","at":"2026-11-01T00:00:00Z","contract":"/p/a.yaml","summary":%q}`+"\n", id, summary)
	}
	var b []byte
	const lines = 400 // about 40 KB: the middle is far from the first and the last 4 KiB
	for i := range lines {
		b = append(b, line(fmt.Sprintf("nv-%04d", i), fmt.Sprintf("summary %04d", i))...)
	}
	jAppend(t, root, string(b))
	check := func(step string) {
		t.Helper()
		if got, want := readEntries(t, root), scanEntries(t, root); got != want {
			t.Fatalf("%s: ReadJournal served what the file does not hold\n got  %.300s\n want %.300s", step, got, want)
		}
	}
	check("first read")
	check("second read, nothing changed") // the memo is in use from here
	journalMemo.Lock()
	kept := journalMemo.m[root]
	journalMemo.Unlock()
	if kept == nil || kept.off < 30000 || len(kept.entries) < lines {
		t.Fatalf("the read kept no memo of the journal: %+v", kept)
	}

	whole, err := os.ReadFile(jf)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(jf)
	if err != nil {
		t.Fatal(err)
	}
	// edit rewrites one byte range of the file in place (the same inode), putting its times back when keepTimes.
	edit := func(at int, was, with string, keepTimes bool) {
		t.Helper()
		cur, err := os.ReadFile(jf)
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(cur[at:], []byte(was))
		if i < 0 {
			t.Fatalf("%q is not in the file after %d", was, at)
		}
		i += at
		f, err := os.OpenFile(jf, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt([]byte(with), int64(i)); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if keepTimes {
			if err := os.Chtimes(jf, fi.ModTime(), fi.ModTime()); err != nil {
				t.Fatal(err)
			}
		}
	}
	mid := len(whole) / 2

	edit(mid, "summary 02", "summary 99", false) // the same length, in the middle
	check("a middle line edited in place, the same length")
	edit(mid, "summary 99", "summary 02", true) // and back again, with the modification time put back
	check("the edit undone, the times put back")
	edit(mid, "summary 02", "summary 77", true)
	check("a middle line edited in place, the file's times put back")
	edit(mid, `"id":"nv-0`, `"id":"xx-0`, true) // an id, so the entry is another one
	check("a middle id edited in place")

	// Another length: the file rewritten in place with a longer line in the middle (the same inode, the old end kept).
	cur, err := os.ReadFile(jf)
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.Index(cur[mid:], []byte("\n")) + mid + 1
	longer := append(append(append([]byte{}, cur[:cut]...), line("nv-inserted", "an inserted line")...), cur[cut:]...)
	if err := os.WriteFile(jf, longer, 0o600); err != nil {
		t.Fatal(err)
	}
	check("a line inserted in the middle, rewritten in place")
	cur = longer

	// Cut short, then grown to the old size with other lines (the size, and the inode, are as before).
	if err := os.Truncate(jf, int64(len(cur)/3)); err != nil {
		t.Fatal(err)
	}
	check("the file cut to a third")
	regrown := append([]byte{}, cur[:len(cur)/3]...)
	for i := 0; len(regrown) < len(cur); i++ {
		regrown = append(regrown, line(fmt.Sprintf("rg-%d", i), "regrown")...)
	}
	if err := os.WriteFile(jf, regrown, 0o600); err != nil {
		t.Fatal(err)
	}
	check("the file grown again with other lines")
	// The same, but only the part after the first kept end is other: its start is as it was.
	if err := os.Truncate(jf, int64(len(regrown)/2)); err != nil {
		t.Fatal(err)
	}
	grown := append([]byte{}, regrown[:len(regrown)/2]...)
	for i := 0; len(grown) < len(regrown); i++ {
		grown = append(grown, line(fmt.Sprintf("rh-%d", i), "again")...)
	}
	if err := os.WriteFile(jf, grown, 0o600); err != nil {
		t.Fatal(err)
	}
	check("cut to half and grown past it")

	// Replaced by another file: the same length, the same modification time, a different inode.
	fi, err = os.Stat(jf)
	if err != nil {
		t.Fatal(err)
	}
	swapped := bytes.Replace(grown, []byte("again"), []byte("agaiN"), 3)
	if err := os.WriteFile(jf+".new", swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(jf+".new", fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(jf+".new", jf); err != nil {
		t.Fatal(err)
	}
	check("replaced by a file of the same length and time")

	jAppend(t, root, line("ap-1", "appended"))
	check("a line appended")
	jAppend(t, root, `{"v":1,"id":"ap-2","op":"change","summary":"unfinished`) // being written
	check("a last line not finished")
	edit(0, `"id":"ap-1"`, `"id":"ap-9"`, true) // a kept line edited while a line is unfinished
	check("a kept line edited while the last line is unfinished")
	jAppend(t, root, "\"}\n")
	check("the last line finished")
	// The first line of the file, edited.
	edit(0, `"op":"change"`, `"op":"chonge"`, true)
	check("the first line edited")

	// A file that is not there any more reads as none, and a new journal in its place as what it holds.
	if err := os.Remove(jf); err != nil {
		t.Fatal(err)
	}
	if es, err := ReadJournal(root); err == nil && len(es) != 0 {
		t.Errorf("a removed journal gave %d entries", len(es))
	}
}
