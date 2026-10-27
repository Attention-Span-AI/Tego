// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// The event details page's reads: one ledger line as written (Line), the lines around it (Context) and the lines
// that name the same file, program or destination across the ledger (Similar).

// LineFacts is one ledger line as written, with the envelope fields Event leaves out.
type LineFacts struct {
	// Raw is the line's exact bytes, without the newline.
	Raw    string
	ID     string
	Prev   string
	PID    int
	TID    int
	Cgroup uint64
	// Pretty is Raw indented, for reading; "" when it does not decode.
	Pretty string
}

// Line reads line seq of run from its events file. A malformed id, a missing run or a missing line is
// os.ErrNotExist.
func Line(root, run string, seq uint64) (*LineFacts, error) {
	if !validRunID(run) {
		return nil, os.ErrNotExist
	}
	f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, os.ErrNotExist
	}
	defer func() { _ = f.Close() }()
	// The read model knows where each line starts: read the one line there when the file is still the one it read,
	// instead of decoding every line before it. Anything that does not match falls back to the scan.
	if off, file, ok := Open(root).lineOffset(run, seq); ok {
		if fi, err := f.Stat(); err == nil {
			if now := idOf(fi); now.dev == file.dev && now.ino == file.ino && now.size >= file.size {
				if _, err := f.Seek(off, io.SeekStart); err == nil {
					sc := bufio.NewScanner(f)
					sc.Buffer(make([]byte, 64<<10), maxLineBytes)
					if sc.Scan() {
						if lf, ok := lineFacts(sc.Bytes(), seq); ok {
							return lf, nil
						}
					}
				}
			}
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), maxLineBytes)
	for sc.Scan() {
		if lf, ok := lineFacts(sc.Bytes(), seq); ok {
			return lf, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, os.ErrNotExist
}

// lineFacts is b's facts when b is line seq.
func lineFacts(b []byte, seq uint64) (*LineFacts, bool) {
	var head struct {
		Seq    uint64 `json:"seq"`
		ID     string `json:"id"`
		Prev   string `json:"prev"`
		PID    int    `json:"pid"`
		TID    int    `json:"tid"`
		Cgroup uint64 `json:"cgroup"`
	}
	if json.Unmarshal(b, &head) != nil || head.Seq != seq {
		return nil, false
	}
	lf := &LineFacts{Raw: string(b), ID: head.ID, Prev: head.Prev, PID: head.PID, TID: head.TID, Cgroup: head.Cgroup}
	var buf bytes.Buffer
	if json.Indent(&buf, b, "", "  ") == nil {
		lf.Pretty = buf.String()
	}
	return lf, true
}

// LinePlace is where a line starts in its run's events file (Off), and that file's device, inode and size when the
// read model read it: the event page hands it to the rule service, which reads that one line instead of every line
// before it (rulefile.FindAt checks it and scans when it does not hold).
type LinePlace struct {
	Off      int64
	Dev, Ino uint64
	Size     int64
}

// LineAt is where line seq of run starts, when the read model of root holds that run's lines; false otherwise.
func LineAt(root, run string, seq uint64) (LinePlace, bool) {
	if !validRunID(run) {
		return LinePlace{}, false
	}
	off, file, ok := Open(root).lineOffset(run, seq)
	if !ok {
		return LinePlace{}, false
	}
	return LinePlace{Off: off, Dev: file.dev, Ino: file.ino, Size: file.size}, true
}

// lineOffset is where line seq of run starts in its events file, and the file as the store read it, when the store
// holds that run's lines.
func (s *Store) lineOffset(run string, seq uint64) (int64, fileID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.runs[run]
	if st == nil || st.pub == nil || st.pub.Events == nil { // the published version: st may be being read
		return 0, fileID{}, false
	}
	evs := st.pub.Events
	i := sort.Search(len(evs), func(k int) bool { return evs[k].Seq >= seq })
	if i == len(evs) || evs[i].Seq != seq {
		return 0, fileID{}, false
	}
	return evs[i].off, st.pub.file, true
}

// Context is the n lines before and the n lines after line seq of r, and the line itself; ok is false when r has
// no line seq. It reads the run's resident lines (a binary search by seq, findSeq), never the events file.
func Context(r *Run, seq uint64, n int) (before []Event, at Event, after []Event, ok bool) {
	evs := r.AllEvents()
	i := findSeq(evs, seq)
	if i < 0 {
		return nil, Event{}, nil, false
	}
	lo, hi := max(0, i-n), min(len(evs), i+n+1)
	return evs[lo:i], evs[i], evs[i+1 : hi], true
}

// Subject is what a line names, as the "Similar" search matches it: the file of a read or write, the program of an
// exec (its basename) or the destination of a connection, with Class saying which ("file", "program",
// "destination"). A line that names none of them has an empty Class.
type Subject struct {
	Class string
	Value string
}

// SubjectOf is e's subject.
func SubjectOf(e *Event) Subject {
	class := ""
	switch e.Kind {
	case "fs":
		class = "file"
	case "exec":
		class = "program"
	case "net":
		class = "destination"
	case "refused":
		switch {
		case e.Reason == "exec-not-allowed":
			class = "program"
		case e.Reason == "net-not-allowed":
			class = "destination"
		case e.Reason == "read-denied" || strings.HasSuffix(e.Reason, "-outside-contract") || e.Reason == "path-unresolved":
			class = "file"
		}
	}
	if class == "" || e.Target == "" {
		return Subject{}
	}
	v := e.Target
	switch class {
	case "file":
		v, _, _ = strings.Cut(v, " → ")
	case "program":
		v = path.Base(strings.Fields(v)[0])
	case "destination":
		// "host (dst)" names the destination by its host name; a refusal names the address alone.
		if h, d, ok := strings.Cut(v, " ("); ok {
			if _, port, ok := strings.Cut(strings.TrimSuffix(d, ")"), ":"); ok && !strings.Contains(port, ":") {
				v = h + ":" + port
			} else {
				v = h
			}
		}
	}
	return Subject{Class: class, Value: v}
}

// SimilarRun is one run's count of lines with the same subject.
type SimilarRun struct {
	Run     string
	Agent   string
	Lines   int
	Refused int
	This    bool // the line's own run
}

// Similar is every line of the snapshot with the same subject as e: per run (the line's own run first, then the
// most lines first) and in all. A refused action's mirror is not counted again (pair.go).
type Similar struct {
	Subject Subject
	Runs    []SimilarRun
	Lines   int
	Refused int
}

// FindSimilar counts the lines of s with e's subject. A line with no subject has none.
func FindSimilar(s *Snapshot, e *Event) Similar {
	out := Similar{Subject: SubjectOf(e)}
	if out.Subject.Class == "" {
		return out
	}
	for _, r := range s.Runs {
		sr := SimilarRun{Run: r.ID, Agent: r.Agent, This: r.ID == e.Run}
		if c := r.subjectCounts()[out.Subject]; c != nil {
			sr.Lines, sr.Refused = c[0], c[1]
		}
		if sr.Lines > 0 {
			out.Runs = append(out.Runs, sr)
			out.Lines += sr.Lines
			out.Refused += sr.Refused
		}
	}
	sort.SliceStable(out.Runs, func(i, j int) bool {
		if out.Runs[i].This != out.Runs[j].This {
			return out.Runs[i].This
		}
		return out.Runs[i].Lines > out.Runs[j].Lines
	})
	return out
}
