// SPDX-License-Identifier: Apache-2.0

// Package chain embeds the chain check's shared vectors (README.md, spec/record/v1/CHAIN.md): each a run directory's
// files and the verdict written by hand from the spec. Go's runners (pkg/spec/record/chaincheck, internal/ledger,
// test/rustdiff) read these bytes; rust/tego-record's runner reads the same files from disk.
package chain

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

//go:embed [0-9][0-9][0-9]-*.json
var files embed.FS

// Segment is one piece of a file: Text as UTF-8, Hex as raw bytes, or Repeat Count times.
type Segment struct {
	Text   *string `json:"text,omitempty"`
	Hex    *string `json:"hex,omitempty"`
	Repeat *string `json:"repeat,omitempty"`
	Count  int     `json:"count,omitempty"`
}

// Expect is a vector's handwritten expectation. Line, Lines, HeadLine, Anchored, TornBytes and Newer are checked only
// when the vector states them.
type Expect struct {
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
	Line      *int   `json:"line,omitempty"`
	Lines     *int   `json:"lines,omitempty"`
	HeadLine  *int   `json:"head_line,omitempty"`
	Anchored  *bool  `json:"anchored,omitempty"`
	TornBytes *int   `json:"torn_bytes,omitempty"`
	Newer     *int   `json:"newer,omitempty"`
}

// Vector is one case.
type Vector struct {
	File string `json:"-"`
	Name string `json:"name"`
	Rule string `json:"rule"`
	// Dir is the run directory's name.
	Dir string `json:"dir"`
	// EventsRaw is null for no events.jsonl, else its segments.
	EventsRaw json.RawMessage `json:"events"`
	// AnchorRaw is null for no anchor given, "absent" for an anchor path naming no file, else its segments.
	AnchorRaw json.RawMessage `json:"anchor"`
	Expect    Expect          `json:"expect"`
	// Finding, when set, is a known disagreement between Go and the spec on this vector: Go's runners hold Go to
	// Finding.Go, so the test fails the day Go changes, and say so; every other runner holds Expect.
	Finding *Finding `json:"finding,omitempty"`
}

// Finding is a recorded disagreement between Go and the spec (CHAIN.md), open until one side changes.
type Finding struct {
	Label string `json:"label"`
	Why   string `json:"why"`
	Go    Expect `json:"go"`
}

// GoExpect is what Go's runners hold Go to: Finding.Go when a finding is recorded, else Expect.
func (v Vector) GoExpect() Expect {
	if v.Finding != nil {
		return v.Finding.Go
	}
	return v.Expect
}

// Load reads every vector, in file order.
func Load() ([]Vector, error) {
	names, err := fs.Glob(files, "*.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]Vector, 0, len(names))
	for _, n := range names {
		b, err := files.ReadFile(n)
		if err != nil {
			return nil, err
		}
		var v Vector
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(&v); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		v.File = n
		out = append(out, v)
	}
	return out, nil
}

// Events is events.jsonl's bytes; ok is false when the run directory holds none.
func (v Vector) Events() (data []byte, ok bool, err error) {
	if isNull(v.EventsRaw) {
		return nil, false, nil
	}
	data, err = assemble(v.EventsRaw)
	return data, err == nil, err
}

// Anchor is chain.log: given says one is consulted, absent that its path names no file.
func (v Vector) Anchor() (data []byte, given, absent bool, err error) {
	switch {
	case isNull(v.AnchorRaw):
		return nil, false, false, nil
	case string(bytes.TrimSpace(v.AnchorRaw)) == `"absent"`:
		return nil, true, true, nil
	}
	data, err = assemble(v.AnchorRaw)
	return data, true, false, err
}

// HeadID is the id written on line n of events.jsonl (counted from 0), for Expect.HeadLine.
func (v Vector) HeadID(n int) (string, error) {
	data, _, err := v.Events()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	if n < 0 || n >= len(lines) {
		return "", fmt.Errorf("%s: no line %d", v.File, n)
	}
	m := idPattern.FindStringSubmatch(lines[n])
	if m == nil {
		return "", fmt.Errorf("%s: line %d has no id", v.File, n)
	}
	return m[1], nil
}

var idPattern = regexp.MustCompile(`"id":"([0-9a-f]{64})"`)

func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

func assemble(raw json.RawMessage) ([]byte, error) {
	var segs []Segment
	if err := json.Unmarshal(raw, &segs); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, s := range segs {
		switch {
		case s.Text != nil:
			b.WriteString(*s.Text)
		case s.Hex != nil:
			h, err := hex.DecodeString(*s.Hex)
			if err != nil {
				return nil, err
			}
			b.Write(h)
		case s.Repeat != nil && s.Count >= 0:
			b.WriteString(strings.Repeat(*s.Repeat, s.Count))
		default:
			return nil, errors.New("a segment that is not text, hex or repeat")
		}
	}
	return b.Bytes(), nil
}

// Result is one implementation's answer in the terms CHAIN.md §8 compares: verdict, reason, the line a finding names
// (AtLine and Line), how many lines chained and the head, and the counts a vector may state.
type Result struct {
	Verdict, Reason string
	AtLine          bool
	Line            uint64
	Lines           uint64
	Head            string
	Anchored        bool
	TornBytes       int
	Newer           int
}

// Judge lists how r differs from e, an expectation of v (Expect, or GoExpect for a Go runner). A cannot-check answer
// is judged on its verdict and reason alone.
func (v Vector) Judge(e Expect, r Result) []string {
	var out []string
	if r.Verdict != e.Verdict || r.Reason != e.Reason {
		out = append(out, fmt.Sprintf("got %s %s, want %s %s", r.Verdict, r.Reason, e.Verdict, e.Reason))
	}
	if r.Verdict == "cannot-check" {
		return out
	}
	if e.Line != nil && (!r.AtLine || r.Line != uint64(*e.Line)) {
		out = append(out, fmt.Sprintf("line: at %v %d, want %d", r.AtLine, r.Line, *e.Line))
	}
	if e.Line == nil && r.AtLine {
		out = append(out, fmt.Sprintf("line: at line %d, want no line", r.Line))
	}
	if e.Lines != nil && r.Lines != uint64(*e.Lines) {
		out = append(out, fmt.Sprintf("lines %d, want %d", r.Lines, *e.Lines))
	}
	if e.HeadLine != nil {
		want, herr := v.HeadID(*e.HeadLine)
		if herr != nil || r.Head != want {
			out = append(out, fmt.Sprintf("head %q, want line %d's id %q (%v)", r.Head, *e.HeadLine, want, herr))
		}
	} else if e.Lines != nil && *e.Lines == 0 && r.Head != "" {
		out = append(out, fmt.Sprintf("head %q, want none", r.Head))
	}
	if e.Anchored != nil && r.Anchored != *e.Anchored {
		out = append(out, fmt.Sprintf("anchored %v, want %v", r.Anchored, *e.Anchored))
	}
	if e.TornBytes != nil && r.TornBytes != *e.TornBytes {
		out = append(out, fmt.Sprintf("torn bytes %d, want %d", r.TornBytes, *e.TornBytes))
	}
	if e.Newer != nil && r.Newer != *e.Newer {
		out = append(out, fmt.Sprintf("newer %d, want %d", r.Newer, *e.Newer))
	}
	return out
}
