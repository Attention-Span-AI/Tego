// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	// Version is the reason file's own version, its "v" key. The file is not a ledger line and takes no record minor.
	Version = 1
	// MaxFileBytes bounds the file: Decode refuses a longer one, and Encode never writes one (it lists fewer recent
	// refusals, then cuts long fields, until the file fits).
	MaxFileBytes = 64 << 10
	// RingSize is how many of the newest refusals the file lists at most (recent).
	RingSize = 32
	// MaxFieldBytes bounds each string field taken from a refused line's payload (a target is a string the agent
	// chose, up to the ledger's 2 MiB line). A longer one is cut to this length, the cut saying how long it was
	// (Cut); the ledger line keeps it whole.
	MaxFieldBytes = 4096
	// tightFieldBytes is the cut a single refusal gets when its fields at MaxFieldBytes still do not fit the file
	// (each byte of a field can take six in JSON): eight fields twice at 512 bytes, escaped, fit.
	tightFieldBytes = 512
)

// The errors Decode returns, wrapped with the detail.
var (
	ErrTooLarge = errors.New("reason: file larger than its bound")
	ErrVersion  = errors.New("reason: not a v1 reason file")
	ErrInvalid  = errors.New("reason: invalid reason file")
)

// Entry is one refusal of the file's recent list. Its fields are a fixed list (TestEntryFieldsAreTheListedOnes): the
// refused line's seq, ts and pid, its payload's op, target, reason and rule, the sentence Text makes of them, and the
// payload's mechanism and command rule when set. No other ledger field is copied, so a common field a later record
// minor adds never reaches the file by accident.
type Entry struct {
	Seq          uint64        `json:"seq"`
	TS           time.Time     `json:"ts"`
	PID          int           `json:"pid"`
	Op           string        `json:"op"`
	Target       string        `json:"target"`
	Reason       record.Reason `json:"reason"`
	Rule         string        `json:"rule"`
	Text         string        `json:"text"`
	Mechanism    string        `json:"mechanism,omitempty"`
	CommandRule  string        `json:"command_rule,omitempty"`
	CommandMatch string        `json:"command_match,omitempty"`
}

// File is last-refusal.json, v1. Its top level is the latest refusal: the keys the file had before v1 (op, target,
// reason, rule, mechanism, decision_plane, command_rule, command_match, a RefusedPayload with the line's reason and
// rule) keep their meaning, so a reader of that shape reads the latest refusal as before. v1 adds the file's
// version, the run, the latest line's seq, ts and pid, its sentence, how many refused lines the run has written, and
// the newest of them, oldest first.
type File struct {
	V             int           `json:"v"`
	Run           string        `json:"run"`
	Seq           uint64        `json:"seq"`
	TS            time.Time     `json:"ts"`
	PID           int           `json:"pid"`
	Op            string        `json:"op"`
	Target        string        `json:"target"`
	Reason        record.Reason `json:"reason"`
	Rule          string        `json:"rule"`
	Mechanism     string        `json:"mechanism,omitempty"`
	DecisionPlane string        `json:"decision_plane,omitempty"`
	CommandRule   string        `json:"command_rule,omitempty"`
	CommandMatch  string        `json:"command_match,omitempty"`
	Text          string        `json:"text"`
	// Refusals is how many refused lines the run's ledger had written when the file was; it only grows, and a
	// reader keeps it as its cursor (Since).
	Refusals uint64 `json:"refusals"`
	// Recent is the newest refusals, oldest first, at most RingSize, and always the latest one last. It is
	// contiguous: the refusals before Recent[0] are the first Refusals-len(Recent) of the run, none in between.
	Recent []Entry `json:"recent"`
}

// Refusal is one refused ledger line as the writer hands it to Encode: the line's seq, ts and pid, and its payload,
// whose Reason and Rule are the line's.
type Refusal struct {
	Seq     uint64
	TS      time.Time
	PID     int
	Payload record.RefusedPayload
	// full is, for each payload string Cut cut, its length before the cut (0 for one not cut), so a later cut, the
	// tight form's or the sentence's, states the field's real length and not the cut copy's.
	full fieldLens
}

// fieldLens is a length for each string field of a RefusedPayload.
type fieldLens struct{ op, target, reason, rule, mechanism, decisionPlane, commandRule, commandMatch int }

// field is one string field of a payload and its length in a fieldLens.
type field struct {
	s    *string
	full *int
}

// fields is p's string fields, each with its length in l.
func fields(p *record.RefusedPayload, l *fieldLens) [8]field {
	return [8]field{{&p.Op, &l.op}, {&p.Target, &l.target}, {(*string)(&p.Reason), &l.reason}, {&p.Rule, &l.rule},
		{&p.Mechanism, &l.mechanism}, {&p.DecisionPlane, &l.decisionPlane}, {&p.CommandRule, &l.commandRule},
		{&p.CommandMatch, &l.commandMatch}}
}

// Cut is r with every payload string longer than MaxFieldBytes cut to it, as Encode first cuts it, and the field's
// length before the cut kept: Encode of refusals Cut made is the bytes Encode makes of the refusals themselves, so a
// writer that holds refusals until it writes them keeps them this small. Cut of a cut refusal is itself.
func (r Refusal) Cut() Refusal {
	for _, f := range fields(&r.Payload, &r.full) {
		if len(*f.s) > MaxFieldBytes {
			*f.full = len(*f.s)
			*f.s = cutAt(*f.s, *f.full, MaxFieldBytes)
		}
	}
	return r
}

// Encode is the file after refusals refused lines of run, recent the newest of them (oldest first, at most
// RingSize, the latest last). The result is at most MaxFileBytes: string fields longer than MaxFieldBytes are cut,
// the oldest refusals are left out of recent while the file is too long (the counts stay exact: Since reports
// them as not listed), and a single refusal too long even then has its fields cut to 512 bytes. Every cut, and the
// sentence (text), states the field's real length, for a refusal Refusal.Cut already cut too.
func Encode(run string, refusals uint64, recent []Refusal) ([]byte, error) {
	if len(recent) == 0 || len(recent) > RingSize || refusals < uint64(len(recent)) {
		return nil, fmt.Errorf("%w: %d recent of %d refusals", ErrInvalid, len(recent), refusals)
	}
	for i := 1; i < len(recent); i++ {
		if recent[i].Seq <= recent[i-1].Seq {
			return nil, fmt.Errorf("%w: recent seq %d after %d", ErrInvalid, recent[i].Seq, recent[i-1].Seq)
		}
	}
	f := build(run, refusals, recent, MaxFieldBytes)
	b, err := json.Marshal(f)
	if err != nil || len(b) <= MaxFileBytes {
		return b, err
	}
	// Too long: keep the newest entries that fit beside everything else, sized one by one, so a flood of long
	// targets costs two encodings, not one per entry left out.
	all := f.Recent
	f.Recent = []Entry{}
	base, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	size, keep := len(base), 0
	for i := len(all) - 1; i >= 0; i-- {
		e, err := json.Marshal(all[i])
		if err != nil {
			return nil, err
		}
		if size+len(e)+1 > MaxFileBytes && keep > 0 {
			break
		}
		size += len(e) + 1
		keep++
	}
	f.Recent = all[len(all)-keep:]
	if b, err = json.Marshal(f); err != nil || len(b) <= MaxFileBytes {
		return b, err
	}
	f = build(run, refusals, recent[len(recent)-1:], tightFieldBytes)
	if b, err = json.Marshal(f); err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%w: one refusal of %d bytes", ErrTooLarge, len(b))
	}
	return b, nil
}

// build is the file of recent with every payload string cut to n bytes, each cut and the sentence stating the
// field's real length (Refusal.full when Cut already cut it).
func build(run string, refusals uint64, recent []Refusal, n int) *File {
	f := &File{V: Version, Run: run, Refusals: refusals, Recent: make([]Entry, len(recent))}
	for i, r := range recent {
		p, l := r.Payload, r.full
		for _, fl := range fields(&p, &l) {
			if *fl.full == 0 {
				*fl.full = len(*fl.s)
			}
			*fl.s = cutAt(*fl.s, *fl.full, n)
		}
		f.Recent[i] = Entry{Seq: r.Seq, TS: r.TS.UTC(), PID: r.PID, Op: p.Op, Target: p.Target, Reason: p.Reason,
			Rule: p.Rule, Text: text(p.Reason, p.Op, p.Target, p.Rule, l.op, l.target, l.rule), Mechanism: p.Mechanism,
			CommandRule: p.CommandRule, CommandMatch: p.CommandMatch}
		if i == len(recent)-1 {
			f.Seq, f.TS, f.PID, f.Text = r.Seq, r.TS.UTC(), r.PID, f.Recent[i].Text
			f.Op, f.Target, f.Reason, f.Rule = p.Op, p.Target, p.Reason, p.Rule
			f.Mechanism, f.DecisionPlane, f.CommandRule, f.CommandMatch = p.Mechanism, p.DecisionPlane, p.CommandRule, p.CommandMatch
		}
	}
	return f
}

// MinEntryBytes is at most the bytes the refusal with payload p takes as an entry of recent in a file Encode writes:
// the entry's payload strings, cut as Encode cuts them, each byte counted at the least JSON escapes it to. Encode
// lists the newest refusals that fit, so a writer whose newest refusals' bounds already pass MaxFileBytes need not
// decode the older ones: none of them would be listed.
func MinEntryBytes(p record.RefusedPayload) int {
	n := 0
	for _, s := range [...]string{p.Op, p.Target, string(p.Reason), p.Rule, p.Mechanism, p.CommandRule, p.CommandMatch} {
		if s != "" { // an empty optional field is left out
			n += minQuotedBytes(Cut(s, MaxFieldBytes))
		}
	}
	return n
}

// minQuotedBytes is at most len of s as a JSON string: its quotes, two bytes for a byte JSON escapes with a
// backslash and a letter, six for another control byte (always \u00XX), and one for any other byte.
func minQuotedBytes(s string) int {
	n := 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
	}
	return n
}

// Cut is s when it is at most n bytes; else its first bytes, at a UTF-8 boundary, then "…(<len(s)> bytes)", n bytes
// at most in all. A cut string is never cut again (its length is at most n).
func Cut(s string, n int) string { return cutAt(s, len(s), n) }

// cutAt is Cut of s, a field of full bytes or a cut of one (Refusal.Cut, whose first bytes are the field's): the
// length it states is full.
func cutAt(s string, full, n int) string {
	if len(s) <= n {
		return s
	}
	suffix := "…(" + strconv.Itoa(full) + " bytes)"
	k := max(0, n-len(suffix))
	for k > 0 && !utf8.RuneStart(s[k]) {
		k--
	}
	return s[:k] + suffix
}

// Decode reads one reason file from r: at most MaxFileBytes (ErrTooLarge past it), v1 (ErrVersion), and whole: at
// least one refusal, recent oldest first by seq, no longer than RingSize nor the refusal count, and its last entry
// the top level's refusal (ErrInvalid). Keys it does not know are ignored, so a field a later v1 adds does not
// break an older reader.
func Decode(r io.Reader) (*File, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reason: read: %w", err)
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, MaxFileBytes)
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if f.V != Version {
		return nil, fmt.Errorf("%w: v %d", ErrVersion, f.V)
	}
	n := len(f.Recent)
	switch {
	case n == 0 || f.Refusals == 0:
		return nil, fmt.Errorf("%w: no refusal", ErrInvalid)
	case n > RingSize || uint64(n) > f.Refusals:
		return nil, fmt.Errorf("%w: %d recent of %d refusals", ErrInvalid, n, f.Refusals)
	}
	for i := 1; i < n; i++ {
		if f.Recent[i].Seq <= f.Recent[i-1].Seq {
			return nil, fmt.Errorf("%w: recent seq %d after %d", ErrInvalid, f.Recent[i].Seq, f.Recent[i-1].Seq)
		}
	}
	if l := f.Recent[n-1]; l.Seq != f.Seq || l.Op != f.Op || l.Target != f.Target || l.Reason != f.Reason || l.Rule != f.Rule {
		return nil, fmt.Errorf("%w: the last recent refusal (seq %d) is not the latest (seq %d)", ErrInvalid, l.Seq, f.Seq)
	}
	return &f, nil
}

// Since is what a reader that has accounted for the run's first seen refusals has not: the refusals after them that
// the file lists, oldest first, and how many more came after them that it no longer lists (older than its recent
// list). seen is the Refusals of the file the reader read last, 0 for none. A seen at or past Refusals (the same
// file, or a cursor of another run) is nothing new.
func (f *File) Since(seen uint64) (entries []Entry, notListed uint64) {
	if seen >= f.Refusals {
		return nil, 0
	}
	first := f.Refusals - uint64(len(f.Recent)) // the refusals before Recent[0]
	if seen <= first {
		return f.Recent, first - seen
	}
	return f.Recent[seen-first:], 0
}
