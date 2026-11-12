// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestRunStartDenyReadFrozen: run_start.deny_read_frozen (MinorDenyReadFrozen, GAPS A12) is refused below its revision
// and when malformed [deny-read-frozen], and is valid as the writer makes it, whatever directories the ruleset listed:
// unsorted, repeated, past the bound, not UTF-8, holding a control character or too long. Such a directory is counted
// in omitted, never named, so the field cannot stop a run_start from being written.
func TestRunStartDenyReadFrozen(t *testing.T) {
	ok := &DenyReadFrozen{Dirs: []string{"/", "/home", "/home/u"}}
	if err := (&RunStartPayload{RecordMinor: MinorDenyReadFrozen, DenyReadFrozen: ok}).ValidateFields(); err != nil {
		t.Fatalf("a valid field at its revision: %v", err)
	}
	many := make([]string, MaxDenyReadFrozen+1)
	for i := range many {
		many[i] = fmt.Sprintf("/d%03d", i)
	}
	for _, tc := range []struct {
		name  string
		minor int
		f     *DenyReadFrozen
		code  string
	}{
		{"below its revision", MinorDenyReadFrozen - 1, ok, "below-minor"},
		{"no dirs key", MinorDenyReadFrozen, &DenyReadFrozen{Omitted: 1}, "deny-read-frozen"},
		{"nothing named or omitted", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{}}, "deny-read-frozen"},
		{"relative", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{"home"}}, "deny-read-frozen"},
		{"not clean", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{"/home/"}}, "deny-read-frozen"},
		{"control character", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{"/a\x1b[2J"}}, "deny-read-frozen"},
		{"unsorted", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{"/home", "/"}}, "deny-read-frozen"},
		{"repeated", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{"/", "/"}}, "deny-read-frozen"},
		{"too many", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: many}, "deny-read-frozen"},
		{"negative omitted", MinorDenyReadFrozen, &DenyReadFrozen{Dirs: []string{"/"}, Omitted: -1}, "deny-read-frozen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (&RunStartPayload{RecordMinor: tc.minor, DenyReadFrozen: tc.f}).ValidateFields()
			if got := FieldCode(err); got != tc.code {
				t.Errorf("ValidateFields = %v (code %q), want [%s]", err, got, tc.code)
			}
			if err != nil && strings.ContainsRune(err.Error(), 0x1b) {
				t.Errorf("the refusal carries the raw control character: %q", err)
			}
		})
	}

	if NewDenyReadFrozen(nil) != nil || NewDenyReadFrozen([]string{}) != nil {
		t.Error("no directory listed must write no field")
	}
	listed := append([]string{"/home/u", "/", "/home", "/home", "/bad\xff", "/c\x07", "/" + strings.Repeat("x", MaxSharePathBytes)}, many...)
	f := NewDenyReadFrozen(listed)
	// The deepest 64 are named, in byte order: /home/u and the first 63 of the 66 at depth 1.
	if len(f.Dirs) != MaxDenyReadFrozen || f.Dirs[0] != "/d000" || f.Dirs[len(f.Dirs)-1] != "/home/u" {
		t.Errorf("NewDenyReadFrozen named %d, first %q, last %q", len(f.Dirs), f.Dirs[0], f.Dirs[len(f.Dirs)-1])
	}
	// 3 not UTF-8, unprintable or too long, and the 4 shallowest printable ones past 64 (/, /home, /d063, /d064), are
	// omitted.
	if total := len(f.Dirs) + f.Omitted; total != len(listed)-1 {
		t.Errorf("named %d and omitted %d, want every one of the %d distinct directories accounted for", len(f.Dirs), f.Omitted, len(listed)-1)
	}
	if err := (&RunStartPayload{RecordMinor: MinorDenyReadFrozen, DenyReadFrozen: f}).ValidateFields(); err != nil {
		t.Errorf("the writer's field is refused: %v", err)
	}
	only := NewDenyReadFrozen([]string{"/c\x07"})
	if only == nil || len(only.Dirs) != 0 || only.Omitted != 1 {
		t.Fatalf("one unprintable directory = %+v, want dirs [] and omitted 1", only)
	}
	if err := (&RunStartPayload{RecordMinor: MinorDenyReadFrozen, DenyReadFrozen: only}).ValidateFields(); err != nil {
		t.Errorf("the writer's field is refused: %v", err)
	}
	b, err := json.Marshal(only)
	if err != nil || string(b) != `{"dirs":[],"omitted":1}` {
		t.Errorf("encoded %s, %v", b, err)
	}
}

// TestNewDenyReadFrozenKeepsTheDeepest: past MaxDenyReadFrozen the field names the deepest directories and counts the
// shallowest in omitted. Every ancestor of a frozen directory is frozen too, so a named directory implies the ones
// above it; the deepest are where a person makes names (their home, the project). Byte order would have kept "/" and
// the 70 shallow /aNN and left out /w/u/proj, which sorts after them.
func TestNewDenyReadFrozenKeepsTheDeepest(t *testing.T) {
	listed := []string{"/w/u/proj", "/w/u", "/w", "/"}
	for i := range 70 {
		listed = append(listed, fmt.Sprintf("/a%02d", i))
	}
	f := NewDenyReadFrozen(listed)
	if len(f.Dirs) != MaxDenyReadFrozen || f.Omitted != len(listed)-MaxDenyReadFrozen {
		t.Fatalf("named %d and omitted %d of %d", len(f.Dirs), f.Omitted, len(listed))
	}
	named := map[string]bool{}
	for _, d := range f.Dirs {
		named[d] = true
	}
	for _, d := range []string{"/w/u/proj", "/w/u", "/a00", "/a61"} {
		if !named[d] {
			t.Errorf("%s is not named: %v", d, f.Dirs)
		}
	}
	for _, d := range []string{"/", "/w", "/a62", "/a69"} {
		if named[d] {
			t.Errorf("%s is named, though a deeper directory was left out for it", d)
		}
	}
	if err := (&RunStartPayload{RecordMinor: MinorDenyReadFrozen, DenyReadFrozen: f}).ValidateFields(); err != nil {
		t.Errorf("the writer's field is refused: %v", err)
	}
}

// TestRunStartDenyReadFrozenAtTheLine: ValidateAt, which the Writer runs on the line it writes and Verify on the line
// it reads, reads deny_read_frozen exactly; a run_start without it, at any revision, passes as before; and an unknown
// run_start key beside it is ignored (docs/VERSIONING.md §2), which is what a reader built before revision 30 does
// with deny_read_frozen itself.
func TestRunStartDenyReadFrozenAtTheLine(t *testing.T) {
	line := func(minor int, extra string) *Event {
		return base(KindRunStart, fmt.Sprintf(`{"record_minor":%d%s}`, minor, extra))
	}
	for _, tc := range []struct {
		name  string
		e     *Event
		minor int
		code  string
	}{
		{"absent at 29", line(29, ""), 29, ""},
		{"absent at 30", line(30, ""), 30, ""},
		{"at 30", line(30, `,"deny_read_frozen":{"dirs":["/","/home"]}`), 30, ""},
		{"omitted only", line(30, `,"deny_read_frozen":{"dirs":[],"omitted":2}`), 30, ""},
		{"unknown key beside it", line(30, `,"deny_read_frozen":{"dirs":["/"],"later":1},"frozen_later":true`), 30, ""},
		{"at 29", line(29, `,"deny_read_frozen":{"dirs":["/"]}`), 29, "below-minor"},
		{"null", line(30, `,"deny_read_frozen":null`), 30, "deny-read-frozen"},
		{"a list", line(30, `,"deny_read_frozen":["/"]`), 30, "deny-read-frozen"},
		{"dirs null", line(30, `,"deny_read_frozen":{"dirs":null}`), 30, "deny-read-frozen"},
		{"spelt otherwise", line(30, `,"Deny_Read_Frozen":{"dirs":["/"]}`), 30, "field-case"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.e.ValidateAt(tc.minor)
			if got := FieldCode(err); got != tc.code || tc.code == "" && err != nil {
				t.Errorf("ValidateAt = %v (code %q), want %q", err, got, tc.code)
			}
		})
	}
	var p RunStartPayload
	if err := line(30, `,"deny_read_frozen":{"dirs":["/","/home"],"omitted":1}`).DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.DenyReadFrozen == nil || strings.Join(p.DenyReadFrozen.Dirs, ",") != "/,/home" || p.DenyReadFrozen.Omitted != 1 {
		t.Errorf("decoded %+v", p.DenyReadFrozen)
	}
}
