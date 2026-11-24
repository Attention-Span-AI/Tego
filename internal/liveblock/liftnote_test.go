// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// legacyLiftMAC is a lift's MAC as a launcher built before the note computes it: domain tego-live-lift-v1 over nine
// length-prefixed fields. A lift with no note must still check under it, so such a launcher keeps accepting it.
func legacyLiftMAC(key []byte, run string, c Change) string {
	m := hmac.New(sha256.New, key)
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	for _, f := range []string{"tego-live-lift-v1", run, strconv.FormatUint(c.Serial, 10), c.Op, string(c.Kind), c.Value, c.By,
		stamp(c.At), stamp(c.Until)} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write([]byte(f))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// TestLiftNoteIsSigned: a note is inside the lift's MAC. A lift with no note keeps the MAC an older launcher computes;
// a lift with one is MAC'ed in another domain with the note bound, so changing the note, taking it off or putting one
// on a lift that had none fails the check.
func TestLiftNoteIsSigned(t *testing.T) {
	key := make([]byte, 32)
	key[3] = 9
	o := New(testRun)
	plain, err := o.Lift(KindNet, "api.stripe.com:443", "uid:1 pid:2 cli", t0, t0.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Note != "" || plain.MAC != legacyLiftMAC(key, testRun, plain) {
		t.Fatalf("a lift with no note is MAC'ed as before the note: %+v, legacy %s", plain, legacyLiftMAC(key, testRun, plain))
	}
	noted, err := o.LiftNote(KindNet, "api.stripe.com:443", "uid:1 pid:2 cli", "ticket 4411", t0, t0.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if noted.Note != "ticket 4411" || !LiftMACOK(key, testRun, noted) {
		t.Fatalf("a lift with a note: %+v", noted)
	}
	if got := o.Changes[len(o.Changes)-1]; got != noted {
		t.Fatalf("the overlay lists %+v, LiftNote returned %+v", got, noted)
	}
	if noted.MAC == legacyLiftMAC(key, testRun, noted) {
		t.Fatal("a note is MAC'ed in the legacy domain, so an older launcher would take it as a lift with no note")
	}
	for name, c := range map[string]Change{
		"a changed note":      func() Change { c := noted; c.Note = "ticket 4412"; return c }(),
		"a note taken off":    func() Change { c := noted; c.Note = ""; return c }(),
		"a note put on":       func() Change { c := plain; c.Note = "ticket 4411"; return c }(),
		"a note with a space": func() Change { c := noted; c.Note += " "; return c }(),
	} {
		if LiftMACOK(key, testRun, c) {
			t.Errorf("%s still checks under the key", name)
		}
	}
	// The overlay's file keeps the note and the check still holds after an encode and a decode.
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(b, testRun)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Changes[len(back.Changes)-1]; !LiftMACOK(key, testRun, got) || got.Note != "ticket 4411" {
		t.Fatalf("after a round trip: %+v", got)
	}
	// A note edited in the file fails the launcher's check.
	edited := strings.Replace(string(b), "ticket 4411", "ticket 9999", 1)
	e, err := Decode([]byte(edited), testRun)
	if err != nil {
		t.Fatal(err)
	}
	if LiftMACOK(key, testRun, e.Changes[len(e.Changes)-1]) {
		t.Fatal("a note edited in live-block.json still checks")
	}
}

// TestNoteText: ValidNote, the writer's rule, and where the overlay refuses a note.
func TestNoteText(t *testing.T) {
	key := make([]byte, 32)
	good := []string{"", "the nightly export", strings.Repeat("a", MaxNote), "d\u00e9ploiement \u65e5\u672c\u8a9e", "100% \"quoted\" <b>&</b>"}
	bad := []string{strings.Repeat("a", MaxNote+1), "a\nb", "a\tb", "a\rb", "\x1b[31m", "a\x00b", "a\xffb", "a\u202eb", "a\u200bb",
		"a\u2028b", "a\u00a0b", "a\u0085b", "\u007f"}
	for _, s := range good {
		if err := ValidNote(s); err != nil {
			t.Errorf("ValidNote(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ValidNote(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidNote(%q) = %v, want ErrInvalid", s, err)
		}
		if _, err := New(testRun).LiftNote(KindRead, "/x", "b", s, t0, time.Time{}, key); !errors.Is(err, ErrInvalid) {
			t.Errorf("LiftNote(%q) = %v, want ErrInvalid", s, err)
		}
	}
	// The overlay's own check: a note on a restore, on a lift past the bound, and one with a control character.
	o := New(testRun)
	c, err := o.LiftNote(KindRead, "/x", "b", "ok", t0, time.Time{}, key)
	if err != nil {
		t.Fatal(err)
	}
	o.Changes[0].Note = "a\nb"
	if err := o.Validate(testRun); !errors.Is(err, ErrInvalid) {
		t.Errorf("an overlay with a control character in a note: %v", err)
	}
	o.Changes[0].Note = c.Note
	r, err := o.Restore(KindRead, "/x", "b", t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	o.Changes[len(o.Changes)-1].Note = "x"
	if err := o.Validate(testRun); !errors.Is(err, ErrInvalid) || r.Op != OpRestore {
		t.Errorf("a restore carrying a note: %v", err)
	}
}

// TestCheckNote: a note is asked only of a launcher that made the mark that it reads one; otherwise the writer refuses
// with ErrNoNote, in words that name the run and the way out, and a lift with no note is never refused for this.
func TestCheckNote(t *testing.T) {
	dir := t.TempDir()
	const run = "r-0123abcd-mabc12-aaaaaa"
	if err := CheckNote(dir, run, ""); err != nil {
		t.Fatalf("no note: %v", err)
	}
	err := CheckNote(dir, run, "ticket 4411")
	if !errors.Is(err, ErrNoNote) || !strings.Contains(RunWords(err), run) || !strings.Contains(RunWords(err), "without a note") {
		t.Fatalf("a launcher with no mark: %v", err)
	}
	if strings.Contains(err.Error(), run) {
		t.Errorf("the page's words name the run by id: %q", err)
	}
	if TakesNote(dir) {
		t.Fatal("TakesNote without the mark")
	}
	if err := MarkNote(dir); err != nil {
		t.Fatal(err)
	}
	if !TakesNote(dir) {
		t.Fatal("TakesNote after MarkNote")
	}
	if err := CheckNote(dir, run, "ticket 4411"); err != nil {
		t.Fatalf("a marked launcher: %v", err)
	}
	if err := CheckNote(dir, run, "a\nb"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a note with a line break: %v", err)
	}
	// A mark that is a symlink or a directory is no mark.
	other := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, NoteName), filepath.Join(other, NoteName)); err != nil {
		t.Fatal(err)
	}
	if TakesNote(other) {
		t.Error("a symlinked mark counts")
	}
}
