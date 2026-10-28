// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// goldenOverlay is an overlay with every kind of block and change a Locked run had before time limits: adds, a
// remove, a pause and a resume, at fixed instants.
func goldenOverlay(t *testing.T) *Overlay {
	t.Helper()
	at := time.Date(2026, 10, 27, 12, 0, 0, 123_000_000, time.UTC)
	o := New(testRun)
	for i, s := range []struct {
		kind  Kind
		value string
	}{{KindExec, "/usr/bin/curl"}, {KindNet, "example.com:443"}, {KindPath, "/home/u/p/.env"}, {KindRead, "/srv/data"},
		{KindWrite, "/srv/out"}, {KindExec, "wget"}} {
		if _, _, err := o.Add(s.kind, s.value, "uid:1000 pid:7 cli", at.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := o.Remove(KindExec, "wget", "uid:1000 pid:8 dashboard", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	o.Pause("uid:1000 pid:9 dashboard", at.Add(2*time.Minute))
	o.Resume("uid:1000 pid:9 dashboard", at.Add(3*time.Minute))
	return o
}

// TestOverlayV1Golden is the Locked-unchanged test (ADR 0125 "What stays the same in Locked"): an overlay that uses
// no time limit and no fence op encodes byte for byte as the base build encoded it, at version 1, so an older
// launcher reads it exactly as before. testdata/overlay_v1_golden.json was captured from the base build.
func TestOverlayV1Golden(t *testing.T) {
	b, err := goldenOverlay(t).Encode()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "overlay_v1_golden.json")
	if os.Getenv("TEGO_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("an overlay with no time limit encodes as\n%s\nwant (the base build's bytes)\n%s", b, want)
	}
	o, err := Decode(want, testRun)
	if err != nil || o.V != Version {
		t.Fatalf("the golden decodes as version %v (%v)", o, err)
	}
}

// fakeClock replaces readClock for the test with a reading the test moves.
type fakeClock struct{ c Clock }

func installClock(t *testing.T, wall time.Time, boot time.Duration) *fakeClock {
	t.Helper()
	f := &fakeClock{c: Clock{Wall: wall, Boot: boot}}
	old := readClock
	readClock = func() Clock { return f.c }
	t.Cleanup(func() { readClock = old })
	return f
}

// set moves both clocks to the instant t, keeping them in step (BOOTTIME advances as the wall clock does).
func (f *fakeClock) set(t time.Time) {
	f.c.Boot += t.Sub(f.c.Wall)
	f.c.Wall = t
}

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// TestEncodeVersion: Encode writes the lowest version that holds the content.
func TestEncodeVersion(t *testing.T) {
	key := make([]byte, 32)
	for _, c := range []struct {
		name string
		fill func(o *Overlay) error
		want int
	}{
		{"plain", func(o *Overlay) error { _, _, err := o.Add(KindExec, "curl", "b", t0); return err }, Version},
		{"pause", func(o *Overlay) error { o.Pause("b", t0); return nil }, Version},
		{"block until", func(o *Overlay) error {
			_, _, err := o.AddUntil(KindExec, "curl", "b", t0, t0.Add(time.Hour))
			return err
		}, VersionTimed},
		{"unblock until", func(o *Overlay) error {
			if _, _, err := o.Add(KindExec, "curl", "b", t0); err != nil {
				return err
			}
			_, _, err := o.RemoveUntil(KindExec, "curl", "b", t0, t0.Add(time.Hour))
			return err
		}, VersionTimed},
		{"lift", func(o *Overlay) error { _, err := o.Lift(KindRead, "/srv/x", "b", t0, time.Time{}, key); return err }, VersionModes},
		{"restore", func(o *Overlay) error { _, err := o.Restore(KindNet, "api.example.com:443", "b", t0); return err }, VersionModes},
	} {
		o := New(testRun)
		if err := c.fill(o); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		b, err := o.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.name, err)
		}
		back, err := Decode(b, testRun)
		if err != nil || back.V != c.want || o.V != c.want {
			t.Fatalf("%s: encoded at version %d (decoded %v, %v), want %d", c.name, o.V, back, err, c.want)
		}
	}
}

// TestValidateRefusesTimed: every field newer than the file's version is refused, and so is a limit that is not one.
func TestValidateRefusesTimed(t *testing.T) {
	mac := strings.Repeat("ab", 32)
	run := `"run":"` + testRun + `"`
	blk := `{"kind":"path","value":"/y","by":"b","at":"2026-10-27T12:00:00Z"`
	chg := func(op, rest string) string {
		return `"serial":1,"changes":[{"serial":1,"op":"` + op + `","by":"b","at":"2026-10-27T12:00:00Z"` + rest + `}]`
	}
	for name, body := range map[string]string{
		"until in v1":         `{"v":1,` + run + `,"blocks":[` + blk + `,"until":"2026-10-27T13:00:00Z"}]}`,
		"from in v1":          `{"v":1,` + run + `,"blocks":[` + blk + `,"from":"2026-10-27T13:00:00Z"}]}`,
		"change until in v1":  `{"v":1,` + run + `,` + chg("add", `,"kind":"path","value":"/y","until":"2026-10-27T13:00:00Z"`) + `}`,
		"lift in v2":          `{"v":2,` + run + `,` + chg("lift", `,"kind":"read","value":"/y","mac":"`+mac+`"`) + `}`,
		"restore in v2":       `{"v":2,` + run + `,` + chg("restore", `,"kind":"read","value":"/y"`) + `}`,
		"until at at":         `{"v":2,` + run + `,"blocks":[` + blk + `,"until":"2026-10-27T12:00:00Z"}]}`,
		"until before at":     `{"v":2,` + run + `,` + chg("add", `,"kind":"path","value":"/y","until":"2026-10-27T11:00:00Z"`) + `}`,
		"from at until":       `{"v":2,` + run + `,"blocks":[` + blk + `,"until":"2026-10-27T14:00:00Z","from":"2026-10-27T14:00:00Z"}]}`,
		"lift without mac":    `{"v":3,` + run + `,` + chg("lift", `,"kind":"read","value":"/y"`) + `}`,
		"lift upper-case mac": `{"v":3,` + run + `,` + chg("lift", `,"kind":"read","value":"/y","mac":"`+strings.ToUpper(mac)+`"`) + `}`,
		"lift of a path":      `{"v":3,` + run + `,` + chg("lift", `,"kind":"path","value":"/y","mac":"`+mac+`"`) + `}`,
		"lift not normalized": `{"v":3,` + run + `,` + chg("lift", `,"kind":"read","value":"/y/../z","mac":"`+mac+`"`) + `}`,
		"restore with mac":    `{"v":3,` + run + `,` + chg("restore", `,"kind":"read","value":"/y","mac":"`+mac+`"`) + `}`,
		"restore with until":  `{"v":3,` + run + `,` + chg("restore", `,"kind":"read","value":"/y","until":"2026-10-27T13:00:00Z"`) + `}`,
		"add with mac":        `{"v":3,` + run + `,` + chg("add", `,"kind":"path","value":"/y","mac":"`+mac+`"`) + `}`,
		"pause with until":    `{"v":2,` + run + `,"paused":true,` + chg("pause", `,"until":"2026-10-27T13:00:00Z"`) + `}`,
		"version 0":           `{"v":0,` + run + `}`,
		"version 5":           `{"v":5,` + run + `}`,
	} {
		if _, err := Decode([]byte(body), testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Decode = %v, want ErrInvalid", name, err)
		}
	}
	for name, body := range map[string]string{
		"until in v2": `{"v":2,` + run + `,"blocks":[` + blk + `,"until":"2026-10-27T13:00:00Z"}]}`,
		"lift in v3":  `{"v":3,` + run + `,` + chg("lift", `,"kind":"read","value":"/y","mac":"`+mac+`"`) + `}`,
	} {
		if _, err := Decode([]byte(body), testRun); err != nil {
			t.Errorf("%s: Decode = %v", name, err)
		}
	}
	// A file cannot name a fence refusal: the flag is not a field.
	o, err := Decode([]byte(`{"v":1,`+run+`,"blocks":[`+blk+`,"fence":true,"Fence":true}]}`), testRun)
	if err != nil || o.Blocks[0].Fence || o.Blocks[0].Rule() != "live.block[path:/y]" {
		t.Fatalf("a file's fence key: %+v, %v", o, err)
	}
}

// TestAddUntilRemoveUntil: a limit is set, kept, changed and cleared by adds and removes, each recorded once.
func TestAddUntilRemoveUntil(t *testing.T) {
	o := New(testRun)
	end := t0.Add(72 * time.Hour)
	if _, _, err := o.AddUntil(KindExec, "/bin/ls", "b", t0, t0.Add(30*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a 30 s limit: %v, want ErrInvalid (1 minute to 400 days)", err)
	}
	if _, _, err := o.AddUntil(KindExec, "/bin/ls", "b", t0, t0.Add(401*24*time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a 401 day limit: %v, want ErrInvalid", err)
	}
	c, ok, err := o.AddUntil(KindExec, "/bin/ls", "b", t0, end)
	if err != nil || !ok || !c.Until.Equal(end) || c.Op != OpAdd || c.Serial != 1 {
		t.Fatalf("AddUntil = %+v, %v, %v", c, ok, err)
	}
	if _, ok, _ := o.AddUntil(KindExec, "/bin/ls", "b", t0, end); ok {
		t.Fatal("the same block with the same limit was added again")
	}
	// A re-add with no limit makes it last the rest of the run.
	c, ok, err = o.Add(KindExec, "/bin/ls", "b2", t0.Add(time.Minute))
	if err != nil || !ok || !c.Until.IsZero() || len(o.Blocks) != 1 || !o.Blocks[0].Until.IsZero() || o.Blocks[0].By != "b2" {
		t.Fatalf("re-add with no limit: %+v %v %v, blocks %+v", c, ok, err, o.Blocks)
	}
	if _, ok, _ := o.Add(KindExec, "/bin/ls", "b", t0); ok {
		t.Fatal("a plain re-add of a block in force with no end changed it")
	}
	// An unblock for a while keeps the block dormant until then.
	back := t0.Add(2 * time.Hour)
	c, ok, err = o.RemoveUntil(KindExec, "/bin/ls", "b", t0.Add(time.Hour), back)
	if err != nil || !ok || c.Op != OpRemove || !c.Until.Equal(back) || len(o.Blocks) != 1 || !o.Blocks[0].From.Equal(back) {
		t.Fatalf("RemoveUntil = %+v %v %v, blocks %+v", c, ok, err, o.Blocks)
	}
	if _, ok, _ := o.RemoveUntil(KindExec, "/bin/ls", "b", t0.Add(time.Hour), back); ok {
		t.Fatal("the same unblock was recorded twice")
	}
	// A re-add of a dormant block puts it back in force now.
	if _, ok, _ := o.Add(KindExec, "/bin/ls", "b", t0.Add(90*time.Minute)); !ok || !o.Blocks[0].From.IsZero() {
		t.Fatalf("re-add of a dormant block: %v, %+v", ok, o.Blocks)
	}
	// An unblock that outlasts the block's own end removes it.
	if _, _, err := o.AddUntil(KindNet, "example.com", "b", t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c, ok, err = o.RemoveUntil(KindNet, "example.com", "b", t0, t0.Add(3*time.Hour))
	if err != nil || !ok || !c.Until.IsZero() {
		t.Fatalf("an unblock past the block's end: %+v %v %v", c, ok, err)
	}
	if _, ok := o.Find(KindNet, "example.com"); ok {
		t.Fatal("an unblock past the block's end kept it")
	}
	if _, ok, _ := o.Remove(KindExec, "/bin/ls", "b", t0); !ok || len(o.Blocks) != 0 {
		t.Fatalf("remove: %v, %+v", ok, o.Blocks)
	}
	if _, err := o.Encode(); err != nil {
		t.Fatal(err)
	}
}

// TestMatchStopsAtTheInstant: a block with a limit refuses 1 ns before it and nothing at it, for a path, a program
// and a destination; the clock is read only by a timed Set.
func TestMatchStopsAtTheInstant(t *testing.T) {
	end := t0.Add(time.Hour)
	fc := installClock(t, t0, 10*time.Second)
	o := New(testRun)
	for _, b := range []struct {
		k Kind
		v string
	}{{KindPath, "/srv/x"}, {KindExec, "/bin/ls"}, {KindNet, "192.0.2.1:443"}} {
		if _, _, err := o.AddUntil(b.k, b.v, "b", t0, end); err != nil {
			t.Fatal(err)
		}
	}
	res := Resolved{Boot: map[string]time.Duration{}}
	for _, e := range o.Blocks {
		res.Boot[DeadlineKey(e.Key(), e.Until)] = fc.c.Pin(end)
	}
	s := Compile(o, res)
	ap := netip.MustParseAddrPort("192.0.2.1:443")
	match := func() (bool, bool, bool) {
		_, p := s.MatchPath("/srv/x/f", AccessRead)
		_, e := s.MatchExec([]string{"/bin/ls"}, FileID{}, false)
		_, n := s.MatchInet(ap, "", nil)
		return p, e, n
	}
	fc.set(end.Add(-time.Nanosecond))
	if p, e, n := match(); !p || !e || !n {
		t.Fatalf("1 ns before the end: path %v exec %v net %v, want all refused", p, e, n)
	}
	fc.set(end)
	if p, e, n := match(); p || e || n {
		t.Fatalf("at the end: path %v exec %v net %v, want none", p, e, n)
	}
	if !s.HasPath() || !s.HasExec() || !s.HasNet() {
		t.Fatal("Has* changed with the clock; they are structural")
	}
	// A Set with no limit never reads the clock.
	readClock = func() Clock { t.Fatal("an untimed Set read the clock"); return Clock{} }
	plain := Compile(goldenOverlay(t), Resolved{})
	if _, ok := plain.MatchPath("/srv/data/f", AccessRead); !ok {
		t.Fatal("an untimed read block does not match")
	}
}

// TestDormantBlockReturnsAtFrom: an unblock with a limit refuses nothing until From and refuses again exactly then.
func TestDormantBlockReturnsAtFrom(t *testing.T) {
	back := t0.Add(2 * time.Hour)
	fc := installClock(t, t0, time.Second)
	o := New(testRun)
	if _, _, err := o.Add(KindExec, "/bin/ls", "b", t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.RemoveUntil(KindExec, "/bin/ls", "b", t0, back); err != nil {
		t.Fatal(err)
	}
	s := Compile(o, Resolved{Boot: map[string]time.Duration{DeadlineKey("exec:/bin/ls", back): fc.c.Pin(back)}})
	fc.set(back.Add(-time.Nanosecond))
	if _, ok := s.MatchExec([]string{"/bin/ls"}, FileID{}, false); ok {
		t.Fatal("a dormant block refused before its From")
	}
	fc.set(back)
	if e, ok := s.MatchExec([]string{"/bin/ls"}, FileID{}, false); !ok || e.Rule() != "live.block[exec:/bin/ls]" {
		t.Fatal("a dormant block did not refuse again at its From")
	}
}

// TestFenceRefusalRule: a fence refusal the launcher makes carries live.fence[...], never live.block[...].
func TestFenceRefusalRule(t *testing.T) {
	s := CompileEntries([]Entry{{Kind: KindNet, Value: "api.example.com:443", Fence: true}}, 0, Resolved{})
	e, ok := s.MatchInet(netip.MustParseAddrPort("192.0.2.9:443"), "api.example.com", nil)
	if !ok || e.Rule() != "live.fence[net:api.example.com:443]" {
		t.Fatalf("fence refusal %+v %v", e, ok)
	}
	if CompileEntries(nil, 3, Resolved{}) != nil {
		t.Fatal("no entries compiled to a Set")
	}
}

// TestClockSteps: a narrowing ends only when both clocks passed it; a loosening ends, and a refusal comes back, as
// soon as either did. A wall-clock step either way never lengthens a loosening or shortens a narrowing.
func TestClockSteps(t *testing.T) {
	limit := t0.Add(time.Hour)
	start := Clock{Wall: t0, Boot: 100 * time.Second}
	pin := start.Pin(limit)
	if pin != 100*time.Second+time.Hour {
		t.Fatalf("Pin = %v", pin)
	}
	for _, c := range []struct {
		name         string
		now          Clock
		ended, begun bool
	}{
		// The wall clock was stepped back an hour; BOOTTIME has reached the limit.
		{"backward step", Clock{Wall: limit.Add(-time.Hour), Boot: pin}, false, true},
		// The wall clock was stepped forward an hour; BOOTTIME is half-way.
		{"forward step", Clock{Wall: limit.Add(30 * time.Minute), Boot: pin - 30*time.Minute}, false, true},
		{"both before", Clock{Wall: limit.Add(-time.Nanosecond), Boot: pin - time.Nanosecond}, false, false},
		{"both at", Clock{Wall: limit, Boot: pin}, true, true},
	} {
		if got := Ended(limit, pin, true, c.now); got != c.ended {
			t.Errorf("%s: Ended = %v, want %v", c.name, got, c.ended)
		}
		if got := Begun(limit, pin, true, c.now); got != c.begun {
			t.Errorf("%s: Begun = %v, want %v", c.name, got, c.begun)
		}
	}
	if !Ended(limit, 0, false, Clock{Wall: limit}) || Begun(limit, 0, false, Clock{Wall: limit.Add(-1), Boot: 1000 * time.Hour}) {
		t.Fatal("an unpinned limit is not judged on the wall clock alone")
	}
	if c := ReadClock(); c.Boot <= 0 || c.Wall.IsZero() {
		t.Fatalf("ReadClock = %+v", c)
	}
}

// TestUpdateDropsLongEndedBlocks: a writer drops a block more than a day past its end by the wall clock, recording
// no change, and keeps one that ended less than a day ago.
func TestUpdateDropsLongEndedBlocks(t *testing.T) {
	dir := t.TempDir()
	fc := installClock(t, t0, time.Second)
	ctx := context.Background()
	if _, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
		if _, _, err := o.AddUntil(KindExec, "/bin/a", "b", t0, t0.Add(time.Hour)); err != nil {
			return false, err
		}
		_, _, err := o.AddUntil(KindExec, "/bin/b", "b", t0, t0.Add(20*time.Hour))
		return true, err
	}); err != nil {
		t.Fatal(err)
	}
	fc.set(t0.Add(26 * time.Hour))
	o, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
		_, ok, err := o.Add(KindExec, "/bin/c", "b", t0.Add(26*time.Hour))
		return ok, err
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, e := range o.Blocks {
		keys = append(keys, e.Key())
	}
	if strings.Join(keys, " ") != "exec:/bin/b exec:/bin/c" || o.Serial != 3 {
		t.Fatalf("blocks %v at serial %d, want /bin/b and /bin/c at 3", keys, o.Serial)
	}
}
