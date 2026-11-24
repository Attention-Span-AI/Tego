// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// fakeProcs is the machine's processes as one hook sees them.
type fakeProcs struct {
	self, harness string
	live          map[string]bool
	now           time.Time
}

func (p *fakeProcs) procs() procs {
	return procs{
		self:    func() string { return p.self },
		harness: func() string { return p.harness },
		alive:   func(id string) bool { return p.live[id] || id == p.self },
		now:     func() time.Time { return p.now },
	}
}

// hookAs runs the hook as the process p describes, over payload, writing its stdout to out.
func (f *fixture) hookAs(t *testing.T, p *fakeProcs, out writer, payload []byte, args ...string) result {
	t.Helper()
	var e bytes.Buffer
	code := runWith(bytes.NewReader(payload), out, &e, append([]string{Harness}, args...), f.getenv, uint32(os.Getuid()), LockBudget, p.procs()) //nolint:gosec // a uid fits 32 bits
	r := result{stderr: e.String(), code: code}
	if b, ok := out.(*bytes.Buffer); ok {
		r.stdout = b.String()
	}
	return r
}

type writer interface{ Write([]byte) (int, error) }

// brokenPipe is a stdout the harness stopped reading.
type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

const (
	harnessA = "10:100"
	harnessB = "20:200"
)

// ownedRefusals publishes the reason file of n refusals whose owners are owners[i] (the refusal's index i, from 0;
// "" for none).
func (f *fixture) ownedRefusals(t *testing.T, owners ...string) {
	t.Helper()
	b := encodeRefusals(t, uint64(len(owners)), func(r *reason.Refusal) {
		r.Owners = owners[(r.Seq-100)/3]
	})
	f.publish(t, b)
}

func targetsIn(text string) []string {
	var out []string
	for i := range 20 {
		if tg := refusalAt(uint64(i)).Payload.Target; strings.Contains(text, tg) {
			out = append(out, fmt.Sprintf("%02d", i))
		}
	}
	return out
}

func toldOf(t *testing.T, r result, event string) []string {
	t.Helper()
	if r.stdout == "" {
		return nil
	}
	return targetsIn(context(t, r.stdout, event))
}

func eq(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

// TestTwoSessionsTellOnlyTheirOwnRefusals: two harnesses in one run each get the refusals their processes drew, a
// refusal nobody owns is told once to whichever hook claims it first, and neither session claims the other's.
func TestTwoSessionsTellOnlyTheirOwnRefusals(t *testing.T) {
	f := newFixture(t)
	f.pendingState(t, State{Harnesses: []string{harnessA, harnessB}}) // both sessions have started
	f.ownedRefusals(t,
		"300:3,200:2,"+harnessA, // 0: A's
		"301:3,"+harnessB,       // 1: B's
		"",                      // 2: nobody's
		"302:3,"+harnessA,       // 3: A's
		"303:3,"+harnessB,       // 4: B's
	)
	a := &fakeProcs{self: "11:111", harness: harnessA, now: time.Now(), live: map[string]bool{harnessB: true}}
	b := &fakeProcs{self: "21:211", harness: harnessB, now: time.Now(), live: map[string]bool{harnessA: true}}
	post := payload(t, "post-tool-use-bash")

	if got := toldOf(t, f.hookAs(t, b, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"01", "02", "04"}) {
		t.Fatalf("B was told %v, want its own refusals (1, 4) and the unowned one (2)", got)
	}
	if got := toldOf(t, f.hookAs(t, a, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"00", "03"}) {
		t.Fatalf("A was told %v, want its own refusals (0, 3) and not B's or the unowned one B already took", got)
	}
	for name, p := range map[string]*fakeProcs{"A": a, "B": b} {
		if r := f.hookAs(t, p, &bytes.Buffer{}, post); r.stdout != "" {
			t.Errorf("%s was told again: %q", name, r.stdout)
		}
	}
	s := f.state(t)
	if s.Pending != nil || s.Deliveries != 2 || s.Owned[harnessA] != refusalAt(4).Seq || s.Owned[harnessB] != refusalAt(4).Seq {
		t.Errorf("state %+v", s)
	}
	// A refusal that comes later is told to its own session only.
	f.ownedRefusals(t, "300:3,"+harnessA, "301:3,"+harnessB, "", "302:3,"+harnessA, "303:3,"+harnessB, "304:3,"+harnessB)
	if got := toldOf(t, f.hookAs(t, a, &bytes.Buffer{}, post), EventPostToolUse); len(got) != 0 {
		t.Errorf("A was told B's new refusal: %v", got)
	}
	if got := toldOf(t, f.hookAs(t, b, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"05"}) {
		t.Errorf("B was told %v, want its new refusal (5)", got)
	}
}

// TestAHookWithNoHarnessTellsEverything: where the hook finds no harness (its /proc is closed to it, or its parent is
// init) it cannot tell whose an owned refusal is, so it tells every refusal above the shared cursor, as before
// ownership: a note told to the wrong session beats one told to none. Its claim does not move any harness's cursor,
// so the owner may be told the refusal again (at least once).
func TestAHookWithNoHarnessTellsEverything(t *testing.T) {
	f := newFixture(t)
	f.ownedRefusals(t, harnessA, "", harnessB)
	none := &fakeProcs{self: "11:111", now: time.Now()}
	if got := toldOf(t, f.hookAs(t, none, &bytes.Buffer{}, payload(t, "post-tool-use-bash")), EventPostToolUse); !eq(got, []string{"00", "01", "02"}) {
		t.Fatalf("told %v, want every refusal (0, 1, 2)", got)
	}
	a := &fakeProcs{self: "12:112", harness: harnessA, now: time.Now()}
	if got := toldOf(t, f.hookAs(t, a, &bytes.Buffer{}, payload(t, "stop")), EventStop); !eq(got, []string{"00"}) {
		t.Errorf("A was told %v, want its own refusal (0) again", got)
	}
}

// pendingState writes a state file that holds claims, as a hook killed after it claimed leaves it.
func (f *fixture) pendingState(t *testing.T, s State) {
	t.Helper()
	s.V, s.Run = StateVersion, testRun
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, StateDirName, StateFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAClaimerKilledBetweenClaimAndPrintIsToldAgain: a hook that claimed and was stopped before it marked its note
// printed leaves the claim pending; the next hook of the same harness tells those refusals again, once, and a claim
// of a hook that is still there and not stale, or of another harness, is left alone.
func TestAClaimerKilledBetweenClaimAndPrintIsToldAgain(t *testing.T) {
	post := payload(t, "post-tool-use-bash")
	now := time.Now()
	seq := func(i uint64) uint64 { return refusalAt(i).Seq }
	killed := func(f *fixture, owner, by string, at time.Time, seqs ...uint64) {
		// The state a hook left that claimed refusals 0 and 1 and died: cursors moved, claim pending.
		f.pendingState(t, State{Harnesses: []string{harnessA, harnessB}, Cursor: seq(2), Owned: map[string]uint64{harnessA: seq(2)}, RefusalsDelivered: 3,
			Pending: []Claim{{Owner: owner, By: by, At: at.Unix(), Seqs: seqs}}})
	}
	a := func() *fakeProcs { return &fakeProcs{self: "12:112", harness: harnessA, now: now} }

	t.Run("dead claimer, same harness", func(t *testing.T) {
		f := newFixture(t)
		f.ownedRefusals(t, harnessA, harnessA, "")
		killed(f, harnessA, "999:9", now, seq(0), seq(1))
		got := toldOf(t, f.hookAs(t, a(), &bytes.Buffer{}, post), EventPostToolUse)
		if !eq(got, []string{"00", "01"}) {
			t.Fatalf("told %v, want the two refusals the killed hook claimed", got)
		}
		if s := f.state(t); s.Pending != nil || s.Deliveries != 1 {
			t.Errorf("state after the second telling: %+v", s)
		}
		if r := f.hookAs(t, a(), &bytes.Buffer{}, post); r.stdout != "" {
			t.Errorf("told a third time: %q", r.stdout)
		}
	})
	t.Run("claimer still there", func(t *testing.T) {
		f := newFixture(t)
		f.ownedRefusals(t, harnessA, harnessA, "")
		killed(f, harnessA, "999:9", now, seq(0), seq(1))
		p := a()
		p.live = map[string]bool{"999:9": true}
		if r := f.hookAs(t, p, &bytes.Buffer{}, post); r.stdout != "" {
			t.Errorf("told a claim whose hook is still printing: %q", r.stdout)
		}
		if s := f.state(t); len(s.Pending) != 1 {
			t.Errorf("the live claim was dropped: %+v", s)
		}
	})
	t.Run("claimer there but past the hook timeout", func(t *testing.T) {
		f := newFixture(t)
		f.ownedRefusals(t, harnessA, harnessA, "")
		killed(f, harnessA, "999:9", now.Add(-time.Minute), seq(0), seq(1))
		p := a()
		p.live = map[string]bool{"999:9": true}
		if got := toldOf(t, f.hookAs(t, p, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"00", "01"}) {
			t.Errorf("told %v, want the stale claim told again", got)
		}
	})
	t.Run("another harness's claim", func(t *testing.T) {
		f := newFixture(t)
		f.ownedRefusals(t, harnessB, harnessB, "")
		killed(f, harnessB, "999:9", now, seq(0), seq(1))
		withB := a()
		withB.live = map[string]bool{harnessB: true}
		if r := f.hookAs(t, withB, &bytes.Buffer{}, post); r.stdout != "" {
			t.Errorf("A told B's claim: %q", r.stdout)
		}
		if s := f.state(t); len(s.Pending) != 1 {
			t.Errorf("B's claim was dropped: %+v", s)
		}
		b := &fakeProcs{self: "22:222", harness: harnessB, now: now}
		if got := toldOf(t, f.hookAs(t, b, &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"00", "01"}) {
			t.Errorf("B was told %v, want the claim its own killed hook left", got)
		}
	})
	t.Run("a claim of a hook that had no harness", func(t *testing.T) {
		f := newFixture(t)
		f.ownedRefusals(t, "", "", "")
		killed(f, "", "999:9", now, seq(0), seq(1))
		if got := toldOf(t, f.hookAs(t, a(), &bytes.Buffer{}, post), EventPostToolUse); !eq(got, []string{"00", "01"}) {
			t.Errorf("told %v, want the unowned claim told by any hook", got)
		}
	})
	t.Run("a seq the file no longer lists", func(t *testing.T) {
		f := newFixture(t)
		f.ownedRefusals(t, harnessA, harnessA, "")
		killed(f, harnessA, "999:9", now, seq(0), seq(1), 9999)
		ctx := context(t, f.hookAs(t, a(), &bytes.Buffer{}, post).stdout, EventPostToolUse)
		if !strings.Contains(ctx, "1 more not listed.") {
			t.Errorf("a claimed refusal that left the list is not counted: %q", ctx)
		}
	})
}

// TestAFailedPrintLeavesTheClaimPending: a hook whose output could not be written marks nothing printed, so the next
// hook of its harness tells the note again (it may then have been told twice, never zero times); one whose output was
// written leaves nothing pending, in both modes.
func TestAFailedPrintLeavesTheClaimPending(t *testing.T) {
	post := payload(t, "post-tool-use-bash")
	for _, mode := range []string{ModeJSON, ModeStderr} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ownedRefusals(t, harnessA, harnessA)
			now := time.Now()
			first := &fakeProcs{self: "11:111", harness: harnessA, now: now}
			var e bytes.Buffer
			args := []string{Harness, "--mode", mode}
			var stdout writer = brokenPipe{}
			var stderr writer = &e
			if mode == ModeStderr {
				stdout, stderr = &bytes.Buffer{}, brokenPipe{}
			}
			code := runWith(bytes.NewReader(post), stdout, stderr, args, f.getenv, uint32(os.Getuid()), LockBudget, first.procs()) //nolint:gosec // a uid fits 32 bits
			_ = code
			s := f.state(t)
			if len(s.Pending) != 1 || s.Deliveries != 0 {
				t.Fatalf("after a failed print: %+v, want the claim pending and no delivery counted", s)
			}
			// The first hook ended; its successor is told the same refusals, and now they print.
			second := &fakeProcs{self: "12:112", harness: harnessA, now: now}
			r := f.hookAs(t, second, &bytes.Buffer{}, post, "--mode", mode)
			text := r.stderr
			if mode == ModeJSON {
				text = context(t, r.stdout, EventPostToolUse)
			}
			if !eq(targetsIn(text), []string{"00", "01"}) {
				t.Fatalf("the next hook told %q, want both refusals again", text)
			}
			if s := f.state(t); s.Pending != nil || s.Deliveries != 1 {
				t.Errorf("after the second telling: %+v", s)
			}
		})
	}
}

// TestTooManyPendingClaimsClaimNothing: at maxPending live claims a hook prints nothing and leaves the refusals
// unclaimed, with its reason on stderr.
func TestTooManyPendingClaimsClaimNothing(t *testing.T) {
	f := newFixture(t)
	f.ownedRefusals(t, harnessA)
	now := time.Now()
	var pend []Claim
	live := map[string]bool{}
	for i := range maxPending {
		by := fmt.Sprintf("%d:7", 500+i)
		pend = append(pend, Claim{Owner: harnessB, By: by, At: now.Unix(), Seqs: []uint64{1}})
		live[by] = true
	}
	f.pendingState(t, State{Pending: pend})
	p := &fakeProcs{self: "11:111", harness: harnessA, now: now, live: live}
	r := f.hookAs(t, p, &bytes.Buffer{}, payload(t, "post-tool-use-bash"))
	if r.stdout != "" || !strings.Contains(r.stderr, "claims are waiting") {
		t.Errorf("%+v, want nothing on stdout and the reason on stderr", r)
	}
	if s := f.state(t); len(s.Pending) != maxPending || s.Owned[harnessA] != 0 {
		t.Errorf("state %+v, want it unchanged", s)
	}
}

// TestTheStateStaysInItsBound: cursors of many harnesses are dropped, the lowest first, rather than let the state
// pass MaxStateBytes, which the next hook would refuse; the hook's own harness keeps its cursor.
func TestTheStateStaysInItsBound(t *testing.T) {
	f := newFixture(t)
	f.ownedRefusals(t, harnessA)
	owned := map[string]uint64{}
	for i := range 155 {
		owned[fmt.Sprintf("%d:123456789012", 100000+i)] = uint64(i + 1)
	}
	f.pendingState(t, State{Owned: owned})
	b, _ := json.Marshal(State{V: StateVersion, Run: testRun, Owned: owned})
	if len(b) >= MaxStateBytes || len(b) < MaxStateBytes-100 {
		t.Fatalf("the fixture's state is %d bytes, want it just under %d so the claim passes it", len(b), MaxStateBytes)
	}
	p := &fakeProcs{self: "11:111", harness: harnessA, now: time.Now()}
	if toldOf(t, f.hookAs(t, p, &bytes.Buffer{}, payload(t, "post-tool-use-bash")), EventPostToolUse) == nil {
		t.Fatal("nothing told")
	}
	s := f.state(t)
	if _, ok := s.Owned["100154:123456789012"]; !ok || s.Owned[harnessA] != refusalAt(0).Seq {
		t.Fatalf("state %+v", s)
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, StateDirName, StateFileName)); len(b) > MaxStateBytes {
		t.Errorf("state file %d bytes, over %d", len(b), MaxStateBytes)
	}
	if _, ok := s.Owned["100000:123456789012"]; ok {
		t.Error("the lowest cursor was kept while others were dropped")
	}
}

// TestAV1StateIsRefused: a state file of version 1 is not read as this one's.
func TestAV1StateIsRefused(t *testing.T) {
	f := newFixture(t)
	f.refusals(t, 1)
	if err := os.WriteFile(filepath.Join(f.dir, StateDirName, StateFileName), []byte(`{"v":1,"run":"`+testRun+`","cursor":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := f.hook(t, payload(t, "post-tool-use-bash")); r.stdout != "" || !strings.Contains(r.stderr, "unusable hook state") {
		t.Errorf("%+v", r)
	}
}

// TestTheHookFindsItsHarnessAboveTheShells: the harness is the nearest ancestor that is not a shell, whether the hook
// was started directly or through a shell or two; none when a process 1 or an unreadable process comes first.
func TestTheHookFindsItsHarnessAboveTheShells(t *testing.T) {
	stat := map[int]procStat{
		100: {comm: "tego", ppid: 90, start: 1000},
		90:  {comm: "sh", ppid: 80, start: 900},
		80:  {comm: "bash", ppid: 70, start: 800},
		70:  {comm: "claude", ppid: 60, start: 700},
		60:  {comm: "tego", ppid: 1, start: 600},
		50:  {comm: "tego", ppid: 40, start: 500},
		40:  {comm: "sh", ppid: 1, start: 400},
		30:  {comm: "tego", ppid: 29, start: 300},
	}
	read := func(pid int) (procStat, bool) { s, ok := stat[pid]; return s, ok }
	for pid, want := range map[int]string{100: "70:700", 90: "70:700", 70: "60:600", 50: "", 30: "", 60: ""} {
		if got := harnessOf(read, pid); got != want {
			t.Errorf("harnessOf(%d) = %q, want %q", pid, got, want)
		}
	}
	if got := identityOf(read, 70); got != "70:700" {
		t.Errorf("identityOf = %q", got)
	}
	if !aliveID(read, "70:700") || aliveID(read, "70:701") || aliveID(read, "71:700") || aliveID(read, "x") || aliveID(read, "70") {
		t.Error("aliveID does not follow pid and start time")
	}
}

// TestParseProcStat: the comm may hold spaces and parentheses; the parent is field 4 and the start field 22.
func TestParseProcStat(t *testing.T) {
	line := "4242 (we) ird (name) S 77 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 987654 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52"
	st, ok := parseProcStat(line)
	if !ok || st.comm != "we) ird (name" || st.ppid != 77 || st.start != 987654 {
		t.Errorf("%+v %v", st, ok)
	}
	for _, bad := range []string{"", "1 comm S 1", "1 (c) S x 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5", "1 (c) S 1 1"} {
		if _, ok := parseProcStat(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}
