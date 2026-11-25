// SPDX-License-Identifier: Apache-2.0

package budgetwindow

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// memAnchor is chain.log in memory.
type memAnchor struct {
	mu    sync.Mutex
	heads map[string]string
}

func (a *memAnchor) Append(run, head string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.heads == nil {
		a.heads = map[string]string{}
	}
	a.heads[run] = head
	return nil
}

// Heads makes the anchor answer for many runs at once, as chain.log's does: the window's cut on a run's proved end
// runs only for an anchor that can.
func (a *memAnchor) Heads(runs []string) map[string]ledger.AnchorHead {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]ledger.AnchorHead, len(runs))
	for _, r := range runs {
		h, ok := a.heads[r]
		out[r] = ledger.AnchorHead{Head: h, OK: ok}
	}
	return out
}

func (a *memAnchor) Head(run string) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.heads[run]
	return h, ok, nil
}

// clock is a ledger clock that stamps from a start time, one millisecond a line.
type clock struct {
	wall time.Time
	mono uint64
}

func (c *clock) Now() time.Time { c.wall = c.wall.Add(time.Millisecond); return c.wall }
func (c *clock) Mono() uint64   { c.mono += uint64(time.Millisecond); return c.mono + 5_000_000_000 }

type fixture struct {
	t      *testing.T
	root   string
	anchor ledger.ChainAnchor
	n      int
}

func newFixture(t *testing.T) *fixture {
	return &fixture{t: t, root: filepath.Join(t.TempDir(), "runs"), anchor: &memAnchor{}}
}

// newFileFixture is a fixture whose anchor is a real chain.log, the file the product reads.
func newFileFixture(t *testing.T) *fixture {
	dir := t.TempDir()
	return &fixture{t: t, root: filepath.Join(dir, "runs"), anchor: ledger.NewFileChainAnchor(filepath.Join(dir, "chain.log"))}
}

var sourceA = &record.ContractSource{Path: "/etc/tego/a.yaml", Name: "retriever", Registry: "user"}

func (f *fixture) runID(at time.Time) string {
	f.n++
	t36 := strconv.FormatInt(at.UnixNano(), 36)
	return "r-3f9c2a1b-" + strings.Repeat("0", 13-len(t36)) + t36 + "-k7m2" + string(rune('a'+f.n/26)) + string(rune('a'+f.n%26))
}

// run writes one run of source that starts at start and spends tokens (input, in total) in responses a minute apart,
// and ends with run_end when end is set.
type spec struct {
	source *record.ContractSource
	start  time.Time
	spends []int
	end    bool
	// lost ends the writer with no run_end, as a launcher killed with its agent leaves a run.
	lost bool
}

func (f *fixture) run(s spec) string {
	f.t.Helper()
	id := f.runID(s.start)
	dir := filepath.Join(f.root, id)
	c := &clock{wall: s.start}
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithClock(c), ledger.WithAnchor(f.anchor))
	if err != nil {
		f.t.Fatalf("Open: %v", err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{LauncherPID: 1, LauncherStartNS: 1, TegoVersion: "0.1.0-dev", Tier: "landlock", Capture: "forwarder",
		Kernel: "6.17", ContractHash: strings.Repeat("7a", 32), Parsers: map[string]string{"anthropic": "1"}, StopGrace: "10s",
		Command: []string{"agent"}, Cwd: "/w", ContractSource: s.source}); err != nil {
		f.t.Fatalf("WriteRunStart: %v", err)
	}
	for _, in := range s.spends {
		ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder, PID: 1, TID: 1}
		if err := ev.SetPayload(record.SSLResponsePayload{Model: "m", Status: 200, ParserVersion: "1", Usage: &record.Usage{Input: in}}); err != nil {
			f.t.Fatal(err)
		}
		if err := w.Append(ev); err != nil {
			f.t.Fatalf("Append: %v", err)
		}
		c.wall = c.wall.Add(time.Minute)
	}
	if s.lost {
		if err := w.Abandon(); err != nil {
			f.t.Fatalf("Abandon: %v", err)
		}
	}
	if s.end {
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			f.t.Fatalf("Close: %v", err)
		}
	}
	return id
}

func (f *fixture) read(self string) (Result, error) {
	id, _ := IdentityOf(sourceA)
	return Read(context.Background(), Request{Root: f.root, Anchor: f.anchor, Self: self, Identity: id, Now: now, Window: 24 * time.Hour})
}

func tokens(r Result) uint64 {
	var n uint64
	for _, c := range r.Carry {
		n += c.Usage.In + c.Usage.Out
	}
	return n
}

func TestReadSumsAnEarlierRun(t *testing.T) {
	f := newFixture(t)
	f.run(spec{source: sourceA, start: now.Add(-3 * time.Hour), spends: []int{100, 200, 300}, end: true})
	self := f.runID(now)
	res, err := f.read(self)
	if err != nil {
		t.Fatal(err)
	}
	if tokens(res) != 600 || res.Runs != 1 || len(res.Lost) != 0 {
		t.Fatalf("carry %d tokens from %d runs, lost %v; want 600 from 1", tokens(res), res.Runs, res.Lost)
	}
}

func TestReadLeavesOutAnotherAgentAndSelfAndOldLines(t *testing.T) {
	f := newFixture(t)
	other := &record.ContractSource{Path: "/etc/tego/b.yaml", Name: "writer", Registry: "user"}
	f.run(spec{source: other, start: now.Add(-3 * time.Hour), spends: []int{1000}, end: true})
	f.run(spec{source: nil, start: now.Add(-3 * time.Hour), spends: []int{1000}, end: true})
	// This agent's, but its first lines are over the window old and its last two are inside it.
	f.run(spec{source: sourceA, start: now.Add(-24*time.Hour - 3*time.Minute), spends: []int{500, 400, 7, 9}, end: true})
	self := f.run(spec{source: sourceA, start: now.Add(-time.Hour), spends: []int{50000}, end: false})
	res, err := f.read(self)
	if err != nil {
		t.Fatal(err)
	}
	if tokens(res) != 7+9 {
		t.Fatalf("carry = %d, want 16: the lines inside the window, of this agent, not this run's own", tokens(res))
	}
}

func TestReadAPathNamedContractIsKeyedByItsPath(t *testing.T) {
	f := newFixture(t)
	byPath := &record.ContractSource{Path: "/srv/agents/x.yaml"}
	f.run(spec{source: byPath, start: now.Add(-time.Hour), spends: []int{40}, end: true})
	f.run(spec{source: &record.ContractSource{Path: "/srv/agents/y.yaml"}, start: now.Add(-time.Hour), spends: []int{99}, end: true})
	id, _ := IdentityOf(byPath)
	res, err := Read(context.Background(), Request{Root: f.root, Anchor: f.anchor, Self: "none", Identity: id, Now: now, Window: 24 * time.Hour})
	if err != nil || tokens(res) != 40 {
		t.Fatalf("%d tokens, %v; want 40", tokens(res), err)
	}
}

func TestReadATamperedLedgerIsRefused(t *testing.T) {
	f := newFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100, 200}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The agent lowers what it spent: a response's input count rewritten in place.
	edited := strings.Replace(string(b), `"input":200`, `"input":2`, 1)
	if edited == string(b) {
		t.Fatalf("test ledger has no input 200 to edit:\n%s", b)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) || !strings.Contains(err.Error(), id) {
		t.Fatalf("err = %v, want ErrUnprovable naming %s", err, id)
	}
}

func TestReadATruncatedLedgerIsRefused(t *testing.T) {
	f := newFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100, 200, 300}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(b), "\n")
	// The last response and run_end cut off: the chain that is left is whole, and only chain.log knows it was longer.
	cut := strings.Join(lines[:len(lines)-3], "")
	if err := os.WriteFile(path, []byte(cut), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) {
		t.Fatalf("err = %v, want ErrUnprovable", err)
	}
}

// TestReadAnEndedRunWithNoAnchorIsCountedAndSaid: an ended run chain.log has no line for is what an honest failure to
// write the anchor leaves (tego run says "anchor not written"). Its chain verifies on its own, so it is counted as the
// record holds it and named in Result.Unanchored; refusing it refused every start for the whole retention, and the only
// way out was to delete the run. Red before: ErrUnprovable.
func TestReadAnEndedRunWithNoAnchorIsCountedAndSaid(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) *fixture{"file": newFileFixture, "mem": newFixture} {
		t.Run(name, func(t *testing.T) {
			f := mk(t)
			id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100}, end: true})
			f.dropAnchor(t)
			res, err := f.read(f.runID(now))
			if err != nil || tokens(res) != 100 || res.Runs != 1 || len(res.Unanchored) != 1 || res.Unanchored[0] != id {
				t.Fatalf("%d tokens, %d runs, unanchored %v, %v; want 100 from 1, %s unanchored", tokens(res), res.Runs, res.Unanchored, err, id)
			}
		})
	}
}

// dropAnchor makes chain.log hold no line for any run.
func (f *fixture) dropAnchor(t *testing.T) {
	t.Helper()
	switch a := f.anchor.(type) {
	case *memAnchor:
		a.heads = nil
	default:
		path := filepath.Join(filepath.Dir(f.root), "chain.log")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReadAnUnanchoredRunThatDoesNotVerifyIsStillRefused: with no anchor to match, the chain is all there is to check,
// and a run edited after it closed breaks it.
func TestReadAnUnanchoredRunThatDoesNotVerifyIsStillRefused(t *testing.T) {
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100, 200}, end: true})
	f.dropAnchor(t)
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"input":200`, `"input":2`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) || !strings.Contains(err.Error(), id) {
		t.Fatalf("err = %v, want ErrUnprovable naming %s", err, id)
	}
}

// TestReadAnAnchorThatCannotBeReadIsRefused: "no line" is chain.log's answer; "could not read it" is not an answer, and
// is not read as one.
func TestReadAnAnchorThatCannotBeReadIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	f := newFileFixture(t)
	f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100}, end: true})
	path := filepath.Join(filepath.Dir(f.root), "chain.log")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) {
		t.Fatalf("err = %v, want ErrUnprovable", err)
	}
}

// TestReadCountsARunStampedAfterNow: a wall clock set back since the run was written makes its lines later than now.
// They are returned, not dropped as not yet spent: hiding spend is the direction that matters (the watcher counts them
// as spent at this run's start).
func TestReadCountsARunStampedAfterNow(t *testing.T) {
	f := newFixture(t)
	f.run(spec{source: sourceA, start: now.Add(48 * time.Hour), spends: []int{250}, end: true})
	res, err := f.read(f.runID(now))
	if err != nil || tokens(res) != 250 {
		t.Fatalf("%d tokens, %v; want 250", tokens(res), err)
	}
}

func TestReadAMissingLedgerFileIsNotCounted(t *testing.T) {
	// A run removed by gc or a person is gone with its spend: stated in ADR 0165, which makes runtime refuse a
	// retention shorter than the window instead.
	f := newFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100}, end: true})
	if err := os.RemoveAll(filepath.Join(f.root, id)); err != nil {
		t.Fatal(err)
	}
	res, err := f.read(f.runID(now))
	if err != nil || tokens(res) != 0 {
		t.Fatalf("%d tokens, %v", tokens(res), err)
	}
}

func TestReadALostRunCountsToItsLastLine(t *testing.T) {
	f := newFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100, 200}, lost: true})
	res, err := f.read(f.runID(now))
	if err != nil {
		t.Fatal(err)
	}
	if tokens(res) != 300 || len(res.Lost) != 1 || res.Lost[0] != id {
		t.Fatalf("%d tokens, lost %v; want 300 and %s", tokens(res), res.Lost, id)
	}
}

func TestReadALiveRunOfTheAgentIsRefused(t *testing.T) {
	f := newFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-time.Hour), spends: []int{100}}) // writer left open
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrLive) || !strings.Contains(err.Error(), id) {
		t.Fatalf("err = %v, want ErrLive naming %s", err, id)
	}
}

// TestTheLockIsNamedAsIsLockNameSays: restoring a mode taken from the lock finds it by IsLockName, so the name Acquire
// makes must be one it accepts, and a name that only looks like one must not be.
func TestTheLockIsNamedAsIsLockNameSays(t *testing.T) {
	root := t.TempDir()
	id, _ := IdentityOf(sourceA)
	l, err := Acquire(root, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	made, err := filepath.Glob(filepath.Join(root, ".window-*"))
	if err != nil || len(made) != 1 {
		t.Fatalf("Acquire made %v (%v), want one file", made, err)
	}
	if name := filepath.Base(made[0]); !IsLockName(name) {
		t.Fatalf("IsLockName(%q) = false for the lock Acquire made", name)
	}
	for _, bad := range []string{"", ".window-.lock", ".window-0123456789abcde.lock", ".window-0123456789abcdef0.lock",
		".window-0123456789ABCDEF.lock", ".window-0123456789abcdeg.lock", "window-0123456789abcdef.lock",
		".window-0123456789abcdef.lock.bak", ".window-0123456789abcdef", "events.jsonl", ".live"} {
		if IsLockName(bad) {
			t.Errorf("IsLockName(%q) = true", bad)
		}
	}
}

// TestALockThatCannotBeOpenedIsErrLockFile: a window lock a launcher cannot open (here a directory at its name, which
// root cannot open for writing either) is ErrUnprovable, so the start is refused, and ErrLockFile too, so the refusal
// says the lock is at fault and does not send a person looking for a run's ledger.
func TestALockThatCannotBeOpenedIsErrLockFile(t *testing.T) {
	root := t.TempDir()
	id, _ := IdentityOf(sourceA)
	l, err := Acquire(root, id)
	if err != nil {
		t.Fatal(err)
	}
	made, _ := filepath.Glob(filepath.Join(root, ".window-*"))
	_ = l.Close()
	if len(made) != 1 {
		t.Fatalf("Acquire made %v", made)
	}
	if err := os.Remove(made[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(made[0], 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = Acquire(root, id)
	if !errors.Is(err, ErrLockFile) || !errors.Is(err, ErrUnprovable) || !strings.Contains(err.Error(), filepath.Base(made[0])) {
		t.Fatalf("Acquire over a directory = %v, want ErrLockFile and ErrUnprovable naming the lock", err)
	}
}

func TestAcquireRefusesASecondRunOfOneAgent(t *testing.T) {
	root := t.TempDir()
	id, _ := IdentityOf(sourceA)
	l, err := Acquire(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(root, id); !errors.Is(err, ErrLive) {
		t.Fatalf("second Acquire = %v, want ErrLive", err)
	}
	other, _ := IdentityOf(&record.ContractSource{Name: "writer", Registry: "user"})
	l2, err := Acquire(root, other)
	if err != nil {
		t.Fatalf("another agent's window is not this one's: %v", err)
	}
	_ = l2.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l3, err := Acquire(root, id)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	_ = l3.Close()
	_ = l3.Close() // twice is fine
}

// backdate sets a run's events.jsonl modification time to 2000-01-01: the agent runs as the ledgers' owner, so it can.
func backdate(t *testing.T, f *fixture, id string) {
	t.Helper()
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(f.root, id, ledger.EventsFile), old, old); err != nil {
		t.Fatal(err)
	}
}

// TestReadABackdatedLedgerIsStillCounted: the file's modification time is the agent's to set, so it decides nothing.
// Red before the cut moved to the run_end that chain.log anchors: 0 tokens, no error.
func TestReadABackdatedLedgerIsStillCounted(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) *fixture{"file": newFileFixture, "mem": newFixture} {
		t.Run(name, func(t *testing.T) {
			f := mk(t)
			id := f.run(spec{source: sourceA, start: now.Add(-3 * time.Hour), spends: []int{100, 200, 300}, end: true})
			backdate(t, f, id)
			res, err := f.read(f.runID(now))
			if err != nil || tokens(res) != 600 || res.Runs != 1 {
				t.Fatalf("after backdating mtime: %d tokens, %d runs, %v; want 600 from 1", tokens(res), res.Runs, err)
			}
		})
	}
}

// TestReadAnOldEndedRunIsCutOnItsAnchoredEnd: a run whose run_end chain.log anchors and which ended before the window is
// left unread, whatever its file looks like: damage inside it is not found and costs nothing.
func TestReadAnOldEndedRunIsCutOnItsAnchoredEnd(t *testing.T) {
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-72 * time.Hour), spends: []int{100, 200}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"input":200`, `"input":2`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := f.read(f.runID(now))
	if err != nil || tokens(res) != 0 || res.Runs != 0 {
		t.Fatalf("%d tokens, %d runs, %v; want the old run left out unread", tokens(res), res.Runs, err)
	}
}

// TestReadAnEditedEndStampIsRefused: the way round the cut is a run_end whose stamp the agent rewrote to be old. Its id
// no longer matches the digest of the line, so it does not match chain.log and the run is read whole and refused.
func TestReadAnEditedEndStampIsRefused(t *testing.T) {
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-3 * time.Hour), spends: []int{100, 200}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	lines := strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
	last := lines[len(lines)-1]
	i := strings.Index(last, `"ts":"`)
	if i < 0 {
		t.Fatalf("no ts in %s", last)
	}
	lines[len(lines)-1] = last[:i] + `"ts":"2000-01-01T00:00:00.000000Z"` + last[i+len(`"ts":"`)+strings.Index(last[i+6:], `"`)+1:]
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backdate(t, f, id)
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) {
		t.Fatalf("err = %v, want ErrUnprovable", err)
	}
}

// TestReadATruncatedOldLedgerIsReadWhole: a ledger cut back has no run_end to prove its age, so the cut does not apply
// and the check against chain.log refuses it, with a backdated modification time or not.
func TestReadATruncatedOldLedgerIsReadWhole(t *testing.T) {
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-3 * time.Hour), spends: []int{100, 200, 300}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(b), "\n")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-3], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	backdate(t, f, id)
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) {
		t.Fatalf("err = %v, want ErrUnprovable", err)
	}
}

// The project registry is the working directory's, so a name in it is only one agent beside its file.
func TestIdentityTellsTwoProjectsApart(t *testing.T) {
	a := &record.ContractSource{Path: "/srv/a/.tego/agents/bot.yaml", Name: "bot", Registry: "project"}
	b := &record.ContractSource{Path: "/srv/b/.tego/agents/bot.yaml", Name: "bot", Registry: "project"}
	ia, _ := IdentityOf(a)
	ib, _ := IdentityOf(b)
	if ia == ib {
		t.Fatalf("bot in two project folders is one identity %q", ia)
	}
	// Two files in one folder named by the project registry's agent.yaml are told apart by name, and one agent is itself.
	again, _ := IdentityOf(&record.ContractSource{Path: a.Path, Name: "bot", Registry: "project", Learn: &record.LearnNote{}})
	if again != ia {
		t.Fatalf("the same agent is %q and %q", ia, again)
	}
	// The user registry is one per account: a name there is the agent, wherever its file is kept.
	u1, _ := IdentityOf(&record.ContractSource{Path: "/home/u/agents/bot.yaml", Name: "bot", Registry: "user"})
	u2, _ := IdentityOf(&record.ContractSource{Path: "/elsewhere/bot.yaml", Name: "bot", Registry: "user"})
	if u1 != u2 || u1 == ia {
		t.Fatalf("user identities %q and %q, project %q", u1, u2, ia)
	}
	if _, ok := IdentityOf(&record.ContractSource{Name: "bot", Registry: "project"}); ok {
		t.Fatal("a project entry with no file path has an identity")
	}
}

func TestProjectRegistryNameIsTheRegistrysOwn(t *testing.T) {
	if registryProject != registry.Project {
		t.Fatalf("registryProject %q is not registry.Project %q", registryProject, registry.Project)
	}
}

// TestReadDoesNotCountAnotherProjectsAgentOfTheSameName: agent bot in /a counts nothing of bot in /b, and the two hold
// two locks. Red before: both were "name:project:bot", one budget and one lock.
func TestReadDoesNotCountAnotherProjectsAgentOfTheSameName(t *testing.T) {
	f := newFixture(t)
	a := &record.ContractSource{Path: "/srv/a/.tego/agents/bot.yaml", Name: "bot", Registry: "project"}
	b := &record.ContractSource{Path: "/srv/b/.tego/agents/bot.yaml", Name: "bot", Registry: "project"}
	f.run(spec{source: b, start: now.Add(-time.Hour), spends: []int{777}, end: true})
	f.run(spec{source: a, start: now.Add(-time.Hour), spends: []int{5}, end: true})
	ida, _ := IdentityOf(a)
	res, err := Read(context.Background(), Request{Root: f.root, Anchor: f.anchor, Self: "none", Identity: ida, Now: now, Window: 24 * time.Hour})
	if err != nil || tokens(res) != 5 || res.Runs != 1 {
		t.Fatalf("%d tokens from %d runs, %v; want 5 from 1", tokens(res), res.Runs, err)
	}
	idb, _ := IdentityOf(b)
	root := t.TempDir()
	la, err := Acquire(root, ida)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = la.Close() }()
	lb, err := Acquire(root, idb)
	if err != nil {
		t.Fatalf("bot of /b is refused for bot of /a: %v", err)
	}
	_ = lb.Close()
}

// TestReadAnotherAgentsDamagedRecordNeverBlocks: whose a run is comes from its first line alone, and a run that is
// another agent's is not read further. Red before: each of these refused every windowed start.
func TestReadAnotherAgentsDamagedRecordNeverBlocks(t *testing.T) {
	other := &record.ContractSource{Path: "/etc/tego/b.yaml", Name: "writer", Registry: "user"}
	damage := map[string]func(t *testing.T, path string){
		"a response edited": func(t *testing.T, path string) {
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"input":200`, `"input":2`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"garbage after the first line": func(t *testing.T, path string) {
			b, _ := os.ReadFile(path)
			first, _, _ := strings.Cut(string(b), "\n")
			if err := os.WriteFile(path, []byte(first+"\nnot json at all\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"cut after the first line": func(t *testing.T, path string) {
			b, _ := os.ReadFile(path)
			first, _, _ := strings.Cut(string(b), "\n")
			if err := os.WriteFile(path, []byte(first+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a torn last line": func(t *testing.T, path string) {
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(path, b[:len(b)-20], 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, dmg := range damage {
		t.Run(name, func(t *testing.T) {
			f := newFileFixture(t)
			id := f.run(spec{source: other, start: now.Add(-2 * time.Hour), spends: []int{100, 200}, end: true})
			dmg(t, filepath.Join(f.root, id, ledger.EventsFile))
			mine := f.run(spec{source: sourceA, start: now.Add(-time.Hour), spends: []int{40}, end: true})
			res, err := f.read(f.runID(now))
			if err != nil || tokens(res) != 40 || res.Runs != 1 {
				t.Fatalf("%d tokens from %d runs, %v (mine %s); want 40 from 1 and no refusal", tokens(res), res.Runs, err, mine)
			}
		})
	}
}

// TestReadARunWithNoReadableFirstLineIsLeftOutAndSaid: a first line that does not decode names no agent. It is not
// counted and not refused, and the result says so: the count is the ledgers', and a record that says nothing is not one.
func TestReadARunWithNoReadableFirstLineIsLeftOutAndSaid(t *testing.T) {
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	_, rest, _ := strings.Cut(string(b), "\n")
	if err := os.WriteFile(path, []byte("{not a run_start\n"+rest), 0o600); err != nil {
		t.Fatal(err)
	}
	// A run whose first line is not even finished holds no spend yet and is simply not there.
	torn := f.runID(now.Add(-time.Hour))
	if err := os.MkdirAll(filepath.Join(f.root, torn), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, torn, ledger.EventsFile), []byte(`{"v":1,"seq":0,"kind":"run_st`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := f.read(f.runID(now))
	if err != nil || res.Runs != 0 || len(res.Unattributed) != 1 || res.Unattributed[0] != id {
		t.Fatalf("runs %d, unattributed %v, %v; want the garbled one named and no refusal", res.Runs, res.Unattributed, err)
	}
}

// TestReadAnUnreadableRecordOfOurOwnAccountIsRefusedByName: a mode taken off a run's ledger is the one thing an agent can
// do to its records (chmod), and a run that cannot be opened cannot say whose it is, so it is not passed over. The
// words name the run, the cause and the command that fixes it.
func TestReadAnUnreadableRecordOfOurOwnAccountIsRefusedByName(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	_, err := f.read(f.runID(now))
	if !errors.Is(err, ErrUnprovable) || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("err = %v, want ErrUnprovable naming %s and the chmod that fixes it", err, id)
	}
}

// TestReadNamesThisAgentsDamagedRunAsItsOwn: a refusal for a run that said it is this agent's says so, and names it.
func TestReadNamesThisAgentsDamagedRunAsItsOwn(t *testing.T) {
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100, 200}, end: true})
	path := filepath.Join(f.root, id, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"input":200`, `"input":2`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.read(f.runID(now))
	if !errors.Is(err, ErrUnprovable) || !strings.Contains(err.Error(), id+" (this agent's)") {
		t.Fatalf("err = %v, want it to name %s as this agent's", err, id)
	}
}

// TestReadRefusesALedgerPastTheReadBudget: a start reads what this agent's runs hold inside the window, and a bound
// keeps that from being a wait without end. Red before: no bound.
func TestReadRefusesALedgerPastTheReadBudget(t *testing.T) {
	f := newFileFixture(t)
	f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{1, 2, 3, 4, 5, 6, 7, 8}, end: true})
	other := &record.ContractSource{Path: "/etc/tego/b.yaml", Name: "writer", Registry: "user"}
	f.run(spec{source: other, start: now.Add(-2 * time.Hour), spends: []int{1, 2, 3, 4, 5, 6, 7, 8}, end: true})
	old := readBudget
	t.Cleanup(func() { readBudget = old })
	readBudget = 1000
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	readBudget = old
	if _, err := f.read(f.runID(now)); err != nil {
		t.Fatalf("with the budget: %v", err)
	}
}

// TestReadAnAgentsAttemptsOnItsOwnRecord is the whole feature read as the agent whose budget this is. Each row does one
// thing to an earlier run that spent 600 tokens; the start is then read, and what it counts is what a person must be told.
// A row that counts nothing is a limit the ADR states (an agent that can delete a ledger can lower its count: the tiers
// are what keep it from the ledger root, and a record-only run is refused a window), never a surprise.
func TestReadAnAgentsAttemptsOnItsOwnRecord(t *testing.T) {
	type row struct {
		name string
		do   func(t *testing.T, f *fixture, id string)
		// want is the count, or -1 for a refusal.
		want int
	}
	rows := []row{
		{"nothing", func(*testing.T, *fixture, string) {}, 600},
		{"backdate the file", func(t *testing.T, f *fixture, id string) { backdate(t, f, id) }, 600},
		{"rename the run to another id", func(t *testing.T, f *fixture, id string) {
			if err := os.Rename(filepath.Join(f.root, id), filepath.Join(f.root, f.runID(now.Add(-time.Hour)))); err != nil {
				t.Fatal(err)
			}
		}, -1}, // its lines name the old run, so the chain check refuses it under the new id
		{"truncate the last response and the end", func(t *testing.T, f *fixture, id string) {
			path := filepath.Join(f.root, id, ledger.EventsFile)
			b, _ := os.ReadFile(path)
			lines := strings.SplitAfter(string(b), "\n")
			if err := os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-3], "")), 0o600); err != nil {
				t.Fatal(err)
			}
		}, -1},
		{"edit a response", func(t *testing.T, f *fixture, id string) {
			path := filepath.Join(f.root, id, ledger.EventsFile)
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"input":300`, `"input":3`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, -1},
		{"replace the ledger with an empty file", func(t *testing.T, f *fixture, id string) {
			if err := os.WriteFile(filepath.Join(f.root, id, ledger.EventsFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, 0}, // an empty ledger holds no first line: no agent, no spend; a limit of the ledger root's own protection
		{"delete the run directory", func(t *testing.T, f *fixture, id string) {
			if err := os.RemoveAll(filepath.Join(f.root, id)); err != nil {
				t.Fatal(err)
			}
		}, 0}, // the stated limit: the tiers keep a held agent from doing this, a record-only run is refused a window
		{"rewrite the first line to another agent", func(t *testing.T, f *fixture, id string) {
			path := filepath.Join(f.root, id, ledger.EventsFile)
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"name":"retriever"`, `"name":"other"`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, 0}, // as deleting it, and the same protection
		{"a decoy folder holding a symlink as its ledger", func(t *testing.T, f *fixture, id string) {
			d := filepath.Join(f.root, f.runID(now.Add(-30*time.Minute)))
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(f.root, id, ledger.EventsFile), filepath.Join(d, ledger.EventsFile)); err != nil {
				t.Fatal(err)
			}
		}, 600}, // nobody's record: not counted twice, not a refusal, said so
		{"a decoy copy of its own ledger under a new run id", func(t *testing.T, f *fixture, id string) {
			b, _ := os.ReadFile(filepath.Join(f.root, id, ledger.EventsFile))
			d := filepath.Join(f.root, f.runID(now.Add(-30*time.Minute)))
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, ledger.EventsFile), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}, -1}, // a copy names another run in its lines and has no chain.log line to match under this name
	}
	for _, rw := range rows {
		t.Run(rw.name, func(t *testing.T) {
			f := newFileFixture(t)
			id := f.run(spec{source: sourceA, start: now.Add(-3 * time.Hour), spends: []int{100, 200, 300}, end: true})
			rw.do(t, f, id)
			res, err := f.read(f.runID(now))
			switch {
			case rw.want < 0 && !errors.Is(err, ErrUnprovable):
				t.Fatalf("counted %d tokens, err %v; want a refusal", tokens(res), err)
			case rw.want >= 0 && (err != nil || int(tokens(res)) != rw.want):
				t.Fatalf("counted %d tokens, err %v; want %d", tokens(res), err, rw.want)
			}
		})
	}
}

// TestReadLeavesARunAccountsCannotOpenUnattributedNotRefused: a run directory another account owns, which this launcher
// cannot open, is left out and said (window-unattributed), where a directory of this account's own is refused by name.
// The launcher's uid is stood in for, since only root can make a directory of another uid.
func TestReadLeavesARunAccountsCannotOpenUnattributedNotRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a directory of mode 000")
	}
	f := newFileFixture(t)
	id := f.run(spec{source: sourceA, start: now.Add(-2 * time.Hour), spends: []int{100}, end: true})
	dir := filepath.Join(f.root, id)
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := f.read(f.runID(now)); !errors.Is(err, ErrUnprovable) {
		t.Fatalf("a directory of this account's own that cannot be opened: err = %v, want it refused", err)
	}
	prev := launcherEUID
	launcherEUID = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { launcherEUID = prev })
	res, err := f.read(f.runID(now))
	if err != nil || res.Runs != 0 || len(res.Unattributed) != 1 || res.Unattributed[0] != id {
		t.Fatalf("runs %d, unattributed %v, %v; want another account's directory named and no refusal", res.Runs, res.Unattributed, err)
	}
}

// TestReadLeavesARunAnotherHostMintedUnopened: Request.Foreign names a run another host minted, whose chain.log is not
// this one's. It is not opened and not said, whatever it holds; a run this host minted that holds the same is said.
func TestReadLeavesARunAnotherHostMintedUnopened(t *testing.T) {
	f := newFileFixture(t)
	mine, theirs := f.runID(now.Add(-time.Hour)), "r-aaaaaaaa-"+f.runID(now.Add(-time.Hour))[len("r-3f9c2a1b-"):]
	for _, id := range []string{mine, theirs} {
		if err := os.MkdirAll(filepath.Join(f.root, id), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.root, id, ledger.EventsFile), []byte("{\"not\":\"a run_start\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id, _ := IdentityOf(sourceA)
	res, err := Read(context.Background(), Request{Root: f.root, Anchor: f.anchor, Self: f.runID(now), Identity: id, Now: now,
		Window: 24 * time.Hour, Foreign: func(run string) bool { return run == theirs }})
	if err != nil || len(res.Unattributed) != 1 || res.Unattributed[0] != mine {
		t.Fatalf("unattributed %v, %v; want this host's run alone: the other host's is not opened", res.Unattributed, err)
	}
}
