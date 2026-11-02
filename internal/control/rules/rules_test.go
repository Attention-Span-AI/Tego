// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	runA  = "r-aaaa-0001-rules"
	runA2 = "r-aaaa-0002-rules"
	runB  = "r-aaaa-0003-rules"
	runG  = "r-aaaa-0004-rules" // a generated contract: no contract_source
)

// baseText is the contract the fixture's runs ran: one entry in most lists the form edits.
const baseText = `version: 0
name: tester
command: ["sh"]
exec:
  allow: [sh, cat, ls]
fs:
  write: ["./out/"]
  ask_read: ["./docs/"]
net:
  allow: ["api.example.com:443"]
`

// fixture is a project with a contract, a second contract, and a ledger root whose runs ran them.
type fixture struct {
	dir, proj, ledger, contract, other string
	s                                  *Service
	compiled                           int
	blocks                             []string
	live                               map[string]bool
	held                               bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir(), live: map[string]bool{}}
	f.proj = filepath.Join(f.dir, "proj")
	f.ledger = filepath.Join(f.dir, "ledger")
	for _, d := range []string{f.proj, f.ledger, filepath.Join(f.proj, "docs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.contract = filepath.Join(f.proj, "agent.yaml")
	f.other = filepath.Join(f.proj, "other.yaml")
	writeFile(t, f.contract, baseText)
	writeFile(t, f.other, strings.Replace(baseText, "name: tester", "name: other", 1))
	f.writeRun(t, runA, f.contract, 0)
	f.writeRun(t, runA2, f.contract, 1)
	f.writeRun(t, runB, f.other, 2)
	f.writeRun(t, runG, "", 3)
	f.s = &Service{Ledger: f.ledger, Home: filepath.Join(f.dir, "home"),
		Now: func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) },
		Compile: func(_ context.Context, cc CheckContext, text []byte) error {
			f.compiled++
			if bytes.Contains(text, []byte("broken")) {
				return errors.New("does-not-compile")
			}
			return nil
		},
		live:      func(dir string) bool { return f.live[filepath.Base(dir)] },
		readsHeld: func(string) (bool, string) { return f.held, "this run reads files directly" },
		block: func(_ context.Context, run, kind, value string) error {
			f.blocks = append(f.blocks, run+" "+kind+":"+value)
			return nil
		},
	}
	return f
}

func writeFile(t *testing.T, p, text string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeRun writes a run that ran contract (none for ""), started i minutes after the first, with an asked read of
// docs/token and an exec of cat.
func (f *fixture) writeRun(t *testing.T, run, contract string, i int, more ...*record.Event) {
	t.Helper()
	p := record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("0", 64), Command: []string{"sh"},
		Cwd: f.proj, Kernel: "6", StopGrace: "1s", RecordMinor: record.Minor}
	if contract != "" {
		p.ContractSource = &record.ContractSource{Path: contract}
	}
	evs := []*record.Event{ledgertest.Event(t, record.KindRunStart, p),
		ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "open", Target: filepath.Join(f.proj, "docs", "token")},
			func(e *record.Event) {
				e.Rule, e.Reason = "fs.ask_read[./docs/]", record.ReasonAskDenied
			}),
		ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/usr/bin/cat", Argv: []string{"cat", "x"}, ExecID: "x/1/1"},
			func(e *record.Event) {
				e.Source, e.Rule, e.Verdict, e.Authority = record.SourceSeccomp, "exec[cat]", record.VerdictAllow, record.AuthorityRule
				e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
			})}
	evs = append(evs, more...)
	var buf bytes.Buffer
	t0 := time.Date(2026, 10, 26, 10, i, 0, 0, time.UTC)
	for n, e := range evs {
		e.Run, e.Seq, e.TS = run, uint64(n), t0.Add(time.Duration(n)*time.Second)
		if n > 0 {
			e.Prev = strings.Repeat("a", 64)
		}
		l, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(l, '\n'))
	}
	if err := os.MkdirAll(filepath.Join(f.ledger, run), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.ledger, run, "events.jsonl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) ref(t *testing.T, path string) ContractRef {
	t.Helper()
	cs, err := f.s.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Path == path {
			return c
		}
	}
	t.Fatalf("Contracts has no %s: %+v", path, cs)
	return ContractRef{}
}

func (f *fixture) text(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.contract)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *fixture) journal(t *testing.T) []rulefile.Entry {
	t.Helper()
	es, err := rulefile.ReadJournal(f.ledger)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// TestContractsBoundedToRuns: the set is exactly the contract files runs here recorded, newest first, each once with
// its runs counted; a generated contract and a file no run ran are not in it.
func TestContractsBoundedToRuns(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.proj, "never-ran.yaml"), baseText)
	cs, err := f.s.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || cs[0].Path != f.other || cs[1].Path != f.contract {
		t.Fatalf("Contracts = %+v", cs)
	}
	a := cs[1]
	if a.Runs != 2 || a.LastRun != runA2 || a.Agent != "tester" || !a.Writable || a.Base != rulefile.Sum([]byte(baseText)) {
		t.Errorf("contract A = %+v", a)
	}
	if len(a.Ref) != 16 || strings.Contains(a.Ref, "/") || a.Ref == cs[0].Ref {
		t.Errorf("refs %q %q", a.Ref, cs[0].Ref)
	}
}

// TestRefOfARecordedPath: Ref of the path a run recorded is the ref Contracts lists for that file, also when the run
// recorded it through a linked folder, which is one contract with the runs of both spellings; a path that is not
// absolute has none.
func TestRefOfARecordedPath(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.dir, "proj-link")
	if err := os.Symlink(f.proj, link); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(link, "agent.yaml")
	f.writeRun(t, "r-aaaa-0005-rules", viaLink, 5)
	c := f.ref(t, viaLink) // listed under its newest run's spelling
	if c.Runs != 3 {
		t.Errorf("the file and its spelling through a linked folder are not one contract with all three runs: %+v", c)
	}
	for _, p := range []string{f.contract, viaLink, link + "/./agent.yaml"} {
		if got := Ref(p); got != c.Ref {
			t.Errorf("Ref(%s) = %q, Contracts lists %q", p, got, c.Ref)
		}
	}
	if o := f.ref(t, f.other); Ref(f.other) != o.Ref || o.Ref == c.Ref {
		t.Errorf("Ref(%s) = %q, Contracts lists %q", f.other, Ref(f.other), o.Ref)
	}
	for _, p := range []string{"", "agent.yaml", "./proj/agent.yaml"} {
		if got := Ref(p); got != "" {
			t.Errorf("Ref(%q) = %q, want none", p, got)
		}
	}
}

// TestRefIsNotAPath: a request names a contract by its ref alone; a path, a traversal, or the ref of a file no run
// here ran names nothing, and nothing is read or written.
func TestRefIsNotAPath(t *testing.T) {
	f := newFixture(t)
	for _, ref := range []string{"", "../../etc/passwd", f.contract, "/etc/passwd", refOf("/etc/passwd"),
		refOf(filepath.Join(f.proj, "never-ran.yaml")), strings.Repeat("g", 16)} {
		_, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: ref, Edits: []Edit{{"add", "fs.deny_read", "./x/"}}})
		if !errors.Is(err, ErrNoContract) {
			t.Errorf("ref %q: err = %v", ref, err)
		}
		_, err = f.s.ApplyRaw(context.Background(), RawReq{Ref: ref, Base: "x", Text: []byte("version: 0\n"), Ack: "x"})
		if !errors.Is(err, ErrNoContract) {
			t.Errorf("raw ref %q: err = %v", ref, err)
		}
	}
	if f.text(t) != baseText || len(f.journal(t)) != 0 {
		t.Error("a refused ref changed something")
	}
}

// TestRefusesLedgerAndTegoHome: a contract a run recorded under the ledger root, or under a refused directory, is in
// the set but not writable, and a change of it is refused with the guard's reason.
func TestRefusesLedgerAndTegoHome(t *testing.T) {
	f := newFixture(t)
	inLedger := filepath.Join(f.ledger, "agent.yaml")
	writeFile(t, inLedger, baseText)
	refused := filepath.Join(f.dir, "tegohome")
	if err := os.MkdirAll(refused, 0o700); err != nil {
		t.Fatal(err)
	}
	inHome := filepath.Join(refused, "agent.yaml")
	writeFile(t, inHome, baseText)
	f.s.Refuse = []string{refused}
	f.writeRun(t, "r-aaaa-0005-rules", inLedger, 5)
	f.writeRun(t, "r-aaaa-0006-rules", inHome, 6)
	for _, p := range []string{inLedger, inHome} {
		c := f.ref(t, p)
		if c.Writable || !strings.Contains(c.Why, "refused") {
			t.Errorf("%s: writable %v, why %q", p, c.Writable, c.Why)
		}
		_, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: c.Ref, Edits: []Edit{{"add", "fs.deny_read", "./x/"}}})
		if !errors.Is(err, ErrNotWritable) {
			t.Errorf("%s: err = %v", p, err)
		}
	}
}

// TestApplyRefusesStaleBase: a confirm whose base is not what the file holds (or carries none) writes nothing.
func TestApplyRefusesStaleBase(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	edits := []Edit{{"remove", "exec.allow", "cat"}}
	for _, base := range []string{"", rulefile.Sum([]byte("other"))} {
		if _, err := f.s.ApplyChange(context.Background(), ChangeReq{Ref: c.Ref, Base: base, Edits: edits}); !errors.Is(err, ErrStale) {
			t.Errorf("base %q: err = %v", base, err)
		}
	}
	// The file changes between the preview and the confirm.
	p, err := f.s.PlanChange(context.Background(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: edits})
	if err != nil || p.Err != "" || p.Stale {
		t.Fatalf("plan: %+v %v", p, err)
	}
	writeFile(t, f.contract, baseText+"# edited\n")
	if _, err := f.s.ApplyChange(context.Background(), ChangeReq{Ref: c.Ref, Base: p.Base, Edits: edits}); !errors.Is(err, ErrStale) {
		t.Errorf("changed since the preview: err = %v", err)
	}
	if f.text(t) != baseText+"# edited\n" || len(f.journal(t)) != 0 {
		t.Error("a stale confirm wrote")
	}
}

// TestWidenNeedsAck: a widening, and a free edit, are refused without the acknowledgement and written with it; a
// narrowing needs none.
func TestWidenNeedsAck(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.ref(t, f.contract)
	widen := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "git"}}}
	p, err := f.s.PlanChange(ctx, widen)
	if err != nil || p.Err != "" || p.Direction != "widens" || !p.NeedsAck || len(p.Now) != 0 {
		t.Fatalf("plan widen: %+v %v", p, err)
	}
	if _, err := f.s.ApplyChange(ctx, widen); !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("widen without ack: %v", err)
	}
	if f.text(t) != baseText {
		t.Fatal("a widening without the acknowledgement wrote")
	}
	widen.Ack = strings.Repeat("0", 64) // a well-formed acknowledgement of nothing previewed
	if _, err := f.s.ApplyChange(ctx, widen); !errors.Is(err, ErrAckMismatch) {
		t.Fatalf("widen with a forged ack: %v", err)
	}
	widen.Ack = p.Ack
	a, err := f.s.ApplyChange(ctx, widen)
	if err != nil || a.ID == "" || !strings.Contains(f.text(t), "git") {
		t.Fatalf("widen with ack: %+v %v", a, err)
	}
	es := f.journal(t)
	if len(es) != 1 || es[0].Via != Via || es[0].Direction != "widens" || es[0].Summary != "exec.allow += git" ||
		len(es[0].Sentences) == 0 || !strings.Contains(es[0].Sentences[0], "→") {
		t.Errorf("journal = %+v", es)
	}
}

// TestNarrowAlsoNowOnlyLiveRuns: a narrowing offers a live block on each running run of the contract alone, places
// it on the runs picked, and journals what it did; a picked run that is not running is reported, never blocked.
func TestNarrowAlsoNowOnlyLiveRuns(t *testing.T) {
	f := newFixture(t)
	f.live[runA2] = true
	f.live[runB] = true // a running run of another contract
	ctx := context.Background()
	c := f.ref(t, f.contract)
	if !slices.Equal(c.Live, []string{runA2}) {
		t.Fatalf("live = %v", c.Live)
	}
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}, AlsoNow: []string{runA2, runA, runB}}
	p, err := f.s.PlanChange(ctx, req)
	if err != nil || p.Direction != "narrows" || p.NeedsAck || len(p.Now) != 1 || p.Now[0].Run != runA2 || p.Now[0].Block != "exec:cat" || !p.Now[0].OK {
		t.Fatalf("plan: %+v %v", p, err)
	}
	a, err := f.s.ApplyChange(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.blocks, []string{runA2 + " exec:cat"}) {
		t.Errorf("blocks placed = %v", f.blocks)
	}
	if len(a.Live) != 3 || !a.Live[0].OK || a.Live[1].OK || a.Live[2].OK {
		t.Errorf("live outcomes = %+v", a.Live)
	}
	h, err := f.s.History(c.Ref)
	if err != nil || len(h) != 1 || len(h[0].Live) != 3 || h[0].Via != Via || !h[0].Current {
		t.Errorf("history = %+v %v", h, err)
	}
}

// TestAlsoNowPathOnlyWhenReadsHeld: "Never allow" on an asked folder offers a path block on a running run only while
// that run holds its reads.
func TestAlsoNowPathOnlyWhenReadsHeld(t *testing.T) {
	f := newFixture(t)
	f.live[runA2] = true
	ctx := context.Background()
	c := f.ref(t, f.contract)
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"never", "fs.ask_read", "./docs/"}}}
	for _, held := range []bool{false, true} {
		f.held = held
		p, err := f.s.PlanChange(ctx, req)
		if err != nil || p.Err != "" || p.Direction != "narrows" {
			t.Fatalf("plan: %+v %v", p, err)
		}
		want := "read:" + filepath.Join(f.proj, "docs")
		if len(p.Now) != 1 || p.Now[0].Block != want || p.Now[0].OK != held || (!held && p.Now[0].Why == "") {
			t.Errorf("held %v: now = %+v", held, p.Now)
		}
	}
}

// TestChangeRefusedWhenCompileFails: a change whose text the compiler refuses is the plan's Err and is not written.
func TestChangeRefusedWhenCompileFails(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "fs.deny_read", "./broken/"}}}
	p, err := f.s.PlanChange(context.Background(), req)
	if err != nil || !strings.Contains(p.Err, "does-not-compile") {
		t.Fatalf("plan: %+v %v", p, err)
	}
	if _, err := f.s.ApplyChange(context.Background(), req); !errors.Is(err, ErrRefused) {
		t.Errorf("apply: %v", err)
	}
	f.s.Compile = nil // no machine config: no compiler, so no write
	if p, _ := f.s.PlanChange(context.Background(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}); !strings.Contains(p.Err, "without the machine config") {
		t.Errorf("no compiler: %+v", p)
	}
	if f.text(t) != baseText {
		t.Error("a refused change wrote")
	}
}

// TestRevert: a change is undone with the page's base; a revert of a narrowing widens and needs the
// acknowledgement; a revert after a later edit is refused, since it would lose that edit.
func TestRevert(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.ref(t, f.contract)
	a, err := f.s.ApplyChange(ctx, ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}})
	if err != nil {
		t.Fatal(err)
	}
	now := rulefile.Sum([]byte(f.text(t)))
	if _, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: now}); !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("revert of a narrowing without ack: %v", err)
	}
	undoAck := historyAck(t, f.s, c.Ref, a.ID)
	if _, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: c.Base, Ack: undoAck}); !errors.Is(err, ErrStale) {
		t.Fatalf("revert with the old base: %v", err)
	}
	r, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: now, Ack: undoAck})
	if err != nil || r.Of != a.ID || r.Direction != "widens" || f.text(t) != baseText {
		t.Fatalf("revert: %+v %v", r, err)
	}
	// History says the revert as what it undid, from the change's own sentences.
	hs, err := f.s.History(c.Ref)
	if err != nil || len(hs) != 2 || hs[0].Op != rulefile.OpRevert || hs[1].UndoneBy != hs[0].ID || len(hs[1].Sentences) != 1 {
		t.Fatalf("history after the revert: %+v %v", hs, err)
	}
	if _, after, _ := strings.Cut(hs[1].Sentences[0], " → "); hs[0].Words != "Undid: "+after || hs[1].Words != "" {
		t.Errorf("the revert reads %q, the change %q; want Undid: %s and none", hs[0].Words, hs[1].Words, after)
	}
	// A change, then an edit by hand: the change is not undone.
	git := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"add", "exec.allow", "git"}}}
	git.Ack = changeAck(t, f.s, git)
	a, err = f.s.ApplyChange(ctx, git)
	if err != nil {
		t.Fatal(err)
	}
	edited := f.text(t) + "# by hand\n"
	writeFile(t, f.contract, edited)
	if _, err := f.s.Revert(ctx, RevertReq{ID: a.ID, Base: rulefile.Sum([]byte(edited))}); !errors.Is(err, ErrStale) {
		t.Errorf("revert after a later edit: %v", err)
	}
	if _, err := f.s.Revert(ctx, RevertReq{ID: "rc-nope", Base: "x"}); !errors.Is(err, ErrRefused) {
		t.Errorf("unknown id: %v", err)
	}
}

// TestRawEdit: a free edit is compiled, classified mixed with the free-edit words, and confirmed like a widening; an
// empty, oversized, binary, unchanged or uncompilable text is refused, and every refusal writes nothing.
func TestRawEdit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.ref(t, f.contract)
	next := strings.Replace(baseText, "[sh, cat, ls]", "[sh, ls]", 1)
	req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(next)}
	p, err := f.s.PlanRaw(ctx, req)
	if err != nil || p.Err != "" || !p.Raw || p.Direction != "mixed" || !p.NeedsAck || p.Why != freeWhy || len(p.Now) != 0 ||
		!strings.Contains(p.Diff, "-  allow: [sh, cat, ls]") {
		t.Fatalf("plan: %+v %v", p, err)
	}
	if _, err := f.s.ApplyRaw(ctx, req); !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("raw without ack: %v", err)
	}
	for name, text := range map[string]string{"empty": "", "big": strings.Repeat("#", 2<<20), "binary": "a\x00b",
		"same": baseText, "broken": baseText + "# broken\n"} {
		bad := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text), Ack: p.Ack}
		if _, err := f.s.ApplyRaw(ctx, bad); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	stale := RawReq{Ref: c.Ref, Base: rulefile.Sum([]byte("x")), Text: []byte(next), Ack: p.Ack}
	if _, err := f.s.ApplyRaw(ctx, stale); !errors.Is(err, ErrStale) {
		t.Errorf("stale raw: %v", err)
	}
	if f.text(t) != baseText {
		t.Fatal("a refused free edit wrote")
	}
	other := req
	other.Text, other.Ack = []byte(strings.Replace(next, "[sh, ls]", "[sh, ls, cat]", 1)), p.Ack // the check's ack on another text
	if _, err := f.s.ApplyRaw(ctx, other); !errors.Is(err, ErrAckMismatch) {
		t.Fatalf("raw with another text's ack: %v", err)
	}
	req.Ack = p.Ack
	a, err := f.s.ApplyRaw(ctx, req)
	if err != nil || f.text(t) != next {
		t.Fatalf("raw with ack: %+v %v", a, err)
	}
	if es := f.journal(t); len(es) != 1 || es[0].Direction != "mixed" || es[0].Via != Via {
		t.Errorf("journal = %+v", es)
	}
}

// TestActBindsConfirmToPreview: the event page's confirm writes only on the base its preview showed (F7), says which
// way the change moves, opens "Never allow" on the asked entry's scope, and places the live block picked.
func TestActBindsConfirmToPreview(t *testing.T) {
	f := newFixture(t)
	f.live[runA2] = true
	f.held = true
	ctx := context.Background()
	p, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1})
	if err != nil || p.Err != "" || p.EntryScope == nil || p.Levels[p.EntryScope.Level] != filepath.Join(f.proj, "docs") {
		t.Fatalf("plan: %+v %v", p, err)
	}
	sc := *p.EntryScope
	p, err = f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "block", Scope: sc})
	if err != nil || p.PickErr != "" || p.Direction != "narrows" || len(p.Now) != 1 || p.Now[0].Block != "read:"+filepath.Join(f.proj, "docs") {
		t.Fatalf("pick: %+v %v", p, err)
	}
	stale, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "block", Scope: sc, Write: true, Base: rulefile.Sum([]byte("x"))})
	if err != nil || !stale.Stale || stale.Saved || f.text(t) != baseText {
		t.Fatalf("stale confirm: %+v %v", stale, err)
	}
	// Allow on the asked folder widens: without the acknowledgement nothing is written; with it the write goes
	// through (and is rolled back by hand, so the narrowing below lands on the preview's base).
	allow, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc})
	if err != nil || allow.PickErr != "" || allow.Direction == "narrows" {
		t.Fatalf("allow preview: %+v %v", allow, err)
	}
	unacked, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc, Write: true, Base: allow.Base})
	if err != nil || !unacked.NeedsAck || unacked.Saved || !strings.Contains(unacked.PickErr, "acknowledgement") || f.text(t) != baseText {
		t.Fatalf("unacknowledged widening: %+v %v", unacked, err)
	}
	acked, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "allow", Scope: sc, Write: true, Base: allow.Base, Ack: allow.Ack})
	if err != nil || !acked.Saved || acked.NeedsAck || f.text(t) == baseText {
		t.Fatalf("acknowledged widening: %+v %v", acked, err)
	}
	if _, err := f.s.Revert(ctx, RevertReq{ID: acked.ID, Base: acked.NewBase}); err != nil || f.text(t) != baseText {
		t.Fatalf("revert of the widening: %v", err)
	}
	done, err := f.s.ActOn(ctx, ActReq{Run: runA2, Seq: 1, Action: "block", Scope: sc, Write: true, Base: p.Base, AlsoNow: []string{runA2}})
	if err != nil || !done.Saved || done.ID == "" || done.PickErr != "" {
		t.Fatalf("confirm: %+v %v", done, err)
	}
	if got := f.text(t); strings.Contains(got, "ask_read") || !strings.Contains(got, "deny_read") || !strings.Contains(got, "./docs/") {
		t.Errorf("contract after never:\n%s", got)
	}
	if !slices.Equal(f.blocks, []string{runA2 + " read:" + filepath.Join(f.proj, "docs")}) {
		t.Errorf("blocks = %v", f.blocks)
	}
	es := f.journal(t)
	// The acknowledged Allow and its revert, then the narrowing and its live block.
	if len(es) != 4 || es[2].Run != runA2 || es[2].Line != 1 || es[2].Via != Via || es[3].Op != rulefile.OpLive {
		t.Errorf("journal = %+v", es)
	}
}

// TestRefusesRetargetedFolder: a contract recorded through a folder symlink that now points elsewhere is not written:
// the write and its journal entry would land on a file no run here ran, which History and Undo never find.
func TestRefusesRetargetedFolder(t *testing.T) {
	f := newFixture(t)
	via := filepath.Join(f.dir, "via")
	if err := os.Symlink(f.proj, via); err != nil {
		t.Fatal(err)
	}
	f.writeRun(t, "r-aaaa-0009-rules", filepath.Join(via, "agent.yaml"), 9)
	c := f.ref(t, filepath.Join(via, "agent.yaml"))
	elsewhere := filepath.Join(f.dir, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(elsewhere, "agent.yaml"), baseText)
	if err := os.Remove(via); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, via); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.ApplyChange(context.Background(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}})
	if !errors.Is(err, ErrNotWritable) || !strings.Contains(err.Error(), "points elsewhere") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(elsewhere, "agent.yaml")); string(b) != baseText {
		t.Error("the write landed on the retargeted folder's file")
	}
}

// journalFails is the local writer whose journal append fails after the write (rulefile.ErrJournal).
type journalFails struct{ Writer }

func (w journalFails) Replace(ctx context.Context, path, base string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	e, err := w.Writer.Replace(ctx, path, base, text, c)
	if err != nil {
		return e, err
	}
	return e, rulefile.ErrJournal
}

// TestJournalFailureOffersNoUndo: a change written but not journaled carries no entry ID, so no page offers an Undo
// the journal cannot do; the warning and the .bak say what happened.
func TestJournalFailureOffersNoUndo(t *testing.T) {
	f := newFixture(t)
	f.s.Writer = journalFails{localWriter{f.s.guard()}}
	c := f.ref(t, f.contract)
	a, err := f.s.ApplyChange(context.Background(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "" || a.Warn == "" || a.Bak == "" {
		t.Errorf("applied: ID %q, Warn %q, Bak %q", a.ID, a.Warn, a.Bak)
	}
}
