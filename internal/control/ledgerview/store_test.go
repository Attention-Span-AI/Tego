// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// appendLines appends lines to a run's events file.
func appendLines(t testing.TB, root, run string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(strings.Join(lines, "")); err != nil {
		t.Fatal(err)
	}
}

func markLive(t testing.TB, root, run string, live bool) {
	t.Helper()
	p := filepath.Join(root, ".live", run)
	if !live {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRevisions: an unchanged ledger keeps its revision; an append, a new run, a run's end and a live state change
// each move it, and Changed names only the run that changed.
func TestRevisions(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	a, b := "r-aaaa-0001-revaxx", "r-aaaa-0002-revbxx"
	writeRun(t, root, a, line(a, "x", 0, t0, "run_start", ""), line(a, "x", 1, t0.Add(1), "ask", `"ask_id":"q-1","hold":"exec"`))
	writeRun(t, root, b, line(b, "y", 0, t0, "run_start", ""))
	markLive(t, root, a, true)
	s1, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := Load(root)
	if s2.Rev != s1.Rev || len(s2.Changed(s1.Rev)) != 0 {
		t.Fatalf("unchanged ledger: rev %d then %d, changed %v", s1.Rev, s2.Rev, s2.Changed(s1.Rev))
	}
	if s1.Find(a) != s2.Find(a) {
		t.Fatal("an unchanged run is not shared between snapshots")
	}

	appendLines(t, root, a, line(a, "x", 2, t0.Add(2), "exec", `"verdict":"allow","argv":["git"]`))
	s3, _ := Load(root)
	ch := s3.Changed(s2.Rev)
	if s3.Rev <= s2.Rev || len(ch) != 1 || ch[0].ID != a || ch[0].Lines != 3 || ch[0].LastSeq != 2 {
		t.Fatalf("after an append: rev %d -> %d, changed %+v", s2.Rev, s3.Rev, ch)
	}
	if r := s3.Find(a); len(r.Pending) != 1 || !r.Live {
		t.Fatalf("live run with an open ask: pending %v live %v", r.Pending, r.Live)
	}

	c := "r-aaaa-0003-revcxx"
	writeRun(t, root, c, line(c, "z", 0, t0.Add(time.Hour), "run_start", ""))
	s4, _ := Load(root)
	if ch := s4.Changed(s3.Rev); s4.Rev <= s3.Rev || len(ch) != 1 || ch[0].ID != c || s4.Runs[0].ID != c {
		t.Fatalf("a new run: changed %v, newest %s", ch, s4.Runs[0].ID)
	}

	appendLines(t, root, a, line(a, "x", 3, t0.Add(3), "run_end", `"reason":"exit","exit_code":0`))
	markLive(t, root, a, false)
	s5, _ := Load(root)
	r := s5.Find(a)
	if s5.Rev <= s4.Rev || !r.Ended || r.Live || len(r.Pending) != 0 || len(s5.Pending()) != 0 {
		t.Fatalf("run end: rev %d -> %d, ended %v live %v pending %v", s4.Rev, s5.Rev, r.Ended, r.Live, r.Pending)
	}

	markLive(t, root, b, true)
	s6, _ := Load(root)
	if ch := s6.Changed(s5.Rev); len(ch) != 1 || ch[0].ID != b || !ch[0].Live {
		t.Fatalf("a live entry alone: changed %v", ch)
	}
	if err := os.RemoveAll(filepath.Join(root, c)); err != nil {
		t.Fatal(err)
	}
	s7, _ := Load(root)
	if s7.Rev <= s6.Rev || s7.Find(c) != nil || len(s7.Runs) != 2 {
		t.Fatalf("a removed run: rev %d -> %d, runs %d", s6.Rev, s7.Rev, len(s7.Runs))
	}
}

// TestReplacedFileIsReadAgain: a file of the same size but another inode, and a file that got shorter, are read
// from the start; an append to a file read before is seen on the next request.
func TestReplacedFileIsReadAgain(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	id := "r-aaaa-0004-replxx"
	writeRun(t, root, id, line(id, "x", 0, t0, "run_start", ""), line(id, "x", 1, t0, "exec", `"verdict":"allow"`))
	r, err := LoadRun(root, id)
	if err != nil || r.Lines != 2 || r.Refusals != 0 {
		t.Fatalf("first read: %v %v", r, err)
	}
	// The same length, another inode: one exec line becomes a refused one of the same size.
	tmp := filepath.Join(root, id, "events.new")
	body := line(id, "x", 0, t0, "run_start", "") + strings.Replace(line(id, "x", 1, t0, "exec", `"verdict":"allow"`), `"kind":"exec"`, `"kind":"ref"`, 1)
	body = strings.Replace(body, `"kind":"ref"`, `"kind":"refused"`, 1)
	body = strings.Replace(body, `"verdict":"allow"`, `"verdict":"xy"`, 1)
	if len(body) != int(fileSize(t, filepath.Join(root, id, "events.jsonl"))) {
		t.Fatalf("test setup: replacement is %d bytes, want the same size", len(body))
	}
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(root, id, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	if r, _ = LoadRun(root, id); r.Lines != 2 || r.Refusals != 1 {
		t.Fatalf("after a same-size replacement: %d lines, %d refusals; want 2 and 1", r.Lines, r.Refusals)
	}
	writeRun(t, root, id, line(id, "x", 0, t0, "run_start", "")) // truncated in place
	if r, _ = LoadRun(root, id); r.Lines != 1 || r.Refusals != 0 {
		t.Fatalf("after truncation: %d lines, %d refusals; want 1 and 0", r.Lines, r.Refusals)
	}
	appendLines(t, root, id, line(id, "x", 1, t0.Add(1), "refused", `"reason":"net-not-allowed","op":"connect","target":"1.2.3.4:80"`))
	s, _ := Load(root)
	if r := s.Find(id); r.Lines != 2 || r.Refusals != 1 || len(s.Refusals(0)) != 1 {
		t.Fatalf("after an append: %+v", r)
	}
}

func fileSize(t testing.TB, p string) int64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// randomLedger writes runs of mixed lines, some with a clock that steps back, and returns the root.
func randomLedger(t testing.TB, seed uint64, runs, lines int) string {
	t.Helper()
	root := t.TempDir()
	rng := rand.New(rand.NewPCG(seed, 1))
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	for i := range runs {
		id := fmt.Sprintf("r-aaaa-%04d-randxx", i)
		agent := []string{"Claude", "codex", "été"}[i%3]
		ts := t0.Add(time.Duration(rng.IntN(1000)) * time.Second)
		ls := []string{line(id, agent, 0, ts, "run_start", `"command":["sh"]`)}
		for j := 1; j < lines; j++ {
			step := time.Duration(rng.IntN(5)) * time.Millisecond
			if i%4 == 0 && rng.IntN(10) == 0 {
				step = -step // a wall clock that steps back
			}
			ts = ts.Add(step)
			var extra, kind string
			switch rng.IntN(6) {
			case 0:
				kind, extra = "refused", fmt.Sprintf(`"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"10.0.0.%d:443"`, rng.IntN(3))
			case 1:
				kind, extra = "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`
			case 2:
				kind, extra = "exec", fmt.Sprintf(`"verdict":"allow","rule":"exec.allow[git]","argv":["git","Status-%d"]`, rng.IntN(4))
			case 3:
				kind, extra = "fs", fmt.Sprintf(`"verdict":"observed","op":"open","path":"/p/Ñ-%d.txt"`, rng.IntN(5))
			case 4:
				// The refused line a draw puts right after it mirrors it (pair.go): same rule and reason.
				kind, extra = "net", `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"udp","dst":"8.8.8.8:65535"`
			default:
				kind, extra = "ask", fmt.Sprintf(`"ask_id":"q-%d","hold":"exec"`, j)
			}
			ls = append(ls, line(id, agent, j, ts, kind, extra))
		}
		writeRun(t, root, id, ls...)
	}
	return root
}

// Fold is the fold this package had before the read model folded per run (foldRun): it folds identical refusals (same run, kind, rule, reason and target) into the newest one's row, keeping the
// order of each group's newest line. evs must be newest first. Nothing is dropped: Count holds the folded lines.
func Fold(evs []*Event) []Row {
	var rows []Row
	idx := map[string]int{}
	for _, e := range evs {
		if e.Refused() {
			k := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s", e.Run, e.Kind, e.Rule, e.Reason, e.Op, e.Target)
			if i, ok := idx[k]; ok {
				rows[i].Count++
				rows[i].First = e.TS
				rows[i].Seqs = append(rows[i].Seqs, e.Seq)
				continue
			}
			idx[k] = len(rows)
		}
		rows = append(rows, Row{Event: *e, Count: 1, First: e.TS, Seqs: []uint64{e.Seq}})
	}
	return rows
}

// queryRef is the Query this package had before the read model was indexed: every matching line sorted, folded,
// then paged, a refused action's mirror left out unless refused lines were asked for. Query must answer exactly as
// it does.
func queryRef(s *Snapshot, f Filter) Page {
	if f.PageSize <= 0 {
		f.PageSize = 100
	}
	var evs []*Event
	pg := Page{Counts: map[string]int{}}
	runs := map[string]bool{}
	for _, r := range s.Runs {
		all := r.AllEvents()
		for i := range all {
			e := &all[i]
			if e.Mirror && f.Kind != "refused" && !f.OnlyRefus {
				continue
			}
			if !f.matchFields(e) {
				continue
			}
			if f.Text != "" {
				hay := strings.ToLower(strings.Join([]string{e.Op, e.Target, e.Rule, e.Reason, e.Agent, e.Run, e.Kind}, " "))
				if !strings.Contains(hay, strings.ToLower(f.Text)) {
					continue
				}
			}
			if f.HideSys && e.SystemLookup || f.HideNoise && SystemNoise(e) {
				pg.SysHidden++
				continue
			}
			pg.Counts[verdictOf(e)]++
			runs[e.Run] = true
			evs = append(evs, e)
		}
	}
	pg.Matched, pg.Runs = len(evs), len(runs)
	sort.Slice(evs, func(i, j int) bool { return less(evs[i], evs[j]) })
	rows := Fold(evs)
	pg.Groups = len(rows)
	start := 0
	if c, ok := parseCursor(f.Before); ok {
		start = sort.Search(len(rows), func(i int) bool { return !less(&rows[i].Event, &c) && !sameKey(&rows[i].Event, &c) })
	}
	end := start + f.PageSize
	if end < len(rows) {
		pg.Next = rows[end-1].Cursor()
	} else {
		end = len(rows)
	}
	pg.Rows = rows[start:end]
	return pg
}

func samePage(t *testing.T, name string, got, want Page) {
	t.Helper()
	if len(got.Rows) == 0 && len(want.Rows) == 0 {
		got.Rows, want.Rows = nil, nil
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: Query differs from the reference\n got  %d rows next %q matched %d groups %d sys %d counts %v\n want %d rows next %q matched %d groups %d sys %d counts %v",
			name, len(got.Rows), got.Next, got.Matched, got.Groups, got.SysHidden, got.Counts,
			len(want.Rows), want.Next, want.Matched, want.Groups, want.SysHidden, want.Counts)
	}
}

// TestQueryMatchesReference: on random runs (a clock stepping back in some, non-ASCII text, refusals that fold),
// Query, with and without each filter and through every page, answers as the unindexed reference does.
func TestQueryMatchesReference(t *testing.T) {
	root := randomLedger(t, 7, 9, 400)
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	mirrors := 0
	for _, r := range s.Runs {
		for i := range r.Events {
			if r.Events[i].Mirror {
				mirrors++
			}
		}
	}
	if mirrors == 0 {
		t.Fatal("the random ledger holds no mirror, so the reference checks nothing of pair.go")
	}
	for _, f := range []Filter{
		{},
		{PageSize: 37},
		{Run: "r-aaaa-0004-randxx", PageSize: 50},
		{Agent: "codex"},
		{Kind: "net"},
		{Kind: "run"},
		{Kind: "ask"},
		{Verdicts: []string{"refused"}},
		{Verdicts: []string{"allow", "observed"}, PageSize: 20},
		{Text: "STATUS-2"},
		{Text: "ñ-3"},
		{Text: "été"},
		{Text: "git status"},
		{Text: "nomatch-anywhere"},
		{Text: "a\nb"},
		{HideSys: true},
		{HideNoise: true},
		{HideSys: true, Verdicts: []string{"refused"}, Text: "10.0.0"},
		{OnlyRefus: true},
	} {
		name := fmt.Sprintf("%+v", f)
		for page := 0; page < 200; page++ {
			got, want := s.Query(f), queryRef(s, f)
			samePage(t, fmt.Sprintf("%s page %d", name, page), got, want)
			if want.Next == "" {
				break
			}
			f.Before = want.Next
		}
	}
	// Refusals and RunRefusals against the fold of every refused line.
	var evs []*Event
	for _, r := range s.Runs {
		probes := probeTargets(r)
		for i := range r.Events {
			if e := &r.Events[i]; e.Kind == "refused" && !probes[e.Target] {
				evs = append(evs, e)
			}
		}
	}
	sort.Slice(evs, func(i, j int) bool { return less(evs[i], evs[j]) })
	if got, want := s.Refusals(0), Fold(evs); !reflect.DeepEqual(got, want) {
		t.Fatalf("Refusals: %d rows, want %d", len(got), len(want))
	}
	for _, r := range s.Runs {
		// RunRefusals lists what Run.Refusals counts: refused actions, and refused lines that mirror no action
		// (pair.go's rule, written out here as the reference), as many as the count says.
		var evs []*Event
		for i := range r.Events {
			e := &r.Events[i]
			if (e.Kind == "refused" && !e.Mirror) || (e.Verdict == "refused" && record.Kind(e.Kind).IsAction()) {
				evs = append(evs, e)
			}
		}
		if len(evs) != r.Refusals {
			t.Fatalf("%s: %d refusals listed by the rule, Run.Refusals %d", r.ID, len(evs), r.Refusals)
		}
		sort.Slice(evs, func(i, j int) bool { return less(evs[i], evs[j]) })
		if got, want := RunRefusals(r), Fold(evs); !reflect.DeepEqual(got, want) {
			t.Fatalf("RunRefusals(%s): %d rows, want %d", r.ID, len(got), len(want))
		}
	}
}

// TestTimelineMatchesFold: the timeline is the run's lines in falling seq order folded, every line but the mirrors
// and quiet gaps or the refusals, and Below pages it by seq.
func TestTimelineMatchesFold(t *testing.T) {
	root := randomLedger(t, 11, 3, 300)
	s, _ := Load(root)
	for _, r := range s.Runs {
		for _, refused := range []bool{false, true} {
			var evs []*Event
			for i := len(r.Events) - 1; i >= 0; i-- {
				e := &r.Events[i]
				if refused && e.Refusal() || !refused && !e.Mirror && !QuietGap(e) {
					evs = append(evs, e)
				}
			}
			want := Fold(evs)
			tl := TimelineOf(r, refused)
			if got := tl.Rows(0, tl.Len()); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s refused=%v: %d rows, want %d", r.ID, refused, len(got), len(want))
			}
			for _, seq := range []uint64{0, 1, 57, 150, 299, 1000} {
				k := 0
				for k < len(want) && want[k].Seq >= seq {
					k++
				}
				if got := tl.Below(seq); got != k {
					t.Fatalf("%s Below(%d) = %d, want %d", r.ID, seq, got, k)
				}
			}
		}
	}
}

// TestEvictedRunsReadAgain: past MaxResidentBytes an ended run's lines leave memory, its summary stays, and every
// view reads them again with the same answer.
func TestEvictedRunsReadAgain(t *testing.T) {
	defer func(b int64) { MaxResidentBytes = b }(MaxResidentBytes)
	root := randomLedger(t, 3, 6, 200)
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	for i := range 6 {
		id := fmt.Sprintf("r-aaaa-%04d-randxx", i)
		appendLines(t, root, id, line(id, "x", 200, t0.Add(time.Hour), "run_end", `"reason":"exit","exit_code":0`))
	}
	full, _ := Load(root)
	want := full.Query(Filter{Text: "git"})
	MaxResidentBytes = 1
	appendLines(t, root, "r-aaaa-0000-randxx", line("r-aaaa-0000-randxx", "x", 201, t0.Add(2*time.Hour), "gap", ""))
	s, _ := Load(root)
	evicted := 0
	for _, r := range s.Runs {
		if r.Events == nil {
			evicted++
			if len(r.AllEvents()) != r.Lines || r.Lines == 0 {
				t.Fatalf("%s: AllEvents %d lines, summary %d", r.ID, len(r.AllEvents()), r.Lines)
			}
		}
	}
	if evicted == 0 {
		t.Fatal("no run was evicted under a 1-byte budget")
	}
	got := s.Query(Filter{Text: "git"})
	if got.Matched != want.Matched || got.Groups != want.Groups || len(got.Rows) != len(want.Rows) {
		t.Fatalf("after eviction: matched %d groups %d, want %d %d", got.Matched, got.Groups, want.Matched, want.Groups)
	}
	r, err := LoadRun(root, "r-aaaa-0003-randxx")
	if err != nil || len(r.Events) != r.Lines {
		t.Fatalf("LoadRun of an evicted run: %d events, %d lines, %v", len(r.Events), r.Lines, err)
	}
}

// TestConcurrentReads: requests read while a run grows; run with -race.
func TestConcurrentReads(t *testing.T) {
	root := randomLedger(t, 5, 4, 100)
	id := "r-aaaa-0001-randxx"
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s, err := Load(root)
				if err != nil {
					t.Error(err)
					return
				}
				_ = s.Query(Filter{Text: "git", PageSize: 10})
				_ = s.Query(Filter{})
				_ = s.Refusals(5)
				r, err := LoadRun(root, id)
				if err != nil {
					t.Error(err)
					return
				}
				tl := TimelineOf(r, g%2 == 0)
				_ = tl.Rows(0, 20)
				_ = RunRefusals(r)
				if len(r.Events) > 0 {
					_ = FindSimilar(s, &r.Events[0])
					_, _ = Line(root, id, r.Events[len(r.Events)/2].Seq)
				}
			}
		}()
	}
	for j := 100; j < 400; j++ {
		appendLines(t, root, id, line(id, "codex", j, t0.Add(time.Duration(j)*time.Millisecond), "exec", `"verdict":"allow","argv":["git"]`))
	}
	close(stop)
	wg.Wait()
	r, err := LoadRun(root, id)
	if err != nil || r.Lines != 400 {
		t.Fatalf("after the writer: %d lines, %v", r.Lines, err)
	}
}

// TestLineByOffset: Line reads a line from the offset the store recorded, and still finds it after the file was
// replaced under it.
func TestLineByOffset(t *testing.T) {
	root := randomLedger(t, 9, 1, 300)
	id := "r-aaaa-0000-randxx"
	if _, err := LoadRun(root, id); err != nil {
		t.Fatal(err)
	}
	lf, err := Line(root, id, 150)
	if err != nil || !strings.Contains(lf.Raw, `"seq":150,`) {
		t.Fatalf("Line 150: %v %v", lf, err)
	}
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id, line(id, "x", 0, t0, "run_start", ""), line(id, "x", 1, t0, "gap", `"what":"replaced"`))
	if lf, err = Line(root, id, 1); err != nil || !strings.Contains(lf.Raw, "replaced") {
		t.Fatalf("Line 1 of the replaced file: %v %v", lf, err)
	}
	if _, err = Line(root, id, 150); !os.IsNotExist(err) {
		t.Fatalf("Line 150 of the replaced file: %v, want not exist", err)
	}
}

// TestChainVerdictCached: an ended run is verified once while its file and the anchor stay the same; a change to
// its file is verified again and caught.
func TestChainVerdictCached(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7400-c4chex"
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "cache-test"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{LauncherPID: 1, LauncherStartNS: 1, TegoVersion: "0.1.0-dev",
		Tier: "landlock", Capture: "off", Kernel: "6.17.0", ContractHash: strings.Repeat("7a", 32), StopGrace: "10s",
		Command: []string{"sh"}, Cwd: "/p"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	n := chainVerifies.Load()
	for range 3 {
		if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
			t.Fatalf("chain: %+v", c)
		}
	}
	if got := chainVerifies.Load() - n; got != 1 {
		t.Fatalf("%d verifications for three checks of an unchanged run, want 1", got)
	}
	p := filepath.Join(root, id, "events.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), `"sh"`, `"zz"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	// The same size: only the mtime (and the content) moved. Make sure the mtime differs on a coarse clock.
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(p, later, later); err != nil {
		t.Fatal(err)
	}
	r, _ = LoadRun(root, id)
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() {
		t.Fatalf("after an edit: %+v, want broken", c)
	}
}

// TestInPlaceRewriteKeepingSizeAndMtimeIsSeen is r10 BR-2: a line of an ended run's events file rewritten in place at
// the same length, its mtime then put back as `touch -r` puts it, leaves the file's device, inode, size and mtime as
// they were. Only its ctime moved. The next read takes the file again from the start, so the read model serves the
// edited bytes, and the chain verdict kept as verified is a new key, checked again before the page answers: broken.
// Before, both kept the old file's view for the verdict's ten minutes (chainTTL).
func TestInPlaceRewriteKeepingSizeAndMtimeIsSeen(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7402-c4chex"
	chainRun(t, root, anchor, id)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
		t.Fatalf("chain before the edit: %+v", c)
	}
	p := filepath.Join(root, id, "events.jsonl")
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"sh"`, `"zz"`, 1) // the run_start's command, at the same length
	if edited == string(b) {
		t.Fatal("test setup: nothing to edit")
	}
	f, err := os.OpenFile(p, os.O_WRONLY, 0) // in place: the same inode, never truncated
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte(edited), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// The mtime put back; again until the ctime differs from the first look's on a coarse clock (each utimes moves it).
	var after os.FileInfo
	for i := 0; ; i++ {
		if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
		if after, err = os.Stat(p); err != nil {
			t.Fatal(err)
		}
		if ctimeOf(t, after) != ctimeOf(t, before) {
			break
		}
		if i == 100 {
			t.Fatal("test setup: the ctime never moved")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if was, now := idOf(before), idOf(after); was.dev != now.dev || was.ino != now.ino || was.size != now.size || was.mtime != now.mtime {
		t.Fatalf("test setup: %+v became %+v, want the same device, inode, size and mtime", was, now)
	}
	r, err = LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	served := false
	for _, e := range r.AllEvents() {
		if e.Kind == string(record.KindRunStart) {
			served = strings.Contains(e.Raw, `"zz"`)
		}
	}
	if !served {
		t.Error("the read model still serves the run_start as it was before the edit")
	}
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() {
		t.Errorf("chain after the edit: %+v, want broken", c)
	}
}

// ctimeOf is fi's inode change time, read here, not through fileID.
func ctimeOf(t *testing.T, fi os.FileInfo) int64 {
	t.Helper()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat for %s", fi.Name())
	}
	return st.Ctim.Nano()
}
