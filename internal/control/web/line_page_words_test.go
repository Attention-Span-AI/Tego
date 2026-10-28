// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The line page's fixes: the headline names its object, "Around it" words ask and answer lines as Logs
// does, a person's no reads as one, the Saved notice makes no future claim, and a deep line of
// a long run is read by its offset, never by a scan from line 0 (QG-2, QG-1).

var h1Re = regexp.MustCompile(`(?s)<h1>(.*?)</h1>`)

// headline is the page's h1 with its tags dropped.
func headline(t *testing.T, page string) (text, raw string) {
	t.Helper()
	m := h1Re.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the page has no h1:\n%s", page)
	}
	return strings.TrimSpace(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(m[1], "")), m[1]
}

// TestR9F1HeadlineNamesItsObject: the h1 of a refused read, an allowed connection and a program run each end in what
// they acted on (a path with its folder, host:port, the program's name), with the whole value in the title.
func TestHeadlineNamesItsObject(t *testing.T) {
	s, c, _, proj := askServer(t)
	for _, tc := range []struct {
		seq       string
		want      string
		wantTitle string
	}{
		{"3", "The agent tried to read …/proj/vault/token", filepath.Join(proj, "vault", "token")},
		{"4", "The agent ran git", "/usr/bin/git"},
		{"5", "The agent connected to api.example.com:443", "api.example.com:443"},
	} {
		page := do(s, "GET", "/runs/"+actRun+"/lines/"+tc.seq, "127.0.0.1:8484", c).Body.String()
		text, raw := headline(t, page)
		// A long folder is elided in the middle, as Highlights does; the start and the file name stay.
		// The temporary folder's name ends in a random number of 9 or 10 digits, so the folder is either just short
		// enough to show whole or just too long; both forms are right, and the test failed about one run in five.
		lead, end, elided := strings.Cut(tc.want, "…")
		whole := elided && text == lead+tc.wantTitle
		if elided && !whole && !(strings.HasPrefix(text, lead) && strings.HasSuffix(text, end) && strings.Contains(text, "…")) || !elided && text != tc.want {
			t.Errorf("line %s: h1 %q, want %q", tc.seq, text, tc.want)
		}
		if !strings.Contains(raw, `class="ev-h-target" title="`+tc.wantTitle+`"`) {
			t.Errorf("line %s: the target carries no title with the whole value: %s", tc.seq, raw)
		}
	}
	// A line no rule is made from keeps "Line #N: <kind>".
	page := do(s, "GET", "/runs/"+actRun+"/lines/0", "127.0.0.1:8484", c).Body.String()
	if text, _ := headline(t, page); !strings.HasPrefix(text, "Line #0: ") {
		t.Errorf("run_start's h1 = %q, want the Line #0 fallback", text)
	}
}

// TestR9F1HeadOf: the headline shortens the run's home to ~/, masks a secret in the path, and cuts a long path near 80
// characters in the middle while the title keeps it whole.
func TestHeadOf(t *testing.T) {
	h := headOf(&rules.ActPlan{Kind: "read", Verb: "read", Refused: true, What: "/home/u/.config/telemetry/token"}, "/home/u")
	if h.Lead+" "+h.Target != "The agent tried to read ~/.config/telemetry/token" || h.Title != "/home/u/.config/telemetry/token" {
		t.Errorf("a refused read: %+v", h)
	}
	long := "/home/u/" + strings.Repeat("deep/", 40) + "file.txt"
	h = headOf(&rules.ActPlan{Kind: "write", Verb: "write to", What: long}, "/home/u")
	if n := len([]rune(h.Target)); n > maxHeadTarget || !strings.HasSuffix(h.Target, "file.txt") || h.Title != long {
		t.Errorf("a long path: %d runes, %+v", n, h)
	}
	if headOf(&rules.ActPlan{}, "") != nil || headOf(nil, "") != nil {
		t.Error("a plan with no action has a headline")
	}
}

// realAskRun rewrites actRun as the supervisor writes an ask a person denied: #1 the ask to read vault/token under
// fs.ask_read, #2 the answer (approved false, ask-denied, by a person from the dashboard after 77 ms), #3 the read it
// refused, #4 git status, #5 a connection to api.example.com:443.
func realAskRun(t *testing.T, root, contract, proj string) {
	t.Helper()
	token := filepath.Join(proj, "vault", "token")
	writeLines(t, root, actRun, []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
			ContractSource: &record.ContractSource{Path: contract}}),
		ledgertest.Event(t, record.KindAsk, map[string]any{"ask_id": testAsk, "ask_rule": "fs.ask_read[./vault/]", "hold": "open",
			"op": "read", "target": token}),
		ledgertest.Event(t, record.KindAnswer, map[string]any{"ask_id": testAsk, "ask_rule": "fs.ask_read[./vault/]",
			"by": "uid:1000 pid:1 dashboard", "after_s": 0.077, "approved": false, "answer_reason": "ask-denied", "op": "read", "target": token}),
		ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: token}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Reason = record.SourceSeccomp, "fs.ask_read[./vault/]", record.VerdictRefused, record.ReasonAskDenied
			e.Authority = record.AuthorityHuman
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		}),
		ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "status"}, ExecID: "x/1/1"}, allowedBy("exec[git]")),
		ledgertest.Event(t, record.KindNet, record.NetPayload{Op: "connect", Dst: "1.2.3.4:443", Host: "api.example.com", Proto: "tcp"},
			allowedBy("net[api.example.com:443]")),
	})
}

var ctxRe = regexp.MustCompile(`(?s)<ul class="ev-ctx">(.*?)</ul>`)

// TestR9F1AroundItWordsAsksAndAnswers: on the refused read, "Around it" says the ask row was asked and the answer row
// was denied by a person, never "Recorded" or the answer line's raw target.
func TestAroundItWordsAsksAndAnswers(t *testing.T) {
	s, c, contract, proj := askServer(t)
	realAskRun(t, s.cfg.Ledger, contract, proj)
	page := do(s, "GET", "/runs/"+actRun+"/lines/3", "127.0.0.1:8484", c).Body.String()
	m := ctxRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the page has no Around it list")
	}
	rows := strings.Split(m[1], "</li>")
	var ask, answer string
	for _, r := range rows {
		switch {
		case strings.Contains(r, ">#1<"):
			ask = r
		case strings.Contains(r, ">#2<"):
			answer = r
		}
	}
	mustContain(t, "the ask row", ask, `v-asked`, `b b-asked`, ">Asked<", "Asked to read", "vault/token")
	mustContain(t, "the answer row", answer, `v-refused`, ">Denied<", "Denied by ", "vault/token")
	for _, r := range []string{ask, answer} {
		if strings.Contains(r, "Recorded") || strings.Contains(r, testAsk+" by") {
			t.Errorf("a row still says Recorded or the raw answer: %s", r)
		}
	}
}

// TestR9F1PersonsNoReadsAsOne: the decision of a read a person refused says so and names the rule that asked.
func TestPersonsNoReadsAsOne(t *testing.T) {
	s, c, contract, proj := askServer(t)
	realAskRun(t, s.cfg.Ledger, contract, proj)
	page := do(s, "GET", "/runs/"+actRun+"/lines/3", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the decision", page, "<dt>Verdict</dt><dd>Refused: a person said no</dd>", "<dt>Decided by</dt>",
		"asked by fs.ask_read[./vault/]")
	if strings.Contains(page, "Refused by a rule") {
		t.Error("a person's no still reads as a rule's refusal")
	}
}

// TestR9F1SavedLineMakesNoFutureClaim: the notice after Confirm points at the panel and never says it is putting the
// block in force, since it stays on screen after the panel says Live now.
func TestSavedLineMakesNoFutureClaim(t *testing.T) {
	p := &rules.ActPlan{Contract: "/p/agent.yaml", Sentences: []rules.Sentence{{After: "Can never read ./vault/"}},
		Live: []rules.LiveResult{{Run: "r-a", OK: true}, {Run: "r-b", OK: true}}}
	for run, want := range map[string]string{
		"r-a": "Saved: Can never read ./vault/, from the next run of agent.yaml. Its state on this run and on 1 other run is shown in the panel.",
		"r-c": "Saved: Can never read ./vault/, from the next run of agent.yaml. Its state on 2 running runs is shown in the panel.",
	} {
		if got := savedLine(p, run, shortener{cwd: p.Cwd, home: p.Home}); got != want {
			t.Errorf("run %s:\n got %q\nwant %q", run, got, want)
		}
	}
	p.Live = p.Live[:1]
	if got := savedLine(p, "r-a", shortener{cwd: p.Cwd, home: p.Home}); strings.Contains(got, "Putting it in force") || !strings.HasSuffix(got, " Its state on this run is shown in the panel.") {
		t.Errorf("one run: %q", got)
	}
}

// bigRun writes run under root: run_start (naming contract unless it is ""), n reads of files under proj, run_end. It
// returns the byte offset each line starts at.
func bigRun(t *testing.T, root, run, contract, proj string, n int) []int64 {
	t.Helper()
	p := record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("0", 64), Command: []string{"sh"},
		Cwd: proj, Kernel: "6", StopGrace: "1s"}
	if contract != "" {
		p.ContractSource = &record.ContractSource{Path: contract}
	}
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	var offs []int64
	put := func(i int, e *record.Event) {
		e.Run, e.Seq, e.TS = run, uint64(i), t0.Add(time.Duration(i)*time.Millisecond) //nolint:gosec // i < n
		if i > 0 {
			e.Prev = strings.Repeat("a", 64)
		}
		l, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		offs = append(offs, int64(buf.Len()))
		buf.Write(append(l, '\n'))
	}
	put(0, ledgertest.Event(t, record.KindRunStart, p))
	allowed := allowedBy("unmatched")
	for i := 1; i <= n; i++ {
		e := ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: filepath.Join(proj, "f"+strconv.Itoa(i%300)+".txt")}, allowed)
		e.PID, e.TID = 4000+i%7, 4000+i%7
		put(i, e)
	}
	put(n+1, ledgertest.Event(t, record.KindRunEnd, record.RunEndPayload{Reason: "exit"}, func(e *record.Event) { e.Reason = "exit" }))
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return offs
}

// damage overwrites line seq of run's events file in place with x's of the same length and puts the file's mtime
// back, so the read model keeps the lines it holds (same device, inode, size and mtime) while any scan from line 0
// stops at the damaged line.
func damage(t *testing.T, root, run string, offs []int64, seq int) {
	t.Helper()
	ev := filepath.Join(root, run, "events.jsonl")
	fi, err := os.Stat(ev)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(ev)
	if err != nil {
		t.Fatal(err)
	}
	copy(b[offs[seq]:offs[seq+1]-1], bytes.Repeat([]byte("x"), int(offs[seq+1]-1-offs[seq])))
	f, err := os.OpenFile(ev, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(b, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(ev, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
}

// TestR9F1DeepLineReadsByItsOffset: line 49000 of a 50k-line run is read where the read model saw it start, by the
// facts column (ledgerview.Explain) and by the rule service (rules.ActReq.Hint): with line 5 damaged in place after the
// page first loaded, a scan from line 0 would stop there, yet the page still explains the line and previews a rule.
// The same holds for a watch run, whose panel says at once that no rule can be made (r9 QG-1). The warm page is timed
// against its 20 ms budget when TEGO_LINE_BUDGET is set (a loaded test machine says nothing about it otherwise).
func TestDeepLineReadsByItsOffset(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 50k-line run")
	}
	root, contract, proj := askFixture(t)
	const big, watch = "r-aaaaaaaa-0000000000050-bigrun", "r-aaaaaaaa-0000000000020-watchd"
	offs := bigRun(t, root, big, contract, proj, 50000)
	woffs := bigRun(t, root, watch, "", proj, 20000)
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	c := login(t, s)
	line, wline := "/runs/"+big+"/lines/49000?a=block", "/runs/"+watch+"/lines/19000"
	for _, p := range []string{line, wline} { // the read model takes the runs in
		if w := do(s, "GET", p, "127.0.0.1:8484", c); w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	damage(t, root, big, offs, 5)
	damage(t, root, watch, woffs, 5)
	if _, err := os.Stat(filepath.Join(root, big, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	page := do(s, "GET", line, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "line 49000 after the damage", page, "Every field", `name="base" value="`, "The agent read ")
	if strings.Contains(page, "could not be read back") || strings.Contains(page, "No rule can be made") {
		t.Fatalf("line 49000 was looked for by a scan from line 0:\n%s", page)
	}
	wpage := do(s, "GET", wline, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the watch run's line after the damage", wpage, "Every field", "names no contract file")

	var ts []time.Duration
	for range 5 {
		a := time.Now()
		do(s, "GET", line, "127.0.0.1:8484", c)
		ts = append(ts, time.Since(a))
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	t.Logf("line 49000 of a 50k-line run, warm: median %v", ts[2])
	if os.Getenv("TEGO_LINE_BUDGET") != "" && ts[2] > 20*time.Millisecond {
		t.Errorf("line 49000 warm median %v, budget 20 ms", ts[2])
	}
}

// TestR9F1LineChainWords: a line before a run's break says it and every line before it hash correctly, the break
// line says its own bytes fail, and a chain that verifies or breaks after the last line adds nothing (r9 QG-10).
func TestLineChainWords(t *testing.T) {
	broken := ledgerview.Chain{State: ledgerview.ChainBroken, AtLine: true, Line: 30000, Reason: "id does not match line bytes"}
	if w, at := lineChainWords(broken, 100); at != "before" || !strings.Contains(w, "broken later at #30000") {
		t.Errorf("line 100: %q %q", w, at)
	}
	if w, at := lineChainWords(broken, 30000); at != "here" || w != "Changed after it was written" {
		t.Errorf("line 30000: %q %q", w, at)
	}
	if w, at := lineChainWords(broken, 30001); w != "" || at != "" {
		t.Errorf("line 30001: %q %q", w, at)
	}
	for _, c := range []ledgerview.Chain{{State: ledgerview.ChainVerified}, {State: ledgerview.ChainBroken, Reason: "anchor"}} {
		if w, at := lineChainWords(c, 5); w != "" || at != "" {
			t.Errorf("%+v: %q %q", c, w, at)
		}
	}
}

// TestR9F1HeldLiveBlockAfterUndo: after an Undo that keeps its live block, the panel says the program is still blocked
// live on this run, with a link to remove it on the run page, and offers no Block now for it again.
func TestHeldLiveBlockAfterUndo(t *testing.T) {
	s, line, saved := savedWithBlock(t)
	v, _ := undoFields(t, saved)
	c := login(t, s)
	v.Set("csrf", s.csrf)
	follow(t, s, c, post(s, line, v, own, "", c))
	page := do(s, "GET", line, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the panel after the Undo", page, "ev-held", "Blocked live on this run", `title="exec:git"`,
		`href="/runs/`+actRun+`#block">Remove it on the run page`)
	if strings.Contains(page, `id="act-block"`) {
		t.Error("the panel offers Block now for a block already in place")
	}
}
