// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// The demo polish: what the recorded frames show, held here.

const (
	vidLeft  = "r-aaaaaaaa-0000000000031-vleftx"
	vidRight = "r-aaaaaaaa-0000000000032-vright"
)

// videoFixture is the supply-chain take while both sides still run: LEFT watched and robbed, RIGHT enforced, its
// token ask denied and its confidential plan allowed once. Both runs are live (.live), as on stage before /quit.
func videoFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	write := func(run, contract string, ls ...string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
		if contract != "" {
			if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	const user = `"launcher_user":"alice","launcher_uid":1000`
	write(vidLeft, "",
		line(vidLeft, "watch-codex", 0, at(0), "run_start", `"tier":"observe","command":["codex"],"cwd":"/d/without/proj",`+user),
		line(vidLeft, "watch-codex", 1, at(1), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/home/.ssh/id_rsa"`),
		line(vidLeft, "watch-codex", 2, at(1), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/home/.config/telemetry/token"`),
		line(vidLeft, "watch-codex", 3, at(1), "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:9481","proto":"tcp"`))
	write(vidRight, "fs:\n  deny_read:\n    - /d/with/home/.ssh/\n  ask_read:\n    - /d/with/home/.config/telemetry/\n    - ./confidential/\nnet:\n  allow:\n    - 127.0.0.1:9483\n",
		line(vidRight, "codex-tego", 0, at(0), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/d/with/proj",`+user),
		line(vidRight, "codex-tego", 1, at(1), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:9482"`),
		line(vidRight, "codex-tego", 2, at(1), "refused", `"rule":"fs.deny_read[/d/with/home/.ssh/]","reason":"read-denied","op":"open","target":"/d/with/home/.ssh/id_rsa"`),
		line(vidRight, "codex-tego", 3, at(1), "ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]","hold":"open","op":"read","target":"/d/with/home/.config/telemetry/token"`),
		line(vidRight, "codex-tego", 4, at(4), "answer", `"ask_id":"q-1","approved":false,"by":"uid:1000 pid:42","after_s":3.0,"answer_reason":"ask-denied","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]","op":"read","target":"/d/with/home/.config/telemetry/token"`),
		line(vidRight, "codex-tego", 5, at(4), "refused", `"rule":"fs.ask_read[/d/with/home/.config/telemetry/]","reason":"ask-denied","op":"open","target":"/d/with/home/.config/telemetry/token"`),
		line(vidRight, "codex-tego", 6, at(5), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:9482"`),
		line(vidRight, "codex-tego", 7, at(20), "ask", `"ask_id":"q-2","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/d/with/proj/confidential/plan.md"`),
		line(vidRight, "codex-tego", 8, at(23), "answer", `"ask_id":"q-2","approved":true,"by":"uid:1000 pid:42","after_s":3.0,"ask_rule":"fs.ask_read[./confidential/]","op":"read","target":"/d/with/proj/confidential/plan.md"`),
		line(vidRight, "codex-tego", 9, at(23), "fs", `"rule":"fs.ask_read[./confidential/]","verdict":"allow","op":"open","flags":524288,"path":"/d/with/proj/confidential/plan.md"`))
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{vidLeft, vidRight} {
		if err := os.WriteFile(filepath.Join(root, ".live", r), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// vidBefore reports whether a occurs in page and comes before b.
func vidBefore(page, a, b string) bool {
	i, j := strings.Index(page, a), strings.Index(page, b)
	return i >= 0 && j >= 0 && i < j
}

// TestVideoVerdictUnderHeader: on a live run page the verdict banner sits right under the header, above the Block now
// panel, and only once; with no live block the panel is one folded line whose body holds #block (the header's link
// opens it); a block, or a Block link's prefill, shows the full panel instead.
func TestVerdictUnderHeader(t *testing.T) {
	root := videoFixture(t)
	s := newServer(t, root)
	c := login(t, s)

	right := get(t, s, c, "/runs/"+vidRight)
	if !vidBefore(right, `class="head"`, "verdict-ok") || !vidBefore(right, "verdict-ok", `data-live="r-run-live"`) {
		t.Error("the RIGHT verdict is not between the header and the Block now panel")
	}
	if n := strings.Count(right, "banner verdict"); n != 1 {
		t.Errorf("the RIGHT page shows %d verdict banners, want 1", n)
	}
	panel := blockPanel(t, right)
	mustContain(t, "the folded Block now", panel, `<details class="panel live-panel live-fold" id="block-fold">`,
		"Block now<span class=\"live-fold-c\"", "No live blocks on this run", `<div class="live-fold-b" id="block">`, `action="/runs/`+vidRight+`/block"`)
	if strings.Contains(panel, `<section class="panel live-panel" id="block"`) {
		t.Error("a run with no live block shows the full panel")
	}
	mustContain(t, "the RIGHT header", right, `href="#block"`)

	left := get(t, s, c, "/runs/"+vidLeft)
	if !vidBefore(left, "verdict-leak", `data-live="r-run-live"`) {
		t.Error("the LEFT verdict is not above the Mark now panel")
	}
	mustContain(t, "the folded Mark now", blockPanel(t, left), "Mark now (recorded only)", "No marks on this run", `id="block-fold"`)

	addOverlay(t, root, vidRight, [2]string{"path", "/d/with/home/.config/telemetry"})
	right = get(t, s, c, "/runs/"+vidRight)
	panel = blockPanel(t, right)
	mustContain(t, "the Block now panel with a block", panel, `<section class="panel live-panel" id="block"`, "Remove")
	if strings.Contains(panel, "block-fold") {
		t.Error("a run with a live block shows the folded line")
	}
	if !vidBefore(right, "verdict-ok", `id="block"`) {
		t.Error("the verdict is not above the Block now panel with a block")
	}

	prefill := blockPanel(t, get(t, s, c, "/runs/"+vidLeft+"?block=exec&value=curl"))
	mustContain(t, "a prefilled panel", prefill, `<section class="panel live-panel" id="block"`, `value="curl"`)
}

// TestVideoLiveNowChip: once the run confirms the block "Also apply now" placed, the Saved panel says "Live now on this
// run" as a green chip, the Narrows chip's colour, with the line it came in force at after it; before that it is the
// plain "Putting it in force on this run…" line. Both are the r-act live region's own render, which live.js swaps.
func TestLiveNowChip(t *testing.T) {
	s, c, _, _ := askServer(t)
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	line := "/runs/" + actRun + "/lines/4"
	preview := get(t, s, c, line+"?a=block&level=0")
	w := post(s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"0"}, "base": {baseOf(t, preview)}, "now": {actRun}}, own, "", c)
	saved := w.Header().Get("Location")
	if !strings.Contains(saved, "?saved=") {
		t.Fatalf("confirm went to %q", saved)
	}
	waiting := get(t, s, c, saved)
	mustContain(t, "the saved panel before the run confirms", waiting, "Putting it in force on this run…")
	if strings.Contains(waiting, "ev-live-chip") {
		t.Error("the panel shows the Live now chip before the run confirmed the block")
	}
	n := strings.Count(readFile(t, filepath.Join(s.cfg.Ledger, actRun, "events.jsonl")), "\n")
	appendLine(t, s.cfg.Ledger, actRun, liveGapLine(actRun, n, time.Now(), "exec", "git", 1))
	live := get(t, s, c, saved)
	mustContain(t, "the saved panel once the run confirms", live, `data-state="in_force"`,
		`<span class="b b-narrows ev-live-chip">`, `Live now on this run</span><span class="ev-live-st">in force since line #`+strconv.Itoa(n))
}

// TestVideoActPanelPaths: the Act panel writes the token's folder from the run's home, ~/.config/telemetry/, as the
// headline does (not from the dashboard user's home), keeps the full path in each sentence's title, folds step 1's
// folders far above the asking one behind "…/", and breaks a long path only between its folders.
func TestActPanelPaths(t *testing.T) {
	root := videoFixture(t)
	rr, err := ledgerview.LoadRun(root, vidRight)
	if err != nil {
		t.Fatal(err)
	}
	const dir = "/d/with/home/.config/telemetry"
	p := &rules.ActPlan{Kind: "read", Cwd: "/d/with/proj", Home: "/d", What: dir + "/token",
		Levels:     []string{dir + "/token", dir, "/d/with/home/.config", "/d/with/home", "/d/with", "/d"},
		EntryScope: &rules.Scope{Level: 1}, Action: "block", Direction: "narrows",
		Sentences: []rules.Sentence{{Before: "Asks you before it reads " + dir + "/", After: "Can never read " + dir + "/", Direction: "narrows"}}}
	v := actModel(p, rules.Scope{Level: 1}, rr, &ledgerview.Event{Seq: 5})
	if got := v.Sentences[0]; got.Before != "Asks you before it reads ~/.config/telemetry/" || got.After != "Can never read ~/.config/telemetry/" ||
		got.AfterTitle != "Can never read "+dir+"/" {
		t.Errorf("the sentence reads %+v", got)
	}
	var texts []string
	for _, sv := range v.Scopes {
		if !sv.Wider {
			texts = append(texts, sv.Text)
		}
	}
	if strings.Join(texts, " ") != "~/ .config/ telemetry/ token" || v.Wider != 2 || v.WiderOpen {
		t.Errorf("step 1 shows %q with %d folded (open %v)", texts, v.Wider, v.WiderOpen)
	}
	for _, sv := range v.Scopes {
		if sv.Current && (sv.Says != "Every file under ~/.config/telemetry/ (the folder that asked)" ||
			!strings.HasSuffix(sv.URL, "?level=1&a=block#act-check")) {
			t.Errorf("the picked chip says %q and links %q", sv.Says, sv.URL)
		}
	}
	if w := savedLine(p, vidRight, actShortener(p, rr)); !strings.HasPrefix(w, "Saved: Can never read ~/.config/telemetry/, from the next run") {
		t.Errorf("the Saved notice reads %q", w)
	}

	// A path outside the run's home and project is cut in its folder's middle, the full words in the title.
	sh := shortener{cwd: "/d/with/proj", home: "/d/with/home"}
	long := "Will refuse reads of files under /home/someone/.cache/tego-workdir/video/w/stage/with/ without asking you first"
	if got := sh.brief(long); got != "Will refuse reads of files under /home/…/.cache/tego-workdir/video/w/stage/with/ without asking you first" || sh.title(long) != long {
		t.Errorf("brief(%q) = %q, title %q", long, got, sh.title(long))
	}
	if sh.title("Can never read /d/with/proj/vault/") == "" || sh.title("Can never read ./vault/") != "" {
		t.Error("the title is not the full words exactly when the panel shortened them")
	}

	// Breaks only between folders of a long path, a hyphenated folder whole; a short path and prose untouched.
	var b strings.Builder
	for _, pc := range pathPieces("Can never read /home/u/.cache/tego-workdir/r10b/telemetry/ now") {
		if pc.Br {
			b.WriteString("|")
		}
		if pc.Keep {
			b.WriteString("{" + pc.Text + "}")
		} else {
			b.WriteString(pc.Text)
		}
	}
	if got := b.String(); got != "Can never read /|home/|u/|.cache/|{tego-workdir/}|r10b/|telemetry/ now" {
		t.Errorf("pathPieces = %q", got)
	}
	if ps := pathPieces("Can never read ./vault/: a rule"); len(ps) != 1 || ps[0].Text != "Can never read ./vault/: a rule" {
		t.Errorf("a short path was cut: %+v", ps)
	}
}

// TestVideoLogsFormOneRow: the Logs search is one row (the text search, the query, Search) with the other filters and
// the facets folded under "Filters", open only while one of the folded fields narrows the lines; the plain q search
// is the same field, sent as before, and finds the same lines.
func TestLogsFormOneRow(t *testing.T) {
	s := newServer(t, videoFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/logs?q=token")
	top := page[strings.Index(page, `<div class="frow lq-top">`):]
	top = top[:strings.Index(top, "</div>")]
	mustContain(t, "the one row", top, `name="q" value="token"`, `name="where"`, `type="submit"`)
	mustContain(t, "the fold", page, `<details class="lq-adv"><summary class="lq-adv-s">Filters`, `name="run"`, `name="verdict"`, `data-live="r-logs-facets"`)
	if !vidBefore(page, `<details class="lq-adv">`, `<section class="lq-side"`) || !vidBefore(page, `<section class="lq-side"`, `</div></details>
</form></details>`) {
		t.Error("the facets are not under Filters")
	}
	for _, q := range []string{"/logs?q=token&verdict=refused", "/logs?q=token&run=" + vidRight, "/logs?q=token&sys=hide"} {
		mustContain(t, q, get(t, s, c, q), `<details class="lq-adv" open>`, `<span class="lq-adv-on">on</span>`)
	}
	// What the form sends for a plain search (its empty fields too) finds the lines the top bar's ?q= finds.
	keys := regexp.MustCompile(`<tr role="row" data-k="([^"]+)"`)
	rowsOf := func(p string) string {
		var ks []string
		for _, m := range keys.FindAllStringSubmatch(p, -1) {
			ks = append(ks, m[1])
		}
		return strings.Join(ks, " ")
	}
	form := get(t, s, c, "/logs?q=token&where=&run=&agent=&kind=")
	if a, b := rowsOf(page), rowsOf(form); a != b || strings.Count(a, " ") < 2 {
		t.Errorf("the form's q search finds %q, ?q= finds %q", b, a)
	}
}

// TestVideoProjectPathsReadDotSlash: a file of the run's project reads ./confidential/plan.md, as the contract and the
// Deny notice write it, on the waiting card, under Answered recently and in the run's Highlights; the token stays
// ~/.config/telemetry/token (the run's home). The full path is in each one's title.
func TestProjectPathsReadDotSlash(t *testing.T) {
	root := videoFixture(t)
	const asker = "r-aaaaaaaa-0000000000033-vasker"
	t0 := time.Date(2026, 10, 27, 12, 5, 0, 0, time.UTC)
	if err := os.MkdirAll(filepath.Join(root, asker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, asker, "events.jsonl"), []byte(
		line(asker, "codex-tego", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/d/with/proj"`)+
			line(asker, "codex-tego", 1, t0.Add(time.Second), "ask", `"ask_id":"q-7","ask_rule":"fs.ask_read[/d/with/proj/confidential/]","hold":"open","op":"read","target":"/d/with/proj/confidential/plan.md"`)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", asker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	const plan = `title="/d/with/proj/confidential/plan.md"><span class="sp-d">./<wbr>confidential/</span><wbr><b class="sp-b">plan.md</b>`
	approvals := get(t, s, c, "/approvals")
	card := approvals[strings.Index(approvals, `<section class="ask"`):]
	mustContain(t, "the waiting card", card[:strings.Index(card, "</section>")], `<p class="ask-path">`+`<span class="ut sp" `+plan)
	recent := approvals[strings.Index(approvals, `id="h-recent-ans"`):]
	mustContain(t, "Answered recently", recent, plan, `<span class="sp-d">~/<wbr>.config/<wbr>telemetry/</span>`)
	mustContain(t, "the run's Highlights", get(t, s, c, "/runs/"+vidRight), plan)
}

// TestVideoAskCardAnswersAndBand: Allow once and Deny are the same button, neither the filled default, on the card and
// in the waiting banner; the "Tego asks you" band stands apart from the card in both themes (the dark one was
// nearly the page's colour) and its words clear AA on it.
func TestAskCardAnswersAndBand(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	page := get(t, s, c, "/approvals")
	form := page[strings.Index(page, `<div class="ask-d">`):]
	form = form[:strings.Index(form, "</form>")]
	mustContain(t, "the card's answers", form, `<button class="btn btn-block ask-btn" type="submit" name="decision" value="approve">`,
		`<button class="btn btn-block ask-btn" type="submit" name="decision" value="deny">`)
	if strings.Contains(form, "btn-primary") || strings.Contains(form, "btn-danger") {
		t.Error("one answer is styled as the default")
	}
	banner := get(t, s, c, "/runs")
	mustContain(t, "the banner's answers", banner, `<button class="btn ask-btn" type="submit" name="decision" value="approve">`,
		`<button class="btn ask-btn" type="submit" name="decision" value="deny">`)
	tokens := get(t, s, c, "/static/tokens.css")
	for name, tk := range map[string]map[string]string{
		"light": tokenBlock(t, tokens, ":root {\n"),
		"auto":  tokenBlock(t, tokens, `:root:not([data-theme="light"]) {`),
		"dark":  tokenBlock(t, tokens, `:root[data-theme="dark"] {`),
	} {
		if r := contrast(tk["on-ask-bar"], tk["ask-bar"]); r < 4.5 {
			t.Errorf("%s: the band's words are %.2f:1 on it, under AA", name, r)
		}
		if r := contrast(tk["ask-bar"], tk["surface"]); r < 3 {
			t.Errorf("%s: the band is %.2f:1 against the card, under 3:1", name, r)
		}
	}
}

// TestVideoOverviewFoldsProgramsAndLeakHeadline: one refused curl, tried by the shell at /usr/bin/curl and /bin/curl,
// is one "curl" row in the Overview's list (a detection is one program, by name); and "1 run leaked secrets" wears
// the run page's red verdict style.
func TestOverviewFoldsProgramsAndLeakHeadline(t *testing.T) {
	root := videoFixture(t)
	t0 := time.Date(2026, 10, 27, 12, 1, 0, 0, time.UTC)
	for i, p := range []string{"/usr/bin/rm", "/bin/rm", "/usr/bin/curl", "/bin/curl"} {
		appendLine(t, root, vidRight, line(vidRight, "codex-tego", 10+i, t0.Add(time.Duration(i)*time.Second), "refused",
			`"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"`+p+`"`))
	}
	s := newServer(t, root)
	c := login(t, s)
	ov := get(t, s, c, "/")
	mustContain(t, "the Overview", ov, `<h1 class="verdict verdict-leak ov-verdict">`, "<span>1 run leaked secrets</span>")
	refusals := ov[strings.Index(ov, `id="h-ref"`):]
	if n := strings.Count(refusals, ">curl<"); n != 1 || strings.Contains(refusals, `<b class="sp-b">curl</b>`) {
		t.Errorf("curl is listed %d times by name, or as a path", n)
	}
}

// TestVideoLiveChainAndAnswerChip: a live run's header says its chain is checked when the run ends (calm, grey),
// never "Chain not checked"; and in a `token` search the answer line "Denied by … after 3 s" carries the Denied chip
// "Around it" gives it, not a grey Recorded.
func TestLiveChainAndAnswerChip(t *testing.T) {
	s := newServer(t, videoFixture(t))
	c := login(t, s)
	right := get(t, s, c, "/runs/"+vidRight)
	head := right[strings.Index(right, `<div class="sub-h1">`):]
	head = head[:strings.Index(head, "</div>")]
	mustContain(t, "the live run's header", head, `<span class="b b-neutral" title="Checked when the run ends"`, "Verify at end")
	if strings.Contains(head, "Not verified") {
		t.Errorf("the live run's header reads as a warning: %s", head)
	}
	logs := get(t, s, c, "/logs?q=token")
	i := strings.Index(logs, `data-k="`+vidRight+`-4"`)
	if i < 0 {
		t.Fatal("no answer row in the token search")
	}
	row := logs[strings.LastIndex(logs[:i], "<tr"):]
	row = row[:strings.Index(row, "</tr>")]
	mustContain(t, "the answer row", row, `class="lq-r v-refused`, `<span class="b b-refused" title="A person's answer to the ask before it">`, "Denied</span>", "Denied by")
	if strings.Contains(row, "Recorded") {
		t.Errorf("the answer row says Recorded: %s", row)
	}
}

// TestVideoBriefAndRest: brief cuts a path inside a rule key at its "]", and a chip's rest never starts with the
// joining comma or colon.
func TestBriefAndRest(t *testing.T) {
	sh := shortener{cwd: "/p", home: "/h"}
	in := "asked by fs.ask_read[/home/someone/.cache/tego-workdir/video/w/stage/with/home/.config/telemetry/]"
	if got := sh.brief(in); got != "asked by fs.ask_read[/home/…/w/stage/with/home/.config/telemetry/]" {
		t.Errorf("brief(%q) = %q", in, got)
	}
	for after, want := range map[string]string{", in force since line #4": "in force since line #4", ": changes are refused": "changes are refused"} {
		if got := (liveOut{After: after}).Rest(); got != want {
			t.Errorf("Rest of %q = %q, want %q", after, got, want)
		}
	}
}

// TestVideoLogsProjectPaths: a Logs row of a file of the run's project reads ./confidential/plan.md, one line, as its
// Rule cell and the contract write it; the full path stays in the title, and the plain q search still finds it by
// any part of the path as written in the ledger.
func TestLogsProjectPaths(t *testing.T) {
	s := newServer(t, videoFixture(t))
	c := login(t, s)
	for _, q := range []string{"plan.md", "/d/with/proj/confidential"} {
		page := get(t, s, c, "/logs?q="+url.QueryEscape(q))
		mustContain(t, "the plan's row for "+q, page, `<span class="ut pw" title="/d/with/proj/confidential/plan.md"><span class="sp-d">./<wbr>confidential/</span><wbr><b class="sp-b">plan.md</b>`)
	}
}
