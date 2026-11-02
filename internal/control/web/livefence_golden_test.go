// SPDX-License-Identifier: Apache-2.0

package web

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// updateLocked rewrites the Locked goldens: run once on the base (before ADR 0125's dashboard), so they hold the pages
// as they were.
var updateLocked = flag.Bool("update-locked", false, "rewrite testdata/locked-*.golden")

var (
	csrfValue = regexp.MustCompile(`name="csrf" value="[0-9a-f]+"`)
	// The live regions' hashes and the page's revision change with any byte of the page. A path's text, shortened at
	// its start ("…/proj/agent.yaml") or in its middle ("/<wbr>home/<wbr>…") or not at all ("/TMPB/proj/agent.yaml"
	// once lockedPage put the folder's place-holder in), depends on how long the temporary folder's name is, so each
	// becomes one token.
	regionHash  = regexp.MustCompile(`data-(h|rev|k)="[0-9a-z]+"`)
	lockedShort = regexp.MustCompile(`(?:/<wbr>[^<"…/]*)*(?:…|/TMP[A-Z])[^<"]*(?:<wbr>[^<"]*)*`)
	lockedTemp  = regexp.MustCompile(`TestLockedPagesUnchanged\d+`)
	// A folder name with a hyphen in it ("tego-workdir/", the temporary folder's own parts when TMPDIR has one) is
	// wrapped in <span class="nb">, which would stop lockedShort mid-path; the span is taken off a path part (one
	// with a slash), never off other text such as a question's id.
	lockedNB = regexp.MustCompile(`<span class="nb">([^<"]*/[^<"]*)</span>`)
	// The two pieces ADR 0125 adds to a Locked run's pages: the run page's time limit on Block now, and the Rules
	// page's Mode line. Each is one element with no element of its own kind inside.
	lockedAdds = []*regexp.Regexp{
		regexp.MustCompile(`(?s)<div class="lfor">.*?</div>`),
		regexp.MustCompile(`(?s)<section class="lmode"[^>]*>.*?</section>`),
	}
)

// lockedPage is page with what varies between test runs made constant (the session's form token, the temporary
// folders) and, with strip, ADR 0125's additions taken out.
func lockedPage(page string, strip bool, paths ...string) string {
	page = csrfValue.ReplaceAllString(page, `name="csrf" value="CSRF"`)
	page = lockedNB.ReplaceAllString(page, "$1")
	for i, p := range paths {
		page = wbrPath(p).ReplaceAllLiteralString(page, "/TMP"+string(rune('A'+i)))
	}
	page = regionHash.ReplaceAllString(page, `data-$1="H"`)
	page = lockedShort.ReplaceAllString(page, "…PATH")
	page = lockedTemp.ReplaceAllString(page, "TestT")
	if strip {
		for _, re := range lockedAdds {
			page = re.ReplaceAllString(page, "")
		}
	}
	return page
}

// wbrPath matches p as the pages print it: plain, or broken up with <wbr> tags wherever the page chose to (a contract
// path in Run details, a file's folder in the timeline). Matching only the plain spelling would leave the temporary
// folder's real name in the golden, and the test would hold only in the checkout that wrote it. A folder name with a
// hyphen in it is also wrapped in <span class="nb"> so it does not break there, so those tags may sit between any two
// characters too.
func wbrPath(p string) *regexp.Regexp {
	var b strings.Builder
	for i, r := range p {
		if i > 0 {
			b.WriteString(`(?:<wbr>|<span class="nb">|</span>)*`)
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	return regexp.MustCompile(b.String())
}

// localUTC makes the pages print clock times in UTC for the rest of the test: they print the local zone, and
// t.Setenv("TZ") alone does not change it, since time.Local is read once.
func localUTC(t *testing.T) {
	t.Helper()
	was := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = was })
}

// machineNames gives the pages a fixed machine name and a fixed login name for uid 1000 (the fixture's answerer): they
// print this computer's, which differ on every machine.
func machineNames(t *testing.T, s *Server) {
	t.Helper()
	s.host = "box"
	userMu.Lock()
	was, had := userNames["1000"]
	userNames["1000"] = "someone"
	userMu.Unlock()
	t.Cleanup(func() {
		userMu.Lock()
		defer userMu.Unlock()
		if had {
			userNames["1000"] = was
		} else {
			delete(userNames, "1000")
		}
	})
}

// checkLocked compares page, with ADR 0125's additions stripped, with the golden file name.
func checkLocked(t *testing.T, name, page string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateLocked {
		if err := os.WriteFile(path, []byte(page), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if page != string(want) {
		a, b := page, string(want)
		i := 0
		for i < len(a) && i < len(b) && a[i] == b[i] {
			i++
		}
		lo := max(0, i-200)
		t.Fatalf("%s differs from the Locked page before ADR 0125 at byte %d:\n got: %q\nwant: %q", name, i,
			a[lo:min(len(a), i+200)], b[lo:min(len(b), i+200)])
	}
}

// TestLockedPagesUnchanged: a Locked run's run page is the page it was before ADR 0125 except for the Block now
// form's time limit, and its Rules page is the page it was plus the Mode line (ADR 0125 "What stays the same in
// Locked").
func TestLockedPagesUnchanged(t *testing.T) {
	localUTC(t)
	s, c, contract, proj := askServer(t)
	machineNames(t, s)
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	// The file was written before the run started, so the page names no edit made after it (and no clock time).
	before := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	if err := os.Chtimes(contract, before, before); err != nil {
		t.Fatal(err)
	}
	paths := []string{s.cfg.Ledger, filepath.Dir(proj), proj, contract, rules.Ref(contract)}
	run := do(s, "GET", "/runs/"+actRun, "127.0.0.1:8484", c)
	if run.Code != 200 {
		t.Fatalf("run page: %d", run.Code)
	}
	rp := lockedPage(run.Body.String(), false, paths...)
	if !*updateLocked {
		for _, want := range []string{`<div class="lfor">`, `name="for"`, `>for the rest of this run</option>`, `name="until"`} {
			if !strings.Contains(rp, want) {
				t.Errorf("the run page's Block now form lacks %q", want)
			}
		}
		if strings.Contains(rp, "Adjustable") {
			t.Error("a Locked run's page names Adjustable")
		}
	}
	checkLocked(t, "locked-run.golden", lockedPage(rp, true))
	rules := do(s, "GET", "/rules?run="+actRun, "127.0.0.1:8484", c)
	if rules.Code != 200 {
		t.Fatalf("rules page: %d", rules.Code)
	}
	rl := lockedPage(rules.Body.String(), false, paths...)
	if !*updateLocked {
		for _, want := range []string{`<section class="lmode"`, ">Locked</span>", "Compare modes", "Adjustable (live both ways)"} {
			if !strings.Contains(rl, want) {
				t.Errorf("the Rules page lacks %q", want)
			}
		}
		if strings.Contains(rl, `id="live-fence"`) {
			t.Error("a Locked run's Rules page has a fence panel")
		}
	}
	checkLocked(t, "locked-rules.golden", lockedPage(rl, true))
}

// TestLockedPageMasksHyphenatedTemp: a temporary folder whose name has a hyphen (TMPDIR=/home/u/.cache/gt-rb, an
// agent's /tmp/claude-1000/-home-...) is printed with its hyphenated parts in <span class="nb">; lockedPage still
// makes the shortened path one token, and leaves a hyphenated id outside a path as it is.
func TestLockedPageMasksHyphenatedTemp(t *testing.T) {
	page := `<span class="sp-d">…/<wbr><span class="nb">tego-workdir/</span><wbr>gf/<wbr><span class="nb">t-x/</span>` +
		`<wbr>TestLockedPagesUnchanged12/<wbr>002/<wbr>proj/</span><wbr><b class="sp-b">token</b>` +
		`<span class="nb">q-0123</span>`
	want := `<span class="sp-d">…PATH</span><wbr><b class="sp-b">token</b><span class="nb">q-0123</span>`
	if got := lockedPage(page, false); got != want {
		t.Errorf("lockedPage\n got: %s\nwant: %s", got, want)
	}
}
