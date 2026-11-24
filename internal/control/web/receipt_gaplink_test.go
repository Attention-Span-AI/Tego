// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	receiptspec "github.com/attention-span-ai/tego/pkg/spec/receipt"
)

// TestCaptureNoteLinksToTheCaptureGaps: the Receipt tab's "Token counts may be low" note opens Logs at the gap lines that
// say model traffic could not be read, not at every gap line of the run (the run's other notes about its record buried
// them). The note about missed actions keeps its link to all of them.
func TestCaptureNoteLinksToTheCaptureGaps(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000072-capgap"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	finishRun(t, root, run,
		line(run, "py", 0, t0, "run_start", `"tier":"landlock","capture":"uprobe","command":["agent"]`),
		line(run, "py", 1, t0.Add(time.Second), "gap", `"what":"capture","why":"no-openssl","binary":"/usr/bin/curl","count":1`),
		line(run, "py", 2, t0.Add(2*time.Second), "gap", `"what":"record","why":"channel-full","count":3`),
		line(run, "py", 3, t0.Add(3*time.Second), "gap", `"what":"capture","why":"no-openssl","binary":"/usr/bin/gh","count":1`),
		line(run, "py", 4, t0.Add(4*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	c := login(t, s)
	page := getRaw(t, s, c, "/runs/"+run+"/receipt")
	tags := regexp.MustCompile(`<[^>]*>`)
	hrefs := map[string]string{}
	for _, m := range regexp.MustCompile(`(?s)<a class="link" href="(/logs\?[^"]*kind=gap[^"]*)"[^>]*>(.*?)</a>`).FindAllStringSubmatch(page, -1) {
		hrefs[strings.TrimSpace(html.UnescapeString(tags.ReplaceAllString(m[2], "")))] = html.UnescapeString(m[1])
	}
	var capture, record string
	for words, href := range hrefs {
		switch {
		case strings.Contains(words, "Token counts may be low"):
			capture = href
		case strings.Contains(words, "in the record"):
			record = href
		}
	}
	if capture == "" || record == "" {
		t.Fatalf("the coverage notes carry no links (%v):\n%s", hrefs, page)
	}
	logs := func(href string) string {
		u, err := url.Parse(href)
		if err != nil {
			t.Fatal(err)
		}
		return get(t, s, c, u.RequestURI())
	}
	got := logs(capture)
	if !strings.Contains(got, "Not captured: no openssl") || strings.Contains(got, "A gap in the record") {
		t.Errorf("the capture note's link %q lists the wrong gaps:\n%s", capture, got)
	}
	if all := logs(record); !strings.Contains(all, "Not captured: no openssl") || !strings.Contains(all, "A gap in the record") {
		t.Errorf("the record note's link %q no longer lists every gap line", record)
	}
}

// TestReceiptTabSaysTheReceiptsWords: the Receipt tab's coverage list says, for the gaps the record links to, the sentence
// `tego receipt` and `tego status` say (gaps.MissedWords, gaps.CaptureWords) with its first letter capitalised, and gives
// every gap its level as a chip with the level's sentence as its title (C175, C165). The page has no wording of its own for
// them.
func TestReceiptTabSaysTheReceiptsWords(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000077-vocab1"
	t0 := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	root := t.TempDir()
	finishRun(t, root, run,
		line(run, "py", 0, t0, "run_start", `"tier":"landlock","capture":"uprobe","command":["agent"]`),
		line(run, "py", 1, t0.Add(time.Second), "gap", `"what":"capture","why":"no-openssl","binary":"/usr/bin/curl","count":1`),
		line(run, "py", 2, t0.Add(2*time.Second), "gap", `"what":"record","why":"channel-full","count":3`),
		line(run, "py", 3, t0.Add(3*time.Second), "gap", `"what":"capture","why":"no-openssl","binary":"/usr/bin/gh","count":1`),
		line(run, "py", 4, t0.Add(4*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	c := login(t, s)
	page := html.UnescapeString(getRaw(t, s, c, "/runs/"+run+"/receipt"))
	for _, want := range []string{
		upperFirst(gaps.CaptureWords(2)), upperFirst(gaps.MissedWords(1, 3)),
		`<span class="b b-neutral rc-lvl" data-number-exclude-text="run.coverage-level" title="` + receiptspec.LevelWords(receiptspec.LevelPartial) + `">partial</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the Receipt tab lacks %q:\n%s", want, page)
		}
	}
	for _, old := range []string{"tego knows it missed some actions", "so the token counts are a floor", "Token counts may be low (2 capture gaps) ("} {
		if strings.Contains(page, old) {
			t.Errorf("the Receipt tab still has the old words %q", old)
		}
	}
}
