// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/csv"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const csvWordsRun = "r-aaaaaaaa-0000000000007-wordsx"

// csvWordsLines is one ended run with a line of every kind Logs lists: each is read by the page and by the CSV.
func csvWordsLines() []string {
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	return []string{
		line(csvWordsRun, "codex", 0, at(0), "run_start", `"tier":"landlock","command":["codex","exec"],"cwd":"/w/x/proj"`),
		line(csvWordsRun, "codex", 1, at(1), "exec", `"verdict":"allow","rule":"exec.allow[rm]","path":"/bin/rm","argv":["rm","-rf","/tmp/dir"]`),
		line(csvWordsRun, "codex", 2, at(2), "fs", `"verdict":"allow","rule":"fs.write[/w/x/proj]","op":"open","path":"/w/x/proj/out.txt","flags":577`),
		line(csvWordsRun, "codex", 3, at(3), "fs", `"verdict":"observed","rule":"fs.read[/w/x]","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`),
		line(csvWordsRun, "codex", 4, at(4), "net", `"verdict":"allow","rule":"net.allow[pypi.org]","proto":"tcp","dst":"151.101.0.223:443","host":"pypi.org"`),
		line(csvWordsRun, "codex", 5, at(5), "refused", `"rule":"net.ask[x]","reason":"ask-denied","op":"first_write","target":"203.0.113.9:443"`),
		line(csvWordsRun, "codex", 6, at(6), "fs", `"verdict":"refused","rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`),
		line(csvWordsRun, "codex", 7, at(7), "ask", `"ask_id":"q-1","ask_rule":"fs.ask_write[/w/x]","hold":"open","op":"write","target":"/w/x/a.txt"`),
		line(csvWordsRun, "codex", 8, at(8), "answer", `"ask_id":"q-1","approved":true,"by":"uid:1000 pid:9"`),
		line(csvWordsRun, "codex", 9, at(9), "ask", `"ask_id":"q-2","ask_rule":"fs.ask_write[/w/x]","hold":"open","op":"write","target":"/w/x/b.txt"`),
		line(csvWordsRun, "codex", 10, at(10), "answer", `"ask_id":"q-2","approved":false,"by":"uid:1000 pid:9"`),
		line(csvWordsRun, "codex", 11, at(11), "ask", `"ask_id":"q-3","ask_rule":"fs.ask_write[/w/x]","hold":"open","op":"write","target":"/w/x/c.txt"`),
		line(csvWordsRun, "codex", 12, at(12), "answer", `"ask_id":"q-3","approved":false,"by":"tego","reason":"ask-timeout"`),
		line(csvWordsRun, "codex", 13, at(13), "gap", `"what":"capture","why":"ring-overflow"`),
		line(csvWordsRun, "codex", 14, at(14), "limit", `"verdict":"refused","reason":"limit-tokens","which":"tokens","value":120,"ceiling":100`),
		line(csvWordsRun, "codex", 15, at(15), "mcp", `"verdict":"allow","name":"files","tool":"read"`),
		line(csvWordsRun, "codex", 16, at(16), "decision", `"tool":"shell","name":"ls"`),
		line(csvWordsRun, "codex", 17, at(17), "run_end", `"reason":"exit","exit_code":0`),
	}
}

var (
	wordsRow   = regexp.MustCompile(`(?s)<tr role="row" data-k="([^"]+)"[^>]*class="lq-r.*?</tr>`)
	wordsChip  = regexp.MustCompile(`(?s)class="c-verdict">.*?<span class="b b-[a-z-]+"[^>]*>(.*?)</span>`)
	wordsOp    = regexp.MustCompile(`(?s)<span class="op"[^>]*>(.*?)</span>`)
	wordsWhy   = regexp.MustCompile(`(?s)<div class="lw-why"[^>]*>(.*?)</div>`)
	wordsTags  = regexp.MustCompile(`(?s)<[^>]*>`)
	wordsBlank = regexp.MustCompile(`\s+`)
)

func plainWords(s string) string {
	return strings.TrimSpace(wordsBlank.ReplaceAllString(html.UnescapeString(wordsTags.ReplaceAllString(s, " ")), " "))
}

// TestCSVAndPageSayTheSameWords (C86): for every kind of line, the CSV's Verdict, Action and Why are the page row's
// verdict chip, action and reason: both come from one set of line words (lineWordsOf).
func TestCSVAndPageSayTheSameWords(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, csvWordsRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, csvWordsRun, "events.jsonl"), []byte(strings.Join(csvWordsLines(), "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	page := do(s, "GET", "/logs?noise=show", "127.0.0.1:8484", c).Body.String()
	recs, err := csv.NewReader(strings.NewReader(do(s, "GET", "/logs.csv", "127.0.0.1:8484", c).Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	type words struct{ verdict, action, why string }
	onPage := map[string]words{}
	for _, m := range wordsRow.FindAllStringSubmatch(page, -1) {
		w := words{}
		if x := wordsChip.FindStringSubmatch(m[0]); x != nil {
			w.verdict = plainWords(x[1])
		}
		if x := wordsOp.FindStringSubmatch(m[0]); x != nil {
			w.action = plainWords(x[1])
		}
		if x := wordsWhy.FindStringSubmatch(m[0]); x != nil {
			w.why = plainWords(x[1])
		}
		onPage[m[1]] = w
	}
	kinds := map[string]bool{}
	for _, r := range recs[1:] {
		key := r[1] + "-" + r[3]
		p, ok := onPage[key]
		if !ok {
			t.Errorf("line %s (%s) is in the CSV and not on the page", key, r[4])
			continue
		}
		kinds[r[4]] = true
		if got := (words{r[5], r[6], r[10]}); got != p {
			t.Errorf("line %s (%s): the CSV says %+v, the page %+v", key, r[4], got, p)
		}
	}
	if len(kinds) < 10 || len(onPage) != len(recs)-1 {
		t.Errorf("the test covers %d kinds and %d page rows for %d CSV rows", len(kinds), len(onPage), len(recs)-1)
	}
}
