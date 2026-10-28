// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	nethtml "golang.org/x/net/html"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

const (
	factsRun = "r-aaaaaaaa-0000000000010-factsx"
	// factsBearer is a credential in an inline argv: no page may show it outside a fold.
	factsBearer = "abcdef123456"
	factsAsk    = "q-0123456789abcdef0123456789abcdef"
)

// factsArgv is a command the writer moved to a blob.
var factsArgv = []string{"python3", "-c", "print('stored apart')", strings.Repeat("x", 300)}

// factsLines writes run as chained lines (each prev the line before's id) under root, with the pids given, and
// returns the lines as written.
func factsLines(t *testing.T, root, run string, t0 time.Time, rows [][3]string) []string {
	t.Helper()
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out []string
	prev := ""
	for i, r := range rows {
		id := fmt.Sprintf("%064x", 0xf000+i)
		l := fmt.Sprintf(`{"v":1,"seq":%d,"id":"%s","prev":"%s","ts":"%s","mono_ns":%d,"run":"%s","agent":"codex","pid":%s,"tid":%s,"cgroup":7,"kind":"%s","source":"seccomp"`,
			i, id, prev, t0.Add(time.Duration(i)*1250*time.Millisecond).UTC().Format(time.RFC3339Nano), i+1, run, r[0], r[0], r[1])
		if r[2] != "" {
			l += "," + r[2]
		}
		out = append(out, l+"}")
		prev = id
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// factsFixture is one ended run with a process chain (launcher → codex → bash → curl), an exec with a bearer token
// inline, a refused read of an ssh key, an ask with its answer and the refusal it led to, a live-block gap, an exec
// whose argv is in a blob, and its end. It returns the root and the blob's sha.
func factsFixture(t *testing.T) (root, sha string) {
	t.Helper()
	root = t.TempDir()
	b, err := json.Marshal(factsArgv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	sha = hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(root, factsRun, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, factsRun, "blobs", sha), b, 0o644); err != nil {
		t.Fatal(err)
	}
	R := factsRun
	exec := func(pid, start, parent, path, argv string) string {
		return `"verdict":"allow","authority":"rule","rule":"exec[` + filepath.Base(path) + `]","exec_id":"` + R + `/` + pid + `/` + start +
			`","parent_exec_id":"` + parent + `","path":"` + path + `",` + argv
	}
	factsLines(t, root, R, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), [][3]string{
		{"100", "run_start", `"tier":"landlock","command":["codex","exec","fix it"],"cwd":"/home/u/proj","launcher_pid":100,"launcher_start_ns":5`},
		{"200", "exec", exec("200", "6", R+"/100/5", "/usr/bin/codex", `"argv":["codex","exec"]`)},
		{"300", "exec", exec("300", "7", R+"/200/6", "/bin/bash", `"argv":["bash","-c","curl it"]`)},
		{"400", "exec", exec("400", "8", R+"/300/7", "/usr/bin/curl", `"argv":["curl","-H","Authorization: Bearer `+factsBearer+`","http://127.0.0.1:4880"]`)},
		{"400", "fs", `"verdict":"refused","authority":"rule","rule":"fs.deny_read[~/.ssh/]","reason":"read-denied","op":"open","path":"/home/u/.ssh/id_ed25519","errno":13`},
		{"400", "ask", `"verdict":"ask","ask_id":"` + factsAsk + `","ask_rule":"fs.ask_read[./c/]","hold":"open","op":"read","target":"/home/u/proj/c/plan.md"`},
		{"400", "answer", `"ask_id":"` + factsAsk + `","approved":false,"by":"uid:1000 pid:9 dashboard","after_s":2.5,"answer_reason":"ask-denied","op":"read","target":"/home/u/proj/c/plan.md"`},
		{"400", "fs", `"verdict":"refused","authority":"human","rule":"fs.ask_read[./c/]","reason":"ask-denied","op":"open","path":"/home/u/proj/c/plan.md","errno":13`},
		{"100", "gap", `"what":"live","why":"live-block-added"`},
		{"500", "exec", exec("500", "9", R+"/300/7", "/usr/bin/python3", `"argv_blob":"`+sha+`","argv_truncated":true`)},
		{"100", "run_end", `"reason":"exit","exit_code":0`},
	})
	return root, sha
}

// folds are the page's closed folds (the raw line and a masked field's "show"), the only places exact bytes may be.
var folds = regexp.MustCompile(`(?s)<details[^>]*>.*?</details>`)

// TestLinePageEveryField: on an exec line, a refused read, an ask, an answer, a live-block gap, run_start and run_end
// the page names every field of the line by its label; the exec line names its process chain with links to each
// program's exec line; the refused read names the error in words; the ask and answer carry the question card.
func TestLinePageEveryField(t *testing.T) {
	root, _ := factsFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	r, err := ledgerview.LoadRun(root, factsRun)
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{3, 4, 5, 6, 8, 0, 10} {
		p := "/runs/" + factsRun + "/lines/" + strconv.FormatUint(seq, 10)
		w := do(s, "GET", p, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
		page := w.Body.String()
		lv, err := ledgerview.Explain(root, r, seq)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range lv.Fields {
			if !strings.Contains(page, html.EscapeString(f.Label)) {
				t.Errorf("line %d: the page lacks the label %q of %s", seq, f.Label, f.Key)
			}
		}
		for _, want := range []string{"Every field", "Integrity", "Line #" + strconv.FormatUint(seq, 10) + " of 11", "Show exactly as written"} {
			if !strings.Contains(page, want) {
				t.Errorf("line %d lacks %q", seq, want)
			}
		}
		if seq > 0 && !strings.Contains(page, "its hash matches") {
			t.Errorf("line %d: the chained prev is not said to match", seq)
		}
		if n := strings.Count(page, `id="ev-rawline"`); n != 1 {
			t.Errorf("line %d: %d raw blocks, want one", seq, n)
		}
		if strings.Contains(page, "<textarea") {
			t.Errorf("line %d still has the second raw copy", seq)
		}
		hidden := map[uint64]bool{0: true, 10: true, 8: true, 6: true}[seq]
		if got := strings.Contains(page, `id="act"`); got == hidden {
			t.Errorf("line %d: Act panel shown %v, want %v", seq, got, !hidden)
		}
	}
	exec3 := get(t, s, c, "/runs/"+factsRun+"/lines/3")
	for _, want := range []string{
		`href="/runs/` + factsRun + `/lines/1"`, ">codex</a>", ">bash</a>", "tego launcher", "pid 400 · tid 400 · cgroup 7",
		"/logs?q=run%3a" + factsRun + "%20pid%3a400", "1250 ms after", "3.8 s into the run",
	} {
		if !strings.Contains(exec3, want) {
			t.Errorf("the exec line lacks %q", want)
		}
	}
	refused := get(t, s, c, "/runs/"+factsRun+"/lines/4")
	for _, want := range []string{"What the agent got", "EACCES", "Already blocked by: <strong>"} {
		if !strings.Contains(refused, want) {
			t.Errorf("the refused read lacks %q", want)
		}
	}
	ask := get(t, s, c, "/runs/"+factsRun+"/lines/5")
	for _, want := range []string{"The question", "Denied", "after 2.5 s", `href="/runs/` + factsRun + `/lines/6"`, `href="/runs/` + factsRun + `/lines/7"`} {
		if !strings.Contains(ask, want) {
			t.Errorf("the ask line lacks %q", want)
		}
	}
}

// TestLinePageMasksTheBearer: a bearer token in an argv shows as •••• everywhere outside the folds, on its own line
// page and on every page that lists it around them.
func TestLinePageMasksTheBearer(t *testing.T) {
	root, _ := factsFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for seq := range 9 {
		page := get(t, s, c, "/runs/"+factsRun+"/lines/"+strconv.Itoa(seq))
		if strings.Contains(folds.ReplaceAllString(page, ""), factsBearer) {
			t.Errorf("line %d shows the bearer token outside a fold", seq)
		}
	}
	page := get(t, s, c, "/runs/"+factsRun+"/lines/3")
	if !strings.Contains(folds.ReplaceAllString(page, ""), "Bearer ••••") {
		t.Error("the exec line does not show the masked bearer")
	}
	if !strings.Contains(page, factsBearer) {
		t.Error("the folds do not hold the exact bytes")
	}
}

// TestLinePageCLIHint: line #0's terminal twin prints line 1, the "seq":0 line, byte for byte.
func TestLinePageCLIHint(t *testing.T) {
	root, _ := factsFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	page := html.UnescapeString(get(t, s, c, "/runs/"+factsRun+"/lines/0"))
	hint := "tego events " + factsRun + " --json | sed -n '1p'"
	if !strings.Contains(page, hint) {
		t.Fatalf("the page lacks %q", hint)
	}
	events := filepath.Join(root, factsRun, "events.jsonl")
	out, err := exec.Command("sh", "-c", strings.Replace(hint, "tego events "+factsRun+" --json", "cat '"+events+"'", 1)).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"seq":0,`) || strings.Count(string(out), "\n") != 1 {
		t.Errorf("the hint prints %q", out)
	}
}

// TestLinePageBlobRoute: the blob a line names downloads as an attachment, exact; a sha the line does not name is
// 404 and a value that is not a sha is 400; a blob changed after it was written is not served.
func TestLinePageBlobRoute(t *testing.T) {
	root, sha := factsFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	line := "/runs/" + factsRun + "/lines/9"
	page := get(t, s, c, line)
	if !strings.Contains(page, `href="`+line+`?blob=`+sha+`"`) || !strings.Contains(page, "verified") || !strings.Contains(page, "stored apart") {
		t.Error("the blob field offers no download, or does not say it is verified")
	}
	w := do(s, "GET", line+"?blob="+sha, "127.0.0.1:8484", c)
	want, _ := json.Marshal(factsArgv)
	if w.Code != http.StatusOK || w.Body.String() != string(want) {
		t.Fatalf("download: %d %q", w.Code, w.Body.String())
	}
	h := w.Header()
	if h.Get("Content-Type") != "application/octet-stream" || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(h.Get("Content-Disposition"), "attachment; filename=") {
		t.Errorf("download headers: %v", h)
	}
	other := strings.Repeat("ab", 32)
	for _, c2 := range []struct {
		path string
		code int
	}{
		{line + "?blob=" + other, http.StatusNotFound},
		{"/runs/" + factsRun + "/lines/3?blob=" + sha, http.StatusNotFound}, // a line that does not name it
		{line + "?blob=XYZ", http.StatusBadRequest},
		{line + "?blob=" + strings.ToUpper(sha), http.StatusBadRequest},
		{line + "?blob=../../events.jsonl", http.StatusBadRequest},
	} {
		if w := do(s, "GET", c2.path, "127.0.0.1:8484", c); w.Code != c2.code {
			t.Errorf("%s: %d, want %d", c2.path, w.Code, c2.code)
		}
	}
	if err := os.WriteFile(filepath.Join(root, factsRun, "blobs", sha), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := do(s, "GET", line+"?blob="+sha, "127.0.0.1:8484", c); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "changed") {
		t.Errorf("a changed blob: %d", w.Code)
	}
}

// TestLinePageA11y: the line pages keep the landmarks and labels checkPage checks, their headings never skip a level,
// and every fold opens from the keyboard (a <details> whose first child is its <summary>).
func TestLinePageA11y(t *testing.T) {
	root, _ := factsFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, seq := range []string{"0", "3", "4", "5", "9"} {
		p := "/runs/" + factsRun + "/lines/" + seq
		body := get(t, s, c, p)
		checkPage(t, p, body)
		doc := parseHTML(t, p, body)
		last := 0
		walk(doc, func(n *nethtml.Node) {
			if n.Type != nethtml.ElementNode {
				return
			}
			if len(n.Data) == 2 && n.Data[0] == 'h' && n.Data[1] >= '1' && n.Data[1] <= '6' {
				lvl := int(n.Data[1] - '0')
				if lvl > last+1 {
					t.Errorf("%s: <%s> follows <h%d>", p, n.Data, last)
				}
				last = lvl
			}
			if n.Data == "details" {
				first := n.FirstChild
				for first != nil && first.Type != nethtml.ElementNode {
					first = first.NextSibling
				}
				if first == nil || first.Data != "summary" {
					t.Errorf("%s: a <details> does not start with its <summary>", p)
				}
			}
		})
	}
}

// TestLinePageRenderBudget renders a line page of a 12,000-line run, warm, against its 25 ms budget.
func TestLinePageRenderBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	root := t.TempDir()
	rows := [][3]string{{"100", "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p","launcher_pid":100,"launcher_start_ns":5`},
		{"200", "exec", `"verdict":"allow","authority":"rule","rule":"exec[sh]","exec_id":"` + factsRun + `/200/6","parent_exec_id":"` + factsRun + `/100/5","path":"/bin/sh","argv":["sh"]`}}
	for i := range 12000 {
		rows = append(rows, [3]string{"200", "fs", `"verdict":"allow","authority":"rule","rule":"unmatched","op":"open","path":"/p/f` + strconv.Itoa(i%300) + `.txt"`})
	}
	factsLines(t, root, factsRun, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), rows)
	s := newServer(t, root)
	c := login(t, s)
	p := "/runs/" + factsRun + "/lines/6000"
	if w := do(s, "GET", p, "127.0.0.1:8484", c); w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	best := time.Hour
	for range 5 {
		a := time.Now()
		do(s, "GET", p, "127.0.0.1:8484", c)
		best = min(best, time.Since(a))
	}
	t.Logf("warm line page of a 12k-line run: %v", best)
	if best > 25*time.Millisecond {
		t.Errorf("warm %v, budget 25 ms", best)
	}
}

// TestLinePageGuardLeads: on a read the contract's deny_read refuses, the Act panel leads with the rule that refuses
// it and folds the options, which all widen, under "Change this rule"; picking one opens the fold on its preview.
// A line whose contract file is gone says so in words.
func TestLinePageGuardLeads(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(filepath.Join(proj, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: g\ncommand:\n  - sh\nfs:\n  deny_read:\n    - ./keys/\nexec:\n  allow:\n    - sh\ntier: landlock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	factsLines(t, root, factsRun, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), [][3]string{
		{"100", "run_start", `"tier":"landlock","command":["sh"],"cwd":"` + proj + `","contract_hash":"` + strings.Repeat("0", 64) + `","contract_source":{"path":"` + contract + `"}`},
		{"100", "fs", `"verdict":"refused","authority":"rule","rule":"fs.deny_read[./keys/]","reason":"read-denied","op":"open","path":"` + proj + `/keys/k","errno":13`},
		{"100", "run_end", `"reason":"exit","exit_code":0`},
	})
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	c := login(t, s)
	line := "/runs/" + factsRun + "/lines/1"
	page := get(t, s, c, line)
	panel := page[strings.Index(page, `id="act"`):strings.Index(page, `</aside>`)]
	lead, fold := strings.Index(panel, "Already blocked by:"), strings.Index(panel, `<details class="ev-change">`)
	if lead < 0 || fold < 0 || lead > fold || !strings.Contains(panel, "Change this rule") || !strings.Contains(panel, "b b-widens") {
		t.Fatalf("the panel does not lead with the rule and fold the options:\n%s", panel)
	}
	if strings.Contains(panel, "btn-primary") {
		t.Error("a widening option is the panel's primary button")
	}
	picked := get(t, s, c, line+"?a=allow&level=0")
	if !strings.Contains(picked, `<details class="ev-change" open>`) {
		t.Error("a picked option does not open the fold")
	}
	if err := os.Remove(contract); err != nil {
		t.Fatal(err)
	}
	gone := get(t, s, c, line)
	if strings.Contains(gone, "no such file or directory") || strings.Contains(gone, "lstat") || !strings.Contains(gone, "the contract file has moved since this run") {
		t.Error("a moved contract is not said in words")
	}
}
