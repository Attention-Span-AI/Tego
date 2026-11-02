// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

const (
	wordsRun = "r-aaaaaaaa-0000000000009-wordsx"
	// wordsToken is a credential in a command line; no page may show it outside the line's "exactly as written" fold.
	wordsToken = "svc_demo_FAKE_SERVICE_TOKEN_0000"
	wordsKey   = "/home/u/.ssh/id_ed25519"
	wordsAsk   = "q-4757578d5c194470c9db60c8b4932435"
)

// wordsArgv is a Codex-shaped command line long enough that the ledger writer moved it to a blob.
var wordsArgv = []string{"/proc/self/exe", "--codex-run-as-process-setup", "/bin/bash", "-c",
	"curl -s -H 'Authorization: Bearer " + wordsToken + "' -d @" + wordsKey + " http://127.0.0.1:4880/xyzzyblobword " + strings.Repeat("#", 4200)}

// wordsFixture is one ended run: its start, an exec whose argv is in a blob, a refused read of an ssh key, an ask
// and its answer, an exec with a credential inline, a capture gap, and its end.
func wordsFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, wordsRun)
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(wordsArgv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "blobs", sha), b, 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ls := []string{
		line(wordsRun, "codex", 0, t0, "run_start", `"tier":"landlock","command":["codex","exec","fix the tests"],"cwd":"/home/u/proj"`),
		line(wordsRun, "codex", 1, t0.Add(time.Second), "exec", `"verdict":"allow","rule":"exec[codex]","path":"/proc/self/exe","argv_blob":"`+sha+`","argv_truncated":true`),
		line(wordsRun, "codex", 2, t0.Add(2*time.Second), "fs", `"verdict":"refused","rule":"fs.deny_read[~/.ssh/]","reason":"read-denied","op":"open","path":"`+wordsKey+`","flags":0`),
		line(wordsRun, "codex", 3, t0.Add(3*time.Second), "ask", `"ask_id":"`+wordsAsk+`","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/home/u/proj/confidential/plan.md"`),
		line(wordsRun, "codex", 4, t0.Add(30*time.Second), "answer", `"ask_id":"`+wordsAsk+`","approved":true,"by":"uid:4000000000 pid:9","after_s":27.2,"op":"read","target":"/home/u/proj/confidential/plan.md"`),
		line(wordsRun, "codex", 5, t0.Add(31*time.Second), "exec", `"verdict":"allow","rule":"exec[curl]","path":"/usr/bin/curl","argv":["curl","-H","Authorization: Bearer `+wordsToken+`","http://127.0.0.1:4880"]`),
		line(wordsRun, "codex", 6, t0.Add(32*time.Second), "gap", `"what":"capture","why":"no-models"`),
		line(wordsRun, "codex", 7, t0.Add(33*time.Second), "net", `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:4880"`),
		line(wordsRun, "codex", 8, t0.Add(40*time.Second), "run_end", `"reason":"exit","exit_code":0`),
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

var (
	tags     = regexp.MustCompile(`(?s)<[^>]*>`)
	asIsFold = regexp.MustCompile(`(?s)<details class="ev-(?:asis|show)">.*?</details>`)
	styles   = regexp.MustCompile(`(?s)<(style|script)[^>]*>.*?</(style|script)>`)
)

// visible is a page's text as a reader sees it: <wbr> dropped, other tags (and their attributes) a space, entities decoded, runs of
// white space one space.
func visible(page string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tags.ReplaceAllString(strings.ReplaceAll(styles.ReplaceAllString(page, ""), "<wbr>", ""), " "))), " ")
}

// TestLogsRowsReadInWords: Logs shows an exec's argv from its blob, masked; an ask as "Asked to read <path>" and the
// header counts it as asked; an ssh key's path in full; and no ledger kind or ask id as row text. A search for a word
// only in the blob finds the line.
func TestLogsRowsReadInWords(t *testing.T) {
	s := newServer(t, wordsFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/logs")
	text := visible(page)
	for _, want := range []string{"Asked to read", "Allowed once by user 4000000000 after 27 s:", "Run started:", "codex exec fix the tests",
		"Run ended, exit 0", "Model traffic not recorded (no model capture for this agent)", "… /bin/bash -c curl -s -H",
		"Authorization: Bearer ••••", "not on the allowed hosts", "a read the rules refuse", "codex #1", "1 asked", "2 blocked"} {
		if !strings.Contains(text, want) {
			t.Errorf("Logs lacks %q", want)
		}
	}
	// The row reads the shell's script; its title holds the whole command line, launcher and all.
	if !strings.Contains(html.UnescapeString(page), `title="/proc/self/exe --codex-run-as-process-setup /bin/bash -c curl`) {
		t.Error("the blob exec's row does not carry the whole command in its title")
	}
	if !strings.Contains(page, `title="`+wordsKey+`"`) {
		t.Errorf("Logs does not carry the key's full path %s", wordsKey)
	}
	for _, bad := range []string{wordsToken, "run_start", "run_end", "q-4757", "/proc/self/exe (command"} {
		if strings.Contains(text, bad) {
			t.Errorf("Logs shows %q", bad)
		}
	}
	if strings.Contains(page, wordsToken) {
		t.Error("Logs carries the credential in its HTML")
	}
	if !strings.Contains(page, `title="Reason code: net-not-allowed"`) {
		t.Error("the reason's code is not in its title")
	}
	if got := get(t, s, c, "/logs?q=xyzzyblobword"); !strings.Contains(got, `data-k="`+wordsRun+`-1"`) || strings.Contains(got, `data-k="`+wordsRun+`-5"`) {
		t.Error("a search for a word only in the blob does not find the exec line, or finds others")
	}
	if got := visible(get(t, s, c, "/logs?verdict=ask")); !strings.Contains(got, "Asked to read") {
		t.Error("the Asked filter does not list the ask line")
	}
	if got := get(t, s, c, "/logs?q=plan.md"); !strings.Contains(got, `data-k="`+wordsRun+`-3"`) || !strings.Contains(got, `data-k="`+wordsRun+`-4"`) {
		t.Error("a search for the asked file does not find both the ask and its answer")
	}
	if !regexp.MustCompile(`(?s)data-k="` + wordsRun + `-3".*?<span class="b b-asked"`).MatchString(page) {
		t.Error("the ask row is not badged Asked")
	}
}

// TestTimelineRowsReadInWords: the run timeline says the same words as Logs (both go through shown and shownOp) and
// carries the blob's argv.
func TestTimelineRowsReadInWords(t *testing.T) {
	s := newServer(t, wordsFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/runs/"+wordsRun)
	text := visible(page)
	for _, want := range []string{"Run started:", "Run ended, exit 0", "Asked to read", "Allowed once by user 4000000000",
		"Model traffic not recorded"} {
		if !strings.Contains(text, want) {
			t.Errorf("the timeline lacks %q", want)
		}
	}
	if !strings.Contains(page, "… /bin/bash -c curl -s -H") {
		t.Error("the timeline does not carry the exec's argv from its blob")
	}
	if strings.Contains(page, wordsToken) {
		t.Error("the run page carries the credential")
	}
	for _, bad := range []string{"open ask", "gap capture no-models", wordsAsk} {
		if strings.Contains(text, bad) {
			t.Errorf("the timeline shows %q", bad)
		}
	}
}

// TestLinePageMasksAndPrintsTheLine: on the line page the headline, the What line and the rows around it mask a
// credential (only the closed "exactly as written" fold holds the line as written); an exec whose argv is in a blob
// shows it whole; and the terminal twin, run against the events file, prints exactly this line.
func TestLinePageMasksAndPrintsTheLine(t *testing.T) {
	root := wordsFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, seq := range []int{4, 5, 6} { // the inline credential's line, and two lines that list it around them
		page := get(t, s, c, "/runs/"+wordsRun+"/lines/"+strconv.Itoa(seq))
		if strings.Contains(asIsFold.ReplaceAllString(page, ""), wordsToken) {
			t.Errorf("line %d shows the credential outside the as-written fold", seq)
		}
	}
	blob := get(t, s, c, "/runs/"+wordsRun+"/lines/1")
	if strings.Contains(blob, wordsToken) {
		t.Error("the blob exec's line page shows the credential")
	}
	if !strings.Contains(html.UnescapeString(blob), strings.Repeat("#", 4200)+"</pre></details>") {
		t.Error("the blob exec's What line does not show the whole command")
	}

	events := filepath.Join(root, wordsRun, "events.jsonl")
	for _, seq := range []uint64{0, 3, 8} {
		page := html.UnescapeString(get(t, s, c, "/runs/"+wordsRun+"/lines/"+strconv.FormatUint(seq, 10)))
		hint := lineCLI(wordsRun, seq)
		if !strings.Contains(page, hint) {
			t.Fatalf("line %d: the page lacks its terminal twin %q", seq, hint)
		}
		// `tego events <run> --json` prints the stored lines byte for byte; cat stands in for it.
		cmd := strings.Replace(hint, "tego events "+wordsRun+" --json", "cat '"+events+"'", 1)
		out, err := exec.Command("sh", "-c", cmd).Output()
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		lf, err := ledgerview.Line(root, wordsRun, seq)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != lf.Raw {
			t.Errorf("line %d: the hint prints\n%s\nwant\n%s", seq, got, lf.Raw)
		}
	}
}

// TestRowWords: the words of the lines a row has no agent text for, the reasons, and pathWords' breaks and escaping.
func TestRowWords(t *testing.T) {
	for raw, want := range map[string]string{
		`{"reason":"exit","exit_code":3}`:                    "Run ended, exit 3",
		`{"reason":"signal","signal":1}`:                     "Run ended by SIGHUP",
		`{"reason":"stopped","stopped_by":"uid:4000000000"}`: "Run stopped by user 4000000000",
		`{"reason":"oom"}`:                                   "Run ended: out of memory",
		`{}`:                                                 "Run ended",
	} {
		if got := endWords(raw); got != want {
			t.Errorf("endWords(%s) = %q, want %q", raw, got, want)
		}
	}
	if got := gapWords("record", "no-price-table"); got != "Cost not counted (no price table for this model)" {
		t.Errorf("price gap %q", got)
	}
	if got := gapWords("capture", "ssl-unhooked"); got != "Not captured: ssl unhooked" {
		t.Errorf("an unnamed capture gap %q", got)
	}
	// A mode tego gave back lost nothing: its row says what tego did, not "A gap in the record".
	if got := gapWords("record", "own-state-mode-restored"); got != "Tego gave its owner back the rights on one of its own files, which something had taken" {
		t.Errorf("a restored mode %q", got)
	}
	for why, want := range map[string]string{"run-paused": "Run paused: the agent is frozen", "run-resumed": "Run resumed",
		"pause-failed": "Pause failed: the agent kept running", "resume-failed": "Resume failed: the run stays paused"} {
		if got := gapWords("enforce", why); got != want {
			t.Errorf("gapWords(enforce, %s) = %q, want %q", why, got, want)
		}
	}
	for code, want := range map[string]string{"net-not-allowed": "not on the allowed hosts", "ask-denied": "a person said no",
		"limit-wall": "a run limit was reached", "made-up": "made-up"} {
		if got := reasonWords(ledgerview.Event{Kind: "refused", Reason: code}); got != want {
			t.Errorf("reasonWords(%s) = %q, want %q", code, got, want)
		}
	}
	if got := reasonWords(ledgerview.Event{Kind: "exec", Reason: "exec-not-allowed", Rule: "live.block[exec:ls]"}); got != "" {
		t.Errorf("a live block's refusal reads %q, want none (its label says it)", got)
	}
	pw := func(text, home string) string {
		t.Helper()
		tm, err := template.New("pw").Funcs(funcs).ParseFS(assets, "templates/layout.tmpl", "templates/logs.tmpl")
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		if err := tm.ExecuteTemplate(&b, "pw", pathWords(text, home)); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	if got, want := pw("/home/u/.cache/tego-workdir/id_ed25519", "/home/u"), `<span class="ut pw" title="/home/u/.cache/tego-workdir/id_ed25519"><span class="sp-d">~/<wbr>.cache/<wbr><span class="nb">tego-workdir/</span></span><wbr><b class="sp-b">id_ed25519</b></span>`; got != want {
		t.Errorf("pw(path)\n = %s\nwant %s", got, want)
	}
	if got, want := pw(`curl <b>"x"</b> http://127.0.0.1:4880/a`, ""), `<span class="ut pw">curl &lt;b&gt;&#34;x&#34;&lt;/<wbr>b&gt; http:<wbr>/<wbr>/<wbr>127.0.0.1:<wbr>4880/<wbr>a</span>`; got != want {
		t.Errorf("pw(text)\n = %s\nwant %s", got, want)
	}
	if got := pw(strings.Repeat("x", clampChars+1), ""); !strings.Contains(got, ` title="`) {
		t.Error("long text carries no title")
	}
	// A long text renders its first shownMax bytes, in few pieces (plain runs merge), and keeps itself whole in the title.
	long := strings.Repeat("curl -s ok ", 900)
	v := pathWords(long, "")
	shownLen := 0
	for _, p := range v.Text {
		shownLen += len(p.Text)
	}
	if shownLen > shownMax+len("…") || len(v.Text) != 1 || v.Title != long {
		t.Errorf("a long text renders %d bytes in %d pieces (title %d bytes); want at most %d bytes in one piece, the whole text in the title",
			shownLen, len(v.Text), len(v.Title), shownMax)
	}
	if got := pathWords("/a/b → /c/d", ""); len(got.Parts) != 2 || got.Parts[1].Full != "/c/d" {
		t.Errorf("a rename is two paths: %+v", got)
	}
	for in, want := range map[string]string{
		"/proc/self/exe --x 46 4036205 pipe /w /bin/bash /bin/bash -c curl -d @k http://h": "… /bin/bash -c curl -d @k http://h",
		"bash -c ls":       "bash -c ls",
		"python3 -c print": "python3 -c print",
		"env sh -lc make":  "… sh -lc make",
	} {
		if got := shellTail(in); got != want {
			t.Errorf("shellTail(%q) = %q, want %q", in, got, want)
		}
	}
	ask := ledgerview.Event{Kind: "ask", Op: "open", Rule: "fs.ask[./held/]", Raw: `{"op":"open","target":"/p/held/a"}`}
	if op := shownOp(ask); op != "Asked a person to let a held open go on" {
		t.Errorf("an ask with no target reads %q", op)
	}
	if shown(ask) != "" {
		t.Errorf("an ask with no target shows %q", shown(ask))
	}
}

// TestMaskMemoIsMask: a long text masks the same through the memo as without it, the first time and after.
func TestMaskMemoIsMask(t *testing.T) {
	long := "curl -H 'Authorization: Bearer " + wordsToken + "' " + strings.Repeat("x ", maskMemoMin)
	want := maskNow(long)
	if strings.Contains(want, wordsToken) {
		t.Fatal("maskNow leaves the credential")
	}
	for i := 0; i < 2; i++ {
		if got := mask(long); got != want {
			t.Fatalf("mask (call %d) differs from maskNow", i+1)
		}
	}
}

// TestBlobArgvMissingSaysSo: an exec whose argv blob fails its checks shows its path and says the command could not
// be read, rather than passing the path off as the command.
func TestBlobArgvMissingSaysSo(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, wordsRun)
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("ab", 32)
	if err := os.WriteFile(filepath.Join(dir, "blobs", sha), []byte(`["not","the","hash"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ls := line(wordsRun, "codex", 0, t0, "run_start", `"tier":"landlock","command":["codex"]`) +
		line(wordsRun, "codex", 1, t0.Add(time.Second), "exec", `"verdict":"allow","path":"/bin/bash","argv_blob":"`+sha+`"`)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ls), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	if text := visible(get(t, s, c, "/logs")); !strings.Contains(text, "/bin/bash (command in blob could not be read)") {
		t.Error("Logs does not say the blob could not be read")
	}
	if strings.Contains(visible(get(t, s, c, "/logs")), "not the hash") {
		t.Error("Logs shows a blob that does not hash to its name")
	}
}
