// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/selfbin"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// codeBlock matches a <code> element, the text a Copy button copies.
var codeBlock = regexp.MustCompile(`(?s)<code[^>]*>(.*?)</code>`)

// writeRunQ is rulesFix.run with the folder and the rules file's path written into the record as JSON strings, so a
// newline or an escape in them is a valid record (the ledger holds whatever a record-only agent's cwd was).
func (f *rulesFix) writeRunQ(t *testing.T, id, source, cwd string, t0 time.Time, live bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(rulesSource), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(source, []byte(rulesSource), &agent.ProfileChain{})
	if err != nil {
		t.Fatal(err)
	}
	canon, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := c.Hash()
	dir := filepath.Join(f.root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), canon, 0o600); err != nil {
		t.Fatal(err)
	}
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	line := fmt.Sprintf(`{"v":1,"seq":0,"id":"%064x","prev":"","ts":"%s","mono_ns":1,"run":"%s","agent":"%s","pid":10,"tid":10,"cgroup":1,`+
		`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":%s,"contract_hash":"%s","contract_source":{"path":%s}}`+"\n",
		1, t0.Format(time.RFC3339Nano), id, c.Name, q(cwd), hex.EncodeToString(sum[:]), q(source))
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if live {
		markLive(t, f.root, id)
	}
}

// TestTerminalTwinsShowNoLineForAValueThatCannotBeShown: the Rules page's terminal lines (tego rules check, cd <folder> &&,
// tego run <contract>, the restart line) are built from values in the record: the run's folder and its rules file's path,
// which a record-only agent or a forged record chooses. shellword.Quote keeps a line's shell syntax, not what the
// terminal shows: a newline in the folder's name showed a second apparent command, and Copy copied it. Every such line goes
// through cmdText (selfbin.Safe): a folder or path with a newline, an escape or a bidi override gives no command and the
// page says why in plain text; the line of a folder that prints is unchanged. The page's Content-Security-Policy and its
// scripts-off behaviour are untouched: the notice is escaped text in the same block, and a Copy copies that text.
func TestTerminalTwinsShowNoLineForAValueThatCannotBeShown(t *testing.T) {
	f := newRulesFix(t)
	t0 := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Millisecond)
	for i, name := range []string{"a\nb", "a\x1b[2Jb", "a\u202eb"} {
		id := fmt.Sprintf("r-aaaaaaaa-00000000001%02d-weird%d", i, i)
		cwd := filepath.Join(f.proj, "x"+name)
		source := filepath.Join(cwd, "agent.yaml")
		f.writeRunQ(t, id, source, cwd, t0.Add(time.Duration(i)*time.Second), true)
		code, body := f.get(t, "/rules?run="+id)
		if code != 200 {
			t.Fatalf("%q: GET /rules?run=: %d", name, code)
		}
		if !strings.Contains(body, unsafeLine) {
			t.Errorf("%q: the page does not say a line cannot be shown", name)
		}
		for _, bad := range []string{"tego rules check ", "tego run "} {
			// The page's other text holds these words in prose; a command block holds them after <code>.
			if strings.Contains(body, "<code>"+bad) || strings.Contains(body, "<code>cd ") {
				t.Errorf("%q: a command block holds %q:\n%s", name, bad, body)
			}
		}
		// Nothing a Copy button can copy (the text of a <code> block) holds the character. The page also shows the folder
		// as text in titles, option labels and definition lists; a browser acts on no control character there, and those are
		// not command blocks.
		for _, m := range codeBlock.FindAllStringSubmatch(body, -1) {
			if !selfbin.Safe(html.UnescapeString(m[1])) {
				t.Errorf("%q: a command block holds an unsafe character: %q", name, m[1])
			}
		}
	}
	// A folder that prints keeps its lines.
	_, body := f.get(t, "/rules?run="+rulesRunB)
	if !strings.Contains(body, "cd "+f.proj+" &amp;&amp; tego rules check "+f.source) || strings.Contains(body, unsafeLine) {
		t.Error("a folder that prints lost its terminal line")
	}
}

// TestCmdText: the one function every page's command block and Copy button goes through.
func TestCmdText(t *testing.T) {
	for in, want := range map[string]string{
		"tego rules check '/a b/agent.yaml'": "tego rules check '/a b/agent.yaml'",
		"cd /x && tego run c":                "cd /x && tego run c",
		"tego rules check 'a\nsudo -i'":      unsafeLine,
		"tego rules check a\rb":              unsafeLine,
		"tego rules check a\x1b[2J":          unsafeLine,
		"tego rules check a\u202eb":          unsafeLine,
		"tego rules check a\xffb":            unsafeLine,
		"tego events r-1 --json | sed -n 1p": "tego events r-1 --json | sed -n 1p",
	} {
		if got := cmdText(in); got != want {
			t.Errorf("cmdText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAskTwinsQuoteAndCheckTheAskID: the approvals page's terminal lines (tego approve, deny, alternate) put the ask id
// from the record in a command, unquoted and unchecked: ask_id is not validated, so an id with a space or a semicolon
// became more commands when pasted, and one with a newline showed a second apparent command. The id is one quoted word and
// the line goes through cmdText.
func TestAskTwinsQuoteAndCheckTheAskID(t *testing.T) {
	for _, tc := range []struct{ id, want string }{
		{"ask-7", "tego approve r-aaaaaaaa-0000000000001-runxyz ask-7 --always"},
		{"a b; sudo -i", "tego approve r-aaaaaaaa-0000000000001-runxyz 'a b; sudo -i' --always"},
		{"x\nsudo -i", unsafeLine},
		{"x\x1b[2J", unsafeLine},
		{"x\u202ey", unsafeLine},
	} {
		if got := cmdText(answerTwin("approve", "r-aaaaaaaa-0000000000001-runxyz", tc.id, " --always")); got != tc.want {
			t.Errorf("ask id %q: %q, want %q", tc.id, got, tc.want)
		}
	}
}
