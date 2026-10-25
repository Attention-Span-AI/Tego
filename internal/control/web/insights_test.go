// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// learnText is the proposal the dashboard's pipeline gives, tego learn's with the leak rule left to the page: learn.New over every line, then
// Contract.
func learnText(t *testing.T, root, run string) string {
	t.Helper()
	r, err := ledger.OpenReader(filepath.Join(root, run))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	l := learn.New(learn.Options{StateDirs: []string{filepath.Join(root, run), "/run/tego", root}, LeaveLeaksToCaller: true})
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	p, err := l.Proposal()
	if err != nil {
		t.Fatal(err)
	}
	return p.Contract()
}

var preRe = regexp.MustCompile(`(?s)<pre class="mono lp-contract">(.*?)</pre>`)

// TestLeastPrivilegeTab: the tab shows learn's proposal escaped, the download is the same text as an attachment,
// and a live run says it is the run so far.
func TestLeastPrivilegeTab(t *testing.T) {
	root := fixture(t)
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/runs/"+cleanRun+"/least-privilege", "127.0.0.1:8484", c)
	if w.Code != 200 {
		t.Fatalf("least-privilege: %d %s", w.Code, w.Body)
	}
	want := learnText(t, root, cleanRun)
	m := preRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no proposal block in %s", w.Body)
	}
	if got := html.UnescapeString(m[1]); got != want {
		t.Errorf("tab proposal:\n%s\nwant learn's:\n%s", got, want)
	}
	if !strings.Contains(want, "out") || !strings.Contains(w.Body.String(), `aria-current="page" title="The smallest policy change this run suggests">Tighten`) {
		t.Errorf("proposal lacks the written directory, or the tab is not current:\n%s", want)
	}
	d := do(s, "GET", "/runs/"+cleanRun+"/least-privilege.yaml", "127.0.0.1:8484", c)
	if d.Code != 200 || d.Body.String() != want {
		t.Fatalf("download: %d %q", d.Code, d.Body)
	}
	if ct, cd := d.Header().Get("Content-Type"), d.Header().Get("Content-Disposition"); !strings.HasPrefix(ct, "text/yaml") || !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("download headers %q %q", ct, cd)
	}
	if p := do(s, "POST", "/runs/"+cleanRun+"/least-privilege.yaml", "127.0.0.1:8484", c); p.Code == 200 {
		t.Errorf("POST download: %d", p.Code)
	}
	live := do(s, "GET", "/runs/"+harmRun+"/least-privilege", "127.0.0.1:8484", c)
	if live.Code != 200 || !strings.Contains(live.Body.String(), "The run has not ended") {
		t.Errorf("live run's tab: %d %s", live.Code, live.Body)
	}
	if strings.Contains(live.Body.String(), "<script>alert(1)</script>") {
		t.Error("an agent's target reached the page unescaped")
	}
}

// TestUnusedPermissionsTab: a compiled contract's entry no action used reads "granted but never used"; one the
// run used reads its counts.
func TestUnusedPermissionsTab(t *testing.T) {
	root := t.TempDir()
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "spare"), 0o755); err != nil {
		t.Fatal(err)
	}
	contract := "version: 0\nname: demo-drift\ncommand: [sh]\ncapture: off\nfs:\n  write: [./out, ./spare]\nnet:\n  allow: ['192.0.2.1:443']\n"
	sum := sha256.Sum256([]byte(contract))
	hash := hex.EncodeToString(sum[:])
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	dir := filepath.Join(root, cleanRun)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lines := line(cleanRun, "demo-drift", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"cwd":"`+cwd+`","contract_hash":"`+hash+`"`) +
		line(cleanRun, "demo-drift", 1, t0.Add(time.Second), "fs", `"verdict":"allow","rule":"fs.write[./out]","op":"open","path":"`+cwd+`/out/a","flags":577`) +
		line(cleanRun, "demo-drift", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Ledger: root, Port: port, Token: "tok123", Machine: &config.Machine{Home: t.TempDir()},
		Now: func() time.Time { return t0.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	w := do(s, "GET", "/runs/"+cleanRun+"/unused", "127.0.0.1:8484", c)
	if w.Code != 200 {
		t.Fatalf("unused: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	v := rulesview.Drift(context.Background(), root, cleanRun, rulesview.Options{Machine: s.cfg.Machine})
	if v.Unknown {
		t.Fatalf("the contract did not compile: %s", v.Contract)
	}
	byRule := map[string]rulesview.DriftRow{}
	for _, r := range v.Rows {
		byRule[r.Rule] = r
	}
	if r := byRule["fs.write[./out]"]; !r.Declared || r.Unused || r.Allow != 1 {
		t.Errorf("fs.write[./out]: %+v", r)
	}
	if r := byRule["fs.write[./spare]"]; !r.Declared || !r.Unused {
		t.Errorf("fs.write[./spare]: %+v", r)
	}
	if v.Unused < 2 || !strings.Contains(body, "Granted but never used") || !strings.Contains(body, "granted but never used") {
		t.Errorf("unused %d; page:\n%s", v.Unused, body)
	}
	// The fixture's live run has no contract: its rules read as not in the contract.
	fs := newServer(t, fixture(t))
	w = do(fs, "GET", "/runs/"+harmRun+"/unused", "127.0.0.1:8484", login(t, fs))
	if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "No policy copy") || !strings.Contains(b, "Not in policy") {
		t.Errorf("no-contract run's tab: %d %s", w.Code, b)
	}
}

// TestMachinePage: the page names the newest run's tier, what the others need, and points to tego doctor.
func TestMachinePage(t *testing.T) {
	root := fixture(t)
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/machine", "127.0.0.1:8484", c)
	if w.Code != 200 {
		t.Fatalf("machine: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"This machine", "<strong>Basic</strong>", "Available", "Run with sudo", "add bpf to the kernel&#39;s lsm= list", "tego doctor", rid(harmRun)} {
		if !strings.Contains(body, want) {
			t.Errorf("machine page lacks %q", want)
		}
	}
	empty := newServer(t, t.TempDir())
	if w := do(empty, "GET", "/machine", "127.0.0.1:8484", login(t, empty)); w.Code != 200 || !strings.Contains(w.Body.String(), "No runs yet") {
		t.Errorf("empty machine page: %d %s", w.Code, w.Body)
	}
}

func rid(id string) string { return shortRun(id) }
