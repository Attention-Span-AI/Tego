// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var investigateLink = regexp.MustCompile(`href="(/runs/[^"]+/investigate/\d+)"`)

// TestInvestigate: a Detections row opens Investigate, which has its four parts in order and a way to change the
// policy; an address that names no detection is a 404.
func TestInvestigate(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	m := investigateLink.FindStringSubmatch(get(t, s, c, "/detections"))
	if m == nil {
		t.Fatal("no Detections row links to Investigate")
	}
	page := get(t, s, c, m[1])
	last := -1
	if !strings.Contains(page, "?a=allow#act-check") || !strings.Contains(page, `data-review="`) {
		t.Error("Investigate lacks its two decisions: Allow from now on and Keep blocked")
	}
	for _, part := range []string{`id="h-what"`, `id="h-how"`, `id="h-else"`, `id="h-now"`, "All policy options"} {
		i := strings.Index(page, part)
		if i < 0 || i < last {
			t.Errorf("%s missing or out of order", part)
		}
		last = i
	}
	if w := do(s, "GET", "/runs/r-nope/investigate/1", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Errorf("an unknown detection answers %d", w.Code)
	}
}

// TestInvestigateRunWithNoContractPath: a run whose run_start names no contract path links no policy. Its base name was
// ".", which the page showed as the policy's name.
func TestInvestigateRunWithNoContractPath(t *testing.T) {
	root := detectionsRoot(t, "r-aaaaaaaa-0000000000031-nopath", "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	s := newServer(t, root)
	c := login(t, s)
	m := investigateLink.FindStringSubmatch(get(t, s, c, "/detections"))
	if m == nil {
		t.Fatal("no Investigate link")
	}
	if page := get(t, s, c, m[1]); strings.Contains(page, `">.</a>`) {
		t.Errorf("the policy reads as a dot:\n%s", page)
	}
}

// TestLivePagesFollowTheLedger: Detections and Investigate are live regions: an unchanged page gets nothing back, and a
// new refused line reaches an open page without a reload, in the row that already stood for its group, whose address
// stays good.
func TestLivePagesFollowTheLedger(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000009-livedt"
	connect := func(target string) [2]string {
		return [2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"` + target + `"`}
	}
	root := detectionsRoot(t, run, "landlock", connect("203.0.113.9:443"))
	s := newServer(t, root)
	c := login(t, s)
	const host = "127.0.0.1:8484"
	list := get(t, s, c, "/detections")
	m := investigateLink.FindStringSubmatch(list)
	if m == nil {
		t.Fatalf("no Investigate link:\n%s", list)
	}
	page := get(t, s, c, m[1])
	for _, where := range []struct{ path, body string }{{"/detections", list}, {m[1], page}} {
		have := regionsIn(where.body)
		if _, ok := have["content"]; !ok {
			t.Fatalf("%s has no live content region: %v", where.path, have)
		}
		if w := doRegions(s, where.path, host, c, headerOf(have)); strings.Contains(w.Body.String(), `data-live="content"`) {
			t.Errorf("%s resends an unchanged region", where.path)
		}
	}

	ev, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Date(2026, 11, 1, 11, 0, 0, 0, time.UTC)
	_, err = ev.WriteString(line(run, "agent", 9, later, "refused", connect("203.0.113.9:8443")[1]))
	if cerr := ev.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	for _, where := range []struct{ path, body, want string }{{"/detections", list, ">2</td>"}, {m[1], page, "2 times"}} {
		w := doRegions(s, where.path, host, c, headerOf(regionsIn(where.body)))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-live="content"`) || !strings.Contains(w.Body.String(), where.want) {
			t.Errorf("%s after a new line: %d, want %q in a fresh region:\n%s", where.path, w.Code, where.want, w.Body)
		}
	}
}

// TestFileKind: well-known files read as what they hold; anything else as nothing.
func TestFileKind(t *testing.T) {
	for p, want := range map[string]string{
		"/home/u/.netrc":                              "Saved logins (git, curl)",
		"/home/u/.ssh/id_ed25519":                     "SSH private key",
		"/home/u/.ssh/id_ed25519.pub":                 "",
		"/home/u/try/.claude-state/.credentials.json": "Claude Code's login",
		"/home/u/p/.git/hooks/pre-commit":             "Runs on git commands",
		"/home/u/p/.env.local":                        "Project secrets",
		"/home/u/p/main.go":                           "",
	} {
		if got := fileKind(p); got != want {
			t.Errorf("fileKind(%s) = %q, want %q", p, got, want)
		}
	}
}

func TestURLHost(t *testing.T) {
	if h := urlHost("/usr/libexec/git-core/git-remote-https origin https://github.com/a/b.git"); h != "github.com" {
		t.Errorf("urlHost = %q, want github.com", h)
	}
	if h := urlHost("curl -s 127.0.0.1:8802"); h != "" {
		t.Errorf("urlHost of no URL = %q", h)
	}
}
