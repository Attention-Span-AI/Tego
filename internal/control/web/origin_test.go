// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestRunKindAndStoppedWords: the run page labels a run Interactive (stdin a terminal), Deployed (a
// deployment block), Background (stdio recorded, no terminal on stdin) or Unknown (nothing recorded), from run_start
// alone, and Overview and Runs show only the informative two (Interactive, Deployed) as a pill;
// a run ended by tego stop or the dashboard's Stop says Stopped, with who asked, not the raw reason code.
func TestRunKindAndStoppedWords(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	runs := []struct{ id, agent, start, end, kind string }{
		{"r-bbbb-0000000000001-intera", "claude-here", `"stdio":{"stdin":"tty","stdout":"tty","stderr":"tty"}`, "", "Interactive"},
		{"r-bbbb-0000000000002-deploy", "nightly-agent", `"stdio":{"stdin":"null","stdout":"socket","stderr":"socket"},"deployment":{"id":"dep_x","name":"nightly","revision":3,"instance":2,"trigger":"boot"}`, `"reason":"exit","exit_code":0`, "Deployed"},
		{"r-bbbb-0000000000003-backgr", "batch-agent", `"stdio":{"stdin":"null","stdout":"pipe","stderr":"pipe"}`, `"reason":"stopped","stopped_by":"user:me"`, "Background"},
		{"r-bbbb-0000000000004-unknow", "old-agent", `"tier":"landlock"`, `"reason":"oom"`, "Unknown"},
	}
	for i, r := range runs {
		ls := []string{line(r.id, r.agent, 0, t0.Add(time.Duration(i)*time.Minute), "run_start", `"command":["x"],`+r.start)}
		if r.end != "" {
			ls = append(ls, line(r.id, r.agent, 1, t0.Add(time.Duration(i)*time.Minute+time.Second), "run_end", r.end))
		}
		if err := os.MkdirAll(filepath.Join(root, r.id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, r.id, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	markLive(t, root, runs[0].id)
	s := newServer(t, root)
	c := login(t, s)
	badge := regexp.MustCompile(`class="b b-origin b-origin-[a-z]+"[^>]*>([A-Za-z]+)</span>`)
	for _, p := range []string{"/", "/runs"} {
		body := get(t, s, c, p)
		got := map[string]bool{}
		for _, m := range badge.FindAllStringSubmatch(body, -1) {
			got[m[1]] = true
		}
		// The lists show the origin only where it tells something (Interactive, Deployed); a background run's status
		// says "Started without a terminal" in its title, and an unknown one says nothing.
		for _, r := range runs {
			if want := r.kind == "Interactive" || r.kind == "Deployed"; got[r.kind] != want {
				t.Errorf("%s: %s label shown %v, want %v (found %v)", p, r.kind, got[r.kind], want, got)
			}
		}
		if !strings.Contains(body, `title="Started without a terminal"`) {
			t.Errorf("%s: the background run's status has no Started without a terminal title", p)
		}
	}
	for _, r := range runs {
		body := get(t, s, c, "/runs/"+r.id)
		if m := badge.FindStringSubmatch(body); m == nil || m[1] != r.kind {
			t.Errorf("%s: run page label %v, want %s", r.id, m, r.kind)
		}
		if !strings.Contains(body, "Started as") {
			t.Errorf("%s: no Started as line in the details", r.id)
		}
	}
	// A label the record cannot support is Unknown, never a guess: the old run has no stdio and no deployment.
	if body := get(t, s, c, "/runs/"+runs[3].id); !strings.Contains(body, "the record does not say") {
		t.Error("an unknown origin does not say the record is silent")
	}
	if body := get(t, s, c, "/runs/"+runs[1].id); !strings.Contains(body, "a supervised instance of nightly") {
		t.Error("a deployed run does not name its deployment")
	}
	stopped := get(t, s, c, "/runs/"+runs[2].id)
	for _, want := range []string{">Stopped</span>", "Stopped on request by user:me"} {
		if !strings.Contains(stopped, want) {
			t.Errorf("stopped run page lacks %q", want)
		}
	}
	if _, ended, _ := strings.Cut(stopped, "<dt>Ended</dt>"); !strings.Contains(ended[:300], "Stopped") || strings.Contains(ended[:300], "· stopped") {
		t.Errorf("the Ended line shows the raw reason code: %q", ended[:300])
	}
	if body := get(t, s, c, "/runs?state=ended"); !strings.Contains(body, "Stopped") || !strings.Contains(body, "Out of memory") {
		t.Error("Runs lacks the Stopped and Out of memory words")
	}
}
