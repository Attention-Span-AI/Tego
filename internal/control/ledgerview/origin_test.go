// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"
	"time"
)

// TestRunOriginIsReadFromTheRecord: a run is Interactive only when run_start says its stdin was a terminal, Deployed
// only when it carries a deployment block, Background when stdio was recorded and no terminal feeds it, and Unknown
// when the record says neither (a ledger older than both fields). A stop is read from run_end.
func TestRunOriginIsReadFromTheRecord(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		id, start, want, word string
	}{
		{"r-aaaa-0001-intera", `"stdio":{"stdin":"tty","stdout":"tty","stderr":"tty"}`, OriginInteractive, "Interactive"},
		{"r-aaaa-0002-deploy", `"stdio":{"stdin":"null","stdout":"socket","stderr":"socket"},"deployment":{"id":"dep_x","name":"nightly","revision":3,"instance":2,"trigger":"boot"}`, OriginDeployed, "Deployed"},
		{"r-aaaa-0003-deptty", `"stdio":{"stdin":"tty","stdout":"tty","stderr":"tty"},"deployment":{"id":"dep_x","name":"nightly","revision":1,"instance":1,"trigger":"start"}`, OriginDeployed, "Deployed"},
		{"r-aaaa-0004-backgr", `"stdio":{"stdin":"null","stdout":"pipe","stderr":"pipe"}`, OriginBackground, "Background"},
		{"r-aaaa-0005-outtty", `"stdio":{"stdin":"pipe","stdout":"tty","stderr":"tty"}`, OriginBackground, "Background"},
		{"r-aaaa-0006-unknow", `"tier":"landlock"`, OriginUnknown, "Unknown"},
		{"r-aaaa-0007-unkstd", `"stdio":{"stdin":"unknown","stdout":"unknown","stderr":"unknown"}`, OriginUnknown, "Unknown"},
	}
	for i, c := range cases {
		writeRun(t, root, c.id, line(c.id, "a", 0, t0.Add(time.Duration(i)*time.Minute), "run_start", `"command":["x"],`+c.start))
	}
	stopped := "r-aaaa-0008-stoppd"
	writeRun(t, root, stopped,
		line(stopped, "a", 0, t0, "run_start", `"command":["x"]`),
		line(stopped, "a", 1, t0.Add(time.Second), "run_end", `"reason":"stopped","stopped_by":"user:me"`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*Run{}
	for _, r := range s.Runs {
		got[r.ID] = r
	}
	for _, c := range cases {
		r := got[c.id]
		if r == nil || r.Origin() != c.want || r.OriginWord() != c.word {
			t.Errorf("%s: origin %q word %q, want %q %q", c.id, r.Origin(), r.OriginWord(), c.want, c.word)
		}
	}
	if r := got["r-aaaa-0002-deploy"]; r.Deployment != "nightly" {
		t.Errorf("deployment name %q", r.Deployment)
	}
	if r := got[stopped]; r.EndReason != "stopped" || r.StoppedBy != "user:me" {
		t.Errorf("stopped run: %q by %q", r.EndReason, r.StoppedBy)
	}
}
