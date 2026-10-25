// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	goodRun   = "r-3f9c2a1b-0dllq06ts7400-g00dxx"
	tamperRun = "r-3f9c2a1b-0dllq06ts7401-t4mp3r"
	liveRun   = "r-3f9c2a1b-0dllq06ts7402-l1vexx"
	openRun   = "r-3f9c2a1b-0dllq06ts7403-0p3nxx"
)

// writeRun writes a real run with the ledger's own Writer, anchored in anchor as tego anchors it: run_start, three fs
// lines and, when end, run_end. It returns the events file.
func writeRun(t *testing.T, root, anchor, id string, end bool) string {
	t.Helper()
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "demo-verify"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	start := record.RunStartPayload{LauncherPID: 4821, LauncherStartNS: 1, TegoVersion: "0.1.0-dev", Commit: "5330a30",
		Tier: "landlock", Capture: "forwarder", Kernel: "6.17.0", ContractHash: strings.Repeat("7a", 32),
		Parsers: map[string]string{"anthropic": "1", "mcp": "1", "openai": "0"}, StopGrace: "10s",
		Command: []string{"sh", "agent.sh"}, Cwd: "/home/u/proj"}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"out/a.txt", "out/b.txt", "out/c.txt"} {
		e := &record.Event{Kind: record.KindFS, Source: record.SourceLandlock, PID: 4822, TID: 4822, Cgroup: 9,
			Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule, Attr: record.Unattributed()}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: p, Flags: 0x241}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if end {
		if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
			t.Fatal(err)
		}
	} else if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, id, ledger.EventsFile)
}

// chainFixture is a ledger root with one good ended run, one live run and, when tamper, an ended run with one byte
// of its line #2 changed after it was anchored (the demo's edited copy). It returns the root and the anchor.
func chainFixture(t *testing.T, tamper bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	writeRun(t, root, anchor, goodRun, true)
	live := writeRun(t, root, anchor, liveRun, false)
	b, err := os.ReadFile(live)
	if err != nil || !bytes.Contains(b, []byte("run_start")) {
		t.Fatalf("live run: %v %q", err, b)
	}
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", liveRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if tamper {
		f := writeRun(t, root, anchor, tamperRun, true)
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.SplitAfter(b, []byte("\n"))
		i := bytes.Index(lines[2], []byte("out/b.txt"))
		if i < 0 {
			t.Fatalf("line 2 is %q", lines[2])
		}
		lines[2][i+4] = 'x' // out/b.txt -> out/x.txt: one byte
		if err := os.WriteFile(f, bytes.Join(lines, nil), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, anchor
}

func chainServer(t *testing.T, root, anchor string) *Server {
	t.Helper()
	s, err := New(Config{Ledger: root, Anchor: anchor, Port: port, Token: "tok123", Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	return s
}

// fixtureServer serves chainFixture's root with its anchor.
func fixtureServer(t *testing.T, tamper bool) *Server {
	t.Helper()
	root, anchor := chainFixture(t, tamper)
	return chainServer(t, root, anchor)
}

func getPage(t *testing.T, s *Server, path string) string {
	t.Helper()
	w := do(s, "GET", path, "127.0.0.1:8484", login(t, s))
	if w.Code != 200 {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func wantIn(t *testing.T, what, body string, want, not []string) {
	t.Helper()
	for _, x := range want {
		if !strings.Contains(body, x) {
			t.Errorf("%s lacks %q", what, x)
		}
	}
	for _, x := range not {
		if strings.Contains(body, x) {
			t.Errorf("%s shows %q", what, x)
		}
	}
}

// TestChainVerifiedRun: a run the ledger's Writer wrote and anchored shows "Chain verified" with its line count on
// its page, and the overview's Ledger tile says the ended runs it checked verify.
func TestChainVerifiedRun(t *testing.T) {
	s := fixtureServer(t, false)
	wantIn(t, "good run page", getPage(t, s, "/runs/"+goodRun), []string{"b b-verified", "Verified · 5 lines"},
		[]string{"Broken at", "Not verified"})
	wantIn(t, "overview", getPage(t, s, "/"), []string{"Verified · 1 run", "newest 20 ended runs"},
		[]string{"Unchecked", "Broken ·"})
}

// TestChainVerifiedOrphanSaysLinesMayBeMissing: a run that lost its supervisor verifies over whatever survived, so the
// Verified pill must not stand alone on its page: the run's end and its gap both say the last lines may be missing.
func TestChainVerifiedOrphanSaysLinesMayBeMissing(t *testing.T) {
	root, anchor := chainFixture(t, false)
	writeRun(t, root, anchor, openRun, false)
	w, err := ledger.Open(filepath.Join(root, openRun), record.RunRef{ID: openRun, Agent: "demo-verify"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}); err != nil {
		t.Fatal(err)
	}
	wantIn(t, "orphaned run page", getPage(t, chainServer(t, root, anchor), "/runs/"+openRun),
		[]string{"Verified · 6 lines", "the record&#39;s last lines may be missing"}, []string{"no action known to be missing"})
}

// TestChainTamperedRun: one byte changed in line #2 of an anchored run shows "Broken at #2" in the danger
// colour on its page, with an alert that says why in plain view and names the check to run, and the overview's tile
// names that run and links to it.
func TestChainTamperedRun(t *testing.T) {
	s := fixtureServer(t, true)
	over := getPage(t, s, "/")
	wantIn(t, "overview", over, []string{`Broken · <span class="mono">` + shortRun(tamperRun), `href="/runs/` + tamperRun + `"`,
		"Broken at #2"}, []string{"Verified ·"})
	why := regexp.MustCompile(`<span class="meta" title="([^"]+)">Broken at #2`).FindStringSubmatch(over)
	if why == nil {
		t.Fatal("the tile gives no reason")
	}
	wantIn(t, "tampered run page", getPage(t, s, "/runs/"+tamperRun),
		[]string{"b b-broken", "Broken at #2", `role="alert"`, "Record broken at #2", "</strong> · " + why[1] + " · not trusted from #2",
			`<span class="mono">tego events ` + tamperRun + ` --verify</span>`},
		[]string{"Verified ·"})
	wantIn(t, "good run page", getPage(t, s, "/runs/"+goodRun), []string{"Verified · 5 lines"}, []string{"Broken at"})
}

// TestChainUnanchoredRun: a run that did not end has no anchor line, so lines cut from its end would not show. Its chain
// checks line by line, but its pill does not read as a fully verified run's, in words or in colour.
func TestChainUnanchoredRun(t *testing.T) {
	root, anchor := chainFixture(t, false)
	writeRun(t, root, anchor, openRun, false)
	s := chainServer(t, root, anchor)
	wantIn(t, "unended run page", getPage(t, s, "/runs/"+openRun), []string{"b b-waiting", "Not anchored · 4 lines"},
		[]string{"Verified ·", "b b-verified"})
	wantIn(t, "good run page", getPage(t, s, "/runs/"+goodRun), []string{"b b-verified", "Verified · 5 lines"}, []string{"Not anchored"})
}

// TestChainLiveRun: a run still being written is not checked, and says when it will be, in a calm grey pill (the
// demo video's live run headers), not as "Chain not checked".
func TestChainLiveRun(t *testing.T) {
	s := fixtureServer(t, false)
	wantIn(t, "live run page", getPage(t, s, "/runs/"+liveRun),
		[]string{"b b-neutral", "Verify at end"}, []string{"Verified ·", "Broken at", "Not verified"})
}

// TestChainNoAnchor: a dashboard that does not know the anchor checks nothing and says so, never "verified".
func TestChainNoAnchor(t *testing.T) {
	root, _ := chainFixture(t, true)
	s := chainServer(t, root, "")
	wantIn(t, "good run page", getPage(t, s, "/runs/"+goodRun), []string{"Not verified", "anchor"}, []string{"Verified ·"})
	wantIn(t, "overview", getPage(t, s, "/"), []string{"Not checked"}, []string{"Verified ·", "Broken ·"})
}
