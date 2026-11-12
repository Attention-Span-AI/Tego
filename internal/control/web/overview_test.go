// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// pageCmd is a terminal command a page gives, as written in its <code>.
var pageCmd = regexp.MustCompile(`<code>(tego [^<]*)</code>`)

// TestEmptyStatesGiveOneStepForAnyAgent: with no run yet, the Overview and the Runs page give the same one command,
// tego watch with the person's own agent command, which every install has, and point at New contract's From a run for
// what comes after. They name no agent and no file the installer does not put on the machine (examples/ is only in a
// source checkout), and the step is not folded away.
func TestEmptyStatesGiveOneStepForAnyAgent(t *testing.T) {
	s := newServer(t, filepath.Join(t.TempDir(), "none"))
	c := login(t, s)
	for _, path := range []string{"/", "/runs"} {
		body := get(t, s, c, path)
		var got []string
		for _, m := range pageCmd.FindAllStringSubmatch(body, -1) {
			got = append(got, html.UnescapeString(m[1]))
		}
		if !slices.Equal(got, []string{"tego watch -- <the command that starts your agent>"}) {
			t.Errorf("%s gives %q, not the one tego watch step", path, got)
		}
		empty := body[strings.Index(body, "<h3>No runs"):]
		empty = empty[:strings.Index(empty, "</section>")]
		for _, bad := range []string{"examples/", "claude", "codex", "<details"} {
			if strings.Contains(strings.ToLower(empty), bad) {
				t.Errorf("%s's empty state has %q:\n%s", path, bad, empty)
			}
		}
		if !strings.Contains(empty, `href="/rules/new?mode=run"`) {
			t.Errorf("%s's empty state does not say where the run goes next:\n%s", path, empty)
		}
	}
}

// TestOverviewRefusalsListWhatMattersFirst: a run whose newest 400 refusals are an agent's route probes (port 65535,
// background on the run page) and whose older refusal is a denied SSH key. The overview's list shows the key as High
// and leaves the routine probes out.
func TestOverviewRefusalsListWhatMattersFirst(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaaaaaa-0000000000005-overvw"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ls := []string{line(run, "supply-chain", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`),
		line(run, "supply-chain", 1, t0.Add(time.Second), "refused", `"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`)}
	for i := 0; i < 400; i++ {
		ls = append(ls, line(run, "supply-chain", 2+i, t0.Add(time.Minute), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`))
	}
	// The UDP action line is what makes them route probes (ledgerview.RouteProbe): a connect to that port is otherwise a real attempt.
	ls = append(ls, line(run, "supply-chain", 402, t0.Add(time.Minute), "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`))
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/")
	ref := body[strings.Index(body, `id="h-ref"`):]
	if !strings.Contains(ref, `<span class="sev sev-High">High</span>`) || !strings.Contains(ref, "id_rsa") {
		t.Errorf("the Overview's list does not lead with the High key read:\n%s", ref)
	}
	if strings.Contains(ref, "104.18.32.47:65535") {
		t.Error("the Overview's list shows a routine probe")
	}
	// On a phone the grid's head is hidden, so each count keeps its column's name through data-label (signal.css).
	for _, label := range []string{"Files", "Programs", "Network", "All"} {
		if !strings.Contains(body, `<td class="num" data-label="`+label+`">`) {
			t.Errorf("the Overview's grid has no %s label", label)
		}
	}
}
