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

// TestEmptyStatesStartAnInteractiveAgent: with no run yet, the Overview and the Runs page give the same commands, and
// each starts an interactive Claude Code or Codex as it stands. tego run takes a copy of an examples/agents/ contract
// under ~/contracts/, written as that contract's own header writes the command, so the page and the file the person
// copies agree. tego init's starter agent.yaml is never named: it runs python3 agent.py and sends the model through
// the forwarder, and Claude Code exits 1 on its start-up check under it. tego watch runs Codex with --no-daemon:
// without it Codex hands its commands to a background server, and one an earlier session started runs them outside
// the run (docs/OPERATIONS.md, "Interactive Codex under a boundary").
func TestEmptyStatesStartAnInteractiveAgent(t *testing.T) {
	s := newServer(t, filepath.Join(t.TempDir(), "none"))
	c := login(t, s)
	var cmds []string
	for _, path := range []string{"/", "/runs"} {
		body := get(t, s, c, path)
		var got []string
		for _, m := range pageCmd.FindAllStringSubmatch(body, -1) {
			got = append(got, html.UnescapeString(m[1]))
		}
		if path == "/" {
			cmds = got
		} else if !slices.Equal(got, cmds) {
			t.Errorf("the empty Runs page gives %q, the empty Overview %q", got, cmds)
		}
		if !strings.Contains(body, "examples/agents/") {
			t.Errorf("%s does not say where the contracts to copy are", path)
		}
	}
	var copied []string
	for _, cmd := range cmds {
		name, isRun := strings.CutPrefix(cmd, "tego run ~/contracts/")
		switch {
		case isRun:
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "agents", name))
			if err != nil {
				t.Errorf("%q: %v", cmd, err)
			} else if !strings.Contains(string(b), cmd+"\n") {
				t.Errorf("%q is not how examples/agents/%s says to run it", cmd, name)
			}
			copied = append(copied, name)
		case cmd == "tego watch -- codex --no-daemon":
		default:
			t.Errorf("an empty state gives %q, which is not known to start an interactive agent", cmd)
		}
	}
	if !slices.Contains(copied, "claude-code-interactive.yaml") || !slices.Contains(copied, "codex-chatgpt.yaml") ||
		!slices.Contains(cmds, "tego watch -- codex --no-daemon") {
		t.Errorf("the empty states give %q: not a contract for Claude Code, one for Codex and a watch", cmds)
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
