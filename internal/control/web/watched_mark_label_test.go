// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"path/filepath"
	"strings"
	"testing"
)

// TestWatchOnlyMarkNamesItself (C115): a line a live mark matched on a watched run reads "Marked live at … by …:
// recorded only, not enforced" on the run page, in Logs, in the CSV and on its line page, never "Blocked live" (it
// refused nothing) and never the bare "Watched only" that names no mark.
func TestWatchOnlyMarkNamesItself(t *testing.T) {
	root := liveBlockFixture(t)
	p := filepath.Join(root, harmRun, "events.jsonl")
	b := readFile(t, p)
	b = strings.Replace(b, `"verdict":"refused","rule":"live.block[exec:ls]"`, `"verdict":"observed","rule":"live.block[exec:ls]"`, 1)
	writeRaw(t, p, b)
	// A watched run writes no refused mirror of a line it only recorded.
	b = strings.Replace(readFile(t, p), `"rule":"live.block[exec:ls]","reason":"exec-not-allowed","op":"exec"`, `"rule":"unmatched","reason":"exec-not-allowed","op":"exec"`, 1)
	writeRaw(t, p, b)
	// The run is only watched.
	writeRaw(t, p, strings.Replace(readFile(t, p), `"tier":"landlock"`, `"tier":"observe"`, 1))
	s := newServer(t, root)
	c := login(t, s)
	const want = "Marked live at "
	for name, page := range map[string]string{
		"run page":  get(t, s, c, "/runs/"+harmRun),
		"logs":      get(t, s, c, "/logs?q=ls"),
		"line page": get(t, s, c, "/runs/"+harmRun+"/lines/8"),
	} {
		if !strings.Contains(page, want) || !strings.Contains(page, "recorded only, not enforced") {
			t.Errorf("%s does not say the mark by name", name)
		}
		if strings.Contains(page, "Blocked live at ") {
			t.Errorf("%s calls a watched mark a block", name)
		}
	}
	if got := csvRuleWords(t, s, c, "q=ls")[harmRun+"-8"]; !strings.HasPrefix(html.UnescapeString(got), want) {
		t.Errorf("the CSV words the mark %q", got)
	}
}
