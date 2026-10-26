// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// interactivePairs are the interactive contracts here and the demo kit's contract each one is the same as. The kit's
// contracts are the ones proven on a laptop; these are the copy-paste forms of them, so a line that matters changes in
// both or the test fails (no copy drift).
var interactivePairs = []struct {
	example, kit string
	// demoRecord: the kit's contract records as a short demo does (record: summary with reads: held, so the
	// dashboard shows what matters, and a wall that ends the demo), while the example records a long working
	// session (record: full, stall_after); record, fs.reads and limits are left out of the comparison.
	demoRecord bool
}{
	{"claude-code-interactive.yaml", "claude-code.yaml", false},
	{"codex.yaml", "codex.yaml", false},
	{"codex-chatgpt.yaml", "codex-chatgpt.yaml", true},
}

// withoutRecording drops the keys a demoRecord pair may differ in.
func withoutRecording(c map[string]any) map[string]any {
	delete(c, "record")
	delete(c, "limits")
	if f, ok := c["fs"].(map[string]any); ok {
		delete(f, "reads")
	}
	return c
}

// loadNormalised reads a contract as plain data with what legitimately differs between the two forms taken out: the
// name, the machine-specific fields the demo kit fills in (@@words@@) and the example asks you to CHANGE.
func loadNormalised(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := yaml.Unmarshal(b, &c); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	delete(c, "name")
	if f, ok := c["fs"].(map[string]any); ok {
		delete(f, "deny_read") // the user's own ~/.codex files, listed by name in the example and filled in by demo.sh
	}
	if e, ok := c["env"].(map[string]any); ok {
		if set, ok := e["set"].(map[string]any); ok {
			delete(set, "CODEX_HOME") // a directory of the user's own
		}
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				x[k] = walk(e)
			}
		case []any:
			for i, e := range x {
				x[i] = walk(e)
			}
		case string:
			switch {
			case strings.Contains(x, "codex-code-mode-host"):
				return "<codex helper>"
			case strings.Contains(x, "cc-socks/"):
				return "<runtime dir>/cc-socks/"
			case strings.HasSuffix(x, "/codex-chatgpt/") || x == "@@CODEXHOME@@/":
				return "<codex home>/"
			}
		}
		return v
	}
	return walk(c).(map[string]any)
}

// TestInteractiveExamplesMatchTheDemoKit: each interactive example is the demo kit's contract with only its own paths
// changed, so the example never lags the demo kit's contract.
func TestInteractiveExamplesMatchTheDemoKit(t *testing.T) {
	for _, p := range interactivePairs {
		t.Run(p.example, func(t *testing.T) {
			got := loadNormalised(t, filepath.Join(pkgDir, p.example))
			want := loadNormalised(t, filepath.Join(pkgDir, "..", "demo", "contracts", p.kit))
			if p.demoRecord {
				got, want = withoutRecording(got), withoutRecording(want)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s and examples/demo/contracts/%s differ beyond their own paths:\n%s: %v\n%s: %v", p.example, p.kit, p.example, got, p.kit, want)
			}
		})
	}
}

// TestInteractiveExamplesEndNoWorkingSession pins three things: no wall (a hard cap that ends a working
// session), a stall_after in its place, and no cost_usd (refused without a price table).
func TestInteractiveExamplesEndNoWorkingSession(t *testing.T) {
	for _, p := range interactivePairs {
		c := loadNormalised(t, filepath.Join(pkgDir, p.example))
		lim, _ := c["limits"].(map[string]any)
		if _, ok := lim["wall"]; ok {
			t.Errorf("%s sets limits.wall: a hard cap ends a working interactive session; use stall_after", p.example)
		}
		if _, ok := lim["stall_after"]; !ok {
			t.Errorf("%s has no limits.stall_after", p.example)
		}
		if _, ok := lim["cost_usd"]; ok {
			t.Errorf("%s sets limits.cost_usd: the run is refused without a price table and counted model calls", p.example)
		}
	}
}
