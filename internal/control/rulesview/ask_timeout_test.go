// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestR9F3AskTimeout: a run's lists carry how long it holds a request: the copy's ask.timeout, else
// agent.CompileAskConfig's default (4 m under hold: request, 5 m otherwise); an ask block of an unexpected shape costs
// only the timeout, never the lists.
func TestAskTimeout(t *testing.T) {
	root := t.TempDir()
	for i, tc := range []struct {
		contract string
		want     time.Duration
		lists    bool
	}{
		{"fs:\n  ask_read: [/h/.config/]\nask:\n  timeout: 3m\n", 3 * time.Minute, true},
		{"fs:\n  ask_read: [/h/.config/]\n", 5 * time.Minute, true},
		{"ask:\n  hold: request\n", 4 * time.Minute, true},
		{"ask:\n  timeout: 2h\n", 5 * time.Minute, true},
		{"fs:\n  ask_read: [/h/.config/]\nask: [odd]\n", 5 * time.Minute, true},
	} {
		run := "r-aaaaaaaa-000000000000" + string(rune('1'+i)) + "-asktmo"
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte(tc.contract), 0o644); err != nil {
			t.Fatal(err)
		}
		l := RunLists(root, run)
		if l.AskTimeout != tc.want || l.OK != tc.lists {
			t.Errorf("%q: timeout %v ok %v, want %v %v", tc.contract, l.AskTimeout, l.OK, tc.want, tc.lists)
		}
		if i == 4 && len(l.AskRead) != 1 {
			t.Errorf("an odd ask block lost the lists: %+v", l)
		}
	}
	if l := RunLists(root, "r-aaaaaaaa-0000000000009-nocopy"); l.AskTimeout != 0 || l.OK {
		t.Errorf("no copy: %+v, want zero", l)
	}
}

// TestReadListsOverAListKeyBesideAMergeKey: yaml.v3 panicked on a key that is a list beside a merge key in the run's
// contract copy (config.GuardYAML). At the top the copy is not read; in ask: the lists are kept and only the timeout
// is lost, as for any ask block this reading does not expect.
func TestReadListsOverAListKeyBesideAMergeKey(t *testing.T) {
	dir := t.TempDir()
	top, ask := filepath.Join(dir, "top.yaml"), filepath.Join(dir, "ask.yaml")
	for p, text := range map[string]string{top: "{<<,[]}", ask: "fs: {write: [/w]}\nask: {<<: {}, []: 0}\n"} {
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if l := readLists(top); l.OK {
		t.Errorf("the top: %+v, want not read", l)
	}
	if l := readLists(ask); !l.OK || len(l.Write) != 1 || l.Write[0] != "/w" {
		t.Errorf("in ask: %+v, want read with write [/w]", l)
	}
}
