// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIntegrationCLIAskNotices (G5, ADR 0122): `tego run` over a contract that can ask prints, before its agent
// starts, one line with the run id and the commands that answer, and runs the desktop notifier (a stand-in named by
// the test build's TEGO_TEST_NOTIFY_SEND, never the desktop's own) once per held request, naming the run; with
// ask.notify: [] it does neither.
func TestIntegrationCLIAskNotices(t *testing.T) {
	for _, tc := range []struct {
		name   string
		notify string // appended to the machine config
		line   bool
		notice bool
	}{
		{name: "default", line: true, notice: os.Geteuid() != 0}, // a root launcher sends no desktop notice
		{name: "turned off", notify: "ask:\n  notify: []\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAskReadScene(t, "30s", 1)
			if tc.notify != "" {
				cfg := filepath.Join(s.f.dir, "config.yaml")
				b, err := os.ReadFile(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfg, append(b, tc.notify...), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stubDir := t.TempDir()
			stub, argv := filepath.Join(stubDir, "notify-send"), filepath.Join(stubDir, "argv")
			script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argv + "; done\necho --- >> " + argv + "\n"
			if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			s.env = append(s.env, "TEGO_TEST_NOTIFY_SEND="+stub)
			run, dir := s.start(t)
			id := filepath.Base(dir)
			req := s.pending(t, id)
			if tc.notice {
				var got string
				for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
					if b, err := os.ReadFile(argv); err == nil && strings.Contains(string(b), "---") {
						got = string(b)
						break
					}
				}
				if !strings.Contains(got, "tego ask "+id) || !strings.Contains(got, "iaskread") || strings.Contains(got, s.secret) {
					t.Errorf("the desktop notice %q does not name the agent and the run, or names the target", got)
				}
			}
			s.answer(t, "deny", id, req["ask_id"].(string))
			s.finish(t, run, dir)
			said := s.said.String()
			hasLine := strings.Contains(said, "tego ask "+id+", then tego approve "+id+" <ask_id>")
			if hasLine != tc.line {
				t.Errorf("tego run printed the answer line: %v, want %v\n%s", hasLine, tc.line, said)
			}
			if _, err := os.Stat(argv); (err == nil) != tc.notice {
				t.Errorf("the notifier ran: %v, want %v", err == nil, tc.notice)
			}
			if b, _ := os.ReadFile(argv); strings.Count(string(b), "---") > 1 {
				t.Errorf("one held request ran the notifier %d times", strings.Count(string(b), "---"))
			}
		})
	}
}
