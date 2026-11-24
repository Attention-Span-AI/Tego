// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func baselineMachineFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("baseline: {env: {deny: [TOKEN]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func machineWithMode(t *testing.T, mode os.FileMode) *config.Machine {
	t.Helper()
	file := baselineMachineFile(t)
	if err := os.Chmod(file, mode); err != nil {
		t.Fatal(err)
	}
	machine, _, err := config.LoadSources(config.Sources{User: file}, "", os.Getuid(), config.TrustWarn)
	wantKnown := mode == 0 && os.Geteuid() == 0 // root's DAC override still reads a mode-000 file
	if err != nil || machine == nil || machine.BaselineKnown() != wantKnown {
		t.Fatalf("mode %04o fixture: known=%v, want %v; err=%v", mode, machine.BaselineKnown(), wantKnown, err)
	}
	return machine
}

func TestDashboardUnknownBaselineRefusesWidening(t *testing.T) {
	type testcase struct {
		name    string
		machine func(*testing.T) *config.Machine
		why     string
	}
	cases := []testcase{
		{"untrusted", func(t *testing.T) *config.Machine { return machineWithMode(t, 0o666) }, "group or other writable"},
		{"no snapshot", func(*testing.T) *config.Machine { return nil }, "no machine config snapshot"},
	}
	if os.Geteuid() != 0 {
		cases = append(cases, testcase{"unreadable", func(t *testing.T) *config.Machine { return machineWithMode(t, 0) }, "permission denied"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fakeBroker(t)
			s := newServer(t, fixture(t))
			s.cfg.Machine = tc.machine(t)
			cookie := login(t, s)
			for _, page := range []string{"/", "/runs", "/runs/" + harmRun, "/logs", "/approvals"} {
				w := do(s, "GET", page, "127.0.0.1:8484", cookie)
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Machine baseline UNKNOWN") || !strings.Contains(w.Body.String(), tc.why) {
					t.Errorf("read %s: %d %s", page, w.Code, w.Body.String())
				}
			}
			for _, action := range []struct{ path, decision string }{
				{"/approvals/answer", "approve"}, {"/approvals/answer", "alternate"},
				{"/runs/" + harmRun + "/resume", ""}, {"/runs/" + harmRun + "/unblock", ""},
				{"/runs/" + harmRun + "/lift", ""}, {"/runs/" + harmRun + "/restore", ""},
				{"/rules/new", ""}, {"/rules/change", ""}, {"/rules/revert", ""},
				{"/mcp/set", ""}, {"/mcp/reset", ""}, {"/routes/set", ""},
			} {
				w := post(s, action.path, url.Values{"csrf": {s.csrf}, "run": {harmRun}, "ask": {testAsk}, "decision": {action.decision}}, own, "", cookie)
				if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "Machine baseline UNKNOWN") || !strings.Contains(w.Body.String(), tc.why) {
					t.Errorf("change %s %s: %d %s", action.path, action.decision, w.Code, w.Body.String())
				}
			}
			if got.calls != 0 {
				t.Fatalf("unknown baseline authorized %d broker calls", got.calls)
			}
			w := post(s, "/approvals/answer", url.Values{"csrf": {s.csrf}, "run": {harmRun}, "ask": {testAsk}, "decision": {"deny"}}, own, "", cookie)
			if w.Code != http.StatusSeeOther || got.calls != 1 || got.approve {
				t.Fatalf("deny: %d, broker=%+v", w.Code, got)
			}
			w = doRegions(s, "/logs", "127.0.0.1:8484", cookie, "r-banner:0")
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Machine baseline UNKNOWN") {
				t.Fatalf("live region dropped unknown baseline: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDashboardUnknownBaselineStillPauses(t *testing.T) {
	root := fixture(t)
	answerAsk7(t, root, 7)
	s := newServer(t, root)
	s.cfg.Machine = machineWithMode(t, 0o666)
	cookie := login(t, s)
	called := false
	original := pauseRun
	t.Cleanup(func() { pauseRun = original })
	pauseRun = func(_ context.Context, _, run string, on bool) (runact.Paused, error) {
		if run != harmRun || !on {
			t.Fatalf("unexpected pause %s %v", run, on)
		}
		called = true
		return runact.Paused{Run: run, Word: runact.WordPaused}, nil
	}
	w := post(s, "/runs/"+harmRun+"/pause", url.Values{"csrf": {s.csrf}}, own, "", cookie)
	if w.Code != http.StatusSeeOther || !called {
		t.Fatalf("unknown baseline blocked pause: %d %s", w.Code, w.Body.String())
	}
}

func TestStopWithUnknownMachineBaseline(t *testing.T) {
	modes := []struct {
		name string
		mode os.FileMode
	}{{"untrusted", 0o666}}
	if os.Geteuid() != 0 {
		modes = append(modes, struct {
			name string
			mode os.FileMode
		}{"unreadable", 0})
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) { testStopThroughHandler(t, machineWithMode(t, tc.mode)) })
	}
}

// Mode 000 is unreadable to the ordinary owner but readable through root's DAC override.
// Neither outcome may be mislabeled by the dashboard. Kernel enforcement is owed in a guest.
func TestDashboardMode000FollowsDAC(t *testing.T) {
	s := newServer(t, fixture(t))
	s.cfg.Machine = machineWithMode(t, 0)
	cookie := login(t, s)
	w := do(s, "GET", "/approvals", "127.0.0.1:8484", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("read: %d", w.Code)
	}
	if os.Geteuid() == 0 {
		if strings.Contains(w.Body.String(), "Machine baseline UNKNOWN") || !strings.Contains(w.Body.String(), "NOT YET APPLIED") {
			t.Fatal("a mode-000 layer readable through root DAC was called unknown")
		}
	} else if !strings.Contains(w.Body.String(), "Machine baseline UNKNOWN") || !strings.Contains(w.Body.String(), "permission denied") {
		t.Fatal("an unreadable mode-000 layer was called known")
	}
}

func TestDashboardKnownBaselineNotAppliedNotice(t *testing.T) {
	file := baselineMachineFile(t)
	machine, _, err := config.LoadSources(config.Sources{User: file}, "", os.Getuid(), config.TrustAbort)
	if err != nil || !machine.BaselineKnown() {
		t.Fatalf("baseline fixture: %v %v", machine, err)
	}
	s := newServer(t, fixture(t))
	s.cfg.Machine = machine
	cookie := login(t, s)
	for _, page := range []string{"/rules?run=" + harmRun, "/runs/" + harmRun, "/approvals"} {
		w := do(s, "GET", page, "127.0.0.1:8484", cookie)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "NOT YET APPLIED to any run") || strings.Contains(w.Body.String(), "baseline UNKNOWN") {
			t.Errorf("%s: %d %s", page, w.Code, w.Body.String())
		}
	}
}

// TestDashboardBaselineBannerNeverPrintsAnUnplacedConfigValue: the banner of an UNKNOWN baseline names a $TEGO_CONFIG
// value that is not a place by the variable.
func TestDashboardBaselineBannerNeverPrintsAnUnplacedConfigValue(t *testing.T) {
	for _, value := range []string{"qzmark/c.yaml", t.TempDir() + "/qzmark-x/../c.yaml"} {
		machine, _, err := config.LoadSources(config.Sources{EnvFile: value}, "", os.Getuid(), config.TrustWarn)
		if err != nil || machine == nil || machine.BaselineKnown() {
			t.Fatalf("%q: fixture: %v", value, err)
		}
		s := newServer(t, fixture(t))
		s.cfg.Machine = machine
		w := do(s, "GET", "/", "127.0.0.1:8484", login(t, s))
		if !strings.Contains(w.Body.String(), "Machine baseline UNKNOWN") || strings.Contains(w.Body.String(), "qzmark") {
			t.Errorf("value %q: banner missing or the value is echoed: %s", value, w.Body.String())
		}
	}
}
