// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// TestDecodeEveryDocumentedShape: each documented payload decodes to its event, and a subagent's carries its id.
func TestDecodeEveryDocumentedShape(t *testing.T) {
	for name, event := range payloadNames {
		in, err := decodeInput(bytes.NewReader(payload(t, name)))
		if err != nil || in.HookEventName != event || in.SessionID != "abc123" {
			t.Errorf("%s: %+v, %v", name, in, err)
		}
	}
	if in, _ := decodeInput(bytes.NewReader(payload(t, "stop-repeat"))); !in.StopHookActive {
		t.Errorf("stop-repeat: stop_hook_active not read")
	}
	if in, _ := decodeInput(bytes.NewReader(payload(t, "post-tool-use-subagent"))); in.AgentID != "agent_7f2c" {
		t.Errorf("subagent: agent_id %q", in.AgentID)
	}
}

func TestDecodeRefuses(t *testing.T) {
	for _, in := range []string{"", "null", "[]", `"PostToolUse"`, "{", `{"hook_event_name": 7}`, `{"session_id":"s"}`} {
		if _, err := decodeInput(strings.NewReader(in)); !errors.Is(err, errInput) {
			t.Errorf("%q: %v, want errInput", in, err)
		}
	}
}

// TestDiscover: the reason file is --reason when given, else $TEGO_REASON, and only last-refusal.json in a run's
// runtime directory by convention; neither given is no run at all.
func TestDiscover(t *testing.T) {
	xdg := "/home/u/.cache/run"
	env := func(reasonPath string, inheritsXDG bool) func(string) string {
		return func(k string) string {
			if k == envRuntimeDir && !inheritsXDG {
				return ""
			}
			return map[string]string{envReason: reasonPath, envRuntimeDir: xdg}[k]
		}
	}
	dirFor, err := reason.DirFor(1000, testRun)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		flag      string
		flagSet   bool
		envReason string
		found     bool
		ok        bool
		noXDG     bool // the hook did not inherit the launcher's XDG_RUNTIME_DIR (env.pass left it out)
	}{
		{"nothing", "", false, "", false, true, false},
		{"TEGO_REASON under /run/user", "", false, dirFor + reason.FileName, true, true, false},
		{"TEGO_REASON under XDG_RUNTIME_DIR", "", false, xdg + "/tego/" + testRun + "/" + reason.FileName, true, true, false},
		{"--reason wins", dirFor + reason.FileName, true, "/elsewhere/last-refusal.json", true, true, false},
		{"--reason empty", "", true, dirFor + reason.FileName, true, false, false},
		{"another uid", "/run/user/1001/tego/" + testRun + "/" + reason.FileName, true, "", true, false, false},
		{"another name", dirFor + "events.jsonl", true, "", true, false, false},
		{"relative", "tego/" + testRun + "/" + reason.FileName, true, "", true, false, false},
		{"not clean", "/run/user/1000/tego/x/../" + testRun + "/" + reason.FileName, true, "", true, false, false},
		{"the ledger's copy", "/home/u/.tego/runs/" + testRun + "/" + reason.FileName, true, "", true, false, false},
		{"no run directory", "/run/user/1000/tego/" + reason.FileName, true, "", true, false, false},
		{"deeper", dirFor + "x/" + reason.FileName, true, "", true, false, false},
		// TEGO_REASON is the launcher's, runtime-reserved and installed last: its own shape, <base>/tego/<run>/, is
		// enough, since a contract's env.pass may leave XDG_RUNTIME_DIR out of the agent's environment.
		{"TEGO_REASON under a base not inherited", "", false, xdg + "/tego/" + testRun + "/" + reason.FileName, true, true, true},
		{"TEGO_REASON under /run/user, no XDG_RUNTIME_DIR", "", false, dirFor + reason.FileName, true, true, true},
		{"TEGO_REASON not under tego/<run>", "", false, "/home/u/.tego/runs/" + testRun + "/" + reason.FileName, true, false, true},
		{"TEGO_REASON with no run directory", "", false, xdg + "/tego/" + reason.FileName, true, false, true},
		{"TEGO_REASON relative", "", false, "x/tego/" + testRun + "/" + reason.FileName, true, false, true},
		{"TEGO_REASON not clean", "", false, xdg + "/tego/x/../" + testRun + "/" + reason.FileName, true, false, true},
		{"TEGO_REASON under the root", "", false, "/tego/" + testRun + "/" + reason.FileName, true, false, true},
		// --reason is a settings file's value: held to the conventions the hook can check, as before.
		{"--reason under a base not inherited", xdg + "/tego/" + testRun + "/" + reason.FileName, true, "", true, false, true},
		// ... unless it is $TEGO_REASON itself, as the settings file the launcher provisions writes it (ADR 0063 (5),
		// as amended): the value is then the launcher's and is taken under its rule.
		{"--reason that is TEGO_REASON, under a base not inherited", xdg + "/tego/" + testRun + "/" + reason.FileName, true,
			xdg + "/tego/" + testRun + "/" + reason.FileName, true, true, true},
		{"--reason that is not TEGO_REASON, under a base not inherited", xdg + "/tego/" + testRun + "/" + reason.FileName, true,
			xdg + "/tego/other/" + reason.FileName, true, false, true},
		{"--reason that is TEGO_REASON, under the root", "/tego/" + testRun + "/" + reason.FileName, true,
			"/tego/" + testRun + "/" + reason.FileName, true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found, err := discover(tc.flag, tc.flagSet, env(tc.envReason, !tc.noXDG), 1000)
			if found != tc.found || (err == nil) != tc.ok {
				t.Fatalf("found %v, err %v; want found %v, ok %v", found, err, tc.found, tc.ok)
			}
			if tc.ok && tc.found && (got.run != testRun || filepath.Join(got.dir, reason.FileName) != got.reasonFile) {
				t.Errorf("target %+v", got)
			}
		})
	}
}

// FuzzHookInput is acceptance (9): no stdin makes the hook panic, exit with anything but 0 in json mode, or print
// anything but one hookSpecificOutput object.
func FuzzHookInput(f *testing.F) {
	entries, err := os.ReadDir(filepath.Join("testdata", "payloads"))
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("testdata", "payloads", e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"hook_event_name":"Stop","stop_hook_active":"yes"}`))
	f.Add([]byte("\xff{"))
	f.Fuzz(func(t *testing.T, stdin []byte) {
		fx := newFixture(t)
		fx.refusals(t, 3)
		_, _ = decodeInput(bytes.NewReader(stdin))
		r := fx.hook(t, stdin)
		if r.code != 0 {
			t.Errorf("exit %d", r.code)
		}
		if r.stdout != "" && !json.Valid([]byte(r.stdout)) {
			t.Errorf("stdout %q", r.stdout)
		}
	})
}
