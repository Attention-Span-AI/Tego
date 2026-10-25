// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// testRun is the run every fixture is: a run id's shape, one path element.
const testRun = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"

// fixture is a run's runtime directory as the launcher leaves it for the hook: <xdg>/tego/<run>/ holding hook-state/
// and, once the run has refused something, last-refusal.json.
type fixture struct {
	xdg, dir, reasonFile string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	xdg := t.TempDir()
	dir := filepath.Join(xdg, runtimeDirName, testRun)
	if err := os.MkdirAll(filepath.Join(dir, StateDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	return &fixture{xdg: xdg, dir: dir, reasonFile: filepath.Join(dir, reason.FileName)}
}

// getenv is the environment a hook inside the run sees.
func (f *fixture) getenv(name string) string {
	switch name {
	case envReason:
		return f.reasonFile
	case envRuntimeDir:
		return f.xdg
	}
	return ""
}

// env is getenv as a process environment, for hook processes.
func (f *fixture) env() []string {
	return append(os.Environ(), helperEnv+"=1", envReason+"="+f.reasonFile, envRuntimeDir+"="+f.xdg)
}

// refusalAt is the run's i-th refusal (from 0): its ledger seq leaves room for the lines between refusals.
func refusalAt(i uint64) reason.Refusal {
	return reason.Refusal{Seq: 100 + 3*i, TS: time.Date(2026, 10, 24, 12, 0, 0, int(i), time.UTC), PID: 4242,
		Payload: record.RefusedPayload{Op: "write", Target: fmt.Sprintf("/home/user/out-%02d.txt", i),
			Reason: record.ReasonWriteOutsideContract, Rule: "fs.write"}}
}

// encodeRefusals is the reason file after the run's first n refusals: the newest RingSize of them listed.
func encodeRefusals(t testing.TB, n uint64, mutate func(*reason.Refusal)) []byte {
	t.Helper()
	var recent []reason.Refusal
	for i := n - min(n, reason.RingSize); i < n; i++ {
		r := refusalAt(i)
		if mutate != nil {
			mutate(&r)
		}
		recent = append(recent, r)
	}
	b, err := reason.Encode(testRun, n, recent)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// refusals publishes the reason file after the run's first n refusals, as the ledger writer does: whole, by rename.
func (f *fixture) refusals(t testing.TB, n uint64) {
	t.Helper()
	f.publish(t, encodeRefusals(t, n, nil))
}

func (f *fixture) publish(t testing.TB, b []byte) {
	t.Helper()
	tmp := f.reasonFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, f.reasonFile); err != nil {
		t.Fatal(err)
	}
}

// result is one hook invocation's output.
type result struct {
	stdout, stderr string
	code           int
}

// hook runs the hook in this process over payload with args after the harness word.
func (f *fixture) hook(t testing.TB, payload []byte, args ...string) result {
	t.Helper()
	return f.hookWithin(t, LockBudget, payload, args...)
}

func (f *fixture) hookWithin(t testing.TB, budget time.Duration, payload []byte, args ...string) result {
	t.Helper()
	var o, e bytes.Buffer
	code := run(bytes.NewReader(payload), &o, &e, append([]string{Harness}, args...), f.getenv, uint32(os.Getuid()), budget) //nolint:gosec // a uid fits 32 bits
	return result{o.String(), e.String(), code}
}

// state is hook-state/state.json, the zero State when there is none.
func (f *fixture) state(t testing.TB) State {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, StateDirName, StateFileName))
	if os.IsNotExist(err) {
		return State{}
	}
	if err != nil {
		t.Fatal(err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("state.json: %v: %s", err, b)
	}
	return s
}

// payload is a documented payload shape from testdata/payloads.
func payload(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "payloads", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// payloadNames is every documented shape the tests replay (Claude Code 2.1.310, hooks reference, read 2026-10-24;
// the same shapes test/e2e/reason-claude/fakeclaude sends), by its event.
var payloadNames = map[string]string{
	"session-start":              EventSessionStart,
	"session-start-no-model":     EventSessionStart,
	"post-tool-use-bash":         EventPostToolUse,
	"post-tool-use-read":         EventPostToolUse,
	"post-tool-use-write":        EventPostToolUse,
	"post-tool-use-subagent":     EventPostToolUse,
	"post-tool-use-failure-bash": EventPostToolUseFailure,
	"post-tool-batch":            EventPostToolBatch,
	"stop":                       EventStop,
	"stop-repeat":                EventStop,
}

// quietPayloads are the shapes the hook answers with nothing whatever the reason file holds: a Stop with
// stop_hook_active, after a Stop hook already kept the turn going.
var quietPayloads = map[string]bool{"stop-repeat": true}

// context is the additionalContext of a hook's JSON stdout, failing the test when stdout is not that object.
func context(t testing.TB, stdout, event string) string {
	t.Helper()
	var o struct {
		HookSpecificOutput struct {
			HookEventName     string `json:"hookEventName"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(stdout)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		t.Fatalf("stdout is not one hookSpecificOutput object: %v: %q", err, stdout)
	}
	if o.HookSpecificOutput.HookEventName != event {
		t.Errorf("hookEventName %q, want %q", o.HookSpecificOutput.HookEventName, event)
	}
	return o.HookSpecificOutput.AdditionalContext
}
