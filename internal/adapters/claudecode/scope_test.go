// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// Use a separate stand-in hook process for each event, as the harness does.
// SessionStart must tell pending refusals, not silently mark them as delivered.
func TestSessionStartReportsPendingRunRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    uint64
		long bool
	}{
		{"startup", 3, false},
		{"ring overflow", 50, false},
		{"bounded context", 50, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.publish(t, encodeRefusals(t, tc.n, func(r *reason.Refusal) {
				if tc.long {
					r.Payload.Target += strings.Repeat("é", reason.MaxFieldBytes)
				}
			}))
			out, err := hookProcess(t, f, payload(t, "session-start"), nil)
			if err != nil {
				t.Fatal(err)
			}
			text := context(t, out, EventSessionStart)
			assertScopeAccounting(t, text, tc.n)
			if !strings.Contains(text, "pending when this SessionStart hook read the reason file") {
				t.Errorf("pending refusals not separated from later tools: %q", text)
			}
			if s := f.state(t); s.RefusalsDelivered != tc.n || s.Deliveries != 1 || s.Sessions != 1 {
				t.Errorf("pending refusals not accounted for: %+v", s)
			}
			out, err = hookProcess(t, f, payload(t, "post-tool-use-bash"), nil)
			if err != nil || out != "" {
				t.Errorf("first allowed tool repeated startup refusals: %q, %v", out, err)
			}
		})
	}
}

// A second session may start while a tool of the first is still running. Its
// pending report must not consume the refusal before the first session's tool hook.
func TestSessionStartPreservesUncertainToolRefusals(t *testing.T) {
	for _, startup := range []uint64{0, 1, 50} {
		t.Run(fmt.Sprintf("startup-%d", startup), func(t *testing.T) {
			f := newFixture(t)
			if startup > 0 {
				f.refusals(t, startup)
			}
			start := payload(t, "session-start") // session A, abc123
			out, err := hookProcess(t, f, start, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := State{V: StateVersion, Run: testRun, Sessions: 1}
			if startup > 0 {
				assertScopeAccounting(t, context(t, out, EventSessionStart), startup)
				want.Cursor, want.RefusalsDelivered, want.Deliveries = refusalAt(startup-1).Seq, startup, 1
			}
			if got := f.state(t); !sameState(got, want) {
				t.Errorf("first start state: %+v, want %+v", got, want)
			}
			// Resuming A does not replay the startup backlog already claimed.
			out, err = hookProcess(t, f, start, nil)
			if err != nil {
				t.Fatal(err)
			}
			if text := context(t, out, EventSessionStart); text != reason.HookInstructions(f.reasonFile) {
				t.Errorf("resume replayed claimed startup refusals: %q", text)
			}
			want.Sessions++
			if got := f.state(t); !sameState(got, want) {
				t.Errorf("resume state: %+v, want %+v", got, want)
			}

			pending := uint64(2)
			if startup == 50 {
				pending = 50 // later starts must also preserve ring-overflow accounting
			}
			f.publish(t, encodeRefusals(t, startup+pending, func(r *reason.Refusal) {
				// Capture can precede the first start, with publication delayed.
				r.PID += int(r.Seq)
				r.TS = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			}))
			var p map[string]any
			if err := json.Unmarshal(start, &p); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"another-session", "abc123"} {
				p["session_id"], p["source"] = id, "resume"
				b, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				out, err = hookProcess(t, f, b, nil)
				if err != nil {
					t.Fatal(err)
				}
				assertScopeAccounting(t, context(t, out, EventSessionStart), pending)
				want.Sessions++
				if got := f.state(t); !sameState(got, want) {
					t.Errorf("%s consumed pending tool refusals: %+v, want %+v", id, got, want)
				}
			}
			// A's own tool result still receives everything the later starts previewed.
			tool := payload(t, "post-tool-use-bash")
			out, err = hookProcess(t, f, tool, nil)
			if err != nil {
				t.Fatal(err)
			}
			text := context(t, out, EventPostToolUse)
			assertScopeAccounting(t, text, pending)
			if !strings.Contains(text, refusalAt(startup+pending-1).Payload.Target) {
				t.Errorf("owning session missed its tool refusal: %q", text)
			}
			want.Cursor, want.RefusalsDelivered = refusalAt(startup+pending-1).Seq, startup+pending
			want.Deliveries++
			if got := f.state(t); !sameState(got, want) {
				t.Errorf("owning tool state: %+v, want %+v", got, want)
			}
			if out, err := hookProcess(t, f, tool, nil); err != nil || out != "" {
				t.Errorf("owning tool repeated a claimed note: %q, %v", out, err)
			}
			if got := f.state(t); !sameState(got, want) {
				t.Errorf("empty tool hook changed state: %+v, want %+v", got, want)
			}
		})
	}
}

// Check what the model receives, including counts when the ring or text cap
// cannot list each refusal. Truncating a combined setup/note loses this proof.
func assertScopeAccounting(t *testing.T, text string, want uint64) {
	t.Helper()
	if len(text) > reason.MaxRenderBytes {
		t.Errorf("context has %d bytes, limit %d", len(text), reason.MaxRenderBytes)
	}
	if !strings.Contains(text, "Scope: whole run, including startup and background work; tool call and session attribution unavailable.") {
		t.Errorf("note implies tool ownership: %q", text)
	}
	if !strings.Contains(text, fmt.Sprintf("refused %d action", want)) {
		t.Errorf("missing refusal total %d: %q", want, text)
	}
	var accounted uint64
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "- x"):
			n, err := strconv.ParseUint(strings.Fields(line)[1][1:], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			accounted += n
		case strings.HasPrefix(line, "- "):
			accounted++
		case strings.HasSuffix(line, " more not listed."):
			n, err := strconv.ParseUint(strings.Fields(line)[0], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			accounted += n
		}
	}
	if accounted != want {
		t.Errorf("model was told %d of %d refusals: %q", accounted, want, text)
	}
}
