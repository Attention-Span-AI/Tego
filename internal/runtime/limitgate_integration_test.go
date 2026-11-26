// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/capture/forwarder"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// lagCgroup is a cgroup manager whose kill lands killLag after the watcher wrote it: the window between the limit line and
// the end of the run, which is a few hundred milliseconds on a loaded machine and which this makes the same on every one.
type lagCgroup struct {
	cgroup.Manager
	lag time.Duration
	wg  sync.WaitGroup
}

func (k *lagCgroup) Kill(c cgroup.Cgroup) error {
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		time.Sleep(k.lag)
		_ = k.Manager.Kill(c) // the run may be gone by then: a request refused at the door can end an agent first
	}()
	return nil
}

// TestIntegrationALimitStopsTheModelAtTheDoorWhileTheKillLands is the admission gate on a real run, the forwarder, the watcher
// and a real kernel together: the model answers every call with the same tool_use, `repeats: 3`, and an agent that calls
// 200 times without pausing. The kill is made to land 400 ms after the limit line (lagCgroup), so the agent has the whole
// window to spend in. What the ledger shows is that the run ended as ever (124, one limit line, run_end limit) and that
// nothing was spent in the window: the upstream answered only the calls admitted before the gate closed, the rest were
// turned away and recorded as refused under limits.repeats, and no request was admitted after the first refusal.
func TestIntegrationALimitStopsTheModelAtTheDoorWhileTheKillLands(t *testing.T) {
	agentBin := modelAgentBinary(t)
	var upstreamCalls atomic.Int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		n := upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"msg_%03d","type":"message","role":"assistant","model":"claude-test-1","stop_reason":"tool_use",`+
			`"content":[{"type":"tool_use","id":"toolu_%03d","name":"read_file","input":{"path":"notes.txt"}}],`+
			`"usage":{"input_tokens":40,"output_tokens":20,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`, n, n)
	}))
	t.Cleanup(up.Close)
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, modelContract("igate", agentBin, u.Hostname(), port, "\n  repeats: 3"))
	mgr, err := forwarder.NewManager(f.rt.Contract.Models, forwarder.Options{
		Transport: up.Client().Transport,
		Deriver:   derive.NewDispatcher([]derive.Parser{anthropic.New(u.Hostname())}),
		Bodies:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := config.InvokingUID()
	cgm, err := cgroup.Detect(uid)
	if err != nil {
		t.Skipf("no delegated cgroup subtree for this process: %v", err)
	}
	killer := &lagCgroup{Manager: cgm, lag: 400 * time.Millisecond}
	t.Cleanup(killer.wg.Wait)

	deps := f.deps(t, nil)
	deps.Capture = []source.Source{mgr}
	deps.Cgroups = killer
	deps.Environ = append(deps.Environ, "MODEL_CALLS="+strconv.Itoa(loopCalls))
	res, err := Run(context.Background(), f.rt, []string{agentBin}, deps)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.ExitCode != identity.ExitLimit || res.Reason != string(identity.ReasonLimit) {
		t.Fatalf("the run ended %d (%s), want %d (limit): the gate must not change how a run ends", res.ExitCode, res.Reason, identity.ExitLimit)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	evs := events(t, dirs[0])
	lim := limitEvent(t, evs)
	if lim.Which != record.LimitRepeats || lim.Value != 3 || lim.Ceiling != 3 {
		t.Fatalf("limit payload %+v, want repeats 3 at a ceiling of 3: the gate must not change how a limit is counted", lim)
	}
	if n := decisionsBeforeLimit(evs); n != 3 {
		t.Fatalf("%d decisions before the limit line, want 3", n)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndLimit || end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v, want limit/124", end)
	}

	refusals := limitRefusals(evs)
	after := responsesAfterLimit(evs)
	t.Logf("%d calls reached the upstream; %d requests turned away; %d responses recorded after the limit line", upstreamCalls.Load(), len(refusals), after)
	for i, e := range evs {
		if e.Kind == record.KindLimit {
			t.Logf("the ledger from the limit line on: %v", kinds(evs[i:min(i+12, len(evs))]))
			break
		}
	}
	if len(refusals) == 0 {
		t.Fatal("no request was turned away: an agent that never paused had 400 ms between the limit line and the kill")
	}
	assertNothingAdmittedAfterTheGateClosed(t, evs, record.LimitRepeats)
	// What the gate buys: without it the 200 calls are answered in the window (the same test fails with 197 after the limit
	// line); with it the answers after the limit line are the calls in flight when the gate closed, one for an agent that
	// calls one at a time, and the exchanges the pipeline had not yet counted (see inFlightAllowance). Half the calls is far from both.
	if after > inFlightAllowance {
		t.Fatalf("%d responses recorded after the limit line, want only the calls that were in flight or not yet counted (at most %d)", after, inFlightAllowance)
	}
	if n := upstreamCalls.Load(); n > 3+inFlightAllowance {
		t.Fatalf("%d calls reached the upstream, want the 3 that crossed and the calls in flight or not yet counted", n)
	}
	for _, e := range refusals {
		if !strings.HasPrefix(e.Rule, "limits.repeats") || e.Reason != record.ReasonLimitRepeats {
			t.Fatalf("refusal %+v, want rule limits.repeats and reason limit-repeats", e)
		}
	}
}
