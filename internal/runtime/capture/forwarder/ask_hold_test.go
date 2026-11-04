// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func askHarness(t *testing.T, maxBody int, request func(context.Context, ask.Request) (ask.Decision, error), handler http.HandlerFunc) (*Listener, *fakeSink) {
	t.Helper()
	return askHarnessWithin(t, maxBody, time.Second, request, handler)
}

func askHarnessWithin(t *testing.T, maxBody int, timeout time.Duration, request func(context.Context, ask.Request) (ask.Decision, error), handler http.HandlerFunc) (*Listener, *fakeSink) {
	t.Helper()
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.Listener.Addr().String())
	p := policyFor(t, host, port, []string{"/allowed"}, []string{"POST"})
	m, err := NewManager([]agent.ModelEndpoint{{Host: host, Port: port}}, Options{HTTPPolicy: p, Transport: up.Client().Transport, MaxBody: maxBody})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	rt := &agent.RuleTable{Record: agent.RecordSummary, HTTP: p, AskConfig: &agent.AskConfig{Hold: agent.AskHoldRequest, Timeout: agent.Duration(timeout), MaxPending: 8}, NetAsk: []agent.NetRule{{Host: host, Port: port, Proto: agent.ProtoTCP, Verdict: agent.VerdictAsk}}}
	if err = m.ConfigureAsk(rt, request); err != nil {
		t.Fatal(err)
	}
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer cgroup unavailable: %v", err)
	}
	run := testRun
	run.CgroupID, run.Contract = id, rt
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err = m.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	return m.Listeners()[0], sink
}

func TestRequestAskActualTLSCoalescesRetriesAndSeparatesBodiesCredentials(t *testing.T) {
	var asks, upstreams atomic.Int64
	queued := make(chan ask.Request, 8)
	approve := make(chan struct{})
	// Peer admission and instrumented TLS setup are not part of the coalescing contract. Use
	// the test's deadline here; the separate deadline-refusal test keeps its one-second hold.
	budget := time.Minute
	if deadline, ok := t.Deadline(); ok {
		budget = time.Until(deadline)
	}
	l, _ := askHarnessWithin(t, 4096, budget, func(ctx context.Context, r ask.Request) (ask.Decision, error) {
		asks.Add(1)
		queued <- r
		select {
		case <-approve:
			return ask.Decision{Approved: true}, nil
		case <-ctx.Done():
			return ask.Decision{}, ctx.Err()
		}
	}, func(w http.ResponseWriter, r *http.Request) {
		upstreams.Add(1)
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "one")
		_, _ = w.Write(append([]byte("echo:"), b...))
	})
	client := &http.Client{}
	t.Cleanup(client.CloseIdleConnections)
	results := make(chan string, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, _ := http.NewRequestWithContext(t.Context(), "POST", l.BaseURL()+"/allowed?token=never-metadata", strings.NewReader("same"))
			r.Header.Set("Authorization", "Bearer first-credential")
			r.Header.Set(RetryHeader, string(rune('0'+i)))
			resp, e := client.Do(r)
			if e != nil {
				results <- e.Error()
				return
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("X-Upstream") != "one" {
				results <- "bad response"
				return
			}
			results <- string(b)
		}(i)
	}
	select {
	case req := <-queued:
		if req.PID != os.Getpid() || strings.Contains(req.Target, "token") || strings.Contains(req.Target, "credential") {
			t.Fatal(req)
		}
	case early := <-results:
		t.Fatalf("request finished before approval: %s", early)
	case <-t.Context().Done():
		t.Fatal("test ended before the request asked")
	}
	if upstreams.Load() != 0 {
		t.Fatal("upstream request before answer")
	}
	close(approve)
	wg.Wait()
	close(results)
	for got := range results {
		if got != "echo:same" {
			t.Fatal(got)
		}
	}
	if asks.Load() != 1 || upstreams.Load() != 1 {
		t.Fatalf("same retry asks=%d upstream=%d", asks.Load(), upstreams.Load())
	}
	for _, tc := range []struct{ body, credential string }{{"changed", "first-credential"}, {"same", "second-credential"}} {
		r, _ := http.NewRequestWithContext(t.Context(), "POST", l.BaseURL()+"/allowed?token=never-metadata", strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.credential)
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
	}
	if asks.Load() != 3 || upstreams.Load() != 3 {
		t.Fatalf("different identity asks=%d upstream=%d", asks.Load(), upstreams.Load())
	}
}

func TestRequestAskConnectionNominationSeparatesApproval(t *testing.T) {
	base, err := http.NewRequest("POST", "https://fixed.example/allowed", strings.NewReader("same"))
	if err != nil {
		t.Fatal(err)
	}
	base.Header.Set("Authorization", "Bearer credential")
	key, err := requestAskIdentity(base, os.Getpid(), "fixed.example:443", "", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	nominated := base.Clone(t.Context())
	nominated.Header.Set("Connection", "Authorization")
	other, err := requestAskIdentity(nominated, os.Getpid(), "fixed.example:443", "", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if key == other {
		t.Fatal("forwarded credential removal reused approval for the authenticated request")
	}
	// Prove this distinction has an actual forwarding effect, rather than
	// merely asserting the implementation's choice of fingerprint fields.
	plain, stripped := make(http.Header), make(http.Header)
	copyHeader(plain, base.Header)
	copyHeader(stripped, nominated.Header)
	if plain.Get("Authorization") == "" || stripped.Get("Authorization") != "" {
		t.Fatalf("forwarded authorization plain=%q nominated=%q", plain.Get("Authorization"), stripped.Get("Authorization"))
	}
}

func TestRequestAskDeadlineRefusesWithTimeoutBeforeUpstream(t *testing.T) {
	var up atomic.Int64
	l, sink := askHarness(t, 64, func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		<-ctx.Done()
		return ask.Decision{}, ctx.Err()
	}, func(http.ResponseWriter, *http.Request) { up.Add(1) })
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(l.BaseURL()+"/allowed", "text/plain", strings.NewReader("complete"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), ask.ReasonTimeout) || up.Load() != 0 {
		t.Fatalf("deadline status=%d body=%q upstream=%d err=%v", resp.StatusCode, body, up.Load(), err)
	}
	found := false
	for _, e := range sink.waitFor(t, record.KindNet, 2) {
		if e.Verdict == record.VerdictRefused && e.Reason == record.Reason(ask.ReasonTimeout) {
			found = true
		}
	}
	if !found {
		t.Fatal("timeout refusal absent from actual forwarder events")
	}
}

func TestRequestAskDenialOversizeStaticPolicyAndNonReplayable(t *testing.T) {
	t.Run("deny and complete-body bound", func(t *testing.T) {
		var asks, up atomic.Int64
		l, sink := askHarness(t, 16, func(context.Context, ask.Request) (ask.Decision, error) {
			asks.Add(1)
			return ask.Decision{Reason: ask.ReasonDenied}, nil
		}, func(http.ResponseWriter, *http.Request) { up.Add(1) })
		for _, tc := range []struct {
			path, body string
			status     int
		}{{"/denied", "x", 403}, {"/allowed", strings.Repeat("x", 64), 413}, {"/allowed", "small", 403}} {
			resp, e := http.Post(l.BaseURL()+tc.path, "text/plain", strings.NewReader(tc.body))
			if e != nil {
				t.Fatal(e)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("%s = %d", tc.path, resp.StatusCode)
			}
		}
		if asks.Load() != 1 || up.Load() != 0 {
			t.Fatalf("asks=%d upstream=%d", asks.Load(), up.Load())
		}
		refusals := 0
		for _, e := range sink.waitFor(t, record.KindNet, 5) {
			if e.Verdict == record.VerdictRefused {
				refusals++
			}
		}
		if refusals != 3 {
			t.Fatalf("refusal count %d", refusals)
		}
	})
	t.Run("large response never redispatches", func(t *testing.T) {
		var up atomic.Int64
		l, _ := askHarness(t, 16, func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{Approved: true}, nil }, func(w http.ResponseWriter, _ *http.Request) {
			up.Add(1)
			_, _ = w.Write([]byte(strings.Repeat("z", 64)))
		})
		for i, status := range []int{200, 503} {
			resp, e := http.Post(l.BaseURL()+"/allowed", "text/plain", strings.NewReader("x"))
			if e != nil {
				t.Fatal(e)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != status {
				t.Fatalf("retry%d = %d", i, resp.StatusCode)
			}
		}
		if up.Load() != 1 {
			t.Fatalf("redispatched %d", up.Load())
		}
	})
}

func TestRequestAskCancelledWaiterDoesNotCancelSharedApproval(t *testing.T) {
	started, approve := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var asks, up atomic.Int64
	l, _ := askHarness(t, 1024, func(ctx context.Context, r ask.Request) (ask.Decision, error) {
		asks.Add(1)
		once.Do(func() { close(started) })
		select {
		case <-approve:
			return ask.Decision{Approved: true}, nil
		case <-ctx.Done():
			return ask.Decision{}, ctx.Err()
		}
	}, func(w http.ResponseWriter, _ *http.Request) { up.Add(1); _, _ = w.Write([]byte("ok")) })
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := http.NewRequestWithContext(ctx, "POST", l.BaseURL()+"/allowed", strings.NewReader("x"))
	done := make(chan error, 1)
	go func() {
		resp, e := http.DefaultClient.Do(r)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- e
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no ask")
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled client succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled client did not return")
	}
	// Client cancellation can return before the server observes it. The ask
	// callback proves this sole handler has already entered the WaitGroup; wait
	// for it to retire before approving, so this exercises a cancelled pending
	// waiter rather than cancellation racing an already-approved dispatch.
	retired := make(chan struct{})
	go func() {
		l.handlers.Wait()
		close(retired)
	}()
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("cancelled server handler did not retire before approval")
	}
	if up.Load() != 0 {
		t.Fatalf("upstream dispatched before approval: %d", up.Load())
	}
	close(approve)
	retry, _ := http.NewRequest("POST", l.BaseURL()+"/allowed", strings.NewReader("x"))
	resp, e := http.DefaultClient.Do(retry)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	// Retrying after cancellation retains the full identical request identity.
	if resp.StatusCode != 200 || up.Load() != 1 || asks.Load() != 1 {
		t.Fatalf("status=%d upstream=%d asks=%d", resp.StatusCode, up.Load(), asks.Load())
	}
}

// An approved response kept for retries holds the run's shared capture budget only for its retry window
// (R24). The window used to end only when another request-ask arrived and swept it, so a run that asked
// nothing more kept every finished replay pinned until it ended, and a later body the budget could no longer
// hold was refused 413 before it reached the sweep.
func TestRequestAskReplayIsReleasedWhenItsRetryWindowEnds(t *testing.T) {
	l, _ := askHarness(t, 64<<10, func(context.Context, ask.Request) (ask.Decision, error) {
		return ask.Decision{Approved: true}, nil
	}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(strings.Repeat("z", 32<<10)))
	})
	a := l.opts.askRequests
	a.mu.Lock()
	a.ttl = 200 * time.Millisecond
	a.mu.Unlock()
	resp, err := http.Post(l.BaseURL()+"/allowed", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approved request = %d", resp.StatusCode)
	}
	// replayHeld is the bytes finished entries hold for a retry, and how many entries the table keeps.
	replayHeld := func() (entries, held int, finished bool) {
		a.mu.Lock()
		defer a.mu.Unlock()
		finished = true
		for _, e := range a.entries {
			finished = finished && e.finished
			if e.replay != nil {
				e.replay.mu.Lock()
				held += e.replay.body.reserved()
				e.replay.mu.Unlock()
			}
		}
		return len(a.entries), held, finished
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, held, finished := replayHeld(); finished && n == 1 && held >= 32<<10 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("approved response not kept for retries: entries=%d held=%d finished=%v", n, held, finished)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// No further request asks: the end of the window alone gives the replay back.
	deadline = time.Now().Add(5 * time.Second)
	for {
		n, held, _ := replayHeld()
		if n == 0 && held == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired replay still pinned without another ask: entries=%d held=%d", n, held)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAskReplayPinsBudgetUntilLastReader(t *testing.T) {
	b := newBudget(1024, 16)
	w := &askReplay{writer: httptest.NewRecorder(), body: b.hold(16), valid: true}
	_, _ = w.Write([]byte("pinned"))
	w.finish(true)
	_, _, body, release, ok := w.acquire()
	if !ok || string(body) != "pinned" {
		t.Fatal("missing replay")
	}
	used := b.used.Load()
	w.drop()
	if b.used.Load() != used || string(body) != "pinned" {
		t.Fatal("eviction invalidated live reader")
	}
	release()
	if b.used.Load() != 0 {
		t.Fatalf("leaked replay bytes %d", b.used.Load())
	}
}
