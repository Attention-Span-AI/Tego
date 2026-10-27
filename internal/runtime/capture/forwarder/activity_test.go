// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The runtime finds the relays' activity hook by this interface; a renamed method would wire nothing silently.
var _ runtime.StreamActivityReporter = (*Manager)(nil)

// activityLog records every report a relay made to the stall check, with its reading.
type activityLog struct {
	mu    sync.Mutex
	at    []uint64
	calls atomic.Int64
}

func (a *activityLog) report(monoNS uint64) {
	a.calls.Add(1)
	a.mu.Lock()
	a.at = append(a.at, monoNS)
	a.mu.Unlock()
}

func (a *activityLog) readings() []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint64(nil), a.at...)
}

// manualMono is a monotonic clock a test sets by hand; the wall clock is never read by the meter.
type manualMono struct{ mono atomic.Uint64 }

func (c *manualMono) Now() time.Time { return time.Unix(0, int64(c.mono.Load())) }
func (c *manualMono) Mono() uint64   { return c.mono.Load() }

// TestActivityMeterIsCoalesced is capture-derive.md R21's activity half (limits R4): a relay reports at most one
// chunk per activityGrain, whatever the chunk rate and however many relays share the meter, the first chunk is
// reported at once, a clock that reads 0 (unknown, E20) reports nothing, and a meter with no callback is nil
// and costs nothing.
func TestActivityMeterIsCoalesced(t *testing.T) {
	clk := &manualMono{}
	clk.mono.Store(uint64(10 * time.Second))
	var log activityLog
	m := newActivityMeter(log.report, clk)
	for range 1000 {
		m.chunk()
	}
	if got := log.calls.Load(); got != 1 {
		t.Fatalf("1000 chunks at one instant made %d reports, want 1", got)
	}
	clk.mono.Add(uint64(activityGrain / 2))
	m.chunk()
	if got := log.calls.Load(); got != 1 {
		t.Fatalf("a chunk half a grain later made report %d, want none", got)
	}
	clk.mono.Add(uint64(activityGrain / 2))
	m.chunk()
	if got := log.calls.Load(); got != 2 {
		t.Fatalf("a chunk a grain after the last report made %d reports in all, want 2", got)
	}
	if r := log.readings(); r[1] != uint64(10*time.Second+activityGrain) {
		t.Fatalf("the report carried %d, want the chunk's own reading %d", r[1], uint64(10*time.Second+activityGrain))
	}

	// Concurrent relays on one meter, under the race detector: at most one report per grain between them.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				m.chunk()
			}
		}()
	}
	clk.mono.Add(uint64(activityGrain))
	wg.Wait()
	if got := log.calls.Load(); got > 3 {
		t.Fatalf("8 concurrent relays across one grain step made %d reports in all, want at most 3", got)
	}

	zero := newActivityMeter(log.report, &manualMono{})
	before := log.calls.Load()
	zero.chunk()
	if log.calls.Load() != before {
		t.Fatal("a chunk read on a clock that reads 0 was reported")
	}
	if newActivityMeter(nil, clk) != nil {
		t.Fatal("a meter with no callback is not nil")
	}
	var none *activityMeter
	none.chunk() // a run with no stall budget: nothing to report, and no panic
}

// TestAStreamingResponseIsActivity is R21's relay half of limits R4: a response that streams for longer than a
// stall_after reports activity while it streams, in every record mode, and not only when it ends; the readings
// rise and are the forwarder's own monotonic clock.
func TestAStreamingResponseIsActivity(t *testing.T) {
	var log activityLog
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		for range 6 {
			_, _ = w.Write([]byte("event: ping\ndata: {\"type\":\"ping\"}\n\n"))
			f.Flush()
			time.Sleep(150 * time.Millisecond)
		}
	}, Options{Clock: ledger.SystemClock{}, Activity: log.report})
	resp := h.post("/v1/messages", []byte(`{"model":"claude-test-1","stream":true}`), nil)
	var buf [256]byte
	reads := 0
	for {
		n, err := resp.Body.Read(buf[:])
		if n > 0 {
			reads++
			if reads == 1 && log.calls.Load() == 0 {
				// The first chunk is reported before it is written on: the client cannot have read it first.
				t.Error("the first chunk reached the client before it was reported")
			}
		}
		if err != nil {
			break
		}
	}
	_ = resp.Body.Close()
	got := log.readings()
	if len(got) < 4 {
		t.Fatalf("%d reports for six chunks 150 ms apart, want one per chunk past the 100 ms grain (at least 4)", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1]+uint64(activityGrain) {
			t.Fatalf("reports %d and %d are %v apart, under the %v grain", i-1, i, time.Duration(got[i]-got[i-1]), activityGrain)
		}
	}
}

// TestASilentUpstreamIsNoActivity is the other half: an upstream that answers its headers and then sends nothing
// reports nothing, so a model that stops producing still stalls. Headers are not a chunk.
func TestASilentUpstreamIsNoActivity(t *testing.T) {
	var log activityLog
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
	}, Options{Clock: ledger.SystemClock{}, Activity: log.report})
	resp := h.post("/v1/messages", []byte(`{"model":"claude-test-1","stream":true}`), nil)
	var buf [64]byte
	for {
		if _, err := resp.Body.Read(buf[:]); err != nil {
			break
		}
	}
	_ = resp.Body.Close()
	if n := log.calls.Load(); n != 0 {
		t.Fatalf("a silent upstream made %d activity reports, want none", n)
	}
}

// TestManagerStreamActivityReachesEveryListener: the runtime wires the stall check through the Manager
// (runtime.StreamActivityReporter), before Start, and every listener reports through one meter; after Start the
// wiring is refused, so a handler never reads a meter being replaced.
func TestManagerStreamActivityReachesEveryListener(t *testing.T) {
	models := []agent.ModelEndpoint{{Provider: "anthropic", Host: "a.example"}, {Provider: "openai", Host: "b.example"}}
	m, err := NewManager(models, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	var log activityLog
	m.SetStreamActivity(log.report)
	ls := m.Listeners()
	if ls[0].activity == nil || ls[0].activity != ls[1].activity {
		t.Fatalf("listeners' meters %p and %p, want one shared meter", ls[0].activity, ls[1].activity)
	}
	if err := m.Start(context.Background(), testRun, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	shared := ls[0].activity
	m.SetStreamActivity(func(uint64) {})
	if ls[0].activity != shared {
		t.Fatal("SetStreamActivity replaced the meter of a started manager")
	}
}

// TestATunnelIsActivity is the tunnel pumps' half: bytes either way through a CONNECT tunnel report activity, and a
// tunnel that carries nothing reports none.
func TestATunnelIsActivity(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := up.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	host, port := hostPort(t, up.Addr().String())
	model := agent.ModelEndpoint{Host: host, Port: port}
	p := compiledProtocols(t, model, &agent.ProxyPolicy{Connect: []string{up.Addr().String()}})
	var log activityLog
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, Clock: ledger.SystemClock{}, Activity: log.report})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	run := testRun
	run.CgroupID, run.Contract = id, &agent.RuleTable{Record: agent.RecordOff, Proxy: p}
	if err := m.Start(context.Background(), run, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	conn, reader, response := protocolConn(t, m.Listeners()[0], connectRequest(up.Addr().String()), nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT: %d", response.StatusCode)
	}
	upstream := <-accepted
	defer upstream.Close()
	time.Sleep(150 * time.Millisecond)
	if n := log.calls.Load(); n != 0 {
		t.Fatalf("an open tunnel that carried nothing made %d reports", n)
	}
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := upstream.Write([]byte("from-model")); err != nil {
		t.Fatal(err)
	}
	var b [16]byte
	if _, err := reader.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for log.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if log.calls.Load() == 0 {
		t.Fatal("bytes from the upstream through the tunnel made no activity report")
	}
	time.Sleep(activityGrain + 20*time.Millisecond)
	before := log.calls.Load()
	if _, err := conn.Write([]byte("to-model")); err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for log.calls.Load() == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if log.calls.Load() == before {
		t.Fatal("bytes from the agent through the tunnel made no activity report")
	}
}
