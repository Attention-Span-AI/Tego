// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/capture/forwarder"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// dualReply is the model's answer, with a usage both producers would count if both emitted it.
const dualReply = `{"id":"msg_dual","type":"message","role":"assistant","model":"claude-test",` +
	`"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",` +
	`"usage":{"input_tokens":1000,"output_tokens":100}}`

// ownCgroupID is the cgroup v2 id of the test process: the run's cgroup here, because the test process is
// the agent that dials the forwarder, and R19a admits only a peer in the run's cgroup.
func ownCgroupID(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no /proc/self/cgroup: %v", err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		p, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat("/sys/fs/cgroup"+strings.TrimSuffix(p, " (deleted)"), &st); err != nil {
			t.Skipf("the cgroup v2 directory of this process: %v", err)
		}
		return st.Ino
	}
	t.Skip("this process is in no cgroup v2 hierarchy")
	return 0
}

// monoClock is limits.Clock over the system clock.
type monoClock struct{ start time.Time }

func (c monoClock) Now() time.Time         { return time.Now() }
func (c monoClock) MonoNS() uint64         { return uint64(time.Since(c.start)) + 1 }
func (monoClock) Kill(cgroup.Cgroup) error { return nil }

// TestForwardedExchangeIsEmittedOnceWithBothSourcesRunning is capture-derive.md I11: at capture: auto a
// run carries both producers (capture.Select), and one model exchange must reach the ledger once, so its
// usage and cost are counted once. The agent talks plaintext HTTP to the forwarder's loopback port, which
// no uprobe sees; the forwarder's own upstream leg is TLS written by tego, a process outside the run's
// cgroup, so even were it written through libssl the uprobe source's run scope drops it. The ring here
// carries exactly that leg's plaintext, stamped with the launcher's cgroup, as the worst case. Both
// producers feed one sink, and a real budget watcher reads it: one ssl_request, one ssl_response, 1100
// tokens. The control half puts the same chunks in the run's own cgroup and shows the uprobe source would
// have emitted them, so the scope is what keeps the count single, not an idle source.
func TestForwardedExchangeIsEmittedOnceWithBothSourcesRunning(t *testing.T) {
	runCg := ownCgroupID(t)
	launcherCg := runCg + 1<<40 // a cgroup id no process of the run is in
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(dualReply))
	}))
	t.Cleanup(up.Close)
	host, portStr, err := net.SplitHostPort(up.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	model := agent.ModelEndpoint{Provider: anthropic.Provider, Host: host, Port: port}
	rules := &agent.RuleTable{Record: agent.RecordFull, Contract: &agent.Contract{Models: []agent.ModelEndpoint{model}}}
	run := source.RunRef{ID: "r-dual", Agent: "a", CgroupID: runCg}

	reqBody := `{"model":"claude-test","max_tokens":256,"messages":[]}`
	// upstreamLeg is what an SSL_write/SSL_read probe would read of the forwarder's own upstream exchange.
	upstreamLeg := func(cg uint64) [][]byte {
		req := "POST /v1/messages HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\n" +
			"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody
		resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(dualReply)) + "\r\n\r\n" + dualReply
		return [][]byte{
			chunkRecord(cg, 7, 7, 0xf00, bpf.SSLWrite, 1_000_000, []byte(req), false),
			chunkRecord(cg, 7, 7, 0xf00, bpf.SSLRead, 2_000_000, []byte(resp), false),
		}
	}
	dispatcher := func() Deriver { return derive.NewDispatcher([]derive.Parser{anthropic.New()}) }

	count := func(t *testing.T, cg uint64, viaForwarder bool) (reqs, resps int, tokens uint64) {
		t.Helper()
		sink := &fakeSink{}
		if viaForwarder {
			l, err := forwarder.NewListener(model, forwarder.Options{Transport: up.Client().Transport,
				Deriver: dispatcher(), Bodies: true})
			if err != nil {
				t.Fatal(err)
			}
			l.Bind(run, sink)
			ctx, cancel := context.WithCancel(context.Background())
			served := make(chan error, 1)
			go func() { served <- l.Serve(ctx) }()
			defer func() {
				cancel()
				_ = l.Close()
				<-served
			}()
			resp, err := http.Post(l.BaseURL()+"/v1/messages", "application/json", bytes.NewReader([]byte(reqBody)))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("the forwarder answered %d", resp.StatusCode)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !hasKind(sink.events(), record.KindSSLResponse) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		}
		u, err := New(Options{Reader: &fakeRing{records: upstreamLeg(cg)}, Rules: rules, Deriver: dispatcher()})
		if err != nil {
			t.Fatal(err)
		}
		runSource(t, u, sink, run)

		clk := monoClock{start: time.Now()}
		w := limits.NewWatcher(agent.ResolvedLimits{}, nil, clk, cgroup.Cgroup{}, clk, &fakeSink{})
		for _, ev := range sink.events() {
			switch ev.Kind {
			case record.KindSSLRequest:
				reqs++
			case record.KindSSLResponse:
				resps++
			}
			w.Observe(ev)
		}
		return reqs, resps, w.Snapshot().Tokens()
	}

	reqs, resps, tokens := count(t, launcherCg, true)
	if reqs != 1 || resps != 1 || tokens != 1100 {
		t.Errorf("both sources running: %d ssl_request, %d ssl_response, %d tokens; want 1, 1, 1100 (I11)",
			reqs, resps, tokens)
	}
	// Control: the uprobe source alone, handed the same chunks in the run's own cgroup, does emit the
	// exchange, so the single count above is the run scope's doing.
	if reqs, resps, tokens := count(t, runCg, false); reqs != 1 || resps != 1 || tokens != 1100 {
		t.Errorf("uprobe alone in the run's cgroup: %d, %d, %d tokens; want the exchange once", reqs, resps, tokens)
	}
}

func hasKind(evs []*record.Event, k record.Kind) bool {
	for _, ev := range evs {
		if ev.Kind == k {
			return true
		}
	}
	return false
}
