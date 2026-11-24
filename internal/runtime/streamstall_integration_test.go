// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sseUpstream is a model endpoint that answers /v1/messages with an Anthropic event stream: message_start, then
// one content_block_delta every `every` for `deltas` deltas, then the closing events. With deltas < 0 it is a
// model that never produces anything after message_start: it holds the response open, silent, until the client
// goes away. It returns what modelUpstream returns.
func sseUpstream(t *testing.T, every time.Duration, deltas int) (host string, port int, caFile string) {
	t.Helper()
	host, port, caFile, _ = sseUpstreamSeen(t, every, deltas, 0)
	return host, port, caFile
}

// sseSeen is what the upstream of sseUpstreamSeen tells the test: reached is closed once the stream has sent its
// probeAfter-th delta, the moment a test may look at the live run (see runOneModelCall).
type sseSeen struct {
	reached chan struct{}
	once    sync.Once
	// connected is closed when the first connection to the upstream is accepted, before its TLS handshake.
	connected     chan struct{}
	connectedOnce sync.Once

	mu      sync.Mutex
	arrived time.Time   // when the request reached the upstream
	sentAt  []time.Time // when each event was written, in order
	conns   []time.Time // when each connection to the upstream was accepted (before its TLS handshake)
}

// sseUpstreamSeen is sseUpstream that also reports what it saw. A probeAfter above 0 closes seen.reached when that
// many deltas have been sent: the test then looks at a run that has been streaming for that long by the upstream's
// own count, however long the run took to start.
func sseUpstreamSeen(t *testing.T, every time.Duration, deltas, probeAfter int) (host string, port int, caFile string, seen *sseSeen) {
	t.Helper()
	seen = &sseSeen{reached: make(chan struct{}), connected: make(chan struct{})}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		seen.mu.Lock()
		seen.arrived = time.Now()
		seen.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		f := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(event, data string) {
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
			f.Flush()
			seen.mu.Lock()
			seen.sentAt = append(seen.sentAt, time.Now())
			seen.mu.Unlock()
		}
		send("message_start", `{"type":"message_start","message":{"id":"msg_sse","type":"message","role":"assistant",`+
			`"model":"claude-test-1","content":[],"stop_reason":null,"usage":{"input_tokens":40,"output_tokens":1}}}`)
		if deltas < 0 {
			select {
			case <-r.Context().Done():
			case <-time.After(60 * time.Second):
			}
			return
		}
		send("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		for i := 1; i <= deltas; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(every):
			}
			send("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}`)
			if i == probeAfter {
				seen.once.Do(func() { close(seen.reached) })
			}
		}
		send("content_block_stop", `{"type":"content_block_stop","index":0}`)
		send("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":20}}`)
		send("message_stop", `{"type":"message_stop"}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			seen.connectedOnce.Do(func() { close(seen.connected) })
			seen.mu.Lock()
			seen.conns = append(seen.conns, time.Now())
			seen.mu.Unlock()
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "upstream-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), p, caFile, seen
}

// streamHangGuard ends a test whose run never reaches the point it waits for, or never ends (a hang). It is not a speed
// estimate: every wait below ends when its event happens.
const streamHangGuard = 5 * time.Minute

// runOneModelCall drives `tego run` over the model-agent making one call, and returns tego's exit code, its
// output, the run's events and how long the run took. A non-nil during is called once, when `when` is closed (or the
// run has ended: then not at all), with the live run's id and the environment that names its machine config. The
// moment is an event of the run, never a time after its start: a host that is slow to start a run (a first use of
// the kernel checks, a busy machine) would otherwise be looked at before the run had begun.
func runOneModelCall(t *testing.T, f *fixture, agentBin, caFile string, when <-chan struct{}, during func(id string, env []string), extraEnv ...string) (int, string, []*record.Event, time.Duration) {
	t.Helper()
	// A price table path that does not exist, so the run never reads the invoking user's ~/.tego.
	cfg := writeMachineConfigWith(t, f, "prices: "+filepath.Join(t.TempDir(), "no-prices.yaml")+"\n")
	run := exec.Command(tegoBinary(t), "run", filepath.Join(f.dir, "agent.yaml"), "--", agentBin)
	run.Dir = f.dir
	run.Env = append(append(os.Environ(), "TEGO_CONFIG="+cfg, "SSL_CERT_FILE="+caFile, "MODEL_CALLS=1"), extraEnv...)
	var buf bytes.Buffer
	run.Stdout, run.Stderr = &buf, &buf
	start := time.Now()
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- run.Wait() }()
	var err error
	waited, probed := false, false
	if during != nil {
		select {
		case <-when:
			if dirs := runDirs(t, f.root); len(dirs) == 1 {
				probed = true
				during(filepath.Base(dirs[0]), run.Env)
			} else {
				t.Errorf("run directories %v when the stream was under way, want one", dirs)
			}
		case err = <-ended:
			// Not an error here: a run that ended without a stream is judged by how it ended (its caller skips a stall
			// before the request reached the upstream, fails any other end); only a clean end that never probed is wrong.
			waited = true
		case <-time.After(streamHangGuard):
			_ = run.Process.Kill()
			t.Fatalf("the stream was not under way %s after the run started", streamHangGuard)
		}
	}
	if !waited {
		select {
		case err = <-ended:
		case <-time.After(streamHangGuard):
			_ = run.Process.Kill()
			t.Fatalf("the run did not end %s after it started", streamHangGuard)
		}
	}
	took := time.Since(start)
	if during != nil && !probed && err == nil {
		t.Errorf("the run ended cleanly without the stream having been under way: the live run was never looked at")
	}
	out := buf.Bytes()
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one\n%s", dirs, out)
	}
	return exitCodeOf(t, err), string(out), events(t, dirs[0]), took
}

// TestIntegrationAStreamingModelResponseIsNotAStall is the relay half at tier landlock:
// a model response that streams an event every 0.5 s for 6 s, three times the run's stall_after of 2 s, is the
// agent waiting on its model, not a stalled agent. The record carries one line at each end of the exchange (in
// summary) or none of the stream (off), and the Go agent makes no syscall the supervisor is notified of while it
// reads, so before the forwarder reported its relayed chunks the stall check killed the run in both modes.
func TestIntegrationAStreamingModelResponseIsNotAStall(t *testing.T) {
	agentBin := modelAgentBinary(t)
	for _, mode := range []string{"summary", "off"} {
		t.Run(mode, func(t *testing.T) {
			// The probe looks at the run once the stream has sent six deltas, three seconds of stream, past stall_after.
			host, port, caFile, seen := sseUpstreamSeen(t, 500*time.Millisecond, 12, 6)
			c := strings.Replace(modelContract("isse"+mode, agentBin, host, port, "\n  stall_after: 2s"),
				"record: full", "record: "+mode, 1)
			f := newFixture(t, c)
			begin := time.Now()
			code, out, evs, took := runOneModelCall(t, f, agentBin, caFile, seen.reached, statusIsActive(t, mode))
			t.Logf("record: %s: the run took %s\n%s%s", mode, took, streamTimeline(begin, seen, evs), stallVerdict(seen, evs, 2*time.Second))
			if code != identity.ExitOK {
				t.Fatalf("record: %s: tego run exited %d after %s, want 0\n%s%s\n%s", mode, code, took, streamTimeline(begin, seen, evs), stallVerdict(seen, evs, 2*time.Second), out)
			}
			if took < 5*time.Second {
				t.Fatalf("record: %s: the run took %s, under the 6 s stream: the upstream did not stream", mode, took)
			}
			for _, ev := range evs {
				if ev.Kind == record.KindLimit {
					t.Errorf("record: %s: a streaming response got a limit line (reason %s)", mode, ev.Reason)
				}
			}
			if !strings.Contains(out, "model-agent: call 1 status 200") {
				t.Errorf("record: %s: the agent did not read its response:\n%s", mode, out)
			}
		})
	}
}

// streamTimeline says, for a run that did not end as expected, what the upstream did and what the run's record shows,
// on one clock (offsets from begin, the moment before `tego run` was started): when the request arrived, the largest gap
// between two events the upstream wrote (an upstream starved of a CPU leaves a gap above stall_after and then the stall is
// the test's host, not Tego), and each line of the record with its own time, the limit line with its payload. That is
// what tells a stall the stream earned from one the product declared while bytes were arriving.
func streamTimeline(begin time.Time, seen *sseSeen, evs []*record.Event) string {
	var b strings.Builder
	seen.mu.Lock()
	arrived, sent, conns := seen.arrived, append([]time.Time(nil), seen.sentAt...), append([]time.Time(nil), seen.conns...)
	seen.mu.Unlock()
	off := func(at time.Time) string { return at.Sub(begin).Round(time.Millisecond).String() }
	for _, c := range conns {
		fmt.Fprintf(&b, "upstream: connection accepted at %s (its TLS handshake and request follow)\n", off(c))
	}
	if arrived.IsZero() {
		b.WriteString("upstream: no request arrived\n")
	} else {
		fmt.Fprintf(&b, "upstream: request arrived at %s, %d events written", off(arrived), len(sent))
		var gap time.Duration
		var at time.Time
		prev := arrived
		for _, w := range sent {
			if d := w.Sub(prev); d > gap {
				gap, at = d, w
			}
			prev = w
		}
		if len(sent) > 0 {
			fmt.Fprintf(&b, ", the last at %s, the largest gap between two writes %s (ending at %s)", off(sent[len(sent)-1]), gap.Round(time.Millisecond), off(at))
		}
		b.WriteString("\n")
	}
	for _, e := range evs {
		fmt.Fprintf(&b, "record: seq %d at %s %s", e.Seq, off(e.TS), e.Kind)
		if e.Kind == record.KindLimit {
			var lim record.LimitPayload
			if e.DecodePayload(&lim) == nil {
				fmt.Fprintf(&b, " %+v", lim)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// stallVerdict says, for a run the stall check ended (stall_after of `after`), where in the run the silence was, from the
// upstream's own writes and the record's limit line: only a stall declared while the upstream was writing within `after`
// of it is the product's to explain (bytes were arriving and were not counted); the others are a stretch of the run in
// which nothing reached the model's side or came back, which stall_after counts by design (the silent-model test holds
// that), however the host came to cause it. "" when the run did not end on its stall limit.
func stallVerdict(seen *sseSeen, evs []*record.Event, after time.Duration) string {
	var limit *record.Event
	for _, e := range evs {
		if e.Kind == record.KindLimit {
			limit = e
		}
	}
	if limit == nil {
		return ""
	}
	seen.mu.Lock()
	arrived, sent := seen.arrived, append([]time.Time(nil), seen.sentAt...)
	seen.mu.Unlock()
	if arrived.IsZero() || arrived.After(limit.TS) {
		return "VERDICT: stalled before the request reached the upstream: the run's silence was the connect, the TLS handshake or the agent's start, not a stream"
	}
	var last time.Time
	for _, w := range sent {
		if w.Before(limit.TS) {
			last = w
		}
	}
	if last.IsZero() {
		return "VERDICT: stalled after the request reached the upstream and before its first byte was written: the upstream was not scheduled"
	}
	if len(sent) > 0 && !sent[len(sent)-1].After(limit.TS) && limit.TS.Sub(sent[len(sent)-1]) >= after {
		return "VERDICT: stalled after the upstream wrote its last event: the end of the response, or the agent's exit, took longer than stall_after"
	}
	if gap := limit.TS.Sub(last); gap >= after {
		return "VERDICT: stalled inside the stream, with the upstream silent for longer than stall_after (it was not scheduled)"
	}
	return "VERDICT: PRODUCT? the stall was declared while the upstream's writes were arriving within stall_after: the forwarder's relayed bytes were not counted"
}

// statusIsActive is R9 on the live streaming run, through the CLI: 3.5 s into a stream whose ledger has nothing
// newer than its request (and under record: off not even that), past the 2 s stall_after, `tego status --json`
// reads the run as the watcher does, idle under a second from its activity sidecar, never stalled.
func statusIsActive(t *testing.T, mode string) func(string, []string) {
	return func(id string, env []string) {
		cmd := exec.Command(tegoBinary(t), "status", id, "--json")
		cmd.Env = env
		// status exits non-zero for a stalled run (R25), and its --json object says so all the same.
		out, err := cmd.Output()
		if _, exited := err.(*exec.ExitError); err != nil && !exited {
			t.Errorf("record: %s: tego status: %v", mode, err)
			return
		}
		var got struct {
			State    string  `json:"state"`
			IdleS    float64 `json:"idle_s"`
			IdleFrom string  `json:"idle_from"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Errorf("record: %s: status --json: %v\n%s", mode, err, out)
			return
		}
		if got.State == "stalled" || got.IdleFrom != "activity" || got.IdleS >= 2 {
			t.Errorf("record: %s: status of the streaming run %+v, want running or waiting model, idle under 2s from activity", mode, got)
		}
	}
}

// TestIntegrationASilentModelStalls is the other half: a model that answers message_start and then nothing is
// silent, the forwarder relays no chunk, and the run stalls at stall_after in both modes, with one limit line.
// Without it the relay hook could be satisfied by one that reports the open connection rather than its bytes.
func TestIntegrationASilentModelStalls(t *testing.T) {
	agentBin := modelAgentBinary(t)
	for _, mode := range []string{"summary", "off"} {
		t.Run(mode, func(t *testing.T) {
			host, port, caFile := sseUpstream(t, 0, -1)
			c := strings.Replace(modelContract("isilent"+mode, agentBin, host, port, "\n  stall_after: 2s"),
				"record: full", "record: "+mode, 1)
			f := newFixture(t, c)
			code, out, evs, took := runOneModelCall(t, f, agentBin, caFile, nil, nil)
			if code != identity.ExitLimit {
				t.Fatalf("record: %s: tego run exited %d after %s, want %d (stall)\n%s", mode, code, took, identity.ExitLimit, out)
			}
			if lim := limitEvent(t, evs); lim.Which != record.LimitStallAfter {
				t.Fatalf("record: %s: limit payload %+v, want stall_after", mode, lim)
			}
			if took > 15*time.Second {
				t.Errorf("record: %s: the stall took %s to end a run with stall_after: 2s", mode, took)
			}
		})
	}
}

// TestIntegrationATegoSideDelayBeforeTheRequestIsSentIsNotAStall: while Tego itself holds the agent's request, getting
// it to the model, the run is not stalled: stall_after counts the agent's and the model's silence, not Tego's latency.
// The fault is Tego's trust-root load. The forwarder reads the system roots on its first TLS handshake, and
// SSL_CERT_DIR names a directory with one file that is a FIFO, which blocks the read until the test lets go, a disk
// that is slow for Tego (the gate saw the read take over two seconds on a host whose disk was busy). The release comes
// four seconds after the upstream accepted Tego's connection, longer than stall_after (2 s) and the stall check's
// one-second tick together, however fast the host is; the request then goes on, the model answers, and the run ends 0.
// Without the hold the run is ended as stalled while it waits (exit 124, before the request reaches the upstream).
func TestIntegrationATegoSideDelayBeforeTheRequestIsSentIsNotAStall(t *testing.T) {
	agentBin := modelAgentBinary(t)
	const delay = 4 * time.Second
	host, port, caFile, seen := sseUpstreamSeen(t, 200*time.Millisecond, 4, 0)
	c := strings.Replace(modelContract("itegoheld", agentBin, host, port, "\n  stall_after: 2s"), "record: full", "record: summary", 1)
	f := newFixture(t, c)
	rootDir := t.TempDir()
	fifo := filepath.Join(rootDir, "slow-roots.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("no FIFO to hold Tego's trust-root read with: %v", err)
	}
	// Opened for reading and writing so that Tego's open of it returns at once and its read waits; closed to end the read.
	hold, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		defer hold.Close()
		select {
		case <-seen.connected:
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		case <-stop:
			return
		}
	}()
	t.Cleanup(func() { close(stop) })
	begin := time.Now()
	code, out, evs, took := runOneModelCall(t, f, agentBin, caFile, nil, nil, "SSL_CERT_DIR="+rootDir)
	if code != identity.ExitOK {
		t.Fatalf("a run whose request Tego held for %s while it read its trust roots exited %d after %s, want 0\n%s%s\n%s",
			delay, code, took, streamTimeline(begin, seen, evs), stallVerdict(seen, evs, 2*time.Second), out)
	}
	for _, ev := range evs {
		if ev.Kind == record.KindLimit {
			t.Errorf("a limit line (reason %s) for a run whose request Tego held", ev.Reason)
		}
	}
	seen.mu.Lock()
	accepted, arrived := time.Time{}, seen.arrived
	if len(seen.conns) > 0 {
		accepted = seen.conns[0]
	}
	seen.mu.Unlock()
	if accepted.IsZero() || arrived.Sub(accepted) < delay-time.Second {
		t.Fatalf("the request reached the upstream %s after its connection was accepted: Tego's trust-root read was not held for the %s the test meant (the fault was not injected)\n%s",
			arrived.Sub(accepted), delay, streamTimeline(begin, seen, evs))
	}
	if !strings.Contains(out, "model-agent: call 1 status 200") {
		t.Errorf("the agent did not read its response:\n%s", out)
	}
}
