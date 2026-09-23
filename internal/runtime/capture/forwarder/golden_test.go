// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// updateGolden rewrites the frozen event lines instead of comparing against them.
var updateGolden = flag.Bool("update", false, "rewrite testdata/golden/events.jsonl")

// goldenFile is the frozen slice of what this package writes. It is a real chain — seq, prev and id
// link the lines the way a ledger writes them — so internal/check views can replay it and any change to
// a field name, a payload key or the event order fails here first.
const goldenFile = "testdata/golden/events.jsonl"

// cannedTransport answers without a network, so the golden lines depend on this package alone.
type cannedTransport struct {
	status int
	header http.Header
	body   string
}

func (c *cannedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	h := c.header.Clone()
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{
		StatusCode: c.status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Request:    r,
	}, nil
}

// TestGoldenEvents freezes one canonical line per kind this component writes: the request, the response
// derive filled in, the decision it carried, the retry that repeats the request, and a gap.
func TestGoldenEvents(t *testing.T) {
	const responseBody = `{"id":"msg_01Xq0001Z","type":"message","model":"claude-opus-5","stop_reason":"tool_use",` +
		`"content":[{"type":"tool_use","id":"toolu_010001A","name":"bash","input":{"command":"rg -n TODO"}}],` +
		`"usage":{"input_tokens":1000,"output_tokens":102,"cache_creation_input_tokens":512}}`

	l, err := NewListener(
		agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		Options{
			Clock: newClock(),
			Rand:  &countingRand{},
			Transport: &cannedTransport{status: http.StatusOK, body: responseBody,
				header: http.Header{"Content-Type": {"application/json"}, "Request-Id": {"req_011CS0001"}}},
			Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()}),
			Bodies:  true,
		})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	sink := &fakeSink{}
	// The golden line freezes testRun's cgroup id, which is a fixed number no process on this machine is
	// in; the peer this case dials from therefore cannot be placed in it. What is frozen here is the
	// shape of the events, not who may open the connection (R19a has its own cases).
	l.peers = anyPeer
	l.Bind(testRun, sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()
	defer l.Close()

	body := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"summarize the repo"}]}`)
	header := http.Header{
		"Content-Type":      {"application/json"},
		"Anthropic-Version": {"2023-06-01"},
		"User-Agent":        {"anthropic-sdk-python/0.69.0"},
		"X-Api-Key":         {"sk-ant-test-credential"},
	}
	client := &http.Client{}
	for i := 0; i < 2; i++ { // the second call is a byte-identical retry of the first
		req, err := http.NewRequest(http.MethodPost, l.BaseURL()+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = header.Clone()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	sink.waitFor(t, record.KindSSLResponse, 2)

	// An h2 preface, driven at the handler: Go's own HTTP/1.1 server refuses it one layer lower.
	rec := httptest.NewRecorder()
	pri := httptest.NewRequest("PRI", "/", nil)
	pri.RequestURI = "*"
	serveDirect(l, rec, pri)

	var buf bytes.Buffer
	prev := ""
	for seq, ev := range sink.all() {
		ev.Seq = uint64(seq)
		ev.Prev = prev
		// The pipeline stamps the process; the forwarder does not know the loopback peer's pid.
		ev.PID, ev.TID = 48212, 48212
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatalf("event %d (%s): %v", seq, ev.Kind, err)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("event %d (%s): %v", seq, ev.Kind, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
		prev = ev.ID
	}
	if bytes.Contains(buf.Bytes(), []byte("sk-ant-")) {
		t.Fatal("a credential reached the ledger lines (I5)")
	}

	path := filepath.Join(".", goldenFile)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/runtime/capture/forwarder -run TestGoldenEvents -update)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("the frozen event lines changed.\n--- want\n%s\n--- got\n%s", want, buf.Bytes())
	}
}

// TestGoldenChainVerifies replays the frozen slice the way a reader does: every line's digest and every
// seq/prev link must hold, and every line must be a forwarder line of one of this component's kinds.
func TestGoldenChainVerifies(t *testing.T) {
	data, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Skipf("no golden file yet: %v", err)
	}
	prev := ""
	kinds := map[record.Kind]bool{}
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		id, err := record.VerifyLine(line)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		ev, err := record.Decode(line)
		if err != nil {
			t.Fatalf("line %d: decode: %v", i, err)
		}
		if ev.Prev != prev {
			t.Errorf("line %d: prev = %q, want %q", i, ev.Prev, prev)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("line %d: %v", i, err)
		}
		if ev.Source != record.SourceForwarder {
			t.Errorf("line %d: source = %s, want forwarder", i, ev.Source)
		}
		switch ev.Kind {
		case record.KindSSLRequest, record.KindSSLResponse, record.KindDecision, record.KindGap:
			kinds[ev.Kind] = true
		default:
			t.Errorf("line %d: kind %s is not one this component writes", i, ev.Kind)
		}
		prev = id
	}
	for _, k := range []record.Kind{record.KindSSLRequest, record.KindSSLResponse, record.KindDecision, record.KindGap} {
		if !kinds[k] {
			t.Errorf("the golden slice has no %s line", k)
		}
	}
}

// TestLatencyUsesTheMonotonicClock: the response's latency comes from the monotonic clock, so a stepped
// wall clock cannot produce a negative one (#25).
func TestLatencyUsesTheMonotonicClock(t *testing.T) {
	c := newClock()
	c.step = time.Second
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}, Options{Clock: c})
	resp := h.post("/v1/messages", []byte(`{}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	p := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if p.LatencyMS <= 0 {
		t.Errorf("latency_ms = %d, want the monotonic difference", p.LatencyMS)
	}
}
