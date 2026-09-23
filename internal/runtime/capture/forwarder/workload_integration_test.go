// SPDX-License-Identifier: Apache-2.0

//go:build integration

package forwarder

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// workloadAgent is the system-Python agent of docs/FEATURES.md I1 and P0-DESIGN §12 item 3.
const workloadAgent = "../../../../test/workloads/python-httpx/agent.py"

// TestIntegrationSystemPythonAgentIsCapturedThroughTheForwarder runs test/workloads/python-httpx unchanged
// against the variables a run installs, with a local TLS stand-in for the model endpoint, and checks that its
// model call is recorded as one ssl_request/ssl_response pair whose usage derive read (I1's zero-adapter
// path at tier 1, §12 item 3's system-Python half). The agent uses httpx when this Python has it (PYTHONPATH
// is passed through, so a developer can point it at one) and urllib when it does not. The stand-in picks
// the best coding the request offers, br then zstd then gzip, the way a CDN in front of the API does;
// httpx offers all of them when its brotli and zstandard modules are present, so the usage is only there if
// the forwarder narrowed the offer to what it decodes or decoded what came back (R15, R20).
func TestIntegrationSystemPythonAgentIsCapturedThroughTheForwarder(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3: the workload is a system-Python agent")
	}
	const answer = `{"id":"msg_01Wk0001","type":"message","model":"claude-sonnet-5","stop_reason":"end_turn",` +
		`"content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":12,"output_tokens":3}}`
	var (
		mu      sync.Mutex
		offered []string
	)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		offered = append(offered, r.Header.Get("Accept-Encoding"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		ae := r.Header.Get("Accept-Encoding")
		var zw io.WriteCloser
		switch {
		case strings.Contains(ae, "br"):
			w.Header().Set("Content-Encoding", "br")
			zw = brotli.NewWriter(w)
		case strings.Contains(ae, "zstd"):
			w.Header().Set("Content-Encoding", "zstd")
			zw, _ = zstd.NewWriter(w)
		case strings.Contains(ae, "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			zw = gzip.NewWriter(w)
		default:
			_, _ = w.Write([]byte(answer))
			return
		}
		_, _ = zw.Write([]byte(answer))
		_ = zw.Close()
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.Listener.Addr().String())

	m, err := NewManager([]agent.ModelEndpoint{{Provider: "anthropic", Host: host, Port: port}}, Options{
		Transport: up.Client().Transport,
		Deriver:   derive.NewDispatcher([]derive.Parser{anthropic.New(host)}),
		Bodies:    true,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	// The agent is this test's child and so in this test's cgroup, which is the run's here: R19a admits it
	// the way it admits an agent cloned into a real run's cgroup.
	run := testRun
	if id, err := liveCgroupID(); err == nil {
		run.CgroupID = id
	} else {
		t.Logf("peer admission not exercised here: %v", err)
		m.Listeners()[0].peers = anyPeer
	}
	sink := &fakeSink{}
	if err := m.Start(context.Background(), run, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })

	work := t.TempDir()
	cmd := exec.Command(py, workloadAgent)
	// The workload's refused-write probe goes to $HOME; pointing HOME at the test's own directory keeps a
	// run with no enforcement from writing into the developer's home.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + work, "TEGO_TEST_OUT=" + filepath.Join(work, "out")}
	if pp := os.Getenv("PYTHONPATH"); pp != "" {
		cmd.Env = append(cmd.Env, "PYTHONPATH="+pp)
	}
	for k, v := range m.Vars() {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the workload failed: %v\n%s", err, out)
	}
	client := ""
	for _, line := range strings.Split(string(out), "\n") {
		if c, ok := strings.CutPrefix(line, "client="); ok {
			client = c
		}
	}
	if client != "httpx" && client != "urllib" {
		t.Fatalf("the workload's model call did not complete (client=%q):\n%s", client, out)
	}
	t.Logf("the workload called the model with %s; the upstream was offered %q", client, offered)
	summary, err := os.ReadFile(filepath.Join(work, "out", "summary.md"))
	if err != nil || !strings.Contains(string(summary), "msg_01Wk0001") {
		t.Errorf("the agent did not receive the model's answer through the forwarder: %q, %v", summary, err)
	}

	resp := sink.waitFor(t, record.KindSSLResponse, 1)[0]
	reqs := sink.of(record.KindSSLRequest)
	if len(reqs) != 1 {
		t.Fatalf("%d ssl_request lines, want the one call the agent made", len(reqs))
	}
	q := payloadOf[record.SSLRequestPayload](t, reqs[0])
	if q.Method != http.MethodPost || q.Path != "/v1/messages" || q.Endpoint != "anthropic" || reqs[0].Source != record.SourceForwarder {
		t.Errorf("ssl_request = %+v from %s", q, reqs[0].Source)
	}
	p := payloadOf[record.SSLResponsePayload](t, resp)
	if p.Usage == nil || p.Usage.Input != 12 || p.Usage.Output != 3 || p.Model != "claude-sonnet-5" {
		t.Errorf("ssl_response = %+v, want the model and usage derive reads from the answer", p)
	}
	if got := recordedBody(t, resp); got != answer {
		t.Errorf("recorded response body = %q, want the decoded answer", got)
	}
}
