// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		f := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(event, data string) {
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
			f.Flush()
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
		for range deltas {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(every):
			}
			send("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}}`)
		}
		send("content_block_stop", `{"type":"content_block_stop","index":0}`)
		send("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":20}}`)
		send("message_stop", `{"type":"message_stop"}`)
	}))
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
	return u.Hostname(), p, caFile
}

// runOneModelCall drives `tego run` over the model-agent making one call, and returns tego's exit code, its
// output, the run's events and how long the run took. A non-nil during is called once, at that time after the
// start, with the live run's id and the environment that names its machine config.
func runOneModelCall(t *testing.T, f *fixture, agentBin, caFile string, at time.Duration, during func(id string, env []string)) (int, string, []*record.Event, time.Duration) {
	t.Helper()
	// A price table path that does not exist, so the run never reads the invoking user's ~/.tego.
	cfg := writeMachineConfigWith(t, f, "prices: "+filepath.Join(t.TempDir(), "no-prices.yaml")+"\n")
	run := exec.Command(tegoBinary(t), "run", filepath.Join(f.dir, "agent.yaml"), "--", agentBin)
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "SSL_CERT_FILE="+caFile, "MODEL_CALLS=1")
	var buf bytes.Buffer
	run.Stdout, run.Stderr = &buf, &buf
	start := time.Now()
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	if during != nil {
		time.Sleep(at)
		if dirs := runDirs(t, f.root); len(dirs) == 1 {
			during(filepath.Base(dirs[0]), run.Env)
		} else {
			t.Errorf("run directories %v at %s, want one", dirs, at)
		}
	}
	err := run.Wait()
	took := time.Since(start)
	out := buf.Bytes()
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one\n%s", dirs, out)
	}
	return exitCodeOf(t, err), string(out), events(t, dirs[0]), took
}

// TestIntegrationAStreamingModelResponseIsNotAStall is limits-check-doctor-cli.md R4's relay half at tier landlock:
// a model response that streams an event every 0.5 s for 6 s, three times the run's stall_after of 2 s, is the
// agent waiting on its model, not a stalled agent. The record carries one line at each end of the exchange (in
// summary) or none of the stream (off), and the Go agent makes no syscall the supervisor is notified of while it
// reads, so before the forwarder reported its relayed chunks the stall check killed the run in both modes.
func TestIntegrationAStreamingModelResponseIsNotAStall(t *testing.T) {
	agentBin := modelAgentBinary(t)
	for _, mode := range []string{"summary", "off"} {
		t.Run(mode, func(t *testing.T) {
			host, port, caFile := sseUpstream(t, 500*time.Millisecond, 12)
			c := strings.Replace(modelContract("isse"+mode, agentBin, host, port, "\n  stall_after: 2s"),
				"record: full", "record: "+mode, 1)
			f := newFixture(t, c)
			code, out, evs, took := runOneModelCall(t, f, agentBin, caFile, 3500*time.Millisecond, statusIsActive(t, mode))
			if code != identity.ExitOK {
				t.Fatalf("record: %s: tego run exited %d after %s, want 0\n%s", mode, code, took, out)
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
			code, out, evs, took := runOneModelCall(t, f, agentBin, caFile, 0, nil)
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
