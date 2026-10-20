// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// limits R4's TLS half end to end, as root through the whole of `tego run` (record-off plan C7): an
// agent that talks TLS to its model through the system libssl, with capture: uprobe, reads a response that streams
// an event every 0.5 s for 10 s, more than three times its stall_after of 3 s. Under summary the record has a line at
// each end of the exchange and none between, under off none at all, and the agent makes no syscall the supervisor
// is notified of while it reads: each SSL_read that returns bytes stamps the run's slot of tego_activity, under off
// through probes placed for the stall check alone. A model that answers the head and then nothing still stalls.

// streamAgent makes one POST to 127.0.0.1:$E2E_PORT over TLS with python3's ssl module (the system libssl, which
// the uprobe source pre-attaches) and reads the response to its end.
const streamAgent = `import os, socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
n = 0
with socket.create_connection(("127.0.0.1", int(os.environ["E2E_PORT"]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"
                  b"Content-Length: 2\r\n\r\n{}")
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            n += len(chunk)
print("RESULT bytes", n, flush=True)
`

// streamContract is the agent under the given record mode and limits block, capture: uprobe.
const streamContract = `version: 0
name: t2-stream
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: ["127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME", "E2E_PORT"]
capture: uprobe
%srecord: %s
`

// streamingUpstream serves TLS on 127.0.0.1 and answers each connection's one request with a 200 event stream: one
// event every `every`, `events` of them, then the connection's close. With events < 0 it sends the head and then
// nothing, until the client goes away or a minute has passed.
func streamingUpstream(t *testing.T, every time.Duration, events int) int {
	t.Helper()
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{anthropicCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Minute))
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"); err != nil {
					return
				}
				if events < 0 {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				for range events {
					time.Sleep(every)
					if _, err := io.WriteString(c, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n"); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// streamRun runs the stream agent once at tier, under the plane pin, and returns its exit code, its ledger, how long
// it took and its output. during, when set, is called while the run is live, every 100 ms until it returns false.
func streamRun(t *testing.T, bin string, uid, gid int, tier, pin, mode, limits string, port int, during func() bool) (int, []map[string]any, time.Duration, string) {
	t.Helper()
	p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": streamAgent,
		"agent.yaml": fmt.Sprintf(streamContract, port, limits, mode)}, []string{"out"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", pin, &out)
	cmd.Env = append(cmd.Env, "E2E_PORT="+strconv.Itoa(port))
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var err error
	for done := false; !done; {
		select {
		case err = <-waited:
			done = true
		case <-time.After(100 * time.Millisecond):
			if during != nil && !during() {
				during = nil
			}
		}
	}
	took := time.Since(start)
	t.Logf("tego run --tier %s (%s, record: %s) after %s: %v\n%s", tier, pin, mode, took, err, out.String())
	code := 0
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		t.Fatalf("tego run: %v", err)
	}
	return code, runEvents(t, p.ledger), took, out.String()
}

// streamCells are the tiers the stream runs at here: tier cgroup under the machine's own plane selection, and tier
// bpflsm where LSM mode passes.
func streamCells(t *testing.T, bin string) [][2]string {
	cells := [][2]string{{"cgroup", "auto"}}
	if slices.Contains(planeModesHere(t, bin), "lsm") {
		cells = append(cells, [2]string{"bpflsm", "lsm"})
	}
	return cells
}

const streamStall = "limits:\n  stall_after: 3s\n"

func TestAStreamingModelResponseIsNotAStall(t *testing.T) {
	bin, uid, gid, _ := activityPreconditions(t)
	port := streamingUpstream(t, 500*time.Millisecond, 20)
	for _, cell := range streamCells(t, bin) {
		for _, mode := range []string{"off", "summary"} {
			t.Run(cell[0]+"/"+mode, func(t *testing.T) {
				code, events, took, out := streamRun(t, bin, uid, gid, cell[0], cell[1], mode, streamStall, port, nil)
				if code != 0 {
					t.Fatalf("record: %s: a response streaming for 10 s under stall_after 3s ended the run with %d after %s",
						mode, code, took)
				}
				if took < 9*time.Second || !strings.Contains(out, "RESULT bytes ") {
					t.Fatalf("record: %s: the run took %s and the agent said %q: the upstream did not stream", mode, took, out)
				}
				for _, e := range events {
					if e["kind"] == "limit" {
						t.Errorf("record: %s: a streaming response got a limit line: %v", mode, e)
					}
				}
				unavailable := findEvent(events, func(e map[string]any) bool {
					return e["kind"] == "gap" && e["what"] == "capture" && e["why"] == "mechanism-unavailable"
				})
				switch mode {
				case "off":
					// Probes placed for the stall check alone: the run still says its capture did not run.
					if unavailable == nil {
						t.Error("record: off: no capture mechanism-unavailable gap: run_start would claim the run's model traffic")
					}
				case "summary":
					if unavailable != nil {
						t.Errorf("record: summary: capture did not run: %v", unavailable)
					}
					if findEvent(events, func(e map[string]any) bool { return e["kind"] == "ssl_response" }) == nil {
						t.Error("record: summary: the exchange has no ssl_response line")
					}
				}
			})
		}
	}
}

func TestASilentModelStalls(t *testing.T) {
	bin, uid, gid, _ := activityPreconditions(t)
	port := streamingUpstream(t, 0, -1)
	for _, cell := range streamCells(t, bin) {
		for _, mode := range []string{"off", "summary"} {
			t.Run(cell[0]+"/"+mode, func(t *testing.T) {
				code, events, took, _ := streamRun(t, bin, uid, gid, cell[0], cell[1], mode, streamStall, port, nil)
				if code != 124 {
					t.Fatalf("record: %s: a model that sends nothing after its head ended the run with %d after %s, want 124",
						mode, code, took)
				}
				// From run_start (sinceRunStart): the request is made at once, and nothing after its response head.
				if at, ok := sinceRunStart(events, "limit"); !ok || at > 7*time.Second {
					t.Errorf("record: %s: the stall's limit line came %s after run_start (found %v), want within stall_after 3s "+
						"and a few ticks; the ledger: %s", mode, at, ok, timeline(events))
				}
				var limits []map[string]any
				for _, e := range events {
					if e["kind"] == "limit" {
						limits = append(limits, e)
					}
				}
				if len(limits) != 1 || limits[0]["which"] != "stall_after" {
					t.Errorf("record: %s: limit lines %v, want exactly one, stall_after", mode, limits)
				}
			})
		}
	}
}

// TestRecordOffWithoutStallBudgetPlacesNoProbe is A-REC-3 and D3: a record: off run places the TLS probes only when a
// stall check reads what they stamp. Without a stall_after no pin of the build's uprobes directory appears while the
// run's agent talks TLS; with one, the probes are there for it.
func TestRecordOffWithoutStallBudgetPlacesNoProbe(t *testing.T) {
	bin, uid, gid, _ := activityPreconditions(t)
	hash, err := bpfHash()
	if err != nil {
		t.Fatal(err)
	}
	probes := filepath.Join(DefaultBPFFS, pinRoot, hash, "uprobes") // uprobe.UprobePinDir
	placed := func() []string {
		entries, _ := os.ReadDir(probes)
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	// A previous run's probes stay ProbeGrace (2 s) after it, and their detacher then removes them.
	deadline := time.Now().Add(20 * time.Second)
	for len(placed()) != 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if left := placed(); len(left) != 0 {
		t.Fatalf("probes of an earlier run are still placed: %v", left)
	}
	port := streamingUpstream(t, 500*time.Millisecond, 4)
	for _, tc := range []struct {
		name, limits string
		want         bool
	}{{"no stall_after", "", false}, {"stall_after", streamStall, true}} {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			code, _, took, _ := streamRun(t, bin, uid, gid, "cgroup", "auto", "off", tc.limits, port, func() bool {
				if p := placed(); len(p) > 0 && seen == nil {
					seen = p
				}
				return true
			})
			if code != 0 {
				t.Fatalf("the run ended with %d after %s", code, took)
			}
			if (len(seen) > 0) != tc.want {
				t.Fatalf("probes placed during a record: off run with %q: %v, want placed %v", tc.limits, seen, tc.want)
			}
			// The next case starts from no probes: wait out this run's grace and detacher.
			deadline := time.Now().Add(20 * time.Second)
			for len(placed()) != 0 && time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
			}
		})
	}
}
