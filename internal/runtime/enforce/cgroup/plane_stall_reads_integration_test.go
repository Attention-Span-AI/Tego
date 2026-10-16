// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// planeReaderAgent reads one file over and over for 7 s, every 50 ms, and does nothing else: no exec, no write, no
// connect.
const planeReaderAgent = `import time
end = time.time() + 7
n = 0
while time.time() < end:
    with open("data.txt") as f:
        f.read()
    n += 1
    time.sleep(0.05)
print("READS", n, flush=True)
`

// planeWriterAgent appends to one file for 7 s, reopening it every 50 ms, and does nothing else: no read of a file,
// no exec, no connect.
const planeWriterAgent = `import time
end = time.time() + 7
n = 0
while time.time() < end:
    with open("out/log", "a") as f:
        f.write("x\n")
    n += 1
    time.sleep(0.05)
print("WRITES", n, flush=True)
`

// TestPlaneRunPureReaderUnderRecordOffIsWarnedAndStalls: at a root
// tier under record: off an allowed open writes no sample. Before the kernel's activity stamp a read, and a write-open
// the plane decides, was therefore neither a line nor activity there, `tego run` warned [stall-reads-unseen], and an
// agent that only read or only wrote files was ended limit-stall by a short stall_after; this test held that. Each
// such open of a stall-bounded run now stamps the run's slot of tego_activity, which the stall check pulls, so the
// same pure reader and pure writer under off are not warned and run to their own end, as they do under record: full,
// where every open is a line. The name is the one test/vm/root-must-pass.txt holds (append-only); what it checks is
// what is true now, and TestAReadingAgentUnderRecordOffIsNotAStall checks it on the fanotify row too.
func TestPlaneRunPureReaderUnderRecordOffIsWarnedAndStalls(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, plane := range modes {
		tiers := []string{"cgroup"}
		if plane == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			for _, a := range []struct{ name, script string }{{"reader", planeReaderAgent}, {"writer", planeWriterAgent}} {
				for _, recording := range []string{"off", "full"} {
					t.Run(tier+"@"+plane+"/"+a.name+"/"+recording, func(t *testing.T) {
						contract := fmt.Sprintf(`version: 0
name: plane-stall-reads
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net: {}
env:
  pass: ["PATH", "HOME"]
capture: off
record: %s
limits:
  wall: 60s
  stall_after: 2s
`, recording)
						p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": a.script, "agent.yaml": contract,
							"data.txt": strings.Repeat("x", 100)}, []string{"out"}, nil)
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
						defer cancel()
						var out lockedBuffer
						runErr := p.runAt(ctx, bin, tier, "agent.yaml", plane, &out).Run()
						events := runEvents(t, p.ledger)
						end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
						stalled := findEvent(events, func(e map[string]any) bool { return e["kind"] == "limit" && e["which"] == "stall_after" })
						warned := strings.Contains(out.String(), "[stall-reads-unseen]")
						if warned || runErr != nil || end == nil || end["reason"] != "exit" || stalled != nil {
							t.Fatalf("the pure %s under record: %s: warned %v, run %v, run_end %v, limit %v; want no warning and the agent's own end\n%s",
								a.name, recording, warned, runErr, end, stalled, out.String())
						}
						if !strings.Contains(out.String(), map[string]string{"reader": "READS ", "writer": "WRITES "}[a.name]) {
							t.Fatalf("the pure %s under record: %s did not finish its loop:\n%s", a.name, recording, out.String())
						}
					})
				}
			}
		}
	}
}

// planeConnectorAgent connects to 127.0.0.1 at the port in port.txt every 50 ms for 7 s, and does nothing else: no
// exec, no file opened after port.txt, no write.
const planeConnectorAgent = `import socket, time
port = int(open("port.txt").read())
end = time.time() + 7
n = 0
while time.time() < end:
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.close()
    n += 1
    time.sleep(0.05)
print("CONNECTS", n, flush=True)
`

// TestPlaneRunStallFollowsWhatTheSupervisorAnswers: under record: off every notification the supervisor answers is
// activity, at a
// root tier too, and what it is not notified of the kernel stamps as the run's activity. connect is notified at every
// tier and no plane hook decides it, so a pure connector runs to its end. A read gate has the filter notify every
// read-open, and any fs gate or fs ask entry keeps every write-open and path change with the supervisor (no plane
// skip): a pure reader or writer under a read gate runs to its end, and so does a pure writer under an fs.ask scope.
// The pure reader under that scope, whose reads the supervisor is not notified of, runs to its end through the stamp
// (it was ended limit-stall under a reads-only warning before it). No cell is warned under off. Under record: summary a
// read the gate scores is its own line, not an aggregate, so a pure reader under a read gate and a 2s stall_after runs
// to its end unwarned.
func TestPlaneRunStallFollowsWhatTheSupervisorAnswers(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	for _, v := range []struct {
		name, extra, record, agent, script string
		warns                              string // the text the warning prints, "" for none
		stalls                             bool
	}{
		{"plain/off/connector", "", "off", "connector", planeConnectorAgent, "", false},
		{"readgate/off/reader", "readgate", "off", "reader", planeReaderAgent, "", false},
		{"readgate/off/writer", "readgate", "off", "writer", planeWriterAgent, "", false},
		{"fsask/off/writer", "fsask", "off", "writer", planeWriterAgent, "", false},
		{"fsask/off/reader", "fsask", "off", "reader", planeReaderAgent, "", false},
		{"readgate/summary/reader", "readgate", "summary", "reader", planeReaderAgent, "", false},
	} {
		for _, plane := range modes {
			tiers := []string{"cgroup"}
			if plane == "lsm" {
				tiers = append(tiers, "bpflsm")
			}
			for _, tier := range tiers {
				t.Run(tier+"@"+plane+"/"+v.name, func(t *testing.T) {
					ask, gateYAML := "", ""
					switch v.extra {
					case "fsask":
						ask = "  ask: [\"./sealed/\"]\n"
					case "readgate":
						gateYAML = "gate:\n  rules:\n    - 'fs.read matches \"*.pem\"': 10\n"
					}
					contract := fmt.Sprintf(`version: 0
name: plane-stall-answers
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
%sexec:
  allow: ["python3"]
net:
  allow: ["127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME"]
%scapture: off
record: %s
limits:
  wall: 60s
  stall_after: 2s
`, ask, port, gateYAML, v.record)
					p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": v.script, "agent.yaml": contract,
						"data.txt": strings.Repeat("x", 100), "sealed/f": "x", "port.txt": fmt.Sprint(port)}, []string{"out", "sealed"}, nil)
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					defer cancel()
					var out lockedBuffer
					runErr := p.runAt(ctx, bin, tier, "agent.yaml", plane, &out).Run()
					events := runEvents(t, p.ledger)
					end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
					stalled := findEvent(events, func(e map[string]any) bool { return e["kind"] == "limit" && e["which"] == "stall_after" })
					warned := strings.Contains(out.String(), "[stall-reads-unseen]")
					if warned != (v.warns != "") || (v.warns != "" && !strings.Contains(out.String(), v.warns)) {
						t.Fatalf("the stall warning: printed %v, want %q:\n%s", warned, v.warns, out.String())
					}
					if v.agent == "connector" && strings.Contains(out.String(), "IP connect") {
						t.Fatalf("the warning still calls a connect unseen:\n%s", out.String())
					}
					if v.stalls {
						if end == nil || end["reason"] != "limit" || stalled == nil {
							t.Fatalf("want the run ended by stall_after: run_end %v, limit %v\n%s", end, stalled, out.String())
						}
						return
					}
					if runErr != nil || end == nil || end["reason"] != "exit" || stalled != nil {
						t.Fatalf("run %v, run_end %v, limit %v; want the agent's own end\n%s", runErr, end, stalled, out.String())
					}
				})
			}
		}
	}
}
