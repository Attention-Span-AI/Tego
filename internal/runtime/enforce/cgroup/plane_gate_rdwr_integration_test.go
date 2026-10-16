// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"strings"
	"testing"
	"time"
)

// planeRDWRAgent opens out/x.pem read-only and then read-write, and says what each open gave it.
const planeRDWRAgent = `import os
try:
    with open("out/x.pem") as f:
        print("RDONLY", f.read().strip(), flush=True)
except Exception as e:
    print("RDONLY refused", type(e).__name__, flush=True)
try:
    fd = os.open("out/x.pem", os.O_RDWR)
    print("RDWR", os.read(fd, 64).decode().strip(), flush=True)
except Exception as e:
    print("RDWR refused", type(e).__name__, flush=True)
`

// TestPlaneRunReadGateScoresAReadWriteOpen at the root tiers: under `fs.read matches
// "*.pem": 90` the agent's read-only open of out/x.pem is refused fs-gate, and so is its O_RDWR open of the same file
// beneath the write entry, which the gate scored as a write alone and so continued, handing over the bytes. Both
// refusals are the gate's lines, with its score.
func TestPlaneRunReadGateScoresAReadWriteOpen(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	const contract = `version: 0
name: plane-gate-rdwr
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net: {}
env:
  pass: ["PATH", "HOME"]
capture: off
record: full
gate:
  rules:
    - 'fs.read matches "*.pem"': 90
limits:
  wall: 60s
`
	for _, plane := range modes {
		tiers := []string{"cgroup"}
		if plane == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			t.Run(tier+"@"+plane, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": planeRDWRAgent, "agent.yaml": contract,
					"out/x.pem": "GATE-REFUSED-PEM\n"}, []string{"out"}, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out lockedBuffer
				if err := p.runAt(ctx, bin, tier, "agent.yaml", plane, &out).Run(); err != nil {
					t.Fatalf("tego run at tier %s: %v\n%s", tier, err, out.String())
				}
				said := out.String()
				if strings.Contains(said, "GATE-REFUSED-PEM") || !strings.Contains(said, "RDONLY refused PermissionError") ||
					!strings.Contains(said, "RDWR refused PermissionError") {
					t.Fatalf("the agent's opens of a file the read gate refuses, at tier %s:\n%s", tier, said)
				}
				refused := 0
				for _, e := range runEvents(t, p.ledger) {
					if path, _ := e["path"].(string); e["kind"] == "fs" && e["reason"] == "fs-gate" && strings.HasSuffix(path, "/out/x.pem") {
						if e["score"] != float64(90) || e["gate_rule"] != "gate.rules[0]" {
							t.Fatalf("the gate's line %v: want score 90 and its rule", e)
						}
						refused++
					}
				}
				if refused != 2 {
					t.Fatalf("%d fs-gate refusals of out/x.pem at tier %s, want 2 (read-only and read-write)\n%s", refused, tier, said)
				}
			})
		}
	}
}
