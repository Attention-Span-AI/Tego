// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const bindLookupAgent = `import errno, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
result = 0
try:
    s.bind("out/file/b.sock")
except OSError as e:
    result = e.errno
print("RESULT beneath-file", result, flush=True)
assert result == errno.ENOTDIR, result
`

// TestPlaneRunBindLookupFailureIsTheKernels retains the lookup-error regression
// from ADR 0019. With ADR 0113's immutable boundary, the supervisor walks the
// captured pathname before continuing it and returns the task's ENOTDIR without
// performing a bind. Its one result must be supervisor-owned, observed and
// unmatched, with the exact errno and captured spelling. The syscall-exit
// producer must suppress its unmarked duplicate, and no plane decision or
// missing-kernel-metadata gap may be invented for this owned completion.
//
// The listener the contract declares sits in a directory, out/b.sock, and the agent binds a name it does not declare,
// beneath a file: a plane run holds each declared listener's directory at prepare (the Landlock fill's
// planeListenParents) and refuses to start when one is not a directory, so a contract that declared out/file/b.sock
// itself started no run and this test failed in every arm before it reached the bind (-2c5-1).
// This test is run only in the coordinated disposable privileged guest.
func TestPlaneRunBindLookupFailureIsTheKernels(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			t.Run(tier+"@"+mode, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": bindLookupAgent, "out/file": "x"}, []string{"out"}, nil)
				name := "unix:" + filepath.Join(p.project, "out/b.sock")
				contract := fmt.Sprintf(`version: 0
name: unix-bind-lookup
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: []
  listen: [%q]
env:
  pass: ["PATH", "HOME"]
record: full
`, name)
				contractPath := filepath.Join(p.project, "agent.yaml")
				if err := os.WriteFile(contractPath, []byte(contract), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(contractPath, uid, gid); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var out bytes.Buffer
				if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err != nil {
					t.Fatalf("the bind workload: %v\n%s", err, out.String())
				}
				if r := agentResults(t, out.String()); r["beneath-file"] != "20" {
					t.Fatalf("the agent's bind: %q, want the kernel's ENOTDIR (20)\n%s", r["beneath-file"], out.String())
				}
				var binds []map[string]any
				for _, e := range runEvents(t, p.ledger) {
					if e["kind"] == "gap" && e["why"] == "bind-metadata-missing" {
						t.Errorf("owned lookup failure acquired a missing-kernel-metadata gap: %v", e)
					}
					if e["kind"] != "net" {
						continue
					}
					if e["rule"] == "path-unreliable" {
						t.Errorf("a line the plane's run never writes for this bind: %v", e)
					}
					if e["op"] == "bind" {
						binds = append(binds, e)
					}
				}
				if len(binds) != 1 {
					t.Fatalf("bind lines %d, want 1\n%s", len(binds), ledgerDump(p.ledger))
				}
				b := binds[0]
				if b["source"] != "supervisor" || b["verdict"] != "observed" || b["rule"] != "unmatched" ||
					b["syscall_errno"] != float64(20) || b["syscall_ret"] != float64(-20) ||
					b["dst"] != "unix:out/file/b.sock" || b["proto"] != "unix" ||
					b["mechanism"] != nil || b["decision_plane"] != nil || b["verdict_from"] != nil {
					t.Errorf("the bind's line: %v, want one supervisor-observed lookup ENOTDIR without a claimed policy decision", b)
				}
			})
		}
	}
}
