// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestPlaneRunBindLookupFailureIsTheKernels is the run's half of ADR 0019's design note (-2s4-3): under a listener
// policy a decision-plane run hands a pathname unix bind
// to the plane (the supervisor's bindHandoffReady), which decides it at path_mknod, and a bind whose lookup fails (here
// beneath a regular file, ENOTDIR) never reaches that hook. The agent gets the kernel's own errno, and the bind's one
// line is the kernel recorder's, observed, rule unmatched, with that errno: no line is refused path-unreliable, the
// supervisor bindUnix's answer, which compile --test's plane column gave such a row before the note
// (limits-check-doctor-cli R28's net.bind amendment; that column now answers the row on its spelling).
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
				if b["source"] != "kernel" || b["verdict"] != "observed" || b["rule"] != "unmatched" ||
					b["syscall_errno"] != float64(20) || !strings.HasPrefix(fmt.Sprint(b["dst"]), "unix:") ||
					!strings.HasSuffix(fmt.Sprint(b["dst"]), "out/file/b.sock") {
					t.Errorf("the bind's line: %v, want the kernel recorder's observed, rule unmatched, errno 20", b)
				}
			})
		}
	}
}
