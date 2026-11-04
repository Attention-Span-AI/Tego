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

const listenerOutcomesAgent = `import errno, os, socket
held = []
def attempt(name, fn, expected):
    result = 0
    try:
        fn()
    except OSError as e:
        result = e.errno
    print("RESULT", name, result, flush=True)
    assert result in expected, (name, result, expected)
def bind(name, address, expected):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    held.append(s)
    attempt(name, lambda: s.bind(address), expected)
    return s
path = bind("allowed-path", "out/allowed.sock", (0,))
attempt("allowed-path-listen", lambda: path.listen(4), (0,))
bind("path-busy", "out/allowed.sock", (errno.EADDRINUSE,))
bind("undeclared-path", "out/other.sock", (errno.EACCES, errno.EPERM))
bind("outside-floor", "outside/blocked.sock", (errno.EACCES, errno.EPERM))
abstract = bind("allowed-abstract", "\0%s", (0,))
attempt("allowed-abstract-listen", lambda: abstract.listen(4), (0,))
bind("abstract-nul-alias", "\0%s\0extra", (errno.EACCES, errno.EPERM))
unbound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
held.append(unbound)
attempt("unbound-listen", lambda: unbound.listen(4), (errno.EACCES, errno.EPERM))
# This is a filesystem operation, not a bind attempt. It must retain its floor
# and must never acquire a fabricated terminal network line.
attempt("standalone-mknod", lambda: os.mknod("out/standalone.sock", 0o140600), (0,))
assert not os.path.exists("out/other.sock")
assert not os.path.exists("outside/blocked.sock")
for s in held:
    s.close()
`

// Real continued Unix bind/listen operations need one kernel terminal record;
// successful image/filesystem telemetry and standalone mknod are independent.
// This test is run only in the coordinated disposable privileged guest.
func TestPlaneRunUnixListenerOutcomes(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			for _, recording := range []string{"full", "off"} {
				t.Run(tier+"@"+mode+"/"+recording, func(t *testing.T) {
					name := fmt.Sprintf("tego-listener-%d-%d", os.Getpid(), time.Now().UnixNano())
					p := newPlaneProject(t, uid, gid, map[string]string{"agent.py": fmt.Sprintf(listenerOutcomesAgent, name, name)}, []string{"out", "outside"}, nil)
					contract := fmt.Sprintf(`version: 0
name: unix-listener-outcomes
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: []
  listen: [%q, %q, "unix:@%s"]
env:
  pass: ["PATH", "HOME"]
record: %s
`, "unix:"+filepath.Join(p.project, "out/allowed.sock"), "unix:"+filepath.Join(p.project, "outside/blocked.sock"), name, recording)
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
						t.Fatalf("actual Unix listener workload: %v\n%s", err, out.String())
					}
					results := agentResults(t, out.String())
					if len(results) != 10 {
						t.Fatalf("actual operations=%d want10: %s", len(results), out.String())
					}
					binds, listens := []map[string]any{}, []map[string]any{}
					for _, e := range runEvents(t, p.ledger) {
						if e["kind"] != "net" || e["op"] != "bind" && e["op"] != "listen" {
							continue
						}
						if e["source"] != "kernel" || e["proto"] != "unix" {
							t.Errorf("terminal source/protocol: %v", e)
						}
						if strings.Contains(fmt.Sprint(e["dst"]), "standalone.sock") {
							t.Errorf("standalone mknod fabricated bind: %v", e)
						}
						if e["op"] == "bind" {
							binds = append(binds, e)
						} else {
							listens = append(listens, e)
						}
						if e["verdict"] == "refused" && e["syscall_ret"] != float64(-13) && e["syscall_ret"] != float64(-1) {
							t.Errorf("refusal lost actual errno: %v", e)
						}
					}
					wantBinds, wantListens := 6, 3
					if recording == "off" {
						wantBinds, wantListens = 3, 1
					}
					if len(binds) != wantBinds || len(listens) != wantListens {
						t.Fatalf("terminal binds/listens=%d/%d want%d/%d\n%s\n%s", len(binds), len(listens), wantBinds, wantListens, out.String(), ledgerDump(p.ledger))
					}
					if recording == "full" {
						if binds[0]["dst"] != "unix:"+filepath.Join(p.project, "out/allowed.sock") || binds[0]["verdict"] != "allow" || binds[0]["syscall_errno"] != nil {
							t.Errorf("relative bind inode proof: %v", binds[0])
						}
						if binds[1]["verdict"] != "observed" || binds[1]["syscall_ret"] != float64(-98) || binds[1]["verdict_from"] != "unknown" {
							t.Errorf("pre-mknod EADDRINUSE invented decision: %v", binds[1])
						}
						if listens[0]["dst"] != "unix:"+filepath.Join(p.project, "out/allowed.sock") || listens[0]["verdict"] != "allow" {
							t.Errorf("listen did not use actual bound dentry: %v", listens[0])
						}
					}
				})
			}
		}
	}
}

// TestPlaneRunIOUringListenerOutcomes now requires startup refusal, including
// an explicit listener allowance: ADR 0113 precedes the old ring admission.
func TestPlaneRunIOUringListenerOutcomes(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		for _, tier := range []string{"cgroup", "bpflsm"} {
			if tier == "bpflsm" && mode != "lsm" {
				continue
			}
			t.Run(tier+"@"+mode, func(t *testing.T) {
				p := newPlaneProject(t, uid, gid, map[string]string{"agent.yaml": `version: 0
name: ring-listener-refusal
command: ["/bin/true"]
io_uring: true
net:
  allow: []
  listen: ["unix:@builtin-ring"]
`}, nil, nil)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				var out bytes.Buffer
				if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err == nil || !strings.Contains(out.String(), "builtin.host_ipc") {
					t.Fatalf("listener allow reopened ring path: %v\n%s", err, out.String())
				}
			})
		}
	}
}
