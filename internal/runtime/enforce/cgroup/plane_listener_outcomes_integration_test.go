// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
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

// TestPlaneRunIOUringListenerOutcomes is enforce-plane §2.20's records for io_uring: IORING_OP_BIND and
// IORING_OP_LISTEN (6.11+) reach the plane's socket_bind and socket_listen with no bind or listen syscall exit, so
// each still needs its one terminal line, and the listener marker its refused bind left must not outlive the op: the
// same task's later plain mknod(S_IFSOCK) in a writable directory is no bind and must succeed without a bind line.
// This test is run only in the coordinated disposable privileged guest.
func TestPlaneRunIOUringListenerOutcomes(t *testing.T) {
	bin, uid, gid, modes := planePreconditions(t)
	if b, err := os.ReadFile("/proc/sys/kernel/io_uring_disabled"); err == nil && strings.TrimSpace(string(b)) != "0" {
		t.Skipf("kernel.io_uring_disabled is %s here: io_uring_setup is EPERM to the agent whatever the plane admits", strings.TrimSpace(string(b)))
	}
	kernel, err := sys.Kernel()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	uringbind := filepath.Join(dir, "uringbind")
	build := exec.Command("go", "build", "-o", uringbind, "github.com/attention-span-ai/tego/test/workloads/uringbind")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the io_uring workload: %v: %s", err, b)
	}
	workload, err := os.ReadFile(uringbind)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			for _, recording := range []string{"full", "off"} {
				t.Run(tier+"@"+mode+"/"+recording, func(t *testing.T) {
					name := fmt.Sprintf("tego-uring-listener-%d-%d", os.Getpid(), time.Now().UnixNano())
					contract := fmt.Sprintf(`version: 0
name: uring-listener-outcomes
command: ["./bin/uringbind", %q]
fs:
  write: ["./out/"]
exec:
  allow: ["./bin/uringbind"]
net:
  allow: []
  listen: ["unix:@%s"]
io_uring: true
env:
  pass: ["PATH", "HOME"]
record: %s
`, name, name, recording)
					p := newPlaneProject(t, uid, gid, map[string]string{"agent.yaml": contract, "bin/uringbind": string(workload)},
						[]string{"out"}, nil)
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					defer cancel()
					var out bytes.Buffer
					if err := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out).Run(); err != nil {
						t.Fatalf("io_uring listener workload: %v\n%s\n%s", err, out.String(), ledgerDump(p.ledger))
					}
					res := agentResults(t, out.String())
					skip, err := uringBindGap(res["uring"], kernel)
					if err != nil {
						t.Fatalf("%v\n%s\n%s", err, out.String(), ledgerDump(p.ledger))
					}
					if skip {
						t.Skipf("kernel %s has no IORING_OP_BIND", kernel)
					}
					for step, want := range map[string][]string{
						"uring-bind-undeclared-abstract": {"13", "1"}, "uring-bind-undeclared-path": {"13", "1"},
						"standalone-mknod": {"0"}, "uring-listen-unbound": {"13", "1"},
						"uring-bind-declared": {"0"}, "uring-listen-declared": {"0"},
					} {
						if !slices.Contains(want, res[step]) {
							t.Errorf("%s: errno %q, want one of %v", step, res[step], want)
						}
					}
					var binds, listens []map[string]any
					for _, e := range runEvents(t, p.ledger) {
						if e["kind"] != "net" || e["op"] != "bind" && e["op"] != "listen" {
							continue
						}
						if e["source"] != "kernel" || e["proto"] != "unix" {
							t.Errorf("terminal source/protocol: %v", e)
						}
						if strings.Contains(fmt.Sprint(e["dst"]), "uring-standalone.sock") {
							t.Errorf("standalone mknod fabricated a bind: %v", e)
						}
						if e["op"] == "bind" {
							binds = append(binds, e)
						} else {
							listens = append(listens, e)
						}
					}
					wantBinds, wantListens := 3, 2
					if recording == "off" {
						wantBinds, wantListens = 2, 1 // refusals are recorded whatever record says
					}
					if len(binds) != wantBinds || len(listens) != wantListens {
						t.Fatalf("io_uring terminal binds/listens=%d/%d want %d/%d\n%s\n%s", len(binds), len(listens),
							wantBinds, wantListens, out.String(), ledgerDump(p.ledger))
					}
					if binds[0]["verdict"] != "refused" || binds[0]["dst"] != "unix:@"+name+"-undeclared" ||
						binds[0]["syscall_ret"] != float64(-13) {
						t.Errorf("undeclared abstract io_uring bind: %v", binds[0])
					}
					if listens[0]["verdict"] != "refused" || listens[0]["syscall_ret"] != float64(-13) {
						t.Errorf("unbound io_uring listen: %v", listens[0])
					}
					if recording == "full" && (binds[2]["verdict"] != "allow" || binds[2]["dst"] != "unix:@"+name ||
						listens[1]["verdict"] != "allow") {
						t.Errorf("declared io_uring bind/listen: %v %v", binds[2], listens[1])
					}
				})
			}
		}
	}
}
