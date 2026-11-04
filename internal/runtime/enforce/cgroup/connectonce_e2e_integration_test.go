// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestTier2ConnectHasOneLine holds R7's one line per connect at tier cgroup,
// for TCP, Unix and resolver connects, with summary and full recording. ADR
// 0113 freezes every enforcing connect to protect local control ports as well
// as Unix servers, including with no net: section. These relayed connects run
// outside the agent's cgroup, so the supervisor owns their one result line.
// Both root builds run this (test/vm/root-must-pass.txt).
func TestTier2ConnectHasOneLine(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	base, err := os.MkdirTemp("", "eyco")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	bin := buildTaggedTego(t, base)
	requireTier(t, bin, "cgroup")
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	tcpDst := tl.Addr().String()
	sock := filepath.Join(base, "s.sock")
	acceptUnix(t, sock)
	if err := os.Chmod(sock, 0o777); err != nil { // the agent runs as the sudo caller
		t.Fatal(err)
	}

	for _, rec := range []string{"summary", "full"} {
		t.Run("record="+rec, func(t *testing.T) {
			dir := filepath.Join(base, rec)
			project := filepath.Join(dir, "p")
			if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(project, "agent.py"), []byte(connectOnceAgent), 0o644); err != nil {
				t.Fatal(err)
			}
			contract := filepath.Join(project, "agent.yaml")
			if err := os.WriteFile(contract, []byte(fmt.Sprintf(connectOnceContract, rec)), 0o644); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{dir, project, filepath.Join(project, "out"), filepath.Join(project, "agent.py"), contract} {
				if err := os.Lchown(p, uid, gid); err != nil {
					t.Fatal(err)
				}
			}
			ledgerRoot := filepath.Join(dir, "ledger")
			if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: [%s]\n", ledgerRoot, connectOnceResolver)), 0o644); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cmd := tegoRunCommand(ctx, bin, "run", "--tier", "cgroup", contract, "--", python, "./agent.py", tcpDst, sock)
			cmd.Dir = project
			cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			t.Logf("tego run: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout.String(), stderr.String())
			if runErr != nil {
				t.Fatalf("`tego run --tier cgroup` did not run to completion: %v", runErr)
			}
			results := agentResults(t, stdout.String())
			for _, name := range []string{"tcp", "unix", "dns"} {
				if got := results[name]; got != "ok" {
					t.Fatalf("%s connects: %q, want ok", name, got)
				}
			}

			var tcpLines, unixLines, dnsLines []map[string]any
			for _, e := range runEvents(t, ledgerRoot) {
				if e["kind"] != "net" {
					continue
				}
				switch e["dst"] {
				case tcpDst:
					tcpLines = append(tcpLines, e)
				case "unix:" + sock:
					unixLines = append(unixLines, e)
				case connectOnceResolver + ":53":
					dnsLines = append(dnsLines, e)
				}
			}
			if len(tcpLines) != connectOnceCount {
				t.Errorf("%d lines for %d TCP connects to %s, want one each: %v", len(tcpLines), connectOnceCount, tcpDst,
					tcpLines)
			}
			for _, e := range tcpLines {
				if e["source"] != "supervisor" {
					t.Errorf("a TCP connect's line came from %v, want the supervisor relay's: %v", e["source"], e)
				}
				if e["rule"] != "unmatched" || e["verdict"] != "allow" {
					t.Errorf("a TCP connect no entry names is %v/%v, want the supervisor's unmatched/allow: %v",
						e["rule"], e["verdict"], e)
				}
			}
			// The relay preserves the resolver exception as well as the result (R7).
			if len(dnsLines) != connectOnceCount {
				t.Errorf("%d lines for %d UDP connects to the resolver %s:53, want one each: %v", len(dnsLines),
					connectOnceCount, connectOnceResolver, dnsLines)
			}
			for _, e := range dnsLines {
				if e["source"] != "supervisor" || e["rule"] != "net.resolver" || e["verdict"] != "allow" {
					t.Errorf("a resolver connect's line is %v %v/%v, want the supervisor's net.resolver/allow: %v",
						e["source"], e["rule"], e["verdict"], e)
				}
			}
			if len(unixLines) != connectOnceCount {
				t.Errorf("%d lines for %d unix connects to %s, want one each: %v", len(unixLines), connectOnceCount, sock,
					unixLines)
			}
			for _, e := range unixLines {
				if e["source"] != "supervisor" {
					t.Errorf("a unix connect's line came from %v, want the supervisor's: %v", e["source"], e)
				}
			}
		})
	}
}

// connectOnceCount is how many connects of each kind the agent makes.
const connectOnceCount = 3

// connectOnceResolver is the run's one resolver (the machine config's resolver list): the agent's UDP
// connects to it on port 53 fall under the resolver exception (supervisor.md R14). A UDP connect sends
// nothing, so no server has to answer there.
const connectOnceResolver = "127.0.0.2"

// connectOnceContract has no net: section. host_sockets: true admits the test's
// ordinary Unix peer; the immutable built-in boundary still freezes all connects.
const connectOnceContract = `version: 0
name: t2-connect-once
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
env:
  pass: ["PATH", "HOME"]
host_sockets: true
record: %s
`

// connectOnceAgent connects to argv[1] (host:port), to the unix socket argv[2] and over UDP to the resolver
// (connectOnceResolver) on port 53, three times each.
const connectOnceAgent = `import socket, sys
host, port = sys.argv[1].rsplit(":", 1)

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

try:
    for _ in range(3):
        socket.create_connection((host, int(port)), timeout=5).close()
    result("tcp", "ok")
except OSError as e:
    result("tcp", "errno=%d" % e.errno)
try:
    for _ in range(3):
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        u.settimeout(5)
        u.connect(sys.argv[2])
        u.close()
    result("unix", "ok")
except OSError as e:
    result("unix", "errno=%d" % e.errno)
try:
    for _ in range(3):
        d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        d.connect(("127.0.0.2", 53))
        d.close()
    result("dns", "ok")
except OSError as e:
    result("dns", "errno=%d" % e.errno)
`
