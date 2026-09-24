// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestTier2UnixEndToEnd is §5 R7 through the whole of `tego run --tier cgroup`, as root under sudo: the real
// supervisor relays the agent's unix connects and continues its datagrams, and connect_unix and sendmsg_unix
// decide beside it in the kernel. It pins the two halves that must agree:
//
//   - a connect to a declared socket succeeds: the supervisor relays it through /proc/self/fd/<n> from the
//     launcher's cgroup, and connect_unix must admit that name from there (Attach's relay cgroup), or every
//     declared unix socket would be refused at tier 2;
//   - an addressed datagram to a socket the contract does not name is refused in the kernel on 6.7+, where the
//     supervisor only records it and continues (supervisor.md R13b), and leaves on an older kernel, where the
//     programs are not loaded (§6 E1); a datagram to a declared socket, and to one the run bound beneath its
//     write entry (SEMANTICS §5), leaves either way.
func TestTier2UnixEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the end-to-end run belongs to the tegobpf suite: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("kernel release %q: %v", release, err)
	}
	unixHooks := major > 6 || (major == 6 && minor >= 7)

	// Short paths: a sun_path holds 107 bytes.
	base, err := os.MkdirTemp("", "eyue")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	bin := buildTaggedTego(t, base)
	requireTier(t, bin, "cgroup")
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	socks := filepath.Join(base, "s")
	if err := os.Mkdir(socks, 0o755); err != nil {
		t.Fatal(err)
	}
	listed, unlisted := filepath.Join(socks, "listed.sock"), filepath.Join(socks, "unlisted.sock")
	listedDgram, unlistedDgram := filepath.Join(socks, "listed.dg"), filepath.Join(socks, "unlisted.dg")
	acceptUnix(t, listed)
	acceptUnix(t, unlisted)
	receiveUnixgram(t, listedDgram)
	strays, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unlistedDgram, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer strays.Close()
	for _, p := range []string{listed, unlisted, listedDgram, unlistedDgram} {
		if err := os.Chmod(p, 0o777); err != nil { // the agent runs as the sudo caller
			t.Fatal(err)
		}
	}

	project := filepath.Join(base, "p")
	if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "agent.py"), []byte(unixE2EAgent), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(contract, []byte(fmt.Sprintf(unixE2EContract, listed, listedDgram)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(project, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledgerRoot)), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := tegoRunCommand(ctx, bin, "run", "--tier", "cgroup", contract, "--", python, "./agent.py")
	cmd.Dir = project
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "E2E_SOCK="+socks)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	t.Logf("tego run: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout.String(), stderr.String())
	if runErr != nil {
		t.Fatalf("`tego run --tier cgroup` did not run to completion: %v", runErr)
	}
	results := agentResults(t, stdout.String())

	want := map[string]string{
		"stream-listed":   "ok",
		"stream-unlisted": "refused errno=13", // the supervisor's refusal (supervisor.md R10)
		"dgram-listed":    "ok",
		"dgram-own":       "ok",
		"dgram-unlisted":  "ok",
	}
	// Below 6.7 a plane mode decides unix names in socket_sendmsg (step D, T15, enforce-plane §2.11): EACCES in the
	// kernel. Only the fanotify fallback leaves an unlisted datagram name undecided there (found on RHEL 9's 5.14 by
	// TIER3-PLAN T11, where the plane runs in LSM mode).
	stepD := false
	if !unixHooks {
		switch planeSelected(t, bin, "") {
		case "lsm", "fmod_ret":
			stepD = true
		}
	}
	switch {
	case unixHooks:
		want["dgram-unlisted"] = "refused errno=1" // sendmsg_unix's, in the kernel
	case stepD:
		want["dgram-unlisted"] = "refused errno=13" // the plane's socket_sendmsg
	}
	for name, w := range want {
		if got := results[name]; got != w {
			t.Errorf("%s on %s: %q, want %q", name, release, got, w)
		}
	}
	_ = strays.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 16)
	_, _, rerr := strays.ReadFrom(buf)
	var ne net.Error
	gotStray := rerr == nil
	if (unixHooks || stepD) && gotStray {
		t.Errorf("a datagram reached %s, which the contract does not name", unlistedDgram)
	}
	if !unixHooks && !stepD && rerr != nil && !(errors.As(rerr, &ne) && ne.Timeout()) {
		t.Errorf("read %s: %v", unlistedDgram, rerr)
	}

	events := runEvents(t, ledgerRoot)
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "net" && e["verdict"] == "allow" && e["dst"] == "unix:"+listed
	}) == nil {
		t.Errorf("no allow line for the relayed connect to %s", listed)
	}
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "net" && e["verdict"] == "refused" && e["dst"] == "unix:"+unlistedDgram
	}) == nil {
		t.Errorf("no refused line for the datagram to %s", unlistedDgram)
	}
	end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
	if code, _ := end["exit_code"].(float64); end == nil || end["reason"] != "exit" || code != 0 {
		t.Errorf("run_end %v, want reason exit with exit code 0", end)
	}
	if !strings.Contains(stdout.String(), "RESULT dgram-own") {
		t.Error("the agent did not reach its last check")
	}
}

// unixE2EContract declares one stream and one datagram socket and a write directory, nothing else.
const unixE2EContract = `version: 0
name: t2-unix
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: ["unix:%s", "unix:%s"]
env:
  pass: ["PATH", "HOME", "E2E_SOCK"]
record: full
`

// unixE2EAgent reports each check as one "RESULT <name> <outcome>" line.
const unixE2EAgent = `import os, socket
S = os.environ["E2E_SOCK"]

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def attempt(name, fn):
    try:
        fn()
        result(name, "ok")
    except OSError as e:
        result(name, "refused errno=%d" % e.errno)

def stream(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    s.close()

def dgram(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", path)
    s.close()

attempt("stream-listed", lambda: stream(S + "/listed.sock"))
attempt("stream-unlisted", lambda: stream(S + "/unlisted.sock"))
attempt("dgram-listed", lambda: dgram(S + "/listed.dg"))
attempt("dgram-unlisted", lambda: dgram(S + "/unlisted.dg"))
own = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
own.bind("out/own.dg")
attempt("dgram-own", lambda: dgram(os.path.abspath("out/own.dg")))
`
