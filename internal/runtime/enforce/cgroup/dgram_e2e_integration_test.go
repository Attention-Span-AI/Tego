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
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestTier2DatagramLineIsTheKernels is §5 R7's record half for an addressed datagram, through the whole of `tego
// run --tier cgroup` as root under sudo: a datagram a kernel program of the run decides by destination has exactly
// one ledger line, and that line is the kernel's verdict, never the supervisor's best effort beside it (ADR 0016;
// supervisor.md R13b, Options.KernelDatagrams).
//
//   - cgroup/sendmsg_unix (6.7+) and, below 6.7, the decision plane's socket_sendmsg (step D, enforce-plane §2.11)
//     refuse a unix name no entry admits, and a name spelled other than canonically (`<write entry>/./x.dg`), which the
//     supervisor's own check cleans and admits. Each such datagram's line is refused, with the errno the kernel
//     program fails it with (EPERM, or EACCES for the plane), and carries no best_effort; before, the first was
//     recorded refused with best_effort ("recorded without enforcing" of an enforced refusal) and the second allow.
//   - cgroup/sendmsg4 refuses a UDP destination no entry admits, on every kernel tier 2 runs on: the same line.
//   - An admitted datagram leaves, and its one line is allow.
//
// On the fanotify fallback below 6.7 no program decides a unix name (§6 E1): the supervisor decides it as at tier 1,
// so the unlisted unix datagram is refused there with EACCES and no best_effort (supervisor R13b as amended
// 2026-10-16), and the non-canonical one, which its cleaned match admits, leaves under a best-effort allow line. The
// test records which case it ran.
func TestTier2DatagramLineIsTheKernels(t *testing.T) {
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
	base, err := os.MkdirTemp("", "eydg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	bin := buildTaggedTego(t, base)
	requireTier(t, bin, "cgroup")
	stepD := false
	if !unixHooks {
		switch planeSelected(t, bin, "") {
		case "lsm", "fmod_ret":
			stepD = true
		}
	}
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	socks := filepath.Join(base, "s")
	if err := os.Mkdir(socks, 0o755); err != nil {
		t.Fatal(err)
	}
	listedDgram, unlistedDgram := filepath.Join(socks, "listed.dg"), filepath.Join(socks, "unlisted.dg")
	receiveUnixgram(t, listedDgram)
	strays, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: unlistedDgram, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer strays.Close()
	for _, p := range []string{listedDgram, unlistedDgram} {
		if err := os.Chmod(p, 0o777); err != nil { // the agent runs as the sudo caller
			t.Fatal(err)
		}
	}
	udpListed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpListed.Close()
	udpStrays, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpStrays.Close()
	listedPort, unlistedPort := udpListed.LocalAddr().(*net.UDPAddr).Port, udpStrays.LocalAddr().(*net.UDPAddr).Port

	project := filepath.Join(base, "p")
	if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "agent.py"), []byte(dgramE2EAgent), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(contract, []byte(fmt.Sprintf(dgramE2EContract, listedDgram, listedPort)), 0o644); err != nil {
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
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "E2E_SOCK="+socks,
		"E2E_UDP_LISTED="+strconv.Itoa(listedPort), "E2E_UDP_UNLISTED="+strconv.Itoa(unlistedPort))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	t.Logf("tego run on %s (sendmsg_unix %t, step D %t): %v\nstdout:\n%s\nstderr:\n%s", release, unixHooks, stepD,
		runErr, stdout.String(), stderr.String())
	if runErr != nil {
		t.Fatalf("`tego run --tier cgroup` did not run to completion: %v", runErr)
	}
	results := agentResults(t, stdout.String())
	project, err = filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(project, "out")

	// A cell is one datagram: the agent's result, and the one line its destination gets.
	type cell struct {
		name, dst, result, verdict string
		bestEffort                 bool
	}
	unixRefused := ""
	switch {
	case unixHooks:
		unixRefused = "refused errno=1" // sendmsg_unix's, in the kernel
	case stepD:
		unixRefused = "refused errno=13" // the plane's socket_sendmsg
	}
	cells := []cell{
		{"udp-unlisted", "127.0.0.1:" + strconv.Itoa(unlistedPort), "refused errno=1", "refused", false},
		{"udp-listed", "127.0.0.1:" + strconv.Itoa(listedPort), "ok", "allow", true},
		{"unix-listed", "unix:" + listedDgram, "ok", "allow", true},
		{"unix-own", "unix:" + out + "/own.dg", "ok", "allow", true},
	}
	if unixRefused != "" {
		cells = append(cells,
			cell{"unix-unlisted", "unix:" + unlistedDgram, unixRefused, "refused", false},
			cell{"unix-noncanonical", "unix:" + out + "/./own.dg", unixRefused, "refused", false})
	} else {
		// The fallback: nothing in the kernel decides a unix name. The supervisor refuses the unlisted one itself,
		// with EACCES, and continues the non-canonical one its cleaned match admits, under a best-effort line.
		cells = append(cells,
			cell{"unix-unlisted", "unix:" + unlistedDgram, "refused errno=13", "refused", false},
			cell{"unix-noncanonical", "unix:" + out + "/./own.dg", "ok", "allow", true})
	}
	events := runEvents(t, ledgerRoot)
	for _, c := range cells {
		if got := results[c.name]; got != c.result {
			t.Errorf("%s on %s: the agent saw %q, want %q", c.name, release, got, c.result)
		}
		var lines []map[string]any
		for _, e := range events {
			if e["kind"] == "net" && e["dst"] == c.dst {
				lines = append(lines, e)
			}
		}
		if len(lines) != 1 {
			t.Errorf("%s: %d net lines for %s, want exactly one: %v", c.name, len(lines), c.dst, lines)
			continue
		}
		e := lines[0]
		be, _ := e["best_effort"].(bool)
		if e["verdict"] != c.verdict || be != c.bestEffort {
			t.Errorf("%s: the line for %s is %v (best_effort %t), want verdict %s with best_effort %t", c.name, c.dst, e,
				be, c.verdict, c.bestEffort)
		}
		if c.verdict == "refused" && !c.bestEffort && e["reason"] != "net-not-allowed" {
			t.Errorf("%s: the refusal of %s has reason %v, want net-not-allowed", c.name, c.dst, e["reason"])
		}
	}

	buf := make([]byte, 16)
	_ = strays.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, rerr := strays.ReadFrom(buf); rerr == nil {
		t.Errorf("a datagram reached %s, which the contract does not name", unlistedDgram)
	}
	_ = udpStrays.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, rerr := udpStrays.ReadFrom(buf); rerr == nil {
		t.Errorf("a datagram reached 127.0.0.1:%d, which the contract does not name", unlistedPort)
	}
	end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
	if code, _ := end["exit_code"].(float64); end == nil || end["reason"] != "exit" || code != 0 {
		t.Errorf("run_end %v, want reason exit with exit code 0", end)
	}
}

// dgramE2EContract declares one unix datagram socket, one UDP port and a write directory, nothing else.
const dgramE2EContract = `version: 0
name: t2-dgram
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3"]
net:
  allow: ["unix:%s", "127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME", "E2E_SOCK", "E2E_UDP_LISTED", "E2E_UDP_UNLISTED"]
record: full
`

// dgramE2EAgent sends one addressed datagram per check and reports each as one "RESULT <name> <outcome>" line.
const dgramE2EAgent = `import os, socket
S = os.environ["E2E_SOCK"]
LISTED, UNLISTED = int(os.environ["E2E_UDP_LISTED"]), int(os.environ["E2E_UDP_UNLISTED"])

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def attempt(name, fn):
    try:
        fn()
        result(name, "ok")
    except OSError as e:
        result(name, "refused errno=%d" % e.errno)

def unixgram(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"x", path)
    s.close()

def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"x", ("127.0.0.1", port))
    s.close()

own = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
own.bind("out/own.dg")
out = os.path.realpath("out")
attempt("udp-unlisted", lambda: udp(UNLISTED))
attempt("udp-listed", lambda: udp(LISTED))
attempt("unix-listed", lambda: unixgram(S + "/listed.dg"))
attempt("unix-own", lambda: unixgram(out + "/own.dg"))
attempt("unix-unlisted", lambda: unixgram(S + "/unlisted.dg"))
attempt("unix-noncanonical", lambda: unixgram(out + "/./own.dg"))
`
