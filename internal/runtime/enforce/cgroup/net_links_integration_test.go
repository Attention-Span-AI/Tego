// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// netLinksHelperEnv selects the launcher half of TestNetLinksOutliveTheLauncher:
// "<cgroup path>|<cgroup id>|<state dir>|<allowed port>".
const netLinksHelperEnv = "TEGO_NET_LINKS_HELPER"

// TestNetLinksOutliveTheLauncher is enforce-cgroup-observe.md E38 (§6) as ADR 0020 (1) closed it: the run's cgroup
// links are pinned, so a launcher killed outright leaves the network programs on the run's cgroup. A launcher
// process prepares and attaches a tier-2 run whose only net rule allows one loopback port; a process in the run's
// cgroup is refused (EPERM) a connect to another port while the launcher lives, and still after it is SIGKILLed.
// cgroup/sock_create's link is one of them (ADR 0018 PR 2): a socket of a protocol outside ADR 0018's allowlist is
// refused before and after the kill alike. PurgeRun then keeps the run's links while its cgroup exists, and removes
// them once it is gone.
func TestNetLinksOutliveTheLauncher(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)

	rel := fmt.Sprintf("/tego-it-netlinks-%d", os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
	}
	t.Cleanup(func() { _ = os.Remove(full) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	allowedPort, refusedPort := listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1")

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher := exec.Command(self, "-test.run=^TestNetLinksHelper$")
	state := pinState(t)
	launcher.Env = append(os.Environ(), netLinksHelperEnv+"="+strings.Join(
		[]string{rel, strconv.FormatUint(id, 10), state, strconv.Itoa(allowedPort)}, "|"))
	if _, err := launcher.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := launcher.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	launcher.Stderr = os.Stderr
	launcher.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := launcher.Start(); err != nil {
		t.Fatalf("start the launcher: %v", err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = launcher.Process.Kill()
		}
		_ = launcher.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if strings.TrimSpace(line) != "attached" {
		t.Fatalf("the launcher did not attach the run: %q, %v", line, err)
	}

	dir, err := os.Open(full)
	if err != nil {
		t.Fatalf("open %s: %v", full, err)
	}
	defer dir.Close()
	target := []string{"tcp4 127.0.0.1:" + strconv.Itoa(refusedPort)}
	if got := runNetHelper(t, dir, "connect", target); len(got) != 1 || !errors.Is(got[0], syscall.EPERM) {
		t.Fatalf("with the launcher alive, a connect to a port the contract does not name = %v, want EPERM", got)
	}
	sock, sockOK := refusable()
	if !sockOK {
		t.Fatal("this kernel created none of SCTP, UDP-Lite, MPTCP and SMC: cgroup/sock_create has nothing to refuse")
	}
	if got := runNetHelper(t, dir, "socket", []string{sock.String()}); !errors.Is(got[0], syscall.EPERM) {
		t.Fatalf("with the launcher alive, socket %s = %v, want EPERM from cgroup/sock_create", sock, got[0])
	}
	if got := runNetHelper(t, dir, "ulp", []string{"smc"}); !errors.Is(got[0], syscall.EPERM) {
		t.Fatalf("with the launcher alive, TCP_ULP smc = %v, want EPERM from cgroup/setsockopt", got[0])
	}

	if err := launcher.Process.Kill(); err != nil {
		t.Fatalf("kill the launcher: %v", err)
	}
	killed = true
	_ = launcher.Wait()

	// Unpinned, a bpf_link was freed with its last fd, which follows the process's exit: give that a second.
	time.Sleep(time.Second)
	if got := runNetHelper(t, dir, "connect", target); len(got) != 1 || !errors.Is(got[0], syscall.EPERM) {
		t.Fatalf("with the launcher dead, a connect to a port the contract does not name = %v, want EPERM: the "+
			"run's links left with its launcher (E38)", got)
	}
	if got := runNetHelper(t, dir, "socket", []string{sock.String()}); !errors.Is(got[0], syscall.EPERM) {
		t.Fatalf("with the launcher dead, socket %s = %v, want EPERM: cgroup/sock_create's link left with its "+
			"launcher (ADR 0020 (1))", sock, got[0])
	}
	if got := runNetHelper(t, dir, "ulp", []string{"smc"}); !errors.Is(got[0], syscall.EPERM) {
		t.Fatalf("with the launcher dead, TCP_ULP smc = %v, want EPERM: cgroup/setsockopt's link left with its "+
			"launcher (ADR 0020 (1))", got[0])
	}
	for _, name := range ebpfbindings.SocketPrograms {
		if _, err := os.Stat(filepath.Join(DefaultBPFFS, pinRoot, mustBPFHash(t), pinLinks, runLinksPrefix+"it-netlinks",
			name)); err != nil {
			t.Fatalf("%s's link is not pinned with the run's links: %v", name, err)
		}
	}

	hash, err := bpfHash()
	if err != nil {
		t.Fatal(err)
	}
	opts := PurgeOptions{StateDir: state, Hash: hash, RunID: "it-netlinks", CgroupID: id}
	links := filepath.Join(DefaultBPFFS, pinRoot, hash, pinLinks, runLinksPrefix+"it-netlinks")
	if _, err := PurgeRun(opts); !errors.Is(err, ErrRunAlive) {
		t.Fatalf("PurgeRun with the run's cgroup alive: %v, want ErrRunAlive", err)
	}
	if _, err := os.Stat(links); err != nil {
		t.Fatalf("the run's links are not pinned at %s: %v", links, err)
	}
	_ = dir.Close()
	if err := os.Remove(full); err != nil {
		t.Fatalf("remove the run's cgroup: %v", err)
	}
	res, err := PurgeRun(opts)
	if err != nil || !res.Links {
		t.Fatalf("PurgeRun once the cgroup is gone: %+v, %v", res, err)
	}
	if _, err := os.Stat(links); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the run's links are still pinned: %v", err)
	}
}

// mustBPFHash is this test binary's bpf_hash, the build whose pins the launcher made.
func mustBPFHash(t *testing.T) string {
	t.Helper()
	hash, err := bpfHash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// TestNetLinksHelper is the launcher half of TestNetLinksOutliveTheLauncher. It does nothing in a normal run.
func TestNetLinksHelper(t *testing.T) {
	spec := os.Getenv(netLinksHelperEnv)
	if spec == "" {
		t.Skip("helper process only")
	}
	f := strings.Split(spec, "|")
	id, _ := strconv.ParseUint(f[1], 10, 64)
	port, _ := strconv.Atoi(f[3])
	rules := []agent.NetRule{{Raw: "127.0.0.1:" + f[3], Port: port, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true}}
	b := New(Options{Machine: machineLinger(0), StateDir: f[2], Events: &sink{}})
	rt := &agent.RuleTable{Net: rules, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-netlinks", Agent: "a", CgroupID: id, CgroupPath: f[0],
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	fmt.Println("attached")
	// Never returns normally: the test kills this process, which is the case under test.
	_, _ = os.Stdin.Read(make([]byte, 1))
}
