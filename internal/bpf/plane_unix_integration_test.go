// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// TIER3-PLAN T15's root cells: step D's socket_connect and socket_sendmsg (enforce-plane R14), in each build and
// mode this kernel offers, decide a run's unix names as cgroup/connect_unix and sendmsg_unix do on 6.7+ (the same
// rows, the same rule, enforce-cgroup-observe §5 R7), refusing with EACCES. The agent is planeUnixHelper, this test
// binary re-executed into a child cgroup, whose sockets are the run's; the supervisor's relay is this process,
// connecting a pidfd_getfd duplicate of one of them.

const planeUnixHelperEnv = "TEGO_PLANE_UNIX_HELPER"

func init() {
	if os.Getenv(planeUnixHelperEnv) != "1" {
		return
	}
	runtime.LockOSThread()
	os.Exit(planeUnixHelperMain())
}

// planeUnixHelperMain answers one command per line: "<op> <name>" with the errno of one socket of the op's type
// (0 when it went ahead), and "hold" with the number of a stream socket it keeps open.
func planeUnixHelperMain() int {
	in := bufio.NewScanner(os.Stdin)
	fmt.Println("ready")
	for in.Scan() {
		verb, arg, _ := strings.Cut(in.Text(), " ")
		if verb == "hold" {
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				fmt.Println("err " + err.Error())
				continue
			}
			fmt.Println(fd)
			continue
		}
		fmt.Println(errnoString(planeUnixOp(verb, arg)))
	}
	return 0
}

// planeUnixOp makes one connect or datagram on a new socket: connect (stream), dgram-connect, sendto, and procfd, a
// stream connect naming an O_PATH descriptor of arg as /proc/self/fd/<n>, the relay's name shape.
func planeUnixOp(verb, arg string) error {
	typ := unix.SOCK_STREAM
	if verb == "sendto" || verb == "dgram-connect" {
		typ = unix.SOCK_DGRAM
	}
	fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	switch verb {
	case "connect", "dgram-connect":
		return unix.Connect(fd, &unix.SockaddrUnix{Name: arg})
	case "sendto":
		return unix.Sendto(fd, []byte("x"), 0, &unix.SockaddrUnix{Name: arg})
	case "procfd":
		pfd, err := unix.Open(arg, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(pfd)
		return unix.Connect(fd, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(pfd)})
	}
	return fmt.Errorf("unknown op %q", verb)
}

// TestPlaneUnixHooksDecide is enforce-plane R14 on a real kernel: below 6.7, where tier 2 has no unix hook, the
// plane's socket_connect and socket_sendmsg refuse a run's connect or datagram to a name no unix: or write entry
// admits, allow a listed one, admit the relay's /proc/self/fd/<n> from the launcher's cgroup only, and refuse every
// name of a run whose slot holds no unix policy of its gen (counted as norows); a policy that decides nothing, and
// a socket of no run, pass. Each decision is recorded in the task's scratch value.
func TestPlaneUnixHooksDecide(t *testing.T) {
	requireBPF(t)
	ran := 0
	for _, o := range PlaneObjects() {
		t.Run(o.String(), func(t *testing.T) {
			if ok, why := planeReaderUsable(t, o); !ok {
				t.Skip(why)
			}
			for _, mode := range PlaneModes {
				t.Run(string(mode), func(t *testing.T) {
					if ok, why := planeModeUsable(mode); !ok {
						t.Skip(why)
					}
					planeUnixCells(t, o, mode)
					ran++
				})
			}
		})
	}
	if ran == 0 {
		t.Fatal("no plane build ran in any mode on this kernel")
	}
}

func planeUnixCells(t *testing.T, o Object, mode PlaneMode) {
	const runIdx, gen = 9, 7777
	spec, err := Load(o)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unpin(spec)
	keep := map[string]bool{}
	var hooks []PlaneHook
	for _, h := range PlaneHooks {
		if h.Unix {
			keep[h.Program(mode)] = true
			hooks = append(hooks, h)
		}
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load %s %s: %+v", o, mode, ve)
		}
		t.Fatalf("load %s %s: %v", o, mode, err)
	}
	t.Cleanup(coll.Close)
	for _, h := range hooks {
		p := coll.Programs[h.Program(mode)]
		if info, err := p.Info(); err == nil {
			if n, ok := info.VerifiedInstructions(); ok {
				t.Logf("%s: %d instructions verified", h.Program(mode), n)
				if n > planeVerifiedBudget {
					t.Errorf("%s: %d instructions verified, over the budget of %d", h.Program(mode), n, planeVerifiedBudget)
				}
			}
		}
		var l link.Link
		if mode == PlaneLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: p})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachModifyReturn})
		}
		if err != nil {
			t.Fatalf("attach %s: %v", h.Program(mode), err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}

	// The names, as TestUnixVerdictOnRealKernel's (internal/runtime/enforce/cgroup): sun_path holds 108 bytes, so
	// the tree is made under /tmp whatever TMPDIR says.
	base, err := os.MkdirTemp("/tmp", "eyu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work := filepath.Join(base, "work")
	secret := filepath.Join(work, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	tag := strconv.Itoa(os.Getpid()) + "-" + string(o) + "-" + string(mode)
	listed, unlisted := filepath.Join(base, "listed.sock"), filepath.Join(base, "unlisted.sock")
	listedDgram, unlistedDgram := filepath.Join(base, "listed.dg"), filepath.Join(base, "unlisted.dg")
	workDgram, secretDgram := filepath.Join(work, "ok.dg"), filepath.Join(secret, "no.dg")
	absListed, absUnlisted := "@tego-pu-listed-"+tag, "@tego-pu-unlisted-"+tag
	for _, p := range []string{listed, unlisted, absListed, absUnlisted} {
		planeAcceptUnix(t, p)
	}
	for _, p := range []string{listedDgram, unlistedDgram, workDgram, secretDgram} {
		c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
		if err != nil {
			t.Fatalf("listen unixgram %s: %v", p, err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}

	names := coll.Maps[MapUnixNames]
	key := func(k UnixKey, err error) UnixKey {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	row := func(k UnixKey, v Verdict, rule uint16) {
		t.Helper()
		if err := names.Put(&k, &NetVerdict{Verdict: uint8(v), RuleIdx: rule}); err != nil {
			t.Fatalf("unix row: %v", err)
		}
	}
	row(key(UnixPathKey(runIdx, listed, false)), VerdictAllow, 1)
	row(key(UnixPathKey(runIdx, listedDgram, false)), VerdictAllow, 2)
	row(key(UnixAbstractKey(runIdx, []byte(absListed[1:]))), VerdictAllow, 3)
	row(key(UnixPathKey(runIdx, work, true)), VerdictAllow, 4)
	row(key(UnixPathKey(runIdx, work, false)), VerdictAllow, 4)
	row(key(UnixPathKey(runIdx, secret, true)), VerdictRefused, 5)
	row(key(UnixPathKey(runIdx, secret, false)), VerdictRefused, 5)

	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var selfID uint64
	for _, line := range strings.Split(strings.TrimSpace(string(self)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			var st unix.Stat_t
			if err := unix.Stat(filepath.Join("/sys/fs/cgroup", p), &st); err != nil {
				t.Fatal(err)
			}
			selfID = st.Ino
		}
	}
	policy := coll.Maps[MapPlaneUnixPolicy]
	setPolicy := func(p PlaneUnix) {
		t.Helper()
		if err := policy.Put(uint32(runIdx), &p); err != nil {
			t.Fatalf("unix policy: %v", err)
		}
	}
	setPolicy(PlaneUnix{Gen: gen, Decides: 1, RelayCgroupID: selfID})
	if err := coll.Maps[MapPlaneCounters].Put(uint32(runIdx), PlaneCounts{}); err != nil {
		t.Fatal(err)
	}
	// The slot's header (enforce-plane R6): this run's gen, and the plane decides its unix names.
	setSlot := func(gen, flags uint32) {
		t.Helper()
		if err := coll.Maps[MapPlaneSlots].Put(uint32(runIdx), PlaneSlot{Gen: gen, Flags: flags}); err != nil {
			t.Fatal(err)
		}
	}
	setSlot(gen, PlaneSlotUnixDecides)

	_, cgfd, cgid := planeChildCgroup(t, "unix-"+string(o)+"-"+string(mode))
	helper := startPlaneUnixHelper(t, cgfd, base)
	if err := coll.Maps[MapRunSet].Put(cgid, Run{RunIdx: runIdx, Tier: 3, Plane: RunPlaneOf(mode), Gen: gen}); err != nil {
		t.Fatalf("arm: %v", err)
	}
	t.Cleanup(func() { _ = coll.Maps[MapRunSet].Delete(cgid) })

	eacces, ok := strconv.Itoa(int(unix.EACCES)), "0"
	cells := []struct{ op, want string }{
		{"connect " + listed, ok},
		{"connect " + unlisted, eacces},
		{"connect " + filepath.Join(base, "missing.sock"), eacces}, // decided before the lookup
		{"connect " + absListed, ok},
		{"connect " + absUnlisted, eacces},
		{"connect listed.sock", eacces}, // relative: never the supervisor's relay
		{"dgram-connect " + listedDgram, ok},
		{"dgram-connect " + unlistedDgram, eacces},
		{"sendto " + listedDgram, ok},
		{"sendto " + unlistedDgram, eacces},
		{"sendto " + workDgram, ok},       // beneath a write entry: the run's own (SEMANTICS §5)
		{"sendto " + secretDgram, eacces}, // beneath a deny_read inside it
		{"sendto unlisted.dg", ok},        // relative: left to tier 1, which records it
		{"sendto " + work + "/../unlisted.dg", eacces},
		{"sendto " + work + "/./ok.dg", eacces}, // not spelled canonically: refused, fail-closed
		{"sendto " + base + "//listed.dg", eacces},
		{"procfd " + unlisted, eacces}, // the relay's name shape, from inside the run
	}
	for _, c := range cells {
		if got := helper.do(t, c.op); got != c.want {
			t.Errorf("%s from inside the run: %s, want %s", c.op, got, c.want)
		}
	}
	var d PlaneDecision
	if got := helper.do(t, "connect "+unlisted); got != eacces {
		t.Fatalf("connect %s: %s", unlisted, got)
	}
	if err := coll.Maps[MapPlaneScratch].Lookup(int32(helper.pidfd), &d); err != nil {
		t.Fatalf("the helper's scratch value: %v", err)
	}
	if int(d.Hook) != planeHookIndex(t, "socket_connect")+1 || d.Verdict != uint8(VerdictRefused) ||
		d.Reason != uint8(ReasonNetNotAllowed) || d.RuleIdx != uint32(PlaneRuleNone) {
		t.Errorf("the refused connect's decision %+v, want socket_connect's refusal, net-not-allowed, no rule", d)
	}
	if got := helper.do(t, "sendto "+listedDgram); got != ok {
		t.Fatalf("sendto %s: %s", listedDgram, got)
	}
	if err := coll.Maps[MapPlaneScratch].Lookup(int32(helper.pidfd), &d); err != nil {
		t.Fatal(err)
	}
	if int(d.Hook) != planeHookIndex(t, "socket_sendmsg")+1 || d.Verdict != uint8(VerdictAllow) || d.RuleIdx != 2 {
		t.Errorf("the allowed datagram's decision %+v, want socket_sendmsg's allow by rule 2", d)
	}

	// The supervisor's relay: this process, the launcher, connects a duplicate of the run's socket.
	relay := func(name string, via bool) error {
		t.Helper()
		fdText := helper.do(t, "hold")
		tfd, err := strconv.Atoi(fdText)
		if err != nil {
			t.Fatalf("hold: %s", fdText)
		}
		dup, err := unix.PidfdGetfd(helper.pidfd, tfd, 0)
		if err != nil {
			t.Fatalf("pidfd_getfd: %v", err)
		}
		defer unix.Close(dup)
		if !via {
			return unix.Connect(dup, &unix.SockaddrUnix{Name: name})
		}
		pfd, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pfd)
		return unix.Connect(dup, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(pfd)})
	}
	if err := relay(unlisted, true); err != nil {
		t.Errorf("relayed connect through /proc/self/fd from the launcher's cgroup: %v, want success", err)
	}
	if err := relay(unlisted, false); !errors.Is(err, unix.EACCES) {
		t.Errorf("relayed connect naming an unlisted socket directly: %v, want EACCES", err)
	}
	if err := relay(absListed, false); err != nil {
		t.Errorf("relayed connect to a listed abstract name: %v, want success", err)
	}
	setPolicy(PlaneUnix{Gen: gen, Decides: 1})
	if err := relay(unlisted, true); !errors.Is(err, unix.EACCES) {
		t.Errorf("/proc/self/fd relay with no relay cgroup in the policy: %v, want EACCES", err)
	}

	// Outside every run: this process's own socket is decided by nothing.
	if err := planeUnixOp("connect", unlisted); err != nil {
		t.Errorf("connect %s outside every run: %v, want success", unlisted, err)
	}

	// A policy of another gen is a previous run's: every name of the run is refused and counted.
	setPolicy(PlaneUnix{Gen: gen + 1, Decides: 1, RelayCgroupID: selfID})
	var before PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &before); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"connect " + listed, "sendto " + listedDgram} {
		if got := helper.do(t, op); got != eacces {
			t.Errorf("%s with no unix policy of the run's gen: %s, want EACCES", op, got)
		}
	}
	var after PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &after); err != nil {
		t.Fatal(err)
	}
	if after.NoRows-before.NoRows != 2 {
		t.Errorf("norows went from %d to %d over two refusals with no policy, want +2", before.NoRows, after.NoRows)
	}

	// A header of another gen (a cleared slot, or the next run's): every name is refused and counted, whatever the
	// policy says.
	setPolicy(PlaneUnix{Gen: gen, Decides: 1, RelayCgroupID: selfID})
	for _, g := range []uint32{0, gen + 1} {
		setSlot(g, PlaneSlotUnixDecides)
		for _, op := range []string{"connect " + listed, "sendto " + listedDgram} {
			if got := helper.do(t, op); got != eacces {
				t.Errorf("%s with a header of gen %d: %s, want EACCES", op, g, got)
			}
		}
	}

	// A header that decides nothing (a contract with no net: section): every name passes.
	setPolicy(PlaneUnix{Gen: gen})
	setSlot(gen, 0)
	for _, op := range []string{"connect " + unlisted, "sendto " + unlistedDgram} {
		if got := helper.do(t, op); got != ok {
			t.Errorf("%s under a header that decides nothing: %s, want it to go ahead", op, got)
		}
	}
}

// planeHookIndex is a hook's position in PlaneHooks.
func planeHookIndex(t *testing.T, name string) int {
	t.Helper()
	for i, h := range PlaneHooks {
		if h.Name == name {
			return i
		}
	}
	t.Fatalf("no plane hook %s", name)
	return -1
}

// planeAcceptUnix listens on a unix stream socket, a pathname or an @abstract name, and accepts and closes every
// connection until the test ends.
func planeAcceptUnix(t *testing.T, name string) {
	t.Helper()
	l, err := net.Listen("unix", name)
	if err != nil {
		t.Fatalf("listen unix %s: %v", name, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
}

// startPlaneUnixHelper starts the unix helper in the cgroup cgroupFD names, in dir, as a planeHelper.
func startPlaneUnixHelper(t *testing.T, cgroupFD int, dir string) *planeHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), planeUnixHelperEnv+"=1")
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the helper in its cgroup: %v", err)
	}
	h := &planeHelper{cmd: cmd, in: in, out: bufio.NewReader(outPipe), pidfd: -1}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if h.pidfd >= 0 {
			_ = unix.Close(h.pidfd)
		}
	})
	if line, err := h.out.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper did not start: %q %v", line, err)
	}
	if h.pidfd, err = unix.PidfdOpen(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("pidfd_open: %v", err)
	}
	return h
}
