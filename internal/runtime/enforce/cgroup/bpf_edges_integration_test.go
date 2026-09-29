// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

const edgesHelperEnv = "TEGO_EDGES_HELPER"

func edgesHelper(dir *os.File, mode string, env ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestBPFEdgesHelper$")
	cmd.Env = append(append(os.Environ(), edgesHelperEnv+"="+mode), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	cmd.Stderr = os.Stderr
	return cmd
}

func runEdgesHelper(t *testing.T, dir *os.File, mode string, env ...string) []string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := edgesHelper(dir, mode, env...)
	cmd.ExtraFiles = []*os.File{w}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	r.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	return out
}

func edgesErrno(err error) int {
	var en syscall.Errno
	if errors.As(err, &en) {
		return int(en)
	}
	if err != nil {
		return -1
	}
	return 0
}

// TestBPFEdgesHelper is the child half of the tests in this file.
func TestBPFEdgesHelper(t *testing.T) {
	mode := os.Getenv(edgesHelperEnv)
	if mode == "" {
		t.Skip("helper only")
	}
	out := os.NewFile(3, "report")
	port, _ := strconv.Atoi(os.Getenv("TEGO_EDGE_PORT"))
	switch mode {
	case "unspec":
		// 1. AF_INET to 127.0.0.1:P
		fd, _ := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		err := unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
		fmt.Fprintf(out, "tcp4 127.0.0.1 %d\n", edgesErrno(err))
		unix.Close(fd)
		// 2. AF_INET6 to ::ffff:127.0.0.1:P
		fd, _ = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		err = unix.Connect(fd, &unix.SockaddrInet6{Port: port, Addr: netip.MustParseAddr("::ffff:127.0.0.1").As16()})
		fmt.Fprintf(out, "tcp6 ::ffff:127.0.0.1 %d\n", edgesErrno(err))
		unix.Close(fd)
		// 3. AF_INET6 bound to ::ffff:127.0.0.1, connect to [::]:P
		fd, _ = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		berr := unix.Bind(fd, &unix.SockaddrInet6{Addr: netip.MustParseAddr("::ffff:127.0.0.1").As16()})
		err = unix.Connect(fd, &unix.SockaddrInet6{Port: port, Addr: netip.IPv6Unspecified().As16()})
		peer := ""
		if err == nil {
			if sa, e := unix.Getpeername(fd); e == nil {
				if s6, ok := sa.(*unix.SockaddrInet6); ok {
					peer = netip.AddrFrom16(s6.Addr).String() + ":" + strconv.Itoa(s6.Port)
				}
			}
		}
		fmt.Fprintf(out, "tcp6 [::] bound-mapped bind=%d %d peer=%s\n", edgesErrno(berr), edgesErrno(err), peer)
		unix.Close(fd)
		// 4. AF_INET to 0.0.0.0:P
		fd, _ = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: port})
		fmt.Fprintf(out, "tcp4 0.0.0.0 %d\n", edgesErrno(err))
		unix.Close(fd)
	case "shortconnect":
		fd, _ := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		// A full connect to an address the contract does not name: EPERM from connect4.
		err := unix.Connect(fd, &unix.SockaddrInet4{Port: 4321, Addr: [4]byte{10, 9, 8, 7}})
		fmt.Fprintf(out, "full %d\n", edgesErrno(err))
		unix.Close(fd)
		fd, _ = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		// Only the family word: addrlen 2. The kernel copies two bytes and the call fails EINVAL.
		sa := [16]byte{byte(unix.AF_INET), 0}
		_, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa[0])), 2)
		fmt.Fprintf(out, "short %d\n", int(e))
		unix.Close(fd)
	case "longname":
		dir := os.Getenv("TEGO_EDGES_DIR")
		name := strings.Repeat("n", 255)
		p := filepath.Join(dir, name)
		err := os.WriteFile(p, nil, 0o600)
		fmt.Fprintf(out, "create %d\n", edgesErrno(err))
		err = os.Remove(p)
		fmt.Fprintf(out, "unlink %d\n", edgesErrno(err))
		err = os.Mkdir(filepath.Join(dir, strings.Repeat("d", 255)), 0o700)
		fmt.Fprintf(out, "mkdir %d\n", edgesErrno(err))
		short := filepath.Join(dir, "short")
		_ = os.WriteFile(short, nil, 0o600)
		err = os.Remove(short)
		fmt.Fprintf(out, "unlink-short %d\n", edgesErrno(err))
	}
}

// TestUnspecifiedDestinationIsRefused: a contract naming only the IPv6 prefix ::/0 on port P. The kernel's
// connect6 decides [::] against that prefix, then tcp_v6_connect turns [::] into IPv4 loopback for a socket
// bound to a v4-mapped address.
func TestUnspecifiedDestinationIsRefused(t *testing.T) {
	port := listenLoopback(t, "tcp4", "127.0.0.1")
	all6 := netip.MustParsePrefix("::/0")
	rules := []agent.NetRule{{Raw: "::/0:" + strconv.Itoa(port), Port: port, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow, CIDR: &all6, Static: true}}
	rt := &agent.RuleTable{Net: rules, Tier: backend.TierCgroup, Record: agent.RecordFull}
	_, dir, _ := realRun(t, "unspec", rt)
	for _, line := range runEdgesHelper(t, dir, "unspec", "TEGO_EDGE_PORT="+strconv.Itoa(port)) {
		t.Logf("%s (EPERM=%d)", line, int(unix.EPERM))
		f := strings.Fields(line)
		errno := f[len(f)-1]
		if strings.Contains(line, "peer=") {
			errno = f[len(f)-2]
		}
		if errno != strconv.Itoa(int(unix.EPERM)) {
			t.Errorf("%s: want EPERM: under ::/0:%d alone no IPv4 destination is named", line, port)
		}
	}
}

// runRing opens the run's own record ring, the one Prepare placed at its slot (ADR 0026 (1)).
func runRing(t *testing.T, h *Handle) *ebpf.Map {
	t.Helper()
	ring, ok, err := ebpfbindings.RingOf(h.kern.(*bpfKernel).maps[ebpfbindings.MapEvents], h.Slot())
	if err != nil || !ok {
		t.Fatalf("the run's ring at slot %d: %v, %v", h.Slot(), ok, err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	return ring
}

// TestShortConnectRecordReadsNoStack: security_socket_connect's record of a connect whose addrlen covers only the
// family word.
func TestShortConnectRecordReadsNoStack(t *testing.T) {
	rt := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, dir, id := realRun(t, "short", rt)
	rd, err := ringbuf.NewReader(runRing(t, h))
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	for _, line := range runEdgesHelper(t, dir, "shortconnect") {
		t.Logf("helper: %s", line)
	}
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		hdr, err := ebpfbindings.DecodeHeader(rec.RawSample)
		if err != nil || hdr.CgroupID != id || ebpfbindings.Kind(hdr.Kind) != ebpfbindings.KindConnect {
			continue
		}
		ev, err := ebpfbindings.Decode[ebpfbindings.NetEvent](rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := ebpfbindings.AddrFrom(ev.Family, ev.Addr)
		t.Logf("connect record: family %d proto %d %s port %d", ev.Family, ev.Proto, a, ev.Port)
		if a != netip.MustParseAddr("10.9.8.7") && (!a.IsUnspecified() || ev.Port != 0) {
			t.Errorf("the short connect's record names %s:%d, bytes the call never carried", a, ev.Port)
		}
	}
}

// TestNameMaxRecordIsWhole: an unlink and a mkdir of a 255-byte name, NAME_MAX, which the 256-byte buffer holds
// whole.
func TestNameMaxRecordIsWhole(t *testing.T) {
	rt := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, dir, id := realRun(t, "long", rt)
	rd, err := ringbuf.NewReader(runRing(t, h))
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	work := t.TempDir()
	for _, line := range runEdgesHelper(t, dir, "longname", "TEGO_EDGES_DIR="+work) {
		t.Logf("helper: %s", line)
	}
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		hdr, err := ebpfbindings.DecodeHeader(rec.RawSample)
		if err != nil || hdr.CgroupID != id {
			continue
		}
		switch ebpfbindings.Kind(hdr.Kind) {
		case ebpfbindings.KindUnlink, ebpfbindings.KindMkdir:
			ev, err := ebpfbindings.Decode[ebpfbindings.FSOpEvent](rec.RawSample)
			if err != nil {
				t.Fatal(err)
			}
			name := ebpfbindings.GoString(ev.Name[:])
			t.Logf("%s record: name_ok=%d len(name)=%d", ebpfbindings.Kind(hdr.Kind), ev.NameOk, len(name))
			if ev.NameOk != 1 {
				t.Errorf("%s of a %d-byte name recorded name_ok=0; NAME_MAX fits the 256-byte buffer", ebpfbindings.Kind(hdr.Kind), len(name))
			}
		}
	}
}

// TestV1HierarchyDoesNotTouchTheRun: cgroup_track acts on a cgroup v1 hierarchy's mkdir/rmdir, whose kernfs ids
// come from another idr and so collide with the unified hierarchy's.
func TestV1HierarchyDoesNotTouchTheRun(t *testing.T) {
	requireBPFCaps(t)
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	mnt := t.TempDir()
	if err := unix.Mount("cgroup", mnt, "cgroup", 0, "none,name=tegoedge"); err != nil {
		t.Skipf("mount a v1 named hierarchy: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	ino := func(p string) uint64 {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	// Alternate: a unified cgroup (under the root, or under a parent with no controllers, so the number of
	// kernfs nodes a mkdir consumes varies), then v1 directories until the v1 counter reaches its id.
	bare := fmt.Sprintf("/sys/fs/cgroup/tego-edge-bare-%d", os.Getpid())
	if err := os.Mkdir(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	var v1dirs, v2dirs []string
	withPids := fmt.Sprintf("/sys/fs/cgroup/tego-edge-pids-%d", os.Getpid())
	_ = os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+pids"), 0)
	if err := os.Mkdir(withPids, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(withPids+"/cgroup.subtree_control", []byte("+pids"), 0); err != nil {
		t.Logf("enable pids under %s: %v", withPids, err)
	}
	t.Cleanup(func() {
		for i := len(v1dirs) - 1; i >= 0; i-- {
			_ = os.Remove(v1dirs[i])
		}
		for i := len(v2dirs) - 1; i >= 0; i-- {
			_ = os.Remove(v2dirs[i])
		}
		_ = os.Remove(bare)
		_ = os.Remove(withPids)
	})
	v1 := map[uint64]string{}
	var last1 uint64
	var rel string
	var id uint64
	for round := 0; round < 400 && rel == ""; round++ {
		parent := "/sys/fs/cgroup"
		switch round % 3 {
		case 1:
			parent = bare
		case 2:
			parent = withPids
		}
		full := filepath.Join(parent, fmt.Sprintf("r%d-%d", os.Getpid(), round))
		if err := os.Mkdir(full, 0o755); err != nil {
			t.Fatal(err)
		}
		v2dirs = append(v2dirs, full)
		T := ino(full)
		for last1 < T {
			p := filepath.Join(mnt, "d"+strconv.Itoa(len(v1dirs)))
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			v1dirs = append(v1dirs, p)
			last1 = ino(p)
			v1[last1] = p
		}
		if round < 5 {
			t.Logf("round %d: unified %s id %d, v1 counter %d", round, full, T, last1)
		}
		if last1 == T {
			rel, id = strings.TrimPrefix(full, "/sys/fs/cgroup"), T
		}
	}
	if rel == "" {
		t.Skip("no collision found")
	}
	twin := v1[id]
	t.Logf("unified cgroup %s has id %d, the same id as v1 directory %s", rel, id, twin)

	rt := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordFull}
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	h, err := b.Prepare(t.Context(), rt, Run{ID: "it-v1", Agent: "a", CgroupID: id, CgroupPath: rel})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
		t.Fatalf("Arm: %v", err)
	}
	runSet := h.kern.(*bpfKernel).maps[ebpfbindings.MapRunSet]
	var val ebpfbindings.Run
	if err := runSet.Lookup(&id, &val); err != nil {
		t.Fatalf("the run's own row is missing: %v", err)
	}
	t.Logf("run row: %+v", val)

	// mkdir in the v1 hierarchy under the twin.
	child := filepath.Join(twin, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	cid := ino(child)
	var cval ebpfbindings.Run
	if err := runSet.Lookup(&cid, &cval); err == nil {
		t.Errorf("a v1 cgroup (%s, id %d) was materialized into the run set as run_idx %d: v1 mkdir under a directory whose id collides with the run's", child, cid, cval.RunIdx)
	} else {
		t.Logf("v1 child %d not in the run set: %v", cid, err)
	}
	_ = os.Remove(child)

	// rmdir of the v1 twin.
	if err := os.Remove(twin); err != nil {
		t.Fatal(err)
	}
	if err := runSet.Lookup(&id, &val); err != nil {
		t.Errorf("removing the unrelated v1 directory %s deleted the run's own run-set row %d: %v", twin, id, err)
	}
}
