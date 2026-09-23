// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// requireFanotify skips unless this process may open a content-class fanotify group, which needs
// CAP_SYS_ADMIN. The skip names the privilege so an unprivileged suite says what it did not run; the manual
// procedure for a machine with root is in bpf/README.md.
func requireFanotify(t *testing.T) *fanotifyListener {
	t.Helper()
	p := newPolicy(&agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull}, "/")
	l, err := newFanotifyListener(p, Run{ID: "it", Agent: "a"}, &sink{}, 200*time.Millisecond)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
		}
		t.Fatalf("newFanotifyListener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestFanotifyGroupOpens asserts the group this backend asks the kernel for is one the kernel grants:
// FAN_CLASS_CONTENT with an unlimited queue and the two permission events, which is what makes deny_read and
// exec denial possible at all.
func TestFanotifyGroupOpens(t *testing.T) {
	l := requireFanotify(t)
	if l.fd < 0 {
		t.Fatalf("group has descriptor %d", l.fd)
	}
	if len(l.marked()) != 0 {
		t.Fatalf("a new group already carries marks: %v", l.marked())
	}
}

// TestFanotifyMarkAndUnmark asserts a mount can be marked once and removed cleanly, which is the whole of the
// listener's setup and teardown against the kernel (§5 R8).
func TestFanotifyMarkAndUnmark(t *testing.T) {
	l := requireFanotify(t)
	mount := mountOf(t, t.TempDir())
	if err := l.mark(mount); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("marking %s needs CAP_SYS_ADMIN: %v", mount, err)
		}
		t.Fatalf("mark %s: %v", mount, err)
	}
	if err := l.mark(mount); err != nil {
		t.Fatalf("marking twice must be idempotent: %v", err)
	}
	if got := l.marked(); len(got) != 1 || got[0] != mount {
		t.Fatalf("marked = %v, want [%s]", got, mount)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close twice: %v", err)
	}
}

// TestFanotifyRefusesDeniedRead: a process inside the run's cgroup that
// opens a path the contract denies is refused in the kernel, with the reason in the ledger, while a path the
// contract does not mention opens normally.
func TestFanotifyRefusesDeniedRead(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	plain := filepath.Join(dir, "plain.txt")
	for _, p := range []string{secret, plain} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	mount := mountOf(t, dir)

	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 path for this process: %v", err)
	}

	events := &sink{}
	p := newPolicy(&agent.RuleTable{
		FS:     []agent.FSRule{{Kind: agent.FSDenyRead, Path: secret, Mount: mount, Raw: "deny_read: secret.txt"}},
		Tier:   backend.TierCgroup,
		Record: agent.RecordFull,
	}, cg)

	l, err := newFanotifyListener(p, Run{ID: "it", Agent: "a", CgroupPath: cg}, events, time.Second)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
		}
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	if err := l.mark(mount); err != nil {
		t.Skipf("marking %s needs CAP_SYS_ADMIN: %v", mount, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	if _, err := os.ReadFile(plain); err != nil {
		t.Fatalf("an unruled file must open: %v", err)
	}
	_, err = os.ReadFile(secret)
	if err == nil {
		t.Fatal("a denied file opened")
	}
	// EPERM and nothing else: a refusal is the bare FAN_DENY, and no kernel lets a FAN_CLASS_CONTENT group
	// phrase it as EACCES (§6 E2). The reason record below is where the precise cause lives.
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("denied open failed with %v, want EPERM", err)
	}

	cancel()
	if err := <-loopErr; err != nil {
		t.Fatalf("listener loop: %v", err)
	}
	if _, refused, _, _ := l.stats(); refused != 1 {
		t.Fatalf("refused %d opens, want 1", refused)
	}
	var found bool
	for _, e := range events.all() {
		if e.Kind == record.KindFS && e.Verdict == record.VerdictRefused && e.Reason == record.ReasonReadDenied {
			found = true
		}
	}
	if !found {
		t.Fatalf("no refusal event: %+v", events.all())
	}
}

// TestFanotifyKernelRefusesAnErrnoFromThisGroup pins the premise of §6 E2 on the running kernel. A refusal is
// the bare FAN_DENY because the kernel will not take anything more precise from a FAN_CLASS_CONTENT group:
// FAN_DENY_ERRNO bits are unknown before 6.14 and, from 6.14, accepted only from a FAN_CLASS_PRE_CONTENT group
// (process_access_response). The test holds a real open on a marked mount, answers it with EACCES and then
// EPERM in the errno bits, requires EINVAL for both, and then answers with the bare FAN_DENY and requires the
// opener to see EPERM. A kernel that starts accepting either errno from this class fails here, which is the
// signal to revisit E2's design rather than a regression.
func TestFanotifyKernelRefusesAnErrnoFromThisGroup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "held.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	mount := mountOf(t, dir)
	l := requireFanotify(t)
	if err := l.mark(mount); err != nil {
		t.Skipf("marking %s needs CAP_SYS_ADMIN: %v", mount, err)
	}

	opened := make(chan error, 1)
	go func() {
		_, err := os.ReadFile(target)
		opened <- err
	}()

	// Read events until the one for the target arrives; anything else on the mount is allowed at once.
	var eventFD int32 = -1
	buf := make([]byte, fanReadBuffer)
	pfd := []unix.PollFd{{Fd: int32(l.fd), Events: unix.POLLIN}}
	for until := time.Now().Add(10 * time.Second); eventFD < 0; {
		if time.Now().After(until) {
			t.Fatal("no permission event for the held open")
		}
		if n, err := unix.Poll(pfd, 100); err != nil || n == 0 {
			continue
		}
		got, err := unix.Read(l.fd, buf)
		if err != nil {
			continue
		}
		events, _ := parseFanotifyEvents(buf[:got])
		for _, ev := range events {
			if ev.FD < 0 {
				continue
			}
			if eventFD < 0 && fdPointsAt(ev.FD, target) {
				eventFD = ev.FD
				continue
			}
			_ = l.writeResponse(ev.FD, unix.FAN_ALLOW)
			_ = unix.Close(int(ev.FD))
		}
	}
	defer unix.Close(int(eventFD))

	write := func(response uint32) error {
		var raw [8]byte
		binary.NativeEndian.PutUint32(raw[0:4], uint32(eventFD))
		binary.NativeEndian.PutUint32(raw[4:8], response)
		_, err := unix.Write(l.fd, raw[:])
		return err
	}
	for _, errno := range []unix.Errno{unix.EACCES, unix.EPERM} {
		if err := write(unix.FAN_DENY | uint32(errno)<<24); !errors.Is(err, unix.EINVAL) {
			t.Fatalf("FAN_DENY with errno %v from a FAN_CLASS_CONTENT group = %v, want EINVAL (§6 E2)", errno, err)
		}
	}
	if err := write(unix.FAN_DENY); err != nil {
		t.Fatalf("the bare FAN_DENY: %v", err)
	}
	select {
	case err := <-opened:
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("the refused open = %v, want EPERM", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open was still held after the bare FAN_DENY")
	}
}

// TestFanotifyListenerDeathFailsOpen is §6 E15 and I8: when the listener goes away, the kernel releases every
// blocked opener rather than holding them, which is why the run treats the goroutine's death as fatal.
func TestFanotifyListenerDeathFailsOpen(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	mount := mountOf(t, dir)
	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 path: %v", err)
	}
	p := newPolicy(&agent.RuleTable{
		FS:     []agent.FSRule{{Kind: agent.FSDenyRead, Path: target, Mount: mount, Raw: "deny_read: f.txt"}},
		Tier:   backend.TierCgroup,
		Record: agent.RecordFull,
	}, cg)
	l, err := newFanotifyListener(p, Run{ID: "it", CgroupPath: cg}, &sink{}, time.Second)
	if err != nil {
		t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
	}
	if err := l.mark(mount); err != nil {
		l.Close()
		t.Skipf("marking needs CAP_SYS_ADMIN: %v", err)
	}
	// No loop is running: with the group closed, the kernel must let the open through rather than block it.
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := os.ReadFile(target)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("open after the listener died: %v, want success (the kernel fails open)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an open stayed blocked after the listener died; the kernel is documented to fail open here")
	}
}

// TestPrepareOnRealKernel runs the whole of Prepare against the running kernel: real objects, real pins, a
// real cgroup and a real fanotify group. It needs the objects (the tegobpf tag), CAP_BPF, CAP_NET_ADMIN and
// CAP_SYS_ADMIN, and a writable bpf filesystem.
func TestPrepareOnRealKernel(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	if unix.Access(DefaultBPFFS, unix.W_OK) != nil {
		t.Skipf("%s is not writable by this uid; run as root", DefaultBPFFS)
	}
	requireBPFCaps(t)

	// A cgroup of the test's own, as a run gets one: Attach refuses a run cgroup that holds the launcher
	// itself, since connect_unix admits the supervisor's relay name from the launcher's cgroup (§5 R7), and
	// this process is the launcher here.
	cgPath := fmt.Sprintf("/tego-it-prepare-%d", os.Getpid())
	if err := os.Mkdir(filepath.Join("/sys/fs/cgroup", cgPath), 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join("/sys/fs/cgroup", cgPath)) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", cgPath)
	if err != nil {
		t.Fatalf("cannot stat the run's cgroup: %v", err)
	}

	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	rt := &agent.RuleTable{
		Net:    []agent.NetRule{},
		Tier:   backend.TierCgroup,
		Record: agent.RecordFull,
	}
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it", Agent: "a", CgroupID: id, CgroupPath: cgPath})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
}

// requireBPFCaps skips unless the effective capability set holds what loading and attaching the tier-2
// objects needs: CAP_BPF with CAP_PERFMON (the tracing programs) and CAP_NET_ADMIN (the cgroup programs), or
// CAP_SYS_ADMIN, which the kernel accepts in place of each.
//
// It decides before anything is loaded and never from a load's error. The verifier refuses a program with
// EACCES, whose text is "permission denied", so the skip this replaces — ErrProgramLoad whose message said
// "permission" — skipped exactly when the verifier rejected an object, and TestPrepareOnRealKernel reported
// as skipped under root the one failure it exists to find. With the capabilities present, a failed Prepare
// is a failure.
func requireBPFCaps(t *testing.T) {
	t.Helper()
	if missing := missingBPFCaps(); missing != "" {
		t.Skipf("loading the tier-2 objects needs %s (or cap_sys_admin); run as root", missing)
	}
}

// missingBPFCaps names what the effective set lacks for the tier-2 objects, or "" when nothing.
func missingBPFCaps() string {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return "a readable capability set (" + err.Error() + ")"
	}
	eff := uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	has := func(c int) bool { return eff&(1<<uint(c)) != 0 }
	if has(unix.CAP_SYS_ADMIN) {
		return ""
	}
	var missing []string
	for _, c := range []struct {
		n    int
		name string
	}{{unix.CAP_BPF, "cap_bpf"}, {unix.CAP_PERFMON, "cap_perfmon"}, {unix.CAP_NET_ADMIN, "cap_net_admin"}} {
		if !has(c.n) {
			missing = append(missing, c.name)
		}
	}
	return strings.Join(missing, ",")
}

// TestAdoptExistingDescendantsOnRealCgroupfs exercises the adopt-time scan against the real cgroup hierarchy,
// read-only: every directory beneath this process's own cgroup must resolve to a distinct cgroup id.
func TestAdoptExistingDescendantsOnRealCgroupfs(t *testing.T) {
	cgPath, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 path: %v", err)
	}
	root := filepath.Join("/sys/fs/cgroup", cgPath)
	entries, err := readSubtree(root)
	if err != nil {
		t.Skipf("cannot read %s: %v", root, err)
	}
	seen := map[uint64]string{}
	self, err := cgroupIDOfPath("/sys/fs/cgroup", cgPath)
	if err != nil {
		t.Fatalf("cgroupIDOfPath: %v", err)
	}
	seen[self] = cgPath
	for _, rel := range entries {
		id, err := cgroupIDOfPath("/sys/fs/cgroup", filepath.Join(cgPath, rel))
		if err != nil {
			continue // removed between the walk and the stat, which the scan tolerates
		}
		if prev, dup := seen[id]; dup {
			t.Fatalf("cgroup id %d for both %s and %s", id, prev, rel)
		}
		seen[id] = rel
	}
	t.Logf("%s has %d descendants, all with distinct ids", cgPath, len(entries))
}

// mountOf returns the mount point that holds a path, which is what a mark is scoped to.
func mountOf(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("df", "--output=target", path).Output()
	if err != nil {
		t.Skipf("cannot find the mount of %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		t.Skipf("df gave no mount for %s: %q", path, out)
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
