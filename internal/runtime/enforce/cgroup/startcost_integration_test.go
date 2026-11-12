// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// requireRealPrepare skips unless this process can run the whole of Prepare against the running kernel: the
// objects built in (tegobpf), a writable bpf filesystem and the capabilities the load needs.
func requireRealPrepare(t *testing.T) {
	t.Helper()
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
}

// runCgroup makes a cgroup of the test's own under the root of the cgroup2 mount, as a run gets one, and
// returns its path relative to the mount and its id.
func runCgroup(t *testing.T, name string) (string, uint64) {
	t.Helper()
	rel := fmt.Sprintf("/tego-it-%s-%d", name, os.Getpid())
	if err := os.Mkdir(filepath.Join("/sys/fs/cgroup", rel), 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join("/sys/fs/cgroup", rel)) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("stat the run's cgroup: %v", err)
	}
	return rel, id
}

// TestSecondLauncherAdoptsTheBuildsPinnedObjects: a launcher that starts while another of its build holds the
// pins runs the pinned programs rather than loading and verifying its own copies (adoptObject), which it then
// left unused for every host-wide hook, since it adopts the first launcher's links. Before, every Prepare
// loaded all three objects, 90–130 ms in the KVM guest (docs/p0/enforce-cgroup-observe.md §9). The program
// ids say which copy a handle runs: the second handle's must be the first's. The last one out still removes
// the build (§5 R14).
func TestSecondLauncherAdoptsTheBuildsPinnedObjects(t *testing.T) {
	requireRealPrepare(t)
	state := pinState(t)
	b := New(Options{Machine: machineLinger(0), StateDir: state, Events: &sink{}})
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}

	var handles []*Handle
	for _, name := range []string{"first", "second"} {
		rel, id := runCgroup(t, "adopt-"+name)
		h, err := b.Prepare(context.Background(), table, Run{ID: name, Agent: "a", CgroupID: id, CgroupPath: rel})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		handles = append(handles, h)
	}
	ids := func(h *Handle) map[string]ebpf.ProgramID {
		out := map[string]ebpf.ProgramID{}
		for name, p := range h.kern.(*bpfKernel).progs {
			info, err := p.Info()
			if err != nil {
				t.Fatalf("program %s: %v", name, err)
			}
			id, ok := info.ID()
			if !ok {
				t.Fatalf("program %s has no id", name)
			}
			out[name] = id
		}
		return out
	}
	first, second := ids(handles[0]), ids(handles[1])
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("programs: first %d, second %d", len(first), len(second))
	}
	for name, id := range first {
		if second[name] != id {
			t.Errorf("%s: the second launcher runs program %d, the first %d: it loaded its own copy", name, second[name], id)
		}
	}

	pinRoot := handles[0].pins.Root
	if err := handles[1].Close(); err != nil {
		t.Fatalf("Close the second: %v", err)
	}
	if _, err := os.Stat(pinRoot); err != nil {
		t.Fatalf("the build's pins went with a launcher that was not the last out: %v", err)
	}
	if err := handles[0].Close(); err != nil {
		t.Fatalf("Close the first: %v", err)
	}
	if _, err := os.Stat(pinRoot); !os.IsNotExist(err) {
		if liveRunRows(t) {
			// leaveBuild keeps a build whose run set names a live cgroup, as it must for a run whose launcher
			// died (ADR 0020): here that is a run an earlier test left behind, not one of this test's.
			t.Fatalf("the last launcher out left %s: its run set holds a live cgroup's row, a run an earlier "+
				"test in this binary left behind", pinRoot)
		}
		t.Fatalf("the last launcher out left %s (%v)", pinRoot, err)
	}
}

// TestExecOnlyMarkAsksForNoOpenEvent: a contract whose one mark comes from its exec entries has that mount
// marked for FAN_OPEN_EXEC_PERM alone, so an ordinary open on it never waits on this listener (markMasks). The
// guest's root filesystem, where the exec entries live, used to be marked for every open as well: kill test
// 4's pip install paid 35–45 µs on each of its opens for a decision that could only allow it.
func TestExecOnlyMarkAsksForNoOpenEvent(t *testing.T) {
	requireRealPrepare(t)
	tool, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true(1) to name in exec.allow: %v", err)
	}
	tool, err = filepath.EvalSymlinks(tool)
	if err != nil {
		t.Fatal(err)
	}
	rel, id := runCgroup(t, "execmark")
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	table := &agent.RuleTable{
		Net:      []agent.NetRule{},
		Exec:     []agent.ExecRule{{Path: tool, Raw: "true", Verdict: agent.VerdictAllow}},
		Contract: &agent.Contract{Exec: &agent.ExecSection{Allow: []string{"true"}}},
		Tier:     backend.TierCgroup, Record: agent.RecordSummary,
	}
	h, err := b.Prepare(context.Background(), table, Run{ID: "execmark", Agent: "a", CgroupID: id, CgroupPath: rel})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if err := h.Arm(); err != nil { // the run-set row is Arm's (ADR 0021 (2))
		t.Fatalf("Arm: %v", err)
	}
	if h.fan == nil {
		t.Fatal("an exec-restricting contract got no permission group")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.RunListener(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("RunListener: %v", err)
		}
	}()

	masks := mountMarkMasks(t, h.fan.fd)
	if len(masks) != 1 {
		t.Fatalf("mount marks %v, want the exec entry's mount alone", masks)
	}
	for mnt, mask := range masks {
		if mask&unix.FAN_OPEN_PERM != 0 || mask&unix.FAN_OPEN_EXEC_PERM == 0 {
			t.Fatalf("mount %s is marked for %#x, want FAN_OPEN_EXEC_PERM (%#x) without FAN_OPEN_PERM (%#x)", mnt,
				mask, unix.FAN_OPEN_EXEC_PERM, unix.FAN_OPEN_PERM)
		}
	}
	before := h.fan.answered.Load()
	for range 50 {
		fd, err := unix.Open(tool, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %s: %v", tool, err)
		}
		_ = unix.Close(fd)
	}
	if n := h.fan.answered.Load() - before; n != 0 {
		t.Fatalf("50 opens on the exec-only mount raised %d permission events, want none", n)
	}
}

// mountMarkMasks reads a fanotify group's mount marks from its fdinfo: the kernel prints one
// "fanotify mnt_id:<id> mflags:<flags> mask:<mask> ignored_mask:<mask>" line per mount mark, in hex.
func mountMarkMasks(t *testing.T, fd int) map[string]uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatalf("fdinfo: %v", err)
	}
	out := map[string]uint64{}
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "fanotify mnt_id:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(f, "mask:"); ok {
				mask, err := strconv.ParseUint(v, 16, 64)
				if err != nil {
					t.Fatalf("fdinfo line %q: %v", line, err)
				}
				out[fields[0]] = mask
			}
		}
	}
	return out
}

// movedHelperEnv selects the child half of TestDirectoryMovedIntoADeniedTreeIsStillAsked: a process of the
// run that opens the path the variable names, for reading, or creates it when the value starts with "create:",
// and prints the errno it got.
const movedHelperEnv = "TEGO_MOVED_HELPER"

// TestMovedHelper is that child half; it does nothing in the parent's own run.
func TestMovedHelper(t *testing.T) {
	arg := os.Getenv(movedHelperEnv)
	if arg == "" {
		t.Skip("helper process only")
	}
	flags, path := unix.O_RDONLY, arg
	if p, ok := strings.CutPrefix(arg, "create:"); ok {
		flags, path = unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, p
	}
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0o600)
	if err == nil {
		_ = unix.Close(fd)
	}
	var errno unix.Errno
	errors.As(err, &errno)
	fmt.Printf("\nMOVED-RESULT %d\n", int(errno))
}

// unmarkedSelf copies this test binary onto a tmpfs of the test's own and returns the copy's path, for a test
// that starts TestMovedHelper while its own group holds marks on marked (mount points). os/exec's clone suspends
// the forking thread (CLONE_VFORK) until the child's execve is past its point of no return, and that thread
// keeps its scheduler slot meanwhile, so a garbage collection that begins in the window waits for it. When the
// binary sits on a marked mount, the execve's open then waits on this process's own group, whose loop the
// collection has stopped, and nothing ever answers it: the cycle TestStageExecUnderGCNeverWaitsOnItsOwnGroup
// pins for the launcher, which proc.Start closes by refusing a start while marks exist (ADR 0021 (3)). With the
// mark on / it freezes every open on the machine, and the suite's own -test.timeout cannot fire. It hung
// TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit on AlmaLinux 9.8, whose /tmp and test binary share the
// root xfs: the test thread in clone3's vfork wait, the helper in fanotify_get_response from execve, the loop's
// goroutine stopping the world (2026-11-10). The copy is on no mount this process marks, so its execve raises no
// event; the helper's own open, after the execve, is what the test asks the group about. Call it before the
// marks exist: reading the binary is itself an open on its mount.
func unmarkedSelf(t *testing.T, marked []string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "self")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tego-unmarked-self", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		t.Skipf("mount a tmpfs for the helper's binary needs CAP_SYS_ADMIN: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "helper.test")
	if err := os.WriteFile(bin, self, 0o755); err != nil {
		t.Fatal(err)
	}
	mountID := func(path string) uint64 {
		t.Helper()
		var st unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &st); err != nil {
			t.Fatalf("statx %s: %v", path, err)
		}
		if st.Mask&unix.STATX_MNT_ID == 0 {
			t.Skipf("this kernel reports no mount id in statx (5.8+), so the helper's mount cannot be told apart")
		}
		return st.Mnt_id
	}
	own := mountID(bin)
	for _, m := range marked {
		if mountID(m) == own {
			t.Fatalf("the helper's binary %s is on %s, which this test marks: its execve would wait on this "+
				"process's own group", bin, m)
		}
	}
	return bin
}

// TestDirectoryMovedIntoADeniedTreeIsStillAsked: what the listener allowed in a directory says nothing about
// that directory once it has moved. The run reads a file in an allowed directory; a process outside the run
// then renames the directory into a deny_read tree and creates a file in it there, as a user's shell or a
// credential tool might; and the run's reads of both files, and a create of its own, through the new names
// must be refused, with a line each. A listener that put an ignore mark on a directory after an allowed open in
// it, to spare the directory's later opens the round trip, failed here: the mark belongs to the inode, went
// along with the rename, and all three opens were allowed with no line (R8's fifth amendment).
func TestDirectoryMovedIntoADeniedTreeIsStillAsked(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	work, denied := filepath.Join(base, "work"), filepath.Join(base, "denied")
	for _, d := range []string{work, denied} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(work, "a"), filepath.Join(base, "barrier")} {
		if err := os.WriteFile(f, []byte("readable"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rel, id := runCgroup(t, "moved")
	cgdir, err := os.Open(filepath.Join("/sys/fs/cgroup", rel))
	if err != nil {
		t.Fatalf("open the run's cgroup: %v", err)
	}
	defer cgdir.Close()

	events := &sink{}
	p := newPolicy(&agent.RuleTable{
		FS:       []agent.FSRule{{Kind: agent.FSDenyRead, Path: denied, Mount: mountOf(t, base), Raw: "deny_read: denied"}},
		Contract: &agent.Contract{},
		Tier:     backend.TierCgroup, Record: agent.RecordFull,
	}, rel)
	helper := unmarkedSelf(t, p.mounts)
	l, err := newFanotifyListener(p, Run{ID: "moved", Agent: "a", CgroupID: id, CgroupPath: rel}, events, time.Second)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
		}
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	for _, m := range p.mounts {
		// Only the missing privilege skips. Any other failure to mark (ENOSPC from root's mark quota, ENOENT)
		// is a failure: skipped, it would report this fail-open regression test as not run rather than failed.
		if err := l.markFor(m, p.masks[m]); errors.Is(err, unix.EPERM) {
			t.Skipf("marking %s needs CAP_SYS_ADMIN: %v", m, err)
		} else if err != nil {
			t.Fatalf("mark %s: %v", m, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-loopErr; err != nil {
			t.Errorf("listener loop: %v", err)
		}
	}
	defer stop()

	// inRun opens a path from a process placed in the run's cgroup at clone time, as the launcher places the
	// agent, and returns the errno it got. It execs the copy on a mount nothing here marks (unmarkedSelf).
	inRun := func(arg string) unix.Errno {
		t.Helper()
		cmd := exec.Command(helper, "-test.run=^TestMovedHelper$")
		cmd.Env = append(os.Environ(), movedHelperEnv+"="+arg)
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgdir.Fd())}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("helper for %s: %v\n%s", arg, err, out)
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "MOVED-RESULT "); ok {
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil {
					t.Fatalf("helper line %q: %v", line, err)
				}
				return unix.Errno(n)
			}
		}
		t.Fatalf("helper for %s reported nothing:\n%s", arg, out)
		return 0
	}

	if errno := inRun(filepath.Join(work, "a")); errno != 0 {
		t.Fatalf("the run's read of %s, which nothing denies, failed with %v", filepath.Join(work, "a"), errno)
	}
	// The read loop answers events in order, so once an open made after that one is answered, whatever the
	// loop did after answering the first (placing such a mark, in that listener) is done.
	if _, err := os.ReadFile(filepath.Join(base, "barrier")); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(denied, "work")
	if err := os.Rename(work, moved); err != nil {
		t.Fatalf("rename into the denied tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moved, "newsecret"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("a process outside the run must still create a file in the denied tree: %v", err)
	}
	fresh := filepath.Join(moved, "fresh")
	want := []string{filepath.Join(moved, "newsecret"), filepath.Join(moved, "a"), "create:" + fresh}
	for _, arg := range want {
		if errno := inRun(arg); errno != unix.EPERM {
			t.Errorf("the run's open of %s through the moved directory got %v, want EPERM", arg, errno)
		}
	}
	// A refused create is not undone: the kernel makes the inode before do_dentry_open raises the permission
	// event, so the file may be left behind (R8, "a refused create"). What the refusal does hold is its bytes:
	// the open failed, so no descriptor wrote anything, and a file left there is empty.
	if st, err := os.Stat(fresh); err == nil {
		if st.Size() != 0 {
			t.Errorf("the refused create left %s with %d bytes, want it empty", fresh, st.Size())
		}
		t.Logf("the refused create left %s behind, empty (R8)", fresh)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat %s: %v", fresh, err)
	}

	stop()
	var refusals []string
	for _, e := range events.all() {
		if e.Kind == record.KindFS && e.Verdict == record.VerdictRefused && e.Reason == record.ReasonReadDenied {
			refusals = append(refusals, string(e.Payload))
		}
	}
	if len(refusals) != len(want) {
		t.Fatalf("%d refusal lines %v, want one for each of the run's %d opens through the moved directory",
			len(refusals), refusals, len(want))
	}
}
