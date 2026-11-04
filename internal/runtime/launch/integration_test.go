// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestMain makes the test binary usable as the child stage (/proc/self/exe __child) and as the
// PDEATHSIG helper parent.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ChildCommand {
		os.Exit(ChildMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == deputy.Command {
		os.Exit(deputy.Main(os.Args[2:], deputyTestPin))
	}
	if os.Getenv("TEGO_LAUNCH_HELPER") == "parent" {
		os.Exit(helperParent())
	}
	// The same leak gate as the unit build's TestMain (leakcheck_test.go).
	os.Exit(testutil.LeakCheckMain(m))
}

// helperParent starts an agent and blocks forever; the test kills it and expects the agent to die too.
func helperParent() int {
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sleep", "60"}, Dir: "/", Handle: fakeHandle{ruleset: -1},
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// The listener stays open until the test kills this process, which is all this helper does.
	if _, err := child.WaitNotifyFD(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := child.Ack(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(child.PID)
	time.Sleep(time.Hour) // the test SIGKILLs this process; a bare select{} trips the deadlock detector
	return 0
}

func auditArch(t testing.TB) uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	}
	t.Skipf("no audit arch for %s", runtime.GOARCH)
	return 0
}

// execveFilter notifies execve only, after an arch guard: the minimum that makes the agent's own execve
// the first notification (R7).
func execveFilter(t testing.TB) []bpf.RawInstruction {
	prog, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 4, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: auditArch(t), SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		bpf.LoadAbsolute{Off: 0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SYS_EXECVE, SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
		bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF},
	})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

// serveContinue answers every notification on fd with CONTINUE until stop is closed, then reports the
// syscall numbers it saw in order.
func serveContinue(ln *sys.FD, stop <-chan struct{}) <-chan []int32 {
	out := make(chan []int32, 1)
	go func() {
		var nrs []int32
		defer func() { out <- nrs }()
		for {
			select {
			case <-stop:
				return
			default:
			}
			var end bool
			if err := ln.Borrow(func(fd int) error {
				fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				n, err := unix.Poll(fds, 50)
				if err == unix.EINTR || n == 0 {
					return nil
				}
				if err != nil || fds[0].Revents&unix.POLLIN == 0 {
					end = true
					return nil
				}
				var nt sys.SeccompNotif
				if err := sys.SeccompNotifRecv(fd, &nt); err != nil {
					end = !errors.Is(err, unix.ENOENT)
					return nil
				}
				nrs = append(nrs, nt.Data.Nr)
				_ = sys.SeccompNotifSend(fd, &sys.SeccompNotifResp{ID: nt.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE})
				return nil
			}); err != nil || end {
				return
			}
		}
	}()
	return out
}

// testCgroup creates a scope under the caller's delegated user subtree and returns its path and directory
// fd; it is removed once empty at cleanup. Skips when the subtree is not writable.
func testCgroup(t testing.TB) (string, *sys.FD) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip(err)
	}
	line := strings.TrimSpace(string(b))
	own := line[strings.Index(line, "::")+2:]
	marker := fmt.Sprintf("user@%d.service", os.Getuid())
	i := strings.Index(own, marker)
	if i < 0 {
		t.Skipf("no delegated %s in %s", marker, own)
	}
	base := filepath.Join("/sys/fs/cgroup", own[:i+len(marker)])
	dir := filepath.Join(base, fmt.Sprintf("tego-test-%d-%d.scope", os.Getpid(), time.Now().UnixNano()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot create a cgroup under %s: %v", base, err)
	}
	fd, err := sys.Own(unix.Open(dir, unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		os.Remove(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = fd.Close()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && !cgroupEmpty(dir) {
			time.Sleep(10 * time.Millisecond)
		}
		if err := os.Remove(dir); err != nil {
			t.Errorf("rmdir %s: %v", dir, err)
		}
	})
	return dir, fd
}

func cgroupEmpty(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
	return err == nil && bytes.Contains(b, []byte("populated 0"))
}

// cgroupFileKiller writes cgroup.kill directly: the mechanism cgroup.Killer delegates to the Manager for.
type cgroupFileKiller struct{ dir string }

func (k cgroupFileKiller) Kill() error {
	return os.WriteFile(filepath.Join(k.dir, "cgroup.kill"), []byte("1"), 0)
}

func procOwnerUID(t testing.TB, pid int) int {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/status", pid), &st); err != nil {
		t.Fatal(err)
	}
	return int(st.Uid)
}

func waitComm(t testing.TB, pid int, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err == nil && strings.TrimSpace(string(b)) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pid %d never became %q", pid, want)
}

// waitSigIgnored waits until pid ignores sig (SigIgn in /proc/pid/status). comm turning "sh" only
// says exec happened, not that the shell has run its `trap ” TERM` yet.
func waitSigIgnored(t testing.TB, pid int, sig syscall.Signal) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(l, "SigIgn:"); ok {
					m, perr := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
					if perr == nil && m&(1<<(uint(sig)-1)) != 0 {
						return
					}
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pid %d never ignored %v", pid, sig)
}

// Also pins runtime-launch.md E5: the child is dumpable at the pidfd_getfd call site.
func TestExecveIsFirstNotification(t *testing.T) {
	cgDir, cgFD := testCgroup(t)
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		RunID: "r-test", AgentID: "t", Command: []string{"/bin/true"}, Env: []string{"X=1"}, Dir: "/",
		Handle: fakeHandle{ruleset: -1, prog: execveFilter(t)},
	}, cgFD)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if child.StartBootNS == 0 {
		t.Fatal("StartBootNS not read")
	}
	// Invariant 3: inside the run cgroup from the first instruction, no cgroup.procs write anywhere.
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.PID))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimPrefix(cgDir, "/sys/fs/cgroup"); !strings.Contains(string(cg), want) {
		t.Fatalf("child cgroup %q, want %q", strings.TrimSpace(string(cg)), want)
	}
	// Case 5: the child is dumpable at the exact pidfd_getfd call site (its /proc entries are ours).
	if uid := procOwnerUID(t, child.PID); uid != os.Getuid() {
		t.Fatalf("/proc/%d/status owned by uid %d before pidfd_getfd: child not dumpable", child.PID, uid)
	}
	fd, err := child.WaitNotifyFD(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fd == nil {
		t.Fatal("no notify fd from a stage that installed a filter")
	}
	defer fd.Close()
	stop := make(chan struct{})
	seen := serveContinue(fd, stop)
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	if err := child.Ack(); err == nil {
		t.Fatal("second Ack accepted")
	}
	r, err := child.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	close(stop)
	nrs := <-seen
	if len(nrs) == 0 || nrs[0] != unix.SYS_EXECVE {
		t.Fatalf("notifications %v: want execve first", nrs)
	}
	if reason, code := Ended(r, Outcome{}); reason != identity.ReasonExit || code != 0 || r.ExecErr != 0 {
		t.Fatalf("Ended = %s/%d execErr=%v", reason, code, r.ExecErr)
	}
	if again, err := child.Wait(ctx); err != nil || again != r {
		t.Fatalf("second Wait = %+v, %v", again, err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if pidfdOpen(child) || child.ControlR != nil {
		t.Fatal("Close left descriptors")
	}
}

// TestChildBlocksUntilAck pins R5 directly: "the child never execve's before the ack byte". Every other
// integration test always Acks before observing anything, so a regression that let awaitAck fall through
// early (or be skipped) would still make every existing test pass -- the exec would just happen a little
// sooner than expected, with no assertion positioned to notice. This test instead holds the ack back and
// polls comm for a bounded window: correct code blocks indefinitely on the read, so the window's length
// cannot introduce flakiness (a longer wait only strengthens the check), while code that raced ahead would
// show "sleep" immediately.
func TestChildBlocksUntilAck(t *testing.T) {
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sleep", "60"}, Dir: "/", Env: []string{"PATH=/usr/bin:/bin"},
		Handle: fakeHandle{ruleset: -1},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Kill(context.Background()); child.Close() })
	if err := takeListener(t)(child.WaitNotifyFD(ctx)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", child.PID))
		if err != nil {
			t.Fatalf("child gone before Ack was ever sent: %v", err)
		}
		if got := strings.TrimSpace(string(b)); got == "sleep" {
			t.Fatalf("child execve'd (comm=%q) before Ack was sent: R5 violated", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	waitComm(t, child.PID, "sleep")
}

// Also pins runtime-launch.md E8, E18, E27: a failed execve, E2BIG included, is an ordinary post-ack exec
// failure.
func TestExecFailures(t *testing.T) {
	tests := []struct {
		cmd    string
		args   []string
		errno  syscall.Errno
		code   int
		reason identity.EndReason
	}{
		{"/nonexistent/agent", nil, syscall.ENOENT, identity.ExitNotFound, identity.ReasonExecFailed},
		{"/etc/passwd", nil, syscall.EACCES, identity.ExitNoExec, identity.ReasonExecFailed},
		// One argument past the kernel's per-string ceiling (MAX_ARG_STRLEN, 128 KiB): execve says E2BIG, and
		// that is an ordinary post-ack execve failure like the two above, not a preparatory-step error
		// (runtime-launch.md E18; E27's large env is the same call refused for the same reason).
		{"/bin/true", []string{strings.Repeat("a", 200_000)}, syscall.E2BIG, identity.ExitNoExec, identity.ReasonExecFailed},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			stderr, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			ctx := context.Background()
			child, err := (&Launcher{}).Start(ctx, ChildSpec{
				Command: append([]string{tc.cmd}, tc.args...), Dir: "/", Stderr: stderr, Handle: fakeHandle{ruleset: -1},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			fd, err := child.WaitNotifyFD(ctx)
			if err != nil || fd != nil {
				t.Fatalf("WaitNotifyFD without a filter = %v, %v", fd, err)
			}
			if err := child.Ack(); err != nil {
				t.Fatal(err)
			}
			r, err := child.Wait(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if r.ExecErr != tc.errno || !r.Status.Exited() || r.Status.ExitStatus() != tc.code {
				t.Fatalf("result %+v (exit %d), want errno %v exit %d", r, r.Status.ExitStatus(), tc.errno, tc.code)
			}
			if reason, code := Ended(r, Outcome{}); reason != tc.reason || code != tc.code {
				t.Fatalf("Ended = %s/%d", reason, code)
			}
			out, _ := os.ReadFile(stderr.Name())
			out = withoutCoverWarning(out)
			if want := "tego: " + tc.cmd + ": "; !strings.HasPrefix(string(out), want) || bytes.Count(out, []byte("\n")) != 1 {
				t.Fatalf("stderr %q, want one line starting %q", out, want)
			}
		})
	}
}

// coverDirWarning is the line a -cover build of this test binary prints as it exits with no GOCOVERDIR,
// which the child stage never has: it starts from an empty environment (wireSpec), so under
// scripts/coverage.sh a child stage whose execve failed writes it after its own one-line message.
const coverDirWarning = "warning: GOCOVERDIR not set, no coverage data emitted\n"

// withoutCoverWarning is out without coverDirWarning when this binary is a -cover build, and out as it is
// otherwise: an uninstrumented child stage that printed the line would be a finding.
func withoutCoverWarning(out []byte) []byte {
	if testing.CoverMode() == "" {
		return out
	}
	return bytes.ReplaceAll(out, []byte(coverDirWarning), nil)
}

// landlockRuleset builds an ABI-1 ruleset with the raw wrappers: read+exec everywhere, everything under
// allowed. The Landlock backend is not imported.
func landlockRuleset(t *testing.T, allowed string) int {
	t.Helper()
	_, err := sys.LandlockABI()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	attr := sys.LandlockRulesetAttr{Handled_access_fs: sys.LandlockAccessFSABI1}
	rs, err := sys.LandlockCreateRuleset(&attr, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(rs) })
	add := func(path string, access uint64) {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := sys.LandlockAddRule(rs, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}), 0); err != nil {
			t.Fatal(err)
		}
	}
	add("/", unix.LANDLOCK_ACCESS_FS_READ_FILE|unix.LANDLOCK_ACCESS_FS_READ_DIR|unix.LANDLOCK_ACCESS_FS_EXECUTE)
	add(allowed, sys.LandlockAccessFSABI1)
	return rs
}

func TestLandlockConfinesWrites(t *testing.T) {
	allowed, denied := t.TempDir(), t.TempDir()
	rs := landlockRuleset(t, allowed)
	tests := []struct {
		name string
		dir  string
		ok   bool
	}{
		{"inside the write dir", allowed, true},
		{"outside the write dir", denied, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stderr, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			defer stderr.Close()
			ctx := context.Background()
			child, err := (&Launcher{}).Start(ctx, ChildSpec{
				Command: []string{"/bin/sh", "-c", "echo hi > \"$1\"/f", "sh", tc.dir}, Dir: "/", Stderr: stderr,
				Env:    []string{"PATH=/usr/bin:/bin"},
				Handle: fakeHandle{ruleset: rs, prog: execveFilter(t)},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer child.Close()
			fd, err := child.WaitNotifyFD(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()
			stop := make(chan struct{})
			seen := serveContinue(fd, stop)
			if err := child.Ack(); err != nil {
				t.Fatal(err)
			}
			r, err := child.Wait(ctx)
			close(stop)
			<-seen
			if err != nil {
				t.Fatal(err)
			}
			out, _ := os.ReadFile(stderr.Name())
			_, statErr := os.Stat(filepath.Join(tc.dir, "f"))
			if tc.ok {
				if r.Status.ExitStatus() != 0 || statErr != nil {
					t.Fatalf("exit %d, stat %v, stderr %q", r.Status.ExitStatus(), statErr, out)
				}
				return
			}
			if r.Status.ExitStatus() == 0 || statErr == nil || !strings.Contains(string(out), "Permission denied") {
				t.Fatalf("write outside succeeded: exit %d, stat %v, stderr %q", r.Status.ExitStatus(), statErr, out)
			}
		})
	}
	// The ruleset fd is still the caller's: Start dup'ed it and never closed the original.
	if _, err := unix.FcntlInt(uintptr(rs), unix.F_GETFD, 0); err != nil {
		t.Fatalf("ruleset fd closed by Start: %v", err)
	}
}

// TestPrivilegedOrderingSwap pins R4, the privileged ordering swap, which nothing else in this suite
// exercises (every other Landlock/seccomp test runs the unprivileged order). A privileged spec runs
// Landlock and seccomp before the credential drop and skips no_new_privs, trusting CAP_SYS_ADMIN instead.
// Which half of that can be observed depends on whether this process holds CAP_SYS_ADMIN, so the test
// asserts the half the running credentials make observable rather than assuming one of them: an
// unprivileged `go test` and a root run in the KVM guest (test/vm, `make vm-root-test`) each pin a side.
//
// Also pins runtime-launch.md E25: Landlock and seccomp survive the credential drop.
func TestPrivilegedOrderingSwap(t *testing.T) {
	eff, _, _, err := sys.Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if eff&(1<<unix.CAP_SYS_ADMIN) != 0 {
		privilegedSwapSucceeds(t)
		return
	}
	privilegedSwapNeedsCapSysAdmin(t)
}

// privilegedSwapNeedsCapSysAdmin is the side an unprivileged process can observe. ARCHITECTURE.md §5
// states the kernel-verified fact it turns into an assertion: "Without no_new_privs and without
// CAP_SYS_ADMIN, landlock_restrict_self fails with EPERM". With spec.Privileged set and no CAP_SYS_ADMIN,
// landlock_restrict_self must therefore fail EPERM before dropCredentials is ever reached.
// TestLandlockConfinesWrites proves the *unprivileged* order succeeds with this same mechanism (it sets
// no_new_privs first); the two together pin the ordering, not just one outcome.
func privilegedSwapNeedsCapSysAdmin(t *testing.T) {
	rs := landlockRuleset(t, t.TempDir())
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command:    []string{"/bin/true"},
		Dir:        "/",
		Handle:     fakeHandle{ruleset: rs},
		Privileged: true, TargetUID: os.Getuid(), TargetGID: os.Getgid(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	err = takeListener(t)(child.WaitNotifyFD(ctx))
	if !errors.Is(err, ErrChildLandlock) || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("WaitNotifyFD = %v, want ErrChildLandlock wrapping EPERM (R4: landlock must run before the "+
			"credential drop under a privileged spec, and this process has no CAP_SYS_ADMIN to exempt it)", err)
	}
}

// privilegedSwapSucceeds is the side a CAP_SYS_ADMIN holder (root, or sudo) observes: the swap must
// confine and drop in one go. The agent reports three facts that only the R4 order produces together:
//
//   - it runs as the target uid/gid, so dropCredentials ran;
//   - Landlock confines it (a write under the granted directory succeeds, one beside it is refused);
//   - its NoNewPrivs is 1, set after the drop (ADR 0033), and 0 only under a contract's setuid: true;
//   - its CapBnd lacks CAP_NET_ADMIN exactly when the spec drops it (ADR 0128), and no other capability goes with it.
//
// With setuid, no_new_privs is never set, and landlock_restrict_self and the seccomp install succeed only while
// CAP_SYS_ADMIN is held, which the drop to a non-root uid removes: a confined agent with NoNewPrivs 0 proves both
// ran before the drop. The seccomp filter is installed too, because R4 moves it with Landlock.
func privilegedSwapSucceeds(t *testing.T) {
	for _, setuid := range []bool{false, true} {
		t.Run(fmt.Sprintf("setuid=%v", setuid), func(t *testing.T) { privilegedSwapWith(t, setuid, false) })
	}
	t.Run("setuid=true,drop_net_admin", func(t *testing.T) { privilegedSwapWith(t, true, true) })
}

func privilegedSwapWith(t *testing.T, setuid, dropNetAdmin bool) {
	const target = 65534 // the conventional nobody: any non-zero uid that owns nothing here
	// Not t.TempDir: its per-test parent is 0700, which the target uid could not search. The target uid
	// must be able to reach and write both directories by DAC, so that the one refusal the agent reports
	// can only be Landlock's, and the allowed write succeeding is what shows DAC let it through.
	base, err := os.MkdirTemp("", "tego-swap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	allowed, denied := filepath.Join(base, "allowed"), filepath.Join(base, "denied")
	for _, d := range []string{allowed, denied} {
		if err := os.Mkdir(d, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o777); err != nil { // Mkdir's mode is filtered by the umask
			t.Fatal(err)
		}
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	rs := landlockRuleset(t, allowed)
	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	script := `echo "ids $(id -u) $(id -g)"; grep '^NoNewPrivs:' /proc/self/status; grep '^CapBnd:' /proc/self/status; ` +
		`if echo x > "$1/f"; then echo allowed-write-ok; fi; ` +
		`if echo x > "$2/f"; then echo denied-write-ok; else echo denied-write-refused; fi`
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sh", "-c", script, "sh", allowed, denied}, Dir: "/", Stdout: stdout, Stderr: stdout,
		Env:        []string{"PATH=/usr/bin:/bin"},
		Handle:     fakeHandle{ruleset: rs, prog: execveFilter(t)},
		Privileged: true, TargetUID: target, TargetGID: target, Setuid: setuid, DropNetAdmin: dropNetAdmin,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	fd, err := child.WaitNotifyFD(ctx)
	if err != nil {
		t.Fatalf("WaitNotifyFD = %v, want the privileged order to install Landlock and seccomp while "+
			"CAP_SYS_ADMIN is still held (R4)", err)
	}
	defer fd.Close()
	stop := make(chan struct{})
	seen := serveContinue(fd, stop)
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	r, err := child.Wait(ctx)
	close(stop)
	<-seen
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(stdout.Name())
	out := string(b)
	if r.Status.ExitStatus() != 0 {
		t.Fatalf("agent exit %d, stdout %q", r.Status.ExitStatus(), out)
	}
	for _, want := range []string{
		fmt.Sprintf("ids %d %d\n", target, target),                                   // dropCredentials ran
		map[bool]string{false: "NoNewPrivs:\t1\n", true: "NoNewPrivs:\t0\n"}[setuid], // ADR 0033
		"allowed-write-ok\n",     // the ruleset grants the write dir
		"denied-write-refused\n", // and confines everything else
	} {
		if !strings.Contains(out, want) {
			t.Errorf("agent stdout %q lacks %q", out, want)
		}
	}
	if _, err := os.Stat(filepath.Join(denied, "f")); err == nil {
		t.Errorf("the agent wrote outside its ruleset: Landlock was not applied before the credential drop")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	want := capBnd(t, string(status))
	if dropNetAdmin {
		want &^= 1 << unix.CAP_NET_ADMIN
	}
	if got := capBnd(t, out); got != want {
		t.Errorf("the agent's CapBnd is %#x, want %#x (drop_net_admin=%v)", got, want, dropNetAdmin)
	}
}

// capBnd reads the CapBnd line of a /proc/<pid>/status text.
func capBnd(t *testing.T, status string) uint64 {
	t.Helper()
	_, rest, ok := strings.Cut(status, "CapBnd:\t")
	if !ok {
		t.Fatalf("no CapBnd line in %q", status)
	}
	line, _, _ := strings.Cut(rest, "\n")
	v, err := strconv.ParseUint(line, 16, 64)
	if err != nil {
		t.Fatalf("CapBnd %q: %v", line, err)
	}
	return v
}

func TestParentDeathKillsAgent(t *testing.T) {
	helper := exec.Command(os.Args[0])
	helper.Env = append(os.Environ(), "TEGO_LAUNCH_HELPER=parent")
	helper.Stderr = os.Stderr
	out, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	agentPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	waitComm(t, agentPID, "sleep")
	agentFD, err := sys.PidfdOpenProcess(agentPID)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(agentFD)
	if exited, _ := sys.PollPidfd(agentFD, 0); exited {
		t.Fatal("agent exited before its launcher died")
	}
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()
	exited, err := sys.PollPidfd(agentFD, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if !exited {
		_ = sys.PidfdSendSignal(agentFD, syscall.SIGKILL)
		t.Fatal("agent survived its launcher's SIGKILL: PDEATHSIG not armed")
	}
}

// TestAgentInheritsNothingTheLauncherInherited is invariant 4a: a descriptor the launcher holds without
// FD_CLOEXEC, as a GitHub Actions step's process inherits them from the runner, reaches the child stage the way
// os/exec passes every such descriptor on, and must not reach the agent. CI caught this as agent fds
// [0 1 142 145 2] in TestSignalTermForwarded; here the leaked descriptors are planted, so the test fails
// wherever the stage leaves them open, not only where a runner happens to leak some.
//
// Also pins runtime-launch.md E42: descriptors the launcher inherited without FD_CLOEXEC do not reach the agent.
func TestAgentInheritsNothingTheLauncherInherited(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], 0); err != nil { // no O_CLOEXEC, as a leaked descriptor arrives
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })
	high, err := unix.FcntlInt(uintptr(p[0]), unix.F_DUPFD, 140) // F_DUPFD leaves FD_CLOEXEC clear too
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(high) })
	child := startReadyAgent(t, nil)
	// The planted descriptors must be gone, checked by number and by what they refer to.
	planted := map[string]bool{}
	for _, fd := range []int{p[0], p[1], high} {
		if l, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
			planted[l] = true
		}
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", child.PID))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		l, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", child.PID, e.Name()))
		n := e.Name()
		if n == strconv.Itoa(p[0]) || n == strconv.Itoa(p[1]) || n == strconv.Itoa(high) || planted[l] {
			t.Fatalf("agent holds fd %s (%s): a descriptor the launcher held without FD_CLOEXEC reached it", n, l)
		}
	}
}

// TestNonUTF8BytesReachExecve: runtime-launch.md E17 through the real stage. The agent writes back the argv
// byte, the env value and its working directory it was given; each must be the launcher's bytes exactly.
func TestNonUTF8BytesReachExecve(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d\x80ir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	arg, env := "a\xffb", "\xfe\xff\xc3"
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sh", "-c", `printf %s "$1" >argv; printf %s "$BAD" >env; pwd -P >cwd`, "sh", arg},
		Env:     []string{"BAD=" + env, "PATH=/usr/bin:/bin"}, Dir: dir, Handle: fakeHandle{ruleset: -1},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if err := takeListener(t)(child.WaitNotifyFD(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	r, err := child.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Status.Exited() || r.Status.ExitStatus() != 0 {
		t.Fatalf("agent ended %+v", r)
	}
	for name, want := range map[string]string{"argv": arg, "env": env, "cwd": dir + "\n"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s reached the agent as %q, want %q", name, got, want)
		}
	}
}

// startSleeper starts an agent, completes the handshake and waits until it has exec'd.
func startSleeper(t *testing.T, cgFD sys.Lender, argv ...string) *Child {
	t.Helper()
	ctx := context.Background()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: argv, Dir: "/", Env: []string{"PATH=/usr/bin:/bin"}, Handle: fakeHandle{ruleset: -1},
	}, cgFD)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Kill(context.Background()); child.Close() })
	if err := takeListener(t)(child.WaitNotifyFD(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	waitComm(t, child.PID, filepath.Base(argv[0]))
	return child
}

// startReadyAgent waits for an agent instruction, after the dynamic loader has closed its own
// descriptors. comm changes at exec, while those descriptors may still be open. The shell uses
// only builtins and blocks on stdin, so no program started after readiness can reopen a descriptor.
func startReadyAgent(t *testing.T, cgFD sys.Lender) *Child {
	t.Helper()
	input, _ := agentPipe(t) // cleanup keeps the write end open while the agent blocks in read
	ready, output := agentPipe(t)
	ctx := t.Context()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sh", "-c", "printf 'ready\\n'; read ignored"}, Dir: "/",
		Env: []string{"PATH=/usr/bin:/bin"}, Handle: fakeHandle{ruleset: -1}, Stdin: input, Stdout: output,
	}, cgFD)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Kill(context.Background()); child.Close() })
	_ = input.Close()
	_ = output.Close()
	if err := takeListener(t)(child.WaitNotifyFD(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("agent readiness = %q, %v", line, err)
	}
	return child
}

func agentPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func TestSignalTermForwarded(t *testing.T) {
	_, cgFD := testCgroup(t)
	child := startReadyAgent(t, cgFD)
	// R6/invariant 4: the agent inherited nothing of the handshake, not even its own listener.
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", child.PID))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "0,1,2" {
		t.Fatalf("agent fds %v, want only 0,1,2", names)
	}
	h, err := NewSignalHandler(child, newFakeKiller(), SignalPolicy{StopGrace: time.Minute, StdinIsTTY: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.stopTimer()
	h.Handle(syscall.SIGTERM)
	r, err := child.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Status.Signaled() || r.Status.Signal() != syscall.SIGTERM {
		t.Fatalf("status %#x, want SIGTERM", uint32(r.Status))
	}
	if reason, code := Ended(r, h.Outcome()); reason != identity.ReasonSignal || code != identity.ExitStoppedTerm {
		t.Fatalf("Ended = %s/%d", reason, code)
	}
}

func TestSignalIntFromTTYNotResent(t *testing.T) {
	child := startSleeper(t, nil, "/bin/sleep", "60")
	h, err := NewSignalHandler(child, newFakeKiller(), SignalPolicy{StopGrace: time.Minute, StdinIsTTY: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h.stopTimer()
	h.Handle(syscall.SIGINT)
	if pollExit(t, child, 200) {
		t.Fatal("SIGINT re-sent to the agent although stdin is a terminal")
	}
	if o := h.Outcome(); o.Signal != syscall.SIGINT || o.Escalated {
		t.Fatalf("outcome %+v", o)
	}
}

func TestStopGraceEscalatesThroughCgroupKill(t *testing.T) {
	cgDir, cgFD := testCgroup(t)
	child := startSleeper(t, cgFD, "/bin/sh", "-c", "trap '' TERM; sleep 60")
	waitSigIgnored(t, child.PID, syscall.SIGTERM)
	h, err := NewSignalHandler(child, cgroupFileKiller{cgDir}, SignalPolicy{StopGrace: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer h.stopTimer()
	start := time.Now()
	h.Handle(syscall.SIGTERM)
	r, err := child.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("agent died after %v, before stop_grace", elapsed)
	}
	if !r.Status.Signaled() || r.Status.Signal() != syscall.SIGKILL {
		t.Fatalf("status %#x, want SIGKILL from cgroup.kill", uint32(r.Status))
	}
	o := h.Outcome()
	if !o.Escalated || o.Signal != syscall.SIGTERM || h.KillError() != nil {
		t.Fatalf("outcome %+v kill error %v", o, h.KillError())
	}
	if reason, code := Ended(r, o); reason != identity.ReasonSignal || code != identity.ExitStoppedKill {
		t.Fatalf("Ended = %s/%d", reason, code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !cgroupEmpty(cgDir) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cgroupEmpty(cgDir) {
		t.Fatal("cgroup.kill left the grandchild alive")
	}
}

// Also pins runtime-launch.md E3: a child that dies before the handshake is ErrChildDied.
func TestChildDiesBeforeHandoff(t *testing.T) {
	ctx := context.Background()
	child, err := (&Launcher{Exe: "/bin/false", Args: []string{}}).Start(ctx, validSpec(), nil)
	if err != nil {
		if !errors.Is(err, ErrChildDied) {
			t.Fatalf("Start = %v, want ErrChildDied", err)
		}
		return
	}
	defer child.Close()
	err = takeListener(t)(child.WaitNotifyFD(ctx))
	if !errors.Is(err, ErrChildDied) {
		t.Fatalf("WaitNotifyFD = %v, want ErrChildDied", err)
	}
	if pidfdOpen(child) {
		t.Fatal("child not reaped and closed after the failed handoff (R13)")
	}
}

// Also pins runtime-launch.md E4: a landlock_restrict_self failure reaches the parent as ErrChildLandlock wrapping the errno.
func TestChildStepFailureIsDecoded(t *testing.T) {
	// A ruleset fd that is not a ruleset: landlock_restrict_self fails EBADFD, reported as StepLandlock.
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx := context.Background()
	spec := validSpec()
	spec.Handle = fakeHandle{ruleset: int(f.Fd())}
	child, err := (&Launcher{}).Start(ctx, spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	err = takeListener(t)(child.WaitNotifyFD(ctx))
	if !errors.Is(err, ErrChildLandlock) || !errors.Is(err, syscall.EBADFD) {
		t.Fatalf("WaitNotifyFD = %v, want ErrChildLandlock wrapping EBADFD", err)
	}
}

func TestWaitNotifyFDHonoursContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// A "child stage" that never writes: the real stage would, so stand in a sleeper.
	child, err := (&Launcher{Exe: "/bin/sleep", Args: []string{"60"}}).Start(ctx, validSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	err = takeListener(t)(child.WaitNotifyFD(ctx))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitNotifyFD = %v, want DeadlineExceeded", err)
	}
	if pidfdOpen(child) {
		t.Fatal("child not aborted after the cancelled handoff (R13)")
	}
	if _, err := (&Launcher{}).Start(ctx, validSpec(), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Start with a done ctx = %v", err)
	}
}

func TestWaitHonoursContext(t *testing.T) {
	child := startSleeper(t, nil, "/bin/sleep", "60")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := child.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait = %v, want DeadlineExceeded", err)
	}
	if err := child.Kill(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := child.Wait(context.Background())
	if err != nil || !r.Status.Signaled() || r.Status.Signal() != syscall.SIGKILL {
		t.Fatalf("after Kill: %+v, %v", r, err)
	}
}

func TestSetSubreaperOnce(t *testing.T) {
	l := &Launcher{}
	if err := l.SetSubreaper(); err != nil {
		t.Fatal(err)
	}
	if err := l.SetSubreaper(); err != nil {
		t.Fatal(err)
	}
	if err := sys.SetChildSubreaper(false); err != nil {
		t.Fatal(err)
	}
}

// TestSubreaperReparentsOrphan pins the actual kernel effect SetSubreaper's own doc comment claims
// ("daemonized descendants of the agent are re-parented to the launcher, not init") and that case 24 relies
// on for the cgroup wait to see a daemonized descendant at all -- TestSetSubreaperOnce above only proves the
// prctl call itself doesn't error twice, never that reparenting actually happens. An intermediate process
// forks a grandchild into the background and exits immediately, orphaning it before it has done any work;
// with PR_SET_CHILD_SUBREAPER set, the kernel must reparent that orphan to this process, never to PID 1.
func TestSubreaperReparentsOrphan(t *testing.T) {
	l := &Launcher{}
	if err := l.SetSubreaper(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sys.SetChildSubreaper(false) })

	// The background job must not inherit this pipe's write end: cmd.Output() waits for stdout's read end
	// to see EOF, which needs every holder of the write end closed, so an un-redirected background sleep
	// would keep the pipe open (and Output() blocked) for its own full lifetime, not just the shell's.
	out, err := exec.Command("/bin/sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!").Output()
	if err != nil {
		t.Fatal(err)
	}
	gcPID, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("grandchild pid %q: %v", out, err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(gcPID, syscall.SIGKILL)
		var ws syscall.WaitStatus
		// We are its reaper now (that is the whole point under test): leaving it unreaped would zombie it.
		_, _ = syscall.Wait4(gcPID, &ws, 0, nil)
	})

	want := os.Getpid()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ppid, err := readPPID(gcPID)
		if err != nil {
			t.Fatalf("grandchild %d gone before reparenting was observed: %v", gcPID, err)
		}
		if ppid == want {
			return // reparented to us, the subreaper -- not to init
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d has parent %d, want %d (this process, the subreaper)", gcPID, ppid, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// readPPID reads field 4 (ppid) of /proc/<pid>/stat, using the same comm-delimiter approach as
// parseStartBootNS since comm may itself contain spaces or parentheses.
func readPPID(pid int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return 0, fmt.Errorf("parse /proc/%d/stat: no comm delimiter", pid)
	}
	fields := bytes.Fields(b[end+1:])
	if len(fields) < 2 { // fields[0] is field 3 (state), fields[1] is field 4 (ppid)
		return 0, fmt.Errorf("parse /proc/%d/stat: too few fields", pid)
	}
	return strconv.Atoi(string(fields[1]))
}

// BenchmarkStartHandshakeWait measures one full launch of /bin/true through the child stage with a served
// execve notification: the per-run startup cost this package adds.
func BenchmarkStartHandshakeWait(b *testing.B) {
	prog := execveFilter(b)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		child, err := (&Launcher{}).Start(ctx, ChildSpec{
			Command: []string{"/bin/true"}, Dir: "/", Handle: fakeHandle{ruleset: -1, prog: prog},
		}, nil)
		if err != nil {
			b.Fatal(err)
		}
		fd, err := child.WaitNotifyFD(ctx)
		if err != nil {
			b.Fatal(err)
		}
		stop := make(chan struct{})
		seen := serveContinue(fd, stop)
		if err := child.Ack(); err != nil {
			b.Fatal(err)
		}
		if _, err := child.Wait(ctx); err != nil {
			b.Fatal(err)
		}
		close(stop)
		<-seen
		_ = fd.Close()
		child.Close()
	}
}
