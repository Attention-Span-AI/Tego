// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
)

// deputyTestPin is the launch tests' walk: an O_PATH open of the pathname as given, or of its parent for a create
// whose final component is missing. The supervisor's own walk is tested where it lives.
func deputyTestPin(q deputy.PinQuery) (deputy.Pinned, error) {
	if q.Create {
		if _, err := os.Lstat(q.Path); errors.Is(err, os.ErrNotExist) {
			fd, err := unix.Open(filepath.Dir(q.Path), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			return deputy.Pinned{FD: fd, Leaf: filepath.Base(q.Path)}, err
		}
	}
	fd, err := unix.Open(q.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
	return deputy.Pinned{FD: fd}, err
}

// TestStageStartsTheDeputyInTheRunsDomain is ADR 0041 Step 7 at the launch: the child stage starts the open deputy
// after landlock_restrict_self and before the listener filter. The deputy says hello with kernel-attested
// credentials, is the launcher's child (CLONE_PARENT) and never the agent's, carries no capability, is not dumpable
// and runs under its own filter; and its opens are the run's own, so the stage's Landlock domain refuses its create
// outside the write directory and allows the one inside it.
func TestStageStartsTheDeputyInTheRunsDomain(t *testing.T) {
	allowed, denied := t.TempDir(), t.TempDir()
	rs := landlockRuleset(t, allowed)
	launcherEnd, stageEnd, err := deputy.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	stageF := os.NewFile(uintptr(stageEnd), "deputy-stage")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sleep", "60"}, Dir: "/", Env: []string{"PATH=/usr/bin:/bin"},
		Handle: fakeHandle{ruleset: rs, prog: execveFilter(t)}, Deputy: stageF,
	}, nil)
	_ = stageF.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Kill(child.PID, unix.SIGKILL)
		_, _ = child.Wait(context.Background())
		_ = child.Close()
	})
	notify, err := child.WaitNotifyFD(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer notify.Close()
	c, err := deputy.Hello(launcherEnd, 10*time.Second)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	stop := make(chan struct{})
	defer close(stop)
	seen := serveContinue(notify, stop)
	_ = seen
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}

	status := readStatus(t, c.PID())
	if ppid := status["PPid"]; ppid != strconv.Itoa(os.Getpid()) {
		t.Fatalf("deputy's parent is %s, want the launcher %d (CLONE_PARENT)", ppid, os.Getpid())
	}
	for key, want := range map[string]string{"Seccomp": "2", "NoNewPrivs": "1", "CapEff": "0000000000000000", "CapPrm": "0000000000000000"} {
		if got := status[key]; got != want {
			t.Errorf("deputy %s: %s, want %s", key, got, want)
		}
	}
	// Not dumpable: a process of the deputy's uid without CAP_SYS_PTRACE (the agent) cannot reach its descriptors. Root
	// holds the capability, so as root the refusal is not there to see.
	if os.Geteuid() != 0 {
		if _, err := os.Readlink("/proc/" + strconv.Itoa(c.PID()) + "/fd/3"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("readlink of the deputy's descriptor = %v, want EACCES: it is not dumpable", err)
		}
	}
	// The agent (the stage, now sleep) has no child: the deputy is the launcher's.
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(child.PID) + "/comm")
		if strings.TrimSpace(string(b)) == "sleep" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if kids, _ := os.ReadFile("/proc/" + strconv.Itoa(child.PID) + "/task/" + strconv.Itoa(child.PID) + "/children"); strings.TrimSpace(string(kids)) != "" {
		t.Errorf("the agent has children %q; the deputy must never be one", kids)
	}

	create := func(dir string) error {
		p, err := c.Pin(deputy.PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: filepath.Join(dir, "made"), Create: true}, nil)
		if err != nil {
			return err
		}
		defer unix.Close(p.FD)
		fd, err := c.Open(p.FD, p.Leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644, 0o022, nil)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	if err := create(allowed); err != nil {
		t.Fatalf("deputy create in the write directory: %v", err)
	}
	if err := create(denied); !errors.Is(err, unix.EACCES) {
		t.Fatalf("deputy create outside the write directory = %v, want the stage's Landlock EACCES", err)
	}
	if _, err := os.Stat(filepath.Join(denied, "made")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused create left a file: %v", err)
	}
}

// TestStageReportsADeputyThatCannotStart: a deputy whose exec fails (here: no /proc/self/exe to run, simulated by a
// stage whose descriptor is not a socket) is reported on the control socket rather than failing the run, and the
// launcher's Hello names the failure (the degrade, ADR 0041 Consequences).
func TestStageReportsADeputyThatCannotStart(t *testing.T) {
	launcherEnd, stageEnd, err := deputy.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	if err := deputy.ReportFailure(stageEnd, unix.ENOEXEC, "deputy: start: exec format error"); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(stageEnd)
	_, err = deputy.Hello(launcherEnd, 5*time.Second)
	if !errors.Is(err, deputy.ErrNotStarted) || !errors.Is(err, unix.ENOEXEC) || !strings.Contains(err.Error(), "deputy: start: exec format error") {
		t.Fatalf("hello after a reported failure = %v, want ErrNotStarted wrapping ENOEXEC, naming the stage's reason", err)
	}
	_ = unix.Close(launcherEnd)
}

// stageDeputy starts a stage under ruleset rs with an open deputy, as TestStageStartsTheDeputyInTheRunsDomain does,
// and returns the deputy's client once the stage is released.
func stageDeputy(t *testing.T, rs int) *deputy.Client {
	t.Helper()
	launcherEnd, stageEnd, err := deputy.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	stageF := os.NewFile(uintptr(stageEnd), "deputy-stage")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	child, err := (&Launcher{}).Start(ctx, ChildSpec{
		Command: []string{"/bin/sleep", "60"}, Dir: "/", Env: []string{"PATH=/usr/bin:/bin"},
		Handle: fakeHandle{ruleset: rs, prog: execveFilter(t)}, Deputy: stageF,
	}, nil)
	_ = stageF.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Kill(child.PID, unix.SIGKILL)
		_, _ = child.Wait(context.Background())
		_ = child.Close()
	})
	notify, err := child.WaitNotifyFD(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notify.Close() })
	c, err := deputy.Hello(launcherEnd, 10*time.Second)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	serveContinue(notify, stop)
	if err := child.Ack(); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDeputyDescriptorCarriesTheDomainsFileRights is ADR 0041 Step 8's Landlock-equivalence of the delivered
// descriptor: Landlock fixes a file's TRUNCATE and IOCTL_DEV rights when it is opened, from the opener's domain, and a
// descriptor the deputy opened carries them wherever it goes, as one the agent opened would. Under a domain that
// handles both and grants TRUNCATE in one write directory only and IOCTL_DEV nowhere, a descriptor the deputy opened
// for writing in the other directory cannot be truncated, an O_TRUNC open there is refused, and an ioctl on its
// /dev/zero is refused; the same opens made outside any domain (as the supervisor-thread completion of ADR 0008 made
// them) carry neither restriction. The write directory with TRUNCATE truncates.
func TestDeputyDescriptorCarriesTheDomainsFileRights(t *testing.T) {
	abi, err := sys.LandlockABI()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	if abi < 5 {
		t.Skipf("Landlock ABI %d: TRUNCATE needs 3 and IOCTL_DEV 5", abi)
	}
	noTrunc, withTrunc := t.TempDir(), t.TempDir()
	for _, d := range []string{noTrunc, withTrunc} {
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("contents"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	attr := sys.LandlockRulesetAttr{Handled_access_fs: sys.LandlockAccessFSABI1 | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV}
	rs, err := sys.LandlockCreateRuleset(&attr, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(rs) })
	add := func(path string, access uint64) {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor
		if err := sys.LandlockAddRule(rs, unix.LANDLOCK_RULE_PATH_BENEATH, unsafe.Pointer(&unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}), 0); err != nil {
			t.Fatal(err)
		}
	}
	add("/", unix.LANDLOCK_ACCESS_FS_READ_FILE|unix.LANDLOCK_ACCESS_FS_READ_DIR|unix.LANDLOCK_ACCESS_FS_EXECUTE)
	add(noTrunc, sys.LandlockAccessFSABI1)
	add(withTrunc, sys.LandlockAccessFSABI1|unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	c := stageDeputy(t, rs)

	open := func(path string, flags int) (int, error) {
		p, err := c.Pin(deputy.PinQuery{TID: os.Getpid(), TGID: os.Getpid(), DirFD: unix.AT_FDCWD, Path: path}, nil)
		if err != nil {
			return -1, err
		}
		defer unix.Close(p.FD) //nolint:errcheck // the pin
		return c.Open(p.FD, p.Leaf, flags, 0, -1, nil)
	}
	truncates := func(fd int, err error) error {
		if err != nil {
			return err
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		return unix.Ftruncate(fd, 1)
	}
	ioctls := func(fd int, err error) error {
		if err != nil {
			return err
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		_, err = unix.IoctlGetTermios(fd, unix.TCGETS)
		return err
	}
	if err := truncates(open(filepath.Join(noTrunc, "f"), unix.O_WRONLY)); !errors.Is(err, unix.EACCES) {
		t.Errorf("ftruncate of the deputy's descriptor where the domain grants no TRUNCATE = %v, want EACCES", err)
	}
	if _, err := open(filepath.Join(noTrunc, "f"), unix.O_WRONLY|unix.O_TRUNC); !errors.Is(err, unix.EACCES) {
		t.Errorf("the deputy's O_TRUNC open where the domain grants no TRUNCATE = %v, want EACCES", err)
	}
	if err := truncates(open(filepath.Join(withTrunc, "f"), unix.O_WRONLY)); err != nil {
		t.Errorf("ftruncate of the deputy's descriptor where the domain grants TRUNCATE = %v, want success", err)
	}
	if err := ioctls(open("/dev/zero", unix.O_RDONLY)); !errors.Is(err, unix.EACCES) {
		t.Errorf("an ioctl on the deputy's /dev/zero, no IOCTL_DEV granted = %v, want EACCES", err)
	}
	// The same opens outside any domain: neither restriction, which is what a completion outside the run gave.
	if err := truncates(unix.Open(filepath.Join(noTrunc, "f"), unix.O_WRONLY|unix.O_CLOEXEC, 0)); err != nil {
		t.Errorf("ftruncate outside the domain = %v, want success", err)
	}
	if err := ioctls(unix.Open("/dev/zero", unix.O_RDONLY|unix.O_CLOEXEC, 0)); !errors.Is(err, unix.ENOTTY) {
		t.Errorf("an ioctl on /dev/zero outside the domain = %v, want the driver's ENOTTY", err)
	}
}

func readStatus(t *testing.T, pid int) map[string]string {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}
