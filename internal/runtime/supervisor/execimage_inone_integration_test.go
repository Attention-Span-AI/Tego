// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// rootedThread starts an OS thread of this process whose root is dir (unshare(CLONE_FS), then chroot) and returns its
// tid, a task whose root is not this process's. The thread parks until the test ends, then exits with its goroutine,
// which never unlocks it, so its root reaches no other goroutine. It is never the main thread: that is the thread
// group's leader, whose root /proc/self/root and /proc/self/mountinfo read for every thread, and the runtime parks a
// main thread whose locked goroutine exits rather than ending it, so a main thread rooted here kept its root for the
// rest of the test binary (in a guest, fourteen later tests then read this process's own root as foreign). A goroutine
// that lands on the main thread holds it while it starts the work again, which then lands on another thread.
func rootedThread(t *testing.T, dir string) int {
	t.Helper()
	tid := make(chan int, 1)
	fail := make(chan error, 1)
	end := make(chan struct{})
	elsewhere := make(chan struct{})
	var root func()
	root = func() {
		runtime.LockOSThread() // never unlocked on the rooted thread: it exits with this goroutine
		if unix.Gettid() == unix.Getpid() {
			go root()
			<-elsewhere
			runtime.UnlockOSThread()
			return
		}
		close(elsewhere)
		if err := unix.Unshare(unix.CLONE_FS); err != nil {
			fail <- err
			return
		}
		if err := unix.Chroot(dir); err != nil {
			fail <- err
			return
		}
		tid <- unix.Gettid()
		<-end
	}
	go root()
	select {
	case id := <-tid:
		t.Cleanup(func() { close(end) })
		return id
	case err := <-fail:
		t.Fatalf("a thread rooted at %s: %v", dir, err)
	}
	return 0
}

// inOneAsAtTierLandlock has image walks ask lookupInOne as they do where this process holds no DAC capability: the root
// suites run as root, whose image walks check the task's search permission and never ask it.
func inOneAsAtTierLandlock(t *testing.T) {
	t.Helper()
	prev := searchChecked
	t.Cleanup(func() { searchChecked = prev })
	searchChecked = func() bool { return false }
}

// TestLookupInOneNeverMountsAnAutomountPoint holds lookupInOne to the image walk's rule that it mounts no automount
// point (automountLookup). The task's root is a fresh debugfs, whose tracing directory is an S_AUTOMOUNT stub on that
// root's own mount, so no mount crossing ends a lookup of /tracing/README first. The image walk leaves the stub
// unmounted and answers as the component walk does (a failure at an automount point, no miss). Then the answering
// lookup is made alone, without its RESOLVE_CACHED guard: in the 6.1 and 6.17 rows' guests it refused EXDEV and mounted
// nothing, on 5.14 (RHEL 9) it mounts tracefs before it refuses (logged, the reason for the guard: without it this test failed on that row); the
// control, a lookup without RESOLVE_NO_XDEV, reaches the file with tracefs mounted, so the stub was live.
func TestLookupInOneNeverMountsAnAutomountPoint(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts a debugfs and roots a thread at it (root-suites.sh)")
	}
	mnt := filepath.Join(t.TempDir(), "debug")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("none", mnt, "debugfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount a debugfs at %s: %v", mnt, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	tracing := filepath.Join(mnt, "tracing")
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, tracing, unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, 0, &stx); err != nil {
		t.Fatalf("statx %s: %v (a kernel built without tracing has no such stub)", tracing, err)
	}
	if stx.Attributes&unix.STATX_ATTR_AUTOMOUNT == 0 {
		t.Fatalf("%s: attributes %#x carry no STATX_ATTR_AUTOMOUNT: the case proves nothing", tracing, stx.Attributes)
	}
	unmounted := func() bool {
		var stx unix.Statx_t
		return unix.Statx(unix.AT_FDCWD, tracing, unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stx) == nil &&
			stx.Mnt_id == mountID(t, mnt)
	}
	inOneAsAtTierLandlock(t)
	tid := rootedThread(t, mnt)
	q := pathQuery{tid: tid, dirfd: atFDCWD, path: "/tracing/README", joined: "/tracing/README", head: true}
	_, err := sysKernel{}.ExecImage(q)
	var a automountLookup
	if !errors.As(err, &a) || lookupErrno(err) != unix.ENOENT {
		t.Errorf("%s from a root at %s: %v, want a failure at an automount point (ENOENT)", q.path, mnt, err)
	}
	if _, answered := inOneAnswers(t, q, 1); answered {
		t.Errorf("lookupInOne answered %s across an unmounted automount point", q.path)
	}
	if !unmounted() {
		t.Fatalf("%s is mounted after the image walk: lookupInOne mounted it", tracing)
	}
	root, err := unix.Open("/proc/"+strconv.Itoa(tid)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root) //nolint:errcheck // a descriptor this test opened
	lookup := func(resolve uint64) error {
		fd, err := unix.Openat2(root, q.path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: resolve})
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	err = lookup(inOneResolve)
	t.Logf("the answering lookup without its guard: %v; this kernel mounted the stub first: %v", err, !unmounted())
	// The control: without RESOLVE_NO_XDEV the lookup reaches the file, tracefs mounted at the stub.
	if err := lookup(unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS); err != nil || unmounted() {
		t.Fatalf("the lookup without RESOLVE_NO_XDEV: %v, the stub unmounted %v: the case proves nothing", err, unmounted())
	}
}

// TestLookupInOneResolvesFromTheTasksRoot holds lookupInOne to the task's root where it is not this process's (a
// chroot): an absolute pathname, an absolute symlink and ".." past the root all resolve inside it, as the kernel
// resolves them for the task (RESOLVE_IN_ROOT), and lookupInOne answers them with the component walk's file.
func TestLookupInOneResolvesFromTheTasksRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: roots a thread at a directory (chroot, root-suites.sh)")
	}
	jail := t.TempDir()
	if err := os.Mkdir(filepath.Join(jail, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(jail, "bin", "f")
	if err := os.WriteFile(f, []byte("#!/x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, to := range map[string]string{"abs": "/bin/f", "up": "../../../bin/f"} {
		if err := os.Symlink(to, filepath.Join(jail, link)); err != nil {
			t.Fatal(err)
		}
	}
	want := statID(t, f)
	inOneAsAtTierLandlock(t)
	tid := rootedThread(t, jail)
	componentWalkOnly(t)
	for _, c := range []struct {
		path    string
		answers bool // a spelled ".." is the walk's to name (namedByWalk), so lookupInOne leaves it
	}{{"/bin/f", true}, {"/abs", true}, {"/up", true}, {"/../../bin/f", false}, {"/bin/../../bin/f", false}} {
		p := c.path
		q := pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p, head: true}
		lookupInOneOn = false
		walked, walkErr := sysKernel{}.ExecImage(q)
		lookupInOneOn = true
		img, err := sysKernel{}.ExecImage(q)
		if err != nil || walkErr != nil || img.id != want || walked.id != want || string(img.head) != "#!/x\n" ||
			img.name != walked.name {
			t.Errorf("%s from a root at %s: %v %v (head %q, name %q), the component walk %v %v (name %q); want %v", p,
				jail, img.id, err, img.head, img.name, walked.id, walkErr, walked.name, want)
		}
		tries := 1
		if c.answers {
			tries = 50
		}
		id, answered := inOneAnswers(t, q, tries)
		switch {
		case answered && (!c.answers || id != want):
			t.Errorf("%s from a root at %s: lookupInOne answered %v (%v), want %v (%v)", p, jail, answered, id,
				c.answers, want)
		case !answered && c.answers:
			// As in TestLookupInOneIsTheComponentWalks: the decline is lookupInOne's fault only where the two lookups
			// it makes, asked here with their flags spelt out, both reach the file now. On RHEL 9.8's 5.14 a
			// RESOLVE_CACHED lookup through a symlink answered EAGAIN on xfs and on strictatime tmpfs, and reached the
			// file on relatime and noatime tmpfs (2026-11-10), so where it answers EAGAIN /abs and /up are the
			// component walk's; its answer was held to the file above.
			if rcuErr, xdevErr := rawInOne(t, tid, p); rcuErr == nil && xdevErr == nil {
				t.Errorf("%s from a root at %s: lookupInOne declined a path both its lookups reach", p, jail)
			} else {
				t.Logf("%s from a root at %s: this kernel's lookups do not reach it (RESOLVE_CACHED: %v, "+
					"RESOLVE_NO_XDEV: %v): left to the component walk", p, jail, rcuErr, xdevErr)
			}
		}
	}
}

// TestLookupInOneLeavesAProcfsRootToTheComponentWalk holds lookupInOne to its last check: with no mount crossed every
// component lies on the root's filesystem, and a root on procfs is the one place where that lookup could still resolve
// "self" as this process; it declines there and the component walk answers.
func TestLookupInOneLeavesAProcfsRootToTheComponentWalk(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: roots a thread at /proc (chroot, root-suites.sh)")
	}
	inOneAsAtTierLandlock(t)
	tid := rootedThread(t, "/proc")
	for _, p := range []string{"/self/status", "/" + strconv.Itoa(os.Getpid()) + "/status", "/cpuinfo"} {
		q := pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p}
		if _, answered := inOneAnswers(t, q, 1); answered {
			t.Errorf("%s from a root at /proc: lookupInOne answered", p)
		}
		if _, err := (sysKernel{}).ExecImage(q); err != nil {
			t.Errorf("%s from a root at /proc: %v, want the component walk to reach it", p, err)
		}
	}
}
