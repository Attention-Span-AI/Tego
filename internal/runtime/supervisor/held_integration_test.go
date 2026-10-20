// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The held-open harness (ADR 0041 Stage B): the target starts a real open deputy (the test binary re-executed as
// deputy.Main with DeputyPin, the production walk) before it installs the gate arms of the real filter, and the loop
// completes every open of an escalating gate kind through that deputy.
const (
	modeHeld      = "held"
	modeHeldRace  = "heldrace"
	modeBenchHeld = "benchheld"
	// helperDeputyFD is the target's descriptor number of the deputy's control socket.
	helperDeputyFD = "TEGO_SUPERVISOR_DEPUTY_FD"
	// helperDeputyMain makes the test binary the deputy, with these arguments.
	helperDeputyMain = "TEGO_SUPERVISOR_DEPUTY_MAIN"
	// helperFilterGate selects the filter's gate arms ("r", "w", "rw").
	helperFilterGate = "TEGO_SUPERVISOR_FILTER_GATE"
	// helperHeldOps lists the differential cases a modeHeld target runs, comma separated; empty runs them all.
	helperHeldOps = "TEGO_SUPERVISOR_HELD_OPS"
	// helperHeldThreads is how many filtered threads the parallel part of modeBenchHeld opens from (default 4).
	helperHeldThreads = "TEGO_SUPERVISOR_HELD_THREADS"
)

// heldAgent is the credentials a held test's target runs under: none (the caller's) without root; as root, the
// invoking user's, as a root run drops its agent. A root target would hold every capability, which the deputy, which
// takes none, cannot match: its walk of the target's /proc entries would be refused (ptrace access needs the
// target's permitted set), as it is for no agent a run starts. It returns a chown for the fixture's files too.
func heldAgent(t testing.TB) (*syscall.Credential, func(paths ...string)) {
	t.Helper()
	if os.Geteuid() != 0 {
		return nil, func(...string) {}
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 {
		t.Skip("as root a held test's agent is the invoking user: needs SUDO_UID and SUDO_GID, as `sudo go test` and test/vm/kvm-run.sh --sudo give")
	}
	own := func(paths ...string) {
		for _, p := range paths {
			if err := os.Lchown(p, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, own
}

// ownedTree gives every name prepare made under dir to the agent (own), dir included.
func ownedTree(t testing.TB, own func(...string), prepare func(string)) func(string) {
	return func(dir string) {
		prepare(dir)
		if err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
			if err == nil {
				own(p)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// spawnTestDeputy starts the deputy as launch.spawnDeputy does, minus CLONE_PARENT (the target is the launcher's
// stand-in here): its control socket at deputy.ControlFD, its readiness socket at deputy.ReadyFD, /dev/null for its
// standard streams. It returns a skip reason, "" once the deputy reported itself confined.
func spawnTestDeputy(fdText string) string {
	fd, err := strconv.Atoi(fdText)
	if err != nil {
		return "deputy fd: " + err.Error()
	}
	ready, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "deputy readiness socketpair: " + err.Error()
	}
	defer unix.Close(ready[0]) //nolint:errcheck // the target's end
	control := os.NewFile(uintptr(fd), "deputy-control")
	readyW := os.NewFile(uintptr(ready[1]), "deputy-ready")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = []string{helperDeputyMain + "=--parent " + strconv.Itoa(os.Getpid()), "GOMAXPROCS=2", "GODEBUG=decoratemappings=0"}
	cmd.ExtraFiles = []*os.File{control, readyW}
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	_ = readyW.Close()
	_ = control.Close()
	if err != nil {
		return "start deputy: " + err.Error()
	}
	// The deputy's pid, in the target's own /proc view (the two share a pid namespace): the deputy-proc differential
	// cases name it (deputyProcCases), to show a held open cannot reach the deputy's own /proc entries.
	testDeputyPid = cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	tv := unix.NsecToTimeval((20 * time.Second).Nanoseconds())
	if err := unix.SetsockoptTimeval(ready[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return "deputy readiness timeout: " + err.Error()
	}
	var b [1]byte
	if n, err := unix.Read(ready[0], b[:]); err != nil || n != 1 {
		return fmt.Sprintf("deputy not ready: %d %v", n, err)
	}
	return ""
}

// installTSyncListener installs the filter with NEW_LISTENER on every thread of the target
// (SECCOMP_FILTER_FLAG_TSYNC with TSYNC_ESRCH, Linux 5.7): the Go runtime's threads exist before the filter, and a
// goroutine on one of them would make the kernel's own syscalls, never notified, where an agent's every thread
// carries the filter from its first execve.
func installTSyncListener(raw []bpf.RawInstruction) (int, error) {
	filter := make([]unix.SockFilter, len(raw))
	for i, in := range raw {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	flags := uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER | unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH)
	r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog)))
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

// filteredThreads returns n locked OS threads, each running the functions sent on its channel. Every thread carries
// the target's filter (installTSyncListener), and a new one inherits it.
func filteredThreads(n int) []chan func() {
	out := make([]chan func(), n)
	for i := range out {
		ch := make(chan func())
		out[i] = ch
		go func() {
			runtime.LockOSThread()
			for f := range ch {
				f()
			}
		}()
	}
	return out
}

// heldCase is one open of the differential suite: the target makes it as the syscall, then describes the outcome
// with facts that do not depend on who opened the file (errno, file type, mode bits, size, flags, contents), so a
// held open and the kernel's own can be compared case by case.
type heldCase struct {
	name string
	run  func(dir string) string
}

// openFacts describes an open's outcome: its errno, or the descriptor's type, permission bits, size, access mode and
// O_APPEND, and up to 16 bytes of its contents.
func openFacts(fd int, err error) string {
	if err != nil {
		return "err=" + errName(err)
	}
	defer unix.Close(fd) //nolint:errcheck // a test descriptor
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return "fstat=" + errName(e)
	}
	fl, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	fdfl, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	out := fmt.Sprintf("type=%o perm=%o size=%d acc=%d append=%t cloexec=%t nonblock=%t", st.Mode&unix.S_IFMT, st.Mode&0o7777,
		st.Size, fl&unix.O_ACCMODE, fl&unix.O_APPEND != 0, fdfl&unix.FD_CLOEXEC != 0, fl&unix.O_NONBLOCK != 0)
	if st.Mode&unix.S_IFMT == unix.S_IFREG && fl&unix.O_ACCMODE != unix.O_WRONLY && fl&unix.O_PATH == 0 {
		buf := make([]byte, 16)
		n, e := unix.Pread(fd, buf, 0)
		if e != nil {
			out += " read=" + errName(e)
		} else {
			out += " data=" + strconv.Quote(string(buf[:n]))
		}
	}
	return out
}

func errName(err error) string {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return unix.ErrnoName(errno)
	}
	return err.Error()
}

// openat is the raw openat(2), so the target's own libc wrapper adds nothing.
func openat(dirfd int, path string, flags int, mode uint32) (int, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	r, _, e := unix.Syscall6(unix.SYS_OPENAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags), uintptr(mode), 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(r), nil
}

// atDir is a case that opens rel beneath the descriptor of start (opened with startFlags, relative to the harness
// directory) with flags and mode.
func atDir(start string, startFlags int, rel string, flags int, mode uint32) func(string) string {
	return func(dir string) string {
		dfd, err := unix.Open(dir+"/"+start, startFlags|unix.O_CLOEXEC, 0)
		if err != nil {
			return "dirfd=" + errName(err)
		}
		defer unix.Close(dfd) //nolint:errcheck // a test descriptor
		return openFacts(openat(dfd, rel, flags, mode))
	}
}

// procFDDir is a case that reads d/in-d through prefix and a descriptor of d (/proc/self/fd/N/in-d, /dev/fd/N/in-d):
// procfs's magic link to the task's own descriptor, as a path's middle component.
func procFDDir(prefix string) func(string) string {
	return func(dir string) string {
		dfd, err := unix.Open(dir+"/d", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return "dirfd=" + errName(err)
		}
		defer unix.Close(dfd) //nolint:errcheck // a test descriptor
		return openFacts(openat(unix.AT_FDCWD, prefix+strconv.Itoa(dfd)+"/in-d", unix.O_RDONLY, 0))
	}
}

// procSelf is a case that opens the task's own /proc/self/name for reading and says whether it opened: the contents
// and the size of a /proc file are the opener's own, so the open's answer is the fact compared.
func procSelf(name string) func(string) string {
	return func(string) string {
		fd, err := openat(unix.AT_FDCWD, "/proc/self/"+name, unix.O_RDONLY, 0)
		if err != nil {
			return "err=" + errName(err)
		}
		_ = unix.Close(fd)
		return "ok"
	}
}

// heldCases is the differential suite (ADR 0041 Step 8): each case is the same open made once with no gate (the
// kernel's own) and once held, and both must describe the same outcome.
func heldCases() []heldCase {
	// The name is dir + "/" + rel, never filepath.Join, which cleans a trailing slash away: the trailing_slash cases
	// opened "d", "f" and "nope" with no slash at all.
	open := func(rel string, flags int, mode uint32) func(string) string {
		return func(dir string) string { return openFacts(openat(unix.AT_FDCWD, dir+"/"+rel, flags, mode)) }
	}
	return []heldCase{
		{"read", open("f", unix.O_RDONLY, 0)},
		{"read_cloexec", open("f", unix.O_RDONLY|unix.O_CLOEXEC, 0)},
		{"read_nonblock", open("f", unix.O_RDONLY|unix.O_NONBLOCK, 0)},
		{"write_append", func(dir string) string {
			fd, err := openat(unix.AT_FDCWD, filepath.Join(dir, "a"), unix.O_WRONLY|unix.O_APPEND, 0)
			if err == nil {
				_, _ = unix.Write(fd, []byte("+"))
				_, _ = unix.Seek(fd, 0, 0)
				_, _ = unix.Write(fd, []byte("!"))
			}
			facts := openFacts(fd, err)
			b, _ := os.ReadFile(filepath.Join(dir, "a"))
			return facts + " after=" + strconv.Quote(string(b))
		}},
		{"write_trunc", func(dir string) string {
			facts := openFacts(openat(unix.AT_FDCWD, filepath.Join(dir, "t"), unix.O_WRONLY|unix.O_TRUNC, 0))
			st, _ := os.Stat(filepath.Join(dir, "t"))
			return facts + " size_after=" + strconv.FormatInt(st.Size(), 10)
		}},
		{"excl_existing", open("f", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)},
		{"excl_new", func(dir string) string {
			facts := openFacts(openat(unix.AT_FDCWD, filepath.Join(dir, "x-new"), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o666))
			st, err := os.Lstat(filepath.Join(dir, "x-new"))
			if err != nil {
				return facts + " stat=" + errName(err)
			}
			return facts + " made=" + strconv.FormatUint(uint64(st.Mode().Perm()), 8)
		}},
		{"excl_symlink", open("link-f", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)},
		{"creat_dangling", func(dir string) string {
			facts := openFacts(openat(unix.AT_FDCWD, filepath.Join(dir, "dangling"), unix.O_WRONLY|unix.O_CREAT, 0o640))
			_, err := os.Lstat(filepath.Join(dir, "dangling-target"))
			return facts + " target=" + strconv.FormatBool(err == nil)
		}},
		{"nofollow_link", open("link-f", unix.O_RDONLY|unix.O_NOFOLLOW, 0)},
		{"nofollow_file", open("f", unix.O_RDONLY|unix.O_NOFOLLOW, 0)},
		{"directory", open("d", unix.O_RDONLY|unix.O_DIRECTORY, 0)},
		{"directory_on_file", open("f", unix.O_RDONLY|unix.O_DIRECTORY, 0)},
		{"write_on_directory", open("d", unix.O_WRONLY, 0)},
		{"path", open("f", unix.O_PATH, 0)},
		{"path_nofollow_link", open("link-f", unix.O_PATH|unix.O_NOFOLLOW, 0)},
		{"tmpfile", func(dir string) string {
			return openFacts(openat(unix.AT_FDCWD, filepath.Join(dir, "d"), unix.O_RDWR|unix.O_TMPFILE, 0o600))
		}},
		{"dirfd_relative", func(dir string) string {
			dfd, err := unix.Open(filepath.Join(dir, "d"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				return "dirfd=" + errName(err)
			}
			defer unix.Close(dfd) //nolint:errcheck // a test descriptor
			return openFacts(openat(dfd, "in-d", unix.O_RDONLY, 0))
		}},
		// The other directory descriptors and starts a lookup can take: a file's descriptor (ENOTDIR), one not open
		// (EBADF), an O_PATH descriptor of a symlink, a directory's with an absolute name (ignored), an empty name
		// (ENOENT without AT_EMPTY_PATH), "." and "..", a create beneath it; and procfs's spellings of the task's own
		// cwd, root and descriptors, and doubled and "." components, which the deputy's walk must answer as the task's.
		{"dirfd_file", atDir("f", unix.O_RDONLY, "x", unix.O_RDONLY, 0)},
		{"dirfd_symlink", atDir("link-f", unix.O_PATH|unix.O_NOFOLLOW, "x", unix.O_RDONLY, 0)},
		{"dirfd_absolute", func(dir string) string {
			return atDir("d", unix.O_PATH|unix.O_DIRECTORY, dir+"/f", unix.O_RDONLY, 0)(dir)
		}},
		{"dirfd_empty", atDir("d", unix.O_RDONLY|unix.O_DIRECTORY, "", unix.O_RDONLY, 0)},
		{"dirfd_dot", atDir("d", unix.O_PATH|unix.O_DIRECTORY, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)},
		{"dirfd_dotdot", atDir("d", unix.O_PATH|unix.O_DIRECTORY, "../f", unix.O_RDONLY, 0)},
		{"dirfd_creat", func(dir string) string {
			facts := atDir("d", unix.O_PATH|unix.O_DIRECTORY, "c-new", unix.O_WRONLY|unix.O_CREAT, 0o600)(dir)
			_, err := os.Lstat(dir + "/d/c-new")
			return facts + " made=" + strconv.FormatBool(err == nil)
		}},
		{"dirfd_not_open", func(string) string { return openFacts(openat(4093, "f", unix.O_RDONLY, 0)) }},
		{"dirfd_negative", func(string) string { return openFacts(openat(-5, "f", unix.O_RDONLY, 0)) }},
		{"empty_name", func(string) string { return openFacts(openat(unix.AT_FDCWD, "", unix.O_RDONLY, 0)) }},
		// The task's own /proc files, which procfs checks at open against the opener: maps and environ ask the opener
		// may read the task (PTRACE_MODE_READ), mem that it may attach to it (PTRACE_MODE_ATTACH).
		{"proc_self_maps", procSelf("maps")},
		{"proc_self_environ", procSelf("environ")},
		{"proc_self_status", procSelf("status")},
		{"proc_self_mem", procSelf("mem")},
		{"proc_self_cwd", func(string) string { return openFacts(openat(unix.AT_FDCWD, "/proc/self/cwd/f", unix.O_RDONLY, 0)) }},
		{"proc_thread_self_cwd", func(string) string {
			return openFacts(openat(unix.AT_FDCWD, "/proc/thread-self/cwd/d/in-d", unix.O_RDONLY, 0))
		}},
		{"proc_self_cwd_dotdot", func(string) string {
			return openFacts(openat(unix.AT_FDCWD, "/proc/self/cwd/d/../f", unix.O_RDONLY, 0))
		}},
		{"proc_self_root", func(dir string) string {
			return openFacts(openat(unix.AT_FDCWD, "/proc/self/root"+dir+"/f", unix.O_RDONLY, 0))
		}},
		{"proc_self_fd_dir", procFDDir("/proc/self/fd/")},
		{"dev_fd_dir", procFDDir("/dev/fd/")},
		{"double_slash", func(string) string { return openFacts(openat(unix.AT_FDCWD, "d//in-d", unix.O_RDONLY, 0)) }},
		{"dot_mid", func(string) string { return openFacts(openat(unix.AT_FDCWD, "./d/./in-d", unix.O_RDONLY, 0)) }},
		{"trailing_slash_dir", open("d/", unix.O_RDONLY, 0)},
		{"trailing_slash_file", open("f/", unix.O_RDONLY, 0)},
		{"trailing_slash_creat", open("nope/", unix.O_WRONLY|unix.O_CREAT, 0o644)},
		// An O_CREAT open whose final name is followed by a slash is EISDIR whatever the name holds (review finding F4's
		// family): the kernel refuses the slash before it looks the name up.
		{"trailing_slash_creat_file", open("f/", unix.O_WRONLY|unix.O_CREAT, 0o644)},
		{"trailing_slash_creat_dir", open("d/", unix.O_RDONLY|unix.O_CREAT, 0o644)},
		{"trailing_slash_excl", open("nope/", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)},
		{"trailing_slash_creat_missing_parent", open("nodir/nope/", unix.O_WRONLY|unix.O_CREAT, 0o644)},
		// O_CREAT on an existing directory (F4): EISDIR, or EEXIST with O_EXCL; and O_CREAT with O_DIRECTORY is EINVAL
		// before any lookup, even where the walk would fail.
		{"creat_rdonly_dir", open("d", unix.O_RDONLY|unix.O_CREAT, 0o644)},
		{"creat_wronly_dir", open("d", unix.O_WRONLY|unix.O_CREAT, 0o644)},
		{"creat_dot", open("d/.", unix.O_RDONLY|unix.O_CREAT, 0o644)},
		{"excl_dot", open("d/.", unix.O_RDONLY|unix.O_CREAT|unix.O_EXCL, 0o644)},
		{"creat_directory_dir", open("d", unix.O_RDONLY|unix.O_CREAT|unix.O_DIRECTORY, 0o644)},
		{"creat_directory_new", open("x-dir-new", unix.O_RDONLY|unix.O_CREAT|unix.O_DIRECTORY, 0o644)},
		{"creat_directory_missing_parent", open("nodir/x", unix.O_RDONLY|unix.O_CREAT|unix.O_DIRECTORY, 0o644)},
		{"tmpfile_rdonly", open("d", unix.O_RDONLY|unix.O_TMPFILE, 0o600)},
		{"tmpfile_creat", open("d", unix.O_RDWR|unix.O_TMPFILE|unix.O_CREAT, 0o600)},
		{"eloop", open("loop", unix.O_RDONLY, 0)},
		{"missing", open("missing", unix.O_RDONLY, 0)},
		{"missing_parent", open("nodir/x", unix.O_RDONLY, 0)},
		{"enotdir", open("f/x", unix.O_RDONLY, 0)},
		{"enametoolong_component", open(strings.Repeat("n", 300), unix.O_RDONLY, 0)},
		{"enametoolong_path", func(dir string) string {
			return openFacts(openat(unix.AT_FDCWD, strings.Repeat("a/", 2100), unix.O_RDONLY, 0))
		}},
		{"efault", func(string) string {
			r, _, e := unix.Syscall6(unix.SYS_OPENAT, cwdArg, 8, uintptr(unix.O_RDONLY), 0, 0, 0)
			if e != 0 {
				return "err=" + unix.ErrnoName(e)
			}
			_ = unix.Close(int(r))
			return "ok"
		}},
		{"umask", func(dir string) string {
			old := unix.Umask(0o077)
			defer unix.Umask(old)
			facts := openFacts(openat(unix.AT_FDCWD, filepath.Join(dir, "u-new"), unix.O_WRONLY|unix.O_CREAT, 0o666))
			st, err := os.Stat(filepath.Join(dir, "u-new"))
			if err != nil {
				return facts + " stat=" + errName(err)
			}
			return facts + " made=" + strconv.FormatUint(uint64(st.Mode().Perm()), 8)
		}},
		{"parallel_creat", func(dir string) string {
			// Eight threads create the same new name with O_CREAT and no O_EXCL: every one must succeed, none with a
			// spurious EEXIST from the create and reopen racing each other.
			var wg sync.WaitGroup
			var mu sync.Mutex
			res := map[string]int{}
			for _, th := range filteredThreads(8) {
				wg.Add(1)
				th <- func() {
					defer wg.Done()
					fd, err := openat(unix.AT_FDCWD, filepath.Join(dir, "p-new"), unix.O_WRONLY|unix.O_CREAT, 0o644)
					k := "ok"
					if err != nil {
						k = errName(err)
					} else {
						_ = unix.Close(fd)
					}
					mu.Lock()
					res[k]++
					mu.Unlock()
				}
			}
			wg.Wait()
			keys := make([]string, 0, len(res))
			for k, v := range res {
				keys = append(keys, k+"="+strconv.Itoa(v))
			}
			sort.Strings(keys)
			return strings.Join(keys, ",")
		}},
		{"devnull", func(string) string { return openFacts(openat(unix.AT_FDCWD, "/dev/null", unix.O_RDONLY, 0)) }},
		{"devzero", func(string) string { return openFacts(openat(unix.AT_FDCWD, "/dev/zero", unix.O_RDONLY, 0)) }},
		{"fifo_nonblock", open("fifo", unix.O_RDONLY|unix.O_NONBLOCK, 0)},
		// D3's checks on the pinned object, never the copied name: a benign name that is a symlink to
		// the gated secret is refused by the gate's score of the pinned object (heldGatedCases), and a write through a
		// symlink to a deny_write target is refused by the floor on the pinned object, as the copied path's walk refuses
		// it. Removing either check let the open through.
		{"symlink_gated", open("link-secret", unix.O_RDONLY, 0)},
		// The same symlink opened as a directory fails the lookup itself, ENOTDIR, before anything opens the secret: the
		// pin's lookup needs a directory as the task's does, and nothing is left for the gate to refuse.
		{"symlink_gated_directory", open("link-secret", unix.O_RDONLY|unix.O_DIRECTORY, 0)},
		{"directory_on_gated_file", open("secret.env", unix.O_RDONLY|unix.O_DIRECTORY, 0)},
		{"denywrite_symlink", func(dir string) string {
			fd, err := openat(unix.AT_FDCWD, dir+"/w-link", unix.O_WRONLY|unix.O_APPEND, 0)
			if err == nil {
				_, _ = unix.Write(fd, []byte("pwned\n"))
			}
			facts := openFacts(fd, err)
			b, _ := os.ReadFile(filepath.Join(dir, ".git", "config"))
			return facts + " after=" + strconv.Quote(string(b))
		}},
		{"proc_self_fd", func(string) string {
			r, w, err := os.Pipe()
			if err != nil {
				return "pipe=" + errName(err)
			}
			defer r.Close() //nolint:errcheck // a test pipe
			defer w.Close() //nolint:errcheck // a test pipe
			facts := openFacts(openat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(int(w.Fd())), unix.O_WRONLY, 0))
			return strings.Replace(facts, "nonblock=true", "nonblock=?", 1)
		}},
		// A procfs file and directory outside the open deputy's tree reached through an O_PATH descriptor: the deputy
		// places such a landing by its directory (landsInDeputyProc, procParent) and must reach it as the kernel does.
		{"proc_file_by_fd", procByFD("/proc/sys/kernel/ostype", unix.O_RDONLY)},
		{"proc_dir_by_fd", procByFD("/proc/sys/kernel", unix.O_RDONLY|unix.O_DIRECTORY)},
	}
}

// procByFD opens name O_PATH, then flags through /proc/self/fd/N: a magic link as the lookup's last step.
func procByFD(name string, flags int) func(string) string {
	return func(string) string {
		fd, err := openat(unix.AT_FDCWD, name, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return "o_path=" + errName(err)
		}
		defer unix.Close(fd) //nolint:errcheck // the O_PATH descriptor this case opened
		return openFacts(openat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), flags, 0))
	}
}

// heldFixture lays out what the differential suite opens, in dir.
func heldFixture(t *testing.T) func(string) {
	return func(dir string) {
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(os.WriteFile(filepath.Join(dir, "f"), []byte("held-content"), 0o644))
		must(os.WriteFile(filepath.Join(dir, "a"), []byte("append"), 0o644))
		must(os.WriteFile(filepath.Join(dir, "t"), []byte("truncate-me"), 0o644))
		must(os.WriteFile(filepath.Join(dir, "secret.env"), []byte("TOKEN=1"), 0o644))
		must(os.Mkdir(filepath.Join(dir, "d"), 0o755))
		must(os.WriteFile(filepath.Join(dir, "d", "in-d"), []byte("inside"), 0o644))
		must(os.Symlink("f", filepath.Join(dir, "link-f")))
		must(os.Symlink("dangling-target", filepath.Join(dir, "dangling")))
		must(os.Symlink("loop", filepath.Join(dir, "loop")))
		must(unix.Mkfifo(filepath.Join(dir, "fifo"), 0o644))
		must(os.Symlink("secret.env", filepath.Join(dir, "link-secret")))
		must(os.Mkdir(filepath.Join(dir, ".git"), 0o755))
		must(os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[core]\n"), 0o644))
		must(os.Symlink(".git/config", filepath.Join(dir, "w-link")))
		// heldMatrixCases' objects, in a directory of their own.
		must(os.Mkdir(filepath.Join(dir, "mx"), 0o755))
		must(os.WriteFile(filepath.Join(dir, "mx", "f"), []byte("matrix"), 0o644))
		must(os.Mkdir(filepath.Join(dir, "mx", "d"), 0o755))
		must(os.WriteFile(filepath.Join(dir, "mx", "d", "in"), []byte("inside"), 0o644))
		must(os.Symlink("f", filepath.Join(dir, "mx", "lf")))
		must(os.Symlink("d", filepath.Join(dir, "mx", "ld")))
		must(os.Symlink("made-by-dang", filepath.Join(dir, "mx", "dang")))
		must(os.Symlink("loop", filepath.Join(dir, "mx", "loop")))
		for _, fl := range heldMatrixFlags {
			must(unix.Mkfifo(filepath.Join(dir, "mx", "fifo-"+fl.name), 0o644))
		}
		// What the task's own permissions refuse: a file it may only read, one it may not open at all, and a directory
		// it may not search or list. Made searchable again before the directory is removed.
		must(os.WriteFile(filepath.Join(dir, "mx", "ro"), []byte("read-only"), 0o444))
		must(os.WriteFile(filepath.Join(dir, "mx", "noperm"), []byte("no-permission"), 0o644))
		must(os.Mkdir(filepath.Join(dir, "mx", "nosearch"), 0o755))
		must(os.WriteFile(filepath.Join(dir, "mx", "nosearch", "in"), []byte("unsearched"), 0o644))
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "mx", "nosearch"), 0o755) })
	}
}

// heldMatrixModes are the modes heldMatrixCases' fixture takes once ownedTree has given it to the agent: chmod after
// the chown, which clears nothing a test needs.
func heldMatrixModes(dir string) {
	for name, mode := range map[string]os.FileMode{"ro": 0o444, "noperm": 0, "nosearch": 0} {
		_ = os.Chmod(filepath.Join(dir, "mx", name), mode)
	}
}

// heldMatrixCases is the differential suite's generated half: every pathname shape of heldMatrixNames opened with
// every flag set of heldMatrixFlags, in that order, O_NONBLOCK added so no FIFO open waits. The kernel's own run and the
// held run make the same opens in the same order on fixtures laid out alike, so a create or a truncation an earlier
// case makes is the same on both sides, and each case must answer alike, errno for errno.
func heldMatrixCases() []heldCase {
	var out []heldCase
	for _, name := range heldMatrixNames {
		for _, fl := range heldMatrixFlags {
			rel, flags, label := name, fl.flags|unix.O_NONBLOCK, "mx:"+name+":"+fl.name
			if name == "fifo" {
				// A FIFO of each case's own: whether an open finds a peer is that one open's answer, never what the
				// copies of an earlier case's descriptor (the deputy's, closed once its reply is sent) still hold.
				rel = "fifo-" + fl.name
			}
			out = append(out, heldCase{label, func(dir string) string {
				return openFacts(openat(unix.AT_FDCWD, dir+"/mx/"+rel, flags, 0o640))
			}})
		}
	}
	return out
}

// heldMatrixNames are the matrix's pathname shapes beneath mx: a file, a directory, a symlink to each, a dangling
// symlink (whose target an O_CREAT open makes), a symlink loop, a FIFO, a missing name and names beneath a missing name
// and a file, trailing slashes on each kind, "." and ".." after a directory and a symlink to one, a "." mid-path, and
// what DAC refuses the task: a read-only file, a file of mode 0, and a directory of mode 0 (heldMatrixModes), its own
// open and names beneath it.
var heldMatrixNames = []string{
	"f", "d", "lf", "ld", "dang", "loop", "fifo", "none", "none/x", "f/x",
	"f/", "d/", "ld/", "lf/", "d/.", "d/..", "ld/.", "./f",
	"ro", "noperm", "nosearch", "nosearch/in", "nosearch/new",
}

// heldMatrixKernel are kernel answers the matrix's fixture is laid out to give, checked on the kernel's own run: DAC's
// refusals of the task (a file of mode 0, a directory it may not search) and the ENOTDIR a final symlink gets from an
// open that needs a directory and does not follow it (which the held path once answered ELOOP).
var heldMatrixKernel = map[string]string{
	"mx:noperm:rdonly":             "err=EACCES",
	"mx:nosearch/in:rdonly":        "err=EACCES",
	"mx:nosearch/new:creat":        "err=EACCES",
	"mx:ro:wronly":                 "err=EACCES",
	"mx:lf:directory_nofollow":     "err=ENOTDIR",
	"mx:ld:tmpfile_nofollow":       "err=ENOTDIR",
	"mx:lf:rdonly_nofollow":        "err=ELOOP",
	"mx:loop:rdonly":               "err=ELOOP",
	"mx:f/:rdonly":                 "err=ENOTDIR",
	"mx:fifo:wronly":               "err=ENXIO",
	"mx:d:creat":                   "err=EISDIR",
	"mx:noperm:creat_excl":         "err=EEXIST",
	"mx:nosearch:directory":        "err=EACCES",
	"mx:nosearch:tmpfile":          "err=EACCES",
	"mx:none:rdonly":               "err=ENOENT",
	"mx:f/x:creat":                 "err=ENOTDIR",
	"mx:dang:creat_nofollow":       "err=ELOOP",
	"mx:lf:append_nofollow":        "err=ELOOP",
	"mx:./f:tmpfile":               "err=ENOTDIR",
	"mx:noperm:directory_nofollow": "err=ENOTDIR",
}

// heldMatrixFlags are the matrix's flag sets: each access mode, O_NOFOLLOW, O_DIRECTORY and both together, the create
// forms with and without O_EXCL and O_NOFOLLOW, truncation, append, and O_TMPFILE with and without O_NOFOLLOW.
var heldMatrixFlags = []struct {
	name  string
	flags int
}{
	{"rdonly", unix.O_RDONLY},
	{"wronly", unix.O_WRONLY},
	{"rdwr", unix.O_RDWR},
	{"rdonly_nofollow", unix.O_RDONLY | unix.O_NOFOLLOW},
	{"directory", unix.O_RDONLY | unix.O_DIRECTORY},
	{"directory_nofollow", unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW},
	{"creat", unix.O_WRONLY | unix.O_CREAT},
	{"creat_excl", unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL},
	{"creat_nofollow", unix.O_WRONLY | unix.O_CREAT | unix.O_NOFOLLOW},
	{"rdwr_trunc", unix.O_RDWR | unix.O_TRUNC},
	{"append_nofollow", unix.O_WRONLY | unix.O_APPEND | unix.O_NOFOLLOW},
	{"creat_trunc", unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC},
	{"tmpfile", unix.O_RDWR | unix.O_TMPFILE},
	{"tmpfile_nofollow", unix.O_RDWR | unix.O_TMPFILE | unix.O_NOFOLLOW},
}

// heldDenyWrite is the held harness's deny_write target, its worktree's .git/config, built in and unenforced by the
// kernel at tier landlock, as a run compiles it: the loop refuses it (supervisor R15c), on the copied path's walk and,
// held, on the pinned object.
func heldDenyWrite(dir string) []agent.FSRule {
	p := filepath.Join(dir, ".git", "config")
	return []agent.FSRule{{Path: p, Kind: agent.FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: p}}
}

// heldChecks runs the differential cases the parent named (all by default) from the harness directory.
func heldChecks() []checkResult {
	dir := os.Getenv(helperDir)
	if err := unix.Chdir(dir); err != nil {
		return []checkResult{{Name: "chdir", Err: err.Error()}}
	}
	want := splitComma(os.Getenv(helperHeldOps))
	var out []checkResult
	cases := append(heldCases(), heldMatrixCases()...)
	if want[0] != "" {
		cases = append(cases, heldMountCases()...)  // named only where their fixture was laid out (heldMountFixture)
		cases = append(cases, deputyProcCases()...) // named only where a deputy serves the run (testDeputyPid)
	}
	for _, c := range cases {
		if want[0] != "" && !slices.Contains(want, c.name) {
			continue
		}
		out = append(out, checkResult{Name: c.name, Out: c.run(dir)})
	}
	return out
}

// heldGate is the gate the held harness runs under: reads of *.env refused, writes outside the worktree refused,
// so both fs kinds escalate, under gate.completion: held, so every open is held when a deputy serves the loop (the
// contract a run starts its deputy for; ADR 0041 Stage B). A harness with no deputy is that contract's degrade.
func heldGate(t testing.TB) *gate.Policy {
	t.Helper()
	g, err := gate.New([]gate.Rule{
		{Predicate: gate.ReadMatches, Argument: "*.env", Score: 90},
		{Predicate: gate.WriteOutsideWorktree, Score: 90},
	}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	return g.WithHeldCompletion()
}

// heldGatedCases are the differential cases the held run's gate decides, with the answer it gives: a write-open of a
// pipe through /proc/self/fd is a nameless object, which fs.write outside worktree scores as outside (as the copied
// spelling was scored before Stage B).
var heldGatedCases = map[string]string{"proc_self_fd": "err=EACCES", "symlink_gated": "err=EACCES",
	// The copied name's refusal is final (D3 step 1), before the lookup that would fail ENOTDIR, as under the copied
	// completion.
	"directory_on_gated_file": "err=EACCES"}

// heldFailClosed are the differential cases where a held open is refused what the task's own open gets, ADR 0041
// D4's documented fail-closed divergences, with the answer the held open gives and when: the task's open of its own
// /proc/<pid>/mem, which procfs checks at open for PTRACE_MODE_ATTACH against the opener, and which Yama refuses the
// deputy under kernel.yama.ptrace_scope 1 or more (the deputy is no ancestor of the task; a thread group is never
// asked about itself).
func heldFailClosed() map[string]string {
	out := map[string]string{}
	if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil && strings.TrimSpace(string(b)) != "0" {
		out["proc_self_mem"] = "err=EACCES"
	}
	return out
}

// TestHeldOpenDifferential is ADR 0041 Step 8's differential suite on a real kernel, filter, loop and deputy: every
// case is opened once with no gate, the kernel's own open, and once under a read and a write gate that escalate,
// where the deputy completes it, and the two outcomes must be the same, errno for errno and fact for fact, save the
// cases the gate itself decides (heldGatedCases). No held open may be refused held-*: each is the kernel's answer.
func TestHeldOpenDifferential(t *testing.T) {
	as, own := heldAgent(t)
	fixture := func(dir string) {
		ownedTree(t, own, heldFixture(t))(dir)
		heldMatrixModes(dir)
	}
	plain := startHarnessWith(t, harnessOpts{as: as, mode: modeHeld, prepare: fixture, filterGate: "rw"})
	held := startHarnessWith(t, harnessOpts{as: as, mode: modeHeld, prepare: fixture, filterGate: "rw", deputy: true, gate: heldGate(t)})
	plain.stop(t)
	m := held.stop(t)
	got := map[string]string{}
	for _, c := range held.report.Checks {
		got[c.Name] = c.Out
	}
	failClosed := heldFailClosed()
	for _, c := range plain.report.Checks {
		h, ok := got[c.Name]
		if !ok {
			t.Errorf("%s: the held run did not report it", c.Name)
			continue
		}
		if want, gated := heldGatedCases[c.Name]; gated {
			if h != want {
				t.Errorf("%s: held %s, want the gate's %s", c.Name, h, want)
			}
			continue
		}
		if want, closed := failClosed[c.Name]; closed {
			if h != want {
				t.Errorf("%s: held %s, want D4's fail-closed %s (the kernel's own: %s)", c.Name, h, want, c.Out)
			}
			continue
		}
		if h != c.Out {
			t.Errorf("%s:\n kernel: %s\n held:   %s", c.Name, c.Out, h)
		}
		// The matrix's fixture took effect: the kernel's own answers that its shapes exist for.
		if want, ok := heldMatrixKernel[c.Name]; ok && c.Out != want {
			t.Errorf("%s: the kernel answered %s, the matrix's fixture is laid out for %s", c.Name, c.Out, want)
		}
	}
	_ = m
	t.Logf("%d shapes opened by the kernel and held (%d of them the generated matrix's)", len(plain.report.Checks),
		len(heldMatrixNames)*len(heldMatrixFlags))
	for _, ev := range held.sink.all() {
		if ev.Kind == record.KindFS && strings.Contains(ev.Rule, "held-") || t.Failed() && ev.Verdict == record.VerdictRefused {
			t.Errorf("held refusal line: rule %q reason %q on %s", ev.Rule, ev.Reason, ev.Payload)
		}
	}
}

// testDeputyPid is the open deputy's pid, set by spawnTestDeputy in the target process; the deputy-proc differential
// cases read it (deputyProcCases). It is the target's view; the loop and the deputy share its pid namespace.
var testDeputyPid int

// deputyProcCases are the differential cases over the open deputy's own thread group's /proc tree. The deputy runs
// the walk and the reopen itself, and a process always passes ptrace_may_access against
// itself, so without the guard it pins and delivers its own ptrace-gated entries (mem, environ, fd/N, cwd, exe, maps)
// that the agent's own open is refused, the deputy being undumpable (PR_SET_DUMPABLE 0). Each is opened held and must
// be refused the agent's own errno, EACCES. They run only in TestHeldOpenCannotReachTheDeputysOwnProc, where a deputy
// serves the run and names them (heldChecks); the kernel-vs-held suite never runs them, since the deputy exists only
// in its held run.
func deputyProcCases() []heldCase {
	open := func(name string, flags int) func(string) string {
		return func(string) string {
			return openFacts(openat(unix.AT_FDCWD, "/proc/"+strconv.Itoa(testDeputyPid)+"/"+name, flags, 0))
		}
	}
	// The same entries reached through a descriptor: the target holds an O_PATH descriptor of
	// one, an O_PATH open being continued and the kernel letting any process look these names up, and a held open of
	// /proc/self/fd/N lands on it by the magic link alone.
	byFD := func(name string, flags int) func(string) string {
		return func(dir string) string { return procByFD("/proc/"+strconv.Itoa(testDeputyPid)+"/"+name, flags)(dir) }
	}
	// The same entries through the directory of one of the deputy's other threads, /proc/<tid> at the procfs root
	// beside /proc/<pid>: the deputy is a Go program with several threads, and their
	// entries ask ptrace_may_access about that thread, which the deputy always passes.
	thread := func(name string, flags int, viaFD bool) func(string) string {
		return func(dir string) string {
			tid := deputyThread()
			if tid == 0 {
				return "no thread of the deputy other than its leader"
			}
			p := "/proc/" + strconv.Itoa(tid) + "/" + strings.ReplaceAll(name, "<tid>", strconv.Itoa(tid))
			if viaFD {
				return procByFD(p, flags)(dir)
			}
			return openFacts(openat(unix.AT_FDCWD, p, flags, 0))
		}
	}
	return []heldCase{
		{"deputy_thread_maps", thread("maps", unix.O_RDONLY, false)},
		{"deputy_thread_exe", thread("exe", unix.O_RDONLY, false)},
		{"deputy_thread_fd_dir", thread("fd", unix.O_RDONLY|unix.O_DIRECTORY, false)},
		{"deputy_thread_environ", thread("environ", unix.O_RDONLY, false)},
		{"deputy_thread_task_maps", thread("task/<tid>/maps", unix.O_RDONLY, false)},
		{"deputy_thread_maps_by_fd", thread("maps", unix.O_RDONLY, true)},
		{"deputy_thread_fd_dir_by_fd", thread("fd", unix.O_RDONLY|unix.O_DIRECTORY, true)},
		{"deputy_thread_dir", thread("", unix.O_RDONLY|unix.O_DIRECTORY, false)},
		{"deputy_proc_environ_by_fd", byFD("environ", unix.O_RDONLY)},
		{"deputy_proc_maps_by_fd", byFD("maps", unix.O_RDONLY)},
		{"deputy_proc_fd_dir_by_fd", byFD("fd", unix.O_RDONLY|unix.O_DIRECTORY)},
		{"deputy_proc_mem", open("mem", unix.O_RDONLY)},
		{"deputy_proc_environ", open("environ", unix.O_RDONLY)},
		{"deputy_proc_auxv", open("auxv", unix.O_RDONLY)},
		{"deputy_proc_maps", open("maps", unix.O_RDONLY)},
		{"deputy_proc_fd0", open("fd/0", unix.O_RDONLY)},
		{"deputy_proc_cwd", open("cwd", unix.O_RDONLY|unix.O_DIRECTORY)},
		{"deputy_proc_exe", open("exe", unix.O_RDONLY)},
	}
}

// deputyThread is a thread of the open deputy other than its leader, found by a stat of /proc/<deputy>/task/<n>: a
// stat is never held, and procfs looks a thread id up in a task directory for any process. 0 when none is found.
func deputyThread() int {
	for n := testDeputyPid + 1; n < testDeputyPid+1<<16; n++ {
		var st unix.Stat_t
		if unix.Stat("/proc/"+strconv.Itoa(testDeputyPid)+"/task/"+strconv.Itoa(n), &st) == nil {
			return n
		}
	}
	return 0
}

// TestHeldOpenCannotReachTheDeputysOwnProc holds a held open of the open deputy's own /proc entries to the agent's own
// errno. Under a read gate every read open is held and goes through the deputy, a process of the run; a held open of
// the deputy's own /proc/<pid>/{mem,environ,auxv,maps,fd/N,cwd,exe} would be made by the deputy against itself, which
// always passes ptrace_may_access, so without the guard the undumpable deputy's own ptrace-gated entries are delivered
// where the agent's own open is refused EACCES. Each must be refused EACCES, never delivered.
// No held-* line: the refusal is the kernel's own errno (pinHeld.heldAnswer).
func TestHeldOpenCannotReachTheDeputysOwnProc(t *testing.T) {
	as, _ := heldAgent(t)
	names := []string{"deputy_proc_mem", "deputy_proc_environ", "deputy_proc_auxv", "deputy_proc_maps",
		"deputy_proc_fd0", "deputy_proc_cwd", "deputy_proc_exe", "deputy_proc_environ_by_fd", "deputy_proc_maps_by_fd",
		"deputy_proc_fd_dir_by_fd", "deputy_thread_maps", "deputy_thread_exe", "deputy_thread_fd_dir", "deputy_thread_environ",
		"deputy_thread_task_maps", "deputy_thread_maps_by_fd", "deputy_thread_fd_dir_by_fd"}
	// reached are the deputy's own directories that are (A), as the agent's own open of a listable directory is: a
	// thread's /proc/<tid> itself, which the deputy's filtered walk places in its thread group and lets through, so the
	// refusals above are the guard's answer and not every procfs lookup failing in the deputy.
	reached := []string{"deputy_thread_dir"}
	h := startHarnessWith(t, harnessOpts{
		as: as, mode: modeHeld, filterGate: "rw", deputy: true, gate: heldGate(t),
		env: []string{helperHeldOps + "=" + strings.Join(append(names, reached...), ",")},
	})
	defer h.stop(t)
	for _, name := range names {
		c := h.check(t, name)
		if c.Out != "err=EACCES" {
			t.Errorf("%s: held open of the deputy's own /proc entry = %q, want err=EACCES (never delivered)", name, c.Out)
		}
	}
	for _, name := range reached {
		if c := h.check(t, name); !strings.HasPrefix(c.Out, "type=40000 ") {
			t.Errorf("%s: held open of the deputy thread's own /proc directory = %q, want it delivered", name, c.Out)
		}
	}
	// The refusal is the kernel's own answer, not a tego held-* line (supervisor R7a): no held-unavailable or
	// held-unsupported for these.
	for _, ev := range h.sink.all() {
		if ev.Kind == record.KindFS && strings.Contains(ev.Rule, "held-") {
			t.Errorf("deputy-proc refusal carried a held-* line: rule %q reason %q on %s", ev.Rule, ev.Reason, ev.Payload)
		}
	}
}

// heldMountCases are the differential cases over the objects only root can lay out (heldMountFixture): ADR 0017's
// bind-mount and overlayfs spaces, a hard link, a nosymfollow mount, and fs.protected_symlinks. Each is opened by the
// kernel for the task and held, and the two must answer alike.
func heldMountCases() []heldCase {
	open := func(rel string, flags int, mode uint32) func(string) string {
		return func(dir string) string { return openFacts(openat(unix.AT_FDCWD, dir+"/"+rel, flags, mode)) }
	}
	appendTo := func(rel, after string) func(string) string {
		return func(dir string) string {
			fd, err := openat(unix.AT_FDCWD, dir+"/"+rel, unix.O_WRONLY|unix.O_APPEND, 0)
			if err == nil {
				_, _ = unix.Write(fd, []byte("+"))
			}
			facts := openFacts(fd, err)
			b, _ := os.ReadFile(dir + "/" + after)
			return facts + " after=" + strconv.Quote(string(b))
		}
	}
	created := func(rel, where string) func(string) string {
		return func(dir string) string {
			facts := openFacts(openat(unix.AT_FDCWD, dir+"/"+rel, unix.O_WRONLY|unix.O_CREAT, 0o640))
			_, err := os.Lstat(dir + "/" + where)
			return facts + " made=" + strconv.FormatBool(err == nil)
		}
	}
	return []heldCase{
		{"bind_read", open("bind/bf", unix.O_RDONLY, 0)},
		{"bind_append", appendTo("bind/ba", "bind-src/ba")},
		{"bind_create", created("bind/bnew", "bind-src/bnew")},
		{"overlay_read_lower", open("ovl/lf", unix.O_RDONLY, 0)},
		{"overlay_append_lower", appendTo("ovl/la", "upper/la")},
		{"overlay_trunc_lower", func(dir string) string {
			facts := openFacts(openat(unix.AT_FDCWD, dir+"/ovl/lt", unix.O_WRONLY|unix.O_TRUNC, 0))
			st, err := os.Stat(dir + "/ovl/lt")
			if err != nil {
				return facts + " stat=" + errName(err)
			}
			return facts + " size_after=" + strconv.FormatInt(st.Size(), 10)
		}},
		{"overlay_create", created("ovl/onew", "upper/onew")},
		{"overlay_dir", open("ovl/ld", unix.O_RDONLY|unix.O_DIRECTORY, 0)},
		{"overlay_symlink", open("ovl/llink", unix.O_RDONLY, 0)},
		{"hardlink_read", open("hl", unix.O_RDONLY, 0)},
		{"nosymfollow_trailing", open("nsf/link", unix.O_RDONLY, 0)},
		{"nosymfollow_mid", open("nsf/dlink/in-d", unix.O_RDONLY, 0)},
		{"nosymfollow_creat", created("nsf/dangle", "nsf/dangle-target")},
		{"protected_symlink_foreign", open("sticky/foreign", unix.O_RDONLY, 0)},
		{"protected_symlink_own", open("sticky/own", unix.O_RDONLY, 0)},
		{"protected_symlink_mid", open("sticky/foreign-d/in-d", unix.O_RDONLY, 0)},
		// fs.protected_regular and fs.protected_fifos: an O_CREAT open of another's existing file or FIFO in a sticky
		// world-writable directory is refused; the same open without O_CREAT is not. The deputy reopens what it pinned
		// through /proc/self/fd, whose directory is no sticky one, so this loop makes the kernel's check
		// (heldStickyCreate).
		{"protected_regular_creat", open("sticky/ffile", unix.O_WRONLY|unix.O_CREAT, 0o644)},
		{"protected_regular_plain", open("sticky/ffile", unix.O_WRONLY, 0)},
		{"protected_regular_own", open("sticky/ofile", unix.O_WRONLY|unix.O_CREAT, 0o644)},
		{"protected_fifo_creat", open("sticky/ffifo", unix.O_RDONLY|unix.O_CREAT|unix.O_NONBLOCK, 0o644)},
		{"protected_fifo_plain", open("sticky/ffifo", unix.O_RDONLY|unix.O_NONBLOCK, 0)},
	}
}

// heldMountFixture is heldFixture plus, as root, what heldMountCases opens: a bind mount of bind-src at bind; an
// overlay of lower (a file to read, one to append to, one to truncate, a directory and a symlink) with upper and work
// at ovl; a hard link hl of f; a tmpfs mounted nosymfollow at nsf with a link to f, one to d and a dangling one; and a
// sticky world-writable sticky owned by root with a link to f owned by another uid (foreign, and foreign-d to d),
// which fs.protected_symlinks refuses to follow, and one owned by the agent. Its mounts are detached at the test's end.
func heldMountFixture(t *testing.T, own func(...string), agent *syscall.Credential, overlay bool) func(string) {
	base := ownedTree(t, own, heldFixture(t))
	return func(dir string) {
		base(dir)
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		file := func(p, body string) {
			must(os.WriteFile(p, []byte(body), 0o644))
			own(p)
		}
		mkdir := func(p string, mode os.FileMode) {
			must(os.Mkdir(p, mode))
			must(os.Chmod(p, mode))
		}
		mount := func(src, at, fstype string, flags uintptr, data string) {
			must(unix.Mount(src, at, fstype, flags, data))
			t.Cleanup(func() { _ = unix.Unmount(at, unix.MNT_DETACH) })
		}
		mkdir(dir+"/bind-src", 0o755)
		own(dir + "/bind-src")
		file(dir+"/bind-src/bf", "bind-read")
		file(dir+"/bind-src/ba", "bind-append")
		mkdir(dir+"/bind", 0o755)
		mount(dir+"/bind-src", dir+"/bind", "", unix.MS_BIND, "")
		for _, d := range []string{"lower", "upper", "work", "ovl"} {
			mkdir(dir+"/"+d, 0o755)
		}
		own(dir+"/lower", dir+"/upper", dir+"/ovl")
		file(dir+"/lower/lf", "lower-read")
		file(dir+"/lower/la", "lower-append")
		file(dir+"/lower/lt", "lower-truncate")
		mkdir(dir+"/lower/ld", 0o755)
		own(dir + "/lower/ld")
		must(os.Symlink("lf", dir+"/lower/llink"))
		own(dir + "/lower/llink")
		if overlay {
			mount("overlay", dir+"/ovl", "overlay", 0, "lowerdir="+dir+"/lower,upperdir="+dir+"/upper,workdir="+dir+"/work")
		}
		must(os.Link(dir+"/f", dir+"/hl"))
		mkdir(dir+"/nsf", 0o755)
		mount("tmpfs", dir+"/nsf", "tmpfs", unix.MS_NOSYMFOLLOW, "mode=0755")
		must(os.Symlink(dir+"/f", dir+"/nsf/link"))
		must(os.Symlink(dir+"/d", dir+"/nsf/dlink"))
		must(os.Symlink(dir+"/nsf-dangle-target", dir+"/nsf/dangle"))
		own(dir+"/nsf", dir+"/nsf/link", dir+"/nsf/dlink", dir+"/nsf/dangle")
		mkdir(dir+"/sticky", 0o777|os.ModeSticky)
		must(os.Chown(dir+"/sticky", 0, 0))
		for name, target := range map[string]string{"foreign": dir + "/f", "foreign-d": dir + "/d", "own": dir + "/f"} {
			must(os.Symlink(target, dir+"/sticky/"+name))
			uid := 65534
			if name == "own" {
				uid = int(agent.Uid)
			}
			must(os.Lchown(dir+"/sticky/"+name, uid, uid))
		}
		// Another's regular file and FIFO, which DAC lets the agent open (mode 0666), and one of the agent's own.
		for name, uid := range map[string]int{"ffile": 65534, "ofile": int(agent.Uid)} {
			must(os.WriteFile(dir+"/sticky/"+name, []byte("sticky"), 0o666))
			must(os.Chmod(dir+"/sticky/"+name, 0o666))
			must(os.Chown(dir+"/sticky/"+name, uid, uid))
		}
		must(unix.Mkfifo(dir+"/sticky/ffifo", 0o666))
		must(os.Chmod(dir+"/sticky/ffifo", 0o666))
		must(os.Chown(dir+"/sticky/ffifo", 65534, 65534))
	}
}

// TestHeldOpenDifferentialAcrossMounts is the differential suite over ADR 0017's bind-mount and overlayfs spaces, a
// hard link, and the two refusals the kernel makes of following a symlink, which the deputy's walk had to learn
// (followFacts): a trailing link fs.protected_symlinks refuses is EACCES, and any link on a nosymfollow mount ELOOP. Root
// only (mounts and a link of another owner); the target and its deputy run as the invoking user, as a root run drops
// its agent. Each case's held open must give the kernel's own answer.
func TestHeldOpenDifferentialAcrossMounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: bind, overlay and nosymfollow mounts, and a symlink of another owner")
	}
	as, own := heldAgent(t)
	old, err := os.ReadFile("/proc/sys/fs/protected_symlinks")
	if err != nil {
		t.Skipf("no fs.protected_symlinks: %v", err)
	}
	if err := os.WriteFile("/proc/sys/fs/protected_symlinks", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile("/proc/sys/fs/protected_symlinks", old, 0o644) })
	for _, sysctl := range []string{"/proc/sys/fs/protected_regular", "/proc/sys/fs/protected_fifos"} {
		prev, err := os.ReadFile(sysctl)
		if err != nil {
			t.Skipf("no %s: %v", sysctl, err)
		}
		if err := os.WriteFile(sysctl, []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(sysctl, prev, 0o644) })
	}
	// The overlay cases need a kernel that mounts overlayfs: a matrix row's guest loads no module (VM_MODULES=""), so
	// on such a row they are the overlay subtest's listed skip (test/vm/root-skips.txt), and every other case runs.
	overlay := overlayMounts(t)
	var names, overlayNames []string
	for _, c := range heldMountCases() {
		switch {
		case !strings.HasPrefix(c.name, "overlay_"):
			names = append(names, c.name)
		case overlay:
			overlayNames = append(overlayNames, c.name)
		}
	}
	ops := []string{helperHeldOps + "=" + strings.Join(append(slices.Clone(names), overlayNames...), ",")}
	plain := startHarnessWith(t, harnessOpts{as: as, mode: modeHeld, env: ops, prepare: heldMountFixture(t, own, as, overlay), filterGate: "rw"})
	held := startHarnessWith(t, harnessOpts{as: as, mode: modeHeld, env: ops, prepare: heldMountFixture(t, own, as, overlay), filterGate: "rw", deputy: true, gate: heldGate(t)})
	plain.stop(t)
	held.stop(t)
	got := map[string]string{}
	for _, c := range held.report.Checks {
		got[c.Name] = c.Out
	}
	kernel := map[string]string{}
	for _, c := range plain.report.Checks {
		kernel[c.Name] = c.Out
	}
	compare := func(t *testing.T, names []string) {
		for _, name := range names {
			k, h := kernel[name], got[name]
			if k == "" || h == "" {
				t.Errorf("%s: kernel %q held %q: a run did not report it", name, k, h)
				continue
			}
			if h != k {
				t.Errorf("%s:\n kernel: %s\n held:   %s", name, k, h)
			}
			t.Logf("%s: %s", name, k)
		}
	}
	compare(t, names)
	t.Run("overlay", func(t *testing.T) {
		if !overlay {
			t.Skip("this kernel mounts no overlayfs (ENODEV; a matrix row's guest loads no module): the bind, hard link, nosymfollow and protected cases ran")
		}
		compare(t, overlayNames)
	})
	// The kernel's own answers are the cases' point: a link fs.protected_symlinks refuses, and one on a nosymfollow
	// mount, are refused, so the held run met the refusals it was to match.
	for name, want := range map[string]string{"protected_symlink_foreign": "err=EACCES", "nosymfollow_trailing": "err=ELOOP",
		"nosymfollow_mid": "err=ELOOP", "protected_regular_creat": "err=EACCES", "protected_fifo_creat": "err=EACCES"} {
		if kernel[name] != want {
			t.Errorf("%s: the kernel answered %q, want %s: the fixture does not test the refusal", name, kernel[name], want)
		}
	}
	for _, ev := range held.sink.all() {
		if ev.Kind == record.KindFS && strings.Contains(ev.Rule, "held-") {
			t.Errorf("held refusal line: rule %q reason %q on %s", ev.Rule, ev.Reason, ev.Payload)
		}
	}
}

// overlayMounts reports whether this kernel mounts an overlay, a module it loads on demand included, by mounting one
// in a scratch directory: ENODEV is a kernel with no overlayfs; any other failure fails the test.
func overlayMounts(t *testing.T) bool {
	t.Helper()
	d := t.TempDir()
	for _, s := range []string{"l", "u", "w", "m"} {
		if err := os.Mkdir(filepath.Join(d, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	err := unix.Mount("overlay", filepath.Join(d, "m"), "overlay", 0, "lowerdir="+d+"/l,upperdir="+d+"/u,workdir="+d+"/w")
	switch {
	case err == nil:
		_ = unix.Unmount(filepath.Join(d, "m"), unix.MNT_DETACH)
		return true
	case errors.Is(err, unix.ENODEV):
		return false
	}
	t.Fatalf("overlay probe mount: %v", err)
	return false
}

// heldRaceChecks races a sibling thread over the name of each open between the gated secret.env and, in turn, a
// regular file, a directory, a symlink to /dev/null and a missing name (ADR 0041 Step 8, finding supervisor-2's open
// half). N is how many opens returned a descriptor of the secret's inode: a bypass.
func heldRaceChecks() []checkResult {
	dir := os.Getenv(helperDir)
	if err := unix.Chdir(dir); err != nil {
		return []checkResult{{Name: "chdir", Err: err.Error()}}
	}
	var secret unix.Stat_t
	if err := unix.Stat("secret.env", &secret); err != nil {
		return []checkResult{{Name: "stat", Err: err.Error()}}
	}
	gated := nameWord("s.env")
	var out []checkResult
	for _, benign := range []string{"f", "d", "n", "m"} {
		buf := make([]uint64, 2)
		addr := uintptr(unsafe.Pointer(&buf[0]))
		states := []uint64{nameWord(benign), gated}
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			for i := 0; !stop.Load(); i++ {
				atomic.StoreUint64(&buf[0], states[i%2])
			}
		}()
		counts := map[string]int{}
		bypass := 0
		for range heldRaceAttempts {
			r, _, e := unix.Syscall6(unix.SYS_OPENAT, cwdArg, addr, uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
			if e != 0 {
				counts[unix.ErrnoName(e)]++
				continue
			}
			counts["ok"]++
			var st unix.Stat_t
			if unix.Fstat(int(r), &st) == nil && st.Dev == secret.Dev && st.Ino == secret.Ino {
				bypass++
			}
			_ = unix.Close(int(r))
		}
		stop.Store(true)
		<-done
		runtime.KeepAlive(buf)
		out = append(out, checkResult{Name: "race_" + benign, N: bypass, Out: countsText(counts)})
	}
	return out
}

// nameWord is a name of at most seven bytes with its NUL as one aligned 8-byte word, so each store of a racing
// thread is a whole name.
func nameWord(s string) uint64 {
	var b [8]byte
	copy(b[:], s)
	return *(*uint64)(unsafe.Pointer(&b[0]))
}

// countsText is a race's outcome counts as sorted name=count pairs.
func countsText(counts map[string]int) string {
	parts := make([]string, 0, len(counts))
	for k, v := range counts {
		parts = append(parts, k+"="+strconv.Itoa(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// cwdArg is AT_FDCWD as a raw syscall argument.
var cwdArg = func() uintptr { fd := unix.AT_FDCWD; return uintptr(fd) }()

// heldRaceAttempts is how many opens each benign name races. Before Stage B about one in five continued opens
// reached the gated file; a fixed loop that lets none through is the race closed.
const heldRaceAttempts = 800

// heldRaceFixture is the race's directory: the gated secret, and the four benign names (a file, a directory, a
// symlink to /dev/null; m is missing).
func heldRaceFixture(t *testing.T) func(string) {
	return func(dir string) {
		for _, err := range []error{
			os.WriteFile(filepath.Join(dir, "s.env"), []byte("TOKEN=1"), 0o644),
			os.WriteFile(filepath.Join(dir, "secret.env"), nil, 0o644),
			os.WriteFile(filepath.Join(dir, "f"), []byte("benign"), 0o644),
			os.Mkdir(filepath.Join(dir, "d"), 0o755),
			os.Symlink("/dev/null", filepath.Join(dir, "n")),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
		// secret.env names the gated inode the target compares against: a hard link of s.env.
		_ = os.Remove(filepath.Join(dir, "secret.env"))
		if err := os.Link(filepath.Join(dir, "s.env"), filepath.Join(dir, "secret.env")); err != nil {
			t.Fatal(err)
		}
	}
}

// TestGateFSOpenRaceIsHeldAndRaceFree is ADR 0041 Step 8's race test: a sibling flips the name of each read-open
// between a gated *.env and each of a benign regular file, a directory, /dev/null and a missing name. Without a
// deputy (the best-effort cell, recorded first as the pre-fix count) some opens the gate scored on the benign copy
// were continued and the kernel opened the secret; with the deputy none is, since the descriptor delivered is the
// inode the gate scored.
func TestGateFSOpenRaceIsHeldAndRaceFree(t *testing.T) {
	as, own := heldAgent(t)
	before := startHarnessWith(t, harnessOpts{as: as, mode: modeHeldRace, prepare: ownedTree(t, own, heldRaceFixture(t)), filterGate: "r", gate: heldGate(t)})
	before.stop(t)
	pre := 0
	for _, c := range before.report.Checks {
		pre += c.N
		t.Logf("without the deputy, %s: %d of %d reached the secret (%s)", c.Name, c.N, heldRaceAttempts, c.Out)
	}
	after := startHarnessWith(t, harnessOpts{as: as, mode: modeHeldRace, prepare: ownedTree(t, own, heldRaceFixture(t)), filterGate: "r", gate: heldGate(t), deputy: true})
	after.stop(t)
	for _, c := range after.report.Checks {
		t.Logf("held, %s: %d of %d reached the secret (%s)", c.Name, c.N, heldRaceAttempts, c.Out)
		if c.N != 0 {
			t.Errorf("%s: %d held opens delivered the gated secret; want none", c.Name, c.N)
		}
		if !strings.Contains(c.Out, "EACCES=") {
			t.Errorf("%s: no open met the gate's refusal (%s); the race did not run", c.Name, c.Out)
		}
		if c.Name != "race_m" && !strings.Contains(c.Out, "ok=") {
			t.Errorf("%s: no benign open succeeded (%s): every open refused is no race closed", c.Name, c.Out)
		}
	}
	t.Logf("pre-fix count (no deputy): %d bypasses over %d opens", pre, 4*heldRaceAttempts)
}

// heldBenchLoop is the benchmark's target: n read-opens and closes of one file on this thread, each timed, then
// heldParallel opens over four threads at once, timed as a whole.
func heldBenchLoop() []checkResult {
	n, err := strconv.Atoi(os.Getenv(helperLoops))
	if err != nil || n <= 0 {
		return []checkResult{{Name: "loops", Err: "no loops"}}
	}
	path := filepath.Join(os.Getenv(helperDir), "f")
	p, _ := unix.BytePtrFromString(path)
	lat := make([]int64, n)
	fails := 0
	start := time.Now()
	for i := 0; i < n; i++ {
		t0 := time.Now()
		r, _, e := unix.Syscall6(unix.SYS_OPENAT, cwdArg, uintptr(unsafe.Pointer(p)), uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
		lat[i] = time.Since(t0).Nanoseconds()
		if e != 0 {
			fails++
			continue
		}
		_ = unix.Close(int(r))
	}
	total := time.Since(start).Nanoseconds()
	slices.Sort(lat)
	out := []checkResult{
		{Name: "p50", N: int(lat[n/2])},
		{Name: "p99", N: int(lat[n*99/100])},
		{Name: "total", N: int(total)},
		{Name: "fails", N: fails},
	}
	if os.Getenv(helperHeldOps) == "parallel" {
		var wg sync.WaitGroup
		var pfails atomic.Int64
		nt := 4
		if v, err := strconv.Atoi(os.Getenv(helperHeldThreads)); err == nil && v > 0 {
			nt = v
		}
		threads := filteredThreads(nt)
		pstart := time.Now()
		for _, th := range threads {
			wg.Add(1)
			th <- func() {
				defer wg.Done()
				for i := 0; i < heldParallel/nt; i++ {
					r, _, e := unix.Syscall6(unix.SYS_OPENAT, cwdArg, uintptr(unsafe.Pointer(p)), uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
					if e != 0 {
						pfails.Add(1)
						continue
					}
					_ = unix.Close(int(r))
				}
			}
		}
		wg.Wait()
		out = append(out, checkResult{Name: "parallel", N: int(time.Since(pstart).Nanoseconds())}, checkResult{Name: "parallel_fails", N: int(pfails.Load())})
	}
	runtime.KeepAlive(p)
	return out
}

// heldParallel is the ADR's throughput figure: 30k held opens across the default four workers.
const heldParallel = 30000

// benchRun is one benchmark configuration's figures, from the target and from this process.
type benchRun struct {
	p50, p99, total, parallel time.Duration
	ops                       int
	mallocsPerOp              float64
	procReadsPerOp            float64
	threadsGrown              int
}

// heldBenchAt is where a benchmark's loop runs: the tier landlock path as the caller (a zero value), or a root tier's
// with the target and its deputy dropped to an agent's credentials (BenchmarkHeldOpenRootTier).
type heldBenchAt struct {
	tier backend.Tier
	as   *syscall.Credential
	// reads holds the run's reads (fs.reads: held, ADR 0069) with no gate, in place of the read gate.
	reads bool
}

func runHeldBench(b *testing.B, at heldBenchAt, deputyOn bool, n int, parallel bool) benchRun {
	b.Helper()
	ops := ""
	if parallel {
		ops = "parallel"
	}
	var ms0, ms1 runtime.MemStats
	var reads0 int64
	threads0 := 0
	opts := harnessOpts{
		tier: at.tier, as: at.as,
		loops: n, mode: modeBenchHeld, filterGate: "r", gate: heldGate(b), deputy: deputyOn,
		env:     []string{helperHeldOps + "=" + ops},
		prepare: func(dir string) { _ = os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644) },
		acked: func() {
			runtime.GC()
			runtime.ReadMemStats(&ms0)
			reads0 = procReads.Load()
			threads0 = selfThreads()
		},
		reported: func() {
			runtime.ReadMemStats(&ms1)
		},
	}
	if at.reads {
		opts.gate = nil
		opts.rules = func(rt *agent.RuleTable, _ string) {
			if rt.Tier == "" {
				rt.Tier = backend.TierLandlock
			}
			rt.Reads = agent.HeldReads{Mode: agent.ReadsHeld}
		}
	}
	h := startHarnessWith(b, opts)
	h.stop(b)
	get := func(name string) int {
		for _, c := range h.report.Checks {
			if c.Name == name {
				return c.N
			}
		}
		b.Fatalf("no %s in %+v", name, h.report.Checks)
		return 0
	}
	if f := get("fails"); f != 0 {
		b.Fatalf("%d of %d opens failed (deputy %t)", f, n, deputyOn)
	}
	total := n
	if parallel {
		if f := get("parallel_fails"); f != 0 {
			b.Fatalf("%d of %d parallel opens failed (deputy %t)", f, heldParallel, deputyOn)
		}
		total += heldParallel
	}
	r := benchRun{
		p50: time.Duration(get("p50")), p99: time.Duration(get("p99")), total: time.Duration(get("total")), ops: total,
		mallocsPerOp:   float64(ms1.Mallocs-ms0.Mallocs) / float64(total),
		procReadsPerOp: float64(procReads.Load()-reads0) / float64(total),
		threadsGrown:   selfThreads() - threads0,
	}
	if parallel {
		r.parallel = time.Duration(get("parallel"))
	}
	return r
}

// selfThreads is this process's thread count.
func selfThreads() int {
	b, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Threads:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// loadPerCPU is the one-minute load average over the CPUs this process may use: the ADR's p99 and wall-clock
// figures are for an idle box.
func loadPerCPU() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 99
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 99
	}
	l, _ := strconv.ParseFloat(f[0], 64)
	return l / float64(runtime.NumCPU())
}

// cpuTicks is the all-CPU line of /proc/stat: the steal ticks (time a guest's vCPUs waited for a host that ran
// something else) and the total. A KVM guest on a busy host shows a low load average of its own while its vCPUs are
// stolen from; the steal share over a run says so.
func cpuTicks() (steal, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return 0, 0
	}
	for i, s := range f[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		if i < 8 { // user nice system idle iowait irq softirq steal; guest time is counted in user already
			total += v
		}
		if i == 7 {
			steal = v
		}
	}
	return steal, total
}

// idleBox reports whether the box was idle over a run whose /proc/stat ticks at its start were steal0 and total0: a
// one-minute load below 0.5 per CPU, and under 2% of the CPU time stolen by a host.
func idleBox(steal0, total0 uint64) (bool, float64) {
	steal1, total1 := cpuTicks()
	share := 0.0
	if total1 > total0 {
		share = float64(steal1-steal0) / float64(total1-total0)
	}
	return loadPerCPU() < 0.5 && share < 0.02, share
}

// heldBenchRounds is how many times BenchmarkHeldOpen measures each configuration, alternating them: the ratio is
// the median of the rounds', so a burst of load on a shared box falls on one round of each rather than on one side.
const heldBenchRounds = 5

// BenchmarkHeldOpen is ADR 0041's Stage B budget (§Performance) on a real kernel, filter, loop and deputy: a held
// read-open of an existing regular file under a read gate (every read-open of the run held), against the same open
// under the same gate with no deputy (today's gated copy+walk+CONTINUE), alternated round by round so box load cancels
// out (heldBenchRounds). It asserts the budget's load-independent terms and prints every term it measures; a missed
// term prints TARGET-MISS with its number:
//   - p50 ≤ 2× the gated path's p50;
//   - p99 < 200 µs at tier 1 on an idle box (asserted only on one: one-minute load below 0.5 per CPU, and under 2% of
//     the CPU time stolen by a host over the run, for a KVM guest, whose own load says nothing of the host's);
//   - no OS-thread creation per open (this process's thread count grows by a bounded handful over the run, not per
//     open);
//   - zero task /proc reads per non-O_CREAT open;
//   - ≤ 64 allocations per open in this process;
//   - 30k held opens in ≤ 1 s wall across the default four workers (idle box only, as the p99).
func BenchmarkHeldOpen(b *testing.B) {
	as, _ := heldAgent(b)
	heldOpenBudget(b, heldBenchAt{as: as}, "BenchmarkHeldOpen")
}

// BenchmarkHeldOpenRootTier is BenchmarkHeldOpen on a root tier's path (ADR 0041 §Performance: "the root-tier path is
// measured in KVM"): the loop runs as root over a tier cgroup table, so a held read-open is pinned, checked and only
// then opened (no read-only open ahead of the checks, heldOpen), and the target and its deputy run as the invoking
// user, as a root run drops its agent. The same budget terms are printed and asserted. Root only, with SUDO_UID naming
// the user (test/vm/kvm-run.sh --sudo gives both).
func BenchmarkHeldOpenRootTier(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("root only: the root tiers' supervisor runs as root over an agent of another uid")
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 {
		b.Skip("needs SUDO_UID and SUDO_GID naming the agent's user, as `sudo go test` and test/vm/kvm-run.sh --sudo give")
	}
	heldOpenBudget(b, heldBenchAt{tier: backend.TierCgroup, as: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}, "BenchmarkHeldOpenRootTier")
}

// heldOpenBudget measures the held and the gated path at at, alternated round by round, and holds the result to ADR
// 0041's Stage B budget (BenchmarkHeldOpen's comment), printing each term and TARGET-MISS for one missed.
func heldOpenBudget(b *testing.B, at heldBenchAt, name string) {
	n := 2000
	if b.N > n {
		n = b.N
	}
	var gated, held benchRun
	var ratios []float64
	var gp50s, hp50s, hp99s []time.Duration
	steal0, total0 := cpuTicks()
	for round := 0; round < heldBenchRounds; round++ {
		g := runHeldBench(b, at, false, n, false)
		h := runHeldBench(b, at, true, n, round == heldBenchRounds-1)
		ratios = append(ratios, float64(h.p50)/float64(g.p50))
		gp50s, hp50s, hp99s = append(gp50s, g.p50), append(hp50s, h.p50), append(hp99s, h.p99)
		gated, held = g, h
	}
	slices.Sort(ratios)
	slices.Sort(gp50s)
	slices.Sort(hp50s)
	slices.Sort(hp99s)
	gated.p50, held.p50, held.p99 = gp50s[len(gp50s)/2], hp50s[len(hp50s)/2], hp99s[len(hp99s)/2]
	idle, steal := idleBox(steal0, total0)
	b.ReportMetric(float64(held.p50.Nanoseconds()), "held-p50-ns")
	b.ReportMetric(float64(held.p99.Nanoseconds()), "held-p99-ns")
	b.ReportMetric(float64(gated.p50.Nanoseconds()), "gated-p50-ns")
	b.ReportMetric(float64(gated.p99.Nanoseconds()), "gated-p99-ns")
	b.ReportMetric(held.mallocsPerOp, "held-allocs/op")
	b.ReportMetric(held.procReadsPerOp, "held-procreads/op")
	b.ReportMetric(float64(held.parallel.Milliseconds()), "held-30k-ms")
	ratio := ratios[len(ratios)/2]
	b.ReportMetric(ratio, "p50-ratio")
	b.Logf("per-round p50 ratios %.2f", ratios)
	b.Logf("held p50 %v p99 %v; gated p50 %v p99 %v; ratio %.2f; %.1f allocs/op; %.3f /proc reads/op; %d threads grown; 30k in %v; load/cpu %.2f; steal %.1f%%",
		held.p50, held.p99, gated.p50, gated.p99, ratio, held.mallocsPerOp, held.procReadsPerOp, held.threadsGrown, held.parallel, loadPerCPU(), 100*steal)
	miss := func(assert bool, format string, args ...any) {
		msg := fmt.Sprintf("TARGET-MISS: "+name+": "+format, args...)
		fmt.Println(msg)
		if assert {
			b.Error(msg)
		}
	}
	if ratio > 2 {
		miss(true, "held p50 %v is %.2f× the gated path's %v (budget 2×)", held.p50, ratio, gated.p50)
	}
	if held.p99 >= 200*time.Microsecond {
		miss(idle, "held p99 %v (budget < 200 µs on an idle box; load/cpu %.2f, steal %.1f%%)", held.p99, loadPerCPU(), 100*steal)
	}
	if held.mallocsPerOp > 64 {
		miss(true, "%.1f allocations per held open (budget 64)", held.mallocsPerOp)
	}
	// One read per thread, its thread group the first time it traps (tgidOf), is per thread, not per open.
	if reads := held.procReadsPerOp * float64(held.ops); reads > 8 {
		miss(true, "%.0f task /proc reads over %d held opens (budget 0 per open, one per thread)", reads, held.ops)
	}
	if held.threadsGrown > 16 {
		miss(true, "this process grew %d threads over %d held opens (budget: none per open)", held.threadsGrown, held.ops)
	}
	if held.parallel > time.Second {
		miss(idle, "30k held opens took %v across four workers (budget 1 s on an idle box; load/cpu %.2f, steal %.1f%%)", held.parallel, loadPerCPU(), 100*steal)
	}
}
