// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// All objects that a governed action needs are created before the probe cgroup
// is armed. Otherwise socket_create or exec could refuse an earlier operation
// and falsely appear to prove the hook under test.
func (p *planePre) prepareControls() error {
	var err error
	p.bind, _, err = planeSocket(-1, unix.SOCK_STREAM)
	if err != nil {
		return err
	}
	p.listening, _, err = planeSocket(-1, unix.SOCK_STREAM)
	if err != nil {
		return err
	}
	if err := unix.Bind(p.listening, &unix.SockaddrUnix{Name: "@tego-doctor-listen-" + strconv.Itoa(os.Getpid())}); err != nil {
		return err
	}
	p.key, p.keyErr = planePrivateKey()
	if p.ptraceTarget, err = startPlaneChildAs(nil, "ptrace-target", "", -1); err != nil {
		return err
	}
	if p.traceme, err = startPlaneChildAs(nil, planeTracemeRole, "", -1); err != nil {
		return err
	}
	return nil
}

func (p *planePre) closeControls() {
	for _, child := range []*planeChild{p.ptraceTarget, p.traceme} {
		if child != nil {
			child.stop()
		}
	}
	for _, fd := range []int{p.bind, p.listening} {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
	if p.key >= 0 {
		// The child's process keyring also releases its last reference on exit.
		// Revocation may itself be refused once the scratch policy is armed.
		planeReleaseKey(p.key)
	}
}

func planeReleaseKey(key int) {
	if ring, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_PROCESS_KEYRING, false); err == nil {
		_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, key, ring, 0, 0)
	}
	_, _ = unix.KeyctlInt(unix.KEYCTL_REVOKE, key, 0, 0, 0)
}

func planePrivateKey() (int, error) {
	// Only the helper's process keyring holds this freshly named key. add_key
	// requires an actual destination: zero cannot create an unlinked keyring.
	processRing, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_PROCESS_KEYRING, true)
	if err != nil {
		return -1, err
	}
	name := "tego-doctor-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	key, err := unix.AddKey("user", name, []byte{1}, processRing)
	if err != nil {
		return -1, err
	}
	// Go threads can have credentials created before the process keyring was
	// installed. Owner rights let the same helper UID use its own key even
	// when that thread does not possess the newly installed ring. Keep all
	// possessor rights, owner view/read/write, and no group/other rights (key.h).
	if _, err := unix.KeyctlInt(unix.KEYCTL_SETPERM, key, (0x3f<<24)|(0x07<<16), 0, 0); err != nil {
		planeReleaseKey(key)
		return -1, err
	}
	return key, nil
}

func planeControlAction(hook string, p planePre) error {
	switch hook {
	case "socket_bind":
		fd, closeFD, err := planeSocket(p.bind, unix.SOCK_STREAM)
		if err != nil {
			return err
		}
		defer closeFD()
		return unix.Bind(fd, &unix.SockaddrUnix{Name: "@tego-doctor-bind-" + strconv.Itoa(os.Getpid())})
	case "socket_listen":
		fd, closeFD, err := planeSocket(p.listening, unix.SOCK_STREAM)
		if err != nil {
			return err
		}
		defer closeFD()
		if p.listening < 0 {
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@tego-doctor-listen-" + strconv.Itoa(os.Getpid())}); err != nil {
				return err
			}
		}
		return unix.Listen(fd, 1)
	case "bpf":
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
		if err != nil {
			return err
		}
		return m.Close()
	case "key_permission":
		key := p.key
		if key < 0 {
			if p.keyErr != nil {
				return p.keyErr
			}
			var err error
			key, err = planePrivateKey()
			if err != nil {
				return err
			}
			defer planeReleaseKey(key)
		}
		// READ remaps an early permission lookup failure to ENOKEY, and can
		// retry via possession. Updating this helper's one-byte payload to
		// itself preserves the permission hook's actual EACCES unchanged.
		_, err := unix.KeyctlBuffer(unix.KEYCTL_UPDATE, key, []byte{1}, 0)
		return err
	case "ptrace_access_check":
		target := p.ptraceTarget
		if target == nil {
			var err error
			target, err = startPlaneChildAs(nil, "ptrace-target", "", -1)
			if err != nil {
				return err
			}
			defer target.stop()
		}
		return planePtraceAttach(target.cmd.Process.Pid)
	case "ptrace_traceme":
		child := p.traceme
		if child == nil {
			var err error
			child, err = startPlaneChildAs(nil, planeTracemeRole, "", -1)
			if err != nil {
				return err
			}
			defer child.stop()
		}
		if _, err := io.WriteString(child.stdin, "go\n"); err != nil {
			return err
		}
		line, err := child.readLine()
		if err != nil {
			return err
		}
		if err := child.wait(); err != nil {
			return err
		}
		switch line {
		case planePassed:
			return nil
		case planeRefused:
			return unix.EACCES
		default:
			return fmt.Errorf("ptrace traceme helper: %s", line)
		}
	}
	return fmt.Errorf("unknown control probe %s", hook)
}

// Linux assigns a tracer to the calling thread. Keep attach, wait and detach
// on that thread, and wait only for our unreaped child, never an arbitrary PID.
func planePtraceAttach(pid int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.PtraceAttach(pid); err != nil {
		return err
	}
	deadline := time.Now().Add(planeProbeTimeout)
	for {
		var status unix.WaitStatus
		got, err := unix.Wait4(pid, &status, unix.WNOHANG|unix.WUNTRACED, nil)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if got == pid {
			if !status.Stopped() {
				return errors.New("ptrace target exited before attach stop")
			}
			return unix.PtraceDetach(pid)
		}
		if !time.Now().Before(deadline) {
			return errors.New("ptrace target did not stop")
		}
		time.Sleep(time.Millisecond)
	}
}

// planeTracemeRole is the ptrace_traceme cell's helper, `__doctor-plane-probe ptrace-traceme`.
const planeTracemeRole = "ptrace-traceme"

// init keeps the main of the probe children that need the thread-group leader (onLeader) on the startup thread: the
// runtime runs every init there, and a LockOSThread made in one makes main run on that thread too. Their own
// LockOSThread pins the goroutine to whatever thread it is on, which is the leader only while the scheduler has not
// moved the main goroutine since the inits; under load it had (TestPtraceTracemeHelperIsAlwaysReaped, and the known
// answers' failed hold of x/xd in a 7.0 guest on 2026-11-11). Only those argvs are locked; every other process of the
// binary runs as before.
func init() {
	if onLeader(os.Args) {
		runtime.LockOSThread()
	}
}

// onLeader reports whether argv starts a probe child whose work must be done on the thread-group leader: the
// ptrace_traceme helper (planePtraceHelper says why), and the known answers' child, which makes its mount namespace on
// the thread it locks (planeKnownSetup), while doctor reaches that namespace's files through /proc/<pid>/root, which
// is the leader's view: from any other thread the child's tmpfs at x is not there, and doctor's hold of x/xd fails
// ENOENT, so the probe could not finish and the plane mode was not offered.
func onLeader(argv []string) bool {
	return len(argv) > 2 && argv[1] == PlaneProbeCommand && (argv[2] == planeTracemeRole || argv[2] == planeKnownRole)
}

// planePtraceHelper is the ptrace cells' helper process: "ptrace-target" says ready and waits to be attached to,
// "ptrace-traceme" says ready, waits for go, makes PTRACE_TRACEME and answers passed, refused or failed.
//
// PTRACE_TRACEME traces the calling thread, not the process, and makes doctor that thread's tracer, so two rules hold
// from the call to the exit. The thread is the thread-group leader (init): a traced thread that is not the leader
// becomes, at exit_group, a zombie only its tracer can reap, by its thread id with __WALL, and until then the leader is
// never reported to doctor's wait (waitid on its pidfd), SIGKILL included, so doctor waited for ever. And every
// signal is blocked on the thread first: a traced thread stops at the delivery of any signal and waits for its tracer,
// and the Go runtime signals its threads (SIGURG preemption); doctor's wait then reported "stop signal: urgent I/O
// condition", the cell failed and the plane mode with it, and the stopped helper outlived the probe. Blocked, a signal
// stays pending, and exit_group ends every thread whatever is pending.
func planePtraceHelper(role string) int {
	runtime.LockOSThread()
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		return 1
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if role == "ptrace-target" {
		// The owning parent's EOF/kill is the only lifetime of this fixture.
		return 0
	}
	if err != nil || line != "go\n" {
		return 1
	}
	passed, refused, failed := []byte("passed\n"), []byte("refused\n"), []byte("failed: ptrace traceme\n")
	answer := []byte("failed: ptrace traceme from a thread that is not the thread-group leader\n")
	if unix.Gettid() == unix.Getpid() {
		answer = failed
		all := ^uint64(0) // the kernel's sigset_t: SIGKILL and SIGSTOP stay unblockable
		_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&all)), 0,
			unsafe.Sizeof(all), 0, 0)
		if errno == 0 {
			_, _, errno = unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
			switch errno {
			case 0:
				answer = passed
			case unix.EACCES:
				answer = refused
			}
		}
	}
	// A successful TRACEME must not resume the Go scheduler, whose signals can
	// create a ptrace stop. Report and exit with raw syscalls on the same thread.
	for len(answer) > 0 {
		n, _, e := unix.RawSyscall(unix.SYS_WRITE, 1, uintptr(unsafe.Pointer(&answer[0])), uintptr(len(answer)))
		if e == unix.EINTR {
			continue
		}
		if e != 0 || n == 0 {
			break
		}
		answer = answer[n:]
	}
	_, _, _ = unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	return 1
}
