// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The process and control ops (FEATURES E54, enforce-plane §2.20; test/conformance cells.go names each): the
// agent's own ptrace, keyring and bpf(2) calls. A ptrace op reports, as its result's value, the pid its hook names:
// the tracee an attach asked for, the tracer a TRACEME asked for.

const (
	// controlStage is `actor control <op> <arg>`: a process of its own for a TRACEME, which marks the caller for good.
	controlStage = "control"
	// sleepStage is `actor sleep`: a child that only waits to be attached to, until it is killed.
	sleepStage = "sleep"
	// hostStage is `actor host`: the process outside every run a ptrace cell's {{HOSTPID}} names (hostMain).
	hostStage = "host"
	// keyDesc names the user key the keyring ops add and request.
	keyDesc = "tego-conformance"
	// tracemeOrphaned is the control stage's grandchild, which asks its new parent for a TRACEME once its own exited.
	tracemeOrphaned = "traceme-orphaned"
	// tracemeOrphan is the control stage that starts tracemeOrphaned and exits at once.
	tracemeOrphan = "traceme-orphan"
	// tracemeOwn is the control stage that asks its parent, the actor, for a TRACEME.
	tracemeOwn = "traceme"
)

// controlOp are the ops performControl performs.
var controlOp = map[string]bool{"ptrace-attach": true, "ptrace-traceme": true, "keyctl": true, "add-key": true, "request-key": true, "bpf": true}

// performControl performs a process or control op; its value is the pid its hook names, "" for the others.
func performControl(a Action) (string, error) {
	switch a.Op {
	case "ptrace-attach":
		return ptraceAttach(a.Target)
	case "ptrace-traceme":
		switch a.Target {
		case "parent":
			return strconv.Itoa(os.Getpid()), runStage(exec.Command("/proc/self/exe", controlStage, tracemeOwn, "-"))
		case "orphan":
			return tracemeFromOrphan()
		}
		return "", fmt.Errorf("ptrace-traceme: target %q is neither parent nor orphan: %w", a.Target, unix.EINVAL)
	case "keyctl":
		_, err := unix.KeyctlInt(unix.KEYCTL_GET_KEYRING_ID, unix.KEY_SPEC_PROCESS_KEYRING, 1, 0, 0)
		return "", err
	case "add-key":
		_, err := unix.AddKey("user", keyDesc, []byte("payload"), unix.KEY_SPEC_PROCESS_KEYRING)
		return "", err
	case "request-key":
		// No callout (a NULL callout_info): a key that is not found is ENOKEY, never an upcall to /sbin/request-key.
		typ, desc := []byte("user\x00"), []byte(keyDesc+"\x00")
		_, _, en := unix.Syscall6(unix.SYS_REQUEST_KEY, uintptr(unsafe.Pointer(&typ[0])), uintptr(unsafe.Pointer(&desc[0])), 0, 0, 0, 0)
		if en != 0 {
			return "", en
		}
		return "", nil
	case "bpf":
		return "", bpfMapCreate()
	}
	return "", fmt.Errorf("unknown op %q", a.Op)
}

// ptraceAttach attaches to target (a child it starts, or a pid), waits for the stop and detaches. The tracer is the
// thread that attached, so the goroutine keeps its thread until it detached.
func ptraceAttach(target string) (string, error) {
	var pid int
	if target == "child" {
		child := exec.Command("/proc/self/exe", sleepStage)
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stderr, os.Stderr
		if err := child.Start(); err != nil {
			return "", err
		}
		defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
		pid = child.Process.Pid
	} else {
		var err error
		if pid, err = strconv.Atoi(target); err != nil || pid <= 0 {
			return "", fmt.Errorf("ptrace-attach: target %q is neither child nor a pid: %w", target, unix.EINVAL)
		}
	}
	value := strconv.Itoa(pid)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.PtraceAttach(pid); err != nil {
		return value, err
	}
	var ws unix.WaitStatus
	_, werr := unix.Wait4(pid, &ws, unix.WALL, nil)
	if err := unix.PtraceDetach(pid); err != nil && werr == nil {
		werr = err
	}
	if werr != nil {
		return value, fmt.Errorf("attached, then: %w", werr)
	}
	return value, nil
}

// tracemeFromOrphan starts the control stage tracemeOrphan, which starts its own child and exits: that grandchild,
// reparented to the subreaper above the actor (outside the run), asks it for a TRACEME and writes "<tracer> <errno>"
// to the pipe it inherited as fd 3.
func tracemeFromOrphan() (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer r.Close() //nolint:errcheck // read to EOF below
	stage := exec.Command("/proc/self/exe", controlStage, tracemeOrphan, "-")
	stage.Stdin, stage.Stdout, stage.Stderr = os.Stdin, os.Stderr, os.Stderr
	stage.ExtraFiles = []*os.File{w}
	err = stage.Run()
	_ = w.Close()
	if err != nil {
		return "", fmt.Errorf("the orphaning stage: %w", err)
	}
	done := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	var out []byte
	select {
	case out = <-done:
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("the orphan said nothing in 10 s: %w", unix.ETIMEDOUT)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		return "", fmt.Errorf("the orphan said %q", out)
	}
	en, err := strconv.Atoi(f[1])
	if err != nil {
		return f[0], fmt.Errorf("the orphan said %q", out)
	}
	if en != 0 {
		return f[0], syscall.Errno(en)
	}
	return f[0], nil
}

// controlStageMain is `actor control <op> <arg>`.
func controlStageMain(op, _ string) {
	switch op {
	case tracemeOwn:
		os.Exit(traceme())
	case tracemeOrphan:
		// The grandchild inherits fd 3; this stage exits without waiting for it, which orphans it.
		gc := exec.Command("/proc/self/exe", controlStage, tracemeOrphaned, strconv.Itoa(os.Getpid()))
		gc.Stdin, gc.Stdout, gc.Stderr = os.Stdin, os.Stderr, os.Stderr
		gc.ExtraFiles = []*os.File{os.NewFile(3, "result")}
		if err := gc.Start(); err != nil {
			log.Fatalf("actor %s %s: %v", controlStage, op, err)
		}
		os.Exit(0)
	case tracemeOrphaned:
		out := os.NewFile(3, "result")
		was, _ := strconv.Atoi(os.Args[3])
		for deadline := time.Now().Add(5 * time.Second); os.Getppid() == was; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				_, _ = fmt.Fprintf(out, "%d %d\n", os.Getppid(), unix.ETIMEDOUT)
				os.Exit(1)
			}
		}
		tracer := os.Getppid()
		code := traceme()
		en := 0
		if code > stageErrnoBase {
			en = code - stageErrnoBase
		}
		_, _ = fmt.Fprintf(out, "%d %d\n", tracer, en)
		os.Exit(0)
	}
	log.Fatalf("actor %s: unknown op %q", controlStage, op)
}

// hostMain is `actor host`. It lets any process of its uid trace it, PR_SET_PTRACER_ANY, so that Yama's
// ptrace_scope 1 (an attach to a non-descendant refused, EPERM) admits an attach to it: only the run (Landlock's
// ptrace scope, the plane's ptrace_access_check) can then refuse one. A kernel without Yama has nothing to opt out
// of (EINVAL). It writes "ready" once it has, and sleeps until the runner kills it.
func hostMain() {
	if err := unix.Prctl(unix.PR_SET_PTRACER, unix.PR_SET_PTRACER_ANY, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		log.Fatalf("actor %s: prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY): %v", hostStage, err)
	}
	fmt.Println("ready")
	time.Sleep(time.Hour)
}

// blockSignals blocks every signal the calling thread can block (all but SIGKILL and SIGSTOP), for good: its caller
// is locked to the thread and exits.
func blockSignals() error {
	var all unix.Sigset_t
	for i := range all.Val {
		all.Val[i] = ^all.Val[i]
	}
	return unix.PthreadSigmask(unix.SIG_BLOCK, &all, nil)
}

// traceme asks the caller's parent for a TRACEME on a thread it keeps, and returns the stage's exit status: 0, or
// stageErrnoBase+errno. A tracee that took a signal would stop until its tracer resumed it, and its tracer here
// never does, so the thread blocks every signal first (the Go runtime's preemption SIGURG among them: one that
// landed between the TRACEME and the report hung the stage on AL2023's 6.1), and a stage that was granted the
// TRACEME reports and exits at once on that thread.
func traceme() int {
	runtime.LockOSThread()
	if err := blockSignals(); err != nil { // no TRACEME asked: an errno no cell reads as a refusal
		en := unix.EINVAL
		_ = errors.As(err, &en)
		return stageErrnoBase + int(en)
	}
	if en := ptraceTraceme(); en != 0 {
		return stageErrnoBase + int(en)
	}
	return 0
}

// ptraceTraceme is the TRACEME itself, on the calling thread; a variable so that the actor's test reads the thread's
// state where traceme asks (TestTracemeThreadBlocksSignals).
var ptraceTraceme = func() syscall.Errno {
	_, _, en := unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
	return en
}

// bpfMapCreate creates a one-entry array map with bpf(BPF_MAP_CREATE) and closes it.
func bpfMapCreate() error {
	attr := struct{ mapType, keySize, valueSize, maxEntries uint32 }{mapType: 2, keySize: 4, valueSize: 4, maxEntries: 1} // BPF_MAP_TYPE_ARRAY
	buf := make([]byte, 128)                                                                                              // the zero tail of union bpf_attr
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&attr)), unsafe.Sizeof(attr)))
	fd, _, en := unix.Syscall(unix.SYS_BPF, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // BPF_MAP_CREATE
	if en != 0 {
		return en
	}
	return unix.Close(int(fd))
}
