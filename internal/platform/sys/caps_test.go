// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClearCapabilities(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("clearing capabilities as root would strip the test thread; covered by the child-stage integration test")
	}
	runtime.LockOSThread() // the empty set is per-thread; never unlock, so the runtime retires this thread
	bndBefore := threadCapSet(t, "CapBnd")
	nnpBefore, err := NoNewPrivs()
	if err != nil {
		t.Fatal(err)
	}
	if err := ClearCapabilities(); err != nil {
		t.Fatal(err)
	}
	e, p, i, err := Capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if e != 0 || p != 0 || i != 0 {
		t.Fatalf("capabilities after clear: effective=%#x permitted=%#x inheritable=%#x", e, p, i)
	}
	if amb := threadCapSet(t, "CapAmb"); amb != 0 {
		t.Fatalf("ambient set after clear = %#x, want empty", amb)
	}
	// ClearCapabilities leaves whether execve can gain capabilities to its caller's ordering: the bounding
	// set stays as it was, and no_new_privs stays wherever the caller put it, because the privileged order
	// (runtime-launch.md R4) calls this without that bit on purpose and a setuid binary must still work there.
	if bnd := threadCapSet(t, "CapBnd"); bnd != bndBefore {
		t.Fatalf("bounding set after clear = %#x, want it untouched at %#x", bnd, bndBefore)
	}
	if nnp, err := NoNewPrivs(); err != nil || nnp != nnpBefore {
		t.Fatalf("no_new_privs after clear = %v (%v), want it untouched at %v", nnp, err, nnpBefore)
	}
	if on, err := Dumpable(); err != nil || !on {
		t.Fatalf("dumpable after capset from an already-empty set: %v, %v", on, err)
	}
}

// capGainEnv re-runs this test binary as TestExecveGainHelper: "plain" or "no_new_privs" for the stage that
// clears its capabilities and execs, "report" for the image that stage execs.
const capGainEnv = "TEGO_SYS_CAPGAIN_HELPER"

// capGainReport prefixes the report stage's line: its permitted set, then its bounding set, in hex.
const capGainReport = "capgain-report"

// capGainExitInheritedNNP is the plain stage's exit code when its thread already had no_new_privs before it
// did anything. The bit is inherited and can never be cleared (prctl(2)), so no execve from that process can
// run without it, and the parent reads this code as "cannot measure here", not as a ClearCapabilities fault.
// It is none of the codes a Go test binary exits with on its own (0 pass, 1 fail, 2 panic or timeout).
const capGainExitInheritedNNP = 3

// TestExecveGainHelper is the target process of TestExecveAfterClearCapabilities, not a test on its own.
func TestExecveGainHelper(t *testing.T) {
	mode := os.Getenv(capGainEnv)
	switch mode {
	case "":
		t.Skip("helper process for TestExecveAfterClearCapabilities")
	case "report":
		// The sets come from /proc, not capget(2): an LSM may mask what capget reports (on an Ubuntu host
		// that restricts unprivileged user namespaces, AppArmor's unprivileged_userns profile makes capget
		// report an empty permitted set in this namespace; measured on 6.17), and the question is what
		// execve put in the credentials, not what a profile lets the task use.
		runtime.LockOSThread() // threadCapSet reads this thread's sets
		fmt.Printf("%s %x %x\n", capGainReport, threadCapSet(t, "CapPrm"), threadCapSet(t, "CapBnd"))
		return
	}
	runtime.LockOSThread() // execve starts from the exec'ing thread's credentials, so they must be this one's
	if mode == "plain" {
		// Read on the thread that will exec, because the bit is per thread. A test binary started with it
		// (setpriv --no-new-privs, a container run with no-new-privileges, systemd NoNewPrivileges=yes, a
		// shell inside a `tego run` on the unprivileged order) would have the root-exec grant downgraded
		// by the kernel, and the parent would blame ClearCapabilities for an empty set it did not cause.
		nnp, err := NoNewPrivs()
		if err != nil {
			t.Fatal(err)
		}
		if nnp {
			os.Exit(capGainExitInheritedNNP)
		}
	}
	if err := ClearCapabilities(); err != nil {
		t.Fatal(err)
	}
	// The plain case is only worth reading if execve started from an empty permitted set, and the
	// no_new_privs case caps the new set at exactly this one.
	if prm, amb := threadCapSet(t, "CapPrm"), threadCapSet(t, "CapAmb"); prm != 0 || amb != 0 {
		t.Fatalf("before execve: permitted %#x ambient %#x, want both empty", prm, amb)
	}
	if mode == "no_new_privs" {
		if err := SetNoNewPrivs(); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := []string{capGainEnv + "=report"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, capGainEnv+"=") {
			env = append(env, kv)
		}
	}
	err = syscall.Exec(exe, []string{exe, "-test.run=^TestExecveGainHelper$", "-test.timeout=30s"}, env)
	t.Fatalf("execve(%s): %v", exe, err)
}

// TestExecveAfterClearCapabilities measures what ClearCapabilities' comment leaves to its caller: an emptied
// permitted set does not keep execve from granting capabilities up to the bounding set, and no_new_privs set
// after the call and before execve, as the unprivileged order does, leaves nothing to grant. The helper runs
// as uid 0 of a user namespace of its own, where the root-exec rule (capabilities(7)) grants every execve
// the bounding set: the grant a setuid-root binary gets on the privileged order, which skips no_new_privs
// (runtime-launch.md R4a), measured here without needing a setuid binary or a file capability.
//
// The plain case needs an execve without no_new_privs, which a test process that inherited the bit can
// never make; its helper checks the bit on the thread that would exec and the subtest skips when it is set.
// The no_new_privs case is valid either way, since it sets the bit itself.
func TestExecveAfterClearCapabilities(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"plain", "no_new_privs"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestExecveGainHelper$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), capGainEnv+"="+mode)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:  syscall.CLONE_NEWUSER,
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
				GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				// clone3 or the id maps were refused: the host allows no user namespace here, and the helper
				// never ran, so nothing about ClearCapabilities was measured.
				t.Skipf("no user namespace to be uid 0 in: %v", err)
			}
			if err != nil && mode == "plain" && ee.ExitCode() == capGainExitInheritedNNP {
				t.Skip("this test process already runs with no_new_privs, which is inherited and can never be " +
					"cleared: no execve from it runs without the bit, so the plain case cannot be measured here")
			}
			if err != nil {
				t.Fatalf("helper: %v\n%s%s", err, out, stderr.Bytes())
			}
			var permitted, bounding uint64
			found := false
			for _, line := range strings.Split(string(out), "\n") {
				if rest, ok := strings.CutPrefix(line, capGainReport+" "); ok {
					if _, err := fmt.Sscanf(rest, "%x %x", &permitted, &bounding); err != nil {
						t.Fatalf("report line %q: %v", line, err)
					}
					found = true
				}
			}
			if !found {
				t.Fatalf("helper printed no %s line:\n%s%s", capGainReport, out, stderr.Bytes())
			}
			switch mode {
			case "plain":
				if permitted == 0 || permitted != bounding {
					// The helper saw no_new_privs unset before the call, so a grant short of the bounding set
					// is not an inherited bit's doing.
					t.Fatalf("execve after ClearCapabilities from a thread without no_new_privs before the call: "+
						"permitted %#x, want the bounding set %#x", permitted, bounding)
				}
			case "no_new_privs":
				if permitted != 0 {
					t.Fatalf("execve after ClearCapabilities and no_new_privs: permitted %#x, want empty", permitted)
				}
			}
		})
	}
}

// threadCapSet reads one capability set of the calling thread from /proc/thread-self/status: capget(2) has
// no bounding or ambient set, and the caller must be locked to its thread for the answer to be its own.
func threadCapSet(t *testing.T, field string) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, field+":")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			t.Fatalf("%s line %q: %v", field, line, err)
		}
		return v
	}
	t.Fatalf("no %s line in /proc/thread-self/status", field)
	return 0
}

// TestAmbientCapabilitiesMatchesTheStatusLine: the prctl reading of the ambient set agrees with the kernel's own
// CapAmb line for this thread (empty for an ordinary test run; a run under an inherited ambient set shows it).
func TestAmbientCapabilitiesMatchesTheStatusLine(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	got, err := AmbientCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if want := threadCapSet(t, "CapAmb"); got != want {
		t.Fatalf("AmbientCapabilities = %#x, CapAmb = %#x", got, want)
	}
}

// TestClearProcessCapabilitiesReachesEveryThread is ADR 0042 (3)(a)'s clearing: capabilities are per thread, so a
// launcher that cleared only the thread it runs on would leave them on every other thread the runtime started,
// and a process started from one of those would inherit an ambient set. Without cgo the call runs on every
// thread and every thread's sets are empty afterwards; with cgo (the -race builds) the runtime cannot reach the
// threads cgo made, and the call fails with ENOTSUP rather than clear some of them.
func TestClearProcessCapabilitiesReachesEveryThread(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("clearing capabilities as root would strip the test process; the guest's privpath tests cover it")
	}
	_, _, probe := syscall.AllThreadsSyscall(syscall.SYS_GETPID, 0, 0, 0)
	err := ClearProcessCapabilities()
	if probe == syscall.ENOTSUP {
		if !errors.Is(err, syscall.ENOTSUP) {
			t.Fatalf("a cgo build: ClearProcessCapabilities = %v, want ENOTSUP", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		b, err := os.ReadFile("/proc/self/task/" + task.Name() + "/status")
		if err != nil {
			continue // a thread that exited meanwhile
		}
		for _, line := range strings.Split(string(b), "\n") {
			for _, field := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
				if rest, ok := strings.CutPrefix(line, field); ok && strings.Trim(strings.TrimSpace(rest), "0") != "" {
					t.Errorf("thread %s: %s", task.Name(), line)
				}
			}
		}
	}
}

// TestDropBoundingCapability: a capability in the set is gone after the drop, or, without CAP_SETPCAP, the refusal is
// the caller's to report; one out of the set asks nothing of the kernel and succeeds; a number the kernel does not know
// is an error, never "not held". The bounding set is per thread, so the thread that dropped it ends with this test
// (runtime.LockOSThread with no unlock).
func TestDropBoundingCapability(t *testing.T) {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		errc <- func() error {
			held, err := InBoundingSet(unix.CAP_NET_ADMIN)
			if err != nil {
				return err
			}
			if !held {
				return nil // a container that never had it: nothing below can be asked of this thread
			}
			err = DropBoundingCapability(unix.CAP_NET_ADMIN)
			if os.Geteuid() != 0 {
				if !errors.Is(err, unix.EPERM) {
					return fmt.Errorf("without CAP_SETPCAP: %w, want EPERM", err)
				}
				return nil
			}
			if err != nil {
				return err
			}
			if held, err := InBoundingSet(unix.CAP_NET_ADMIN); err != nil || held {
				return fmt.Errorf("after the drop: in the set %v, %w", held, err)
			}
			return DropBoundingCapability(unix.CAP_NET_ADMIN)
		}()
	}()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := DropBoundingCapability(63); !errors.Is(err, unix.EINVAL) {
		t.Errorf("capability 63: %v, want EINVAL", err)
	}
}
