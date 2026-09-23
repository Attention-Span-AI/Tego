// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// openForEvent opens a file read-only and hands back the descriptor the way fanotify hands one over.
func openForEvent(t *testing.T, path string) int32 {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return int32(fd)
}

// TestDecideEventReadsProcOnlyWhenItCouldRefuse is the cost side of enforce-cgroup-observe.md §6 E34.
//
// A FAN_MARK_MOUNT mark is scoped to the whole mount (fanotify_mark(2): "if path is not itself a mount point,
// the mount containing path will be marked"), so a rule on ~/.ssh marks "/" on an ordinary box and this
// listener decides every open and every execve by every process on the machine. Deciding by reading
// /proc/<pid>/cgroup first made each of those — systemd, sshd, the user's shell, unrelated containers — pay
// an open, a read and a parse of procfs before being allowed, and put a read that can block in D state in
// front of every open on the filesystem.
//
// The membership check can only ever turn a refusal into an allow, so it is unnecessary for any event the
// policy already allows. This asserts the ordering that follows from that, not merely the verdict: the
// verdicts were correct before too, which is why the assertion has to be on the lookup count.
func TestDecideEventReadsProcOnlyWhenItCouldRefuse(t *testing.T) {
	t.Parallel()
	const runCgroup = "/tego.slice/run-1.scope"

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.Mkdir(secret, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	denied := filepath.Join(secret, "id_ed25519")
	ordinary := filepath.Join(dir, "ordinary.txt")
	for _, p := range []string{denied, ordinary} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	var lookups atomic.Int64
	l := &fanotifyListener{
		run:      Run{ID: "run-1", Agent: "a", CgroupPath: runCgroup, CgroupID: 99},
		policy:   &policy{runCgroup: runCgroup, denyRead: newPathSet([]fsEntry{{path: secret, dir: true, rule: "fs.deny_read[secret]"}})},
		now:      time.Now,
		deadline: time.Second,
		marks:    map[string]uint64{},
	}
	l.cgroupOfPID = func(int) (string, error) {
		lookups.Add(1)
		return runCgroup, nil
	}

	t.Run("an open the policy allows never touches procfs", func(t *testing.T) {
		v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_PERM, FD: openForEvent(t, ordinary), PID: 4242})
		if err != nil || !v.allow {
			t.Fatalf("decideEvent on an unruled path = %+v, %v; want an allow", v, err)
		}
		if got := lookups.Load(); got != 0 {
			t.Fatalf("%d /proc/<pid>/cgroup reads for an open no rule covers, want 0: every process on the "+
				"marked mount pays this one, and its answer cannot change an allow (§6 E34)", got)
		}
	})

	t.Run("an open the policy would refuse still checks membership", func(t *testing.T) {
		before := lookups.Load()
		v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_PERM, FD: openForEvent(t, denied), PID: 4242})
		if err != nil {
			t.Fatalf("decideEvent under a deny_read entry: %v", err)
		}
		if v.allow || v.reason != record.ReasonReadDenied || v.path != denied {
			t.Fatalf("decideEvent under a deny_read entry = %+v, want a refusal naming %s", v, denied)
		}
		if got := lookups.Load() - before; got != 1 {
			t.Fatalf("%d membership lookups for an open that could be refused, want exactly 1", got)
		}
	})

	t.Run("a refusable open by a process outside the run is still allowed", func(t *testing.T) {
		l.cgroupOfPID = func(int) (string, error) { return "/user.slice/user-1000.slice", nil }
		v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_PERM, FD: openForEvent(t, denied), PID: 4242})
		if err != nil || !v.allow {
			t.Fatalf("decideEvent for an opener outside the run = %+v, %v; the run is the only thing this "+
				"backend may decide for", v, err)
		}
	})
}

// TestDecideEventExecReadsProcUnlessTheBinaryIsNamed is the exec half of §6 E34's cost, which deciding on the
// path first does not remove. decideExec refuses any binary the contract did not name (§5 R8), so an execve
// of such a binary never reaches decideEvent's early allow: it reads /proc/<pid>/cgroup to learn whether the
// process is the run's, even when it is systemd's or the user's shell's. An execve of a binary the contract
// names is allowed before that read, whichever process ran it. For a host process the verdict is an allow
// both ways, so, as in the open half, the assertion has to be on the lookup count.
func TestDecideEventExecReadsProcUnlessTheBinaryIsNamed(t *testing.T) {
	t.Parallel()
	const (
		runCgroup  = "/tego.slice/run-1.scope"
		hostCgroup = "/user.slice/user-1000.slice/session-2.scope"
	)

	dir := t.TempDir()
	named := filepath.Join(dir, "python3")
	unnamed := filepath.Join(dir, "curl")
	for _, p := range []string{named, unnamed} {
		if err := os.WriteFile(p, nil, 0o700); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	var lookups atomic.Int64
	member := hostCgroup
	l := &fanotifyListener{
		run:      Run{ID: "run-1", Agent: "a", CgroupPath: runCgroup, CgroupID: 99},
		policy:   &policy{runCgroup: runCgroup, execAllow: newPathSet([]fsEntry{{path: named, rule: "exec[python3]"}})},
		now:      time.Now,
		deadline: time.Second,
		marks:    map[string]uint64{},
	}
	l.cgroupOfPID = func(int) (string, error) {
		lookups.Add(1)
		return member, nil
	}
	exec := func(t *testing.T, path string) verdict {
		t.Helper()
		v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_EXEC_PERM, FD: openForEvent(t, path), PID: 4242})
		if err != nil {
			t.Fatalf("decideEvent on an exec of %s: %v", path, err)
		}
		return v
	}

	// The subtests share the listener and the counter, so they run in order and none is parallel.
	t.Run("an exec of a named binary never touches procfs, whichever process ran it", func(t *testing.T) {
		before := lookups.Load()
		if v := exec(t, named); !v.allow {
			t.Fatalf("exec of a binary the contract names = %+v, want an allow", v)
		}
		if got := lookups.Load() - before; got != 0 {
			t.Fatalf("%d /proc/<pid>/cgroup reads for an exec of a named binary, want 0: the policy already "+
				"allows it and membership can only turn a refusal into an allow (§6 E34)", got)
		}
	})

	t.Run("an exec of an unnamed binary by a host process still reads procfs", func(t *testing.T) {
		before := lookups.Load()
		if v := exec(t, unnamed); !v.allow {
			t.Fatalf("a host process's exec = %+v, want an allow: the run is the only thing this backend may "+
				"decide for", v)
		}
		if got := lookups.Load() - before; got != 1 {
			t.Fatalf("%d membership lookups for a host exec of an unnamed binary, want exactly 1: only /proc "+
				"separates the host's execs from the run's, and §6 E34 says this one is paid", got)
		}
	})

	t.Run("the same exec by the run is refused", func(t *testing.T) {
		member = runCgroup + "/child"
		before := lookups.Load()
		v := exec(t, unnamed)
		if v.allow || v.reason != record.ReasonExecNotAllowed || v.path != unnamed {
			t.Fatalf("the run's exec of an unnamed binary = %+v, want a refusal naming %s", v, unnamed)
		}
		if got := lookups.Load() - before; got != 1 {
			t.Fatalf("%d membership lookups, want exactly 1", got)
		}
	})
}
