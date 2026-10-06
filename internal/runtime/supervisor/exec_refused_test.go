// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// TestExecImageRefusesWhatTheKernelRefuses: in a run with command rules, an image the kernel's do_open_execat is
// sure to refuse the task with EACCES is that lookup's EACCES, and its head is never opened: a file with no execute
// bit, a procfs file (SB_I_NOEXEC), and permission bits that give the task's filesystem ids none. Before, the head was
// read and parsed for any regular file, so a `chmod 644` script naming a missing interpreter was answered ENOENT and
// refused interpreter-unresolved, and a root supervisor read files the task could not run. A file the task may run is
// read as before, and so is one whose answer depends on what is not read here (CAP_DAC_OVERRIDE).
func TestExecImageRefusesWhatTheKernelRefuses(t *testing.T) {
	tid := selfTask(t)
	dir := t.TempDir()
	me, err := sys.ReadTaskCreds(tid)
	if err != nil {
		t.Fatal(err)
	}
	// The task is the owner with no DAC capability: run as root (the KVM guest's root suites), the test's own
	// credentials hold CAP_DAC_OVERRIDE, which execRefused rightly reads as unsure, so "the owner's class has none"
	// was never refused there.
	me.CapEff = 0
	other := me
	other.FSUID, other.EUID, other.FSGID, other.EGID, other.Groups, other.CapEff = me.FSUID+1, me.EUID+1, me.FSGID+1, me.EGID+1, nil, 0
	var opened []string
	prevOpen := headOpen
	headOpen = func(p string) (int, error) {
		l, _ := os.Readlink(p)
		opened = append(opened, l)
		return prevOpen(p)
	}
	// This test is the final file's check alone. The walk's search check (walkImage) reads the same stubbed
	// credentials, and as root it runs: another user's credentials cannot search the 0700 temporary directory, which
	// TestExecImageHoldsTheTaskToSearchPermission covers.
	prevCreds, prevChecked := taskCreds, searchChecked
	searchChecked = func() bool { return false }
	t.Cleanup(func() { headOpen, taskCreds, searchChecked = prevOpen, prevCreds, prevChecked })
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/nonexistent\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		name    string
		path    string
		creds   sys.TaskCreds
		refused bool
	}{
		{"no execute bit", write("plain", 0o644), me, true},
		{"the owner's class has none", write("ownernox", 0o655), me, true},
		{"a procfs file", "/proc/self/status", me, true},
		{"executable by its owner", write("mine", 0o700), me, false},
		{"executable by everyone", write("all", 0o755), other, false},
		{"another user, no execute bit for others", write("theirs", 0o750), other, true},
		{"another user with CAP_DAC_OVERRIDE", write("override", 0o700), func() sys.TaskCreds { c := other; c.CapEff = 1 << unix.CAP_DAC_OVERRIDE; return c }(), false},
	} {
		taskCreds = func(int) (sys.TaskCreds, error) { return c.creds, nil }
		opened = nil
		img, err := sysKernel{}.ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: c.path, joined: c.path, head: true})
		if c.refused {
			if !errors.Is(err, unix.EACCES) || len(opened) != 0 {
				t.Errorf("%s: %v, reopened %v; want EACCES and no open", c.name, err, opened)
			}
			continue
		}
		if err != nil || img.head == nil || len(opened) != 1 {
			t.Errorf("%s: %v, head %q, reopened %v; want the head read once", c.name, err, img.head, opened)
		}
	}
	// A query that asks for no head is never refused here: a run without command rules leaves the exec to the
	// kernel as before.
	p := filepath.Join(dir, "plain")
	if _, err := (sysKernel{}).ExecImage(pathQuery{tid: tid, dirfd: atFDCWD, path: p, joined: p}); err != nil {
		t.Errorf("no head asked: %v", err)
	}
}
