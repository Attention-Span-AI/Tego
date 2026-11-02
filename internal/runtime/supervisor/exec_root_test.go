// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// walkAllKernel is the fake kernel with every exec walk, the exec's own and those of its #! interpreters and a loader's
// program, made by sysKernel itself from this process's root: the descriptors a run's decision opens are opened.
type walkAllKernel struct{ selfKernel }

func (k walkAllKernel) ExecImage(q pathQuery) (execImage, error) { return k.sys.ExecImage(q) }

// notifAt is e as an execveat from dirfd with flags.
func (e *liveExec) notifAt(nr int32, dirfd, flags int) *notif {
	return notifFor(nr, os.Getpid(), uint64(dirfd), uint64(uintptr(unsafe.Pointer(&e.path[0]))),
		uint64(uintptr(unsafe.Pointer(&e.ptrs[0]))), 0, uint64(flags))
}

// TestExecHeldRootClosedAfterEachExec pins that an exec's decision closes every descriptor it opened, in a run with
// command rules the task's root it holds for all of its walks (taskRoot) above all: recordExec's deferred close is the
// only one, and without it each exec left one O_PATH descriptor open, which a long run spends until the supervisor can
// open nothing (on work/EXEC-PERF). Each exec is decided many times, at tier landlock (the
// one-call lookup, lookupInOne) and with search checks (the component walk), along every path that opens the root: an
// absolute #! script, whose own walk opens it and whose interpreter's walk reuses it; the same script by descriptor
// (execveat AT_EMPTY_PATH), where the interpreter's walk opens it; a directly-invoked loader, whose program's walk
// reuses it; a plain image; and the walk's other shapes and failures (a relative path through a symlink, a ".." path,
// a magic link, a missing file, a symlink loop, a final symlink not followed).
func TestExecHeldRootClosedAfterEachExec(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "s")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	loader := filepath.Join(dir, "ld-linux-x86-64.so.2") // a loader by its name (execmatch.LoaderName)
	if err := os.Symlink(self, loader); err != nil {
		t.Fatal(err)
	}
	link, loop := filepath.Join(dir, "link"), filepath.Join(dir, "loop")
	if err := os.Symlink("s", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	sfd, err := unix.Open(script, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sfd) //nolint:errcheck // an O_PATH descriptor of the test's own
	dfd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd) //nolint:errcheck // an O_PATH descriptor of the test's own

	execve, execveat := nrFor(t, "execve"), nrFor(t, "execveat")
	scriptExec := newLiveExec(script, []string{"s", "a"})
	byFD := newLiveExec("", []string{"s", "a"})
	loaded := newLiveExec(loader, []string{"ld", self, "-test.run=none"})
	plain := newLiveExec(self, []string{"t", "-test.run=none"})
	relative := newLiveExec("link", []string{"s"})
	dotdot := newLiveExec(dir+"/../"+filepath.Base(dir)+"/link", []string{"s"})
	missing := newLiveExec(filepath.Join(dir, "none"), []string{"none"})
	looped := newLiveExec(loop, []string{"loop"})
	nofollow := newLiveExec(link, []string{"s"})
	magic := newLiveExec("/proc/self/fd/"+strconv.Itoa(sfd), []string{"s"})
	cases := []struct {
		name string
		n    func() *notif
		// errno is what a run with command rules answers the exec, and without what a run without them does: 0
		// continues it.
		errno, without unix.Errno
	}{
		{"script", func() *notif { return scriptExec.notif(execve) }, 0, 0},
		{"script by descriptor", func() *notif { return byFD.notifAt(execveat, sfd, unix.AT_EMPTY_PATH) }, 0, 0},
		{"loader", func() *notif { return loaded.notif(execve) }, 0, 0},
		{"plain", func() *notif { return plain.notif(execve) }, 0, 0},
		{"relative through a symlink", func() *notif { return relative.notifAt(execveat, dfd, 0) }, 0, 0},
		{"dot-dot", func() *notif { return dotdot.notif(execve) }, 0, 0},
		{"missing", func() *notif { return missing.notif(execve) }, unix.ENOENT, unix.ENOENT},
		{"symlink loop", func() *notif { return looped.notif(execve) }, unix.ELOOP, 0},
		{"final symlink not followed", func() *notif {
			return nofollow.notifAt(execveat, atFDCWD, unix.AT_SYMLINK_NOFOLLOW)
		}, unix.ELOOP, 0},
		{"magic link", func() *notif { return magic.notif(execve) }, 0, 0},
	}
	prev := searchChecked
	t.Cleanup(func() { searchChecked = prev })
	for _, run := range []struct {
		name  string
		rules bool
	}{{"with command rules", true}, {"without", false}} {
		for _, checked := range []bool{false, true} {
			searchChecked = func() bool { return checked }
			pol := contractPolicy(&agent.Contract{Exec: &agent.ExecSection{Deny: []string{}}}, nil, nil)
			if run.rules {
				pol = commandPolicy(t, "deny: git push")
			}
			pol.Record = agent.RecordOff
			k := walkAllKernel{selfKernel{fakeKernel: newFake()}}
			l, err := New(testListener(), pol, &testSink{}, Options{kernel: k, Workers: 1})
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cases {
				l.handle(c.n())
				// Answered as the case says, so its walks were made.
				want := c.errno
				if !run.rules {
					want = c.without
				}
				if got, ok := k.lastResp(); !ok || (got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0) != (want == 0) ||
					want != 0 && got.Error != -int32(want) {
					t.Fatalf("%s, search checked %v, %s: response %+v, want errno %d (0: continued)", run.name, checked,
						c.name, got, want)
				}
				const execs = 64
				before := openFDs(t)
				for range execs {
					l.handle(c.n())
				}
				after := openFDs(t)
				// Anything else the test process opens meanwhile is far fewer than one descriptor an exec.
				if after-before >= execs/2 {
					t.Errorf("%s, search checked %v, %s: %d execs left %d more descriptors open (%d before, %d after)",
						run.name, checked, c.name, execs, after-before, before, after)
				}
			}
		}
	}
	for _, e := range []*liveExec{scriptExec, byFD, loaded, plain, relative, dotdot, missing, looped, nofollow, magic} {
		runtime.KeepAlive(e)
	}
}
