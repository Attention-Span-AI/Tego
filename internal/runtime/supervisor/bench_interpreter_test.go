// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// BenchmarkExecImageInterpreterLookup is what a #! exec's lookups cost on the real kernel, where
// BenchmarkExecCommandCost's #! case fakes the interpreter's walk: the script's own walk with its head read, and the
// walk of its interpreter (/bin/sh, and the symlink chain a distribution's /bin/sh may be), each as this process's
// lookup at tier landlock (no search check) by lookupInOne's two openat2 calls and by the component walk. Nothing is
// faked but the task: it is this thread, so the walk is what a supervisor pays for a task whose root and view are its
// own.
func BenchmarkExecImageInterpreterLookup(b *testing.B) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	script := filepath.Join(b.TempDir(), "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		b.Fatal(err)
	}
	prevChecked, prevOn := searchChecked, lookupInOneOn
	b.Cleanup(func() { searchChecked, lookupInOneOn = prevChecked, prevOn })
	searchChecked = func() bool { return false }
	for _, one := range []bool{true, false} {
		walk := "component_walk"
		if one {
			walk = "one_call"
		}
		for _, c := range []struct {
			name, path string
			head       bool
		}{{"script_with_head", script, true}, {"interpreter_bin_sh", "/bin/sh", false}, {"interpreter_usr_bin_env", "/usr/bin/env", false}} {
			b.Run(walk+"/"+c.name, func(b *testing.B) {
				if _, err := os.Stat(c.path); err != nil {
					b.Skip(err)
				}
				lookupInOneOn = one
				tid := unix.Gettid()
				q := pathQuery{tid: tid, dirfd: atFDCWD, path: c.path, joined: c.path, head: c.head}
				if _, err := (sysKernel{}).ExecImage(q); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					_, _ = sysKernel{}.ExecImage(q)
				}
			})
		}
	}
}
