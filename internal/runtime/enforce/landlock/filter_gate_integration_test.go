// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestWriteGateNotifiesChmodOnRealKernel installs the filter Prepare builds for a run under the default record
// level on a poisoned thread, with no listener, and changes a file's mode: under an fs.write gate the family is
// notified, so with no listener fchmodat and fchmod get ENOSYS and the mode stays; with no gate the kernel
// performs both. Before, the gated run's filter let the kernel change the mode with no gate decision and no line,
// as the ungated run's does (TestWriteGateNotifiesTheChmodFamilyUnderEveryRecordLevel is the same on both arches).
func TestWriteGateNotifiesChmodOnRealKernel(t *testing.T) {
	write, err := gate.New([]gate.Rule{{Predicate: gate.WriteOutsideWorktree, Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		gate *gate.Policy
		want error
		mode os.FileMode
	}{
		{"write gate", write, unix.ENOSYS, 0o600},
		{"no gate", nil, nil, 0o777},
	} {
		h, _ := prepare(t, 7, &agent.RuleTable{Contract: &agent.Contract{}, Gate: tc.gate, Record: agent.RecordSummary})
		prog, ok := h.SeccompFilter()
		if !ok {
			t.Fatal("no seccomp filter")
		}
		dir := t.TempDir()
		byPath, byFD := filepath.Join(dir, "by-path"), filepath.Join(dir, "by-fd")
		for _, p := range []string{byPath, byFD} {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		f, err := os.Open(byFD)
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			fchmodat, fchmod error
			installed        bool
		}
		done := make(chan result, 1)
		go func() {
			runtime.LockOSThread() // deliberately never unlocked: the filter cannot be removed
			var out result
			if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
				done <- out
				return
			}
			if err := setFilterNoListener(prog); err != nil {
				done <- out
				return
			}
			out.installed = true
			out.fchmodat = unix.Fchmodat(unix.AT_FDCWD, byPath, 0o777, 0) // fchmodat(2): flags 0
			out.fchmod = unix.Fchmod(int(f.Fd()), 0o777)
			done <- out
			runtime.Goexit()
		}()
		got := <-done
		_ = f.Close()
		if !got.installed {
			t.Skip("could not install a seccomp filter on this thread")
		}
		for _, c := range []struct {
			call string
			err  error
			path string
		}{{"fchmodat", got.fchmodat, byPath}, {"fchmod", got.fchmod, byFD}} {
			if !errors.Is(c.err, tc.want) {
				t.Errorf("%s: %s returned %v, want %v", tc.name, c.call, c.err, tc.want)
			}
			st, err := os.Stat(c.path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != tc.mode {
				t.Errorf("%s: after %s the mode is %v, want %v", tc.name, c.call, st.Mode().Perm(), tc.mode)
			}
		}
	}
}
