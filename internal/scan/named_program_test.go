// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

// unreadableAs reads the fixture tree with the program file of each pid in hidden refused, as an undumpable process's is.
func unreadableAs(t *testing.T, hidden ...int) func(context.Context, procAccess, string, uint32, []catalog.Row) processSnapshot {
	t.Helper()
	return func(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
		isHidden := func(pid int) bool {
			for _, h := range hidden {
				if h == pid {
					return true
				}
			}
			return false
		}
		spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(pid int, owner uint32, err error) (uint32, error) {
			if isHidden(pid) {
				return 0, nil // a non-dumpable process's proc files belong to root
			}
			return owner, err
		}, linkHook: func(pid int, name, value string, err error) (string, error) {
			if isHidden(pid) && name == "exe" {
				return "", unix.EACCES
			}
			return value, err
		}}
		return readProcesses(ctx, spy, root, uid, rows)
	}
}

// TestCheckDoesNotCountAProvedDashboardAsUnreadable: the dashboard is non-dumpable (it holds secrets), so its program
// file cannot be read and the check counted it among the unreadable programs, which made `tego scan --check` exit 3 on
// every machine where it runs. A caller that proves a process to be the dashboard (Options.NamedProgram) has it left
// out of that count, like a readable process that matches nothing, and the check answers as if it were not unreadable.
// Every other unreadable program stays counted, a name for a process that is not unreadable changes nothing, and
// with no proof nothing changes.
func TestCheckDoesNotCountAProvedDashboardAsUnreadable(t *testing.T) {
	const dashboard, other = 20, 30
	for _, tc := range []struct {
		name   string
		hidden []int
		named  func(home string, pid int) bool
		want   int
		pids   []int
	}{
		{"the dashboard is the only unreadable program and is proved", []int{dashboard}, func(_ string, pid int) bool { return pid == dashboard }, 0, nil},
		{"no proof: it is unreadable, as before", []int{dashboard}, nil, 3, []int{dashboard}},
		{"a proof that names another process", []int{dashboard}, func(_ string, pid int) bool { return pid == 99 }, 3, []int{dashboard}},
		{"a proof that refuses", []int{dashboard}, func(string, int) bool { return false }, 3, []int{dashboard}},
		{"another program the proof does not name", []int{dashboard, other}, func(_ string, pid int) bool { return pid == dashboard }, 3, []int{other}},
		{"the proof names a process whose program file is readable: it is judged as ever (claude, outside)", nil, func(string, int) bool { return true }, 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandOptions(t)
			o.Check = true
			var asked []int
			var home string
			if tc.named != nil {
				o.NamedProgram = func(h string, pid int) bool { home = h; asked = append(asked, pid); return tc.named(h, pid) }
			}
			s := collect(t.Context(), o, unreadableAs(t, tc.hidden...)).Snapshot
			if got := s.ExitCode(); got != tc.want {
				t.Fatalf("exit %d, want %d (check %s, unreadable %v)", got, tc.want, s.Check, s.UnreadableProgramPIDs)
			}
			if len(s.UnreadableProgramPIDs) != len(tc.pids) || s.Counts.UnreadablePrograms != len(tc.pids) {
				t.Fatalf("unreadable programs %v (count %d), want %v", s.UnreadableProgramPIDs, s.Counts.UnreadablePrograms, tc.pids)
			}
			for i, pid := range tc.pids {
				if s.UnreadableProgramPIDs[i] != pid {
					t.Fatalf("unreadable programs %v, want %v", s.UnreadableProgramPIDs, tc.pids)
				}
			}
			for _, pid := range asked {
				hiddenPID := false
				for _, h := range tc.hidden {
					hiddenPID = hiddenPID || h == pid
				}
				if !hiddenPID {
					t.Errorf("the proof was asked about pid %d, whose program file is readable", pid)
				}
			}
			if len(asked) > 0 && home == "" {
				t.Error("the proof was not given the caller's home")
			}
		})
	}
}

// TestAdvancedScopeNeverAsksForAProof: root reads every program file, and an unreadable one there is a coverage gap; the
// proof for the dashboard is basic scope's alone.
func TestAdvancedScopeNeverAsksForAProof(t *testing.T) {
	o := commandOptions(t)
	o.Check, o.Advanced = true, true
	called := false
	o.NamedProgram = func(string, int) bool { called = true; return true }
	_ = Collect(t.Context(), o) // refused as not root before it reads anything; the proof must not run either
	if called {
		t.Fatal("the proof ran in advanced scope")
	}
}
