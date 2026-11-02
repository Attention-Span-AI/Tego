// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestFilterNumbersAreTheKernels checks every syscall number the filter's tables hold (x86Table, arm64Table,
// enosysSet), named lists and scalar fields alike, against golang.org/x/sys's generated tables
// (testutil.LinuxSyscalls). The tables are hand-typed and the goldens are written from them, and no kernel test
// runs the arm64 numbers, so a typo that lands on another dispatched syscall (arm64 mkdirat typed 33, mknodat)
// passed TestEveryNotifiedSyscallHasAHandler. ClientDeny is the same: the strict-client tests issue and simulate
// the table's own numbers, so recvmsg typed 48 passed them while the real recvmsg stayed allowed and
// NetworkGuarantees still reported socket imports denied. The supervisor's TestDispatchNumbersAreTheKernels
// checks its own constants against the same source, so the filter and the supervisor agree per syscall name.
func TestFilterNumbersAreTheKernels(t *testing.T) {
	for _, c := range []struct {
		tab    archTable
		goarch string
	}{{x86Table, "amd64"}, {arm64Table, "arm64"}} {
		canon, err := testutil.LinuxSyscalls(c.goarch)
		if err != nil {
			t.Fatal(err)
		}
		check := func(where, name string, nr uint32) {
			t.Helper()
			want, ok := canon[name]
			switch {
			case !ok && nr == noSyscall:
			case !ok:
				t.Errorf("%s %s: %s = %d, and %s has no such syscall", c.goarch, where, name, nr, c.goarch)
			case nr != want:
				t.Errorf("%s %s: %s = %d, the kernel's number is %d", c.goarch, where, name, nr, want)
			}
		}
		tab := c.tab
		for where, list := range map[string][]sysNR{
			"ENOSYS": tab.ENOSYS, "Notify": tab.Notify, "Chmod": tab.Chmod, "Attr": tab.Attr, "Signal": tab.Signal,
			"RootDeny": tab.RootDeny, "TaskArg0": tab.TaskArg0, "ClientDeny": tab.ClientDeny, "enosysSet": enosysSet,
			"landlockSet": landlockSet, "Frames": tab.Frames, "Watch": tab.Watch,
		} {
			if len(list) == 0 {
				t.Errorf("%s %s is empty", c.goarch, where)
			}
			for _, s := range list {
				check(where, s.Name, s.NR)
			}
		}
		for name, nr := range map[string]uint32{
			"ioctl": tab.Ioctl, "sendto": tab.SendTo, "open": tab.Open, "openat": tab.OpenAt,
			"truncate": tab.Truncate, "socket": tab.Socket, "socketpair": tab.Pair,
			"bind": tab.Bind, "listen": tab.Listen, "setsockopt": tab.Setsockopt,
			"pidfd_send_signal": tab.PidfdSignal, "fcntl": tab.Fcntl, "prlimit64": tab.Prlimit,
			"setpriority": tab.Setpriority, "ioprio_set": tab.IoprioSet, "unshare": tab.Unshare,
			"clone": tab.Clone, "setns": tab.Setns, "memfd_create": tab.Memfd,
		} {
			check("field", name, nr)
		}
		// A field this test does not name would go unchecked: the counts are pinned so a new one is added here.
		if nrs, lists := countNRFields(); nrs != 19 || lists != 10 {
			t.Errorf("archTable has %d uint32 and %d []sysNR fields, this test names 19 and 10: add the new one", nrs, lists)
		}
	}
}

// countNRFields counts archTable's uint32 fields (each one syscall number) and its []sysNR fields.
func countNRFields() (nrs, lists int) {
	rt := reflect.TypeFor[archTable]()
	for i := range rt.NumField() {
		switch rt.Field(i).Type {
		case reflect.TypeFor[uint32]():
			nrs++
		case reflect.TypeFor[[]sysNR]():
			lists++
		}
	}
	return nrs, lists
}
