// SPDX-License-Identifier: Apache-2.0

//go:build integration

package proc

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// nsLastPID is the pid the calling pid namespace issued last; the next fork gets the next free one after it.
const nsLastPID = "/proc/sys/kernel/ns_last_pid"

// TestStartIdentityOutlivesPidReuse is Start's identity against the kernel's own pid reuse: a child started
// through Start is reaped, its pid is issued again to another process (ns_last_pid, CONFIG_CHECKPOINT_RESTORE),
// and the identity kept from the first start no longer names a live process, while the new holder's does. Root
// only: writing ns_last_pid needs CAP_SYS_ADMIN (or CAP_CHECKPOINT_RESTORE) over the pid namespace.
func TestStartIdentityOutlivesPidReuse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("reissuing a chosen pid through ns_last_pid needs root: `make vm-root-test`")
	}
	if _, err := os.Stat(nsLastPID); err != nil {
		t.Skipf("no %s (a kernel without CONFIG_CHECKPOINT_RESTORE): %v", nsLastPID, err)
	}
	first := Command("/bin/true")
	kept, err := Start(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	// Two USER_HZ ticks, so the reissued pid's start is past SameProcess's one-tick tolerance.
	time.Sleep(3 * time.Second / TicksPerSecond)

	var again *Cmd
	var now Identity
	for try := 0; try < 2000 && again == nil; try++ {
		if err := os.WriteFile(nsLastPID, []byte(strconv.Itoa(kept.PID-1)), 0); err != nil {
			t.Fatalf("write %s: %v", nsLastPID, err)
		}
		c := Command("/bin/sleep", "300")
		id, err := Start(c)
		if err != nil {
			t.Fatal(err)
		}
		if id.PID == kept.PID {
			again, now = c, id
			t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
			break
		}
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	if again == nil {
		t.Fatalf("pid %d was never reissued", kept.PID)
	}
	if SameProcess(kept.StartBootNS, now.StartBootNS) {
		t.Fatalf("the reissued pid's identity %+v is the first process's %+v", now, kept)
	}
	if cur, err := New().Identity(kept.PID); err != nil || SameProcess(cur.StartBootNS, kept.StartBootNS) ||
		!SameProcess(cur.StartBootNS, now.StartBootNS) {
		t.Fatalf("Identity(pid %d, reissued) = %+v, %v; want the new holder %+v", kept.PID, cur, err, now)
	}
}
