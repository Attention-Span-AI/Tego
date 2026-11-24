// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os/exec"
	"testing"
	"time"
)

// TestMinOfTreeSeesAnOrphanedDescendant: the CPU time of a process that a short launcher started and left (the worker of
// rulesview.InForce is one: it is nobody's child once its launcher has exited) is in the figure, and the thread's own
// clock sees none of it.
func TestMinOfTreeSeesAnOrphanedDescendant(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	launch := func() { // the launcher exits at once; its child burns about 50 to 150 ms of CPU in a shell loop
		cmd := exec.Command("sh", "-c", "(i=0; while [ $i -lt 40000 ]; do i=$((i+1)); done) &")
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	}
	var thread []time.Duration
	got := MinOfTree(2, func() { thread = MinOf(ThreadCPU, 1, launch) })[0]
	if got.CPU < 10*time.Millisecond {
		t.Fatalf("an orphaned descendant spent its CPU in a shell loop: tree CPU %v, want at least 10ms (wall %v)", got.CPU, got.Wall)
	}
	if thread[0] > 5*time.Millisecond {
		t.Fatalf("the thread's own clock read %v for starting a launcher: the contrast this test relies on is gone", thread[0])
	}
	if idle := MinOfTree(2, func() {})[0]; idle.CPU > 5*time.Millisecond {
		t.Fatalf("an empty round read %v of CPU", idle.CPU)
	}
	if kids := childPIDs(); len(kids) != 0 {
		t.Fatalf("children left after the measurement: %v", kids)
	}
}
