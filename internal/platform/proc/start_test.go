// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestStartRefusesWhileArmed is ADR 0021 (3)'s guard: while any arm is held, Start forks nothing and says
// ErrArmed; arms nest; disarm is idempotent; once the last is released, Start starts again.
func TestStartRefusesWhileArmed(t *testing.T) {
	disarm1 := Arm()
	disarm2 := Arm()
	if !Armed() {
		t.Fatal("Armed() = false with two arms held")
	}
	cmd := Command("true")
	if _, err := Start(cmd); !errors.Is(err, ErrArmed) {
		t.Fatalf("Start while armed = %v, want ErrArmed", err)
	}
	if cmd.Process != nil {
		t.Fatalf("Start while armed started pid %d", cmd.Process.Pid)
	}
	disarm1()
	disarm1() // idempotent: must not release the second arm
	if !Armed() {
		t.Fatal("one disarm called twice released the other arm")
	}
	if _, err := Start(Command("true")); !errors.Is(err, ErrArmed) {
		t.Fatalf("Start with one arm left = %v, want ErrArmed", err)
	}
	disarm2()
	if Armed() {
		t.Fatal("Armed() = true after every disarm")
	}
	cmd = Command("true")
	id, err := Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if id.PID != cmd.Process.Pid || id.StartBootNS == 0 {
		t.Fatalf("identity %+v, started pid %d", id, cmd.Process.Pid)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

// TestArmWaitsForAStartInFlight: a start that passed the check holds the gate until its fork and exec are over,
// so Arm returns only once it has, and the first mark an armer places never meets a vfork in flight.
func TestArmWaitsForAStartInFlight(t *testing.T) {
	gate.RLock() // stands in for a start between its check and the end of its exec
	armed := make(chan func())
	go func() { armed <- Arm() }()
	select {
	case d := <-armed:
		gate.RUnlock()
		d()
		t.Fatal("Arm returned while a start was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	gate.RUnlock()
	(<-armed)()
}

// TestIdentityNamesOneProcessAcrossPidReuse: a pid kept with its start time is told from the same number
// reissued to a process that started later (SameProcess on the two starts), and from a pid with no process at
// all (ErrGone). Nothing is signalled.
//
// Also pins runtime-launch.md E19: the start time is /proc's starttime field, CLOCK_BOOTTIME-relative.
func TestIdentityNamesOneProcessAcrossPidReuse(t *testing.T) {
	f := fakeProc(t, 4242, map[string]string{"stat": statLine(4242, "a b) c", 1, 1, 900)}, nil)
	kept, err := f.Identity(4242)
	if err != nil {
		t.Fatal(err)
	}
	if kept != (Identity{PID: 4242, StartBootNS: 900 * NanosPerTick}) {
		t.Fatalf("Identity = %+v", kept)
	}
	// The kernel reissues 4242 to a process that started 5 s later.
	stat := filepath.Join(f.Root(), "4242", "stat")
	if err := os.WriteFile(stat, []byte(statLine(4242, "other", 1, 1, 1400)), 0o644); err != nil {
		t.Fatal(err)
	}
	now, err := f.Identity(4242)
	if err != nil {
		t.Fatal(err)
	}
	if SameProcess(kept.StartBootNS, now.StartBootNS) {
		t.Fatalf("reused pid: %+v and %+v read as one process", kept, now)
	}
	if err := os.RemoveAll(filepath.Join(f.Root(), "4242")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Identity(4242); !errors.Is(err, ErrGone) {
		t.Fatalf("Identity(gone pid) = %v, want ErrGone", err)
	}
}

// TestStartIdentityIsTheChilds: Start's identity is the started child's own stat, read before it could be
// reaped, and it stays readable (a zombie) until the caller waits.
func TestStartIdentityIsTheChilds(t *testing.T) {
	cmd := Command("true")
	id, err := Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	// true has exited by now, most likely; unreaped, its pid still names it.
	time.Sleep(20 * time.Millisecond)
	if now, err := New().Identity(id.PID); err != nil || !SameProcess(now.StartBootNS, id.StartBootNS) {
		t.Fatalf("Identity(unreaped child %d) = %+v, %v; want %+v", id.PID, now, err, id)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	self, err := New().Identity(os.Getpid())
	if err != nil || self.StartBootNS == 0 || self.StartBootNS > id.StartBootNS {
		t.Fatalf("own identity %+v (%v) against the child's %+v", self, err, id)
	}
	if _, err := New().Identity(-1); err == nil {
		t.Fatal("pid -1 has an identity")
	}
}
