// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"slices"
	"strings"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"golang.org/x/sys/unix"
)

func TestPlaneControlOwnedSocketAndPtraceFixtures(t *testing.T) {
	pre := planeMakeEach
	if err := pre.prepareControls(); err != nil {
		pre.closeControls()
		t.Fatal(err)
	}
	defer pre.closeControls()
	for _, hook := range []string{"socket_bind", "socket_listen", "ptrace_access_check", "ptrace_traceme"} {
		if err := planeControlAction(hook, pre); err != nil {
			t.Errorf("outside the governed cgroup %s: %v", hook, err)
		}
	}
	if pre.keyErr == nil {
		if err := planeControlAction("key_permission", pre); err != nil {
			t.Errorf("outside the governed cgroup key_permission: %v", err)
		}
	} else {
		t.Logf("private key fixture unavailable here: %v; other control fixtures still exercised", pre.keyErr)
	}
	// A successful listen must have changed the actual socket's state.
	if accepting, err := unix.GetsockoptInt(pre.listening, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || accepting != 1 {
		t.Fatalf("listen fixture did not actually listen: %d %v", accepting, err)
	}
}

// TestPlaneKeyFixtureFailureIsAFault: an error made while preparing the key (the thread race of 2026-11-24, another
// LSM, a seccomp profile) is not the key_permission hook's answer. Read as EACCES it was "refused": on the inside leg
// the hook was never exercised and the row could pass by accident. It is a fault now: the row is not OK and the mode
// is Faulted, so the run-probe cache keeps nothing, with the errno named in the detail.
func TestPlaneKeyFixtureFailureIsAFault(t *testing.T) {
	for _, tc := range []struct {
		name string
		pre  planePre
	}{
		{"the child's key failed to prepare", func() planePre {
			p := planeMakeEach
			p.keyErr = unix.EACCES
			return p
		}()},
	} {
		err := planeControlAction("key_permission", tc.pre)
		if err == nil || errors.Is(err, unix.EACCES) {
			t.Fatalf("%s: err %v, want an error that is not an EACCES the outcome reads as a refusal", tc.name, err)
		}
		out := planeOutcome(err)
		if out == planeRefused || out == planePassed || !planeOutcomeFaulted(out) {
			t.Errorf("%s: outcome %q, want a faulted failure", tc.name, out)
		}
		if !strings.Contains(out, "key fixture") || !strings.Contains(out, unix.EACCES.Error()) {
			t.Errorf("%s: outcome %q does not name the key fixture and the errno", tc.name, out)
		}
		// The hook-deciding row on either leg: inside is the fixture's failure, outside passed.
		rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
		i := slices.IndexFunc(rows, func(r HookResult) bool { return strings.HasSuffix(r.Hook, "key_permission") })
		if i < 0 {
			t.Fatalf("no key_permission row in %d rows", len(rows))
		}
		rows[i].Inside = out
		v := planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, passingKnown())
		if v.OK || !v.Faulted {
			t.Errorf("%s: verdict OK %v Faulted %v, want a faulted mode that is not OK", tc.name, v.OK, v.Faulted)
		}
		rows[i].Inside, rows[i].Outside = planeRefused, out
		if v := planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, passingKnown()); v.OK || !v.Faulted {
			t.Errorf("%s (outside leg): verdict OK %v Faulted %v, want a faulted mode that is not OK", tc.name, v.OK, v.Faulted)
		}
	}
}

// TestPlaneFixtureErrIsNeverRefused: every fixture step's error leaves the errno out of the chain, so EACCES reads
// as a fault; ENOSYS and EOPNOTSUPP keep the kernel's repeated answer, a failed mode.
func TestPlaneFixtureErrIsNeverRefused(t *testing.T) {
	for _, tc := range []struct {
		errno   unix.Errno
		faulted bool
	}{
		{unix.EACCES, true}, {unix.EPERM, true}, {unix.EDQUOT, true}, {unix.EMFILE, true},
		{unix.ENOSYS, false}, {unix.EOPNOTSUPP, false},
	} {
		err := planeFixtureErr("socket fixture", tc.errno)
		out := planeOutcome(err)
		if out == planeRefused || out == planePassed || errors.Is(err, tc.errno) {
			t.Errorf("%v: outcome %q, errno in the chain %v", tc.errno, out, errors.Is(err, tc.errno))
		}
		if got := planeOutcomeFaulted(out); got != tc.faulted {
			t.Errorf("%v: faulted %v, want %v (%q)", tc.errno, got, tc.faulted, out)
		}
		if !strings.Contains(out, tc.errno.Error()) {
			t.Errorf("%v: outcome %q does not name the errno", tc.errno, out)
		}
	}
}

// TestPlaneFixtureFaultFix: a mode Faulted because doctor's own side could not prepare a fixture says so in its fix:
// the hook, the leg, the step and the errno, what to check, and that nothing is cached. It must not tell the user to
// wait for room the host has, which is the fix of a probe syscall that ran out of space or descriptors.
func TestPlaneFixtureFaultFix(t *testing.T) {
	fixture := planeOutcome(planeFixtureErr("socket fixture", unix.EACCES))
	if !planeOutcomeFixture(fixture) || !planeOutcomeFaulted(fixture) {
		t.Fatalf("outcome %q: fixture %v faulted %v, want both", fixture, planeOutcomeFixture(fixture), planeOutcomeFaulted(fixture))
	}
	for _, o := range []string{planePassed, planeRefused, "failed: " + unix.EMFILE.Error(), "failed: " + unix.EACCES.Error()} {
		if planeOutcomeFixture(o) {
			t.Errorf("outcome %q read as a fixture failure", o)
		}
	}
	for _, leg := range []string{"inside", "outside"} {
		rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
		i := slices.IndexFunc(rows, func(r HookResult) bool { return strings.HasSuffix(r.Hook, "socket_bind") })
		if i < 0 {
			t.Fatalf("no socket_bind row")
		}
		if leg == "inside" {
			rows[i].Inside = fixture
		} else {
			rows[i].Outside = fixture
		}
		v := planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, passingKnown())
		if v.OK || !v.Faulted {
			t.Fatalf("%s leg: OK %v Faulted %v, want a faulted mode", leg, v.OK, v.Faulted)
		}
		for _, want := range []string{"socket_bind", "socket fixture", unix.EACCES.Error(), "never exercised", "Nothing is cached"} {
			if !strings.Contains(v.Fix, want) {
				t.Errorf("%s leg: fix %q lacks %q", leg, v.Fix, want)
			}
		}
		if strings.Contains(v.Fix, "to spare") || strings.Contains(v.Fix, "the host has") {
			t.Errorf("%s leg: fix %q blames the host's room", leg, v.Fix)
		}
		if !strings.Contains(v.Fix, map[string]string{"inside": "inside the scratch cgroup", "outside": "outside it"}[leg]) {
			t.Errorf("%s leg: fix %q does not name the leg", leg, v.Fix)
		}
	}
	// A syscall's own errno keeps the room text; a fixture and such a row together carry both.
	rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
	rows[0].Inside = "failed: " + unix.EMFILE.Error()
	v := planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, passingKnown())
	if !v.Faulted || !strings.Contains(v.Fix, "to spare") || strings.Contains(v.Fix, "never exercised") {
		t.Errorf("syscall errno: faulted %v fix %q, want the room text alone", v.Faulted, v.Fix)
	}
	rows[1].Outside = fixture
	v = planeModeVerdict(bpfobj.PlaneLSM, rows, planeScope{Inside: 1}, passingKnown())
	if !strings.Contains(v.Fix, "never exercised") || !strings.Contains(v.Fix, "to spare") {
		t.Errorf("fixture and syscall errno: fix %q, want both texts", v.Fix)
	}
}
