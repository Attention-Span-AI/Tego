// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestIOUringAtTheFallbackIsATestBuildsAlone is A-0018-5: io_uring stays ENOSYS on the fanotify fallback in a product
// build, whatever the contract declares, because cgroup/sock_create sees inet sockets only and the fallback has no hook
// for the rest of a submission. Only the test seam (a -tags tegotesthooks build's TEGO_TEST_FALLBACK_IOURING) admits
// it there, to prove the backstop; it never changes a plane-mode run's answer.
func TestIOUringAtTheFallbackIsATestBuildsAlone(t *testing.T) {
	defer func(was func() bool) { fallbackIOUringTestHook = was }(fallbackIOUringTestHook)
	defer func(was func() bool) { ioUringDecided = was }(ioUringDecided)
	rows := &decide.PlaneRows{}
	for _, tc := range []struct {
		name          string
		hook, decided bool
		rows          *decide.PlaneRows
		want          bool
	}{
		{"product build, fanotify fallback", false, true, nil, false},
		{"product build, a plane mode", false, true, rows, true},
		{"product build, a plane mode that does not decide submissions", false, false, rows, false},
		{"test hook, fanotify fallback", true, true, nil, true},
		{"test hook, a plane mode that does not decide submissions", true, false, rows, false},
	} {
		fallbackIOUringTestHook = func() bool { return tc.hook }
		ioUringDecided = func() bool { return tc.decided }
		if got := inheritedRun(cgroupenforce.Run{PlaneRows: tc.rows}).IOUring; got != tc.want {
			t.Errorf("%s: IOUring = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestIOUringWarningNamesTheFallbacksResidual: the warning a contract with io_uring: true gets where io_uring stays
// refused names why it is not admitted on the fanotify fallback, not only where it would be: cgroup/sock_create
// decides inet sockets alone, so an IORING_OP_SOCKET of another family, a unix name below 6.7 and an fs operation only
// the supervisor decides would pass a submission undecided. A test build whose seam admits io_uring there says that
// it did, and what goes undecided.
func TestIOUringWarningNamesTheFallbacksResidual(t *testing.T) {
	defer func(was func() bool) { fallbackIOUringTestHook = was }(fallbackIOUringTestHook)
	rt := table(backend.TierCgroup, "cgroup")
	rt.Contract.IOUring = true
	fallbackIOUringTestHook = func() bool { return false }
	d, ok := ioUringIgnored(rt, "agent.yaml", backend.TierCgroup, false)
	if !ok {
		t.Fatal("no warning on the fanotify fallback")
	}
	for _, want := range []string{"stays refused (ENOSYS)", "IORING_OP_SOCKET", "cgroup/sock_create", "6.7", "supervisor"} {
		if !strings.Contains(d.Message, want) {
			t.Errorf("the warning does not name %q: %s", want, d.Message)
		}
	}
	fallbackIOUringTestHook = func() bool { return true }
	d, ok = ioUringIgnored(rt, "agent.yaml", backend.TierCgroup, false)
	if !ok || !strings.Contains(d.Message, "TEGO_TEST_FALLBACK_IOURING") || strings.Contains(d.Message, "stays refused") ||
		!strings.Contains(d.Message, "IORING_OP_SOCKET") {
		t.Errorf("the test build's warning: %+v, %v", d, ok)
	}
	if _, ok := ioUringIgnored(rt, "agent.yaml", backend.TierCgroup, true); ok {
		t.Error("a plane mode that holds the contract is warned")
	}
}

// TestIOUringWarningAgreesWithTheRunWhenThePlaneCannotHoldIt: a plane mode is selected but
// cannot hold the table, so the run decides on the fanotify listener with no plane rows. There a test build's seam
// admits io_uring (inheritedRun), and the warning has to say so; it said io_uring stayed refused (ENOSYS). Without
// the seam the warning is unchanged: refused, naming why the plane cannot hold the contract.
func TestIOUringWarningAgreesWithTheRunWhenThePlaneCannotHoldIt(t *testing.T) {
	defer func(was func() bool) { fallbackIOUringTestHook = was }(fallbackIOUringTestHook)
	defer func(was func() bool) { ioUringDecided = was }(ioUringDecided)
	ioUringDecided = func() bool { return true }
	rt := table(backend.TierCgroup, "cgroup")
	rt.Contract.IOUring = true
	rt.Exec = []agent.ExecRule{{Path: "/usr/bin/true", Verdict: agent.VerdictAsk}} // decide.ErrPlaneExecVerdict
	if _, err := holdablePlaneRows(rt); err == nil {
		t.Fatal("precondition: the plane holds a table with an ask exec entry")
	}
	for _, hook := range []bool{true, false} {
		fallbackIOUringTestHook = func() bool { return hook }
		admitted := inheritedRun(cgroupenforce.Run{}).IOUring // the run's plane rows are nil on the listener
		d, ok := ioUringIgnored(rt, "agent.yaml", backend.TierCgroup, true)
		if !ok {
			t.Fatalf("seam %v: no warning", hook)
		}
		saysRefused := strings.Contains(d.Message, "stays refused (ENOSYS)")
		if admitted == saysRefused {
			t.Errorf("seam %v: the run admits io_uring %v, the warning says %q", hook, admitted, d.Message)
		}
		if hook && (!strings.Contains(d.Message, envTestFallbackIOUring) || !strings.Contains(d.Message, "cannot hold")) {
			t.Errorf("seam on: the warning names neither the seam nor why the plane does not decide the run: %q", d.Message)
		}
		if !hook && !strings.Contains(d.Message, "cannot hold this contract") {
			t.Errorf("seam off: the warning does not say the plane cannot hold the contract: %q", d.Message)
		}
	}
}
