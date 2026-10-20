// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/json"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// errReplyLost is what sys.SeccompNotifAddfdSend returns when the kernel took the notification as answered and
// installed nothing (a stop signal or a freeze inside the ioctl, which blocking signals cannot keep out).
var errReplyLost = fmt.Errorf("ioctl(SECCOMP_IOCTL_NOTIF_ADDFD): %w: %w", sys.ErrNotifReplyLost, unix.EINPROGRESS)

// checkReplyLostLine: nothing answered the notification again, and one human-authorized line says the open was
// performed, the descriptor not delivered and the agent's result unknown, with no syscall_ret.
func checkReplyLostLine(t *testing.T, x *askReadFixture, l *Loop, n *notif, sink *testSink, path string) {
	t.Helper()
	if len(x.f.responses) != 0 {
		t.Fatalf("responses %+v: a notification the kernel holds as answered was answered again", x.f.responses)
	}
	if !n.answered {
		t.Fatal("the notification is not marked answered: a later path could answer it again")
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Kind != record.KindFS || evs[0].Authority != record.AuthorityHuman || evs[0].Verdict != record.VerdictAllow {
		t.Fatalf("lines %+v", evs)
	}
	var p struct {
		Path               string `json:"path"`
		OperationCompleted bool   `json:"operation_completed"`
		FDDelivered        bool   `json:"fd_delivered"`
		ResultUnknown      bool   `json:"result_unknown"`
		SyscallRet         *int64 `json:"syscall_ret"`
	}
	if err := json.Unmarshal(evs[0].Payload, &p); err != nil || p.Path != path || !p.OperationCompleted || p.FDDelivered || !p.ResultUnknown || p.SyscallRet != nil {
		t.Fatalf("the line %s: want operation_completed, not fd_delivered, result_unknown, no syscall_ret", evs[0].Payload)
	}
	if got := l.metrics.orphaned.Load(); got != 1 {
		t.Fatalf("orphaned %d, want 1", got)
	}
}

// An approved held open whose ADDFD|SEND the kernel took as answered without installing the descriptor (custom-agent
// POC, item 5) is not answered again, and its line does not claim a result: before, the loop answered it with the
// ioctl's errno and wrote that errno as syscall_ret, while the agent's open had returned 0.
func TestApprovedOpenWhoseReplyWasLostIsNotAnsweredAgain(t *testing.T) {
	x := newAskReadFixture(t)
	x.k.completeErr = &askOpenDeliveryError{errReplyLost}
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "standing:q-1"} })
	n := x.open(t, l, x.secret, unix.O_RDONLY|unix.O_CLOEXEC)
	checkReplyLostLine(t, x, l, n, sink, x.secret)
}

// The same for an alternate's delivery.
func TestAlternateWhoseReplyWasLostIsNotAnsweredAgain(t *testing.T) {
	x := newAskReadFixture(t)
	x.k.deliverErr = errReplyLost
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return alternateDecision(t, x.standIn) })
	n := x.open(t, l, x.secret, unix.O_RDONLY|unix.O_CLOEXEC)
	checkReplyLostLine(t, x, l, n, sink, x.standIn)
}
