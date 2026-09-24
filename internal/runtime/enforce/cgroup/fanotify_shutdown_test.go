// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestListenerRemovesItsMarksBeforeItStopsAnswering is the rule for a listener that is stopping: its marks
// come down before it stops reading, and every event already in the group gets the answer the contract gives
// it. The event here reaches the group as the mark is removed, the way an opener that passed the mark in that
// instant does. A cancelled loop used to stop reading first and remove the marks in Close, after its workers:
// such an event then waited on a group nobody read, and the close released it with an allow nobody decided.
// The kernel side here is one end of a socket pair, so an event nobody answers shows up as a read that times
// out rather than a real opener held on a real mount.
func TestListenerRemovesItsMarksBeforeItStopsAnswering(t *testing.T) {
	t.Parallel()
	s := &sink{}
	refusal := verdict{path: "/home/u/.ssh/id_ed25519", rule: "fs.deny_read[~/.ssh]", reason: record.ReasonReadDenied}
	l, kernelSide := socketpairListener(t, s, func(fanEvent) (verdict, error) { return refusal, nil })
	if err := unix.SetsockoptTimeval(kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}
	late := openFD(t)
	event := metadata(unix.FAN_OPEN_PERM, late, 777, fanMetadataVersion, 0)
	unmarked := make(chan error, 1)
	l.marks["/"] = fanPermMask
	l.unmarkMounts = func() error {
		_, err := unix.Write(kernelSide, event)
		unmarked <- err
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()
	cancel()

	var resp [8]byte
	n, err := readRetrying(kernelSide, resp[:])
	if err := <-unmarked; err != nil {
		t.Fatalf("write the event that raced the mark's removal: %v", err)
	}
	if err != nil || n != 8 {
		t.Fatalf("the event in the group when its mark came down was never answered (%d bytes, %v): the "+
			"listener stopped reading before it removed its marks", n, err)
	}
	if fd := int32(binary.NativeEndian.Uint32(resp[0:4])); fd != late {
		t.Fatalf("answered descriptor %d, want %d", fd, late)
	}
	if got := binary.NativeEndian.Uint32(resp[4:8]); got != unix.FAN_DENY {
		t.Fatalf("answered %#x, want the refusal the contract decided (FAN_DENY), not an allow nobody decided", got)
	}
	select {
	case err := <-loopErr:
		if err != nil {
			t.Fatalf("loop() after cancellation = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop() did not return after its context was cancelled")
	}
	if len(l.marks) != 0 {
		t.Fatalf("marks %v left after the loop returned", l.marked())
	}
	if _, refused, _, _ := l.stats(); refused != 1 {
		t.Fatalf("refused %d, want the one refusal the drain decided", refused)
	}
}
