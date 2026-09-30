// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gateAnchor holds Append until release is closed, standing in for a Close still between run_end and the anchor.
type gateAnchor struct {
	*memAnchor
	entered chan struct{}
	release chan struct{}
}

func (a *gateAnchor) Append(run, head string) error {
	close(a.entered)
	<-a.release
	return a.memAnchor.Append(run, head)
}

// TestVerifyWaitsForAClosingRun: Close holds the run lock until the anchor line is written, so an ended
// ledger with no line and a held lock is a run that is closing, not E29. Verify waits for the line, and
// past closeWait reports ErrRunClosing, never ErrUnverified.
func TestVerifyWaitsForAClosingRun(t *testing.T) {
	mem := &memAnchor{}
	g := &gateAnchor{memAnchor: mem, entered: make(chan struct{}), release: make(chan struct{})}
	dir := filepath.Join(t.TempDir(), "runs", testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(g))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	done := make(chan error, 1)
	go func() { done <- w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()
	<-g.entered

	old := closeWait
	defer func() { closeWait = old }()
	closeWait = 30 * time.Millisecond
	_, err = verifyErr(t, dir, mem)
	if !errors.Is(err, ErrRunClosing) || errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify of a closing run = %v, want ErrRunClosing and not ErrUnverified", err)
	}

	closeWait = 10 * time.Second
	time.AfterFunc(100*time.Millisecond, func() { close(g.release) })
	rep, err := verifyErr(t, dir, mem)
	if err != nil || !rep.Anchored {
		t.Fatalf("Verify across Close = %+v, %v, want anchored", rep, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Close: %v", err)
	}
}
