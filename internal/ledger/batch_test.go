// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"io"
	"sync"
	"testing"
)

type gatedWrite struct {
	to               io.Writer
	once             sync.Once
	entered, proceed chan struct{}
}

func (g *gatedWrite) Write(b []byte) (int, error) {
	g.once.Do(func() { close(g.entered); <-g.proceed })
	return g.to.Write(b)
}

// Force a competing Append to start after the batch's first write. It must land
// after both lines; each still has its own hash and sequence number.
func TestAppendBatchExcludesCompetingAppend(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	gate := &gatedWrite{to: w.events, entered: make(chan struct{}), proceed: make(chan struct{})}
	w.out = gate
	a, b, c := gapEvent("first"), gapEvent("second"), gapEvent("concurrent")
	batchDone := make(chan error, 1)
	otherDone := make(chan error, 1)
	go func() { batchDone <- w.AppendBatch(a, b) }()
	<-gate.entered
	otherStarted := make(chan struct{})
	go func() { close(otherStarted); otherDone <- w.Append(c) }()
	<-otherStarted
	close(gate.proceed)
	if err := <-batchDone; err != nil {
		t.Fatal(err)
	}
	if err := <-otherDone; err != nil {
		t.Fatal(err)
	}
	if b.Seq != a.Seq+1 || c.Seq != b.Seq+1 {
		t.Fatalf("batch seqs %d,%d, competing seq %d", a.Seq, b.Seq, c.Seq)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if got := len(readAll(t, dir)); got != 5 {
		t.Fatalf("lines=%d, want 5", got)
	}
}

type failSecondWrite struct {
	to io.Writer
	n  int
}

func (f *failSecondWrite) Write(b []byte) (int, error) {
	f.n++
	if f.n == 2 {
		return 0, errors.New("second line refused")
	}
	return f.to.Write(b)
}

func TestAppendBatchFailureKeepsOnlyWrittenPrefix(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	w.out = &failSecondWrite{to: w.events}
	a, b := gapEvent("first"), gapEvent("second")
	if err := w.AppendBatch(a, b); err == nil {
		t.Fatal("second write failure was lost")
	}
	w.out = w.events
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, dir)
	if len(got) != 3 || got[1].ID != a.ID || got[2].Prev != a.ID {
		t.Fatal("batch failure left something other than its written prefix")
	}
}
