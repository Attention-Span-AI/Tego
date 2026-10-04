// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPipelineOutlivesAWorkerFailure: a sibling worker's failure cancels the group's context, and the tree is
// still being killed and reaped; the pipeline keeps reading the queue until shutdown's stopPipeline.
func TestPipelineOutlivesAWorkerFailure(t *testing.T) {
	r := &runner{
		log:     slog.New(slog.DiscardHandler),
		rt:      &agent.RuleTable{Contract: &agent.Contract{Name: "pipe"}},
		queue:   NewQueue(8),
		started: make(chan struct{}),
	}
	sink := &collectSink{}
	r.pipe = newPipeline(r.queue, sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 1, TID: 1, Cgroup: 2}, nil, nil, slog.New(slog.DiscardHandler))
	group, gctx := newGroup(context.Background())
	r.group = group
	r.runPipeline(gctx)
	close(r.started)
	group.Go("worker", func() error { return context.DeadlineExceeded })
	select {
	case <-gctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("group never cancelled")
	}
	select {
	case <-r.pipeDone:
		t.Fatal("pipeline ended with the group's context")
	case <-time.After(200 * time.Millisecond):
	}
	r.stopPipeline()
	select {
	case <-r.pipeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline did not end on stopPipeline")
	}
	_ = group.Wait()
}
