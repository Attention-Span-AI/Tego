// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// ctxCheckingCgroups records whether the context Remove received was already cancelled.
type ctxCheckingCgroups struct {
	*fakeCgroups
	removeCtxErr error
}

func (c *ctxCheckingCgroups) Remove(ctx context.Context, cg cgroup.Cgroup) error {
	c.removeCtxErr = ctx.Err()
	return c.fakeCgroups.Remove(ctx, cg)
}

// TestShutdownRemovesTheScopeOnACancelledCallerContext pins R18 for an embedder that cancels Run's ctx: the
// scope's removal runs on a context that is not the cancelled one, so its EBUSY retry is not cut short.
func TestShutdownRemovesTheScopeOnACancelledCallerContext(t *testing.T) {
	cgroups := &ctxCheckingCgroups{fakeCgroups: &fakeCgroups{root: t.TempDir()}}
	g, _ := newGroup(context.Background())
	r := &runner{
		log: slog.New(slog.DiscardHandler), group: g,
		cgm: cgroups, cg: cgroup.Cgroup{Path: cgroups.root},
		runtimeDir: t.TempDir(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = r.shutdown(ctx)
	if cgroups.removed != 1 {
		t.Fatalf("cgroup removed %d times, want 1", cgroups.removed)
	}
	if cgroups.removeCtxErr != nil {
		t.Fatalf("Remove got a cancelled context (%v): its retry would give up after one attempt", cgroups.removeCtxErr)
	}
}
