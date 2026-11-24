// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"
)

func TestContractsRegistryCancelledBeforeRead(t *testing.T) {
	l := newLayout(t)
	l.write(l.user, "agents/a.yaml", "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entries, roots := l.places.CatalogContext(ctx)
	if len(entries) != 0 || len(roots) != 1 || !errors.Is(roots[0].Err, context.Canceled) {
		t.Fatalf("read after cancellation: entries %v roots %+v", entries, roots)
	}
}

func TestContractsRegistryStopsAfterBlockedPlacement(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, ProjectFile, "project")
	l.write(l.user, "agents/user.yaml", "user")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		<-entered
		cancel()
	}()
	called := false
	entries, roots := l.places.catalogContext(ctx, func(p Places) (Places, *Error) {
		called = true
		close(entered)
		// A placement syscall may return only after caller cancellation.
		// Once it does, no following source-read phase may start.
		<-ctx.Done()
		return p, nil
	})
	<-stopped
	if !called || len(entries) != 0 || len(roots) != 1 || !errors.Is(roots[0].Err, context.Canceled) {
		t.Fatalf("continued after placement timeout: called %t, entries %v, roots %+v", called, entries, roots)
	}
}
