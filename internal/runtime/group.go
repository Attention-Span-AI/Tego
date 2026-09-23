// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"sync"
)

// group is the worker set of one run: every goroutine Run starts is started here and joined by Wait,
// none is fire-and-forget (docs/p0/runtime-launch.md §9 "Goroutine ownership"). It implements the
// errgroup.WithContext contract the design names (P0-DESIGN §2.4, §6) over the standard library, so
// internal/runtime adds no module dependency: the first member to fail records its error, cancels the
// group's context and so stops every other member, and Wait reports that first error.
type group struct {
	cancel context.CancelFunc

	wg   sync.WaitGroup
	once sync.Once
	mu   sync.Mutex
	err  error
}

// newGroup returns a group and the context its members must use; cancelling it stops them all.
func newGroup(parent context.Context) (*group, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	return &group{cancel: cancel}, ctx
}

// Go starts fn as a member called name. A non-nil error from the first failing member is kept,
// wrapped with the member's name, and cancels the group; later errors are dropped.
func (g *group) Go(name string, fn func() error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if err := fn(); err != nil {
			g.once.Do(func() {
				g.mu.Lock()
				g.err = fmt.Errorf("%s: %w", name, err)
				g.mu.Unlock()
				g.cancel()
			})
		}
	}()
}

// Wait blocks until every member has returned, then cancels the group's context (so a member that
// leaked a child context is released too) and reports the first error. Safe to call once.
func (g *group) Wait() error {
	g.wg.Wait()
	g.cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Err reports the first member's error without waiting, nil while every member is healthy.
func (g *group) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Cancel stops every member without waiting; Wait still reports the first error.
func (g *group) Cancel() { g.cancel() }
