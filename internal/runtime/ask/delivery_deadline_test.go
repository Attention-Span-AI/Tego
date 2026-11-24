// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalRolesDeadlineDuringFinalAuthorityRead(t *testing.T) {
	for _, approve := range []bool{true, false} {
		name := "approve"
		if !approve {
			name = "deny"
		}
		t.Run(name, func(t *testing.T) {
			entered, resume := make(chan struct{}), make(chan struct{})
			var recorded atomic.Bool
			b, _ := localBroker(t, func(o *Options) {
				o.Timeout = time.Second
				o.Emit = func(e Event) error {
					if e.Kind == "answer" {
						recorded.Store(true)
					}
					return nil
				}
				o.OwnerOnly.Check = func() error {
					if recorded.Load() {
						select {
						case <-entered:
						default:
							close(entered)
						}
						<-resume
					}
					return nil
				}
			})
			ready := make(chan string, 1)
			b.opts.Pending = func(r Request) { ready <- r.AskID }
			done := make(chan Decision, 1)
			requestErr := make(chan error, 1)
			go func() {
				d, err := b.Request(t.Context(), testRequest())
				done <- d
				requestErr <- err
			}()
			id := <-ready
			b.mu.Lock()
			deadline := b.pending[id].started.Add(b.opts.Timeout)
			b.mu.Unlock()
			answered := make(chan Decision, 1)
			go func() { d, _ := b.answer(context.Background(), id, approve, false, nil, localRoot()); answered <- d }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("final authority read not reached")
			}
			timer := time.NewTimer(time.Until(deadline))
			<-timer.C
			close(resume)
			for _, got := range []Decision{<-done, <-answered} {
				if got.Approved || got.Reason != ReasonTimeout || got.Actor != nil || got.SystemCause != "timeout" || got.By != "timeout" {
					t.Fatalf("expired in-flight %s delivered without timeout cause: %+v", name, got)
				}
			}
			if err := <-requestErr; !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("held operation would lose timeout cause: %v", err)
			}
			if b.Waiting() {
				t.Fatal("terminal timeout left pending request")
			}
		})
	}
}
