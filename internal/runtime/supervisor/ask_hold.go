// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
)

// askHeld releases the human wait when the original notification or run ends.
// The duplicate socket or pinned file stays owned by its caller throughout.
func (l *Loop) askHeld(n *notif, req ask.Request) (ask.Decision, error) {
	return l.askHeldUnless(n, req, nil)
}

// askHeldUnless is askHeld that also withdraws the request once blocked reports true, which the hold's watcher asks at
// each of its ticks: a held open that a live block landing while the person decides now refuses
// (completeHeldAskOpen, heldAsk). It is withdrawn as a notification that went away withdraws it: the broker answers it
// ask-unavailable by cancelled, so the dashboard's card and `tego ask` drop it and nobody is left asked about an open
// that no answer could complete. The caller refuses it under the block (liveHeld). blocked runs on the watcher's
// goroutine, so it must be safe there and must not block; nil never withdraws.
func (l *Loop) askHeldUnless(n *notif, req ask.Request, blocked func() bool) (ask.Decision, error) {
	if l.ask == nil || !l.valid(n) {
		return ask.Decision{Reason: ask.ReasonUnavailable}, ask.ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-n.done:
				cancel()
				return
			case <-tick.C:
				valid, err := l.k.IDValid(n.id)
				if err != nil || !valid || blocked != nil && blocked() {
					cancel()
					return
				}
			}
		}
	}()
	l.backfill(n)
	d, err := l.ask(ctx, req)
	waitErr := ctx.Err()
	cancel()
	<-watchDone
	// Every refusal returned in place of d closes d's alternate descriptor, if any: the caller owns only what it gets.
	if !l.valid(n) {
		d.CloseAlternate()
		return ask.Decision{Reason: ask.ReasonUnavailable}, ask.ErrUnavailable
	}
	if waitErr != nil {
		d.CloseAlternate()
		return ask.Decision{Reason: ask.ReasonUnavailable}, waitErr
	}
	// An alternate completes the open as an approval does (a descriptor is delivered), so it waits on the same
	// last check that the notification is still there.
	if err != nil || (!d.Approved && d.Alternate == "") {
		return d, err
	}
	select {
	case <-n.done:
		d.CloseAlternate()
		return ask.Decision{Reason: ask.ReasonUnavailable}, context.Canceled
	default:
	}
	return d, nil
}

func askReason(d ask.Decision, err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return ask.ReasonTimeout
	}
	if err != nil {
		return ask.ReasonUnavailable
	}
	switch d.Reason {
	case ask.ReasonTimeout, ask.ReasonDenied, ask.ReasonUnavailable:
		return d.Reason
	}
	return ask.ReasonDenied
}
