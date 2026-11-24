// SPDX-License-Identifier: Apache-2.0

package pathcheck

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
)

func TestLocationErrorPreservesUnavailableCause(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, syscall.EIO, syscall.ENOTCONN} {
		err := LocationError(cause)
		if !strings.Contains(err.Error(), Unavailable) || !errors.Is(err, cause) {
			t.Errorf("%v mapped to %v", cause, err)
		}
	}
}

// A caller that gave up, and a compile that did not finish, are not a location that does not answer: LocationError
// words the first neutrally and leaves the second's own words, and neither counts as a refusal of the location.
func TestLocationErrorKeepsCancellationAndUnfinishedCompilesApart(t *testing.T) {
	cancelled := LocationError(context.Canceled)
	if !contracts.IsCancelledCheck(cancelled) || !errors.Is(cancelled, context.Canceled) || strings.Contains(cancelled.Error(), Unavailable) || IsUnanswered(cancelled) {
		t.Errorf("a cancellation mapped to %v", cancelled)
	}
	unfinished := contracts.CompileNotFinished(context.DeadlineExceeded)
	if got := LocationError(unfinished); got != unfinished || strings.Contains(got.Error(), Unavailable) || IsUnanswered(got) {
		t.Errorf("an unfinished compile mapped to %v", got)
	}
	// Both arrive across the pipe as text with their cause kept (rules.serviceErrors).
	remote := &RemoteError{Message: unfinished.Error(), Causes: []error{contracts.ErrCompileUnfinished}}
	if IsUnanswered(remote) || IsBusy(remote) || !contracts.IsCompileUnfinished(remote) {
		t.Errorf("a remote unfinished compile: unanswered=%v busy=%v", IsUnanswered(remote), IsBusy(remote))
	}
}

// The two refusals keep their own words through every wrapper: a checker that did not start is never re-worded as a
// location that does not answer, and both count as refusals that changed nothing.
func TestBusyAndUnavailableStayApart(t *testing.T) {
	busy := &RemoteError{Message: Busy + ": context deadline exceeded"}
	failed := &RemoteError{Message: StartFailed + ": start filesystem helper: resource temporarily unavailable"}
	stuck := &RemoteError{Message: Unavailable + ": context deadline exceeded"}
	other := errors.New("the contract does not compile")
	for _, c := range []struct {
		name                 string
		err                  error
		busy, unanswered     bool
		wordsAfterLocationFn string
	}{
		{"busy", busy, true, true, Busy},
		{"start failure", failed, true, true, StartFailed},
		{"stuck", stuck, false, true, Unavailable},
		{"other", other, false, false, ""},
	} {
		if got := IsBusy(c.err); got != c.busy {
			t.Errorf("%s: IsBusy=%v, want %v", c.name, got, c.busy)
		}
		if got := IsUnanswered(c.err); got != c.unanswered {
			t.Errorf("%s: IsUnanswered=%v, want %v", c.name, got, c.unanswered)
		}
		if c.wordsAfterLocationFn != "" {
			mapped := LocationError(c.err)
			if mapped != c.err || strings.Count(mapped.Error(), Unavailable)+strings.Count(mapped.Error(), Busy)+strings.Count(mapped.Error(), StartFailed) != 1 {
				t.Errorf("%s: LocationError re-worded %q as %q", c.name, c.err, mapped)
			}
		}
	}
	if !UnansweredText("x: "+StartFailed) || !UnansweredText("x: "+Busy) || !UnansweredText("x: "+Unavailable) || UnansweredText("cannot tell something else") {
		t.Error("UnansweredText does not know both sets of words")
	}
	if Busy == Unavailable {
		t.Fatal("the two refusals share words")
	}
}

// A scope has the start-up and the location budget; no clock crosses the pipe, and the helper restores the deadline
// its own request handling set.
func TestBoundIsAScopeAndContextRestoresTheHelpersDeadline(t *testing.T) {
	ctx, cancel := Bound(context.Background())
	defer cancel()
	if left := contracts.LocationLeft(ctx); left != contracts.CheckTimeout {
		t.Fatalf("a new scope has %v of location budget, want %v", left, contracts.CheckTimeout)
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > contracts.StartTimeout+contracts.CheckTimeout+contracts.PauseLimit {
		t.Fatalf("the scope's backstop is %v", time.Until(deadline))
	}
	parent, stop := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer stop()
	restored, release := Context(parent)
	defer release()
	got, _ := restored.Deadline()
	want, _ := parent.Deadline()
	if !got.Equal(want) {
		t.Fatalf("Context moved the deadline of its parent: %v, want %v", got, want)
	}
}

// The two refusals of a helper that ran out of its location time without a stuck mount (too slow, unclear) keep the
// refusal class of the mount's: callers that refuse a check that did not finish refuse these the same way, whether the
// error is carried or arrives across the pipe as text, and each keeps its own words.
func TestTooSlowAndUnclearAreRefusalsLikeTheMounts(t *testing.T) {
	slow := &RemoteError{Message: TooSlow + ": context deadline exceeded"}
	unclear := &RemoteError{Message: Unclear + ": context deadline exceeded"}
	working := &RemoteError{Message: Working + ": context deadline exceeded"}
	disk := &RemoteError{Message: Disk + ": context deadline exceeded"}
	for name, c := range map[string]struct {
		err   error
		words string
	}{
		"too slow, carried":   {contracts.CheckUnavailable(context.DeadlineExceeded), Unavailable},
		"too slow, remote":    {slow, TooSlow},
		"unclear, remote":     {unclear, Unclear},
		"unavailable, remote": {&RemoteError{Message: Unavailable + ": x"}, Unavailable},
	} {
		if !IsUnanswered(c.err) || IsBusy(c.err) || !UnansweredText(c.err.Error()) || !strings.Contains(LocationError(c.err).Error(), c.words) {
			t.Errorf("%s: unanswered=%v busy=%v text=%v words=%q", name, IsUnanswered(c.err), IsBusy(c.err), UnansweredText(c.err.Error()), LocationError(c.err))
		}
	}
	if strings.Contains(LocationError(slow).Error(), Unavailable) || strings.Contains(LocationError(unclear).Error(), Unavailable) || strings.Contains(LocationError(working).Error(), Unavailable) || strings.Contains(LocationError(disk).Error(), Unavailable) {
		t.Error("a refusal in its own words was re-worded as a stuck mount")
	}
	if !strings.Contains(TooSlow, "very busy") || strings.Contains(Unclear, "does not answer") || !strings.Contains(Unclear, "stuck location, or a very busy machine") {
		t.Errorf("the words changed: %q / %q", TooSlow, Unclear)
	}
}
