// SPDX-License-Identifier: Apache-2.0

package pathcheck

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// Unavailable is the refusal shown when a location does not answer within its budget, counted from the moment the
// filesystem helper reports it is about to touch it.
const Unavailable = contracts.UnavailableLocation

// Busy is the refusal shown when the filesystem helper did not start, or did not report ready, in time: the location
// was never asked.
const Busy = contracts.StartupUnavailable

// StartFailed is the refusal shown when the filesystem helper could not start at all (a failed fork, a refused
// credential check, no slot): the location was never asked either.
const StartFailed = contracts.StartFailure

// TooSlow is the refusal shown when the helper was ready but ran out of its location time while the machine kept it
// off the CPU for the whole of the cap: the location is not known to be at fault.
const TooSlow = contracts.CheckTooSlow

// Working is the refusal shown when the helper ran out of its location time, to the cap, while it was on a CPU for
// most of it: the check was still working, and the location is not known to be at fault.
const Working = contracts.CheckWorking

// Disk is the refusal shown when the helper ran out of its location time sitting in this computer's own disk or journal.
const Disk = contracts.CheckDisk

// Unclear is the refusal shown when the helper ran out of its location time and Tego could not tell whether it was
// blocked or starved (no scheduler statistics, or the helper had gone).
const Unclear = contracts.CheckUnclear

// IsBusy reports whether err says the helper did not start: in time (Busy) or at all (StartFailed). The location was
// never asked, and callers refuse alike; the error's own words say which.
func IsBusy(err error) bool {
	var remote *RemoteError
	return contracts.IsStartupUnavailable(err) ||
		errors.As(err, &remote) && (strings.HasPrefix(remote.Message, Busy) || strings.HasPrefix(remote.Message, StartFailed))
}

// IsUnanswered reports whether err is a refusal in either of the two sets of words: a location that did not answer,
// or a checker that did not start. Callers that refuse the same way for both (nothing changed, ask again) test this;
// they show err's own words, which say which it was.
func IsUnanswered(err error) bool {
	var remote *RemoteError
	return IsBusy(err) || contracts.IsLocationUnavailable(err) || contracts.IsCheckTooSlow(err) || contracts.IsCheckWorking(err) || contracts.IsCheckDisk(err) || contracts.IsCheckUnclear(err) ||
		errors.As(err, &remote) && (strings.Contains(remote.Message, Unavailable) || strings.Contains(remote.Message, TooSlow) || strings.Contains(remote.Message, Working) || strings.Contains(remote.Message, Disk) || strings.Contains(remote.Message, Unclear))
}

// IsNotFinished reports whether err is a check that did not finish and found nothing about what it was asked:
// IsUnanswered, a draft compile that ran out of time or was refused a slot (contracts.IsCompileUnfinished), or a
// request that was cancelled or timed out. It is a temporary failure: the caller must neither call it a difference
// between what a person reviewed and what is there, nor save anything on it.
func IsNotFinished(err error) bool {
	return err != nil && (IsUnanswered(err) || contracts.IsCompileUnfinished(err) || contracts.IsCancelledCheck(err) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
}

// UnansweredText is IsUnanswered for text a view carries as a string.
func UnansweredText(text string) bool {
	return strings.Contains(text, Unavailable) || strings.Contains(text, Busy) || strings.Contains(text, StartFailed) ||
		strings.Contains(text, TooSlow) || strings.Contains(text, Working) || strings.Contains(text, Disk) || strings.Contains(text, Unclear)
}

// active is private to the single-threaded helper dispatch. The service never
// sets it, so recursive calls stay in the worker without bypassing its boundary.
var active bool

// InHelper reports whether a registered path operation is executing here.
func InHelper() bool { return active }

// Register installs a fixed operation during binary initialization.
func Register(name string, handle func(context.Context, []byte) ([]byte, error)) {
	contracts.RegisterHelperOperation(name, func(ctx context.Context, payload []byte) ([]byte, error) {
		active = true
		defer func() { active = false }()
		return handle(ctx, payload)
	})
}

// Encode encodes private pipe data without losing fields hidden from public JSON.
func Encode(value any) ([]byte, error) {
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(value)
	return b.Bytes(), err
}

// Decode decodes private pipe data.
func Decode(payload []byte, value any) error {
	return gob.NewDecoder(bytes.NewReader(payload)).Decode(value)
}

// Call sends data to a fixed linked operation, within the helper's deadline.
func Call(ctx context.Context, name string, in, out any) error {
	data, err := Encode(in)
	if err != nil {
		return err
	}
	data, err = contracts.HelperExchange(ctx, name, data)
	if err != nil {
		if IsUnanswered(err) {
			return err
		}
		return contracts.CheckUnavailable(err)
	}
	return Decode(data, out)
}

// LocationError names disconnected filesystem replies in the same words as a
// helper deadline. Some write guards preserve only the operating system's text.
func LocationError(err error) error {
	if err == nil {
		return nil
	}
	if IsUnanswered(err) || contracts.IsCancelledCheck(err) || contracts.IsCompileUnfinished(err) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ENOTCONN) || strings.Contains(err.Error(), "transport endpoint is not connected") || strings.Contains(err.Error(), "input/output error") {
		return contracts.CheckUnavailable(err)
	}
	return err
}

// RemoteError carries only the original public words while retaining typed
// refusal causes across the helper pipe.
type RemoteError struct {
	Message string
	Causes  []error
}

func (e *RemoteError) Error() string   { return e.Message }
func (e *RemoteError) Unwrap() []error { return e.Causes }

// Bound makes ctx one scope of helper work: its exchanges share one start-up budget and one location budget (see
// contracts.WithBudget), as a page's single deadline was shared. No wall-clock time crosses the pipe: a deadline set
// here would start before the helper exists. The helper's location budget starts when it reports ready, and
// Context restores it there. A write already in a kernel syscall can still have an uncertain outcome after the
// caller returns.
func Bound(ctx context.Context) (context.Context, context.CancelFunc) {
	return contracts.WithBudget(ctx)
}

// Context restores the operation's bound in the helper: parent already carries the helper's location clock, which
// the helper's own request handling started when it reported ready and which a compile pauses
// (contracts.PauseLocation); the derived context ends with it and checks the helper's lifetime as it does. A parent
// that has none (a direct call) gets one location budget from now.
func Context(parent context.Context) (context.Context, context.CancelFunc) {
	if _, ok := parent.Deadline(); ok || contracts.HasLocationClock(parent) {
		return contracts.WithHelperContext(parent)
	}
	return contracts.WithHelperDeadline(parent, time.Now().Add(contracts.CheckTimeout))
}

// WithLocations declares the absolute paths a Call made with the returned context touches, so that a wait for a
// location on this computer's own storage is told from one for a mount that may not answer (contracts.WithLocations,
// ADR 0144, "A local location is a busy disk, not a stuck mount"). A Call that declares none is as it always was.
func WithLocations(ctx context.Context, paths ...string) context.Context {
	return contracts.WithLocations(ctx, paths...)
}
