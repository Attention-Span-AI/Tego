// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// The words of a refusal say what happened, and a caller tells them apart by type, never by substring where it
// carries an error. This file holds the ones of ADR 0144's 2026-11-20 amendments that are not the mount's or the
// busy machine's: a checker that could not start, a caller that gave up, a compile that did not finish, and a pool
// whose every slot is held by a check that is stuck on a location.

// StartFailure is the explanation for a check whose helper could not be started, or refused its credential check, or
// did not run: nothing was asked of the location and nothing is known about it.
const StartFailure = "cannot tell: Tego's checker could not start"

// CancelledCheck is the explanation for a check its caller gave up: nothing is known about the location.
const CancelledCheck = "cannot tell: the check was cancelled before it finished"

// CompileUnfinished is the explanation for a draft compile that did not finish in time. Nobody knows whether the
// contract compiles, and nothing was written. CompileCancelled is the same for a caller that gave up.
const (
	CompileUnfinished = "cannot tell whether the new contract compiles: the check did not finish in time (the machine is very busy)"
	CompileCancelled  = "cannot tell whether the new contract compiles: the check was cancelled before it finished"
)

// CompileNoAnswer is the explanation for a draft compile that ran out of time when the kernel's counters did not say
// the machine was to blame: its child was asleep or blocked, or could not be read. It claims no cause.
// CompileStillWorking is for a compile whose child was on a CPU for most of its time, to the cap.
// CompileBusy is the explanation for a compile that could not start for want of a free compiler slot, and
// CompileCouldNotRun for one whose compiler could not be run at all (a failed start, a child that died, a reply
// that is not a result): in none of these did the compiler look at the contract.
const (
	CompileNoAnswer     = "cannot tell whether the new contract compiles: the check did not finish in time"
	CompileStillWorking = "cannot tell whether the new contract compiles: the compile was still working when its time ran out"
	CompileBusy         = "cannot tell whether the new contract compiles: the compiler is busy with other checks"
	CompileCouldNotRun  = "cannot tell whether the new contract compiles: Tego's compiler could not run"
)

// ErrCompileUnfinished is the cause every compile refusal of CompileUnfinished, CompileNoAnswer, CompileStillWorking, CompileBusy,
// CompileCouldNotRun and CompileCancelled carries across the helper pipe (errors.Is).
var ErrCompileUnfinished = errors.New("the contract check did not finish")

type cancelledError struct{ err error }

func (e *cancelledError) Error() string { return CancelledCheck + ": " + e.err.Error() }
func (e *cancelledError) Unwrap() error { return e.err }

// IsCancelledCheck reports whether err says the caller gave up (CancelledCheck).
func IsCancelledCheck(err error) bool {
	var c *cancelledError
	return errors.As(err, &c)
}

// isCancellation is a caller's cancellation that is not also a deadline.
func isCancellation(err error) bool {
	return errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

type compileError struct {
	words string
	err   error
}

func (e *compileError) Error() string { return e.words + ": " + e.err.Error() }
func (e *compileError) Unwrap() error { return e.err }
func (e *compileError) Is(target error) bool {
	return target == ErrCompileUnfinished
}

// NotFinishedWords is the compile refusal's own words, for a layer that cannot import this package and tests the
// error by this method (check/rule).
func (e *compileError) NotFinishedWords() string { return e.words }

// CompileNotFinished is the refusal for a draft compile that ran out of time or was cancelled: nobody knows whether
// the contract compiles. It wraps err, so it still says why. A real compile error is never given to it.
func CompileNotFinished(err error) error {
	if err == nil {
		return nil
	}
	if IsCompileUnfinished(err) {
		return err
	}
	if isCancellation(err) {
		return &compileError{words: CompileCancelled, err: err}
	}
	return &compileError{words: CompileUnfinished, err: err}
}

// CompileNotFinishedUnclear is CompileNotFinished for a compile that ran out of time without the counters saying the
// machine was too busy: CompileNoAnswer, which claims no cause. A caller that gave up is still the cancelled words.
func CompileNotFinishedUnclear(err error) error {
	if err == nil {
		return nil
	}
	if IsCompileUnfinished(err) {
		return err
	}
	if isCancellation(err) {
		return &compileError{words: CompileCancelled, err: err}
	}
	return &compileError{words: CompileNoAnswer, err: err}
}

// CompileNotFinishedWorking is CompileNotFinished for a compile whose child was on a CPU for most of its time, to the
// cap: CompileStillWorking. A caller that gave up is still the cancelled words.
func CompileNotFinishedWorking(err error) error {
	if err == nil {
		return nil
	}
	if IsCompileUnfinished(err) {
		return err
	}
	if isCancellation(err) {
		return &compileError{words: CompileCancelled, err: err}
	}
	return &compileError{words: CompileStillWorking, err: err}
}

// CompileUnavailable is the refusal for a compile that was never run because the compiler was busy (CompileBusy) or
// could not be run (CompileCouldNotRun): words of a check that did not finish, never "does not compile". It wraps
// err, so the reason is kept.
func CompileUnavailable(busy bool, err error) error {
	if err == nil {
		return nil
	}
	if IsCompileUnfinished(err) {
		return err
	}
	if busy {
		return &compileError{words: CompileBusy, err: err}
	}
	return &compileError{words: CompileCouldNotRun, err: err}
}

// IsCompileUnfinished reports whether err says a draft compile did not finish (CompileUnfinished, CompileNoAnswer, CompileStillWorking, CompileBusy, CompileCouldNotRun, CompileCancelled).
func IsCompileUnfinished(err error) bool { return errors.Is(err, ErrCompileUnfinished) }

// slotsTaken is the refusal of a start-up whose wait for a kernel slot ended with every slot still taken, by helpers
// this process cannot say anything about (another command's, or one it does not know to be stuck). The only thing
// known is how many are alive: it says exactly that, and does not say the machine is busy.
type slotsTaken struct {
	alive int
	err   error
}

func (e *slotsTaken) Error() string {
	return fmt.Sprintf("%d filesystem helpers are still alive in this uid and network namespace, and Tego cannot tell whether they are busy or stuck: %v", e.alive, e.err)
}
func (e *slotsTaken) Unwrap() error { return e.err }

// Stuck helpers. A helper that reported ready and then used up its location budget is abandoned, and keeps its kernel
// slot until the mount answers or it dies. The process that abandoned it knows exactly that much, and what it knows
// is kept here, by the slot's name, with the helper's pid and start time: a slot that is taken again by another
// helper, after this one ended, has another process and is not counted.
var stuck = struct {
	sync.Mutex
	by map[string]stuckHelper
}{by: map[string]stuckHelper{}}

type stuckHelper struct {
	pid   int
	start uint64
	// disk says why the helper is stuck: waiting for this computer's own disk (a local check in uninterruptible sleep:
	// the disk words), not on a mount. A refusal for want of a slot says what holds the slots, and the mount's
	// reading wins unless every holder is stuck on the disk.
	disk bool
}

// processStart is the start time (in clock ticks since boot) of a process, 0 when it cannot be read or is gone.
func processStart(pid int) uint64 {
	if pid <= 0 {
		return 0
	}
	st, err := proc.ReadParsedStat(func() ([]byte, error) { return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") })
	if err != nil || st.Gone() {
		return 0
	}
	return st.StartTicks
}

// markStuck records that the helper w, abandoned after it had said it was ready, still holds its slot. disk says it
// was abandoned for a wait for this computer's own disk (a local check in a disk wait), not for a mount.
func markStuck(w *helperWorker, disk bool) {
	if w.slot == "" || w.pid <= 0 || w.start == 0 {
		return
	}
	stuck.Lock()
	stuck.by[w.slot] = stuckHelper{w.pid, w.start, disk}
	stuck.Unlock()
}

// forgetStuck drops the record of a slot this process has just taken itself.
func forgetStuck(slot string) {
	stuck.Lock()
	delete(stuck.by, slot)
	stuck.Unlock()
}

// stuckOnDisk reports whether the helper recorded on slot is stuck for the disk (stuckAt says it is stuck at all).
func stuckOnDisk(slot string) bool {
	stuck.Lock()
	defer stuck.Unlock()
	return stuck.by[slot].disk
}

// stuckAt reports whether the helper this process abandoned on slot is still the process that holds it.
func stuckAt(slot string) bool {
	stuck.Lock()
	h, ok := stuck.by[slot]
	stuck.Unlock()
	if !ok {
		return false
	}
	if processStart(h.pid) != h.start {
		forgetStuck(slot)
		return false
	}
	return true
}
