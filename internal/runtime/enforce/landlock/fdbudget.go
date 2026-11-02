// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The launcher's descriptor budget (enforce-landlock E11; enforce-plane §2.4 condition 7). Every held path costs
// this process one O_PATH descriptor for the length of the run: each fs entry, each exec grant and its loader,
// every plane key, and every sibling and ancestor a deny_read target's enumeration holds (R3), which in a wide
// directory is most of them; a target R4 leaves out holds none (snapshotTarget). The cap on them is RLIMIT_NOFILE,
// not the plane's 4096 rows: measured as root in the
// KVM guest (soft = hard = 4096 there), a table of about 3,800 to 4,000 keyed paths ran out at Prepare with EMFILE.
// A plan is therefore held against a budget read before its first open, and a table that needs more is refused
// naming the cap, never left to fail on whichever open happens to meet the limit.

// FDBudget is what a run's Landlock plan may hold: the soft RLIMIT_NOFILE, less the descriptors this process
// already holds when the plan starts and a reserve for everything the run opens after it (the tier's BPF objects,
// the ledger, the supervisor's pidfds and duplicates, a listing's transient reopen).
type FDBudget struct {
	Limit, InUse, Reserve int
}

// Cap is how many descriptors the plan may hold; 0 or less holds none.
func (b FDBudget) Cap() int { return b.Limit - b.InUse - b.Reserve }

// fdReserveFor is the reserve under a soft limit: a sixteenth of it, at least 64 and at most 256. 256 is what a
// tier-3 run opens beside its plan with room to spare (the plane and tier-2 objects adopted, the fill, the run's
// ledger and supervisor); a small limit keeps a smaller share so a tier-1 run under `ulimit -n 1024` still holds most
// of it.
func fdReserveFor(limit int) int {
	return min(max(limit/16, 64), 256)
}

// ReadFDBudget raises this process's soft RLIMIT_NOFILE to one under its hard limit where it is lower (Go's runtime does
// so at start on Linux; a caller that lowered it since gets it back), then reads the limit and counts the descriptors
// held now. One under, and no raise at all where it stands there, because that is the mark the runtime leaves: it puts
// the limit a process was started with back in each child only while the soft limit reads hard-1, and unix.Prlimit
// drops its record of that limit. A raise to the hard limit did both, so under `ulimit -Sn 1024` the agent ran with the
// hard limit, which a program built on select(2), or one that closes every descriptor up to the limit, does not survive.
func ReadFDBudget() (FDBudget, error) {
	var lim unix.Rlimit
	if err := unix.Prlimit(0, unix.RLIMIT_NOFILE, nil, &lim); err != nil {
		return FDBudget{}, fmt.Errorf("read RLIMIT_NOFILE: %w", err)
	}
	if lim.Cur < lim.Max-1 {
		raised := unix.Rlimit{Cur: lim.Max - 1, Max: lim.Max}
		_ = unix.Prlimit(0, unix.RLIMIT_NOFILE, &raised, nil) // a refusal leaves the lower limit, which is read next
	}
	return currentFDBudget()
}

// currentFDBudget is the budget under the soft limit as it is now.
func currentFDBudget() (FDBudget, error) {
	var lim unix.Rlimit
	if err := unix.Prlimit(0, unix.RLIMIT_NOFILE, nil, &lim); err != nil {
		return FDBudget{}, fmt.Errorf("read RLIMIT_NOFILE: %w", err)
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return FDBudget{}, fmt.Errorf("count the descriptors held: %w", err)
	}
	limit := int(min(lim.Cur, uint64(1)<<30)) // fs.nr_open's ceiling; RLIM_INFINITY reads as that
	// ReadDir's own descriptor was open while it listed, and is closed now.
	return FDBudget{Limit: limit, InUse: max(len(ents)-1, 0), Reserve: fdReserveFor(limit)}, nil
}

// readFDBudget is ReadFDBudget, a variable so tests can give a plan a small budget.
var readFDBudget = ReadFDBudget

// FDCapError is a plan refused because it would hold more descriptors than FDBudget.Cap: the count held when the
// next open was refused, the path it was for, and the budget. It is errors.Is ErrFDExhausted, the E11 refusal, and
// is never an EMFILE: the open it stands in for was not made.
type FDCapError struct {
	Held   int
	Path   string
	Budget FDBudget
}

func (e *FDCapError) Error() string {
	return fmt.Sprintf("the run's Landlock plan holds %d descriptors, its cap on this launcher, and needs more for %q "+
		"(soft RLIMIT_NOFILE %d, less %d held before Prepare and %d kept for the run): narrow the fs, deny_read and "+
		"exec.allow entries (a deny_read target holds every sibling along its path) or raise the launcher's "+
		"RLIMIT_NOFILE (ulimit -n)", e.Held, e.Path, e.Budget.Limit, e.Budget.InUse, e.Budget.Reserve)
}

// Unwrap returns ErrFDExhausted so callers use errors.Is.
func (e *FDCapError) Unwrap() error { return ErrFDExhausted }

// room refuses the next open when the set holds its budget already. A set without a budget (tests building one
// directly) has room.
func (s *fdSet) room(name string) error {
	if s == nil || !s.budgeted {
		return nil
	}
	if held := len(s.open); held >= s.budget.Cap() {
		return &FDCapError{Held: held, Path: name, Budget: s.budget}
	}
	return nil
}
