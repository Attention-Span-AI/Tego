// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// LedgerCheck is what `tego doctor` reports about a ledger root: the runs no sweep on this host finishes, said
// once when asked rather than on every sweep.
type LedgerCheck struct {
	// Root is the ledger root checked.
	Root string `json:"root"`
	// Host is this host's host8, the one its runs are minted with.
	Host string `json:"host"`
	// Foreign counts, per host8, the run directories in Root minted on a host other than this one. No sweep here
	// ends, repairs or kills them, and `tego gc` removes them past retention whatever they read but running.
	// Every run of this host reads as foreign once its machine id changed (a reinstall keeping /home, a cloned
	// image, the hostname fallback with a renamed host).
	Foreign map[string]int `json:"foreign,omitempty"`
	// Unfinished are this host's runs the live index still lists though they ended, whose launcher is gone: every
	// sweep since has kept the entry because it could not finish them — the anchor repair failed on the anchor
	// (chain.log unreadable or not writable), or the ended run's scope could not be removed.
	Unfinished []string `json:"unfinished,omitempty"`
	// LiveWithoutFloor are this host's runs that are still running and whose run_start does not carry the root-only
	// approval floor, filled only when the system `local_roles: owner_only` is set (CheckLedgerWithFloor): the floor
	// binds the runs launched after it was set, so these keep same-user approvals until they end (ADR 0154).
	LiveWithoutFloor []string `json:"live_without_root_floor,omitempty"`
}

// Empty reports whether the check found nothing to say.
func (c LedgerCheck) Empty() bool {
	return len(c.Foreign) == 0 && len(c.Unfinished) == 0 && len(c.LiveWithoutFloor) == 0
}

// CheckLedger checks the ledger root at root without writing to it or taking any run's lock: its directory
// names, the live index's names, and, for each entry of this host's, the tail of its ledger and its lock line.
// A root that does not exist is nothing to report.
//
// With floor set (the system local_roles is owner_only) it also lists this host's running runs whose run_start
// carries no root-only floor (LedgerCheck.LiveWithoutFloor).
func CheckLedger(root string, floor bool) (LedgerCheck, error) {
	c := LedgerCheck{Root: root, Host: localHost8()}
	ents, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, fmt.Errorf("ledger check: %w", err)
	}
	for _, e := range ents {
		if !e.IsDir() || !ledger.IsRunID(e.Name()) || !foreignRun(e.Name()) {
			continue
		}
		if c.Foreign == nil {
			c.Foreign = map[string]int{}
		}
		c.Foreign[identity.RunID(e.Name()).Host8()]++
	}
	ids, err := ledger.LiveEntries(root)
	if err != nil {
		return c, fmt.Errorf("ledger check: %w", err)
	}
	for _, id := range ids {
		if !foreignRun(id) && endedUnfinished(filepath.Join(root, id)) {
			c.Unfinished = append(c.Unfinished, id)
		}
	}
	slices.Sort(c.Unfinished)
	if floor {
		for _, id := range ids {
			if !foreignRun(id) && runningWithoutFloor(filepath.Join(root, id)) {
				c.LiveWithoutFloor = append(c.LiveWithoutFloor, id)
			}
		}
		slices.Sort(c.LiveWithoutFloor)
	}
	return c, nil
}

// runningWithoutFloor reports whether the run in dir is running and its run_start does not carry the root-only
// approval floor. A running run whose first line cannot be read or decoded is reported too: nothing shows it holds the
// floor. An ended or lost run is not reported; it takes no answers.
func runningWithoutFloor(dir string) bool {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return false
	}
	defer func() { _ = rd.Close() }() // read-only
	if state, err := rd.State(); err != nil || state != ledger.StateRunning {
		return false
	}
	for line, err := range rd.Lines() {
		if err != nil {
			return true
		}
		e, err := record.Decode(line)
		if err != nil || e.Kind != record.KindRunStart {
			return true
		}
		return record.ValidatedLocalApprovalAuthority(e.Payload) == nil
	}
	return true
}

// endedUnfinished reports whether the run in dir has ended and the launcher its lock line names is gone: a live
// launcher is between run_end and clearing its own entry.
func endedUnfinished(dir string) bool {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return false
	}
	state, err := rd.State() // State probes the lock, then reads the tail; only StateEnded (run_end last) is used here
	_ = rd.Close()
	if err != nil || state != ledger.StateEnded {
		return false
	}
	f, err := openLockFile(lockPath(dir))
	if err != nil {
		return true // no lock line: no launcher to wait for
	}
	b := make([]byte, 128)
	n, _ := f.Read(b)
	_ = f.Close()
	info, err := ParseLockInfo(b[:n])
	if err != nil || info.PID == 0 {
		return true
	}
	target, err := OpenStopTargetFor(dir, info)
	if err == nil {
		_ = target.Close()
		return false // the launcher is alive and clears its entry itself
	}
	return errors.Is(err, ErrStale)
}
