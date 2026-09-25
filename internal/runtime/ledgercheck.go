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
)

// LedgerCheck is what `tego doctor` reports about a ledger root: the runs no sweep on this host finishes, said
// once when asked rather than on every sweep (limits-check-doctor-cli.md R27).
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
}

// Empty reports whether the check found nothing to say.
func (c LedgerCheck) Empty() bool { return len(c.Foreign) == 0 && len(c.Unfinished) == 0 }

// CheckLedger checks the ledger root at root without writing to it or taking any run's lock: its directory
// names, the live index's names, and, for each entry of this host's, the tail of its ledger and its lock line.
// A root that does not exist is nothing to report.
func CheckLedger(root string) (LedgerCheck, error) {
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
	return c, nil
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
