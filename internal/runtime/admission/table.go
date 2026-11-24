// SPDX-License-Identifier: Apache-2.0

package admission

import (
	"fmt"
	"strings"
)

// Check names one preparation requirement and its final-admission policy. Every
// check has a Run function and exactly one classification: Rechecked, or a
// SnapshotReason explaining why preparation's result remains the requested input.
type Check struct {
	Name           string
	Run            func() error
	Rechecked      bool
	SnapshotReason string
}

type entry struct {
	check    Check
	prepared bool
}

// Table holds one adoption's admission checks. Its zero value is ready for use.
// Preparation stages may add checks and prepare the pending entries. The first
// Recheck seals the table against further additions. One adoption owns the table;
// its methods must not be called concurrently.
type Table struct {
	entries []entry
	sealed  bool
}

// Add appends checks atomically after validating names, functions and explicit
// classifications. A name may occur only once, so errors identify one requirement.
func (t *Table) Add(checks ...Check) error {
	if t.sealed {
		return fmt.Errorf("admission table is sealed")
	}
	names := make(map[string]bool, len(t.entries)+len(checks))
	for _, e := range t.entries {
		names[e.check.Name] = true
	}
	for _, c := range checks {
		switch {
		case strings.TrimSpace(c.Name) == "":
			return fmt.Errorf("admission check %q has no name", c.Name)
		case c.Run == nil:
			return fmt.Errorf("admission check %q has no function", c.Name)
		case c.Rechecked && c.SnapshotReason != "":
			return fmt.Errorf("admission check %q is both rechecked and a snapshot", c.Name)
		case !c.Rechecked && strings.TrimSpace(c.SnapshotReason) == "":
			return fmt.Errorf("admission check %q has no final-admission classification", c.Name)
		case names[c.Name]:
			return fmt.Errorf("admission check %q is duplicated", c.Name)
		}
		names[c.Name] = true
	}
	for _, c := range checks {
		t.entries = append(t.entries, entry{check: c})
	}
	return nil
}

// Prepare runs each pending entry in order, retaining successful preparation so
// later stages run only their new entries. A failure leaves that entry pending.
func (t *Table) Prepare() error {
	if t.sealed {
		return fmt.Errorf("admission table is sealed")
	}
	for i := range t.entries {
		e := &t.entries[i]
		if e.prepared {
			continue
		}
		if err := e.check.Run(); err != nil {
			return fmt.Errorf("admission check %q during preparation: %w", e.check.Name, err)
		}
		e.prepared = true
	}
	return nil
}

// Recheck seals the table, refuses any unprepared entry, and runs every entry
// marked Rechecked in table order. Snapshot entries retain their prepared result.
func (t *Table) Recheck() error {
	t.sealed = true
	for _, e := range t.entries {
		if !e.prepared {
			return fmt.Errorf("admission check %q was not prepared", e.check.Name)
		}
	}
	for _, e := range t.entries {
		if e.check.Rechecked {
			if err := e.check.Run(); err != nil {
				return fmt.Errorf("admission check %q during final admission: %w", e.check.Name, err)
			}
		}
	}
	return nil
}
