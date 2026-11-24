// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnitRejectedListingSpendsAggregateBudget(t *testing.T) {
	root := unitFixtureRoot(t)
	for _, spec := range []struct {
		name  string
		count int
	}{{"a.wants", 4000}, {"b.wants", 100}, {"c.wants", 10}} {
		for i := range spec.count {
			if err := os.MkdirAll(filepath.Join(root, spec.name, fmt.Sprintf("entry-%04d", i)), 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	units := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	// The root and a.wants use 4003 entries. The overflow probe in b.wants
	// spends the rest. c.wants must never receive a fresh listing allowance.
	for _, src := range units.Sources {
		if strings.HasSuffix(src.Path, "c.wants") {
			if src.State != "not-read" || src.Reason != "limit" {
				t.Fatalf("rejected listing left allowance for later directory: %+v", src)
			}
			return
		}
	}
	t.Fatalf("missing c.wants limit source: %+v", units.Sources)
}

type countedUnitDirectory struct {
	requested, returned, available int
	err                            error
}

func (d *countedUnitDirectory) names(n int) ([]string, error) {
	d.requested += n
	count := min(n, d.available)
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("entry-%d", i)
	}
	d.returned += count
	return names, d.err
}
func (d *countedUnitDirectory) stat() (unix.Stat_t, error) {
	return unix.Stat_t{Mode: unix.S_IFDIR | 0700}, nil
}

func TestUnitDirectoryChargesRejectedResults(t *testing.T) {
	for _, failure := range []error{nil, unix.EIO} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			remaining := unitTotalEntries
			requested, returned := 0, 0
			for range unitDirectoryCount {
				d := &countedUnitDirectory{available: unitDirectoryEntries + 1, err: failure}
				names, err := unitDirectoryNames(t.Context(), d, &remaining)
				if err == nil || len(names) > unitTotalEntries {
					t.Fatalf("unbounded listing accepted: %d (%v)", len(names), err)
				}
				requested += d.requested
				returned += d.returned
			}
			if requested != unitTotalEntries || returned != unitTotalEntries || remaining != 0 {
				t.Fatalf("rejected listings escaped cap: requested=%d returned=%d remaining=%d", requested, returned, remaining)
			}
		})
	}
}

func TestUnitDirectoryChargesEmptyAndFailedAttempts(t *testing.T) {
	remaining := 2
	for range 3 {
		d := &countedUnitDirectory{err: unix.EIO}
		_, err := unitDirectoryNames(t.Context(), d, &remaining)
		if err == nil {
			t.Fatal("failed enumeration accepted")
		}
	}
	if remaining != 0 {
		t.Fatalf("failed attempts did not spend allowance: %d", remaining)
	}
	d := &countedUnitDirectory{}
	remaining = 1
	names, err := unitDirectoryNames(t.Context(), d, &remaining)
	if err != nil || len(names) != 0 || remaining != 0 || d.requested != 1 {
		t.Fatalf("empty listing: %v, remaining=%d, requested=%d", err, remaining, d.requested)
	}
}
