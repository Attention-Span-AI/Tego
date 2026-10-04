// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// TestTheReapersSlotPurgeUsesTheDirectoryItWasHanded: PurgeRun hands purgeDeadSlots the state directory it opened
// (verified, for the host's), and the purge reopened it by name with OpenAt, re-resolving the path and skipping
// that verification. The purge's slot table must be the directory it was handed, whatever the name now leads
// to, and closing the table must leave the caller's descriptor open.
func TestTheReapersSlotPurgeUsesTheDirectoryItWasHanded(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	table := slotTableName + "-h1"
	if err := os.WriteFile(filepath.Join(dir, table), make([]byte, slotRecordSize), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := hoststate.OpenAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	st, err := openPurgeTable(d, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if !st.peek {
		t.Error("the purge's table would be created for a build that has none")
	}
	f, err := st.dir.OpenFile(table, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("the purge's table is not the one in the directory it was handed: %v", err)
	}
	_ = f.Close()
	if err := st.close(); err != nil {
		t.Fatal(err)
	}
	f, err = d.OpenFile(table, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("closing the purge's table closed the caller's directory: %v", err)
	}
	_ = f.Close()
	if _, err := os.Stat(filepath.Join(dir, table)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the directory now at the name was touched: %v", err)
	}
}
