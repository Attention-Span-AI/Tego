// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func TestWholeLedgerExportRemainsAvailableAfterEviction(t *testing.T) {
	old := ledgerview.MaxResidentBytes
	ledgerview.MaxResidentBytes = 1
	t.Cleanup(func() { ledgerview.MaxResidentBytes = old })
	root := fixture(t)
	s := newServer(t, root)
	c := login(t, s)
	page := get(t, s, c, "/logs?run="+harmRun)
	if !strings.Contains(page, "Record (JSONL)") {
		t.Fatal("an evicted window hid the whole-ledger download")
	}
	data, err := os.ReadFile(filepath.Join(root, harmRun, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := get(t, s, c, "/logs.jsonl?run="+harmRun); got != string(data) {
		t.Fatalf("whole ledger download has %d bytes, want %d", len(got), len(data))
	}
}
