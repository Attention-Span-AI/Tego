// SPDX-License-Identifier: Apache-2.0

package status

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A legacy sweep omitted exit_code, whose decoded zero made a failed launcher
// appear to have succeeded. Reading it must preserve the original chained bytes.
func TestDeriveOrphanExitCodePreservesLegacyLedger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
		code   int
		want   int
	}{
		{"legacy orphan omits code", record.RunEndOrphaned, 0, identity.ExitLauncher},
		{"new orphan records launcher failure", record.RunEndOrphaned, identity.ExitLauncher, identity.ExitLauncher},
		{"explicit nonzero orphan code retained", record.RunEndOrphaned, 137, 137},
		{"successful exit remains zero", record.RunEndExit, 0, 0},
		{"explicit agent failure retained", record.RunEndExit, 7, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := write(t, false, runStart(""), &record.RunEndPayload{Reason: tc.reason, ExitCode: tc.code})
			path := filepath.Join(dir, ledger.EventsFile)
			before := readFile(t, path)
			if tc.code == 0 && bytes.Contains(before, []byte(`"exit_code"`)) {
				t.Fatal("legacy fixture must omit exit_code")
			}
			s := derive(t, dir, false, base, time.Hour)
			if s.St != Done || s.ExitReason != tc.reason || s.ExitCode != tc.want {
				t.Fatalf("snapshot %+v, want %s/%d", s, tc.reason, tc.want)
			}
			if after := readFile(t, path); !bytes.Equal(before, after) {
				t.Fatal("deriving legacy status changed the ledger's chained bytes")
			}
			// An orphan end on disk does not override a still-held launcher lock.
			live := derive(t, dir, true, base, time.Hour)
			if live.St != Running || live.ExitReason != "" || live.ExitCode != 0 {
				t.Fatalf("locked run exposes a terminal result: %+v", live)
			}
		})
	}
}
