// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRunExitCodeReportsAnIncompleteRecord: a run whose ledger could not be closed exits 125 with a line that
// says which failure it was, never the agent's own code alone (record-ledger.md §7).
func TestRunExitCodeReportsAnIncompleteRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
		say  string
	}{
		{"a clean record", nil, 0, ""},
		{"a record that could not be completed", errors.New("ledger: write seq 9: no space left on device"),
			identity.ExitLauncher, "the run's record is incomplete"},
		{"a record whose anchor was not written", fmt.Errorf("%w: disk full", ledger.ErrAnchorWrite),
			identity.ExitLauncher, "its chain anchor was not written"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			got := runExitCode(&stderr, "tego run", tegoruntime.Result{RunID: "r-x", ExitCode: 0, Reason: "exit", RecordErr: tc.err})
			if got != tc.code {
				t.Fatalf("exit %d, want %d", got, tc.code)
			}
			if !strings.Contains(stderr.String(), tc.say) || (tc.say == "") != (stderr.Len() == 0) {
				t.Fatalf("stderr %q, want it to say %q", stderr.String(), tc.say)
			}
		})
	}
}
