// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/receipt"
)

func TestWatchOverflowKeepsIdentityAndAttemptUnits(t *testing.T) {
	rc := &receipt.Receipt{Connections: []receipt.Connection{{Destination: "example.com:443", Count: 1}}, ConnectionTries: 4, ConnectionsOverflowAttempts: 3}
	got := (&endSummary{rc: rc}).seen()
	if strings.Contains(got, "4 places") || !strings.Contains(got, "1 listed place") || !strings.Contains(got, "3 connection attempts beyond the identity limit") {
		t.Fatalf("watch footer mislabels identities: %q", got)
	}
}
