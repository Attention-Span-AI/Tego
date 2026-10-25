// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestCutDetail: a run_end detail of at most MaxDetailBytes is kept as it is; a longer one is cut at a character
// boundary to at most MaxDetailBytes, the marker included, and ends saying how many bytes were cut.
func TestCutDetail(t *testing.T) {
	fits := strings.Repeat("d", MaxDetailBytes)
	if got := CutDetail(fits); got != fits {
		t.Fatalf("a detail of MaxDetailBytes was changed to %d bytes", len(got))
	}
	if got := CutDetail(""); got != "" {
		t.Fatalf("an empty detail = %q", got)
	}
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"one byte over", strings.Repeat("d", MaxDetailBytes+1)},
		{"a 3 MiB hook error", "started hook: " + strings.Repeat("x", 3<<20)},
		{"multi-byte characters across the cut", strings.Repeat("é", MaxDetailBytes)},
		{"four-byte characters across the cut", strings.Repeat("\U0001F600", MaxDetailBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CutDetail(tc.in)
			if len(got) > MaxDetailBytes || !utf8.ValidString(got) {
				t.Fatalf("cut to %d bytes (valid UTF-8 %v), want at most %d", len(got), utf8.ValidString(got),
					MaxDetailBytes)
			}
			kept, marker, ok := strings.Cut(got, " [cut ")
			if !ok || !strings.HasPrefix(tc.in, kept) || !strings.HasSuffix(marker, " bytes]") {
				t.Fatalf("cut detail ends %q, want the kept prefix and a [cut N bytes] marker", got[max(0, len(got)-40):])
			}
			if want := " [cut " + strconv.Itoa(len(tc.in)-len(kept)) + " bytes]"; " [cut "+marker != want {
				t.Fatalf("marker %q, want %q", " [cut "+marker, want)
			}
		})
	}
}
