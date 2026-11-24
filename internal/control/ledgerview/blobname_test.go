// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// oldValidSHA is the reader's own copy of the blob-name check, as it was before it called the writer's (ledger.IsSHA).
func oldValidSHA(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// TestBlobNameCheckMatchesTheWriters: the dashboard's check of a blob name and the ledger writer's are one function,
// and give what the reader's old copy gave over names that are, and are not, a sha256.
func TestBlobNameCheckMatchesTheWriters(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	for _, s := range []string{
		good, strings.ToUpper(good), good[1:], good + "0", "", "../" + good[3:], good[:63] + "g", good[:63] + "\x00",
		good[:32] + "/" + good[33:], strings.Repeat("é", 32), good[:63] + "F", " " + good[1:],
	} {
		if got, want := validSHA(s), oldValidSHA(s); got != want {
			t.Errorf("validSHA(%q) = %v, the old copy said %v", s, got, want)
		}
	}
}
