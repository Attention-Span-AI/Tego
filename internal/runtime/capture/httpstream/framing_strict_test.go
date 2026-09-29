// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"testing"
)

// TestContentLengthRequiresDigits holds Content-Length to RFC 9110's 1*DIGIT (R18): a sign, inner space or
// hex prefix is malformed, as net/http on the forwarder tier treats it.
func TestContentLengthRequiresDigits(t *testing.T) {
	for _, v := range []string{"+5", "-0", "5 5", "0x5", "+0", "5,+5"} {
		if _, err := parseContentLength([]string{v}); !errors.Is(err, ErrMalformed) {
			t.Errorf("parseContentLength(%q) err = %v, want ErrMalformed", v, err)
		}
	}
	if n, err := parseContentLength([]string{"5, 5"}); err != nil || n != 5 {
		t.Errorf("parseContentLength(\"5, 5\") = %d, %v", n, err)
	}
}
