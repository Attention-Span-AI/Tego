// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// TestParseRequestHalfCopiesNothing: reading the request half of an exchange only decides whether it is
// readable, so it must not copy the conversation (a request is up to megabytes on a long agent session).
func TestParseRequestHalfCopiesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}
	body := []byte(`{"model":"m","system":"` + strings.Repeat("s", 1<<20) + `","messages":[{"role":"user","content":"` +
		strings.Repeat("x", 4<<20) + `"}],"tools":[{"name":"t","input_schema":{"a":"` + strings.Repeat("y", 1<<20) + `"}}]}`)
	msg := &derive.Message{Body: body}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := parseRequestHalf(msg)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > uint64(len(body))/8 {
		t.Errorf("reading the request half allocated %d KiB for a %d KiB body", got>>10, len(body)>>10)
	}
}

// TestValidateRequestAgreesWithParseRequest: the validate-only reading refuses exactly what ParseRequest does.
func TestValidateRequestAgreesWithParseRequest(t *testing.T) {
	for _, b := range []string{
		``, `{`, `[]`, `null`, `{}`, `{"model":""}`, `{"model":"m"}`, `{"MODEL":"m"}`, `{"model":1}`,
		`{"model":"m","messages":"x"}`, `{"model":"m","messages":[1]}`, `{"model":"m","messages":[{"role":3}]}`,
		`{"model":"m","messages":[{"role":"user","content":[1,{"a":2}]}]}`,
		`{"model":"m","tools":{}}`, `{"model":"m","tools":[{"name":"a","input_schema":7}]}`, `{"model":"m","tools":[{"name":5}]}`,
		`{"model":"m","stream":"yes"}`, `{"model":"m","stream":true,"system":[{"type":"text"}]}`, `{"model":"m"} x`,
	} {
		_, want := ParseRequest([]byte(b))
		got := validateRequest([]byte(b))
		if (want == nil) != (got == nil) {
			t.Errorf("%q: ParseRequest err %v, validateRequest err %v", b, want, got)
		}
	}
}
