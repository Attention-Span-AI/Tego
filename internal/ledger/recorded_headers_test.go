// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"net/http"
	"reflect"
	"testing"
)

// TestRecordedHeadersIsTheAllowList covers R9 and I5 at the capture sources: both record AllowedHeaders
// alone, keyed as the list spells them, repeated values joined, and nothing when none is present.
func TestRecordedHeadersIsTheAllowList(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Add("Tracestate", "a=1")
	h.Add("Tracestate", "b=2")
	h.Set("X-Api-Key", "sk-ant-secret")
	h.Set("Authorization", "Bearer secret")
	h.Set("X-Stainless-Retry-Count", "1")
	want := map[string]string{"content-type": "application/json", "tracestate": "a=1, b=2"}
	if got := RecordedHeaders(h); !reflect.DeepEqual(got, want) {
		t.Errorf("RecordedHeaders = %v, want %v", got, want)
	}
	if got := RecordedHeaders(http.Header{"Cookie": {"x"}}); got != nil {
		t.Errorf("RecordedHeaders with no allowed field = %v, want nil", got)
	}
}
