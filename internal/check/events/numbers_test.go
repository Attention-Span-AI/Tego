// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestSummaryPreservesExactIntegerPayloads(t *testing.T) {
	for _, tt := range []struct {
		name    string
		kind    record.Kind
		payload string
		want    string
	}{
		{"limit", record.KindLimit, `{"which":"tokens","value":9007199254740993,"ceiling":9223372036854775807}`, "tokens=9007199254740993 ceiling=9223372036854775807"},
		{"usage", record.KindSSLResponse, `{"status":200,"model":"test","usage":{"input":18446744073709551615,"output":9007199254740993}}`, "200 test in=18446744073709551615 out=9007199254740993"},
		{"count", record.KindFS, `{"op":"read","path":"/tmp/data","count":9007199254740993}`, "read /tmp/data x9007199254740993"},
		{"empty usage", record.KindSSLResponse, `{"model":"test","usage":{"input":0,"output":0}}`, "test"},
		{"one usage field", record.KindSSLResponse, `{"model":"test","usage":{"input":1}}`, "test in=1 out=0"},
		{"fraction and exponent", record.KindLimit, `{"which":"cost_usd","value":0.52,"ceiling":5e-1}`, "cost_usd=0.52 ceiling=0.5"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := &record.Event{Kind: tt.kind, Payload: json.RawMessage(tt.payload)}
			if got := Summary(e); got != tt.want {
				t.Fatalf("Summary = %q, want %q", got, tt.want)
			}
		})
	}
}
