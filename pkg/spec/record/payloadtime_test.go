// SPDX-License-Identifier: Apache-2.0

package record

import (
	jsonv2 "encoding/json/v2"
	"testing"
	"time"
)

func TestPayloadValidationTimesDoNotConsultLocal(t *testing.T) {
	original := time.Local
	t.Cleanup(func() { time.Local = original })
	for _, stamp := range []string{"2026-09-22T09:00:00+01:00", "2026-09-22T09:00:00.123456789123+01:00"} {
		t.Run(stamp, func(t *testing.T) {
			time.Local = time.FixedZone("payload-must-not-use-host-location", 60*60)
			var block LiveBlockChange
			var control LiveControlChange
			var tool MCPToolChange
			var route ModelRouteChange
			for _, tc := range []struct {
				field string
				raw   string
				out   any
				times func() []time.Time
			}{
				{"gap.live_block", `{"at":"` + stamp + `","until":"` + stamp + `"}`, &block, func() []time.Time { return []time.Time{block.At, block.Until} }},
				{"gap.live_control", `{"at":"` + stamp + `"}`, &control, func() []time.Time { return []time.Time{control.At} }},
				{"gap.mcp_tool", `{"at":"` + stamp + `"}`, &tool, func() []time.Time { return []time.Time{tool.At} }},
				{"gap.model_route", `{"at":"` + stamp + `"}`, &route, func() []time.Time { return []time.Time{route.At} }},
			} {
				t.Run(tc.field, func(t *testing.T) {
					if err := decodeField(tc.field, []byte(tc.raw), tc.out); err != nil {
						t.Fatal(err)
					}
					want, err := time.ParseInLocation(time.RFC3339Nano, stamp, time.UTC)
					if err != nil {
						t.Fatal(err)
					}
					for _, got := range tc.times() {
						if got.Location() == time.Local {
							t.Errorf("%s retained host location", tc.field)
						}
						if !got.Equal(want) {
							t.Errorf("%s instant = %v, want %v", tc.field, got, want)
						}
					}
				})
			}
		})
	}
}

// Payload validation already used json/v2's strict RFC 3339 profile. Avoiding its implicit
// time.Time unmarshaler must keep those refusals and the accepted numeric-offset instants.
func TestPayloadValidationTimestampGrammarUnchanged(t *testing.T) {
	for _, stamp := range []string{
		"2026-09-22T09:00:00Z", "2026-09-22T09:00:00.001+01:30", "0000-01-01T00:00:00-23:59",
		"2026-09-22T09:00:00.123456789123-00:00", "2024-02-29T09:00:00Z",
		"2026-09-22T9:00:00Z", "2026-09-22T09:00:00,001Z", "2026-09-22T09:00:00+24:00",
		"2026-09-22T09:00:00+00:60", "2026-02-29T09:00:00Z", "2026-09-22T09:00:60Z",
		"2026-09-22t09:00:00Z", "2026-09-22T09:00:00z", "2026-09-22T09:00:00.Z", "",
	} {
		t.Run(stamp, func(t *testing.T) {
			raw := []byte(`{"at":"` + stamp + `"}`)
			var got, want LiveControlChange
			gotErr := decodeField("gap.live_control", raw, &got)
			wantErr := jsonv2.Unmarshal(raw, &want)
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("decodeField err = %v, previous json/v2 err = %v", gotErr, wantErr)
			}
			if gotErr == nil && !got.At.Equal(want.At) {
				t.Fatalf("instant = %v, previous json/v2 = %v", got.At, want.At)
			}
		})
	}
}
