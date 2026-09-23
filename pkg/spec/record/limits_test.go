// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"reflect"
	"testing"
)

// ptr returns a pointer to v, for the presence fields of Limits.
func ptr[T any](v T) *T { return &v }

// TestLimitsKeepAZeroBudget is E16 on the wire: an explicit 0 is the tightest budget there is, so a run_start
// that carried one must still carry it after a reader decodes and re-encodes the block, and an absent key must
// stay absent. The test works on JSON alone, so it holds whatever Go types the fields are given.
func TestLimitsKeepAZeroBudget(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"every dimension bounded at zero", `{"cost_usd":0,"repeats":0,"stall_after":"0s","tokens":0,"wall":"0s"}`},
		{"one zero among positives", `{"cost_usd":2.5,"tokens":0}`},
		{"nothing bounded", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l Limits
			if err := json.Unmarshal([]byte(tc.in), &l); err != nil {
				t.Fatal(err)
			}
			out, err := json.Marshal(l)
			if err != nil {
				t.Fatal(err)
			}
			var got, want map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tc.in), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip\n got %s\nwant %s", out, tc.in)
			}
		})
	}
}

// TestRunStartCapabilitiesRoundTrip pins the capability line's encoding: every row is written, false
// included, because a false is the statement that the run could not do that thing, and a ledger without the
// key at all is an older writer's.
func TestRunStartCapabilitiesRoundTrip(t *testing.T) {
	in := RunStartPayload{Tier: "landlock", Capabilities: map[string]bool{"fs.deny_read": false, "exec.deny": true}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if got := string(back["capabilities"]); got != `{"exec.deny":true,"fs.deny_read":false}` {
		t.Fatalf("capabilities = %s", got)
	}
	b, err = json.Marshal(RunStartPayload{Tier: "landlock"})
	if err != nil {
		t.Fatal(err)
	}
	back = nil
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["capabilities"]; ok {
		t.Fatal("a run_start with no capability line wrote an empty one")
	}
}
