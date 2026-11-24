// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// liveSchemaNode is the part of a JSON Schema node the agreement test reads.
type liveSchemaNode struct {
	Pattern    string                     `json:"pattern"`
	Enum       []string                   `json:"enum"`
	MaxLength  int                        `json:"maxLength"`
	MaxItems   int                        `json:"maxItems"`
	Required   []string                   `json:"required"`
	Properties map[string]*liveSchemaNode `json:"properties"`
	Defs       map[string]*liveSchemaNode `json:"$defs"`
}

// TestLiveSchemaMatchesGo: spec/record/v1/live-fields.schema.json and this package agree on the live fields' keys, value
// sets and limits: each block's keys are its type's JSON keys, the ops, kinds, refusals and sources are the constants',
// and the schema's caps are MaxLiveBlockAddrs, MaxLiveFence and MaxLiveFenceValue. internal/testutil/jsonschema's
// TestRecordLiveFixturesAgainstSchema and TestLiveBoundariesAgreeWithGo run the documents and the boundaries through the
// real validator (C177).
func TestLiveSchemaMatchesGo(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "live-fields.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root liveSchemaNode
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	d := root.Defs
	check := func(what string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: schema %v, Go %v", what, got, want)
		}
	}
	keys := func(n *liveSchemaNode) []string {
		var ks []string
		for k := range n.Properties {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return ks
	}
	goKeys := func(v any) []string {
		ks := jsonNames(v)
		slices.Sort(ks)
		return ks
	}
	lb, lc, lf, fe := d["live_block"], d["live_control"], d["live_fence"], d["live_fence_entry"]
	check("live_block keys", keys(lb), goKeys(LiveBlockChange{}))
	check("live_block required", slices.Sorted(slices.Values(lb.Required)), []string{"at", "by", "kind", "op", "rule", "serial", "value"})
	check("live_block ops", lb.Properties["op"].Enum, []string{LiveOpAdd, LiveOpRemove, LiveOpExpire, LiveOpLift, LiveOpRestore})
	check("live_block kinds", lb.Properties["kind"].Enum, LiveBlockKinds)
	check("live_block refused", lb.Properties["refused"].Enum, liveRefusals[:])
	check("live_block addrs cap", lb.Properties["addrs"].MaxItems, MaxLiveBlockAddrs)
	check("live_control keys", keys(lc), goKeys(LiveControlChange{}))
	check("live_control required", slices.Sorted(slices.Values(lc.Required)), []string{"at", "by", "op", "serial"})
	check("live_control ops", lc.Properties["op"].Enum, []string{LiveOpPause, LiveOpResume})
	check("live_fence keys", keys(lf), goKeys(LiveFence{}))
	check("live_fence entries cap", lf.Properties["entries"].MaxItems, MaxLiveFence)
	check("live_fence_entry keys", keys(fe), goKeys(LiveFenceEntry{}))
	check("live_fence_entry kinds", fe.Properties["kind"].Enum, liveFenceKinds[:])
	check("live_fence_entry sources", fe.Properties["source"].Enum, []string{LiveFenceSourceDeny, LiveFenceSourceNew})
	check("live_fence_entry value cap", fe.Properties["value"].MaxLength, MaxLiveFenceValue)
	check("live_fence sha256", lf.Properties["sha256"].Pattern, "^[0-9a-f]{64}$")
	// Every why the schema gives a live_block or live_control branch is one the validator maps to an op.
	for why := range liveBlockWhys {
		if !hasWhyBranch(t, b, why) {
			t.Errorf("the schema has no branch for the live block why %q", why)
		}
	}
	for why := range liveControlWhys {
		if !hasWhyBranch(t, b, why) {
			t.Errorf("the schema has no branch for the live control why %q", why)
		}
	}
}

// hasWhyBranch reports whether the schema's allOf names why in a branch's if.
func hasWhyBranch(t *testing.T, schema []byte, why string) bool {
	t.Helper()
	var s struct {
		AllOf []struct {
			If struct {
				Properties struct {
					Payload struct {
						Properties struct {
							Why struct {
								Const string `json:"const"`
							} `json:"why"`
						} `json:"properties"`
					} `json:"payload"`
				} `json:"properties"`
			} `json:"if"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		t.Fatal(err)
	}
	for _, b := range s.AllOf {
		if b.If.Properties.Payload.Properties.Why.Const == why {
			return true
		}
	}
	return false
}
