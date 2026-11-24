// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveGoOnly are the invalid fixtures of spec/record/v1/fixtures/live whose rule JSON Schema cannot state (the schema's
// description lists them: a key spelt in another letter case, and a rule that is not the change's own kind and value):
// pkg/spec/record refuses them, and the schema accepts them. The other field-case fixtures the schema refuses too, for
// the member they leave out.
var liveGoOnly = []string{"field-case.Live_Mode.", "live-block.rule-of-another-kind."}

// TestRecordLiveFixturesAgainstSchema: spec/record/v1/live-fields.schema.json, read by the real validator, accepts every
// valid document of fixtures/live and refuses every invalid one except those whose rule is pkg/spec/record's alone.
// pkg/spec/record's TestLiveFieldFixtures runs the same documents through Event.ValidateAt, and TestLiveSchemaMatchesGo
// holds the schema's limits and value sets to the Go ones (C177).
func TestRecordLiveFixturesAgainstSchema(t *testing.T) {
	schema := filepath.Join(recordDir, "live-fields.schema.json")
	valid, _ := filepath.Glob(filepath.Join(recordDir, "fixtures", "live", "valid", "*.json"))
	invalid, _ := filepath.Glob(filepath.Join(recordDir, "fixtures", "live", "invalid", "*.json"))
	if len(valid) < 20 || len(invalid) < 45 {
		t.Fatalf("found %d valid and %d invalid live fixtures, want the shipped set", len(valid), len(invalid))
	}
	for _, f := range valid {
		t.Run("valid/"+filepath.Base(f), func(t *testing.T) {
			doc, ok := decodeLiveJSON(t, f)
			if !ok {
				t.Fatalf("%s is not I-JSON", filepath.Base(f))
			}
			Validate(t, schema, doc)
		})
	}
	for _, f := range invalid {
		t.Run("invalid/"+filepath.Base(f), func(t *testing.T) {
			doc, ok := decodeLiveJSON(t, f)
			if !ok {
				return // refused by the reader before any schema
			}
			err := Check(schema, doc)
			goOnly := false
			for _, p := range liveGoOnly {
				goOnly = goOnly || strings.HasPrefix(filepath.Base(f), p)
			}
			switch {
			case goOnly && err == nil:
			case goOnly:
				t.Errorf("%s is in liveGoOnly but the schema refuses it too; take it out of the list", filepath.Base(f))
			case err == nil:
				t.Errorf("the schema accepts %s, which pkg/spec/record refuses", filepath.Base(f))
			}
		})
	}
}

// liveDocOf is a fixture of fixtures/live as a map to change.
func liveDocOf(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(recordDir, "fixtures", "live", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// goVerdict is what pkg/spec/record says of a document of fixtures/live's form: the error ValidateAt returns at the
// document's revision, or nil.
func goVerdict(t *testing.T, doc map[string]any) error {
	t.Helper()
	payload, err := json.Marshal(doc["payload"])
	if err != nil {
		t.Fatal(err)
	}
	e := &record.Event{V: record.Version, Kind: record.Kind(doc["kind"].(string)), Source: record.SourceSupervisor,
		Run: "r-00000000-000000000000a-aaaaaa", Agent: "retriever", TS: time.Date(2026, 10, 27, 12, 3, 1, 0, time.UTC), Payload: payload}
	if r, ok := doc["rule"].(string); ok && e.Kind == record.KindRefused {
		var p struct {
			Reason record.Reason `json:"reason"`
		}
		_ = json.Unmarshal(payload, &p)
		e.Rule, e.Reason = r, p.Reason
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("the envelope is not valid: %v", err)
	}
	return e.ValidateAt(int(doc["minor"].(float64)))
}

// TestLiveBoundariesAgreeWithGo: at each boundary of the live fields (a serial of 0 and 1, 32 and 33 addresses, 64 and 65
// fence entries, a value of 4096 and of 4097 characters, a time limit, a refusal and a kind at the revision before the
// one that adds them and at it) the schema and Event.ValidateAt give one answer. A boundary only Go holds is in
// liveGoOnly's family and is not here.
func TestLiveBoundariesAgreeWithGo(t *testing.T) {
	schema := filepath.Join(recordDir, "live-fields.schema.json")
	addrs := func(n int) []any {
		var out []any
		for i := range n {
			out = append(out, fmt.Sprintf("10.0.%d.%d", i/200, i%200+1))
		}
		return out
	}
	entries := func(n int) []any {
		var out []any
		for i := range n {
			v := fmt.Sprintf("/data/%d", i)
			out = append(out, map[string]any{"kind": "read", "value": v, "source": "new", "rule": "live.fence[read:" + v + "]"})
		}
		return out
	}
	netAdd := func(t *testing.T, minor int, mutate func(b map[string]any)) map[string]any {
		doc := liveDocOf(t, "live-block-add-until.json")
		b := doc["payload"].(map[string]any)["live_block"].(map[string]any)
		delete(b, "until")
		b["kind"], b["value"], b["rule"] = "net", "example.test:443", "live.block[net:example.test:443]"
		doc["minor"] = float64(minor)
		mutate(b)
		return doc
	}
	block := func(doc map[string]any) map[string]any {
		return doc["payload"].(map[string]any)["live_block"].(map[string]any)
	}
	cases := []struct {
		name string
		doc  func(t *testing.T) map[string]any
		ok   bool
	}{
		{"serial 1", func(t *testing.T) map[string]any { return netAdd(t, 26, func(b map[string]any) { b["serial"] = 1.0 }) }, true},
		{"serial 0", func(t *testing.T) map[string]any { return netAdd(t, 26, func(b map[string]any) { b["serial"] = 0.0 }) }, false},
		{"32 addresses at 41", func(t *testing.T) map[string]any {
			return netAdd(t, 41, func(b map[string]any) { b["addrs"] = addrs(32) })
		}, true},
		{"33 addresses at 41", func(t *testing.T) map[string]any {
			return netAdd(t, 41, func(b map[string]any) { b["addrs"] = addrs(33) })
		}, false},
		{"addresses at 40", func(t *testing.T) map[string]any {
			return netAdd(t, 40, func(b map[string]any) { b["addrs"] = addrs(2) })
		}, false},
		{"more with a full list", func(t *testing.T) map[string]any {
			return netAdd(t, 41, func(b map[string]any) { b["addrs"], b["addrs_more"] = addrs(32), 3.0 })
		}, true},
		{"more with a short list", func(t *testing.T) map[string]any {
			return netAdd(t, 41, func(b map[string]any) { b["addrs"], b["addrs_more"] = addrs(2), 3.0 })
		}, false},
		{"a negative more", func(t *testing.T) map[string]any {
			return netAdd(t, 41, func(b map[string]any) { b["addrs"], b["addrs_more"] = addrs(32), -1.0 })
		}, false},
		{"until at 26", func(t *testing.T) map[string]any {
			return netAdd(t, 26, func(b map[string]any) { b["until"] = "2026-10-30T12:03:00Z" })
		}, true},
		{"until at 25", func(t *testing.T) map[string]any {
			return netAdd(t, 25, func(b map[string]any) { b["until"] = "2026-10-30T12:03:00Z" })
		}, false},
		{"a read block at 24", func(t *testing.T) map[string]any {
			return netAdd(t, 24, func(b map[string]any) { b["kind"], b["rule"] = "read", "live.block[read:example.test:443]" })
		}, true},
		{"a read block at 23", func(t *testing.T) map[string]any {
			return netAdd(t, 23, func(b map[string]any) { b["kind"], b["rule"] = "read", "live.block[read:example.test:443]" })
		}, false},
		{"a pause at 24", func(t *testing.T) map[string]any { d := liveDocOf(t, "run-paused.json"); d["minor"] = 24.0; return d }, true},
		{"a pause at 23", func(t *testing.T) map[string]any { d := liveDocOf(t, "run-paused.json"); d["minor"] = 23.0; return d }, false},
		{"a pause op on a resume", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "run-resumed.json")
			d["payload"].(map[string]any)["live_control"].(map[string]any)["op"] = "pause"
			return d
		}, false},
		{"64 fence entries", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "run-start-adjustable.json")
			d["payload"].(map[string]any)["live_fence"].(map[string]any)["entries"] = entries(64)
			return d
		}, true},
		{"65 fence entries", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "run-start-adjustable.json")
			d["payload"].(map[string]any)["live_fence"].(map[string]any)["entries"] = entries(65)
			return d
		}, false},
		{"a fence at 25", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "run-start-adjustable.json")
			d["minor"], d["payload"].(map[string]any)["record_minor"] = 25.0, 25.0
			return d
		}, false},
		{"a fence value of 4096 characters", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "run-start-adjustable.json")
			v := "/" + strings.Repeat("a", 4095)
			d["payload"].(map[string]any)["live_fence"].(map[string]any)["entries"] = []any{map[string]any{"kind": "read", "value": v, "source": "new", "rule": "live.fence[read:" + v + "]"}}
			return d
		}, true},
		{"a block value left empty", func(t *testing.T) map[string]any { return netAdd(t, 26, func(b map[string]any) { b["value"] = "" }) }, false},
		{"an op that is not the why's", func(t *testing.T) map[string]any { return netAdd(t, 26, func(b map[string]any) { b["op"] = "remove" }) }, false},
		{"a refusal that is none of the four", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "live-lift-refused.json")
			block(d)["refused"] = "because"
			return d
		}, false},
		{"refused on an add", func(t *testing.T) map[string]any {
			return netAdd(t, 26, func(b map[string]any) { b["refused"] = "mac" })
		}, false},
		{"a note of 200 characters on a lift at 41", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "live-rule-lifted-note.json")
			block(d)["note"] = strings.Repeat("n", 200)
			return d
		}, true},
		{"a note of 201 characters", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "live-rule-lifted-note.json")
			block(d)["note"] = strings.Repeat("n", 201)
			return d
		}, false},
		{"a note at 40", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "live-rule-lifted-note.json")
			d["minor"] = 40.0
			return d
		}, false},
		{"a note with a line break", func(t *testing.T) map[string]any {
			d := liveDocOf(t, "live-rule-lifted-note.json")
			block(d)["note"] = "a\nb"
			return d
		}, false},
		{"a note on an add", func(t *testing.T) map[string]any {
			return netAdd(t, 41, func(b map[string]any) { b["note"] = "why" })
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := c.doc(t)
			sErr, gErr := Check(schema, doc), goVerdict(t, doc)
			if (sErr == nil) != c.ok || (gErr == nil) != c.ok {
				t.Errorf("want accepted=%v: schema %v, pkg/spec/record %v", c.ok, sErr != nil, gErr)
			}
		})
	}
	if !slices.Contains(record.LiveBlockKinds, "write") {
		t.Fatal("the live block kinds changed; revisit the boundaries")
	}
}

// decodeLiveJSON reads a fixture into the data model the schema checks; a document with a repeated key or invalid UTF-8
// is no I-JSON (RFC 7493) and its reader refuses it before any schema is consulted.
func decodeLiveJSON(t *testing.T, path string) (doc any, iJSON bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !jsontext.Value(b).IsValid() {
		return nil, false
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc, true
}
