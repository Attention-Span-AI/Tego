// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBaselineRecordedReplay(t *testing.T) {
	for _, observe := range []bool{false, true} {
		t.Run(map[bool]string{false: "applied", true: "not-applied"}[observe], func(t *testing.T) {
			f := newFixture(t)
			c := f.load("version: 0\nname: recorded\ncommand: [python]\n")
			m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n  env: {deny: [TOKEN]}\n")
			opts := f.opts()
			if observe {
				opts = append(opts, WithObserve())
			}
			rt, ds, err := Compile(c, m, opts...)
			if err != nil {
				t.Fatalf("%v %v", err, ds)
			}
			tier := backend.TierLandlock
			if observe {
				tier = backend.TierObserve
			}
			p := record.RunStartPayload{Tier: string(tier)}
			if err := rt.RecordBaseline(&p, m, tier, "", false, true); err != nil {
				t.Fatal(err)
			}
			if p.RecordMinor != record.MinorBaseline || p.Baseline == nil || len(p.Baseline.Rules) != 2 {
				t.Fatalf("missing record: %+v", p)
			}
			if err := p.ValidateBaseline(); err != nil {
				t.Fatal(err)
			}
			for _, s := range m.LayerSources() {
				if s.File != "" {
					if err := os.Remove(s.File); err != nil {
						t.Fatal(err)
					}
				}
			}
			replay, err := ReplayRecordedBaseline(c, p)
			if err != nil {
				t.Fatal(err)
			}
			got, ds, err := replay.Compile(c, m, opts...)
			if err != nil {
				t.Fatalf("%v %v", err, ds)
			}
			if got.EffectiveHash != rt.EffectiveHash || len(got.Baseline.Entries) != 2 || !got.Replayed() {
				t.Fatal("record replay changed or applied twice")
			}
			edits := map[string]func(*record.RunStartPayload){
				"sha256":         func(p *record.RunStartPayload) { p.Baseline.SHA256 = strings.Repeat("0", 64) },
				"contract_hash":  func(p *record.RunStartPayload) { p.ContractHash = strings.Repeat("0", 64) },
				"effective_hash": func(p *record.RunStartPayload) { p.EffectiveHash = strings.Repeat("0", 64) },
				"owner":          func(p *record.RunStartPayload) { p.Baseline.OwnerUID++ },
				"home":           func(p *record.RunStartPayload) { p.Baseline.Home += "/changed" },
				"mode":           func(p *record.RunStartPayload) { p.Baseline.Mode = "broken" },
				"sources": func(p *record.RunStartPayload) {
					p.Baseline.Sources[1].Bytes = append(p.Baseline.Sources[1].Bytes, '#')
				},
				"absence":  func(p *record.RunStartPayload) { p.Baseline.Sources[0].State = "absent" },
				"expanded": func(p *record.RunStartPayload) { p.Baseline.Rules[0].Expanded = "different" },
				"membership": func(p *record.RunStartPayload) {
					p.Baseline.Rules[0].Rule = append(p.Baseline.Rules[0].Rule, "made.up")
				},
				"coverage": func(p *record.RunStartPayload) {
					p.Baseline.Rules[0].Limits = append(p.Baseline.Rules[0].Limits, "invented")
				},
				"tier":   func(p *record.RunStartPayload) { p.Baseline.Rules[0].Tier = "bpflsm" },
				"plane":  func(p *record.RunStartPayload) { p.Baseline.Rules[0].Plane = "lsm" },
				"replay": func(p *record.RunStartPayload) { p.Baseline.Replay = json.RawMessage(`{}`) },
			}
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			for name, edit := range edits {
				t.Run(name, func(t *testing.T) {
					var q record.RunStartPayload
					if err := json.Unmarshal(data, &q); err != nil {
						t.Fatal(err)
					}
					edit(&q)
					if _, err := ReplayRecordedBaseline(c, q); err == nil {
						t.Fatalf("edited %s accepted", name)
					}
				})
			}
		})
	}
}

func TestBaselineRecordAbsentWithoutBaseline(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: legacy\ncommand: [python]\n")
	rt, _, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatal(err)
	}
	p := record.RunStartPayload{RecordMinor: record.MinorLearn, ContractHash: "legacy"}
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.RecordBaseline(&p, f.machine, backend.TierLandlock, "", false, true); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("no-baseline bytes changed: %s", after)
	}
}

func TestEveryRecordedBaselineFactRejectsAnEdit(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: facts\ncommand: [python]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n  env: {deny: [TOKEN]}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %v", err, ds)
	}
	p := record.RunStartPayload{Tier: "landlock"}
	if err := rt.RecordBaseline(&p, m, backend.TierLandlock, "", false, true); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for path := range p.Baseline.FactSHA256 {
		if strings.HasSuffix(path, ".length") {
			continue
		}
		t.Run(path, func(t *testing.T) {
			var root map[string]any
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			if err := decoder.Decode(&root); err != nil {
				t.Fatal(err)
			}
			node := root["baseline"]
			parts := strings.Split(path, ".")
			for _, part := range parts[:len(parts)-1] {
				switch v := node.(type) {
				case map[string]any:
					node = v[part]
				case []any:
					i, err := strconv.Atoi(part)
					if err != nil {
						t.Fatal(err)
					}
					node = v[i]
				default:
					t.Fatalf("cannot visit %s", path)
				}
			}
			obj := node.(map[string]any)
			key := parts[len(parts)-1]
			value := obj[key]
			switch v := value.(type) {
			case string:
				if strings.HasSuffix(path, ".bytes") || path == "source_contract" || path == "effective_contract" {
					obj[key] = base64.StdEncoding.EncodeToString([]byte("edited"))
				} else {
					obj[key] = v + "-edited"
				}
			case bool:
				obj[key] = !v
			case json.Number:
				n, err := v.Int64()
				if err != nil {
					t.Fatal(err)
				}
				obj[key] = n + 1
			case float64:
				obj[key] = v + 1
			case []any:
				if len(v) > 0 {
					if first, ok := v[0].(map[string]any); ok {
						first["line"] = float64(999)
					} else {
						obj[key] = append(v, "edited")
					}
				} else {
					obj[key] = []any{"edited"}
				}
			case map[string]any:
				obj[key] = map[string]any{}
			case nil:
				if strings.HasSuffix(path, ".bytes") {
					obj[key] = base64.StdEncoding.EncodeToString([]byte("edited"))
				} else {
					obj[key] = "edited"
				}
			default:
				t.Fatalf("unhandled %s: %T", path, value)
			}
			edited, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			var q record.RunStartPayload
			// Raw evidence now refuses the edit before a typed replay is possible.
			err = json.Unmarshal(edited, &q)
			if err == nil {
				_, err = ReplayRecordedBaseline(c, q)
			}
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("edited %s: %v", path, err)
			}
		})
		checked++
	}
	if checked < 50 {
		t.Fatalf("only %d fact edits checked", checked)
	}
}

func TestBaselineReplayRejectsResealedContradictions(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: contradictions\ncommand: [python]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
	rt, _, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatal(err)
	}
	p := record.RunStartPayload{Tier: "landlock"}
	if err := rt.RecordBaseline(&p, m, backend.TierLandlock, "", false, true); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"coverage", "membership", "expanded", "sources"} {
		t.Run(which, func(t *testing.T) {
			var q record.RunStartPayload
			if err := json.Unmarshal(data, &q); err != nil {
				t.Fatal(err)
			}
			switch which {
			case "coverage":
				q.Baseline.Rules[0].Limits = append(q.Baseline.Rules[0].Limits, "invented")
			case "membership":
				q.Baseline.Rules[0].Rule = []string{"invented"}
			case "expanded":
				q.Baseline.Rules[0].Expanded = "other"
				q.Baseline.SHA256, err = record.BaselineDigest(q.Baseline.Rules)
				if err != nil {
					t.Fatal(err)
				}
			case "sources":
				q.Baseline.Rules[0].Sources[0].Line++
			}
			if err := q.Baseline.SealEvidence(); err != nil {
				t.Fatal(err)
			}
			_, err := ReplayRecordedBaseline(c, q)
			if err == nil || !strings.Contains(err.Error(), which) {
				t.Fatalf("resealed %s contradiction: %v", which, err)
			}
		})
	}
}

func TestBaselineReplayUsesRecordedPathRelations(t *testing.T) {
	e := BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: config.BaselineDenyRead, Value: "/recorded/target"}, Expanded: "/recorded/target", Target: "/recorded/target", State: config.LayerPresent}}
	path := "/no-current-filesystem-probe/grant"
	facts := &baselineRecordFacts{relations: map[baselineRelationKey]baselineRecordRelation{{e.Key, e.Value, path}: {Inside: true, Enclosing: true}}}
	rt := &RuleTable{baselineReplayFacts: facts}
	inside, enclosing := rt.baselineCoverageRelation(&e, path)
	if !inside || !enclosing {
		t.Fatal("historical coverage discarded recorded identity relations")
	}
}

func TestBaselineFileReplaySurvivesTargetDeletion(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.home, "recorded-private")
	f.file(target, "secret", 0600)
	c := f.load("version: 0\nname: file-replay\ncommand: [python]\n")
	m := baselineMachine(t, f, "  fs: {deny_read: ['"+target+"']}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %v", err, ds)
	}
	p := record.RunStartPayload{Tier: "landlock"}
	if err := rt.RecordBaseline(&p, m, backend.TierLandlock, "", false, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	for _, layer := range m.LayerSources() {
		if layer.File != "" {
			if err := os.Remove(layer.File); err != nil {
				t.Fatal(err)
			}
		}
	}
	handle, err := ReplayRecordedBaseline(c, p)
	if err != nil {
		t.Fatal(err)
	}
	if handle == nil || !handle.known || handle.facts == nil {
		t.Fatal("recorded file facts did not mint a sealed handle")
	}
	var facts baselineRecordFacts
	if err := json.Unmarshal(p.Baseline.Replay, &facts); err != nil {
		t.Fatal(err)
	}
	facts.Entries[0].Relations = nil
	p.Baseline.Replay, err = json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Baseline.SealEvidence(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayRecordedBaseline(c, p); err == nil || !strings.Contains(err.Error(), "path_relations") {
		t.Fatalf("missing recorded relations accepted: %v", err)
	}
}

func TestBaselineFrozenRecordInsertionReplay(t *testing.T) {
	for _, name := range []string{"applied", "not-applied", "zero"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", name+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			e, err := record.Decode(bytes.Split(data, []byte{'\n'})[0])
			if err != nil {
				t.Fatal(err)
			}
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			c, ds, err := LoadBytes("/srv/agent.yaml", p.Baseline.SourceContract, nil)
			if err != nil {
				t.Fatalf("%v %v", err, ds)
			}
			if _, err := ReplayRecordedBaseline(c, p); err != nil {
				t.Fatalf("frozen %s insertion/coverage changed: %v", name, err)
			}
		})
	}
}
