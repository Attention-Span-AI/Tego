// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// baselineRecordFacts retains the compiler's private, historical placement facts.
// It is evidence, never an input to a launching compiler or a fresh topology probe.
type baselineRecordFacts struct {
	relations          map[baselineRelationKey]baselineRecordRelation
	DenyWrite          []FSRule              `json:"deny_write"`
	Absent             []AbsentRow           `json:"absent"`
	Entries            []baselineRecordEntry `json:"entries"`
	FS                 []FSRule              `json:"fs"`
	FSAsk              []FSRule              `json:"fs_ask"`
	Exec               []ExecRule            `json:"exec"`
	Reads              HeldReads             `json:"reads"`
	HoldsNotifications bool                  `json:"holds_notifications"`
	ExecPinned         bool                  `json:"exec_pinned"`
}
type baselineRecordEntry struct {
	Relations      map[string]baselineRecordRelation `json:"path_relations"`
	LinksCovered   bool                              `json:"links_covered"`
	Resolved       config.ResolvedBaselineEntry      `json:"resolved"`
	Aliases        []string                          `json:"aliases"`
	Detached       []string                          `json:"detached"`
	Linked         []baselineRecordPin               `json:"linked"`
	CaseExact      bool                              `json:"case_exact"`
	Problem        string                            `json:"problem"`
	EnclosingWrite bool                              `json:"enclosing_write"`
}
type baselineRelationKey struct {
	Key         config.BaselineKey
	Value, Path string
}
type baselineRecordRelation struct {
	Inside    bool `json:"inside"`
	Enclosing bool `json:"enclosing"`
}
type baselineRecordPin struct {
	Path                 string
	Device, Inode, Links uint64
}

// RecordBaseline adds complete evidence only for a nonempty configured baseline.
// ownerKnown must describe the governed owner's passwd context, not a fallback home.
// No-baseline payloads retain their original revision and bytes.
func (rt *RuleTable) RecordBaseline(p *record.RunStartPayload, m *config.Machine, tier backend.Tier, plane string, execPinned, ownerKnown bool) error {
	if rt == nil || rt.Baseline == nil || len(rt.Baseline.Entries) == 0 {
		return nil
	}
	if p == nil || rt.Contract == nil || rt.EffectiveContract == nil {
		return fmt.Errorf("baseline record needs payload and source/effective contracts")
	}
	if rt.Replayed() {
		return fmt.Errorf("baseline replay cannot write launch evidence")
	}
	if m == nil || !m.BaselineKnown() {
		return fmt.Errorf("baseline sources: complete machine snapshot required")
	}
	bt := rt.Baseline
	b := &record.Baseline{V: 1, Mode: "applied", OwnerUID: bt.Owner.UID, Home: bt.Owner.Home, OwnerKnown: ownerKnown, ProtectedOwnerLayer: bt.ProtectedOwnerLayer, Rules: []record.BaselineRule{}, Sources: []record.BaselineSource{}}
	if !ownerKnown {
		b.Home = ""
	}
	if !bt.Applied {
		b.Mode = "not-applied"
	}
	for _, s := range m.LayerSources() {
		v := record.BaselineSource{Layer: s.Layer.String(), File: s.File, State: string(s.State)}
		if s.State == config.LayerPresent {
			v.SHA256 = new(s.SHA256)
			v.Bytes = m.LayerBytes(s.Layer)
			if v.Bytes == nil {
				v.Bytes = []byte{}
			}
		}
		b.Sources = append(b.Sources, v)
	}
	var err error
	b.SourceContract, err = rt.Contract.Canonical()
	if err != nil {
		return err
	}
	b.EffectiveContract, err = rt.EffectiveContract.Canonical()
	if err != nil {
		return err
	}
	cells, err := rt.BaselineCoverageAt(tier, plane, execPinned)
	if err != nil {
		return err
	}
	facts := baselineRecordFacts{DenyWrite: rt.DenyWrite, Absent: rt.AbsentDenyRead, FS: rt.FS, FSAsk: rt.FSAsk, Exec: rt.Exec, Reads: rt.Reads, HoldsNotifications: rt.HoldsFSNotifications(), ExecPinned: execPinned}
	for i, e := range bt.Entries {
		cell := cells[i]
		if (e.Key == config.BaselineDenyRead || e.Key == config.BaselineDenyWrite) && strings.HasPrefix(e.Value, "~/") && b.OwnerKnown {
			e.Expanded = strings.TrimSuffix(b.Home, "/") + "/" + e.Value[2:]
		}
		r := record.BaselineRule{ID: fmt.Sprintf("baseline.%d", i), Key: string(e.Key), Value: e.Value, Expanded: e.Expanded, State: string(e.State), Rule: slices.Clone(e.Rules), Sources: []record.BaselineOrigin{}, Tier: string(tier), Plane: plane, Held: cell.Held, ImageMode: cell.ImageMode, Operations: append([]string{}, cell.Operations...), Conditions: append([]string{}, cell.Conditions...), Limits: append([]string{}, cell.Limits...)}
		if !bt.Applied {
			r.State = "unresolved"
			r.Rule = nil
		}
		if r.State == "" {
			r.State = "unresolved"
		}
		if len(r.Rule) == 0 {
			r.Rule = []string{}
			r.EmptyReason = "redundant outside-grant write refusal or absent guard"
			if !bt.Applied {
				r.EmptyReason = "not-applied"
			}
		}
		for _, o := range e.Sources {
			r.Sources = append(r.Sources, record.BaselineOrigin{Layer: o.Layer.String(), File: o.File, Line: o.Line})
		}
		b.Rules = append(b.Rules, r)
		f := baselineRecordEntry{Relations: map[string]baselineRecordRelation{}, LinksCovered: rt.baselineReadLinksCovered(e.topology.linked), Resolved: e.ResolvedBaselineEntry, Aliases: e.topology.aliases, Detached: e.topology.detached, CaseExact: e.topology.caseExact, Problem: e.topology.problem, EnclosingWrite: e.topology.enclosingWrite}
		if bt.Applied && (e.Key == config.BaselineDenyRead || e.Key == config.BaselineDenyWrite) {
			for _, path := range baselineRelationPaths(e.Key, rt.FS, rt.FSAsk, rt.Exec) {
				inside, enclosing := baselineGrantRelation(&e, path)
				f.Relations[path] = baselineRecordRelation{inside, enclosing}
			}
		}
		for _, pin := range e.topology.linked {
			f.Linked = append(f.Linked, baselineRecordPin{pin.path, pin.key.dev, pin.key.ino, pin.links})
		}
		facts.Entries = append(facts.Entries, f)
	}
	if _, err := jsonv2.Marshal(facts); err != nil {
		return fmt.Errorf("baseline replay facts cannot be recorded losslessly: %w", err)
	}
	b.Replay, err = json.Marshal(facts)
	if err != nil {
		return err
	}
	b.SHA256, err = record.BaselineDigest(b.Rules)
	if err != nil {
		return err
	}
	if err = b.SealEvidence(); err != nil {
		return err
	}
	cp := *p
	// The baseline needs revision 39 at least; a caller that already selected a later one (every launch selects
	// record.MinorEveryLaunch, ADR 0157) keeps it, since that revision includes everything 39 allows.
	cp.RecordMinor = max(cp.RecordMinor, record.MinorBaseline)
	cp.ContractHash = hex.EncodeToString(rt.Hash[:])
	cp.EffectiveHash = hex.EncodeToString(rt.EffectiveHash[:])
	cp.Baseline = b
	if err = cp.ValidateBaseline(); err != nil {
		return err
	}
	*p = cp
	return nil
}

// ReplayRecordedBaseline validates the recorded facts before issuing a sealed
// handle. It reads no files, config, passwd database or mount inventory.
func ReplayRecordedBaseline(source *Contract, p record.RunStartPayload) (*BaselineReplay, error) {
	if err := p.ValidateBaseline(); err != nil {
		return nil, err
	}
	if !p.BaselineRecorded() {
		return UnknownBaselineReplay(), nil
	}
	b := p.Baseline
	if source == nil {
		return nil, fmt.Errorf("baseline source_contract is missing")
	}
	if !b.OwnerKnown {
		return nil, fmt.Errorf("baseline owner/home unknown: no verified replay handle")
	}
	var layers []config.ReplayLayer
	for _, s := range b.Sources {
		layer := config.LayerEtc
		switch s.Layer {
		case "etc":
		case "user":
			layer = config.LayerUser
		case "env":
			layer = config.LayerEnvFile
		default:
			return nil, fmt.Errorf("baseline sources.layer invalid")
		}
		layers = append(layers, config.ReplayLayer{LayerSource: config.LayerSource{Layer: layer, File: s.File, State: config.LayerState(s.State)}, Bytes: s.Bytes})
	}
	union, err := config.ReplayBaseline(layers)
	if err != nil {
		return nil, err
	}
	entries := union.Entries()
	if len(entries) != len(b.Rules) {
		return nil, fmt.Errorf("baseline rules: recorded source union length differs")
	}
	var facts baselineRecordFacts
	if err := json.Unmarshal(b.Replay, &facts); err != nil {
		return nil, fmt.Errorf("baseline replay facts: %w", err)
	}
	facts.relations = map[baselineRelationKey]baselineRecordRelation{}
	if len(facts.Entries) != len(entries) {
		return nil, fmt.Errorf("baseline replay entries length differs")
	}
	bt := &BaselineTable{Owner: config.BaselineOwner{UID: b.OwnerUID, Home: b.Home}, Applied: b.Mode == "applied", ProtectedOwnerLayer: b.ProtectedOwnerLayer, identities: map[string]fileKey{}, denyWrites: map[string]bool{}}
	for i, e := range entries {
		r, f := b.Rules[i], facts.Entries[i]
		if err := validateRecordedBaselineResolution(f, bt.Applied); err != nil {
			return nil, fmt.Errorf("baseline rules.%d resolution/state: %w", i, err)
		}
		if bt.Applied && (e.Key == config.BaselineDenyRead || e.Key == config.BaselineDenyWrite) {
			for _, path := range baselineRelationPaths(e.Key, facts.FS, facts.FSAsk, facts.Exec) {
				relation, ok := f.Relations[path]
				if !ok {
					return nil, fmt.Errorf("baseline replay rules.%d path_relations missing %q", i, path)
				}
				facts.relations[baselineRelationKey{e.Key, e.Value, path}] = relation
			}
		}
		if string(e.Key) != r.Key || e.Value != r.Value || (e.Key != f.Resolved.Key || e.Value != f.Resolved.Value || !slices.Equal(e.Sources, f.Resolved.Sources)) {
			return nil, fmt.Errorf("baseline rules.%d source membership/value does not reproduce", i)
		}
		origins := make([]record.BaselineOrigin, 0, len(e.Sources))
		for _, s := range e.Sources {
			origins = append(origins, record.BaselineOrigin{Layer: s.Layer.String(), File: s.File, Line: s.Line})
		}
		if !slices.Equal(origins, r.Sources) {
			return nil, fmt.Errorf("baseline rules.%d sources/lines do not reproduce", i)
		}
		expanded := e.Value
		if (e.Key == config.BaselineDenyRead || e.Key == config.BaselineDenyWrite) && strings.HasPrefix(expanded, "~/") {
			expanded = strings.TrimSuffix(b.Home, "/") + "/" + expanded[2:]
		}
		if expanded != r.Expanded || expanded != f.Resolved.Expanded {
			return nil, fmt.Errorf("baseline rules.%d expanded/home do not reproduce", i)
		}
		state := string(f.Resolved.State)
		if !bt.Applied {
			state = "unresolved"
		}
		if state != r.State {
			return nil, fmt.Errorf("baseline rules.%d state does not reproduce", i)
		}
		row := BaselineRule{ResolvedBaselineEntry: f.Resolved, Rules: slices.Clone(r.Rule), topology: baselineTopologyFacts{aliases: f.Aliases, detached: f.Detached, caseExact: f.CaseExact, problem: f.Problem, enclosingWrite: f.EnclosingWrite}}
		for _, pin := range f.Linked {
			row.topology.linked = append(row.topology.linked, baselinePin{pin.Path, fileKey{pin.Device, pin.Inode}, pin.Links})
		}
		row.Coverage = []BaselineCoverage{{Tier: backend.Tier(r.Tier), Plane: r.Plane, Held: r.Held, ImageMode: r.ImageMode, Operations: r.Operations, Conditions: r.Conditions, Limits: r.Limits}}
		bt.Entries = append(bt.Entries, row)
		if f.Resolved.State == config.LayerPresent {
			for _, path := range []string{f.Resolved.Expanded, f.Resolved.Target} {
				bt.identities[path] = fileKey{f.Resolved.Device, f.Resolved.Inode}
			}
		} else {
			bt.identities[f.Resolved.Ancestor] = fileKey{f.Resolved.Device, f.Resolved.Inode}
		}
		for _, pin := range f.Linked {
			bt.identities[pin.Path] = fileKey{pin.Device, pin.Inode}
		}
		if e.Key == config.BaselineDenyWrite {
			bt.denyWrites[f.Resolved.Target] = true
		}
	}
	sourceBytes, err := source.Canonical()
	if err != nil || !bytes.Equal(sourceBytes, b.SourceContract) {
		return nil, fmt.Errorf("baseline source_contract bytes do not reproduce")
	}
	ch, err := hex.DecodeString(p.ContractHash)
	if err != nil {
		return nil, err
	}
	eh, err := hex.DecodeString(p.EffectiveHash)
	if err != nil {
		return nil, err
	}
	handle, err := VerifyBaselineReplay(source, bt, [32]byte(ch), [32]byte(eh), b.EffectiveContract)
	if err != nil {
		return nil, err
	}
	// Recompute action membership and the actual coverage cell from the recorded
	// compiler projection, never from today's files or capability probes.
	projection := &RuleTable{Contract: source, EffectiveContract: source, FS: facts.FS, FSAsk: facts.FSAsk, Exec: facts.Exec, DenyWrite: facts.DenyWrite, AbsentDenyRead: facts.Absent, Reads: facts.Reads, Baseline: cloneBaseline(bt), baselineReplayFacts: &facts}
	if bt.Applied {
		effective, err := prependBaseline(source, bt)
		if err != nil {
			return nil, err
		}
		projection.EffectiveContract = effective
	}
	for i := range projection.Baseline.Entries {
		projection.Baseline.Entries[i].Rules = nil
	}
	(&compiler{rt: projection}).baselineRules()
	cells, err := projection.BaselineCoverageAt(backend.Tier(p.Tier), p.DecisionPlane, facts.ExecPinned)
	if err != nil {
		return nil, fmt.Errorf("baseline coverage: %w", err)
	}
	for i, r := range b.Rules {
		if !slices.Equal(projection.Baseline.Entries[i].Rules, r.Rule) {
			return nil, fmt.Errorf("baseline rules.%d action membership does not reproduce", i)
		}
		if r.Tier != p.Tier || r.Plane != p.DecisionPlane {
			return nil, fmt.Errorf("baseline rules.%d actual tier/plane differs from run_start", i)
		}
		cell := cells[i]
		if cell.Held != r.Held || cell.ImageMode != r.ImageMode || !slices.Equal(cell.Operations, r.Operations) || !slices.Equal(cell.Conditions, r.Conditions) || !slices.Equal(cell.Limits, r.Limits) {
			return nil, fmt.Errorf("baseline rules.%d coverage does not reproduce", i)
		}
	}
	handle.facts = &facts
	return handle, nil
}

func baselineRelationPaths(key config.BaselineKey, fs, ask []FSRule, exec []ExecRule) []string {
	paths := map[string]bool{}
	for _, g := range slices.Concat(fs, ask) {
		if g.Kind == FSWrite || g.Kind == FSAsk {
			paths[g.Canonical()] = true
		}
	}
	if key == config.BaselineDenyRead {
		for _, g := range exec {
			for _, p := range []string{g.Path, g.Resolved, g.Interp} {
				if p != "" {
					paths[p] = true
				}
			}
		}
	}
	out := make([]string, 0, len(paths))
	for p := range paths {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func (rt *RuleTable) baselineCoverageRelation(e *BaselineRule, path string) (inside, enclosing bool) {
	if rt.baselineReplayFacts != nil {
		r := rt.baselineReplayFacts.relations[baselineRelationKey{e.Key, e.Value, path}]
		return r.Inside, r.Enclosing
	}
	return baselineGrantRelation(e, path)
}

func validateRecordedBaselineResolution(f baselineRecordEntry, applied bool) error {
	if !applied {
		return nil
	}
	e := f.Resolved
	switch e.Key {
	case config.BaselineDenyRead, config.BaselineDenyWrite:
		if f.Problem != "" {
			return fmt.Errorf("recorded topology refused launch: %s", f.Problem)
		}
		switch e.State {
		case config.LayerPresent:
			if !filepath.IsAbs(e.Target) || e.Ancestor != "" || e.Missing != "" {
				return fmt.Errorf("present target facts disagree")
			}
		case config.LayerAbsent:
			if e.Target != "" || !filepath.IsAbs(e.Ancestor) || e.Missing == "" || filepath.IsAbs(e.Missing) {
				return fmt.Errorf("absent ancestor/name facts disagree")
			}
			for _, part := range strings.Split(e.Missing, "/") {
				if part == ".." {
					return fmt.Errorf("absence cannot cross unresolved parent components")
				}
			}
			for _, s := range e.Sources {
				if s.Layer != config.LayerEtc {
					return fmt.Errorf("absent target needs system-only sources")
				}
			}
		case config.LayerUnselected, config.LayerUnknown:
			return fmt.Errorf("applied file entry has unresolved state")
		default:
			return fmt.Errorf("applied file entry has invalid state %q", e.State)
		}
	case config.BaselineDenyExec, config.BaselineDenyEnv:
		if e.State != config.LayerPresent || e.Target != "" || e.Ancestor != "" || e.Missing != "" || e.Device != 0 || e.Inode != 0 || f.Problem != "" {
			return fmt.Errorf("non-file entry carries incompatible resolution facts")
		}
	}
	return nil
}
