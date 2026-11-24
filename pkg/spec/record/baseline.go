// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// Baseline is the self-contained historical baseline evidence (ADR 0144).
// EvidenceSHA256 binds the auxiliary facts; SHA256 names only normalized rules.
// Neither digest authenticates the machine administrator or its mount namespace.
type Baseline struct {
	V                   int               `json:"v"`
	Mode                string            `json:"mode"`
	SHA256              string            `json:"sha256"`
	OwnerUID            int               `json:"owner_uid"`
	Home                string            `json:"home"`
	OwnerKnown          bool              `json:"owner_known"`
	Sources             []BaselineSource  `json:"sources"`
	ProtectedOwnerLayer string            `json:"protected_owner_layer"`
	Rules               []BaselineRule    `json:"rules"`
	SourceContract      []byte            `json:"source_contract"`
	EffectiveContract   []byte            `json:"effective_contract"`
	Replay              json.RawMessage   `json:"replay"`
	FactSHA256          map[string]string `json:"fact_sha256"`
	EvidenceSHA256      string            `json:"evidence_sha256"`
}

// BaselineSource distinguishes consulted bytes, absence and unselected layers.
type BaselineSource struct {
	Layer  string  `json:"layer"`
	File   string  `json:"file"`
	State  string  `json:"state"`
	SHA256 *string `json:"sha256"`
	Bytes  []byte  `json:"bytes"`
}

// BaselineOrigin is every contributing declaration, independent of action rule ids.
type BaselineOrigin struct {
	Layer string `json:"layer"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// BaselineRule retains the insertion order and actual mechanism coverage of an entry.
type BaselineRule struct {
	ID          string           `json:"id"`
	Key         string           `json:"key"`
	Value       string           `json:"value"`
	Expanded    string           `json:"expanded"`
	State       string           `json:"state"`
	Rule        []string         `json:"rule"`
	EmptyReason string           `json:"empty_reason"`
	Sources     []BaselineOrigin `json:"sources"`
	Tier        string           `json:"tier"`
	Plane       string           `json:"plane"`
	Held        string           `json:"held"`
	ImageMode   string           `json:"image_mode"`
	Operations  []string         `json:"operations"`
	Conditions  []string         `json:"conditions"`
	Limits      []string         `json:"limits"`
}

// BaselineDigest implements ADR 0144's fixed-field sorted JSON encoding.
func BaselineDigest(rules []BaselineRule) (string, error) {
	n := struct {
		V     int      `json:"v"`
		Read  []string `json:"fs.deny_read"`
		Write []string `json:"fs.deny_write"`
		Exec  []string `json:"exec.deny"`
		Env   []string `json:"env.deny"`
	}{1, []string{}, []string{}, []string{}, []string{}}
	for _, r := range rules {
		if !utf8.ValidString(r.Expanded) {
			return "", fmt.Errorf("baseline expanded: invalid UTF-8")
		}
		switch r.Key {
		case "fs.deny_read":
			n.Read = append(n.Read, r.Expanded)
		case "fs.deny_write":
			n.Write = append(n.Write, r.Expanded)
		case "exec.deny":
			n.Exec = append(n.Exec, r.Expanded)
		case "env.deny":
			n.Env = append(n.Env, r.Expanded)
		default:
			return "", fmt.Errorf("baseline key: unknown %q", r.Key)
		}
	}
	for _, a := range []*[]string{&n.Read, &n.Write, &n.Exec, &n.Env} {
		slices.Sort(*a)
		*a = slices.Compact(*a)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(n); err != nil {
		return "", err
	}
	return baselineHash(out.Bytes()), nil
}

func baselineHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// SealEvidence binds the record's auxiliary facts after construction. This is an
// integrity check, not authentication; the ledger chain still covers original bytes.
func (b *Baseline) SealEvidence() error {
	replay, err := canonicalBaselineJSON(b.Replay)
	if err != nil {
		return err
	}
	b.Replay = replay
	facts, err := b.factDigests()
	if err != nil {
		return err
	}
	b.FactSHA256 = facts
	cp := *b
	cp.EvidenceSHA256 = ""
	if _, err := jsonv2.Marshal(cp); err != nil {
		return err
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	b.EvidenceSHA256 = baselineHash(data)
	return nil
}

// ValidateRunStartBaseline validates baseline evidence on the original payload bytes.
// It must precede any typed use: omitted and null facts can otherwise become
// indistinguishable from committed zero values. Unknown optional keys stay ignorable.
func ValidateRunStartBaseline(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	fields, err := objectFieldsRaw(raw)
	if err != nil {
		return fmt.Errorf("run_start: %w", err)
	}
	minor, err := runStartMinor(fields)
	if err != nil {
		return err
	}
	if !SupportsMinor(minor) {
		return fieldErr("record-minor", "run_start.record_minor", "unsupported revision %d", minor)
	}
	relevant := minor == MinorBaseline // the revision made for the baseline requires it; a later one carries it when it has one
	for _, member := range fields {
		if foldEqual(member.key, "baseline") || foldEqual(member.key, "effective_hash") {
			relevant = true
		}
	}
	if !relevant {
		return nil
	}
	p := RunStartPayload{RecordMinor: minor}
	for _, member := range fields {
		for _, target := range []struct {
			key   string
			value any
		}{
			{"baseline", &p.Baseline}, {"effective_hash", &p.EffectiveHash},
			{"contract_hash", &p.ContractHash}, {"tier", &p.Tier}, {"decision_plane", &p.DecisionPlane},
		} {
			if member.key != target.key {
				if foldEqual(member.key, target.key) {
					return fieldErr("field-case", "run_start."+target.key, "incorrect key %q", member.key)
				}
				continue
			}
			if target.key == "baseline" {
				if err := baselineRequiredShape(member.val); err != nil {
					return err
				}
			}
			if err := decodeField("run_start."+target.key, member.val, target.value); err != nil {
				return err
			}
		}
	}
	return p.ValidateBaseline()
}

// UnmarshalJSON keeps every typed run-start decoder behind the raw evidence gate.
// Decode into a fresh alias only after validation, so refusal cannot expose partial
// evidence. Callers of json.Unmarshal must discard the destination on any error:
// syntax errors can be rejected before this method is invoked.
func (p *RunStartPayload) UnmarshalJSON(raw []byte) error {
	*p = RunStartPayload{}
	if err := ValidateRunStartBaseline(raw); err != nil {
		return err
	}
	type plain RunStartPayload
	var next plain
	if err := json.Unmarshal(raw, &next); err != nil {
		return fmt.Errorf("run_start: %w", err)
	}
	*p = RunStartPayload(next)
	return nil
}

// ValidateBaseline checks revision gates, required facts and their digest relations.
func (p *RunStartPayload) ValidateBaseline() error {
	fail := func(fact, why string) error { return fieldErr("baseline", "run_start."+fact, "%s", why) }
	if !SupportsMinor(p.RecordMinor) {
		return fieldErr("record-minor", "run_start.record_minor", "unsupported revision %d", p.RecordMinor)
	}
	present := p.Baseline != nil || p.EffectiveHash != ""
	if p.RecordMinor < MinorBaseline {
		if present {
			return belowMinor("run_start.baseline/effective_hash", true, p.RecordMinor, MinorBaseline)
		}
		return nil
	}
	b := p.Baseline
	if b == nil {
		if p.RecordMinor > MinorBaseline && p.EffectiveHash == "" {
			return nil // a later revision reached for another field, by a run with no baseline
		}
		return fail("baseline", "missing block at baseline revision")
	}
	facts, err := b.factDigests()
	if err != nil {
		return fail("baseline.fact_sha256", err.Error())
	}
	if len(facts) != len(b.FactSHA256) {
		return fail("baseline.fact_sha256", "missing fact digests")
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if facts[key] != b.FactSHA256[key] {
			return fail("baseline."+key, "recorded fact does not reproduce its digest")
		}
	}
	if !sha256Hex.MatchString(p.ContractHash) {
		return fail("contract_hash", "need lowercase SHA-256")
	}
	if !sha256Hex.MatchString(p.EffectiveHash) || baselineHash(b.EffectiveContract) != p.EffectiveHash {
		return fail("effective_hash", "does not match effective_contract bytes")
	}
	if baselineHash(b.SourceContract) != p.ContractHash {
		return fail("contract_hash", "does not match source_contract bytes")
	}
	if b.V != 1 {
		return fail("baseline.v", "unsupported version")
	}
	if b.Mode != "applied" && b.Mode != "not-applied" {
		return fail("baseline.mode", "need applied or not-applied")
	}
	if b.OwnerUID < 0 || uint64(b.OwnerUID) >= uint64(^uint32(0)) {
		return fail("baseline.owner_uid", "invalid governed uid")
	}
	if b.OwnerKnown && !filepath.IsAbs(b.Home) {
		return fail("baseline.home", "known owner needs absolute passwd home")
	}
	if b.Mode == "applied" && !b.OwnerKnown {
		return fail("baseline.owner_known", "applied baseline needs known owner/home")
	}
	if len(b.Sources) != 3 {
		return fail("baseline.sources", "need all three consulted layers")
	}
	for i, s := range b.Sources {
		if s.Layer != []string{"etc", "user", "env"}[i] {
			return fail("baseline.sources.layer", "wrong layer order")
		}
		switch s.State {
		case "present":
			if !filepath.IsAbs(s.File) || s.SHA256 == nil || !sha256Hex.MatchString(*s.SHA256) || *s.SHA256 != baselineHash(s.Bytes) || s.Bytes == nil {
				return fail("baseline.sources.bytes/sha256/file", "present source bytes/digest/path disagree")
			}
		case "absent":
			if !filepath.IsAbs(s.File) || s.SHA256 != nil || s.Bytes != nil {
				return fail("baseline.sources.absence", "absent source needs path and null bytes/digest")
			}
		case "unselected":
			if s.File != "" || s.SHA256 != nil || s.Bytes != nil {
				return fail("baseline.sources.unselected", "unselected layer has no path/bytes/digest")
			}
		default:
			return fail("baseline.sources.state", "unknown layer cannot establish recorded baseline")
		}
	}
	if b.Rules == nil || len(b.Rules) > 100000 {
		return fail("baseline.rules", "missing or excessive rules")
	}
	seen := map[string]bool{}
	for i, r := range b.Rules {
		at := fmt.Sprintf("baseline.rules.%d", i)
		if r.ID != fmt.Sprintf("baseline.%d", i) {
			return fail(at+".id", "does not match union position")
		}
		id := r.Key + "\x00" + r.Value
		if seen[id] {
			return fail(at+".value", "duplicate union entry")
		}
		seen[id] = true
		if r.Value == "" || !utf8.ValidString(r.Value) || r.Expanded == "" || !utf8.ValidString(r.Expanded) {
			return fail(at+".value/expanded", "missing or invalid UTF-8")
		}
		if r.State != "present" && r.State != "absent" && r.State != "unresolved" {
			return fail(at+".state", "unknown resolution state")
		}
		if r.Rule == nil || (len(r.Rule) == 0 && r.EmptyReason == "") {
			return fail(at+".rule", "empty action membership needs reason")
		}
		if len(r.Sources) == 0 {
			return fail(at+".sources", "missing membership")
		}
		for _, o := range r.Sources {
			ok := false
			for _, s := range b.Sources {
				if o.Layer == s.Layer && o.File == s.File && s.State == "present" && o.Line > 0 {
					ok = true
				}
			}
			if !ok {
				return fail(at+".sources", "origin is not a consulted present layer")
			}
		}
		if r.Operations == nil || r.Conditions == nil || r.Limits == nil {
			return fail(at+".coverage", "missing operations/conditions/limits arrays")
		}
		if r.Tier != p.Tier || r.Plane != p.DecisionPlane {
			return fail(at+".tier/plane", "differs from actual run_start mechanism")
		}
		if b.Mode == "applied" && (r.Tier == "observe" || r.Tier == "landlock" && r.Plane != "" || r.Tier == "bpflsm" && r.Plane != "lsm" || r.Tier == "cgroup" && r.Plane == "") {
			return fail(at+".tier/plane", "cannot claim applied coverage at this mechanism")
		}
		if b.Mode == "not-applied" {
			if r.Held != "not-applied" || len(r.Rule) != 0 {
				return fail(at+".held", "record-only entry claims enforcement")
			}
		} else if !slices.Contains([]string{"kernel", "conditional", "best-effort"}, r.Held) {
			return fail(at+".held", "unsupported coverage or refuse-launch")
		}
		if !slices.Contains([]string{"landlock", "cgroup", "bpflsm", "observe"}, r.Tier) || !slices.Contains([]string{"", "lsm", "fmod_ret", "fanotify"}, r.Plane) {
			return fail(at+".tier/plane", "unknown mechanism")
		}
	}
	digest, err := BaselineDigest(b.Rules)
	if err != nil || digest != b.SHA256 {
		return fail("baseline.sha256", "normalized rules do not reproduce digest")
	}
	if b.Mode == "not-applied" && !bytes.Equal(b.SourceContract, b.EffectiveContract) {
		return fail("baseline.mode", "record-only contract bytes differ")
	}
	if len(b.Replay) == 0 || !json.Valid(b.Replay) {
		return fail("baseline.replay", "missing reconstruction facts")
	}
	var replay json.RawMessage
	if err := decodeField("run_start.baseline", []byte(`{"replay":`+string(b.Replay)+`}`), &replay); err != nil {
		return fail("baseline.replay", err.Error())
	}
	cp := *b
	if err := cp.SealEvidence(); err != nil || cp.EvidenceSHA256 != b.EvidenceSHA256 || !sha256Hex.MatchString(b.EvidenceSHA256) {
		return fail("baseline.evidence_sha256", "recorded owner/home/mode/sources/absence/rules/state/membership/tier/plane/coverage/replay facts do not reproduce evidence digest")
	}
	// Bound evidence before the ledger's 2 MiB line limit, retaining room for other fields.
	data, err := json.Marshal(b)
	if err != nil || len(data) > 1<<20 {
		return fail("baseline", "evidence exceeds 1 MiB record budget")
	}
	if strings.ContainsRune(b.Home, 0) {
		return fail("baseline.home", "NUL in owner home")
	}
	return nil
}

// Only the specified nullable source fields and opaque compiler facts admit null.
func baselineNullAllowed(field, pointer string) bool {
	if field != "run_start.baseline" {
		return false
	}
	if strings.HasPrefix(pointer, "/replay/") {
		return true
	}
	parts := strings.Split(pointer, "/")
	return len(parts) == 4 && parts[1] == "sources" && (parts[3] == "sha256" || parts[3] == "bytes")
}

func baselineRequiredShape(raw []byte) error {
	var walk func([]byte, string) error
	walk = func(data []byte, at string) error {
		if at == "run_start.baseline.replay" {
			return nil
		}
		if len(data) > 0 && data[0] == '[' {
			var items []json.RawMessage
			if err := json.Unmarshal(data, &items); err != nil {
				return err
			}
			for _, item := range items {
				if err := walk(item, at); err != nil {
					return err
				}
			}
			return nil
		}
		children := fieldChildren[at]
		if len(children) == 0 {
			return nil
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return fieldErr("baseline", at, "need object: %v", err)
		}
		for _, path := range children {
			key := strings.TrimPrefix(path, at+".")
			value, ok := obj[key]
			if !ok {
				return fieldErr("baseline", path, "missing required fact")
			}
			if err := walk(value, path); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(raw, "run_start.baseline")
}

// Fact commitments identify an independently edited field without claiming that
// a consistent author-supplied record authenticates its own collection.
func (b *Baseline) factDigests() (map[string]string, error) {
	cp := *b
	replay, err := canonicalBaselineJSON(cp.Replay)
	if err != nil {
		return nil, err
	}
	cp.Replay = replay
	cp.FactSHA256 = nil
	cp.EvidenceSHA256 = ""
	if _, err := jsonv2.Marshal(cp); err != nil {
		return nil, err
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	delete(root, "fact_sha256")
	delete(root, "evidence_sha256")
	out := map[string]string{}
	for key, value := range root {
		if key == "rules" || key == "sources" {
			var rows []map[string]json.RawMessage
			if err := json.Unmarshal(value, &rows); err != nil {
				return nil, err
			}
			out[key+".length"] = baselineHash([]byte(fmt.Sprint(len(rows))))
			for i, row := range rows {
				for field, value := range row {
					out[fmt.Sprintf("%s.%d.%s", key, i, field)] = baselineHash(value)
				}
			}
		} else {
			out[key] = baselineHash(value)
		}
	}
	return out, nil
}

// Sort only object keys in the opaque projection. UseNumber preserves inode and
// device integer tokens exactly; decoding through float64 would lose evidence.
func canonicalBaselineJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, fmt.Errorf("baseline replay is not one JSON value")
	}
	var strict json.RawMessage
	if err := decodeField("run_start.baseline", []byte(`{"replay":`+string(raw)+`}`), &strict); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
