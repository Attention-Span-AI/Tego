// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// BaselineTable is the detached machine snapshot consulted for this compilation.
// Membership is separate from a rule's single source position (ADR 0144).
type BaselineTable struct {
	Owner               config.BaselineOwner
	Entries             []BaselineRule
	Applied             bool
	ProtectedOwnerLayer string
	MountInfo           string
	identities          map[string]fileKey
	denyWrites          map[string]bool
}

// BaselineRule retains every source and the exact compiled rules contributed by an entry.
type BaselineRule struct {
	config.ResolvedBaselineEntry
	Rules    []string
	Coverage []BaselineCoverage
	topology baselineTopologyFacts
}

// BaselineConflictDiagnostic records both sides without environment values.
type BaselineConflictDiagnostic struct {
	Entry         config.BaselineEntry
	Owner         config.BaselineOwner
	GrantKey      string
	Grant         Pos
	Target        string
	Device, Inode uint64
	Tier, Plane   string
}

// OriginClass distinguishes declared contract/profile origins and baseline membership.
type OriginClass string

const (
	// OriginContract is a field in the top-level source contract.
	OriginContract OriginClass = "contract"
	// OriginProfile is a field inherited through profiles or presets.
	OriginProfile OriginClass = "profile/preset"
	// OriginBaseline is an inserted machine refusal. Sources remain many-to-one.
	OriginBaseline OriginClass = "baseline"
)

// Origin returns the position and class of a decoded field without conflating
// baseline membership with the contract's or profile's position.
func (c *Contract) Origin(key string) (Pos, OriginClass, bool) {
	if c == nil {
		return Pos{}, "", false
	}
	p, ok := c.Pos(key)
	if !ok {
		return p, "", false
	}
	for prefix, n := range c.baselineCounts {
		if raw, has := strings.CutPrefix(key, prefix+"."); has {
			first, _, _ := strings.Cut(raw, ".")
			if i, err := strconv.Atoi(first); err == nil && i < n {
				return p, OriginBaseline, true
			}
		}
	}
	if p.File != c.file {
		return p, OriginProfile, true
	}
	return p, OriginContract, true
}

// DecisionContract returns the effective source for enforcement consumers. Historical
// source pinning and contract.yaml must continue to use Contract and Hash.
func (rt *RuleTable) DecisionContract() *Contract {
	if rt == nil {
		return nil
	}
	if rt.EffectiveContract != nil {
		return rt.EffectiveContract
	}
	return rt.Contract
}

// Replayed reports a historical reconstruction, which cannot authorize a launch.
func (rt *RuleTable) Replayed() bool { return rt != nil && rt.replayed }

func (k *compiler) materializeBaseline() error {
	b, _ := k.m.BaselineSnapshot()
	if b.Empty() {
		return nil
	}
	uid, _ := config.InvokingUID()
	owner := config.BaselineOwner{UID: uid, Home: k.o.home}
	if k.o.ownerSet {
		owner.UID = k.o.ownerUID
	}
	if owner.UID < 0 || uint64(owner.UID) >= uint64(^uint32(0)) {
		k.ds.errorf(k.cpos, CodeBaselinePlacement, "baseline owner uid %d is not a valid governed uid", owner.UID).
			fix("select the agent owner's valid passwd uid and home before compiling")
		return firstError(k.ds.list)
	}
	table := &BaselineTable{Owner: owner, Applied: !k.o.observe, MountInfo: k.o.mountInfo}
	k.rt.Baseline = table
	if k.o.observe {
		for _, e := range b.Entries() {
			table.Entries = append(table.Entries, BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: e, Expanded: e.Value}})
		}
		return nil
	}
	// Runtime command/image interpretation needs the governed cwd even without
	// a gate. Leave empty-baseline tables byte-identical to their parent fixtures.
	k.rt.Workdir = k.resolve(k.o.cwd)
	resolved, err := b.Resolve(owner)
	if err != nil {
		k.ds.errorf(k.cpos, CodeBaselinePlacement, "%s", err).fix("use an absolute existing target, or remove this baseline entry")
		return firstError(k.ds.list)
	}
	for _, e := range resolved.Entries {
		table.Entries = append(table.Entries, BaselineRule{ResolvedBaselineEntry: e})
	}
	cp, err := prependBaseline(k.c, table)
	if err != nil {
		return err
	}
	k.c, k.rt.EffectiveContract = cp, cp
	k.rt.EffectiveHash, err = cp.Hash()
	return err
}

// prependBaseline owns the only insertion. The caller supplies resolved entries,
// either from today's trusted Machine or a verified replay snapshot.
func prependBaseline(c *Contract, table *BaselineTable) (*Contract, error) {
	cp := *c
	cp.materialized = true
	cp.baselineCounts = map[string]int{}
	cp.origins = maps.Clone(c.origins)
	if cp.origins == nil {
		cp.origins = origins{}
	}
	if cp.FS != nil {
		fs := *cp.FS
		cp.FS = &fs
	}
	if cp.Exec != nil {
		es := *cp.Exec
		cp.Exec = &es
	}
	mode := c.ExecUnrestricted()
	for _, key := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite, config.BaselineDenyExec, config.BaselineDenyEnv} {
		var prefix []string
		var sources []Pos
		for _, entry := range table.Entries {
			if entry.Key != key {
				continue
			}
			prefix = append(prefix, entry.Expanded)
			s := entry.Sources[0]
			sources = append(sources, Pos{File: s.File, Line: s.Line, Col: 1})
		}
		if len(prefix) == 0 {
			continue
		}
		cp.baselineCounts[string(key)] = len(prefix)
		var target *[]string
		switch key {
		case config.BaselineDenyRead, config.BaselineDenyWrite:
			if cp.FS == nil {
				cp.FS = &FSSection{}
			}
			if key == config.BaselineDenyRead {
				target = &cp.FS.DenyRead
			} else {
				target = &cp.FS.DenyWrite
			}
		case config.BaselineDenyExec:
			if cp.Exec == nil {
				cp.Exec = &ExecSection{}
			}
			if !mode && cp.Exec.Allow == nil {
				cp.Exec.Allow = []string{}
			}
			target = &cp.Exec.Deny
		case config.BaselineDenyEnv:
			target = &cp.Env.Deny
		}
		*target = slices.Concat(prefix, *target)
		shiftBaselineOrigins(cp.origins, string(key), len(prefix))
		for i, p := range sources {
			cp.origins[string(key)+"."+strconv.Itoa(i)] = p
		}
	}
	if cp.ExecUnrestricted() != mode {
		return nil, fmt.Errorf("agent: baseline insertion changed the exec image mode")
	}
	return &cp, nil
}

func shiftBaselineOrigins(o origins, key string, count int) {
	prefix := key + "."
	moved := origins{}
	for old, p := range o {
		if !strings.HasPrefix(old, prefix) {
			continue
		}
		index, suffix, _ := strings.Cut(strings.TrimPrefix(old, prefix), ".")
		i, err := strconv.Atoi(index)
		if err != nil {
			continue
		}
		to := prefix + strconv.Itoa(i+count)
		if suffix != "" {
			to += "." + suffix
		}
		moved[to] = p
		delete(o, old)
	}
	maps.Copy(o, moved)
}

func (k *compiler) baselineMember(key string) *BaselineRule {
	if k.rt.Baseline == nil || !k.rt.Baseline.Applied {
		return nil
	}
	for _, kind := range []config.BaselineKey{config.BaselineDenyRead, config.BaselineDenyWrite, config.BaselineDenyExec, config.BaselineDenyEnv} {
		prefix := string(kind) + "."
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		raw, _, _ := strings.Cut(strings.TrimPrefix(key, prefix), ".")
		idx, err := strconv.Atoi(raw)
		if err != nil {
			return nil
		}
		n := 0
		for i := range k.rt.Baseline.Entries {
			e := &k.rt.Baseline.Entries[i]
			if e.Key != kind {
				continue
			}
			if n == idx {
				return e
			}
			n++
		}
	}
	return nil
}

func (k *compiler) baselineConflict(entry *BaselineRule, grantKey, detail string, positions ...Pos) {
	at := k.pos(grantKey)
	if len(positions) > 0 {
		at = positions[0]
	}
	// Sources stay complete in BaselineRule; bound only the displayed list.
	sources := entry.Sources
	shown := sources
	if len(shown) > 8 {
		shown = shown[:8]
	}
	extra := ""
	if len(sources) > len(shown) {
		extra = fmt.Sprintf(" (and %d more sources)", len(sources)-len(shown))
	}
	d := k.ds.errorf(at, CodeBaselineConflict, "%s conflicts with baseline.%s %q from %v%s (owner uid %d, home %q, target %q, identity %d:%d, tier %s): %s", grantKey, entry.Key, entry.Value, shown, extra, k.rt.Baseline.Owner.UID, k.rt.Baseline.Owner.Home, entry.Target, entry.Device, entry.Inode, k.rt.Tier, detail).
		fix("remove this grant, or remove the baseline entry from every contributing layer")
	d.Baseline = &BaselineConflictDiagnostic{Entry: entry.BaselineEntry, Owner: k.rt.Baseline.Owner, GrantKey: grantKey, Grant: at, Target: entry.Target, Device: entry.Device, Inode: entry.Inode, Tier: string(k.rt.Tier), Plane: "selected at preparation"}
}

func (k *compiler) baselineRules() {
	if k.rt.Baseline == nil || !k.rt.Baseline.Applied || k.rt.Replayed() {
		return
	}
	for i := range k.rt.Baseline.Entries {
		e := &k.rt.Baseline.Entries[i]
		for _, r := range append(slices.Clone(k.rt.FS), k.rt.DenyWrite...) {
			if (e.Key == config.BaselineDenyRead && r.Kind == FSDenyRead || e.Key == config.BaselineDenyWrite && r.Kind == FSDenyWrite) && (r.Raw == e.Expanded || r.Canonical() == e.Target) {
				e.Rules = append(e.Rules, r.RuleName())
			}
		}
		if e.Key == config.BaselineDenyRead {
			for _, r := range k.rt.AbsentDenyRead {
				if r.Path == e.Expanded {
					e.Rules = append(e.Rules, r.RuleName())
				}
			}
		}
		if e.Key == config.BaselineDenyExec {
			e.Rules = []string{"exec.deny[" + e.Expanded + "]"}
		}
		if e.Key == config.BaselineDenyEnv {
			e.Rules = []string{"env.deny[" + e.Expanded + "]"}
		}
	}
}
