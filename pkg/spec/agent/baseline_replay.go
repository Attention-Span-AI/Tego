// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// BaselineReplay is a sealed historical compilation context. It is deliberately
// not a CompileOption: launch compilers cannot accept a replay opt-out.
type BaselineReplay struct {
	snapshot  *BaselineTable
	contract  [32]byte
	effective [32]byte
	known     bool
	facts     *baselineRecordFacts
}

// UnknownBaselineReplay represents records predating baseline facts. It never
// substitutes today's union for unknown historical enforcement.
func UnknownBaselineReplay() *BaselineReplay { return &BaselineReplay{} }

// VerifyBaselineReplay verifies a snapshot against source and effective bytes.
// Slice 6's record decoder must first validate its revision, digests, owner and
// per-entry coverage, then use this verifier; it cannot mint an unchecked handle.
func VerifyBaselineReplay(source *Contract, snapshot *BaselineTable, contractHash, effectiveHash [32]byte, effective []byte) (*BaselineReplay, error) {
	if source == nil || source.materialized {
		return nil, errors.New("baseline replay needs a source contract")
	}
	if snapshot == nil || snapshot.Owner.UID < 0 || uint64(snapshot.Owner.UID) >= uint64(^uint32(0)) || !filepath.IsAbs(snapshot.Owner.Home) {
		return nil, errors.New("baseline replay needs its recorded valid owner uid and absolute home")
	}
	h, err := source.Hash()
	if err != nil || h != contractHash {
		return nil, errors.New("baseline replay contract hash does not match source")
	}
	if sha256.Sum256(effective) != effectiveHash {
		return nil, errors.New("baseline replay effective hash does not match bytes")
	}
	cp := cloneBaseline(snapshot)
	working := source
	if cp != nil && cp.Applied && len(cp.Entries) > 0 {
		for _, e := range cp.Entries {
			if len(e.Sources) == 0 || e.Expanded == "" {
				return nil, errors.New("baseline replay entry is incomplete")
			}
		}
		working, err = prependBaseline(source, cp)
		if err != nil {
			return nil, err
		}
	}
	b, err := working.Canonical()
	if err != nil || !bytes.Equal(b, effective) {
		return nil, errors.New("baseline replay snapshot does not reproduce effective bytes")
	}
	return &BaselineReplay{snapshot: cp, contract: contractHash, effective: effectiveHash, known: true}, nil
}

// Compile reconstructs historical rules only. Its table is rejected by every
// runtime launch and adoption boundary, even when its hashes are verified.
func (r *BaselineReplay) Compile(c *Contract, m *config.Machine, opts ...CompileOption) (*RuleTable, []Diagnostic, error) {
	if r == nil {
		return nil, nil, errors.New("nil baseline replay handle")
	}
	return compileContractHiding(c, m, r, opts...)
}

func (k *compiler) materializeReplay(r *BaselineReplay) error {
	k.rt.replayed = true
	if !r.known {
		return nil
	}
	if k.rt.Hash != r.contract {
		return errors.New("baseline replay handle belongs to a different source contract")
	}
	k.rt.Baseline = cloneBaseline(r.snapshot)
	k.rt.baselineReplayFacts = r.facts
	if k.rt.Baseline != nil && k.rt.Baseline.Applied && len(k.rt.Baseline.Entries) > 0 {
		cp, err := prependBaseline(k.c, k.rt.Baseline)
		if err != nil {
			return err
		}
		k.c, k.rt.EffectiveContract = cp, cp
	}
	h, err := k.rt.EffectiveContract.Hash()
	if err != nil || h != r.effective {
		return errors.New("baseline replay effective state changed")
	}
	k.rt.EffectiveHash = h
	return nil
}

func cloneBaseline(b *BaselineTable) *BaselineTable {
	if b == nil {
		return nil
	}
	cp := *b
	cp.Entries = slices.Clone(b.Entries)
	for i := range cp.Entries {
		e := &cp.Entries[i]
		e.Sources = slices.Clone(e.Sources)
		e.Rules = slices.Clone(e.Rules)
		e.Coverage = slices.Clone(e.Coverage)
		for j := range e.Coverage {
			c := &e.Coverage[j]
			c.Operations = slices.Clone(c.Operations)
			c.Conditions = slices.Clone(c.Conditions)
			c.Limits = slices.Clone(c.Limits)
		}
	}
	return &cp
}
