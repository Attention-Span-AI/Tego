// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ErrLoadBudget means the complete profile graph could not be inspected within its budget.
var ErrLoadBudget = errors.New("contract graph budget exhausted")

// LoadLimits bounds one entire load, including the top file, all profile attempts,
// alias expansion, intermediate merges and diagnostics. ExpandedBytes charges 32
// bytes per YAML node plus six times its scalar/tag bytes and indentation, and
// the sum of operand charges before each merge. This is a conservative work/output bound, not a serialized-file size.
type LoadLimits struct {
	SourceBytes     int64
	Profiles        int
	ExpandedBytes   int64
	Diagnostics     int
	DiagnosticBytes int64
}

// LoadBytesBounded is LoadBytes with a request context and aggregate graph limits.
// It returns no contract on cancellation or exhaustion. Resolution must itself be
// bounded (ProfileSource); cancellation is checked before and after each resolve,
// parse, validation and merge, and while accounting expanded nodes.
func LoadBytesBounded(ctx context.Context, path string, data []byte, profiles ProfileSource, limits LoadLimits) (*Contract, []Diagnostic, error) {
	if ctx == nil || limits.SourceBytes <= 0 || limits.Profiles <= 0 || limits.ExpandedBytes <= 0 || limits.Diagnostics <= 0 || limits.DiagnosticBytes <= 0 {
		return nil, nil, fmt.Errorf("%w: invalid limits or context", ErrLoadBudget)
	}
	b := &loadBudget{ctx: ctx, left: limits, costs: map[*Contract]int64{}}
	return loadBytes(path, data, profiles, b)
}

type loadBudget struct {
	ctx        context.Context
	left       LoadLimits
	err        error
	costs      map[*Contract]int64
	parsedCost int64
}

func (b *loadBudget) check() error {
	if b == nil {
		return nil
	}
	if b.err == nil {
		b.err = b.ctx.Err()
	}
	return b.err
}

func (b *loadBudget) spend(file, kind string, n int64, left *int64) bool {
	if b.check() != nil {
		return false
	}
	if n > *left {
		b.err = fmt.Errorf("%w: %s: %s; reduce the profile graph", ErrLoadBudget, file, kind)
		return false
	}
	*left -= n
	return true
}

func (b *loadBudget) input(file string, n int) bool {
	return b == nil || b.spend(file, "source bytes", int64(n), &b.left.SourceBytes)
}

func (b *loadBudget) profile(file string) bool {
	if b == nil {
		return true
	}
	if b.check() != nil {
		return false
	}
	if b.left.Profiles == 0 {
		b.err = fmt.Errorf("%w: %s: profile count; reduce the profile graph", ErrLoadBudget, file)
		return false
	}
	b.left.Profiles--
	return true
}

func (b *loadBudget) expansion(file string, n *yaml.Node) bool {
	if b == nil {
		return true
	}
	before := b.left.ExpandedBytes
	var visit func(*yaml.Node, int) bool
	visit = func(n *yaml.Node, depth int) bool {
		if depth > maxAliasDepth*64 {
			b.err = fmt.Errorf("%w: %s: expanded output depth", ErrLoadBudget, file)
			return false
		}
		if n == nil {
			return true
		}
		if !b.spend(file, "expanded output", 32+6*int64(len(n.Value)+len(n.Tag))+2*int64(depth), &b.left.ExpandedBytes) {
			return false
		}
		if n.Kind == yaml.AliasNode {
			return visit(n.Alias, depth+1)
		}
		for _, child := range n.Content {
			if !visit(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !visit(n, 0) {
		return false
	}
	b.parsedCost = before - b.left.ExpandedBytes
	return true
}

func (b *loadBudget) parsed(c *Contract) {
	if b != nil {
		b.costs[c] = b.parsedCost
	}
}

func (b *loadBudget) merge(file string, a, c *Contract) bool {
	if b == nil {
		return true
	}
	return b.spend(file, "expanded merge output", b.costs[a]+b.costs[c], &b.left.ExpandedBytes)
}

func (b *loadBudget) merged(out, a, c *Contract) {
	if b != nil {
		b.costs[out] = b.costs[a] + b.costs[c]
	}
}

// combineBounded uses the existing merge semantics but reserves each intermediate
// result before allocating it. Whole views are conservatively charged as full views.
func (l *loader) combineBounded(parents []*Contract, scalars bool) (*Contract, []extendsConflict) {
	if l.budget == nil {
		if scalars {
			return checkParents(parents)
		}
		return combineParents(parents), nil
	}
	acc := parents[0]
	var conflicts []extendsConflict
	for _, p := range parents[1:] {
		if !l.budget.merge(p.file, acc, p) {
			return nil, nil
		}
		pair, ds := combine([]*Contract{acc, p}, scalars)
		l.budget.merged(pair, acc, p)
		acc = pair
		conflicts = append(conflicts, ds...)
	}
	return acc, conflicts
}

func (b *loadBudget) diagnostic(p Pos, code, message string) bool {
	if b == nil {
		return true
	}
	if b.check() != nil {
		return false
	}
	if b.left.Diagnostics == 0 {
		b.err = fmt.Errorf("%w: %s: diagnostic count; repair the source", ErrLoadBudget, p.File)
		return false
	}
	if !b.spend(p.File, "diagnostic bytes", int64(len(p.File)+len(code)+len(message)), &b.left.DiagnosticBytes) {
		return false
	}
	b.left.Diagnostics--
	return true
}

func (l *loader) resolveBounded(name string) resolvedProfile {
	if l.budget == nil {
		return resolveProfile(l.profiles, name)
	}
	max := min(int64(MaxContractSize), l.budget.left.SourceBytes)
	r := resolveProfileBounded(l.budget.ctx, l.profiles, name, max)
	if r.err == nil && !l.budget.input(r.path, len(r.data)) {
		r.err = l.budget.err
	}
	if errors.Is(r.err, ErrLoadBudget) {
		l.budget.err = r.err
	}
	return r
}
