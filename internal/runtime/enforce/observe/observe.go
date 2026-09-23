// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Verdict is what every action decided under this backend carries: observed, never allow or refused.
const Verdict = record.VerdictObserved

var (
	// ErrNoTable is returned by Prepare for a nil rule table.
	ErrNoTable = errors.New("observe: nil rule table")
	// ErrNoFilter is returned by Prepare when the backend was built without a filter, or the filter it
	// was given came back empty. An observe run with no filter installs no listener, so nothing it does
	// reaches the ledger; that run would claim a record it does not have, so it does not start.
	ErrNoFilter = errors.New("observe: no record filter")
)

// FilterFunc builds the classic-BPF program an observe run installs with NEW_LISTENER. full asks for
// every open to be notified (record: full); otherwise only the write-opens are, as at tier 1. frames asks for the
// pending-frame arms (enforce-landlock R11d), where the run's contract decides datagrams, as at tier 1.
type FilterFunc func(full, frames bool) ([]bpf.RawInstruction, error)

// Options configures the observe backend.
type Options struct {
	// Filter builds the run's seccomp filter; required. It is injected because the program is tier 1's
	// own, and backends never import each other (docs/REPO-LAYOUT.md): enforce.Observe supplies it.
	Filter FilterFunc
}

// Backend is the record-only mode (P0-DESIGN §2.6): no Landlock ruleset and nothing attached, but the
// tier-1 seccomp filter, so the supervisor sees and records every exec, write and connect the run makes
// while refusing none of them. It is never selected by enforce.Select; an explicit --observe reaches it
// through enforce.Observe, which wraps it as an enforce.Backend.
type Backend struct {
	filter FilterFunc
}

// New returns the observe backend over opts.
func New(opts Options) *Backend { return &Backend{filter: opts.Filter} }

// Tier is backend.TierObserve.
func (*Backend) Tier() backend.Tier { return backend.TierObserve }

// Capabilities is the observe column of the matrix: an empty, non-nil set — nothing is enforced.
func (*Backend) Capabilities() backend.Set { return backend.Matrix(backend.TierObserve) }

// Prepare validates its inputs and builds the run's record filter for the table's record mode and whether it decides
// datagrams (the pending-frame arms, which the supervisor's pending-frame decisions read the same predicate as). It opens
// nothing; the failures are a cancelled context, a missing table and a filter that could not be built.
func (b *Backend) Prepare(ctx context.Context, rt *agent.RuleTable) (*Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("observe: prepare cancelled: %w", err)
	}
	if rt == nil {
		return nil, ErrNoTable
	}
	if b.filter == nil {
		return nil, ErrNoFilter
	}
	prog, err := b.filter(rt.Record == agent.RecordFull, rt.DecidesDatagrams())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoFilter, err)
	}
	if len(prog) == 0 {
		return nil, ErrNoFilter
	}
	return &Handle{filter: prog}, nil
}

// Handle is the prepared state of an observe run: a filter and nothing else. Every verdict it stands
// behind is observed. Its method set is api.Handle plus enforce.Reporter.
type Handle struct {
	filter []bpf.RawInstruction
}

// LandlockRuleset reports that there is no ruleset to apply.
func (*Handle) LandlockRuleset() (int, bool) { return -1, false }

// SeccompFilter returns the record filter for seccomp(SET_MODE_FILTER, NEW_LISTENER); the caller must not
// mutate it. ok is false only for a zero Handle, which Prepare never returns.
func (h *Handle) SeccompFilter() ([]bpf.RawInstruction, bool) {
	if len(h.filter) == 0 {
		return nil, false
	}
	return h.filter, true
}

// Attach is a no-op.
func (*Handle) Attach(uint64) error { return nil }

// Detach is a no-op.
func (*Handle) Detach() error { return nil }

// Close is a no-op; safe to call twice. The filter is memory the handle owns, not a kernel object.
func (*Handle) Close() error { return nil }

// Capabilities is the run's matrix: nothing provided.
func (*Handle) Capabilities() backend.Set { return backend.Matrix(backend.TierObserve) }

// Verdict is the verdict every action of the run is recorded with. The runtime reads it to put the
// supervisor in observe mode (docs/p0/supervisor.md R30), so this handle is what decides it.
func (*Handle) Verdict() record.Verdict { return Verdict }
