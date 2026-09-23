// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeFilter stands in for tier 1's filter builder and records the record mode and the pending-frame arms it was
// asked for.
type fakeFilter struct {
	prog   []bpf.RawInstruction
	err    error
	fulls  []bool
	frames []bool
}

func (f *fakeFilter) build(full, frames bool) ([]bpf.RawInstruction, error) {
	f.fulls = append(f.fulls, full)
	f.frames = append(f.frames, frames)
	return f.prog, f.err
}

// TestPrepareAsksForThePendingFrameArms: an observe run's filter carries enforce-landlock R11d's pending-frame arms
// exactly where its contract decides datagrams (agent.RuleTable.DecidesDatagrams), the predicate an enforcing run's
// filter and every run's supervisor read, so the record holds a line for each operation enforcement would refuse
// datagram-corked.
func TestPrepareAsksForThePendingFrameArms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		c      *agent.Contract
		frames bool
	}{
		{"no net: section", &agent.Contract{}, false},
		{"a net: section", &agent.Contract{Net: &agent.NetSection{}}, true},
	} {
		ff := &fakeFilter{prog: twoInsts}
		rt := &agent.RuleTable{Contract: tc.c}
		if _, err := New(Options{Filter: ff.build}).Prepare(context.Background(), rt); err != nil {
			t.Fatal(err)
		}
		if len(ff.frames) != 1 || ff.frames[0] != tc.frames || tc.frames != rt.DecidesDatagrams() {
			t.Errorf("%s built the filter with frames=%v, want %v", tc.name, ff.frames, tc.frames)
		}
	}
}

var twoInsts = []bpf.RawInstruction{{Op: 0x20, K: 4}, {Op: 0x06, K: 0x7fff0000}}

func TestBackend(t *testing.T) {
	ff := &fakeFilter{prog: twoInsts}
	b := New(Options{Filter: ff.build})
	if b.Tier() != backend.TierObserve {
		t.Errorf("Tier = %s", b.Tier())
	}
	if caps := b.Capabilities(); caps == nil || len(caps) != 0 {
		t.Errorf("Capabilities = %v, want empty non-nil", caps)
	}
	h, err := b.Prepare(context.Background(), &agent.RuleTable{Record: agent.RecordSummary})
	if err != nil {
		t.Fatal(err)
	}
	if fd, ok := h.LandlockRuleset(); ok || fd != -1 {
		t.Errorf("LandlockRuleset = %d, %v", fd, ok)
	}
	// The filter is what makes an observe run recordable at all: without it the child installs no
	// listener, the supervisor is never started, and the ledger holds no exec, fs or net line.
	if prog, ok := h.SeccompFilter(); !ok || len(prog) != len(twoInsts) {
		t.Errorf("SeccompFilter = %v, %v, want the record filter", prog, ok)
	}
	for _, f := range []func() error{func() error { return h.Attach(7) }, h.Detach, h.Close, h.Close} {
		if err := f(); err != nil {
			t.Error(err)
		}
	}
	if len(h.Capabilities()) != 0 {
		t.Errorf("Capabilities = %v", h.Capabilities())
	}
	if h.Verdict() != record.VerdictObserved || Verdict != record.VerdictObserved {
		t.Errorf("verdict = %v", h.Verdict())
	}
}

// TestPrepareAsksForTheRecordMode checks the one input the filter depends on: record: full notifies every
// open, the other modes only the write-opens, exactly as tier 1 builds it.
func TestPrepareAsksForTheRecordMode(t *testing.T) {
	for _, tc := range []struct {
		mode agent.RecordMode
		full bool
	}{{agent.RecordFull, true}, {agent.RecordSummary, false}, {agent.RecordOff, false}, {"", false}} {
		ff := &fakeFilter{prog: twoInsts}
		if _, err := New(Options{Filter: ff.build}).Prepare(context.Background(), &agent.RuleTable{Record: tc.mode}); err != nil {
			t.Fatal(err)
		}
		if len(ff.fulls) != 1 || ff.fulls[0] != tc.full {
			t.Errorf("record %q built the filter with full=%v, want %v", tc.mode, ff.fulls, tc.full)
		}
	}
}

func TestPrepareErrors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name   string
		ctx    func() context.Context
		rt     *agent.RuleTable
		filter FilterFunc
		want   error
	}{
		{"nil table", context.Background, nil, (&fakeFilter{prog: twoInsts}).build, ErrNoTable},
		{"cancelled", func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c },
			&agent.RuleTable{}, (&fakeFilter{prog: twoInsts}).build, context.Canceled},
		// A backend built without a filter would start a run that records nothing: fail closed.
		{"no filter builder", context.Background, &agent.RuleTable{}, nil, ErrNoFilter},
		{"filter build fails", context.Background, &agent.RuleTable{}, (&fakeFilter{err: boom}).build, boom},
		{"empty filter", context.Background, &agent.RuleTable{}, (&fakeFilter{}).build, ErrNoFilter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, err := New(Options{Filter: tc.filter}).Prepare(tc.ctx(), tc.rt)
			if !errors.Is(err, tc.want) || h != nil {
				t.Errorf("Prepare = %v, %v, want nil, %v", h, err, tc.want)
			}
		})
	}
}

func TestZeroHandleHasNoFilter(t *testing.T) {
	if prog, ok := (&Handle{}).SeccompFilter(); ok || prog != nil {
		t.Errorf("zero Handle SeccompFilter = %v, %v", prog, ok)
	}
}
