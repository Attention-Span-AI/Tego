// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeLoopback is a capture source that binds nothing but answers the two questions a run asks a
// LoopbackSource: where it listens and what variable points a harness at it.
type fakeLoopback struct {
	name  string
	vars  map[string]string
	addrs []netip.AddrPort
}

func (s *fakeLoopback) Name() string                                            { return s.name }
func (s *fakeLoopback) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (s *fakeLoopback) Stop() error                                             { return nil }
func (s *fakeLoopback) Gaps() []source.Gap                                      { return nil }
func (s *fakeLoopback) Vars() map[string]string                                 { return s.vars }
func (s *fakeLoopback) Endpoints() []netip.AddrPort                             { return s.addrs }

// plainSource is a capture source that is not reachable over loopback: a run must ask it for nothing.
type plainSource struct{ name string }

func (s *plainSource) Name() string                                            { return s.name }
func (s *plainSource) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (s *plainSource) Stop() error                                             { return nil }
func (s *plainSource) Gaps() []source.Gap                                      { return nil }

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// TestAdmitLoopback is R38's half that no compiler could write: the enforcement tier has to admit the
// ephemeral port a forwarder bound, and the entry has to name the source so the ledger says where the
// destination came from.
func TestAdmitLoopback(t *testing.T) {
	t.Parallel()
	base := &agent.RuleTable{Net: []agent.NetRule{{Raw: "example.com:443"}}}

	t.Run("no loopback source leaves the table alone", func(t *testing.T) {
		t.Parallel()
		got := admitLoopback(base, []source.Source{&plainSource{name: "uprobe"}})
		if got != base {
			t.Fatalf("the table was rebuilt for a source with no endpoints")
		}
	})

	t.Run("a bound listener becomes one allow entry", func(t *testing.T) {
		t.Parallel()
		src := &fakeLoopback{name: "forwarder", addrs: []netip.AddrPort{ap("127.0.0.1:41001"), ap("127.0.0.1:41002")}}
		got := admitLoopback(base, []source.Source{src})
		if len(base.Net) != 1 {
			t.Fatalf("the compiled table was mutated: %v", base.Net)
		}
		if len(got.Net) != 3 {
			t.Fatalf("net rules %v, want the declared one plus two", got.Net)
		}
		// The entry is a grant the runtime makes on its own authority, so it is named as one:
		// net.capture[<addr>], which agent.IsRuntimeRule recognises and drift does not count as an
		// undeclared contract entry.
		for i, want := range []string{"net.capture[127.0.0.1:41001]", "net.capture[127.0.0.1:41002]"} {
			r := got.Net[i+1]
			if r.RuleName() != want {
				t.Fatalf("rule %d is %q, want %q", i, r.RuleName(), want)
			}
			if !agent.IsRuntimeRule(r.RuleName()) {
				t.Fatalf("rule %d is not recognised as a runtime grant: %q", i, r.RuleName())
			}
			if r.Proto != agent.ProtoTCP || r.Verdict != agent.VerdictAllow || !r.Static {
				t.Fatalf("rule %d is %+v", i, r)
			}
			if r.Port != 41001+i || r.Host != "127.0.0.1" || len(r.IPs) != 1 {
				t.Fatalf("rule %d is %+v", i, r)
			}
		}
	})

	t.Run("an unbound endpoint contributes nothing", func(t *testing.T) {
		t.Parallel()
		// Port 0 is a listener that never bound: admitting it would open every ephemeral port on
		// loopback at tier 1, where the kernel rule is by port alone.
		src := &fakeLoopback{name: "forwarder", addrs: []netip.AddrPort{ap("127.0.0.1:0"), {}}}
		if got := admitLoopback(base, []source.Source{src}); got != base {
			t.Fatalf("net rules %v, want none added", got.Net)
		}
	})
}

// TestForwarderVars is R7: every loopback source's variables reach one map, which is what
// identity.Env installs immediately before execve.
func TestForwarderVars(t *testing.T) {
	t.Parallel()
	r := &runner{deps: Deps{
		Observe: &fakeLoopback{name: "observe", vars: map[string]string{"OBSERVE_URL": "http://127.0.0.1:1"}},
		Capture: []source.Source{
			&fakeLoopback{name: "forwarder", vars: map[string]string{"ANTHROPIC_BASE_URL": "http://127.0.0.1:2"}},
			&plainSource{name: "uprobe"},
		},
	}}
	got := r.forwarderVars()
	want := map[string]string{"OBSERVE_URL": "http://127.0.0.1:1", "ANTHROPIC_BASE_URL": "http://127.0.0.1:2"}
	if len(got) != len(want) {
		t.Fatalf("vars %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("vars[%s] = %q, want %q", k, got[k], v)
		}
	}
	if (&runner{deps: Deps{Capture: []source.Source{&plainSource{name: "uprobe"}}}}).forwarderVars() != nil {
		t.Fatal("a run with no loopback source must set no forwarder variable at all")
	}
}

// TestEmitCaptureGaps is §8 I4 seen from the facade: what the caller's selection could not build is one
// gap event each, and a caller that wired neither a source nor a gap still leaves a line behind.
func TestEmitCaptureGaps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		capture agent.CaptureMode
		deps    Deps
		want    []string
	}{
		{
			name: "selection gaps are written as they came", capture: agent.CaptureForwarder,
			deps: Deps{
				Capture:     []source.Source{&plainSource{name: "forwarder"}},
				CaptureGaps: []source.Gap{{Why: "no-openssl", Binary: "uprobe", Count: 1}},
			},
			want: []string{"no-openssl"},
		},
		{
			name: "a caller that wired nothing still says so", capture: agent.CaptureForwarder,
			want: []string{"mechanism-unavailable"},
		},
		{
			name: "capture off asks for nothing and gaps nothing", capture: agent.CaptureOff,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &runner{rt: &agent.RuleTable{Capture: tc.capture}, deps: tc.deps, queue: NewQueue(8)}
			r.emitCaptureGaps()
			r.queue.Close()
			var got []string
			for ev := range r.queue.C() {
				if ev.Kind != record.KindGap {
					t.Fatalf("queued a %s", ev.Kind)
				}
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.What != record.GapCapture {
					t.Fatalf("gap what=%q, want capture", p.What)
				}
				got = append(got, p.Why)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("gaps %v, want %v", got, tc.want)
			}
		})
	}
}
