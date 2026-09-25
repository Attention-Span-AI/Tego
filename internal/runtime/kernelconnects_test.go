// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gappedRecorder is a kernel recorder with fixed gaps and, optionally, a Reading answer (KernelReading).
type gappedRecorder struct {
	plainSource
	gaps []source.Gap
}

func (s *gappedRecorder) Gaps() []source.Gap { return s.gaps }

type liveRecorder struct {
	plainSource
	reading bool
}

func (s *liveRecorder) Reading() bool { return s.reading }

// TestKernelConnectsFollowsTheRecorder is the runtime's half of supervisor.md R7's one line per connect:
// the supervisor leaves a continued IP connect to the kernel recorder only while that recorder reads this
// run's ring. The answer waits for the recorder's start (the supervisor's loop runs first), and is false
// for a recorder that read nothing, one whose drain has failed, a run whose sources did not all start,
// and a run cancelled before the decision: in each the supervisor's line is the connect's only one.
func TestKernelConnectsFollowsTheRecorder(t *testing.T) {
	inert := []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}
	for _, tc := range []struct {
		name    string
		src     source.Source
		started bool
		want    bool
	}{
		{"a recorder that reads", &plainSource{name: "observe"}, true, true},
		{"a recorder that reads nothing", &gappedRecorder{plainSource{name: "observe"}, inert}, true, false},
		{"a recorder whose drain failed", &liveRecorder{plainSource{name: "observe"}, false}, true, false},
		{"a recorder still reading", &liveRecorder{plainSource{name: "observe"}, true}, true, true},
		{"sources that did not all start", &plainSource{name: "observe"}, false, false},
		{"no recorder", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{})
			r.kernelRecord = tc.src
			r.kernelDecided = make(chan struct{})
			ask := r.kernelConnects(context.Background())
			got := make(chan bool, 1)
			go func() { got <- ask() }()
			select {
			case v := <-got:
				t.Fatalf("answered %v before the recorder was started", v)
			case <-time.After(20 * time.Millisecond):
			}
			r.decideKernelRecord(tc.started)
			select {
			case v := <-got:
				if v != tc.want {
					t.Errorf("kernelConnects = %v, want %v", v, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("kernelConnects never answered once the recorder was decided")
			}
		})
	}

	t.Run("a cancelled run keeps the supervisor's line", func(t *testing.T) {
		r := newTestRunner(Deps{})
		r.kernelRecord = &plainSource{name: "observe"}
		r.kernelDecided = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		ask := r.kernelConnects(ctx)
		cancel()
		if ask() {
			t.Error("kernelConnects = true for a run cancelled before its recorder started")
		}
	})
	// A budget trip or SIGINT cancels the run after the recorder was decided and while it still reads: the
	// decision already made must win, or the supervisor writes its own line beside the recorder's (two lines
	// for one connect). Go's select picks at random among ready cases, so this asks many times.
	t.Run("a decided recorder wins over a cancelled run", func(t *testing.T) {
		r := newTestRunner(Deps{})
		r.kernelRecord = &liveRecorder{plainSource{name: "observe"}, true}
		r.kernelDecided = make(chan struct{})
		r.decideKernelRecord(true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ask := r.kernelConnects(ctx)
		for i := 0; i < 10000; i++ {
			if !ask() {
				t.Fatalf("kernelConnects = false on ask %d: a decided, reading recorder lost to the cancelled run", i)
			}
		}
	})
	t.Run("no decision to wait for", func(t *testing.T) {
		r := newTestRunner(Deps{})
		r.kernelRecord = &plainSource{name: "observe"}
		if r.kernelConnects(context.Background())() {
			t.Error("kernelConnects = true with nothing to decide it")
		}
	})
}

type namingRecorder struct {
	plainSource
	fn func(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool)
}

func (s *namingRecorder) SetContinuedNet(fn func(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool)) {
	s.fn = fn
}

// TestKernelRecorderNamesConnectsAsTheSupervisor: the kernel recorder is handed the supervisor's lookup for a
// connect the supervisor continues, whose line the recorder's then replaces (supervisor.md R7); a recorder
// that cannot take it, or no recorder, is left alone.
func TestKernelRecorderNamesConnectsAsTheSupervisor(t *testing.T) {
	lookup := func(netip.AddrPort, string) (string, string, record.Verdict, bool) {
		return "net.resolver", "192.0.2.53", record.VerdictAllow, true
	}
	rec := &namingRecorder{plainSource: plainSource{name: "observe"}}
	r := newTestRunner(Deps{})
	r.kernelRecord = rec
	r.nameKernelConnects(lookup)
	if rec.fn == nil {
		t.Fatal("the kernel recorder was not handed the supervisor's lookup")
	}
	if rule, _, _, _ := rec.fn(netip.MustParseAddrPort("192.0.2.53:53"), "udp"); rule != "net.resolver" {
		t.Errorf("the recorder's lookup names %q, want the supervisor's", rule)
	}
	for _, src := range []source.Source{nil, &plainSource{name: "observe"}} {
		r := newTestRunner(Deps{})
		r.kernelRecord = src
		r.nameKernelConnects(lookup) // must not panic
	}
}
