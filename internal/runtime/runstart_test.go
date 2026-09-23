// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// tierBackend is an enforce.Backend that only answers the two questions run_start asks of it.
type tierBackend struct {
	tier backend.Tier
	caps backend.Set
}

func (b tierBackend) Tier() backend.Tier        { return b.tier }
func (b tierBackend) Capabilities() backend.Set { return b.caps.Clone() }
func (b tierBackend) Prepare(context.Context, *agent.RuleTable, enforce.RunRef) (api.Handle, error) {
	return tier1Handle{}, nil
}

// reportingHandle is a handle that narrowed its tier's row while it prepared (enforce.Reporter).
type reportingHandle struct {
	tier1Handle
	caps backend.Set
}

func (h reportingHandle) Capabilities() backend.Set { return h.caps.Clone() }

// gapSource is a capture source that started and reports the given gaps, the way a real one does from the
// moment Start returns.
type gapSource struct {
	plainSource
	gaps []source.Gap
}

func (s *gapSource) Gaps() []source.Gap { return s.gaps }

// inertSource is a capture source whose Start returned nil and whose mechanism never ran: it says so the way
// the uprobe source does when its capture object will not load, with a mechanism-unavailable gap naming itself.
func inertSource(name string) *gapSource {
	return &gapSource{plainSource: plainSource{name: name},
		gaps: []source.Gap{{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: name}}}
}

// TestCaptureModeIsWhatStarted is run_start.capture read off the mechanisms that ran. rt.Capture is compiled
// against the machine ceiling, not the tier, so on a machine with no tier ceiling an auto contract compiles
// to uprobe and then runs at tier 1 with the forwarder alone: recording rt.Capture wrote capture=uprobe for a
// run no uprobe ever saw. And the tier's kernel recorder raises no ssl event, so a run that has one and no
// capture source captured nothing, whatever the contract asked.
func TestCaptureModeIsWhatStarted(t *testing.T) {
	cases := []struct {
		name     string
		compiled agent.CaptureMode
		capture  []source.Source
		kernel   source.Source
		want     string
	}{
		{"auto compiled to uprobe, forwarder alone ran", agent.CaptureUprobe,
			[]source.Source{&plainSource{name: "forwarder"}}, nil, "forwarder"},
		{"both mechanisms ran", agent.CaptureUprobe,
			[]source.Source{&plainSource{name: "uprobe"}, &plainSource{name: "forwarder"}}, nil, "uprobe"},
		{"uprobe alone ran", agent.CaptureUprobe, []source.Source{&plainSource{name: "uprobe"}}, nil, "uprobe"},
		{"a tier-2 recorder with no capture source captured nothing", agent.CaptureForwarder,
			nil, &plainSource{name: "observe"}, "off"},
		{"nothing ran", agent.CaptureForwarder, nil, nil, "off"},
		{"capture off", agent.CaptureOff, nil, nil, "off"},
		// An uprobe source that could not load its capture object starts without error (§4) and captures
		// nothing; its own gap says so at run end, and run_start must not say otherwise at the start.
		{"an inert uprobe beside the forwarder", agent.CaptureUprobe,
			[]source.Source{inertSource("uprobe"), &plainSource{name: "forwarder"}}, nil, "forwarder"},
		{"an inert uprobe alone", agent.CaptureUprobe, []source.Source{inertSource("uprobe")}, nil, "off"},
		{"an inert forwarder alone", agent.CaptureForwarder, []source.Source{inertSource("forwarder")}, nil, "off"},
		// Only the source's own mechanism counts: a per-binary gap is what a running uprobe reports.
		{"a running uprobe with a per-binary gap", agent.CaptureUprobe,
			[]source.Source{&gapSource{plainSource: plainSource{name: "uprobe"}, gaps: []source.Gap{
				{What: record.GapCapture, Why: "static-tls-no-symbols", Binary: "/usr/bin/bun"},
				{What: record.GapCapture, Why: derive.GapMechanismUnavailable, Binary: "forwarder"},
			}}}, nil, "uprobe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{Capture: tc.capture})
			r.rt = &agent.RuleTable{Capture: tc.compiled}
			r.kernelRecord = tc.kernel
			if got := r.captureMode(); got != tc.want {
				t.Fatalf("captureMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRunLimitsWritesAZeroBudget: the watcher enforces a dimension whenever
// ResolvedLimits.Bounded says so, a 0 included (E16), so run_start.limits has to carry the same set of
// dimensions or a reader sees no budget on a run the watcher ends at its first token. Checked on the JSON a
// reader decodes, key by key.
func TestRunLimitsWritesAZeroBudget(t *testing.T) {
	cases := []struct {
		name string
		in   agent.ResolvedLimits
		want map[string]any // nil: no limits block at all
	}{
		{"nothing asked", agent.ResolvedLimits{}, nil},
		{"every dimension bounded at zero",
			agent.ResolvedLimits{Set: agent.BudgetTokens | agent.BudgetCostUSD | agent.BudgetWall |
				agent.BudgetStallAfter | agent.BudgetRepeats},
			map[string]any{"tokens": 0.0, "cost_usd": 0.0, "wall": "0s", "stall_after": "0s", "repeats": 0.0}},
		{"a zero token budget beside a cost budget",
			agent.ResolvedLimits{CostUSD: 2.5, Set: agent.BudgetTokens | agent.BudgetCostUSD},
			map[string]any{"tokens": 0.0, "cost_usd": 2.5}},
		{"a value with no bit still counts, as Bounded says",
			agent.ResolvedLimits{Tokens: 10, StallAfter: 90 * time.Second},
			map[string]any{"tokens": 10.0, "stall_after": "1m30s"}},
		{"a zero with no bit is no budget", agent.ResolvedLimits{Tokens: 0, Repeats: 0}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runLimits(tc.in, 0)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("runLimits = %+v, want no block", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("runLimits = nil, want %v", tc.want)
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var keys map[string]any
			if err := json.Unmarshal(b, &keys); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(keys, tc.want) {
				t.Fatalf("run_start.limits = %s, want %v", b, tc.want)
			}
		})
	}
}

// TestCapabilityLine is run_start.capabilities: every row of the matrix, the handle's own narrowed set when it
// reports one, and the rows only the facade can answer — capture, set from the same value as run_start.capture;
// the record rows, set from the record mode and from what records an observe run; reads that cannot reach the
// record; and the rows no contract this binary loads can ask for.
func TestCapabilityLine(t *testing.T) {
	tier1 := backend.Matrix(backend.TierLandlock)
	tier2 := backend.Matrix(backend.TierCgroup)
	observe := backend.Matrix(backend.TierObserve)
	narrowed := tier1.Clone()
	delete(narrowed, backend.CapReadDeny) // R4: a deny_read entry left unenforced under a writable parent
	fwd := func() []source.Source { return []source.Source{&plainSource{name: "forwarder"}} }
	recordRowsAre := func(exec, reads, logged bool) map[backend.Capability]bool {
		return map[backend.Capability]bool{backend.CapRecordExecOpenNet: exec, backend.CapRecordReads: reads,
			backend.CapLogAllowed: logged}
	}

	cases := []struct {
		name    string
		backend tierBackend
		handle  api.Handle
		record  agent.RecordMode
		capture []source.Source
		kernel  source.Source
		want    map[backend.Capability]bool // rows checked; every other row must match the start set
		start   backend.Set
	}{
		{
			name: "the handle's narrowed set wins over the tier's row", backend: tierBackend{backend.TierLandlock, tier1},
			handle: reportingHandle{caps: narrowed}, record: agent.RecordFull, capture: fwd(),
			want: map[backend.Capability]bool{backend.CapReadDeny: false, backend.CapCaptureModel: true,
				backend.CapRecordReads: true},
			start: narrowed,
		},
		{
			name: "a handle that reports nothing falls back to the backend", backend: tierBackend{backend.TierLandlock, tier1},
			handle: tier1Handle{}, record: agent.RecordFull, capture: fwd(),
			want:  map[backend.Capability]bool{backend.CapReadDeny: true, backend.CapExecDeny: true},
			start: tier1,
		},
		{
			name: "no capture source started", backend: tierBackend{backend.TierLandlock, tier1},
			handle: tier1Handle{}, record: agent.RecordFull,
			want:  map[backend.Capability]bool{backend.CapCaptureModel: false},
			start: tier1,
		},
		{
			name: "an inert uprobe is no capture", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordSummary, kernel: &plainSource{name: "observe"},
			capture: []source.Source{inertSource("uprobe")},
			want:    map[backend.Capability]bool{backend.CapCaptureModel: false},
			start:   tier2,
		},
		// A uprobe source that decided at its own Start to capture, beside a recorder that decided at its Start
		// to read nothing: nothing hands the source an exec or an open, so it attaches nothing, and run_start
		// must not name it as the run's capture. The two decide from two walks of the run set, which another
		// run's row can fall between.
		{
			name: "a live uprobe beside an inert recorder is no capture", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordSummary,
			kernel: &gapSource{plainSource: plainSource{name: "observe"},
				gaps: []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}},
			capture: []source.Source{&followerSource{plainSource: plainSource{name: "uprobe"}}},
			want:    map[backend.Capability]bool{backend.CapCaptureModel: false, backend.CapRecordReads: false},
			start:   tier2,
		},
		{
			name: "a live uprobe beside a reading recorder captures", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordSummary, kernel: &plainSource{name: "observe"},
			capture: []source.Source{&followerSource{plainSource: plainSource{name: "uprobe"}}},
			want:    map[backend.Capability]bool{backend.CapCaptureModel: true},
			start:   tier2,
		},
		{
			name: "tier 1 under summary records no reads", backend: tierBackend{backend.TierLandlock, tier1},
			handle: tier1Handle{}, record: agent.RecordSummary, capture: fwd(),
			want:  recordRowsAre(true, false, true),
			start: tier1,
		},
		{
			name: "tier 1 under record: off keeps refusals only", backend: tierBackend{backend.TierLandlock, tier1},
			handle: tier1Handle{}, record: agent.RecordOff, capture: fwd(),
			want:  recordRowsAre(false, false, false),
			start: tier1,
		},
		{
			name: "tier 2 whose recorder never started records no reads", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordSummary, capture: fwd(),
			want:  map[backend.Capability]bool{backend.CapRecordReads: false},
			start: tier2,
		},
		// The recorder started and reads nothing: another run of the build holds the ring, or the run had
		// no row to scope by. Its own gap says so, and run_start must not claim the reads the ring would
		// have carried. Exec, write-open and connect still reach the supervisor through the inherited
		// tier-1 filter, so that row stays.
		{
			name: "tier 2 whose recorder reads nothing records no reads", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordSummary, capture: fwd(),
			kernel: &gapSource{plainSource: plainSource{name: "observe"},
				gaps: []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}},
			want:  recordRowsAre(true, false, true),
			start: tier2,
		},
		// Under record: full the inherited tier-1 filter notifies read-opens, as tier 1's does, and the
		// supervisor records them whether or not anything drains the ring.
		{
			name: "tier 2 under record: full records reads without its ring", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordFull, capture: fwd(),
			kernel: &gapSource{plainSource: plainSource{name: "observe"},
				gaps: []source.Gap{{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1}}},
			want:  recordRowsAre(true, true, true),
			start: tier2,
		},
		{
			name: "tier 2 with its recorder records reads under summary", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordSummary, kernel: &plainSource{name: "observe"},
			capture: fwd(),
			want:    recordRowsAre(true, true, true),
			start:   tier2,
		},
		{
			name: "tier 2 under record: off keeps refusals only", backend: tierBackend{backend.TierCgroup, tier2},
			handle: tier2Handle{hash: "h"}, record: agent.RecordOff, kernel: &plainSource{name: "observe"},
			capture: fwd(),
			want:    recordRowsAre(false, false, false),
			start:   tier2,
		},
		// An observe run enforces nothing, so its row is empty, but it records through tier 1's filter and
		// captures through whatever source started: a line of all false next to capture=forwarder and an
		// exec event with verdict observed was a false statement in the record.
		{
			name: "observe with a forwarder under summary", backend: tierBackend{backend.TierObserve, observe},
			handle: reportingHandle{caps: observe}, record: agent.RecordSummary, capture: fwd(),
			want: map[backend.Capability]bool{backend.CapCaptureModel: true, backend.CapRecordExecOpenNet: true,
				backend.CapRecordReads: false, backend.CapLogAllowed: true},
			start: observe,
		},
		{
			name: "observe under record: full records reads", backend: tierBackend{backend.TierObserve, observe},
			handle: reportingHandle{caps: observe}, record: agent.RecordFull,
			want: map[backend.Capability]bool{backend.CapCaptureModel: false, backend.CapRecordExecOpenNet: true,
				backend.CapRecordReads: true, backend.CapLogAllowed: true},
			start: observe,
		},
		{
			name: "observe under record: off", backend: tierBackend{backend.TierObserve, observe},
			handle: reportingHandle{caps: observe}, record: agent.RecordOff, capture: fwd(),
			want: map[backend.Capability]bool{backend.CapCaptureModel: true, backend.CapRecordExecOpenNet: false,
				backend.CapRecordReads: false, backend.CapLogAllowed: false},
			start: observe,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{Enforce: tc.backend, Capture: tc.capture})
			r.rt = &agent.RuleTable{Record: tc.record}
			r.handle = tc.handle
			r.kernelRecord = tc.kernel
			capture := r.captureMode()
			got := r.capabilityLine(capture)
			all := backend.AllCapabilities()
			if len(got) != len(all) {
				t.Fatalf("%d rows, want every one of the %d (a false is a statement)", len(got), len(all))
			}
			if got[string(backend.CapCaptureModel)] != (capture != string(agent.CaptureOff)) {
				t.Errorf("capture.model_traffic = %v beside run_start.capture = %q",
					got[string(backend.CapCaptureModel)], capture)
			}
			for _, c := range all {
				v, ok := got[string(c)]
				if !ok {
					t.Fatalf("row %s missing", c)
				}
				want, checked := tc.want[c]
				if !checked {
					want = tc.start.Has(c) && !slices.Contains(notInThisPhase, c)
					if c == backend.CapNetHTTPRules || c == backend.CapAsk || c == backend.CapGateNetCompletion || c == backend.CapHostSocketsRefused {
						want = false
					} // no policy-bearing source and no started supervisor in these capture-only cases
					if c == backend.CapTCPDestinationKernel || c == backend.CapUDPByDestination || c == backend.CapUnixDestinationKernel ||
						c == backend.CapSocketFamilies {
						want = false // these doubles provide no actual attachment proof
					}
					if t := tc.backend.Tier(); (c == backend.CapReadDenyNested || c == backend.CapReadDenyCreatedLater) &&
						(t == backend.TierLandlock || t == backend.TierObserve) {
						want = false // no run here holds its reads, which is what makes both hold at tier landlock (ADR 0069)
					}
				}
				if v != want {
					t.Errorf("%s = %v, want %v", c, v, want)
				}
			}
			for _, c := range notInThisPhase {
				if got[string(c)] {
					t.Errorf("%s = true: no contract this binary loads can ask for it", c)
				}
			}
		})
	}
}

// TestCapabilityLineCompletionRows is ADR 0041 D7's two run-answered rows. gate.net_completion is the supervisor's
// relay: present on the tier's row, it holds only once a started supervisor owns the notifications.
// fs.protected_write_targets holds where a decision plane mode decides the run, and never at tier 1 or on tier 2's
// fanotify listener, whatever the handle's set says, so it matches best_effort's deny_write/default.
func TestCapabilityLineCompletionRows(t *testing.T) {
	r := newTestRunner(Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}})
	r.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "completion-rows"}, Record: agent.RecordSummary}
	r.handle, r.notifyFD = tier1Handle{}, sys.InertForTest(3)
	if got := r.capabilityLine("off"); got[string(backend.CapGateNetCompletion)] || got[string(backend.CapProtectedWriteTargets)] {
		t.Fatalf("no supervisor and no plane: net completion %v, protected writes %v", got[string(backend.CapGateNetCompletion)],
			got[string(backend.CapProtectedWriteTargets)])
	}
	startedNotifyLoop(t, r)
	if got := r.capabilityLine("off"); !got[string(backend.CapGateNetCompletion)] || got[string(backend.CapProtectedWriteTargets)] {
		t.Fatalf("tier 1 with a started supervisor: net completion %v, protected writes %v", got[string(backend.CapGateNetCompletion)],
			got[string(backend.CapProtectedWriteTargets)])
	}
	for _, tc := range []struct {
		mode string
		want bool
	}{{"", false}, {record.DecisionPlaneFmodRet, true}, {record.DecisionPlaneLSM, true}} {
		// The handle claims the row either way: the run's own plane decides it.
		caps := backend.Matrix(backend.TierCgroup)
		caps[backend.CapProtectedWriteTargets] = true
		r := newTestRunner(Deps{Enforce: tierBackend{backend.TierCgroup, backend.Matrix(backend.TierCgroup)}})
		r.rt = &agent.RuleTable{Record: agent.RecordSummary, DenyWrite: []agent.FSRule{{Path: "/w/.git/hooks",
			Kind: agent.FSDenyWrite, BuiltIn: true, Resolved: "/w/.git/hooks"}}}
		r.handle = planeReportingHandle{reportingHandle: reportingHandle{caps: caps}, mode: tc.mode}
		if got := r.capabilityLine("off")[string(backend.CapProtectedWriteTargets)]; got != tc.want {
			t.Errorf("plane %q: protected write targets %v, want %v", tc.mode, got, tc.want)
		}
		if listed := slices.Contains(r.rt.BestEffortCellsAt(backend.TierCgroup, r.decisionPlane()), agent.BestEffortDenyWrite); listed == tc.want {
			t.Errorf("plane %q: best_effort lists %s %v beside protected write targets %v", tc.mode, agent.BestEffortDenyWrite,
				listed, tc.want)
		}
	}
}

// planeReportingHandle is a reporting handle whose run a decision plane decides in mode ("" for the listener).
type planeReportingHandle struct {
	reportingHandle
	mode string
}

func (h planeReportingHandle) DecisionPlane() (string, bool) { return h.mode, false }

// TestNotInThisPhaseIsRefusedByTheLoader is what keeps notInThisPhase honest: each row is there because the only
// contract that could use it is one the loader refuses as not yet supported. The day a phase lands and the
// loader accepts one, this fails, and that row has to leave the list and be answered by the run instead.
func TestNotInThisPhaseIsRefusedByTheLoader(t *testing.T) {
	asks := map[backend.Capability][]string{
		backend.CapNamespaceSandbox:  {"containers: rootless\n"},
		backend.CapAdoptedContainers: {"docker:\n  allow: [privileged]\n"},
	}
	if len(asks) != len(notInThisPhase) {
		t.Fatalf("notInThisPhase has %d rows and %d have a contract that asks for them", len(notInThisPhase), len(asks))
	}
	for _, row := range notInThisPhase {
		snippets, ok := asks[row]
		if !ok {
			t.Fatalf("%s is in notInThisPhase with no contract field that would ask for it", row)
		}
		for _, s := range snippets {
			_, ds, err := agent.LoadBytes("a.yaml", []byte("version: 0\nname: a\ncommand: [x]\n"+s), nil)
			refused := errors.Is(err, agent.ErrInvalidContract) && len(ds) > 0
			for _, d := range ds {
				refused = refused && d.Code == agent.CodeNotYetSupported
			}
			if !refused {
				t.Errorf("%s: the loader accepts %q (err %v, %+v); the row is reachable now", row, s, err, ds)
			}
		}
	}
}

// TestWatchedReadGap is E56 and SEMANTICS §7's last sentence: tier 1 notifies read-opens only under record:
// full, so a run with deny_read or fs.watch entries and any other record mode writes gap what=record
// why=unprivileged-tier, once, instead of a ledger where a watched secret that was read looks untouched.
func TestWatchedReadGap(t *testing.T) {
	denyRead := []agent.FSRule{{Path: "/home/u/.ssh", Kind: agent.FSDenyRead, BuiltIn: true}}
	watch := []agent.FSRule{{Path: "/work/secrets.txt", Kind: agent.FSWatch}}
	writeOnly := []agent.FSRule{{Path: "/work/out", Kind: agent.FSWrite}}
	cases := []struct {
		name   string
		tier   backend.Tier
		record agent.RecordMode
		fs     []agent.FSRule
		want   bool
	}{
		{"tier 1 summary with a built-in deny_read", backend.TierLandlock, agent.RecordSummary, denyRead, true},
		{"tier 1 off with an fs.watch entry", backend.TierLandlock, agent.RecordOff, watch, true},
		{"an observe run installs the same filter", backend.TierObserve, agent.RecordSummary, denyRead, true},
		{"record: full notifies every read", backend.TierLandlock, agent.RecordFull, denyRead, false},
		{"nothing watched, nothing missing", backend.TierLandlock, agent.RecordSummary, writeOnly, false},
		{"tier 2 records reads in the kernel", backend.TierCgroup, agent.RecordSummary, denyRead, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(Deps{Enforce: tierBackend{tier: tc.tier}})
			r.rt = &agent.RuleTable{Record: tc.record, FS: tc.fs}
			r.queue = NewQueue(8)
			r.emitWatchedReadGap()
			r.queue.Close()
			var got []record.GapPayload
			for ev := range r.queue.C() {
				var p record.GapPayload
				if ev.Kind != record.KindGap || ev.DecodePayload(&p) != nil {
					t.Fatalf("queued %s", ev.Kind)
				}
				got = append(got, p)
			}
			var want []record.GapPayload
			if tc.want {
				want = []record.GapPayload{{What: record.GapRecord, Why: GapUnprivilegedTier}}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("gaps %+v, want %+v", got, want)
			}
		})
	}
}

// TestRunEndCountersCarryEverything pins the E35 and R21 counters into run_end.supervisor: both totals used to
// stop at the loop, where nothing read them, and so did R23a's order_lost. exec_missing (supervisor
// R16b (0)) is the only trace of the misses.
func TestRunEndCountersCarryEverything(t *testing.T) {
	got := runEndCounters(supervisor.Metrics{Notifications: 5, HeldMS: 7, Anomalies: 1, Orphaned: 3, Starved: 2, OrderLost: 4, ExecMissing: 9})
	want := record.Supervisor{Notifications: 5, HeldMS: 7, Anomalies: 1, Orphaned: 3, Starved: 2, OrderLost: 4, ExecMissing: 9}
	if got != want {
		t.Fatalf("run_end.supervisor = %+v, want %+v", got, want)
	}
}

// A run that holds its reads (ADR 0069) has an open deputy without gate.completion: held: the held-read rows hold,
// and the gate's open completion row stays false, since no gate open is held (conformance's capability cross-check
// caught the over-claim: the row once read the deputy's presence alone).
func TestCapabilityLineHeldReadsClaimNoGateCompletion(t *testing.T) {
	r := newTestRunner(Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}})
	r.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "held-reads"}, Record: agent.RecordSummary, Tier: backend.TierLandlock,
		Reads: agent.HeldReads{Mode: agent.ReadsHeld}}
	r.handle = tier1Handle{}
	startedNotifyLoop(t, r)
	r.deputy = &deputy.Client{}
	got := r.capabilityLine("off")
	if got[string(backend.CapGateFSOpenCompletion)] {
		t.Errorf("capabilities[%s] = true in a run whose deputy holds only its reads", backend.CapGateFSOpenCompletion)
	}
	for c, want := range map[backend.Capability]bool{backend.CapReadDenyNested: true, backend.CapReadDenyCreatedLater: true,
		backend.CapReadDenyMoved: false} {
		if got[string(c)] != want {
			t.Errorf("capabilities[%s] = %t, want %t", c, got[string(c)], want)
		}
	}
}
