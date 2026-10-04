// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestAskCapabilityRequiresStartedAvailableBroker(t *testing.T) {
	b, err := ask.New(t.TempDir(), ask.Options{UID: uint32(os.Getuid()), Authorize: func(ask.Peer) error { return nil }, Emit: func(ask.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r := newTestRunner(Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}})
	r.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "ask-readiness"}, Record: agent.RecordSummary, AskConfig: &agent.AskConfig{Hold: agent.AskHoldConnect}}
	r.handle, r.askBroker, r.notifyFD = tier1Handle{}, b, sys.InertForTest(3)
	if r.capabilityLine("off")[string(backend.CapAsk)] {
		t.Fatal("an unstarted notification listener advertised ask")
	}
	startedNotifyLoop(t, r)
	if r.notifyFD != nil || r.sup == nil || !r.sup.Started() {
		t.Fatal("notification listener ownership did not transfer to an armed supervisor")
	}
	if !r.capabilityLine("off")[string(backend.CapAsk)] {
		t.Fatal("armed supervisor and live broker capability absent after fd transfer")
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	if r.capabilityLine("off")[string(backend.CapAsk)] {
		t.Fatal("closed broker advertised ask")
	}
}

func TestAskLedgerFailureEndsGovernedRun(t *testing.T) {
	const id = "r-00000000-000000000000a-askxyz"
	w, err := ledger.Open(filepath.Join(t.TempDir(), id), record.RunRef{ID: id, Agent: "ask-test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	cgm := &fakeCgroups{}
	r := &runner{writer: w, deps: Deps{Clock: fixedClock{at: time.Now()}}, cg: cgroup.Cgroup{Path: "/private-fixture", ID: 1}, cgm: cgm, log: slog.New(slog.DiscardHandler)}
	err = r.emitAsk(ask.Event{Kind: "answer", Request: ask.Request{AskID: "q-00112233445566778899aabbccddeeff", Op: "connect", Target: "192.0.2.1:443", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()}, Decision: ask.Decision{Approved: true, By: "human"}})
	if !errors.Is(err, ledger.ErrClosed) || r.terminal != identity.ReasonError || cgm.killed != 1 || !strings.HasPrefix(r.detail, "ledger: ") {
		t.Fatalf("unrecordable approval err=%v terminal=%q killed=%d detail=%q", err, r.terminal, cgm.killed, r.detail)
	}
}

func TestAskLifecyclePrivateLedgerPreservesSchemaRedactionAndRefusal(t *testing.T) {
	const id = "r-00000000-000000000000a-askxyz"
	dir := filepath.Join(t.TempDir(), id)
	w, e := ledger.Open(dir, record.RunRef{ID: id, Agent: "ask-test"}, ledger.WithAnchor(nopAnchor{}))
	if e != nil {
		t.Fatal(e)
	}
	if e = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); e != nil {
		t.Fatal(e)
	}
	r := &runner{writer: w, deps: Deps{Clock: fixedClock{at: time.Now()}}, cg: cgroup.Cgroup{ID: 1}}
	// A credential can reach an ask target only through a forwarder request's
	// path (a connect target is the copied ip:port); the denied first_write
	// connect writes the refusal mirror and last-refusal.json.
	httpReq := ask.Request{AskID: "q-00112233445566778899aabbccddeeff", Op: "http_request", Target: "api.anthropic.com:443 GET /v1/files/never-retain", Rule: "net.ask[tcp://api.anthropic.com:443]", Hold: "request", PID: os.Getpid(), TID: os.Getpid()}
	connectReq := ask.Request{AskID: "q-00112233445566778899aabbccddeef0", Op: "connect", Target: "192.0.2.1:443", Rule: "net.ask[tcp://192.0.2.1:443]", Hold: "first_write", PID: os.Getpid(), TID: os.Getpid()}
	for _, req := range []ask.Request{httpReq, connectReq} {
		if e = r.emitAsk(ask.Event{Kind: "ask", Request: req}); e != nil {
			t.Fatal(e)
		}
		if e = r.emitAsk(ask.Event{Kind: "answer", Request: req, Decision: ask.Decision{Reason: ask.ReasonDenied, By: "human", AfterS: 1}}); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(record.RunEndPayload{Reason: record.RunEndExit}); e != nil {
		t.Fatal(e)
	}
	for _, ev := range events(t, dir) {
		if e = ev.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	for _, file := range []string{ledger.EventsFile, ledger.LastRefusalFile} {
		data, e := os.ReadFile(filepath.Join(dir, file))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(data), "never-retain") {
			t.Fatalf("secret in %s", file)
		}
	}
	if rep, e := ledger.VerifyRunDir(context.Background(), dir, nil); e != nil || !rep.Started || !rep.Ended {
		t.Fatalf("chain %+v %v", rep, e)
	}
}

func TestAskCgroupBoundaryAndAdministrativeMembership(t *testing.T) {
	for _, tc := range []struct {
		run, task string
		want      bool
	}{{"/run/a", "/run/a", true}, {"/run/a", "/run/a/child", true}, {"/run/a", "/run/ab", false}, {"/", "/child", false}, {"", "/run/a", false}} {
		if got := inAskCgroup(tc.run, tc.task); got != tc.want {
			t.Fatalf("%q %q=%v", tc.run, tc.task, got)
		}
	}
	cg, e := unifiedAskCgroup(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	r := &runner{cg: cgroup.Cgroup{Path: "/sys/fs/cgroup" + cg}, askOwner: uint32(os.Getuid())}
	// The peer as the socket identified it, in this run's own cgroup (no run's shape: the own-run rule refuses it).
	if e = r.askPeerAuthorize(ask.Peer{PID: os.Getpid(), UID: uint32(os.Getuid()), Cgroup: cg, CgroupNS: selfCgroupNS(t)}); e == nil {
		t.Fatal("governed same-UID process authenticated as administrator")
	}
	if _, e = r.askRequest(t.Context(), ask.Request{PID: os.Getpid(), TID: os.Getpid()}); e == nil {
		t.Fatal("missing broker granted ask")
	}
}

// The ask and answer lines are the audit record of a human grant, so they keep the
// target the human was shown: a filesystem path or connect destination exactly, as
// the following fs/net action records it (record-ledger R9a). Only an HTTP request
// target's path is projected onto the public routes, because a path segment can
// carry a credential; its fixed authority and method stay. The first_write refusal
// mirror and last-refusal.json keep the exact destination as every refusal does.
func TestAskLedgerRecordsApprovedTargetsFaithfully(t *testing.T) {
	const id = "r-00000000-000000000000a-askxyz"
	dir := filepath.Join(t.TempDir(), id)
	w, e := ledger.Open(dir, record.RunRef{ID: id, Agent: "ask-test"}, ledger.WithAnchor(nopAnchor{}))
	if e != nil {
		t.Fatal(e)
	}
	if e = w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Tier: "landlock"}); e != nil {
		t.Fatal(e)
	}
	r := &runner{writer: w, deps: Deps{Clock: fixedClock{at: time.Now()}}, cg: cgroup.Cgroup{ID: 1}}
	pid := os.Getpid()
	cases := []struct {
		req  ask.Request
		want string
	}{
		{ask.Request{Op: record.FSOpen, Target: "/home/u/proj/approved/x", Rule: "fs.ask[/home/u/proj/approved]", Hold: ask.HoldOpen}, "/home/u/proj/approved/x"},
		{ask.Request{Op: "connect", Target: "192.0.2.2:443", Rule: "net.ask[tcp://192.0.2.2:443]", Hold: "first_write"}, "192.0.2.2:443"},
		{ask.Request{Op: "http_request", Target: "api.anthropic.com:443 POST /v1/messages", Hold: "request"}, "api.anthropic.com:443 POST /v1/messages"},
		{ask.Request{Op: "http_request", Target: "api.anthropic.com:443 GET /v1/files/sk-never-retain", Hold: "request"}, "api.anthropic.com:443 GET /redacted"},
		{ask.Request{Op: "http_request", Target: "sk-never-retain", Hold: "request"}, "/redacted"},
	}
	for i, tc := range cases {
		tc.req.AskID, tc.req.PID, tc.req.TID = fmt.Sprintf("q-%032x", i+1), pid, pid
		if e = r.emitAsk(ask.Event{Kind: "ask", Request: tc.req}); e != nil {
			t.Fatal(e)
		}
		// The connect is denied under first_write so its refusal mirror is written.
		d := ask.Decision{Approved: tc.req.Op != "connect", By: "human", AfterS: 1}
		if !d.Approved {
			d.Reason = ask.ReasonDenied
		}
		if e = r.emitAsk(ask.Event{Kind: "answer", Request: tc.req, Decision: d}); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(record.RunEndPayload{Reason: record.RunEndExit}); e != nil {
		t.Fatal(e)
	}
	var got []string
	for _, ev := range events(t, dir) {
		if ev.Kind != record.KindAsk && ev.Kind != record.KindAnswer && ev.Kind != record.KindRefused {
			continue
		}
		var p struct {
			Target string `json:"target"`
		}
		if e = json.Unmarshal(ev.Payload, &p); e != nil {
			t.Fatal(e)
		}
		got = append(got, string(ev.Kind)+" "+p.Target)
	}
	var want []string
	for _, tc := range cases {
		want = append(want, "ask "+tc.want, "answer "+tc.want)
		if tc.req.Op == "connect" {
			want = append(want, "refused "+tc.want)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("stored targets:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	data, e := os.ReadFile(filepath.Join(dir, ledger.LastRefusalFile))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(data), `"target":"192.0.2.2:443"`) {
		t.Fatalf("last refusal lost the denied destination: %s", data)
	}
	if strings.Contains(string(data), "never-retain") {
		t.Fatal("HTTP path credential reached last-refusal.json")
	}
	lines, e := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(lines), "never-retain") {
		t.Fatal("HTTP path credential reached the ledger")
	}
}

// A pending human approval holds the agent in Tego itself, for up to the
// ask timeout, so it is not a stall (limits R4): a run with stall_after 2m
// waiting 3m on `tego approve` must not be killed under the operator. The
// stall clock restarts when the wait ends, so a hung agent is still caught
// stall_after later.
func TestPendingApprovalHoldsTheStallClock(t *testing.T) {
	r, cgroups, _, clk := budgetRunner(t, agent.ResolvedLimits{StallAfter: 2 * time.Minute})
	asked := make(chan struct{}, 1)
	b, err := ask.New(t.TempDir(), ask.Options{UID: uint32(os.Getuid()), Timeout: time.Hour, Authorize: func(ask.Peer) error { return nil }, Emit: func(e ask.Event) error {
		if e.Kind == "ask" {
			asked <- struct{}{}
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r.askBroker = b
	ctx, cancel := context.WithCancel(t.Context())
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		_, _ = b.Request(ctx, ask.Request{Op: "connect", Target: "192.0.2.1:443", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()})
	}()
	<-asked
	for deadline := time.Now().Add(5 * time.Second); !b.Waiting(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) { // published once its ask line is accepted
			t.Fatal("ask never published")
		}
	}
	clk.advance(3 * time.Minute)
	if br, err := r.budget.Tick(t.Context()); br != nil || err != nil || cgroups.killed != 0 {
		t.Fatalf("a run waiting on a human was stopped: breach %+v err %v killed %d", br, err, cgroups.killed)
	}
	cancel()
	<-answered
	clk.advance(time.Minute)
	if br, _ := r.budget.Tick(t.Context()); br != nil {
		t.Fatalf("stall clock did not restart at the end of the wait: %+v", br)
	}
	clk.advance(2 * time.Minute)
	if br, _ := r.budget.Tick(t.Context()); br == nil || br.Which != record.LimitStallAfter {
		t.Fatalf("an idle run after its answer was not stalled: %+v", br)
	}
}

// A net.ask unix: entry is held at the connect (supervisor R11c): the launcher starts a table that holds one there,
// and refuses one whose ask.hold is first_write, which holds TCP bytes, rather than leave its asks to refuse.
func TestAskUnixScopeIsHeldAtTheConnectOnly(t *testing.T) {
	table := func(hold agent.AskHold) *agent.RuleTable {
		return &agent.RuleTable{
			Contract:  &agent.Contract{Name: "ask-unix", Net: &agent.NetSection{Ask: []string{"unix:/run/app.sock"}}},
			Record:    agent.RecordSummary,
			AskConfig: &agent.AskConfig{Hold: hold, Timeout: agent.Duration(time.Minute), MaxPending: 4},
			NetAsk:    []agent.NetRule{{Raw: "unix:/run/app.sock", Proto: agent.ProtoUnix, UnixPath: "/run/app.sock", Verdict: agent.VerdictAsk, Static: true}},
		}
	}
	deps := Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}}
	if err := validateAskRequest(table(agent.AskHoldConnect), deps); err != nil {
		t.Fatalf("connect hold: %v", err)
	}
	if err := validateAskRequest(table(agent.AskHoldFirstWrite), deps); !errors.Is(err, ask.ErrUnavailable) {
		t.Fatalf("first_write hold: %v; want the run refused", err)
	}
}

// A net.ask udp:// or bare host:port entry is held at the datagram or the UDP connect (supervisor R13d): the launcher
// starts a table that holds one under ask.hold: connect and refuses one under first_write, which holds TCP bytes, as it
// refuses a unix: entry there; a tcp:// entry under first_write still starts. An entry without a port starts nothing.
func TestAskUDPScopeIsHeldAtTheSyscallOnly(t *testing.T) {
	table := func(hold agent.AskHold, proto string, port int) *agent.RuleTable {
		raw := "192.0.2.1:53"
		return &agent.RuleTable{
			Contract:  &agent.Contract{Name: "ask-udp", Net: &agent.NetSection{Ask: []string{raw}}},
			Record:    agent.RecordSummary,
			AskConfig: &agent.AskConfig{Hold: hold, Timeout: agent.Duration(time.Minute), MaxPending: 4},
			NetAsk:    []agent.NetRule{{Raw: raw, Proto: proto, Port: port, Host: "192.0.2.1", Verdict: agent.VerdictAsk, Static: true}},
		}
	}
	deps := Deps{Enforce: tierBackend{backend.TierLandlock, backend.Matrix(backend.TierLandlock)}}
	for _, proto := range []string{agent.ProtoUDP, agent.ProtoInet} {
		if err := validateAskRequest(table(agent.AskHoldConnect, proto, 53), deps); err != nil {
			t.Fatalf("%s under the connect hold: %v", proto, err)
		}
		if err := validateAskRequest(table(agent.AskHoldFirstWrite, proto, 53), deps); !errors.Is(err, ask.ErrUnavailable) {
			t.Fatalf("%s under first_write: %v; want the run refused", proto, err)
		}
		if err := validateAskRequest(table(agent.AskHoldConnect, proto, 0), deps); !errors.Is(err, ask.ErrUnavailable) {
			t.Fatalf("%s without a port: %v; want the run refused", proto, err)
		}
	}
	if err := validateAskRequest(table(agent.AskHoldFirstWrite, agent.ProtoTCP, 53), deps); err != nil {
		t.Fatalf("tcp under first_write: %v", err)
	}
}
