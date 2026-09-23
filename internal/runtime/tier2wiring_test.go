// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The tests in this file are the runtime's half of what tier 2's kernel rows need from it: the run's resolver
// list, the child stage's binary and the addresses a TTL refresh moves (docs/p0/enforce-cgroup-observe.md §5
// R5, R8, §6 E7). The resolver rows and RefreshNet were built and tested on the tier's side and never handed
// over, so a tier-2 run refused, with EPERM, every DNS query and every connect to a rotated address that the
// supervisor admitted and the ledger recorded allowed. The stage binary is what the tier's detached helpers
// exec.

// refreshingHandle is a tier-2-shaped handle that records the tables RefreshNet is handed.
type refreshingHandle struct {
	mu     sync.Mutex
	tables []*agent.RuleTable
	// failed holds, per entry of tables, whether that call was answered fail.
	failed []bool
	fail   error
	called chan struct{}
}

func (*refreshingHandle) LandlockRuleset() (int, bool)                { return -1, false }
func (*refreshingHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (*refreshingHandle) Attach(uint64) error                         { return nil }
func (*refreshingHandle) Detach() error                               { return nil }
func (*refreshingHandle) Close() error                                { return nil }

func (h *refreshingHandle) RefreshNet(rt *agent.RuleTable) error {
	h.mu.Lock()
	h.tables = append(h.tables, rt)
	err := h.fail
	h.failed = append(h.failed, err != nil)
	h.mu.Unlock()
	select {
	case h.called <- struct{}{}:
	default:
	}
	return err
}

func (h *refreshingHandle) got() []*agent.RuleTable {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.tables)
}

// answers is, per call so far, whether RefreshNet answered it fail.
func (h *refreshingHandle) answers() []bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.failed)
}

var _ enforce.NetRefresher = (*refreshingHandle)(nil)

// rotatingLookup answers each host with the next of its scripted answers, the last one repeating.
type rotatingLookup struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   int
}

func (l *rotatingLookup) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	out := l.answers[0]
	if len(l.answers) > 1 {
		l.answers = l.answers[1:]
	}
	return out, nil
}

// count is how many lookups the set has made so far.
func (l *rotatingLookup) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// TestPrepareAndSupervisorShareOneResolverList: the tier is prepared with the resolver list the supervisor's
// set is later built from, read once. Without it tier 2 wrote no port-53 row, so every query the supervisor
// admitted under R14 and relayed on the agent's socket was refused in the kernel.
func TestPrepareAndSupervisorShareOneResolverList(t *testing.T) {
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53")}
	m := config.Builtin()
	m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{Servers: want}}
	b := &handoffBackend{tier: backend.TierCgroup, handle: tier2Handle{hash: "0123456789abcdef"}}
	r := handoffRunner(b, Build{})
	r.deps.Config = m
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.gotRun.Resolvers, want) {
		t.Fatalf("the tier was prepared with resolvers %v, want the machine's %v", b.gotRun.Resolvers, want)
	}
	// The supervisor's set is built from the same read: a config edited after Prepare changes neither.
	m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{
		Servers: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}}}
	if got := r.runResolvers(); !slices.Equal(got, want) {
		t.Fatalf("the supervisor would be given %v after Prepare was given %v", got, want)
	}
}

// startedNotifyLoop runs startNotifyLoop on r over a pipe standing in for the listener, as armedRunner does,
// and returns once the loop is armed. The group ends with the test.
func startedNotifyLoop(t *testing.T, r *runner) {
	t.Helper()
	g, gctx := newGroup(context.Background())
	r.group, r.queue, r.notifyFD = g, NewQueue(4), listenerPipe(t)
	if r.rt == nil {
		r.rt = &agent.RuleTable{Contract: &agent.Contract{Name: "a"}}
	}
	if r.id == "" {
		r.id, r.agentID = "r-00000000-000000000000a-aaaaaa", "a"
	}
	t.Cleanup(func() {
		g.Cancel()
		_ = g.Wait()
	})
	done := make(chan error, 1)
	go func() { done <- r.startNotifyLoop(gctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("startNotifyLoop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor loop never armed")
	}
}

// TestTheSupervisorGetsThePreparedResolverList: the supervisor's resolver set is built from the list the tier
// was prepared with, not from a second read. A machine config or resolv.conf that changed between two reads
// would give the kernel's port-53 rows and the supervisor's exception different servers.
func TestTheSupervisorGetsThePreparedResolverList(t *testing.T) {
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}
	m := config.Builtin()
	m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{Servers: want}}
	b := &handoffBackend{tier: backend.TierCgroup, handle: tier2Handle{hash: "0123456789abcdef"}}
	r := handoffRunner(b, Build{})
	r.deps.Config = m
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{
		Servers: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.53:53")}}}
	startedNotifyLoop(t, r)
	if got := r.dnsSet.ResolverAddrs(); !slices.Equal(got, b.gotRun.Resolvers) || !slices.Equal(got, want) {
		t.Fatalf("the supervisor was given %v, the tier %v; want both %v", got, b.gotRun.Resolvers, want)
	}
}

// TestTheRunsDNSWorkerMovesTheTiersRows: the worker startNotifyLoop starts is the one that hands a refresh to
// the tier. A worker that refreshed the supervisor's set alone left tier 2's rows at run start's addresses.
func TestTheRunsDNSWorkerMovesTheTiersRows(t *testing.T) {
	h := &refreshingHandle{called: make(chan struct{}, 1)}
	r := dnsRunner(h)
	r.log = slog.New(slog.DiscardHandler)
	r.dnsTick = time.Millisecond
	r.dnsOptions = dns.Options{MinTTL: time.Millisecond, Lookup: &rotatingLookup{answers: [][]netip.Addr{
		{netip.MustParseAddr("203.0.113.9")}}}}
	startedNotifyLoop(t, r)
	select {
	case <-h.called:
	case <-time.After(5 * time.Second):
		t.Fatal("the run's DNS worker never handed the tier a refresh that moved a host's addresses")
	}
	if got := h.got()[0].Net[0].IPs; !slices.Equal(got, []netip.Addr{netip.MustParseAddr("203.0.113.9")}) {
		t.Fatalf("the tier was handed %v", got)
	}
}

// TestPrepareNamesTheStageBinary: the tier is told which binary the child stage execs, the one its detached
// helpers exec too. "" is the launcher's own image.
func TestPrepareNamesTheStageBinary(t *testing.T) {
	b := &handoffBackend{tier: backend.TierCgroup, handle: tier2Handle{hash: "0123456789abcdef"}}
	r := handoffRunner(b, Build{})
	r.deps.Launcher = &launch.Launcher{Exe: "/opt/tego/bin/tego"}
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.gotRun.StageExe != "/opt/tego/bin/tego" {
		t.Fatalf("StageExe %q, want the launcher's Exe", b.gotRun.StageExe)
	}

	b = &handoffBackend{tier: backend.TierCgroup, handle: tier2Handle{hash: "0123456789abcdef"}}
	r = handoffRunner(b, Build{})
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.gotRun.StageExe != "" {
		t.Fatalf("StageExe %q with the default launcher, want \"\" (/proc/self/exe)", b.gotRun.StageExe)
	}
}

// dnsRunner is a runner at the point startNotifyLoop starts the DNS worker: a table with one host entry and one
// literal entry, and a handle.
func dnsRunner(h api.Handle) *runner {
	host := agent.NetRule{Raw: "api.example:443", Host: "api.example", Port: 443, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("198.51.100.4")}, TTL: time.Millisecond}
	literal := agent.NetRule{Raw: "192.0.2.1:22", Host: "192.0.2.1", Port: 22, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Static: true}
	return &runner{
		log:    slog.New(slog.DiscardHandler),
		rt:     &agent.RuleTable{Tier: backend.TierCgroup, Contract: &agent.Contract{Name: "a"}, Net: []agent.NetRule{host, literal}},
		handle: h,
	}
}

// TestDNSRefreshMovesTheTiersRows is §6 E7 wired: a refresh that moves a host entry's addresses reaches the
// tier as the run's table with the new addresses and nothing else changed, and a refresh that brings the same
// answer again reaches it not at all, before the move and after it. A worker that forgot a move it had handed
// over rewrote every row, and repeated any warning, on every tick for the rest of the run.
func TestDNSRefreshMovesTheTiersRows(t *testing.T) {
	h := &refreshingHandle{called: make(chan struct{}, 1)}
	r := dnsRunner(h)
	lk := &rotatingLookup{answers: [][]netip.Addr{
		{netip.MustParseAddr("198.51.100.4")}, // the compiled answer again: nothing to move
		{netip.MustParseAddr("203.0.113.9")},  // then the move, repeated by every later lookup
	}}
	set := dns.NewSet(r.rt.Net, nil, dns.Options{Lookup: lk, MinTTL: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.refreshDNS(ctx, set, time.Millisecond) }()
	select {
	case <-h.called:
	case <-time.After(5 * time.Second):
		t.Fatal("a refresh that moved a host's addresses never reached the tier")
	}
	// Ticks after the move whose lookups bring the moved answer again: each re-resolves the host and finds
	// nothing new, so none of them may reach the tier.
	for moved, deadline := lk.count(), time.Now().Add(5*time.Second); lk.count() < moved+5; {
		if time.Now().After(deadline) {
			t.Fatalf("%d lookups after the move, want 5 more ticks to have re-resolved the host", lk.count()-moved)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("refreshDNS: %v", err)
	}
	tables := h.got()
	if len(tables) != 1 {
		t.Fatalf("%d RefreshNet calls, want 1: only a change is handed over", len(tables))
	}
	got := tables[0]
	if want := []netip.Addr{netip.MustParseAddr("203.0.113.9")}; !slices.Equal(got.Net[0].IPs, want) {
		t.Errorf("host entry %v, want the refreshed %v", got.Net[0].IPs, want)
	}
	if !slices.Equal(got.Net[1].IPs, r.rt.Net[1].IPs) || got.Net[1].Raw != r.rt.Net[1].Raw {
		t.Errorf("the literal entry changed: %+v", got.Net[1])
	}
	if got.Contract != r.rt.Contract || got.Tier != r.rt.Tier || len(got.Net) != len(r.rt.Net) {
		t.Errorf("RefreshNet was handed another table: %+v", got)
	}
	if !slices.Equal(r.rt.Net[0].IPs, []netip.Addr{netip.MustParseAddr("198.51.100.4")}) {
		t.Errorf("the run's own table was modified: %v", r.rt.Net[0].IPs)
	}
}

// TestDNSRefreshRetriesAFailedMove: a refresh the tier could not apply is handed over again on the next tick,
// so a transient bpf(2) failure does not leave the rows at the old addresses for the rest of the run.
func TestDNSRefreshRetriesAFailedMove(t *testing.T) {
	h := &refreshingHandle{called: make(chan struct{}, 1), fail: errors.New("bpf: ENOMEM")}
	r := dnsRunner(h)
	lk := &rotatingLookup{answers: [][]netip.Addr{{netip.MustParseAddr("203.0.113.9")}}}
	set := dns.NewSet(r.rt.Net, nil, dns.Options{Lookup: lk, MinTTL: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.refreshDNS(ctx, set, time.Millisecond) }()
	for deadline := time.Now().Add(5 * time.Second); len(h.got()) < 2; {
		if time.Now().After(deadline) {
			t.Fatalf("%d RefreshNet calls after a failure, want a retry", len(h.got()))
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("refreshDNS: %v", err)
	}
}

// TestDNSRefreshWithoutKernelRows: a tier whose handle holds no addresses (tier 1) still gets the supervisor's
// set refreshed, and the worker ends cleanly with the run.
func TestDNSRefreshWithoutKernelRows(t *testing.T) {
	r := dnsRunner(nil)
	lk := &rotatingLookup{answers: [][]netip.Addr{{netip.MustParseAddr("203.0.113.9")}}}
	set := dns.NewSet(r.rt.Net, nil, dns.Options{Lookup: lk, MinTTL: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.refreshDNS(ctx, set, time.Millisecond) }()
	for deadline := time.Now().Add(5 * time.Second); set.Match(netip.MustParseAddrPort("203.0.113.9:443"), dns.ProtoTCP) == nil; {
		if time.Now().After(deadline) {
			t.Fatal("the supervisor's set never followed the refresh")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("refreshDNS: %v", err)
	}
}
