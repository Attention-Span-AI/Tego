// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The tests in this file hold the kernel's rows to what the supervisor admits on its own authority. The
// supervisor relays every connect it allows on the agent's socket, so the run's connect4/6 decides each one
// again (§5 R1, R5), and anything the supervisor admits that the rows lack is refused with EPERM in the kernel
// while the ledger records it allowed.

// exactRow reports whether the fake kernel holds a row for a destination under a run's slot.
func exactRow(t *testing.T, k *fakeKernel, slot uint32, proto uint8, addr string, port uint16) (ebpfbindings.NetVerdict, bool) {
	t.Helper()
	key, err := ebpfbindings.NewNetKey(slot, proto, netip.MustParseAddr(addr), port)
	if err != nil {
		t.Fatalf("NewNetKey: %v", err)
	}
	v, ok := k.net.exact[key]
	return v, ok
}

// TestPrepareWritesTheRunsResolverRows is supervisor R14 reaching the kernel through Prepare: the run's
// resolver endpoints become port-53 rows under its slot, named net.resolver, and go when the run does.
func TestPrepareWritesTheRunsResolverRows(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.run.Resolvers = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for _, proto := range []uint8{ebpfbindings.ProtoUDP, ebpfbindings.ProtoTCP} {
		v, ok := exactRow(t, f.kernel, h.Slot(), proto, "127.0.0.53", 53)
		if !ok || v.Verdict != uint8(ebpfbindings.VerdictAllow) || h.Rules().RuleName(v.RuleIdx) != agent.ResolverRule {
			t.Fatalf("protocol %d to the resolver: row %+v (present %v), want allow named %s", proto, v, ok,
				agent.ResolverRule)
		}
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := f.kernel.net.rowsFor(h.Slot()); n != 0 {
		t.Fatalf("%d rows left under the slot after Close", n)
	}
}

// TestAttachUnrestrictedAttachesUnixBuiltinPrograms holds ADR 0113: a no-net
// run retains unrestricted IP while its immutable Unix destination rows attach.
func TestAttachUnrestrictedAttachesUnixBuiltinPrograms(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	open := *f.table
	open.Contract = &agent.Contract{}
	h, err := f.backend.Prepare(context.Background(), &open, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if h.Rules().Unrestricted || !h.Rules().UnixOnly {
		t.Fatal("no-net contract must keep IP open and attach built-in Unix policy")
	}
	if n := f.kernel.net.rowsFor(h.Slot()); n == 0 {
		t.Fatalf("%d verdict rows: missing built-in refusals", n)
	}
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	attached := false
	for _, c := range f.kernel.calls {
		if c == "attachCgroup" {
			attached = true
		}
	}
	if !attached {
		t.Fatal("built-in Unix programs were not attached")
	}
	if err := h.Attach(f.run.CgroupID + 1); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("Attach with another cgroup's id = %v, want ErrNotPrepared", err)
	}

	// The restricted table on the same fixture does attach, so the branch above is the contract's doing.
	g := newFixture(t)
	hr, err := g.backend.Prepare(context.Background(), g.table, g.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer hr.Close()
	if err := hr.Attach(g.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if g.kernel.attached == "" {
		t.Fatal("a restricted run attached no network program")
	}
}

// hostTable is a restricted table with one host entry, the kind a TTL refresh re-resolves (supervisor R8).
func hostTable(f *fixture, ips ...string) *agent.RuleTable {
	rt := *f.table
	r := agent.NetRule{Raw: "api.example:443", Host: "api.example", Port: 443, Proto: agent.ProtoInet,
		Verdict: agent.VerdictAllow}
	for _, ip := range ips {
		r.IPs = append(r.IPs, netip.MustParseAddr(ip))
	}
	rt.Net = []agent.NetRule{r}
	return &rt
}

// TestRefreshNetFollowsARotatedHost is §6 E7 as amended. The supervisor re-resolves a host entry on its TTL
// and admits the new addresses (supervisor R8); rows left at Prepare's addresses would refuse every relayed
// connect to an address the host rotated to. A refresh moves the rows, never removes the row of an address
// both resolutions share, and leaves nothing behind at Close.
func TestRefreshNetFollowsARotatedHost(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), hostTable(f, "198.51.100.4", "198.51.100.5"), f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	f.kernel.calls = nil
	if err := h.RefreshNet(hostTable(f, "198.51.100.5", "198.51.100.6")); err != nil {
		t.Fatalf("RefreshNet: %v", err)
	}
	for addr, want := range map[string]bool{"198.51.100.4": false, "198.51.100.5": true, "198.51.100.6": true} {
		for _, proto := range []uint8{ebpfbindings.ProtoTCP, ebpfbindings.ProtoUDP} {
			if _, ok := exactRow(t, f.kernel, h.Slot(), proto, addr, 443); ok != want {
				t.Errorf("protocol %d, %s:443: row present %v, want %v", proto, addr, ok, want)
			}
		}
	}
	if got := strings.Join(f.kernel.calls, ","); got != "removeRules,populate" {
		t.Fatalf("calls %q, want the stale rows removed and then the fresh ones written", got)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := f.kernel.net.rowsFor(h.Slot()); n != 0 {
		t.Fatalf("%d rows left under the slot after Close", n)
	}
}

// TestRefreshNetKeepsAddressesALookupDidNotReplace mirrors supervisor R8a: a failed lookup keeps an entry's
// previous addresses, so a refresh that brings an entry no address must not take its rows away.
func TestRefreshNetKeepsAddressesALookupDidNotReplace(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), hostTable(f, "198.51.100.4"), f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if err := h.RefreshNet(hostTable(f)); err != nil {
		t.Fatalf("RefreshNet: %v", err)
	}
	if _, ok := exactRow(t, f.kernel, h.Slot(), ebpfbindings.ProtoTCP, "198.51.100.4", 443); !ok {
		t.Fatal("a refresh with no address for the entry removed its row; the supervisor keeps the stale set (R8a)")
	}
}

// TestRefreshNetRefusesAChangedPolicy: a refresh changes where a host resolves, never what the contract
// admits, or the kernel would enforce a table the supervisor never compiled.
func TestRefreshNetRefusesAChangedPolicy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), hostTable(f, "198.51.100.4"), f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	otherPort := hostTable(f, "198.51.100.4")
	otherPort.Net[0].Port = 8443
	extra := hostTable(f, "198.51.100.4")
	extra.Net = append(extra.Net, extra.Net[0])
	f.kernel.calls = nil
	for name, rt := range map[string]*agent.RuleTable{"another port": otherPort, "another entry": extra} {
		if err := h.RefreshNet(rt); !errors.Is(err, ErrRefreshShape) {
			t.Fatalf("%s: RefreshNet = %v, want ErrRefreshShape", name, err)
		}
	}
	if len(f.kernel.calls) != 0 {
		t.Fatalf("a refused refresh touched the kernel: %v", f.kernel.calls)
	}
}

// TestRefreshNetFailingPartWayLeavesNothingBehind: a refresh whose write fails has already deleted the stale
// rows and may have written some fresh ones. Teardown must still remove every row either set left under the
// slot, or the slot's next owner inherits them (§5 R12, §8 I5, I10).
func TestRefreshNetFailingPartWayLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), hostTable(f, "198.51.100.4"), f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	f.kernel.failAt = "populate"
	fresh := hostTable(f, "198.51.100.9")
	// What a populate that fails after its first rows leaves: some of the fresh rows are in the map.
	partial, err := BuildRuleMaps(fresh, h.Slot(), nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	f.kernel.net.exact[partial.Exact[0].Key] = partial.Exact[0].Val
	if err := h.RefreshNet(fresh); err == nil {
		t.Fatal("RefreshNet succeeded although its write failed")
	}
	f.kernel.failAt = ""
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := f.kernel.net.rowsFor(h.Slot()); n != 0 {
		t.Fatalf("%d rows left under slot %d after a failed refresh and Close", n, h.Slot())
	}
}

// TestRefreshNetAfterDetachWritesNothing: the run's DNS refresher can tick once more while the run ends. A
// refresh that lands after Detach removed the rows would put back rows no one removes.
func TestRefreshNetAfterDetachWritesNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	h, err := f.backend.Prepare(context.Background(), hostTable(f, "198.51.100.4"), f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = h.RefreshNet(hostTable(f, "198.51.100.9"))
	}()
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	wg.Wait()
	if err := h.RefreshNet(hostTable(f, "198.51.100.7")); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("RefreshNet after Detach = %v, want ErrNotPrepared", err)
	}
	if n := f.kernel.net.rowsFor(h.Slot()); n != 0 {
		t.Fatalf("%d rows under the slot after Detach and a racing refresh", n)
	}
}

// TestRefreshNetKeepsTheResolverRows: the resolver rows are part of the table every refresh rebuilds, so a
// refresh of a run prepared with resolvers must write them again rather than delete them as stale. Rebuilt
// without the run's resolvers, the first TTL refresh would take DNS away from the run for the rest of its
// life, while the supervisor went on admitting and recording every query (supervisor R14).
func TestRefreshNetKeepsTheResolverRows(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.run.Resolvers = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}
	h, err := f.backend.Prepare(context.Background(), hostTable(f, "198.51.100.4"), f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if err := h.RefreshNet(hostTable(f, "198.51.100.9")); err != nil {
		t.Fatalf("RefreshNet: %v", err)
	}
	for _, proto := range []uint8{ebpfbindings.ProtoUDP, ebpfbindings.ProtoTCP} {
		for _, addr := range []string{"127.0.0.53", "::ffff:127.0.0.53"} {
			v, ok := exactRow(t, f.kernel, h.Slot(), proto, addr, 53)
			if !ok || v.Verdict != uint8(ebpfbindings.VerdictAllow) || h.Rules().RuleName(v.RuleIdx) != agent.ResolverRule {
				t.Fatalf("protocol %d, %s:53 after a refresh: row %+v (present %v), want allow named %s",
					proto, addr, v, ok, agent.ResolverRule)
			}
		}
	}
	if _, ok := exactRow(t, f.kernel, h.Slot(), ebpfbindings.ProtoTCP, "198.51.100.9", 443); !ok {
		t.Fatal("the refresh did not move the host entry's rows")
	}
}

// TestRefreshNetRefusesMovingAnUnresolvedEntry: a literal address, and an entry with no host at all, are
// entries no lookup re-resolves (dns.Set never refreshes them), so their addresses are what the contract
// admits. A refresh that moves them is a policy change, not a refresh, and the kernel would enforce a table
// the supervisor never compiled.
func TestRefreshNetRefusesMovingAnUnresolvedEntry(t *testing.T) {
	t.Parallel()
	literal := func(f *fixture, ips ...string) *agent.RuleTable {
		rt := hostTable(f, ips...)
		rt.Net[0].Raw, rt.Net[0].Host, rt.Net[0].Static = "198.51.100.4:443", "198.51.100.4", true
		return rt
	}
	hostless := func(f *fixture, ips ...string) *agent.RuleTable {
		rt := hostTable(f, ips...)
		rt.Net[0].Host = ""
		return rt
	}
	for name, table := range map[string]func(*fixture, ...string) *agent.RuleTable{
		"a literal address": literal, "an entry with no host": hostless,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			h, err := f.backend.Prepare(context.Background(), table(f, "198.51.100.4"), f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			defer h.Close()
			f.kernel.calls = nil
			if err := h.RefreshNet(table(f, "203.0.113.9")); !errors.Is(err, ErrRefreshShape) {
				t.Fatalf("RefreshNet moving %s = %v, want ErrRefreshShape", name, err)
			}
			if len(f.kernel.calls) != 0 {
				t.Fatalf("a refused refresh touched the kernel: %v", f.kernel.calls)
			}
			if _, ok := exactRow(t, f.kernel, h.Slot(), ebpfbindings.ProtoTCP, "203.0.113.9", 443); ok {
				t.Fatal("the refused refresh left a row for the new address")
			}
			// What the supervisor's set hands back for such an entry is its own addresses, in any order and
			// either spelling of an IPv4 address, or none (R8a): both are refreshes and succeed.
			if err := h.RefreshNet(table(f, "::ffff:198.51.100.4")); err != nil {
				t.Fatalf("RefreshNet with the same address: %v", err)
			}
			if err := h.RefreshNet(table(f)); err != nil {
				t.Fatalf("RefreshNet with no address: %v", err)
			}
			if _, ok := exactRow(t, f.kernel, h.Slot(), ebpfbindings.ProtoTCP, "198.51.100.4", 443); !ok {
				t.Fatal("the entry's own row is gone")
			}
		})
	}
}
