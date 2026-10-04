// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func nk(port uint16, last byte) bpf.NetKey {
	k := bpf.NetKey{RunIdx: 1, Family: 2, Proto: 6, Port: port}
	k.Addr[0] = last
	return k
}

func lk(prefix uint32, first byte) bpf.NetLPMKey {
	k := bpf.NetLPMKey{PrefixLen: prefix, RunIdx: 1, Family: 2, Proto: 6}
	k.Addr[0] = first
	return k
}

// A TTL refresh writes the new rows, then deletes the old rows the new set lacks: deleting one it still
// needs would open a window in which an allowed destination is refused (or, for a deny row, admitted).
func TestStaleRowsAreOnlyWhatTheNewSetLacks(t *testing.T) {
	old := RuleMaps{
		Exact: []NetRow{{Key: nk(443, 1)}, {Key: nk(443, 2)}, {Key: nk(80, 1)}},
		CIDR:  []CIDRRow{{Key: lk(24, 10)}, {Key: lk(16, 172)}},
	}
	next := RuleMaps{
		Exact: []NetRow{{Key: nk(443, 2)}, {Key: nk(443, 3)}},
		CIDR:  []CIDRRow{{Key: lk(16, 172)}},
	}
	stale := staleRows(old, next)
	if len(stale.Exact) != 2 || stale.Exact[0].Key != nk(443, 1) || stale.Exact[1].Key != nk(80, 1) {
		t.Errorf("stale exact rows = %+v", stale.Exact)
	}
	if len(stale.CIDR) != 1 || stale.CIDR[0].Key != lk(24, 10) {
		t.Errorf("stale cidr rows = %+v", stale.CIDR)
	}
	if s := staleRows(next, next); len(s.Exact)+len(s.CIDR) != 0 {
		t.Errorf("an unchanged set has nothing stale: %+v", s)
	}

	u := unionRows(old, next)
	for _, k := range []bpf.NetKey{nk(443, 1), nk(443, 2), nk(443, 3), nk(80, 1)} {
		if !slices.ContainsFunc(u.Exact, func(r NetRow) bool { return r.Key == k }) {
			t.Errorf("union lacks exact row %+v", k)
		}
	}
	if len(u.Exact) != 4 || len(u.CIDR) != 2 {
		t.Errorf("union sizes: %d exact, %d cidr; want 4 and 2 (no row twice)", len(u.Exact), len(u.CIDR))
	}
	if len(next.Exact) != 2 {
		t.Error("unionRows must not write into next's backing array")
	}
}

func TestSameEntryIgnoresOnlyWhatARefreshChanges(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	other := netip.MustParsePrefix("10.0.0.0/16")
	base := agent.NetRule{Raw: "api.x:443", Host: "api.x", Port: 443, Proto: "tcp"}
	if !sameEntry(base, base) {
		t.Fatal("an entry is its own")
	}
	changed := []struct {
		name string
		mut  func(*agent.NetRule)
	}{
		{"host", func(r *agent.NetRule) { r.Host = "evil.x" }},
		{"port", func(r *agent.NetRule) { r.Port = 80 }},
		{"proto", func(r *agent.NetRule) { r.Proto = "udp" }},
		{"raw", func(r *agent.NetRule) { r.Raw = "api.x" }},
		{"unix path", func(r *agent.NetRule) { r.UnixPath = "/s" }},
		{"static", func(r *agent.NetRule) { r.Static = !r.Static }},
		{"runtime", func(r *agent.NetRule) { r.Runtime = "capture" }},
		{"cidr appears", func(r *agent.NetRule) { c := cidr; r.CIDR = &c }},
	}
	for _, c := range changed {
		b := base
		c.mut(&b)
		if sameEntry(base, b) || sameEntry(b, base) {
			t.Errorf("a change of %s must be a different entry", c.name)
		}
	}
	a, b := base, base
	ca, cb := cidr, other
	a.CIDR, b.CIDR = &ca, &cb
	if sameEntry(a, b) {
		t.Error("two different prefixes are different entries")
	}
	cc := cidr
	b.CIDR = &cc
	if !sameEntry(a, b) {
		t.Error("equal prefixes behind different pointers are the same entry")
	}
}

func TestSameAddrsComparesDestinationsNotSpellings(t *testing.T) {
	a := netip.MustParseAddr
	cases := []struct {
		name string
		x, y []netip.Addr
		want bool
	}{
		{"order does not matter", []netip.Addr{a("1.1.1.1"), a("2.2.2.2")}, []netip.Addr{a("2.2.2.2"), a("1.1.1.1")}, true},
		{"v4 and its mapped form are one destination", []netip.Addr{a("1.1.1.1")}, []netip.Addr{a("::ffff:1.1.1.1")}, true},
		{"zone is not part of it", []netip.Addr{a("fe80::1%eth0")}, []netip.Addr{a("fe80::1")}, true},
		{"duplicates collapse", []netip.Addr{a("1.1.1.1"), a("1.1.1.1")}, []netip.Addr{a("1.1.1.1")}, true},
		{"different member", []netip.Addr{a("1.1.1.1")}, []netip.Addr{a("1.1.1.2")}, false},
		{"subset", []netip.Addr{a("1.1.1.1")}, []netip.Addr{a("1.1.1.1"), a("2.2.2.2")}, false},
		{"both empty", nil, nil, true},
	}
	for _, c := range cases {
		if got := sameAddrs(c.x, c.y); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTierByteNumbersTheRunSetRows(t *testing.T) {
	want := map[backend.Tier]int{
		backend.TierLandlock: 1, backend.TierCgroup: 2, backend.TierBPFLSM: 3,
		backend.TierObserve: 0, backend.TierAuto: 0, backend.Tier("nonsense"): 0,
	}
	for tier, n := range want {
		if got := tierByte(tier); got != n {
			t.Errorf("tierByte(%q) = %d, want %d", tier, got, n)
		}
	}
}

func TestReadSubtreeListsDirectoriesOnlyAndToleratesVanishing(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a/b/c", "a/d", "e"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "a", "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readSubtree(root)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{"a", "a/b", "a/b/c", "a/d", "e"}
	if !slices.Equal(got, want) {
		t.Errorf("readSubtree = %v, want %v", got, want)
	}
	if got, err := readSubtree(filepath.Join(root, "gone")); err != nil || len(got) != 0 {
		t.Errorf("a vanished root: %v, %v; want empty and no error", got, err)
	}
	if err := os.Chmod(filepath.Join(root, "a"), 0); err == nil && os.Geteuid() != 0 {
		if _, err := readSubtree(root); err == nil {
			t.Error("an unreadable directory must refuse, not be skipped: a missed descendant loses its tracing")
		}
		_ = os.Chmod(filepath.Join(root, "a"), 0o755)
	}
}
