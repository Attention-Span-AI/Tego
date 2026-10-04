// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"net/netip"
	"testing"
)

// A key built for a slot the maps do not have would write another run's rows: every constructor refuses
// an out-of-range run_idx or an address it cannot key, and never returns a half-built key with it.
func TestKeyConstructorsRefuseWhatTheMapsCannotHold(t *testing.T) {
	v4 := netip.MustParseAddr("10.1.2.3")
	pfx := netip.MustParsePrefix("10.0.0.0/8")

	if _, err := NetKeys(MaxSlots, 6, v4, 443); !errors.Is(err, ErrSlot) {
		t.Errorf("NetKeys slot: %v", err)
	}
	if _, err := NetKeys(0, 6, netip.Addr{}, 443); !errors.Is(err, ErrFamily) {
		t.Errorf("NetKeys invalid address: %v", err)
	}
	if _, err := NetLPMKeys(MaxSlots, 6, pfx, 0); !errors.Is(err, ErrSlot) {
		t.Errorf("NetLPMKeys slot: %v", err)
	}
	if _, err := NetLPMKeys(0, 6, netip.Prefix{}, 0); !errors.Is(err, ErrPrefix) {
		t.Errorf("NetLPMKeys invalid prefix: %v", err)
	}
	if _, err := LookupLPMKey(MaxSlots, 6, v4, 443); !errors.Is(err, ErrSlot) {
		t.Errorf("LookupLPMKey slot: %v", err)
	}
	if _, err := LookupLPMKey(0, 6, netip.Addr{}, 443); !errors.Is(err, ErrFamily) {
		t.Errorf("LookupLPMKey invalid address: %v", err)
	}
	if _, err := AddrFrom(9, [16]byte{}); !errors.Is(err, ErrFamily) {
		t.Errorf("AddrFrom unknown family: %v", err)
	}
}

// The lookup key is full width, so the trie answers with the longest stored prefix that covers it: a stored
// /8 covers the lookup of an address inside it and not one outside, a /32 covers exactly its own address.
func TestLookupKeyIsCoveredByStoredPrefixesOfEveryLength(t *testing.T) {
	lookup, err := LookupLPMKey(3, 6, netip.MustParseAddr("10.1.2.3"), 443)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.PrefixLen != LPMMaxBits {
		t.Fatalf("lookup width = %d, want %d", lookup.PrefixLen, LPMMaxBits)
	}
	cases := []struct {
		prefix string
		port   uint16
		want   bool
	}{
		{"10.0.0.0/8", 443, true},
		{"10.1.0.0/16", 443, true},
		{"10.1.2.3/32", 443, true},
		{"10.1.2.4/32", 443, false},
		{"11.0.0.0/8", 443, false},
		{"10.0.0.0/8", 80, false},
		{"0.0.0.0/0", 443, true},
		{"10.0.0.0/9", 443, true},
		{"10.128.0.0/9", 443, false},
	}
	for _, c := range cases {
		k, err := NewNetLPMKey(3, 6, netip.MustParsePrefix(c.prefix), c.port)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.Matches(lookup); got != c.want {
			t.Errorf("stored %s port %d covers the lookup: %v, want %v", c.prefix, c.port, got, c.want)
		}
	}
	other, _ := NewNetLPMKey(4, 6, netip.MustParsePrefix("10.0.0.0/8"), 443)
	if other.Matches(lookup) {
		t.Error("another run's slot must never cover this run's lookup")
	}
}

func TestAcceptsKindPairsEachRecordWithItsKinds(t *testing.T) {
	if !acceptsKind(&ExecEvent{}, KindExec) || acceptsKind(&ExecEvent{}, KindExit) {
		t.Error("exec")
	}
	if !acceptsKind(&NetEvent{}, KindConnect) || !acceptsKind(&NetEvent{}, KindBind) || acceptsKind(&NetEvent{}, KindOpen) {
		t.Error("net")
	}
	if !acceptsKind(&CgroupEvent{}, KindCgroupRmdir) || acceptsKind(&CgroupEvent{}, KindConnect) {
		t.Error("cgroup")
	}
	if !acceptsKind(&PlaneEvent{}, KindPlaneExec) || !acceptsKind(&PlaneEvent{}, KindPlaneFS) || acceptsKind(&PlaneEvent{}, KindExec) {
		t.Error("plane")
	}
	if acceptsKind("not a record", KindExec) || acceptsKind(nil, KindExec) {
		t.Error("an unknown record type accepts nothing")
	}
}
