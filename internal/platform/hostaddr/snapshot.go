// SPDX-License-Identifier: Apache-2.0

// Package hostaddr snapshots the addresses assigned in the caller's network namespace.
package hostaddr

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Snapshot caches interface addresses. Each consumer owns its own instance.
// A failed refresh retains the last successful snapshot; a failed first lookup
// reports unknown so the caller can fail closed.
type Snapshot struct {
	list   func() ([]net.Addr, error)
	now    func() time.Time
	maxAge time.Duration
	mu     sync.Mutex
	at     time.Time
	ok     bool
	set    map[netip.Addr]bool
	bcast  map[netip.Addr]bool
}

// New creates a snapshot with injectable enumeration and clock functions.
func New(list func() ([]net.Addr, error), now func() time.Time, maxAge time.Duration) *Snapshot {
	return &Snapshot{list: list, now: now, maxAge: maxAge}
}

// Has reports whether a belongs to this host and whether any snapshot succeeded.
func (h *Snapshot) Has(a netip.Addr) (local, known bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refresh()
	if !h.ok {
		return false, false
	}
	return h.set[a.Unmap().WithZone("")], true
}

// HasBroadcast reports whether a is the broadcast address of a subnet of this host, and whether any snapshot succeeded.
func (h *Snapshot) HasBroadcast(a netip.Addr) (bcast, known bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refresh()
	if !h.ok {
		return false, false
	}
	return h.bcast[a.Unmap().WithZone("")], true
}

// refresh takes the snapshot again when it is older than maxAge. The caller holds h.mu.
func (h *Snapshot) refresh() {
	if now := h.now(); h.at.IsZero() || now.Sub(h.at) >= h.maxAge {
		h.at = now
		if addrs, err := h.list(); err == nil {
			h.set, h.bcast, h.ok = addressSet(addrs), broadcastSet(addrs), true
		}
	}
}

// View is one immutable interface-address enumeration. It is independent of the cached snapshot's age.
type View struct {
	set   map[netip.Addr]bool
	known bool
}

// Fresh enumerates addresses for a security decision that cannot tolerate the cache window. An error
// returns unknown even if an earlier enumeration succeeded: a new interface may have appeared meanwhile.
func (h *Snapshot) Fresh() View {
	h.mu.Lock()
	defer h.mu.Unlock()
	addrs, err := h.list()
	if err != nil {
		return View{}
	}
	return View{set: addressSet(addrs), known: true}
}

func addressSet(addrs []net.Addr) map[netip.Addr]bool {
	set := make(map[netip.Addr]bool, len(addrs))
	for _, na := range addrs {
		if ipn, ok := na.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				set[ip.Unmap().WithZone("")] = true
			}
		}
	}
	return set
}

// broadcastSet is the broadcast address of each IPv4 subnet in addrs, the mask's host bits all set, where fib_add_ifaddr
// adds one: a /31 and a /32 have none (RFC 3021). The enumeration gives no IFA_BROADCAST, so a broadcast address set by
// hand to anything else is not read.
func broadcastSet(addrs []net.Addr) map[netip.Addr]bool {
	set := make(map[netip.Addr]bool)
	for _, na := range addrs {
		ipn, ok := na.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipn.IP.To4()
		ones, bits := ipn.Mask.Size()
		if ip4 == nil || bits != 8*net.IPv4len || ones >= 31 {
			continue
		}
		var b [net.IPv4len]byte
		for i := range b {
			b[i] = ip4[i] | ^ipn.Mask[i]
		}
		set[netip.AddrFrom4(b)] = true
	}
	return set
}

// Has reports membership in this enumeration and whether enumeration succeeded.
func (v View) Has(a netip.Addr) (local, known bool) {
	return v.set[a.Unmap().WithZone("")], v.known
}
