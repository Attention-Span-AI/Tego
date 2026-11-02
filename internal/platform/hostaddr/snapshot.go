// SPDX-License-Identifier: Apache-2.0

// Package hostaddr snapshots the addresses assigned in the caller's network namespace and, for a snapshot that reads
// them, what the kernel's routing tables send to this host besides them (LocalTable: the `local`, `broadcast` and
// `anycast` routes of tables local, main and default, which the kernel's default policy rules look up).
package hostaddr

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Snapshot caches this host's addresses: the interfaces' and, made by NewWithLocalTable, the routing tables'
// (LocalTable). Each consumer owns its own instance. A failed refresh retains the last successful snapshot of each, so
// once the tables were read the last reading stays in force while they cannot be read again; a failed first lookup of
// the addresses reports unknown so the caller can fail closed, and while the tables were never read the answers are
// the addresses'.
type Snapshot struct {
	list   func() ([]net.Addr, error)
	table  func() (LocalTable, error)
	now    func() time.Time
	maxAge time.Duration
	mu     sync.Mutex
	at     time.Time
	ok     bool
	set    map[netip.Addr]bool
	bcast  map[netip.Addr]bool
	routes routeIndex
}

// New creates a snapshot with injectable enumeration and clock functions.
func New(list func() ([]net.Addr, error), now func() time.Time, maxAge time.Duration) *Snapshot {
	return &Snapshot{list: list, now: now, maxAge: maxAge}
}

// NewWithLocalTable is New that also reads what the kernel's routing tables send here through table (ReadLocalTable)
// each time it takes the addresses, for Has, HasBroadcast and HasAnycast, and with them in Fresh. A nil table reads
// none, as New.
func NewWithLocalTable(list func() ([]net.Addr, error), table func() (LocalTable, error), now func() time.Time, maxAge time.Duration) *Snapshot {
	return &Snapshot{list: list, table: table, now: now, maxAge: maxAge}
}

// Has reports whether this host takes a as its own, and whether any snapshot succeeded: a is assigned to one of its
// interfaces or, for a snapshot that reads the local table, lies in a `local` route there, which the kernel delivers
// here as it does an address of its own (127.0.0.0/8 on loopback, an AnyIP range). A server bound to all interfaces
// answers on each.
func (h *Snapshot) Has(a netip.Addr) (local, known bool) {
	return h.answer(a, func(a netip.Addr) bool { return h.set[a] || h.routes.local.contains(a) })
}

// HasBroadcast reports whether a is a broadcast address of this host, and whether any snapshot succeeded: an IPv4
// subnet's, from its mask, or one a `broadcast` route of the local table names, which is how one set by hand is read.
func (h *Snapshot) HasBroadcast(a netip.Addr) (bcast, known bool) {
	return h.answer(a, func(a netip.Addr) bool { return h.bcast[a] || h.routes.broadcast.contains(a) })
}

// HasAnycast reports whether a is an IPv6 anycast address this host joined, an `anycast` route of the local table, and
// whether any snapshot succeeded.
func (h *Snapshot) HasAnycast(a netip.Addr) (anycast, known bool) {
	return h.answer(a, func(a netip.Addr) bool { return h.routes.anycast.contains(a) })
}

// answer is in's answer for a, read unmapped and with no zone, from a snapshot taken again when it is due, and known
// false while no snapshot of the addresses ever succeeded. in runs under h.mu.
func (h *Snapshot) answer(a netip.Addr, in func(netip.Addr) bool) (yes, known bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refresh()
	if !h.ok {
		return false, false
	}
	return in(a.Unmap().WithZone("")), true
}

// refresh takes the snapshot again when it is older than maxAge. The caller holds h.mu.
func (h *Snapshot) refresh() {
	if now := h.now(); h.at.IsZero() || now.Sub(h.at) >= h.maxAge {
		h.at = now
		if addrs, err := h.list(); err == nil {
			h.set, h.bcast, h.ok = addressSet(addrs), broadcastSet(addrs), true
		}
		if h.table != nil {
			if t, err := h.table(); err == nil {
				h.routes = indexLocalTable(t)
			}
		}
	}
}

// View is one immutable enumeration of this host's own addresses, Has's reading taken at once: the interfaces'
// addresses and, from a snapshot that reads it, every address of a `local` route of the local table. It is independent
// of the cached snapshot's age.
type View struct {
	set   map[netip.Addr]bool
	local prefixSet
	known bool
}

// Fresh enumerates this host's own addresses for a security decision that cannot tolerate the cache window: the
// interfaces' addresses and, for a snapshot made by NewWithLocalTable, the local table, both read now, so an AnyIP
// range is the host's own here as it is to Has. An error in either returns unknown even if an earlier enumeration
// succeeded: a new interface or route may have appeared meanwhile.
func (h *Snapshot) Fresh() View {
	h.mu.Lock()
	defer h.mu.Unlock()
	addrs, err := h.list()
	if err != nil {
		return View{}
	}
	v := View{set: addressSet(addrs), known: true}
	if h.table != nil {
		t, err := h.table()
		if err != nil {
			return View{}
		}
		v.local = newPrefixSet(t.Local)
	}
	return v
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
// hand to anything else is read from the local table's `broadcast` route alone (HasBroadcast), and only by a snapshot
// that reads the table.
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

// Has reports whether a is one of this host's own addresses in this enumeration, read unmapped and with no zone: an
// interface's, or one in a `local` route of the table read with it. known says whether the enumeration succeeded.
func (v View) Has(a netip.Addr) (local, known bool) {
	a = a.Unmap().WithZone("")
	return v.set[a] || v.local.contains(a), v.known
}
