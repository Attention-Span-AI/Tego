// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// hostAddrsMaxAge is how old a hostAddrs snapshot may be before the next check that needs it takes it again: the
// age the supervisor's own snapshot may reach (internal/runtime/supervisor, resolved.go), so the run's filter reads
// an address DHCP, a VPN or a container bridge adds as fresh as the supervisor does.
const hostAddrsMaxAge = time.Second

// hostAddrs is a snapshot of this host's own addresses, for refreshDenied, the check the table a tier is prepared
// with (rowsTable) and the run's DNS set's refreshes are filtered by: those assigned to its interfaces, taken through
// list (net.InterfaceAddrs: an RTM_GETADDR dump over netlink, which needs no privilege and no cgo), and every address
// of a `local` route in the kernel's local routing table, an AnyIP range's, read through table
// (hostaddr.ReadLocalTable: an RTM_GETROUTE dump, unprivileged as well). Both are taken again when the snapshot is
// older than maxAge, on the next check that needs it. The supervisor keeps a snapshot of its own from the same dumps
// for its connect and send decisions; this one is the run's, so the rows follow the same addresses without reading
// the supervisor's, and refuse every one the supervisor's resolved-address check refuses (supervisor R13b). Both run
// in the host's network namespace, which the agent shares in tiers 1 and 2, so these are the addresses a connect
// from the run reaches this host on.
type hostAddrs struct{ *hostaddr.Snapshot }

// newHostAddrs is a snapshot over list and table; a nil table reads the interfaces' addresses alone.
func newHostAddrs(list func() ([]net.Addr, error), table func() (hostaddr.LocalTable, error), now func() time.Time, maxAge time.Duration) *hostAddrs {
	return &hostAddrs{hostaddr.NewWithLocalTable(list, table, now, maxAge)}
}

// has reports whether a is one of this host's own addresses: an interface's, or one in a `local` route of the local
// table. known is false while no snapshot was ever taken, and refreshDenied then refuses the address, since one the
// check cannot place may be this host's (fail-closed). A snapshot that fails to be taken again keeps the last one,
// the table's as the addresses', the best knowledge there is of addresses that change rarely; a failed first
// snapshot is tried again after maxAge.
func (h *hostAddrs) has(a netip.Addr) (local, known bool) { return h.Has(a) }

// refreshDenied is the resolved-address check a tier's kernel rows are filtered by, in the table it is prepared
// with (rowsTable) and in every refresh the run's DNS set hands it (dns.Options.ResolvedDenied,
// dns.Set.Refreshed): the run table's own ResolvedDenied, with the machine's ranges,
// and this host's own addresses (an interface's, or one of an AnyIP range its local routing table sends here), which
// agent-contract R18 counts as loopback, since a name resolved or rebound to one reaches every service bound to all
// interfaces as loopback would. Those are refused for every
// host entry but a localhost name, which keeps the loopback class, and while no snapshot of them was ever taken
// every address is refused: the supervisor's check does the same, and a row that admitted what the supervisor
// refuses would decide a datagram whose address a sibling thread rewrote after the supervisor read it
// (supervisor R13b).
func refreshDenied(rt *agent.RuleTable, host *hostAddrs) func(agent.NetRule, netip.Addr) (string, bool) {
	return func(e agent.NetRule, a netip.Addr) (string, bool) {
		if class, denied := rt.ResolvedDenied(e, a); denied {
			return class, true
		}
		if agent.LocalhostName(e.Host) {
			return "", false
		}
		if local, known := host.has(a); local || !known {
			return agent.ResolvedLoopback, true
		}
		return "", false
	}
}

// hostSnapshot is the run's snapshot of this host's addresses, made the first time the run needs one, so the
// table Prepare is given and the set's refreshes are filtered against the same one.
func (r *runner) hostSnapshot() *hostAddrs {
	if r.hostAddrs == nil {
		r.hostAddrs = newHostAddrs(net.InterfaceAddrs, hostaddr.ReadLocalTable, time.Now, hostAddrsMaxAge)
	}
	return r.hostAddrs
}

// rowsTable is the table the enforcement backend is prepared with: the run's own, with each host entry's
// compile-time addresses passed through refreshDenied, and one it refuses moved to the entry's Denied, as Compile
// moves an address in a class it knows. Compile cannot know this host's addresses (agent-contract R18), and tier
// 2 writes its first rows from these, so without this a name whose first answer held one of them was a row
// admitting it until the DNS worker's first pass, and for the whole run when every address of the entry was one,
// since tier 2 keeps an entry's rows when a refresh leaves it with none (enforce-cgroup-observe §4 RefreshNet).
// An entry left with no address gets no row, as one Compile left with none does. Tier 1 reads no address from
// the table, so the same filter is harmless there. The run's table is not changed (agent.RuleTable I4), and when
// nothing is refused the backend is given it as it is.
func (r *runner) rowsTable() *agent.RuleTable {
	deny := refreshDenied(r.rt, r.hostSnapshot())
	var entries []agent.NetRule
	for i, e := range r.rt.Net {
		if !e.FiltersResolved() {
			continue
		}
		var kept, refused []netip.Addr
		for _, a := range e.IPs {
			if _, denied := deny(e, a); denied {
				refused = append(refused, a)
			} else {
				kept = append(kept, a)
			}
		}
		if len(refused) == 0 {
			continue
		}
		if entries == nil {
			entries = slices.Clone(r.rt.Net)
		}
		entries[i].IPs = kept
		entries[i].Denied = append(slices.Clone(e.Denied), refused...)
	}
	if entries == nil {
		return r.rt
	}
	rows := *r.rt
	rows.Net = entries
	return &rows
}

// sameNetAddrs reports whether two versions of the run's net entries hold the same addresses entry by entry, in
// any order and with an IPv4 address and its v4-mapped form as one, which is how tier 2 keys its rows: only a
// difference there is something the rows have to follow (refreshDNS).
func sameNetAddrs(a, b []agent.NetRule) bool {
	if len(a) != len(b) {
		return false
	}
	set := func(in []netip.Addr) map[netip.Addr]bool {
		out := make(map[netip.Addr]bool, len(in))
		for _, x := range in {
			out[x.Unmap().WithZone("")] = true
		}
		return out
	}
	for i := range a {
		sa, sb := set(a[i].IPs), set(b[i].IPs)
		if len(sa) != len(sb) {
			return false
		}
		for x := range sa {
			if !sb[x] {
				return false
			}
		}
	}
	return true
}
