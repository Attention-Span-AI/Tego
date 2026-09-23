// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// NetRow is one exact host:port verdict row of tego_net_exact.
type NetRow struct {
	// Key is what connect4/6 and sendmsg4/6 build from the destination they were handed.
	Key bpf.NetKey
	// Val is the verdict, the reason a refusal carries, and the rule index the ledger event names.
	Val bpf.NetVerdict
}

// CIDRRow is one longest-prefix verdict row of tego_net_cidr.
type CIDRRow struct {
	Key bpf.NetLPMKey
	Val bpf.NetVerdict
}

// UnixRow is one row of tego_unix_names, the name trie connect_unix and sendmsg_unix decide by (§5 R7).
type UnixRow struct {
	Key bpf.UnixKey
	Val bpf.NetVerdict
}

// RuleMaps is a compiled RuleTable's whole kernel-side network policy for one run: the rows to insert and the
// rule names the rule indexes in them refer to. It is a value, not kernel state — Prepare builds it, asserts
// it fits, and only then touches a map.
type RuleMaps struct {
	// Control is the opt-in bind, packet and resource policy for this run.
	Control   *NetworkControlMaps
	Timelines []TimelineRow
	// Exact holds the host:port rows; an exact hit always beats a prefix hit (§5 R3, §6 E8).
	Exact []NetRow
	// CIDR holds the prefix rows.
	CIDR []CIDRRow
	// Unix holds the unix socket name rows: every unix: entry, and the filesystem entries a pathname socket
	// is implicitly admitted or refused by (§5 R7).
	Unix []UnixRow
	// Rules maps a rule index to the compiled rule's name, as agent.NetRule.RuleName spells it, e.g.
	// "net[api.github.com:443]". Index 0 is the empty name, so a zero rule_idx in a map value or an event
	// means "no rule named this". The mapping is index -> name and never the reverse: two entries that
	// declare the same endpoint twice hold two indexes with one name, which is what a reader wants — the
	// event names the entry the author wrote, not its position in the list.
	Rules []string
	// Skipped names the compiled entries no cgroup hook can decide, with the reason, so a caller can report
	// what tier 2 is not enforcing rather than let it look enforced.
	Skipped []SkippedRule
	// Unrestricted is a contract with no net: section, which SEMANTICS §1 reads as "deny nothing" and the
	// supervisor admits every destination under. Both ask agent.RuleTable.NetUnrestricted, the one predicate
	// for that bit (agent-contract R15). No row is built for it, and Attach attaches no network program to its
	// cgroup (§5 R1), because a deciding program with no row to match refuses, and the kernel would then
	// refuse every connect the supervisor relays.
	Unrestricted bool
}

// SkippedRule is one compiled entry the network programs cannot decide, and why.
type SkippedRule struct {
	// Rule is the entry's name, e.g. "net[api.github.com:443]".
	Rule string
	// Raw is the entry as it was declared.
	Raw string
	// Why is a short, stable phrase naming the mechanism that decides it instead.
	Why string
}

// Reasons a rule is skipped. Each names the mechanism that still decides the entry, so a capability report
// can say what tier 2 adds and what it leaves to tier 1. A unix: entry is skipped only when it is longer than
// sun_path (SkipUnixLong): connect_unix and sendmsg_unix decide every other one by name on 6.7+, and below 6.7
// the inherited tier-1 path decides it, as it always does alongside them (§5 R7).
const (
	// SkipUnixLong is a pathname unix: entry longer than sun_path's 108 bytes once cleaned. The contract parser
	// checks the length before a leading ~/ is expanded (pkg/spec/agent parseUnixEndpoint), so such an entry
	// loads. No row can hold it and no name the programs look up can equal it: an absolute sun_path carries at
	// most 108 bytes. Only a relative name can reach it, which the supervisor resolves against the caller's cwd,
	// and the programs never look a relative name up — a connect's reaches them as the relay's /proc/self/fd
	// name, a datagram's is left to tier 1 (§5 R7). Failing the run over it, as an unbuildable row did, refused
	// a contract tier 1 serves, on every kernel, below 6.7 included.
	SkipUnixLong = "unix socket path is longer than sun_path; only a relative name reaches it, which tier 1 decides"
	// SkipAnyPort is a port-0 entry (ICMP or raw). Such a socket never reaches connect4/6 at all, which is
	// a stronger statement than "the hook sees no port and returns neutral": af_inet.c calls the hook only
	// under BPF_CGROUP_PRE_CONNECT_ENABLED(sk), i.e. only for a struct proto that defines .pre_connect, and
	// commit d74bad4e74ee assigned that to tcp_prot, tcpv6_prot, udp_prot and udpv6_prot alone. So the
	// entry is recorded and never refused (§5 R4) — as are SCTP and UDP-Lite connects, which no entry
	// shape flags at all because the contract names destinations, not protocols (§5 R4, §6).
	SkipAnyPort = "raw and ICMP sockets are recorded, not refused"
	// SkipUnresolved is a host entry that compiled to no address at all, which only happens in an offline
	// compile; there is nothing to key a row on.
	SkipUnresolved = "entry resolved to no address"
)

// BuildRuleMaps compiles a rule table's net entries into the rows the two verdict maps and the unix name trie
// hold, for one run's slot. It touches no kernel and no file: Prepare calls it first so a table that cannot be
// represented fails before anything is created.
//
// The compilation applies these rules the C side then relies on:
//
//   - an inet entry decides both TCP connects and UDP destinations (SEMANTICS §5), so it becomes two rows,
//     one per protocol number, because the hook keys by the socket's own protocol;
//   - an IPv4 destination is inserted twice, once as AF_INET and once as its IPv4-mapped AF_INET6 form,
//     because the kernel dispatches a connect by the socket's family and a dual-stack socket reaching the
//     same host arrives at connect6 (internal/bpf.NetKeys);
//   - an ask entry's persistent row compiles as refused; an authenticated approval can separately authorize a
//     scoped one-shot TCP completion (§5 R3, SEMANTICS §3.1);
//   - a unix: entry becomes one name row, and the filesystem entries become the rows that admit a socket
//     under a write entry and refuse one under any other entry (fsUnixRows, §5 R7); plane is the run's plane rows
//     when a plane mode decides the run (nil otherwise), whose compacted deny_read files get no rows.
//
// Every inet row carries the verdict and rule of the entries covering it, composed as decide's matcher
// composes them (SEMANTICS §5): a refusing covering entry decides regardless of declaration order, and
// otherwise the first declared. An exact row is covered by the entries naming its address and by every cidr
// entry containing it, a cidr row by every cidr entry containing its prefix. Since the kernel reads the exact
// row first and then the longest prefix (§5 R3), the entries covering the row it reads are exactly those
// covering the destination, so tier 2 answers each destination as Evaluate and the supervisor do: an allow
// under an earlier refusing prefix is refused, and an exact entry under an earlier allowing prefix is named by
// the prefix. Two entries that produce the same key are the case of this where both cover the same row.
//
// resolvers are the endpoints the supervisor's port-53 exception covers (supervisor R14, SEMANTICS §5), which
// the runtime admits on its own authority, contract or no contract. The supervisor relays an allowed connect
// on the agent's own socket, so the run's connect4/6 decides it too (§5 R1, R5), and a resolver without a row
// here would have its UDP and TCP queries refused with EPERM while the supervisor records them allowed. Each
// endpoint on port 53 becomes a TCP and a UDP row, v4 plus v4-mapped, named agent.ResolverRule; an endpoint
// on any other port gets none, because the supervisor's exception does not cover it either. A resolver row
// replaces whatever a declared entry put under the same key, because the supervisor asks the resolver
// exception before any entry (its decideDest), so an ask entry on a resolver's own address does not refuse
// it there.
func BuildRuleMaps(rt *agent.RuleTable, runIdx uint32, resolvers []netip.AddrPort, plane *decide.PlaneRows) (RuleMaps, error) {
	var out RuleMaps
	if rt == nil {
		return out, ErrNoTable
	}
	if runIdx >= bpf.MaxSlots {
		return out, fmt.Errorf("%w: run slot %d", ErrSlotsExhausted, runIdx)
	}
	dns := resolverAddrs(resolvers)
	names := len(rt.Net)
	if len(dns) > 0 {
		names++
	}
	if names > bpf.MaxRules {
		return out, fmt.Errorf("%w: %d net entries exceed the %d rule indexes an event can name",
			ErrMapFull, names, bpf.MaxRules)
	}

	out.Rules = make([]string, names+1) // index 0 is "no rule"
	for i := range rt.Net {
		// agent.NetRule.RuleName is the one spelling of a `rule` field, so a tier-2 event names the same
		// entry the contract declared and `tego drift` can match the two (spec/record/v1/README.md).
		out.Rules[i+1] = rt.Net[i].RuleName()
	}
	if len(dns) > 0 {
		out.Rules[names] = agent.ResolverRule
	}
	if rt.NetUnrestricted() {
		out.Unrestricted = true
		return out, nil
	}

	exact := map[bpf.NetKey]bpf.NetVerdict{}
	cidr := map[bpf.NetLPMKey]bpf.NetVerdict{}
	unix := map[bpf.UnixKey]bpf.NetVerdict{}
	cover := newNetCover(rt.Net)
	clock, err := newDeadlineClock(rt.Net)
	if err != nil {
		return out, err
	}
	chains := map[bpf.NetTimeline]uint32{}
	compose := func(proto uint8, port uint16, target netip.Prefix, exact bool) (bpf.NetVerdict, error) {
		value, timeline, err := cover.timelineVerdict(proto, port, target, exact, clock)
		if err != nil {
			return value, err
		}
		if timeline.Count != 0 {
			index := chains[timeline]
			if index == 0 {
				if len(chains) >= bpf.NetRowsMax {
					return value, ErrMapFull
				}
				index = uint32(len(chains) + 1)
				chains[timeline] = index
				out.Timelines = append(out.Timelines, TimelineRow{Key: bpf.NetTimelineKey{RunIdx: runIdx, Index: index}, Val: timeline})
			}
			value.Timeline = index
		}
		return value, nil
	}

	for i := range rt.Net {
		r := &rt.Net[i]
		idx := uint16(i + 1)
		name := out.Rules[idx]

		if r.Proto == agent.ProtoUnix {
			if !r.Abstract && len(path.Clean(r.UnixPath)) > bpf.UnixNameMax {
				out.Skipped = append(out.Skipped, SkippedRule{Rule: name, Raw: r.Raw, Why: SkipUnixLong})
				continue
			}
			key, err := unixEntryKey(runIdx, r)
			if err != nil {
				return out, fmt.Errorf("cgroup: %s (%s): %w", name, r.Raw, err)
			}
			unix[key] = mergeVerdict(unix[key], verdictOf(r.Verdict, idx))
			continue
		}
		if r.Port <= 0 || r.Port > 65535 {
			out.Skipped = append(out.Skipped, SkippedRule{Rule: name, Raw: r.Raw, Why: SkipAnyPort})
			continue
		}
		protos := protocolsOf(r.Proto)
		if len(protos) == 0 {
			out.Skipped = append(out.Skipped, SkippedRule{Rule: name, Raw: r.Raw, Why: SkipUnresolved})
			continue
		}
		port := uint16(r.Port)

		switch {
		case r.CIDR != nil:
			for _, proto := range protos {
				keys, err := bpf.NetLPMKeys(runIdx, proto, *r.CIDR, port)
				if err != nil {
					return out, fmt.Errorf("cgroup: %s (%s): %w", name, r.Raw, err)
				}
				val, err := compose(proto, port, r.CIDR.Masked(), false)
				if err != nil {
					return out, err
				}
				for _, k := range keys {
					cidr[k] = mergeVerdict(cidr[k], val)
				}
			}
		case len(r.IPs) > 0:
			for _, ip := range r.IPs {
				// The supervisor's set compares an entry's addresses unwrapped (internal/platform/dns unmap),
				// so a v4-mapped address in the table is the IPv4 destination: keyed as it is spelled it
				// would get only the AF_INET6 row, and connect4 would refuse what the supervisor admits.
				ip = ip.Unmap().WithZone("")
				for _, proto := range protos {
					keys, err := bpf.NetKeys(runIdx, proto, ip, port)
					if err != nil {
						return out, fmt.Errorf("cgroup: %s (%s): %w", name, r.Raw, err)
					}
					val, err := compose(proto, port, netip.PrefixFrom(ip, ip.BitLen()), true)
					if err != nil {
						return out, err
					}
					for _, k := range keys {
						exact[k] = mergeVerdict(exact[k], val)
					}
				}
			}
		default:
			out.Skipped = append(out.Skipped, SkippedRule{Rule: name, Raw: r.Raw, Why: SkipUnresolved})
		}
	}

	// An IPv6 prefix wide enough to hold ::ffff:0:0/96 would decide v4-mapped destinations in connect6 by
	// itself, where the supervisor unwraps them and no IPv6 prefix contains an IPv4 address: a refusing row
	// at ::ffff:0:0/96, unless an IPv4 entry's mapped twin holds that key, leaves them to the IPv4 rows.
	mapped := netip.MustParsePrefix("::ffff:0:0/96")
	var guards []bpf.NetLPMKey
	for k := range cidr {
		if k.Family != bpf.AFInet6 {
			continue
		}
		pfx := netip.PrefixFrom(netip.AddrFrom16(k.Addr), int(k.PrefixLen)-bpf.LPMHeaderBits)
		if pfx.Bits() < 96 && pfx.Contains(mapped.Addr()) {
			g, err := bpf.NewNetLPMKey(runIdx, k.Proto, mapped, k.Port)
			if err != nil {
				return out, err
			}
			guards = append(guards, g)
		}
	}
	for _, g := range guards {
		if _, taken := cidr[g]; !taken {
			cidr[g] = bpf.NetVerdict{Verdict: uint8(bpf.VerdictRefused), Reason: uint8(bpf.ReasonNetNotAllowed)}
		}
	}

	resolverVal := bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow), Reason: uint8(bpf.ReasonNone), RuleIdx: uint16(names)}
	for _, addr := range dns {
		for _, proto := range []uint8{bpf.ProtoTCP, bpf.ProtoUDP} {
			keys, err := bpf.NetKeys(runIdx, proto, addr, resolverPort)
			if err != nil {
				return out, fmt.Errorf("cgroup: resolver %s: %w", addr, err)
			}
			for _, k := range keys {
				exact[k] = resolverVal
			}
		}
	}

	if err := fsUnixRows(unix, rt.FS, runIdx, plane); err != nil {
		return out, err
	}

	out.Exact = sortedExact(exact)
	out.CIDR = sortedCIDR(cidr)
	out.Unix = sortedUnix(unix)
	if len(out.Exact) > bpf.NetRowsMax {
		return out, fmt.Errorf("%w: %d exact rows exceed the map's %d", ErrMapFull, len(out.Exact), bpf.NetRowsMax)
	}
	if len(out.CIDR) > bpf.NetRowsMax {
		return out, fmt.Errorf("%w: %d cidr rows exceed the trie's %d", ErrMapFull, len(out.CIDR), bpf.NetRowsMax)
	}
	if len(out.Unix) > bpf.UnixRowsMax {
		return out, fmt.Errorf("%w: %d unix name rows exceed the trie's %d", ErrMapFull, len(out.Unix), bpf.UnixRowsMax)
	}
	return out, nil
}

// unixEntryKey is the row one unix: entry becomes: an abstract name by its bytes, a pathname by its cleaned
// absolute form, which is what the supervisor matches a name against (supervisor.md R11: "matched as a
// cleaned absolute string").
func unixEntryKey(runIdx uint32, r *agent.NetRule) (bpf.UnixKey, error) {
	if r.Abstract {
		return bpf.UnixAbstractKey(runIdx, []byte(r.UnixPath))
	}
	return bpf.UnixPathKey(runIdx, path.Clean(r.UnixPath), false)
}

// fsUnixRows adds the rows through which the filesystem entries decide a pathname socket that no unix: entry
// names, mirroring the supervisor's name check (supervisor.md R11, SEMANTICS §5): the nearest entry at or
// above the name admits it when it is a write entry (multiprocessing, Ray, local MCP servers) and refuses it when it
// is any other entry, or when there is none. The row admits any name under a write entry: the programs cannot see
// which process bound a socket, so the supervisor, which decides first, holds the implicit admit to the sockets
// the run bound (supervisor R11a) and these rows are its wider backstop. Each entry is two
// rows, the entry itself and its subtree, and the trie's longest match is the nearest entry.
//
// The rows mirror the supervisor's table exactly: every entry but a watch entry (which carries no rights, and
// would shadow a write ancestor), at its declared path with a trailing slash trimmed. A key already present
// is kept, which is the supervisor's order: a unix: entry is asked before any filesystem entry, and among two
// filesystem entries at one path the one declared first is the one nearestIn returns. An entry too long for
// any row lies where no absolute sun_path can reach (a name has at most 108 bytes), and a relative name the
// supervisor resolves beneath it is never looked up by the programs (SkipUnixLong), so it is left out.
//
// A refusing entry with no write entry at or above it gets no rows: every row between it and the root refuses
// too, and a name no row covers is refused, so its rows could not change a verdict. They would only fill the
// trie, which every run of a build shares (UnixRowsMax), with the built-in deny_read list and the implicit
// entries of every run.
//
// The one other entry left out: in a run a decision plane decides (plane non-nil), a deny_read file the plane
// compacted (ADR 0043 D6: a regular file with one link beneath a write entry, its name entry alone deciding it).
// Without its pair the trie answers that path as it answers a covered name made after compile, which no row names
// either: by the write entry above. The plane refuses the run a socket node at a covered name (path_mknod), the
// file's unlink and a rename at either end of it (ADR 0043 D1), so no process of the run can make the path a
// socket or a directory, and the supervisor, which decides every connect first, keeps every entry (nearestIn) and
// still refuses one there. Kept, the pairs exhausted the shared trie for a project with thousands of .env files
// that the plane itself holds (9,006 rows for 4,500 files against 4,096). The listener's run (plane nil) keeps
// every pair.
func fsUnixRows(rows map[bpf.UnixKey]bpf.NetVerdict, fs []agent.FSRule, runIdx uint32, plane *decide.PlaneRows) error {
	allow := bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow), Reason: uint8(bpf.ReasonNone)}
	refuse := bpf.NetVerdict{Verdict: uint8(bpf.VerdictRefused), Reason: uint8(bpf.ReasonNetNotAllowed)}
	clean := func(p string) string {
		if p != "/" {
			return strings.TrimSuffix(p, "/")
		}
		return p
	}
	var writes []string
	for i := range fs {
		if fs[i].Kind == agent.FSWrite && fs[i].Path != "" {
			writes = append(writes, clean(fs[i].Path))
		}
	}
	underWrite := func(p string) bool {
		for _, w := range writes {
			if w == "/" || p == w || strings.HasPrefix(p, w+"/") {
				return true
			}
		}
		return false
	}
	for i := range fs {
		r := &fs[i]
		if r.Path == "" || r.Kind == agent.FSWatch || (r.Kind == agent.FSDenyRead && plane.CompactedAt(r.Path)) {
			continue
		}
		p := clean(r.Path)
		val := refuse
		if r.Kind == agent.FSWrite {
			val = allow
		} else if !underWrite(p) {
			continue
		}
		for _, subtree := range []bool{false, true} {
			key, err := bpf.UnixPathKey(runIdx, p, subtree)
			if errors.Is(err, bpf.ErrUnixName) && len(p) >= bpf.UnixNameMax {
				continue
			}
			if err != nil {
				return fmt.Errorf("cgroup: fs entry %s: %w", r.Path, err)
			}
			if _, taken := rows[key]; !taken {
				rows[key] = val
			}
		}
	}
	return nil
}

// resolverPort is the one port the supervisor's resolver exception covers, on TCP and UDP alike (supervisor
// R14, SEMANTICS §5).
const resolverPort = 53

// resolverAddrs reduces the runtime's resolver endpoints to the addresses a port-53 row is keyed by, in the
// canonical form the supervisor compares them in (its canonical: no IPv4-in-IPv6 wrapper, no zone), without
// duplicates. An endpoint on another port is dropped, as the supervisor's isResolver never matches it.
func resolverAddrs(eps []netip.AddrPort) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, ep := range eps {
		if !ep.IsValid() || ep.Port() != resolverPort {
			continue
		}
		a := ep.Addr().Unmap().WithZone("")
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// protocolsOf expands a compiled entry's protocol into the IP protocol numbers a hook keys by. An inet entry
// covers both, which is what makes one declaration decide a TCP connect and a UDP datagram alike.
func protocolsOf(proto string) []uint8 {
	switch proto {
	case agent.ProtoInet:
		return []uint8{bpf.ProtoTCP, bpf.ProtoUDP}
	case agent.ProtoTCP:
		return []uint8{bpf.ProtoTCP}
	case agent.ProtoUDP:
		return []uint8{bpf.ProtoUDP}
	default:
		return nil
	}
}

// netCover indexes the inet entries that produce rows by protocol, port and prefix, so the composition
// BuildRuleMaps gives each row (first refusing covering entry, else first covering) costs one lookup per
// distinct prefix length rather than a walk of the table.
type netCover struct {
	net               []agent.NetRule
	cidr              map[coverKey]coverHit
	exact             map[coverKey]coverHit
	bits              map[coverKey][]int // per protocol and port (pfx unset): the distinct cidr widths present
	allCIDR, allExact map[coverKey][]int
}

type coverKey struct {
	proto uint8
	port  uint16
	pfx   netip.Prefix
}

// coverHit is the first entry and the first refusing entry at one key, as positions in the table (-1: none).
type coverHit struct{ first, refusing int }

func (h coverHit) add(i int, refused bool) coverHit {
	if h.first < 0 {
		h.first = i
	}
	if refused && h.refusing < 0 {
		h.refusing = i
	}
	return h
}

func newNetCover(net []agent.NetRule) *netCover {
	c := &netCover{net: net, cidr: map[coverKey]coverHit{}, exact: map[coverKey]coverHit{}, bits: map[coverKey][]int{}, allCIDR: map[coverKey][]int{}, allExact: map[coverKey][]int{}}
	none := coverHit{first: -1, refusing: -1}
	put := func(m map[coverKey]coverHit, k coverKey, i int, refused bool) {
		h, ok := m[k]
		if !ok {
			h = none
		}
		m[k] = h.add(i, refused)
		all := c.allCIDR
		// The two stores are selected by the caller through the presence of a
		// CIDR on the source rule; no map identity comparison is needed.
		if c.net[i].CIDR == nil {
			all = c.allExact
		}
		all[k] = append(all[k], i)
	}
	for i := range net {
		r := &net[i]
		if r.Proto == agent.ProtoUnix || r.Port <= 0 || r.Port > 65535 {
			continue
		}
		refused := r.Verdict != agent.VerdictAllow
		for _, proto := range protocolsOf(r.Proto) {
			pp := coverKey{proto: proto, port: uint16(r.Port)}
			switch {
			case r.CIDR != nil:
				m := r.CIDR.Masked()
				put(c.cidr, coverKey{proto: proto, port: pp.port, pfx: m}, i, refused)
				if !slices.Contains(c.bits[pp], m.Bits()) {
					c.bits[pp] = append(c.bits[pp], m.Bits())
				}
			default:
				for _, ip := range r.IPs {
					ip = ip.Unmap().WithZone("")
					put(c.exact, coverKey{proto: proto, port: pp.port, pfx: netip.PrefixFrom(ip, ip.BitLen())}, i, refused)
				}
			}
		}
	}
	return c
}

// verdict is the row value for target on proto and port: exact says the row is the exact map's, which the
// entries naming the address cover too. Every entry that produced the row covers it, so a row always has one.
func (c *netCover) verdict(proto uint8, port uint16, target netip.Prefix, exact bool) bpf.NetVerdict {
	best := coverHit{first: -1, refusing: -1}
	merge := func(h coverHit, ok bool) {
		if !ok {
			return
		}
		if h.first >= 0 && (best.first < 0 || h.first < best.first) {
			best.first = h.first
		}
		if h.refusing >= 0 && (best.refusing < 0 || h.refusing < best.refusing) {
			best.refusing = h.refusing
		}
	}
	if exact {
		h, ok := c.exact[coverKey{proto: proto, port: port, pfx: target}]
		merge(h, ok)
	}
	for _, b := range c.bits[coverKey{proto: proto, port: port}] {
		if b > target.Bits() {
			continue
		}
		p, err := target.Addr().Prefix(b)
		if err != nil {
			continue
		}
		h, ok := c.cidr[coverKey{proto: proto, port: port, pfx: p}]
		merge(h, ok)
	}
	i := best.first
	if best.refusing >= 0 {
		i = best.refusing
	}
	if i < 0 { // unreachable: the entry that produced the row covers it; refuse rather than guess
		return bpf.NetVerdict{Verdict: uint8(bpf.VerdictRefused), Reason: uint8(bpf.ReasonNetNotAllowed)}
	}
	return verdictOf(c.net[i].Verdict, uint16(i+1))
}

// verdictOf turns a compiled verdict into the persistent map value the kernel reads. Ask compiles as refused;
// approved TCP completion uses a separate scoped one-shot grant (§5 R3).
func verdictOf(v agent.Verdict, ruleIdx uint16) bpf.NetVerdict {
	if v == agent.VerdictAllow {
		return bpf.NetVerdict{Verdict: uint8(bpf.VerdictAllow), Reason: uint8(bpf.ReasonNone), RuleIdx: ruleIdx}
	}
	return bpf.NetVerdict{Verdict: uint8(bpf.VerdictRefused), Reason: uint8(bpf.ReasonNetNotAllowed), RuleIdx: ruleIdx}
}

// mergeVerdict resolves two entries that produced the same key, fail-closed: a refusal wins, and otherwise
// the first entry keeps the key so the rule name an event reports is stable.
func mergeVerdict(existing, incoming bpf.NetVerdict) bpf.NetVerdict {
	switch {
	case existing == (bpf.NetVerdict{}):
		return incoming
	case existing.Verdict == uint8(bpf.VerdictRefused):
		return existing
	case incoming.Verdict == uint8(bpf.VerdictRefused):
		return incoming
	default:
		return existing
	}
}

// sortedExact returns the rows in a deterministic order so two Prepare calls over one table insert the same
// rows in the same sequence, which makes a partial failure reproducible.
func sortedExact(m map[bpf.NetKey]bpf.NetVerdict) []NetRow {
	out := make([]NetRow, 0, len(m))
	for k, v := range m {
		out = append(out, NetRow{Key: k, Val: v})
	}
	sort.Slice(out, func(i, j int) bool { return lessNetKey(out[i].Key, out[j].Key) })
	return out
}

// sortedCIDR orders prefix rows by width first, so a reader of the slice sees general before specific.
func sortedCIDR(m map[bpf.NetLPMKey]bpf.NetVerdict) []CIDRRow {
	out := make([]CIDRRow, 0, len(m))
	for k, v := range m {
		out = append(out, CIDRRow{Key: k, Val: v})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Key, out[j].Key
		if a.PrefixLen != b.PrefixLen {
			return a.PrefixLen < b.PrefixLen
		}
		return lessNetKey(
			bpf.NetKey{RunIdx: a.RunIdx, Family: a.Family, Proto: a.Proto, Port: a.Port, Addr: a.Addr},
			bpf.NetKey{RunIdx: b.RunIdx, Family: b.Family, Proto: b.Proto, Port: b.Port, Addr: b.Addr})
	})
	return out
}

// sortedUnix orders name rows by width, then bytes, for the same reproducibility sortedExact gives.
func sortedUnix(m map[bpf.UnixKey]bpf.NetVerdict) []UnixRow {
	out := make([]UnixRow, 0, len(m))
	for k, v := range m {
		out = append(out, UnixRow{Key: k, Val: v})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Key, out[j].Key
		switch {
		case a.PrefixLen != b.PrefixLen:
			return a.PrefixLen < b.PrefixLen
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		default:
			return bytes.Compare(a.Name[:], b.Name[:]) < 0
		}
	})
	return out
}

// lessNetKey orders keys by run, family, protocol, port and address.
func lessNetKey(a, b bpf.NetKey) bool {
	switch {
	case a.RunIdx != b.RunIdx:
		return a.RunIdx < b.RunIdx
	case a.Family != b.Family:
		return a.Family < b.Family
	case a.Proto != b.Proto:
		return a.Proto < b.Proto
	case a.Port != b.Port:
		return a.Port < b.Port
	default:
		return netip.AddrFrom16(a.Addr).Less(netip.AddrFrom16(b.Addr))
	}
}

// RuleName resolves a rule index carried by a map value, a breadcrumb or an event back to the compiled
// entry's name. An index the table does not name yields "", which a caller records as an unnamed rule rather
// than as a wrong one.
func (m RuleMaps) RuleName(idx uint16) string {
	if int(idx) >= len(m.Rules) {
		return ""
	}
	return m.Rules[idx]
}
