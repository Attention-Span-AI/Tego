// SPDX-License-Identifier: Apache-2.0

package hostaddr

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// route is one route message of a dump, as the kernel writes it (rt_fill_info, rt6_fill_node): an nlmsghdr, a struct
// rtmsg, RTA_TABLE and, unless dst is a default route, RTA_DST.
type route struct {
	typ     uint8
	table   uint32
	dst     string // a prefix
	flags   uint16 // nlmsghdr flags beside NLM_F_MULTI: NLM_F_DUMP_FILTERED, NLM_F_DUMP_INTR
	family  uint8  // 0: the prefix's own
	rtFlags uint32
	seq     uint32 // 0: the dump of its type's (seqOf)
}

// seqOf is the sequence number ReadLocalTable gives the dump of route type typ, and 0 for a type it does not read.
func seqOf(typ uint8) uint32 {
	for i, x := range localTableTypes {
		if x == typ {
			return uint32(i + 1)
		}
	}
	return 0
}

func nlMsg(typ, flags uint16, seq uint32, body []byte) []byte {
	m := make([]byte, unix.NLMSG_HDRLEN, align4(unix.NLMSG_HDRLEN+len(body)))
	ne := binary.NativeEndian
	ne.PutUint32(m[0:], uint32(unix.NLMSG_HDRLEN+len(body)))
	ne.PutUint16(m[4:], typ)
	ne.PutUint16(m[6:], flags|unix.NLM_F_MULTI)
	ne.PutUint32(m[8:], seq)
	m = append(m, body...)
	return m[:cap(m)]
}

func rtAttr(typ uint16, data []byte) []byte {
	a := make([]byte, unix.SizeofRtAttr, align4(unix.SizeofRtAttr+len(data)))
	binary.NativeEndian.PutUint16(a[0:], uint16(unix.SizeofRtAttr+len(data)))
	binary.NativeEndian.PutUint16(a[2:], typ)
	a = append(a, data...)
	return a[:cap(a)]
}

func (r route) msg() []byte {
	p := netip.MustParsePrefix(r.dst)
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET6
	if p.Addr().Is4() {
		body[0] = unix.AF_INET
	}
	if r.family != 0 {
		body[0] = r.family
	}
	body[1], body[4], body[5], body[7] = uint8(p.Bits()), unix.RT_TABLE_COMPAT, unix.RTPROT_KERNEL, r.typ
	if r.table < 256 {
		body[4] = uint8(r.table)
	}
	binary.NativeEndian.PutUint32(body[8:], r.rtFlags)
	table := binary.NativeEndian.AppendUint32(nil, r.table)
	body = append(body, rtAttr(unix.RTA_TABLE, table)...)
	if p.Bits() != 0 {
		body = append(body, rtAttr(unix.RTA_DST, p.Addr().AsSlice())...)
	}
	body = append(body, rtAttr(unix.RTA_OIF, []byte{1, 0, 0, 0})...)
	seq := r.seq
	if seq == 0 {
		seq = seqOf(r.typ)
	}
	return nlMsg(unix.RTM_NEWROUTE, r.flags, seq, body)
}

// familyIPMR is RTNL_FAMILY_IPMR (linux/rtnetlink.h), the IPv4 multicast routing tables' family.
const familyIPMR = 128

// errnoBytes is a negative errno as an NLMSG_DONE or NLMSG_ERROR carries it.
func errnoBytes(e unix.Errno) []byte {
	v := -int32(e)
	return binary.NativeEndian.AppendUint32(nil, uint32(v))
}

// done is the end of the dump of sequence number seq, carrying e.
func done(seq uint32, e unix.Errno) []byte { return nlMsg(unix.NLMSG_DONE, 0, seq, errnoBytes(e)) }

func dump(rs ...route) []byte {
	var b []byte
	for _, r := range rs {
		b = append(b, r.msg()...)
	}
	return b
}

// parseDump parses b as the whole answer to the dump of route type typ into t, failing the test unless it ends there.
func parseDump(t *testing.T, typ uint8, b []byte, into *LocalTable) {
	t.Helper()
	if end, err := parseLocalTable(b, seqOf(typ), typ, into); !end || err != nil {
		t.Fatalf("the dump of type %d: end %v, %v", typ, end, err)
	}
}

func prefixes(ps ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, p := range ps {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// TestParseLocalTable reads the three filtered dumps of a host with 192.0.2.10/24 on eth0 and its broadcast set by hand
// to 192.0.2.100 (`ip addr ... brd`), an AnyIP range routed to loopback (`ip route add local 198.51.100.0/24 dev lo`),
// another put in table main (`... table main`, which the default rules look up with no rule of anyone's), a broadcast
// address in table default, and IPv6 forwarding on, so it joined its subnets' router anycast addresses. A route of a
// table no default rule looks up (TPROXY's `local 0.0.0.0/0 dev lo table 100`, a VRF's anycast address), a cached
// route and a multicast routing table's route are not this host's; a dump's first datagram need not hold its end.
func TestParseLocalTable(t *testing.T) {
	const f, local, main, def = unix.NLM_F_DUMP_FILTERED, unix.RT_TABLE_LOCAL, unix.RT_TABLE_MAIN, unix.RT_TABLE_DEFAULT
	first := dump(
		route{typ: unix.RTN_LOCAL, table: local, dst: "127.0.0.0/8", flags: f},
		route{typ: unix.RTN_LOCAL, table: local, dst: "127.0.0.1/32", flags: f},
		route{typ: unix.RTN_LOCAL, table: local, dst: "192.0.2.10/32", flags: f},
		route{typ: unix.RTN_LOCAL, table: local, dst: "198.51.100.0/24", flags: f},
		route{typ: unix.RTN_LOCAL, table: main, dst: "203.0.113.0/24", flags: f},
		route{typ: unix.RTN_LOCAL, table: 100, dst: "0.0.0.0/0", flags: f},
		route{typ: unix.RTN_LOCAL, table: local, dst: "203.0.113.9/32", flags: f, rtFlags: unix.RTM_F_CLONED},
		route{typ: unix.RTN_LOCAL, table: local, dst: "10.9.0.0/16", flags: f, family: familyIPMR},
	)
	second := append(dump(
		route{typ: unix.RTN_LOCAL, table: local, dst: "::1/128", flags: f},
		route{typ: unix.RTN_LOCAL, table: local, dst: "2001:db8:1::10/128", flags: f},
		route{typ: unix.RTN_LOCAL, table: local, dst: "fe80::1/128", flags: f},
	), done(seqOf(unix.RTN_LOCAL), 0)...)
	var tab LocalTable
	if end, err := parseLocalTable(first, seqOf(unix.RTN_LOCAL), unix.RTN_LOCAL, &tab); end || err != nil {
		t.Fatalf("first datagram: end %v, %v", end, err)
	}
	parseDump(t, unix.RTN_LOCAL, second, &tab)
	parseDump(t, unix.RTN_BROADCAST, append(dump(
		route{typ: unix.RTN_BROADCAST, table: local, dst: "127.255.255.255/32", flags: f},
		route{typ: unix.RTN_BROADCAST, table: local, dst: "192.0.2.100/32", flags: f},
		route{typ: unix.RTN_BROADCAST, table: local, dst: "192.0.2.255/32", flags: f},
		route{typ: unix.RTN_BROADCAST, table: def, dst: "198.18.0.255/32", flags: f},
	), done(seqOf(unix.RTN_BROADCAST), 0)...), &tab)
	parseDump(t, unix.RTN_ANYCAST, append(dump(
		route{typ: unix.RTN_ANYCAST, table: local, dst: "2001:db8:1::/128", flags: f},
		route{typ: unix.RTN_ANYCAST, table: local, dst: "fe80::/128", flags: f},
		route{typ: unix.RTN_ANYCAST, table: 10, dst: "2001:db8:2::/128", flags: f},
	), done(seqOf(unix.RTN_ANYCAST), 0)...), &tab)
	want := LocalTable{
		Local: prefixes("127.0.0.0/8", "127.0.0.1/32", "192.0.2.10/32", "198.51.100.0/24", "203.0.113.0/24",
			"::1/128", "2001:db8:1::10/128", "fe80::1/128"),
		Broadcast: prefixes("127.255.255.255/32", "192.0.2.100/32", "192.0.2.255/32", "198.18.0.255/32"),
		Anycast:   prefixes("2001:db8:1::/128", "fe80::/128"),
	}
	if !slices.Equal(tab.Local, want.Local) || !slices.Equal(tab.Broadcast, want.Broadcast) || !slices.Equal(tab.Anycast, want.Anycast) {
		t.Errorf("read %+v\nwant %+v", tab, want)
	}
}

// TestParseLocalTableUnfiltered: a kernel that does not filter a dump sends every route of every table to each, and a
// route is this host's once, in the dump of its type, and only from a table the default policy rules look up: local,
// main and default. TPROXY's `local 0.0.0.0/0 dev lo table 100` delivers here only what its rule marks, and a table
// above 255 names itself in RTA_TABLE alone (table 1255 is not table local). A kernel without IPv6 policy routing keeps
// its IPv6 local routes in main, so they count.
func TestParseLocalTableUnfiltered(t *testing.T) {
	every := func(typ uint8) []byte {
		seq := seqOf(typ)
		return append(dump(
			route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "192.0.2.10/32", seq: seq},
			route{typ: unix.RTN_BROADCAST, table: unix.RT_TABLE_LOCAL, dst: "192.0.2.255/32", seq: seq},
			route{typ: unix.RTN_UNICAST, table: unix.RT_TABLE_MAIN, dst: "192.0.2.0/24", seq: seq},
			route{typ: unix.RTN_LOCAL, table: 100, dst: "0.0.0.0/0", seq: seq},
			route{typ: unix.RTN_LOCAL, table: 1000 + unix.RT_TABLE_LOCAL, dst: "198.51.100.0/24", seq: seq},
			route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_MAIN, dst: "2001:db8::1/128", seq: seq},
			route{typ: unix.RTN_ANYCAST, table: unix.RT_TABLE_MAIN, dst: "2001:db8::/128", seq: seq},
		), done(seq, 0)...)
	}
	var tab LocalTable
	for _, typ := range localTableTypes {
		parseDump(t, typ, every(typ), &tab)
	}
	want := LocalTable{
		Local:     prefixes("192.0.2.10/32", "2001:db8::1/128"),
		Broadcast: prefixes("192.0.2.255/32"),
		Anycast:   prefixes("2001:db8::/128"),
	}
	if !slices.Equal(tab.Local, want.Local) || !slices.Equal(tab.Broadcast, want.Broadcast) || !slices.Equal(tab.Anycast, want.Anycast) {
		t.Errorf("read %+v\nwant %+v", tab, want)
	}
}

// TestLocalTableRequest: each dump asks for its own type, no table and both families, under its own sequence number, so
// a kernel that filters walks every table for that type alone.
func TestLocalTableRequest(t *testing.T) {
	for i, typ := range localTableTypes {
		req := localTableRequest(uint32(i+1), typ)
		ne := binary.NativeEndian
		if len(req) != unix.NLMSG_HDRLEN+unix.SizeofRtMsg || int(ne.Uint32(req[0:])) != len(req) ||
			ne.Uint16(req[4:]) != unix.RTM_GETROUTE || ne.Uint16(req[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP ||
			ne.Uint32(req[8:]) != uint32(i+1) {
			t.Fatalf("type %d: header %x", typ, req[:unix.NLMSG_HDRLEN])
		}
		rtm := req[unix.NLMSG_HDRLEN:]
		if want := []byte{unix.AF_UNSPEC, 0, 0, 0, unix.RT_TABLE_UNSPEC, 0, 0, typ, 0, 0, 0, 0}; !slices.Equal(rtm, want) {
			t.Errorf("type %d: rtmsg %x, want %x", typ, rtm, want)
		}
	}
}

// TestParseLocalTableRefuses: a dump that failed, or that cannot be read whole, is no table; the snapshot keeps the one
// it had.
func TestParseLocalTableRefuses(t *testing.T) {
	seq := seqOf(unix.RTN_LOCAL)
	good := route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "192.0.2.10/32", flags: unix.NLM_F_DUMP_FILTERED}
	errMsg := nlMsg(unix.NLMSG_ERROR, 0, seq, append(errnoBytes(unix.EINVAL), make([]byte, unix.NLMSG_HDRLEN)...))
	ack := nlMsg(unix.NLMSG_ERROR, 0, seq, make([]byte, 20))
	shortDst := good.msg()
	binary.NativeEndian.PutUint16(shortDst[unix.NLMSG_HDRLEN+unix.SizeofRtMsg+8:], unix.SizeofRtAttr+3) // RTA_DST of 3 bytes
	longPrefix := good.msg()
	longPrefix[unix.NLMSG_HDRLEN+1] = 33
	overlong := good.msg()
	binary.NativeEndian.PutUint32(overlong[0:], uint32(len(overlong)+4))
	badAttr := good.msg()
	binary.NativeEndian.PutUint16(badAttr[unix.NLMSG_HDRLEN+unix.SizeofRtMsg:], 2)
	shortRoute := nlMsg(unix.RTM_NEWROUTE, 0, seq, make([]byte, unix.SizeofRtMsg-1))
	for name, b := range map[string][]byte{
		"an error":                             errMsg,
		"an acknowledgement":                   ack,
		"an end that carries an error":         done(seq, unix.ENOENT),
		"an interrupted dump":                  route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "192.0.2.10/32", flags: unix.NLM_F_DUMP_INTR}.msg(),
		"another request's answer":             route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "192.0.2.10/32", seq: 7}.msg(),
		"another dump's end":                   done(seqOf(unix.RTN_BROADCAST), 0),
		"a destination of the wrong size":      shortDst,
		"a prefix longer than its family":      longPrefix,
		"a message past the datagram":          overlong,
		"an attribute shorter than its header": badAttr,
		"a route shorter than its rtmsg":       shortRoute,
		"bytes after the last message":         append(good.msg(), 1, 2, 3),
	} {
		var tab LocalTable
		if _, err := parseLocalTable(b, seq, unix.RTN_LOCAL, &tab); err == nil {
			t.Errorf("%s: read %+v, want an error", name, tab)
		}
	}
	var tab LocalTable
	if _, err := parseLocalTable(errMsg, seq, unix.RTN_LOCAL, &tab); !errors.Is(err, unix.EINVAL) {
		t.Errorf("the kernel's error is not the one returned: %v", err)
	}
}

// TestParseLocalTableDefaultRoute: a route with no RTA_DST is its family's default route, so a `local` default route in
// the local table makes every address of its family this host's own, as the kernel then delivers them all here.
func TestParseLocalTableDefaultRoute(t *testing.T) {
	var tab LocalTable
	b := append(route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "::/0", flags: unix.NLM_F_DUMP_FILTERED}.msg(),
		done(seqOf(unix.RTN_LOCAL), 0)...)
	parseDump(t, unix.RTN_LOCAL, b, &tab)
	if want := prefixes("::/0"); !slices.Equal(tab.Local, want) {
		t.Fatalf("local %v, want %v", tab.Local, want)
	}
	if routes := indexLocalTable(tab); !routes.local.contains(netip.MustParseAddr("2001:db8::7")) ||
		routes.local.contains(netip.MustParseAddr("192.0.2.7")) {
		t.Errorf("an IPv6 default route covers %v", tab.Local)
	}
}

// TestReadLocalTableReal reads this machine's local table as whoever runs the test: the dump needs no privilege. Every
// IPv4 address of an interface that is up has its `local` route there, and so does the whole subnet of one on a
// loopback interface (fib_add_ifaddr), loopback's 127.0.0.0/8.
func TestReadLocalTableReal(t *testing.T) {
	tab, err := ReadLocalTable()
	if err != nil {
		t.Fatalf("the local table cannot be read unprivileged: %v", err)
	}
	t.Logf("local %v, broadcast %v, anycast %v", tab.Local, tab.Broadcast, tab.Anycast)
	routes := indexLocalTable(tab)
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			ip, _ := netip.AddrFromSlice(n.IP.To4())
			if !routes.local.contains(ip) {
				t.Errorf("%s's address %s has no local route in %v", i.Name, ip, tab.Local)
			}
			if ones, _ := n.Mask.Size(); i.Flags&net.FlagLoopback != 0 && ones == 8 && !routes.local.contains(ip.Next()) {
				t.Errorf("%s's subnet of %s/8 is not this host's: %v", i.Name, ip, tab.Local)
			}
		}
	}
}

// FuzzParseLocalTable: no datagram panics the parse of any of the three dumps, and every destination it keeps from one
// it reads whole is a valid prefix with no zone, which a lookup can match.
func FuzzParseLocalTable(f *testing.F) {
	const filtered = unix.NLM_F_DUMP_FILTERED
	f.Add(uint8(0), append(dump(
		route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "198.51.100.0/24", flags: filtered},
		route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_MAIN, dst: "203.0.113.0/24", flags: filtered},
		route{typ: unix.RTN_LOCAL, table: unix.RT_TABLE_LOCAL, dst: "::/0"},
	), done(seqOf(unix.RTN_LOCAL), 0)...))
	f.Add(uint8(1), append(route{typ: unix.RTN_BROADCAST, table: unix.RT_TABLE_LOCAL, dst: "192.0.2.100/32", flags: filtered}.msg(),
		done(seqOf(unix.RTN_BROADCAST), 0)...))
	f.Add(uint8(2), append(route{typ: unix.RTN_ANYCAST, table: unix.RT_TABLE_LOCAL, dst: "2001:db8:1::/128", flags: filtered}.msg(),
		done(seqOf(unix.RTN_ANYCAST), 0)...))
	f.Add(uint8(0), done(seqOf(unix.RTN_LOCAL), unix.ENOENT))
	f.Add(uint8(0), route{typ: unix.RTN_LOCAL, table: 100, dst: "10.0.0.0/8", family: familyIPMR}.msg())
	f.Fuzz(func(t *testing.T, which uint8, b []byte) {
		i := int(which) % len(localTableTypes)
		var tab LocalTable
		if _, err := parseLocalTable(b, uint32(i+1), localTableTypes[i], &tab); err != nil {
			return
		}
		for _, ps := range [][]netip.Prefix{tab.Local, tab.Broadcast, tab.Anycast} {
			for _, p := range ps {
				if !p.IsValid() || p.Addr().Zone() != "" {
					t.Fatalf("kept %v from %x", p, b)
				}
			}
		}
	})
}
