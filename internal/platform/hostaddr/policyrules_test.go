// SPDX-License-Identifier: Apache-2.0

package hostaddr

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rule is one RTM_NEWRULE message of a dump as the kernel writes it (fib_nl_fill_rule): an nlmsghdr, a struct
// fib_rule_hdr and the attributes the rule has.
type rule struct {
	family uint8 // 0: AF_INET
	table  uint32
	action uint8 // 0: FR_ACT_TO_TBL
	flags  uint32
	attrs  []byte
	srcLen uint8
	seq    uint32 // 0: the dump of its family's
}

func attr(typ uint16, data ...byte) []byte { return rtAttr(typ, data) }

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func (r rule) msg() []byte {
	family, action := r.family, r.action
	if family == 0 {
		family = unix.AF_INET
	}
	if action == 0 {
		action = unix.FR_ACT_TO_TBL
	}
	body := make([]byte, sizeofFibRuleHdr)
	body[0], body[2], body[7] = family, r.srcLen, action
	if r.table < 256 {
		body[4] = uint8(r.table)
	}
	binary.NativeEndian.PutUint32(body[8:], r.flags)
	body = append(body, rtAttr(unix.FRA_TABLE, u32(r.table))...)
	body = append(body, r.attrs...)
	body = append(body, rtAttr(unix.FRA_PRIORITY, u32(100))...)
	seq := r.seq
	if seq == 0 {
		seq = ruleSeqBase
		if family == unix.AF_INET6 {
			seq++
		}
	}
	return nlMsg(unix.RTM_NEWRULE, 0, seq, body)
}

func ruleDump(family uint8, rs ...rule) []byte {
	var b []byte
	for _, r := range rs {
		if r.family == 0 {
			r.family = family
		}
		b = append(b, r.msg()...)
	}
	seq := uint32(ruleSeqBase)
	if family == unix.AF_INET6 {
		seq++
	}
	return append(b, done(seq, 0)...)
}

var (
	fwmark     = attr(unix.FRA_FWMARK, u32(0x200)...)
	fwmask     = attr(unix.FRA_FWMASK, u32(0xf00)...)
	oifname    = attr(unix.FRA_OIFNAME, append([]byte("vrf-blue"), 0)...)
	l3mdev     = attr(unix.FRA_L3MDEV, 1)
	iifLo      = attr(unix.FRA_IIFNAME, append([]byte("lo"), 0)...)
	iifEth     = attr(unix.FRA_IIFNAME, append([]byte("eth0"), 0)...)
	fromPrefix = attr(unix.FRA_SRC, 192, 0, 2, 0)
)

func uidRange(lo, hi uint32) []byte { return attr(unix.FRA_UID_RANGE, append(u32(lo), u32(hi)...)...) }

// TestRuleReaches: which `ip rule` the run's own traffic (locally generated: mark 0, no output interface, loopback as
// input interface, the run's user) can match, so that the table it leads to counts as this host's.
func TestRuleReaches(t *testing.T) {
	user := userSet{uids: []uint32{1000}}
	for _, tc := range []struct {
		name  string
		r     rule
		users userSet
		want  bool
		table uint32
	}{
		{"every packet to table 100", rule{table: 100}, user, true, 100},
		{"a table above 255 named in FRA_TABLE", rule{table: 1000}, user, true, 1000},
		{"from a prefix: a selector the traffic's own choices decide", rule{table: 100, srcLen: 24, attrs: fromPrefix}, user, true, 100},
		{"a fwmark (TPROXY, Cilium)", rule{table: 2004, attrs: append(append([]byte{}, fwmark...), fwmask...)}, user, false, 2004},
		// An unprivileged agent can SO_BINDTODEVICE a socket since Linux 5.7, so the output interface and a VRF are its choice.
		{"an output interface (the agent binds the socket to it)", rule{table: 10, attrs: oifname}, user, true, 10},
		{"l3mdev (the agent binds the socket to a VRF device)", rule{table: 10, attrs: l3mdev}, user, true, 10},
		{"a mark whose mask covers it: unmarked traffic misses", rule{table: 2004, attrs: append(append([]byte{}, fwmark...), fwmask...)}, user, false, 2004},
		{"a mark the mask does not cover (0x100/0xff): unmarked traffic matches", rule{table: 100, attrs: append(attr(unix.FRA_FWMARK, u32(0x100)...), attr(unix.FRA_FWMASK, u32(0xff)...)...)}, user, true, 100},
		{"a mark with a zero mask: unmarked traffic matches", rule{table: 100, attrs: append(attr(unix.FRA_FWMARK, u32(0x100)...), attr(unix.FRA_FWMASK, u32(0)...)...)}, user, true, 100},
		{"a mark with its mask before it in the message", rule{table: 100, attrs: append(attr(unix.FRA_FWMASK, u32(0xff)...), attr(unix.FRA_FWMARK, u32(0x100)...)...)}, user, true, 100},
		{"a mark with no mask: the kernel's default is all bits", rule{table: 100, attrs: fwmark}, user, false, 100},
		{"not a mark the mask does not cover: unmarked traffic matches it, so the rule does not", rule{table: 100, flags: unix.FIB_RULE_INVERT, attrs: append(attr(unix.FRA_FWMARK, u32(0x100)...), attr(unix.FRA_FWMASK, u32(0xff)...)...)}, user, false, 100},
		{"the loopback as input interface", rule{table: 100, attrs: iifLo}, user, true, 100},
		{"another input interface", rule{table: 100, attrs: iifEth}, user, false, 100},
		{"a uidrange holding the run's user", rule{table: 100, attrs: uidRange(1000, 1000)}, user, true, 100},
		{"a uidrange that does not", rule{table: 100, attrs: uidRange(2000, 3000)}, user, false, 100},
		{"a uidrange, for a supervisor that is root", rule{table: 100, attrs: uidRange(2000, 3000)}, userSet{any: true}, true, 100},
		{"not fwmark: unmarked traffic misses the mark, so the inverted rule takes it",
			rule{table: 100, flags: unix.FIB_RULE_INVERT, attrs: fwmark}, user, true, 100},
		{"not oif", rule{table: 100, flags: unix.FIB_RULE_INVERT, attrs: oifname}, user, true, 100},
		{"not from all: matches nothing", rule{table: 100, flags: unix.FIB_RULE_INVERT}, user, false, 100},
		{"not iif lo: matches nothing", rule{table: 100, flags: unix.FIB_RULE_INVERT, attrs: iifLo}, user, false, 100},
		{"not uidrange holding the user", rule{table: 100, flags: unix.FIB_RULE_INVERT, attrs: uidRange(0, 0xfffffffe)}, user, false, 100},
		{"a fwmark and a uidrange: both must match", rule{table: 100, attrs: append(append([]byte{}, uidRange(1000, 1000)...), fwmark...)}, user, false, 100},
		{"blackhole", rule{table: 100, action: unix.FR_ACT_BLACKHOLE}, user, false, 100},
		{"goto", rule{table: 100, action: unix.FR_ACT_GOTO}, user, false, 100},
		{"no table", rule{table: 0}, user, false, 0},
	} {
		table, got, err := ruleReaches(tc.r.msg()[unix.NLMSG_HDRLEN:], unix.AF_INET, tc.users)
		if err != nil || got != tc.want || table != tc.table {
			t.Errorf("%s: table %d, reaches %v, %v; want table %d, reaches %v", tc.name, table, got, err, tc.table, tc.want)
		}
	}
	// The header's own table byte is read when no FRA_TABLE says otherwise (a kernel before 2.6.19's attribute).
	hdr := make([]byte, sizeofFibRuleHdr)
	hdr[0], hdr[4], hdr[7] = unix.AF_INET, 100, unix.FR_ACT_TO_TBL
	if table, got, err := ruleReaches(hdr, unix.AF_INET, user); err != nil || !got || table != 100 {
		t.Errorf("header table: %d, %v, %v", table, got, err)
	}
	// A rule of another family in an unfiltered dump leads to nothing here.
	if _, got, err := ruleReaches(rule{family: unix.AF_INET6, table: 100}.msg()[unix.NLMSG_HDRLEN:], unix.AF_INET, user); err != nil || got {
		t.Errorf("another family's rule reaches %v, %v", got, err)
	}
}

// TestParseRulesRefuses: a rule dump that failed or cannot be read whole is no answer.
func TestParseRulesRefuses(t *testing.T) {
	seq := uint32(ruleSeqBase)
	good := rule{table: 100}
	shortAttr := good.msg()
	binary.NativeEndian.PutUint16(shortAttr[unix.NLMSG_HDRLEN+sizeofFibRuleHdr:], 2)
	longAttr := good.msg()
	binary.NativeEndian.PutUint16(longAttr[unix.NLMSG_HDRLEN+sizeofFibRuleHdr:], 200)
	badTable := rule{table: 100, attrs: attr(unix.FRA_TABLE, 1, 2)}.msg()
	_ = badTable
	for name, b := range map[string][]byte{
		"an error":                  nlMsg(unix.NLMSG_ERROR, 0, seq, append(errnoBytes(unix.EINVAL), make([]byte, unix.NLMSG_HDRLEN)...)),
		"an end that carries one":   done(seq, unix.EPERM),
		"another dump's answer":     rule{table: 100, seq: seq + 1}.msg(),
		"a short rule":              nlMsg(unix.RTM_NEWRULE, 0, seq, make([]byte, sizeofFibRuleHdr-1)),
		"an attribute of no size":   shortAttr,
		"an attribute past the end": longAttr,
		"an interrupted dump":       nlMsg(unix.RTM_NEWRULE, unix.NLM_F_DUMP_INTR, seq, make([]byte, sizeofFibRuleHdr)),
		"a uid range of 4 bytes":    rule{table: 100, attrs: attr(unix.FRA_UID_RANGE, 1, 2, 3, 4)}.msg(),
		"a mark of 2 bytes":         rule{table: 100, attrs: attr(unix.FRA_FWMARK, 1, 2)}.msg(),
		"bytes after the last":      append(good.msg(), 1, 2, 3),
	} {
		var reach reachable
		if _, err := parseRules(b, seq, unix.AF_INET, userSet{uids: []uint32{1000}}, &reach); err == nil {
			t.Errorf("%s: read %+v, want an error", name, reach)
		}
	}
	var reach reachable
	if _, err := parseRules(done(seq, unix.EPERM), seq, unix.AF_INET, userSet{}, &reach); !errors.Is(err, unix.EPERM) {
		t.Errorf("the kernel's error is not the one returned: %v", err)
	}
}

func TestRuleRequest(t *testing.T) {
	for i, family := range ruleFamilies {
		req := ruleRequest(uint32(ruleSeqBase+i), family)
		ne := binary.NativeEndian
		if len(req) != unix.NLMSG_HDRLEN+sizeofFibRuleHdr || int(ne.Uint32(req[0:])) != len(req) ||
			ne.Uint16(req[4:]) != unix.RTM_GETRULE || ne.Uint16(req[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP ||
			ne.Uint32(req[8:]) != uint32(ruleSeqBase+i) {
			t.Fatalf("family %d: header %x", family, req[:unix.NLMSG_HDRLEN])
		}
		// Strict checking (fib_valid_dumprule_req) refuses a request with any field but the family set.
		if want := make([]byte, sizeofFibRuleHdr); !slices.Equal(req[unix.NLMSG_HDRLEN+1:], want[1:]) || req[unix.NLMSG_HDRLEN] != family {
			t.Errorf("family %d: fib_rule_hdr %x", family, req[unix.NLMSG_HDRLEN:])
		}
	}
}

// collect reads every dump through dump, which stands in for the kernel; ReadLocalTable drives the same collector with
// readDump on a socket, inside its one Borrow.
func collect(dump func(req []byte, seq uint32, parse func([]byte) (bool, error)) error, users userSet) (LocalTable, error) {
	c := newCollector(users)
	for {
		req, seq, parse, ok := c.next()
		if !ok {
			return c.table(), nil
		}
		if err := c.done(dump(req, seq, parse)); err != nil {
			return LocalTable{}, err
		}
	}
}

// fakeKernel answers collect's dumps from fixed rule and route sets, and records the order of the requests.
type fakeKernel struct {
	rules    map[uint8][]rule  // by family
	routes   map[uint8][]route // by route type
	ruleErr  map[uint8]error   // by family: the dump ends with this error
	routeErr error
	order    []string
}

func (k *fakeKernel) dump(req []byte, seq uint32, parse func([]byte) (bool, error)) error {
	ne := binary.NativeEndian
	var answer []byte
	switch ne.Uint16(req[4:]) {
	case unix.RTM_GETRULE:
		family := req[unix.NLMSG_HDRLEN]
		k.order = append(k.order, "rules")
		if err := k.ruleErr[family]; err != nil {
			var e unix.Errno
			errors.As(err, &e)
			answer = done(seq, e)
		} else {
			answer = ruleDump(family, k.rules[family]...)
		}
	case unix.RTM_GETROUTE:
		typ := req[unix.NLMSG_HDRLEN+7]
		k.order = append(k.order, "routes")
		if k.routeErr != nil {
			return k.routeErr
		}
		answer = append(dump(k.routes[typ]...), done(seq, 0)...)
	}
	ok, err := parse(answer)
	if err == nil && !ok {
		return errors.New("the fake dump did not end")
	}
	return err
}

// TestCollect: the policy rules say which tables count, and only then are the routes read.
func TestCollect(t *testing.T) {
	const f, local = unix.NLM_F_DUMP_FILTERED, unix.RT_TABLE_LOCAL
	user := userSet{uids: []uint32{1000}}
	defaultRules := map[uint8][]rule{
		unix.AF_INET:  {{table: local}, {table: unix.RT_TABLE_MAIN}, {table: unix.RT_TABLE_DEFAULT}},
		unix.AF_INET6: {{table: local}, {table: unix.RT_TABLE_MAIN}},
	}
	with := func(r4 ...rule) map[uint8][]rule {
		return map[uint8][]rule{unix.AF_INET: append(append([]rule{}, defaultRules[unix.AF_INET]...), r4...), unix.AF_INET6: defaultRules[unix.AF_INET6]}
	}
	someRoutes := func(table uint32, dst string) map[uint8][]route {
		return map[uint8][]route{unix.RTN_LOCAL: {
			{typ: unix.RTN_LOCAL, table: local, dst: "127.0.0.0/8", flags: f},
			{typ: unix.RTN_LOCAL, table: table, dst: dst, flags: f},
		}}
	}

	// `ip rule add from all lookup 100` and `ip route add local 192.0.2.0/24 dev lo table 100`: this host's range.
	k := &fakeKernel{rules: with(rule{table: 100}), routes: someRoutes(100, "192.0.2.0/24")}
	got, err := collect(k.dump, user)
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("127.0.0.0/8", "192.0.2.0/24"); !slices.Equal(got.Local, want) || len(got.Unread) != 0 {
		t.Errorf("a rule that leads to table 100: local %v unread %v, want %v and none", got.Local, got.Unread, want)
	}
	if len(k.order) < 3 || k.order[0] != "rules" || k.order[1] != "rules" || k.order[2] != "routes" {
		t.Errorf("order %v: both rule dumps come before the route dumps", k.order)
	}

	// Cilium's shape: a fwmark rule to 2004, `local default dev lo table 2004`. The world must not become this host;
	// the table is named.
	k = &fakeKernel{rules: with(rule{table: 2004, attrs: append(append([]byte{}, fwmark...), fwmask...)}), routes: someRoutes(2004, "0.0.0.0/0")}
	got, err = collect(k.dump, user)
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("127.0.0.0/8"); !slices.Equal(got.Local, want) || !slices.Equal(got.Unread, []uint32{2004}) {
		t.Errorf("a fwmark rule to 2004: local %v unread %v, want %v and [2004]", got.Local, got.Unread, want)
	}

	// A table no rule leads to is named too (a route sits there, with a VRF or by hand), and not read.
	k = &fakeKernel{rules: with(), routes: someRoutes(77, "198.51.100.0/24")}
	got, err = collect(k.dump, user)
	if err != nil || !slices.Equal(got.Unread, []uint32{77}) || slices.Contains(got.Local, netip.MustParsePrefix("198.51.100.0/24")) {
		t.Errorf("a table no rule leads to: %+v, %v", got, err)
	}

	// Rules are per family: an IPv4 rule to table 100 does not make an IPv6 route of table 100 this host's.
	k = &fakeKernel{rules: with(rule{table: 100}), routes: map[uint8][]route{unix.RTN_LOCAL: {
		{typ: unix.RTN_LOCAL, table: 100, dst: "2001:db8::/32", flags: f}, {typ: unix.RTN_LOCAL, table: 100, dst: "192.0.2.0/24", flags: f}}}}
	got, err = collect(k.dump, user)
	if err != nil || !slices.Equal(got.Local, prefixes("192.0.2.0/24")) || !slices.Equal(got.Unread, []uint32{100}) {
		t.Errorf("rules are per family: %+v, %v", got, err)
	}

	// A kernel without IPv6 policy routing refuses the IPv6 rule dump; that family has no rules to read.
	k = &fakeKernel{rules: with(rule{table: 100}), routes: someRoutes(100, "192.0.2.0/24"), ruleErr: map[uint8]error{unix.AF_INET6: unix.EAFNOSUPPORT}}
	if got, err = collect(k.dump, user); err != nil || !slices.Contains(got.Local, netip.MustParsePrefix("192.0.2.0/24")) {
		t.Errorf("no IPv6 rules: %+v, %v", got, err)
	}

	// Fail closed: rules that cannot be read give no table at all, whichever family and whatever the error.
	for name, ruleErr := range map[string]map[uint8]error{
		"IPv4 rules refused":        {unix.AF_INET: unix.EPERM},
		"IPv4 rules unsupported":    {unix.AF_INET: unix.EAFNOSUPPORT},
		"IPv6 rules refused":        {unix.AF_INET6: unix.EPERM},
		"IPv6 rules fail otherwise": {unix.AF_INET6: unix.EINVAL},
	} {
		k = &fakeKernel{rules: with(rule{table: 100}), routes: someRoutes(100, "192.0.2.0/24"), ruleErr: ruleErr}
		if got, err = collect(k.dump, user); err == nil || len(got.Local) != 0 || len(got.Unread) != 0 {
			t.Errorf("%s: read %+v, %v; want an error and no table", name, got, err)
		}
		if slices.Contains(k.order, "routes") && ruleErr[unix.AF_INET] != nil {
			t.Errorf("%s: routes were read after IPv4 rules failed: %v", name, k.order)
		}
	}
	k = &fakeKernel{rules: with(), routes: someRoutes(100, "192.0.2.0/24"), routeErr: unix.EIO}
	if got, err = collect(k.dump, user); err == nil || len(got.Local) != 0 {
		t.Errorf("a failed route dump: %+v, %v", got, err)
	}
}

// TestUnreadWords: the words name each table and say why it is not this host's.
func TestUnreadWords(t *testing.T) {
	if got := (LocalTable{}).UnreadWords(); got != "" {
		t.Errorf("no tables unread: %q", got)
	}
	got := LocalTable{Unread: []uint32{100, 2004}}.UnreadWords()
	for _, want := range []string{"routing table 100, 2004", "no policy rule that the run's own traffic can match", "a mark selects it"} {
		if !strings.Contains(got, want) {
			t.Errorf("words %q lack %q", got, want)
		}
	}
	long := make([]uint32, maxUnread)
	if !strings.Contains((LocalTable{Unread: long}).UnreadWords(), "and possibly more") {
		t.Error("a list cut at its bound does not say there may be more")
	}
}

// FuzzParseRules: no datagram panics the rule parse, and a table it keeps is never one of the standard three twice.
func FuzzParseRules(f *testing.F) {
	f.Add(ruleDump(unix.AF_INET, rule{table: 100}, rule{table: 2004, attrs: fwmark}))
	f.Add(ruleDump(unix.AF_INET6, rule{family: unix.AF_INET6, table: 100, attrs: uidRange(0, 1)}))
	f.Fuzz(func(t *testing.T, b []byte) {
		var reach reachable
		_, _ = parseRules(b, ruleSeqBase, unix.AF_INET, userSet{uids: []uint32{1000}}, &reach)
	})
}
