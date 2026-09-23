// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"unsafe"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

// TestAddr16 covers the three shapes a compiled rule can carry: a plain IPv4 address, an explicitly
// IPv4-mapped IPv6 address, and a native IPv6 address.
func TestAddr16(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		addr   string
		family uint8
		first  []byte
	}{
		{"v4", "203.0.113.7", AFInet, []byte{203, 0, 113, 7}},
		{"v4-zero", "0.0.0.0", AFInet, []byte{0, 0, 0, 0}},
		{"v4-mapped", "::ffff:203.0.113.7", AFInet6, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7}},
		{"v6", "2001:db8::1", AFInet6, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"v6-loopback", "::1", AFInet6, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, family, err := Addr16(mustAddr(t, tc.addr))
			if err != nil {
				t.Fatalf("Addr16: %v", err)
			}
			if family != tc.family {
				t.Fatalf("family = %d, want %d", family, tc.family)
			}
			for i, b := range tc.first {
				if raw[i] != b {
					t.Fatalf("byte %d = %#x, want %#x (%v)", i, raw[i], b, raw)
				}
			}
			for i := len(tc.first); i < 16; i++ {
				if raw[i] != 0 {
					t.Fatalf("byte %d = %#x, want 0 padding", i, raw[i])
				}
			}
			back, err := AddrFrom(family, raw)
			if err != nil {
				t.Fatalf("AddrFrom: %v", err)
			}
			if want := mustAddr(t, tc.addr); back.Compare(want) != 0 {
				t.Fatalf("round trip = %s, want %s", back, want)
			}
		})
	}
}

// TestAddr16Invalid asserts an unusable address is an error and never a silently zero key.
func TestAddr16Invalid(t *testing.T) {
	t.Parallel()
	if _, _, err := Addr16(netip.Addr{}); !errors.Is(err, ErrFamily) {
		t.Fatalf("Addr16(zero) = %v, want ErrFamily", err)
	}
	if _, err := AddrFrom(99, [16]byte{}); !errors.Is(err, ErrFamily) {
		t.Fatalf("AddrFrom(99) = %v, want ErrFamily", err)
	}
}

// TestNewNetKey builds the exact key the C side builds, including the host-order port.
func TestNewNetKey(t *testing.T) {
	t.Parallel()
	k, err := NewNetKey(7, ProtoTCP, mustAddr(t, "198.51.100.9"), 443)
	if err != nil {
		t.Fatalf("NewNetKey: %v", err)
	}
	if k.RunIdx != 7 || k.Family != AFInet || k.Proto != ProtoTCP || k.Port != 443 {
		t.Fatalf("key header wrong: %+v", k)
	}
	if k.Addr[0] != 198 || k.Addr[3] != 9 {
		t.Fatalf("addr wrong: %v", k.Addr)
	}
	if _, err := NewNetKey(MaxSlots, ProtoTCP, mustAddr(t, "198.51.100.9"), 443); !errors.Is(err, ErrSlot) {
		t.Fatalf("slot %d accepted, want ErrSlot", MaxSlots)
	}
}

// TestNetKeysDualStack pins the reason a v4 rule produces two rows: the kernel dispatches a connect by the
// socket's family, so a dual-stack socket reaching 198.51.100.9 arrives at connect6 with the mapped address.
func TestNetKeysDualStack(t *testing.T) {
	t.Parallel()
	keys, err := NetKeys(3, ProtoTCP, mustAddr(t, "198.51.100.9"), 8080)
	if err != nil {
		t.Fatalf("NetKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("v4 rule produced %d keys, want 2", len(keys))
	}
	if keys[0].Family != AFInet || keys[1].Family != AFInet6 {
		t.Fatalf("families = %d,%d want %d,%d", keys[0].Family, keys[1].Family, AFInet, AFInet6)
	}
	if keys[1].Addr[10] != 0xff || keys[1].Addr[11] != 0xff || keys[1].Addr[15] != 9 {
		t.Fatalf("mapped address wrong: %v", keys[1].Addr)
	}
	v6, err := NetKeys(3, ProtoTCP, mustAddr(t, "2001:db8::1"), 8080)
	if err != nil {
		t.Fatalf("NetKeys v6: %v", err)
	}
	if len(v6) != 1 {
		t.Fatalf("v6 rule produced %d keys, want 1", len(v6))
	}
}

// TestLPMPrefixLen walks every IPv4 and IPv6 width plus the two out-of-range cases.
func TestLPMPrefixLen(t *testing.T) {
	t.Parallel()
	for bits := 0; bits <= 128; bits++ {
		got, err := LPMPrefixLen(bits)
		if err != nil {
			t.Fatalf("LPMPrefixLen(%d): %v", bits, err)
		}
		if want := uint32(LPMHeaderBits + bits); got != want {
			t.Fatalf("LPMPrefixLen(%d) = %d, want %d", bits, got, want)
		}
		if got > LPMMaxBits {
			t.Fatalf("LPMPrefixLen(%d) = %d exceeds LPMMaxBits %d", bits, got, LPMMaxBits)
		}
	}
	for _, bad := range []int{-1, 129, 1 << 20} {
		if _, err := LPMPrefixLen(bad); !errors.Is(err, ErrPrefix) {
			t.Fatalf("LPMPrefixLen(%d) = %v, want ErrPrefix", bad, err)
		}
	}
}

// TestNewNetLPMKey checks masking and prefix arithmetic across the widths a contract can declare.
func TestNewNetLPMKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		prefix    string
		prefixLen uint32
		family    uint8
		addr0     byte
	}{
		{"v4-slash-0", "0.0.0.0/0", LPMHeaderBits, AFInet, 0},
		{"v4-slash-8", "10.0.0.0/8", LPMHeaderBits + 8, AFInet, 10},
		{"v4-slash-24", "192.0.2.0/24", LPMHeaderBits + 24, AFInet, 192},
		{"v4-slash-32", "192.0.2.5/32", LPMHeaderBits + 32, AFInet, 192},
		{"v6-slash-0", "::/0", LPMHeaderBits, AFInet6, 0},
		{"v6-slash-48", "2001:db8:1::/48", LPMHeaderBits + 48, AFInet6, 0x20},
		{"v6-slash-128", "2001:db8::1/128", LPMHeaderBits + 128, AFInet6, 0x20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := NewNetLPMKey(1, ProtoTCP, mustPrefix(t, tc.prefix), 53)
			if err != nil {
				t.Fatalf("NewNetLPMKey: %v", err)
			}
			if k.PrefixLen != tc.prefixLen {
				t.Fatalf("prefixlen = %d, want %d", k.PrefixLen, tc.prefixLen)
			}
			if k.Family != tc.family {
				t.Fatalf("family = %d, want %d", k.Family, tc.family)
			}
			if k.Addr[0] != tc.addr0 {
				t.Fatalf("addr[0] = %#x, want %#x", k.Addr[0], tc.addr0)
			}
		})
	}
}

// TestNewNetLPMKeyMasks asserts two spellings of one network produce one key, so an unmasked declaration
// cannot create a second row that shadows the first.
func TestNewNetLPMKeyMasks(t *testing.T) {
	t.Parallel()
	a, err := NewNetLPMKey(2, ProtoTCP, mustPrefix(t, "192.0.2.77/24"), 443)
	if err != nil {
		t.Fatalf("NewNetLPMKey: %v", err)
	}
	b, err := NewNetLPMKey(2, ProtoTCP, mustPrefix(t, "192.0.2.0/24"), 443)
	if err != nil {
		t.Fatalf("NewNetLPMKey: %v", err)
	}
	if a != b {
		t.Fatalf("unmasked %+v != masked %+v", a, b)
	}
}

// TestNetLPMKeysDualStack pins the mapped-prefix arithmetic: an IPv4 /24 becomes a /120 under ::ffff:0:0/96.
func TestNetLPMKeysDualStack(t *testing.T) {
	t.Parallel()
	keys, err := NetLPMKeys(1, ProtoTCP, mustPrefix(t, "192.0.2.0/24"), 443)
	if err != nil {
		t.Fatalf("NetLPMKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].PrefixLen != LPMHeaderBits+24 {
		t.Fatalf("v4 prefixlen = %d", keys[0].PrefixLen)
	}
	if keys[1].PrefixLen != LPMHeaderBits+120 {
		t.Fatalf("mapped prefixlen = %d, want %d", keys[1].PrefixLen, LPMHeaderBits+120)
	}
	if keys[1].Addr[10] != 0xff || keys[1].Addr[11] != 0xff || keys[1].Addr[12] != 192 {
		t.Fatalf("mapped addr = %v", keys[1].Addr)
	}
}

// TestNetLPMKeysInvalid covers the two rejected inputs.
func TestNetLPMKeysInvalid(t *testing.T) {
	t.Parallel()
	if _, err := NewNetLPMKey(0, ProtoTCP, netip.Prefix{}, 1); !errors.Is(err, ErrPrefix) {
		t.Fatalf("zero prefix accepted")
	}
	if _, err := NewNetLPMKey(MaxSlots+1, ProtoTCP, mustPrefix(t, "10.0.0.0/8"), 1); !errors.Is(err, ErrSlot) {
		t.Fatalf("out-of-range slot accepted")
	}
}

// TestLPMMatches models the trie's answer in userspace: longest prefix wins, a differing header never
// matches, and /0 matches everything of the same family (§5 R3, §6 E8).
func TestLPMMatches(t *testing.T) {
	t.Parallel()
	lookup, err := LookupLPMKey(4, ProtoTCP, mustAddr(t, "192.0.2.130"), 443)
	if err != nil {
		t.Fatalf("LookupLPMKey: %v", err)
	}
	if lookup.PrefixLen != LPMMaxBits {
		t.Fatalf("lookup prefixlen = %d, want %d", lookup.PrefixLen, LPMMaxBits)
	}
	cases := []struct {
		prefix string
		port   uint16
		run    uint32
		proto  uint8
		want   bool
	}{
		{"0.0.0.0/0", 443, 4, ProtoTCP, true},
		{"192.0.2.0/24", 443, 4, ProtoTCP, true},
		{"192.0.2.128/25", 443, 4, ProtoTCP, true},
		{"192.0.2.0/25", 443, 4, ProtoTCP, false},
		{"192.0.2.130/32", 443, 4, ProtoTCP, true},
		{"192.0.2.131/32", 443, 4, ProtoTCP, false},
		{"192.0.2.0/24", 80, 4, ProtoTCP, false},
		{"192.0.2.0/24", 443, 5, ProtoTCP, false},
		{"192.0.2.0/24", 443, 4, ProtoUDP, false},
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			stored, err := NewNetLPMKey(tc.run, tc.proto, mustPrefix(t, tc.prefix), tc.port)
			if err != nil {
				t.Fatalf("NewNetLPMKey: %v", err)
			}
			if got := stored.Matches(lookup); got != tc.want {
				t.Fatalf("%s port %d run %d proto %d: match = %v, want %v", tc.prefix, tc.port, tc.run, tc.proto, got, tc.want)
			}
		})
	}
}

// TestLPMMatchesRejectsBadPrefixLen guards the model against a corrupt stored key.
func TestLPMMatchesRejectsBadPrefixLen(t *testing.T) {
	t.Parallel()
	lookup, err := LookupLPMKey(0, ProtoTCP, mustAddr(t, "10.0.0.1"), 1)
	if err != nil {
		t.Fatalf("LookupLPMKey: %v", err)
	}
	for _, bad := range []uint32{0, LPMHeaderBits - 1, LPMMaxBits + 1} {
		k := lookup
		k.PrefixLen = bad
		if k.Matches(lookup) {
			t.Fatalf("prefixlen %d matched", bad)
		}
	}
}

// TestUnixKeyMarshalsPacked pins what the kernel receives for a UnixKey. struct tego_unix_key is packed, 118
// bytes; Go pads UnixKey to 120 after Name, so cilium/ebpf cannot use its memory as is and encodes it field by
// field (encoding/binary), which is the packed layout. A field that needed padding before Name would shift
// every name byte the trie compares.
func TestUnixKeyMarshalsPacked(t *testing.T) {
	t.Parallel()
	k, err := UnixPathKey(3, "/run/pg.sock", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.Size(k); got != 4+4+1+1+UnixNameMax {
		t.Fatalf("binary size %d, want the packed %d", got, 4+4+1+1+UnixNameMax)
	}
	var mine UnixKey
	if off := unsafe.Offsetof(mine.Name); off != 10 || off+UnixNameMax != 118 {
		t.Fatalf("Name at %d; the padding Go adds must trail the struct", off)
	}
	b, err := binary.Append(nil, binary.NativeEndian, k)
	if err != nil {
		t.Fatal(err)
	}
	if b[8] != UnixPath || b[9] != 0 || string(b[10:23]) != "/run/pg.sock\x00" {
		t.Fatalf("encoded key = %q", b[:24])
	}
	if want := uint32(UnixHeaderBits + 8*len("/run/pg.sock\x00")); k.PrefixLen != want {
		t.Fatalf("prefixlen %d, want %d", k.PrefixLen, want)
	}
}

// TestUnixApprovalLayout pins MapUnixApprovals' row (struct tego_unix_approval_key, struct tego_unix_credit):
// a 16-byte key, a 136-byte value with the approved name's kind, length and bytes at offsets 24, 25 and 26, as
// tego_unix_approved reads them, and no Go padding, so cilium/ebpf hands the kernel UnixCredit's memory as it is.
// A row is refused for no gen, no cookie, a slot past MaxSlots and a name no abstract key holds.
func TestUnixApprovalLayout(t *testing.T) {
	t.Parallel()
	k, v, err := UnixApproval(3, 7, 0xfeed, []byte("bus"), 99)
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Sizeof(k) != 16 || binary.Size(k) != 16 || unsafe.Sizeof(v) != 136 || binary.Size(v) != 136 {
		t.Fatalf("sizes key %d/%d value %d/%d, want 16 and 136", unsafe.Sizeof(k), binary.Size(k), unsafe.Sizeof(v), binary.Size(v))
	}
	if unsafe.Offsetof(v.Kind) != 24 || unsafe.Offsetof(v.Len) != 25 || unsafe.Offsetof(v.Name) != 26 {
		t.Fatalf("name fields at %d %d %d", unsafe.Offsetof(v.Kind), unsafe.Offsetof(v.Len), unsafe.Offsetof(v.Name))
	}
	if k != (UnixApprovalKey{RunIdx: 3, Gen: 7, Cookie: 0xfeed}) || v.Credit != 1 || v.DeadlineNS != 99 ||
		v.Kind != UnixAbstract || v.Len != 4 || string(v.Name[:4]) != "\x00bus" || v.Name[4] != 0 {
		t.Fatalf("row %+v %+v", k, v)
	}
	for _, bad := range []struct {
		slot, gen uint32
		cookie    uint64
		name      string
	}{{MaxSlots, 7, 1, "bus"}, {3, 0, 1, "bus"}, {3, 7, 0, "bus"}, {3, 7, 1, ""}, {3, 7, 1, strings.Repeat("x", UnixNameMax)}} {
		if _, _, err := UnixApproval(bad.slot, bad.gen, bad.cookie, []byte(bad.name), 1); err == nil {
			t.Errorf("UnixApproval(%d, %d, %d, %d bytes) made a row", bad.slot, bad.gen, bad.cookie, len(bad.name))
		}
	}
}

// TestUnixKeysMatchLikeTheTrie checks the row shapes against the lookup the programs build, through the
// trie's own rule (Matches): an exact row matches its name and nothing longer, a subtree row matches only at
// a component boundary, the root covers every absolute name, an abstract row matches only its own length, a
// path that fills sun_path gets an exact row without a NUL, and nothing longer gets a row at all (§5 R7).
func TestUnixKeysMatchLikeTheTrie(t *testing.T) {
	t.Parallel()
	must := func(k UnixKey, err error) UnixKey {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	look := func(sun string) UnixKey { return must(LookupUnixKey(0, []byte(sun))) }
	exact := must(UnixPathKey(0, "/tmp/work", false))
	sub := must(UnixPathKey(0, "/tmp/work", true))
	root := must(UnixPathKey(0, "/", true))
	abs := must(UnixAbstractKey(0, []byte("bus\x00x")))
	full := "/" + strings.Repeat("f", UnixNameMax-1)
	fullKey := must(UnixPathKey(0, full, false))
	cases := []struct {
		row  UnixKey
		sun  string
		want bool
	}{
		{exact, "/tmp/work", true},
		{exact, "/tmp/work\x00junk", true},
		{exact, "/tmp/work/x", false},
		{exact, "/tmp/workshop", false},
		{sub, "/tmp/work/x.sock", true},
		{sub, "/tmp/work", false},
		{sub, "/tmp/workshop/x.sock", false},
		{root, "/any", true},
		{root, "rel/x", false},
		{abs, "\x00bus\x00x", true},
		{abs, "\x00bus\x00", false},
		{abs, "\x00bus\x00xy", false},
		{abs, "/bus", false},
		{fullKey, full, true},
		{must(UnixPathKey(1, "/tmp/work", false)), "/tmp/work", false}, // another run's row
	}
	for _, tc := range cases {
		if got := tc.row.Matches(look(tc.sun)); got != tc.want {
			t.Errorf("row %q/%d matches %q = %v, want %v", tc.row.Name[:tc.row.PrefixLen/8-6], tc.row.PrefixLen, tc.sun, got, tc.want)
		}
	}
	if _, err := UnixPathKey(0, full+"g", false); !errors.Is(err, ErrUnixName) {
		t.Errorf("a path longer than sun_path got a row: %v", err)
	}
	if _, err := UnixPathKey(0, full, true); !errors.Is(err, ErrUnixName) {
		t.Errorf("a subtree no name fits under got a row: %v", err)
	}
	for _, bad := range []string{"rel/x", "", "/a\x00b"} {
		if _, err := UnixPathKey(0, bad, false); !errors.Is(err, ErrUnixName) {
			t.Errorf("UnixPathKey(%q) = %v, want ErrUnixName", bad, err)
		}
	}
	if _, err := UnixAbstractKey(0, nil); !errors.Is(err, ErrUnixName) {
		t.Errorf("an empty abstract name got a row")
	}
	if _, err := UnixPathKey(MaxSlots, "/x", false); !errors.Is(err, ErrSlot) {
		t.Errorf("a slot out of range got a row")
	}
}
