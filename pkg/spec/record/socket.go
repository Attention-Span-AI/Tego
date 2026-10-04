// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strconv"
	"strings"
)

// SocketTriple names a socket's family, type and protocol for a refused socket line's target: the symbolic name
// where the family or type is a common one, the number always, e.g. "AF_INET SOCK_STREAM protocol 132". Tier 2's
// supervisor and tier 3's plane both write it, so one refused socket reads the same from either and drift
// matching pairs them. The numbers are Linux's (the package imports the standard library only).
func SocketTriple(family, typ, proto int32) string {
	fam, ok := socketFamilies[family]
	if !ok {
		fam = "family " + strconv.Itoa(int(family))
	}
	t, ok := socketTypes[typ&0xf]
	if !ok {
		t = "type " + strconv.Itoa(int(typ&0xf))
	}
	return fam + " " + t + " protocol " + strconv.Itoa(int(proto))
}

// TCPULPNameMax is the longest TCP upper-layer-protocol name the kernel reads from setsockopt(TCP_ULP)'s value:
// TCP_ULP_NAME_MAX (16) less its NUL.
const TCPULPNameMax = 15

// SocketOption names a refused setsockopt for its line's target (ADR 0018 (7)): `TCP_ULP "smc"` for SOL_TCP's
// TCP_ULP, with the name as the kernel reads it, up to the first NUL and at most TCPULPNameMax bytes, quoted;
// "TCP_ULP (name unread)" when read is false, the name not readable; any other option by its numbers. The supervisor
// (from the agent's memory) and cgroup/setsockopt (from the kernel's copy) both write it, so one refusal reads the same
// from either.
func SocketOption(level, option int32, name []byte, read bool) string {
	if level != 6 || option != 31 {
		return "setsockopt level " + strconv.Itoa(int(level)) + " option " + strconv.Itoa(int(option))
	}
	if !read {
		return "TCP_ULP (name unread)"
	}
	if len(name) > TCPULPNameMax {
		name = name[:TCPULPNameMax]
	}
	for i, b := range name {
		if b == 0 {
			name = name[:i]
			break
		}
	}
	return "TCP_ULP " + strconv.Quote(string(name))
}

var socketFamilies = map[int32]string{
	0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 10: "AF_INET6", 16: "AF_NETLINK", 17: "AF_PACKET", 30: "AF_TIPC",
	40: "AF_VSOCK", 21: "AF_RDS", 43: "AF_SMC", 44: "AF_XDP", 38: "AF_ALG", 31: "AF_BLUETOOTH", 29: "AF_CAN",
	41: "AF_KCM", 42: "AF_QIPCRTR",
}

var socketTypes = map[int32]string{
	1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM", 5: "SOCK_SEQPACKET", 6: "SOCK_DCCP",
	10: "SOCK_PACKET",
}

// SocketFamilyNumber reads a family as SocketTriple spells it ("AF_INET", any case) back into its number; ok is
// false for a name SocketTriple does not print.
func SocketFamilyNumber(name string) (int32, bool) { return numberOf(socketFamilies, name) }

// SocketTypeNumber reads a socket type as SocketTriple spells it ("SOCK_STREAM", any case) back into its number.
func SocketTypeNumber(name string) (int32, bool) { return numberOf(socketTypes, name) }

func numberOf(names map[int32]string, name string) (int32, bool) {
	for n, s := range names {
		if strings.EqualFold(s, name) {
			return n, true
		}
	}
	return 0, false
}
