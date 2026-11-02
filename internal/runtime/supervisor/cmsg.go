// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"math"

	"golang.org/x/sys/unix"
)

// struct cmsghdr as the 64-bit kernel lays it out (size_t cmsg_len, int cmsg_level, int cmsg_type, then the data),
// the same on both supported architectures, and CMSG_ALIGN's unit there, sizeof(long).
const (
	cmsgHdrLen   = 16
	cmsgLevelOff = 8
	cmsgTypeOff  = 12
	cmsgAlignTo  = 8
)

// msgCtl is one message's control buffer as its msghdr names it: msg_control and msg_controllen.
type msgCtl struct{ ptr, len uint64 }

// ctlOf reads a msghdr's control buffer fields.
func ctlOf(hdr []byte) msgCtl {
	return msgCtl{ptr: leU64(hdr[msgControlOff:]), len: leU64(hdr[msgControlLenOff:])}
}

// routingControl reports whether a control message of level and typ gives a datagram a source route: SOL_IP's
// IP_RETOPTS, whose options block ip_options_get takes an LSRR or SSRR from (an unprivileged task's before Linux 7.1
// and its stable backports), and IP_OPTIONS, which ip_cmsg_send answers EINVAL as a control message and which is
// refused with it rather than rest on that; and SOL_IPV6's IPV6_RTHDR and IPV6_2292RTHDR, a routing header
// ip6_datagram_send_ctl takes from any task (type 2) and fl6_update_dst then sends the datagram to.
func routingControl(level, typ int32) bool {
	switch level {
	case unix.SOL_IP:
		return typ == unix.IP_RETOPTS || typ == unix.IP_OPTIONS
	case unix.SOL_IPV6:
		return typ == unix.IPV6_RTHDR || typ == unix.IPV6_2292RTHDR
	}
	return false
}

// controlRoutes walks a control buffer of total bytes as the kernel's for_each_cmsghdr does (CMSG_FIRSTHDR, then
// CMSG_NXTHDR while a whole header fits) and reports whether the send carries a route: a message routingControl
// names. b is what was read of the buffer, a prefix. A message CMSG_OK refuses (a cmsg_len shorter than its header
// or past the buffer's end) fails the whole send EINVAL in every protocol that reads these levels (udp_cmsg_send
// checks every message first; ip_cmsg_send and ip6_datagram_send_ctl stop at it), and nothing is sent, so it routes
// nothing. A walk that reaches the end of b before the end of the buffer is taken as a route: the kernel walks on
// into bytes this loop did not read.
func controlRoutes(b []byte, total uint64) bool {
	routes := false
	for off := uint64(0); off+cmsgHdrLen <= total; {
		if off+cmsgHdrLen > uint64(len(b)) {
			return true
		}
		n := leU64(b[off:])
		if n < cmsgHdrLen || n > total-off {
			return false
		}
		routes = routes || routingControl(int32(leU32(b[off+cmsgLevelOff:])), int32(leU32(b[off+cmsgTypeOff:])))
		off += (n + cmsgAlignTo - 1) &^ (cmsgAlignTo - 1)
	}
	return routes
}

// ctlRoutes reads one message's control buffer, at most msgControlMax bytes of it, and reports whether it routes
// (controlRoutes). The caller brackets the reads with ID_VALID (R2). A buffer shorter than one header holds no
// message (CMSG_FIRSTHDR), and ____sys_sendmsg refuses one past INT_MAX with ENOBUFS before it copies a byte:
// neither routes. A read that comes back short, at its first byte or part-way, a fault included, is taken as a
// route, the side that refuses (R5: an argument this loop cannot read is never continued on a guess): the kernel's
// own copy runs in the task's context, where a page this read faults on can be there by then (a sibling's mmap, a
// userfaultfd handler), so a fault here says nothing certain about what the kernel will copy.
func (l *Loop) ctlRoutes(r *reader, ctl msgCtl) bool {
	if ctl.len < cmsgHdrLen || ctl.len > math.MaxInt32 {
		return false
	}
	buf := r.scratch[:min(ctl.len, msgControlMax)]
	if got := r.read(ctl.ptr, buf); got < len(buf) {
		return true
	}
	return controlRoutes(buf, ctl.len)
}

// refusesRoute refuses a sendmsg or sendmmsg whose control messages give its datagram a source route, in a run whose
// contract has a net: section (R13b; GAPS C34), and reports whether it answered. ctls are the call's control buffers,
// one per message the kernel sends that carries one. udp_sendmsg, raw_sendmsg and ping_v4_sendmsg take the first hop
// from an IP_RETOPTS LSRR or SSRR (ipc.opt->opt.faddr), and udpv6_sendmsg and its raw and ping twins from an
// IPV6_RTHDR (fl6_update_dst), a socket connected or not, so the datagram went to an address in the route, which no
// entry admits and which neither this loop's decision nor the root tiers' sendmsg4/6 see: they read the destination.
// The message is refused, with R10's errno and rule relay-source-routed, on an IP socket that is not a stream one (the
// socket's own type and domain, read on the duplicate); TCP and SCTP read no message of these levels, and a unix
// socket none of either, so there the call goes on to its own decision. d is the destination the line names: the
// one the call carries, or none.
//
// The control buffer stays in the agent's memory until the kernel copies it, so the read is a snapshot, as R13b's
// address read is: a sibling thread can write a route into it between this read and the kernel's copy of a send
// this loop continues. It is best effort at every tier, the root tiers included, whose programs never see the
// control messages. A send this loop relays (under a net gate or the models[] guard) carries no ancillary data at
// all (ruleAncillary), so it is refused whatever the race. A contract with no net: section admits every IP
// destination, and is not read.
func (l *Loop) refusesRoute(n *notif, r *reader, sockfd int, d dest, ctls []msgCtl) bool {
	c := l.table.Load()
	if c.netOpen || len(ctls) == 0 {
		return false
	}
	if !l.valid(n) {
		return true // R19: gone, or failed closed by valid itself
	}
	routed := false
	for _, ctl := range ctls {
		if routed = l.ctlRoutes(r, ctl); routed {
			break
		}
	}
	if !l.valid(n) {
		return true // the bytes are only the target's if the notification is still the same one
	}
	if !routed {
		return false
	}
	t, why, ok := l.resolveSocket(n, c, sockfd)
	if !ok {
		if n.gone {
			return true
		}
		l.refuseNet(n, d, protoOf(0, 0, d), refuse(why))
		return true
	}
	defer l.closeDup(t.dup)
	if t.stream() || !l.ipSocket(&t) {
		return false
	}
	l.refuseNet(n, d, protoOf(t.sockType, t.sockProto, d), refuse(ruleSourceRouted))
	return true
}
