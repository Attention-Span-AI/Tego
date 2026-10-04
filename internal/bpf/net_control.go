// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"structs"
	"time"
)

// Network control objects are private to cgroup_net. Flags distinguish an
// absent compatibility policy from an explicit zero ceiling or empty list.
const (
	NetControlListen uint32 = 1 << iota
	NetControlIngress
	NetControlBytes
	NetControlDatagrams
	NetControlConnections
	NetControlPending
)

const (
	MapNetControl       = "tego_net_control"
	MapBindExact        = "tego_bind_exact"
	MapIngress          = "tego_net_ingress"
	MapNetFlows         = "tego_net_flows"
	MapNetStats         = "tego_net_stats"
	MapNetSockets       = "tego_net_sockets"
	MapNetBinds         = "tego_net_binds"
	MapBindPending      = "tego_bind_pending"
	MapNetPending       = "tego_net_pending"
	MapConnectApprovals = "tego_connect_approvals"
	ProgNetIngress      = "tego_cg_ingress"
	ProgNetEgress       = "tego_cg_egress"
	ProgNetSockOps      = "tego_cg_sockops"
	ProgNetRelease      = "tego_cg_release"
	ProgPostBind4       = "tego_cg_post_bind4"
	ProgPostBind6       = "tego_cg_post_bind6"
	NetFlowCapacity     = 16384
	NetSocketCapacity   = 65536
	IngressHeaderBits   = 224 // run index, listener index, family, protocol, local port/address
	IngressMaxBits      = IngressHeaderBits + 128
)

var NetControlMaps = []string{MapNetControl, MapBindExact, MapIngress, MapNetFlows, MapNetStats, MapNetSockets, MapNetBinds, MapBindPending, MapNetPending, MapConnectApprovals}
var NetControlPrograms = []string{ProgNetIngress, ProgNetEgress, ProgNetSockOps, ProgNetRelease, ProgPostBind4, ProgPostBind6}

// NetControl is struct tego_net_control. Gen prevents stale socket state from
// a dead launcher being mistaken for the next occupant of the same dense slot.
type NetControl struct {
	_                                                       structs.HostLayout
	Flags, Gen                                              uint32
	Bytes, DatagramsPerSecond, Connections, PendingConnects uint64
}

// IngressKey is a longest-prefix source key scoped to one declared listener.
type IngressKey struct {
	_                           structs.HostLayout
	PrefixLen, RunIdx, BindRule uint32
	Family, Proto               uint8
	Port                        uint16
	Local                       [16]byte
	Addr                        [16]byte
}

// NetFlowKey has local/remote ordering in both directions; no payload content
// is stored. A tuple created by outgoing delivery admits only its exact reply.
type NetFlowKey struct {
	_                          structs.HostLayout
	RunIdx, Gen                uint32
	Family, Proto              uint8
	LocalPort, RemotePort, Pad uint16
	Local, Remote              [16]byte
}

// NetReservation is struct tego_net_reservation, MapNetPending's value: an inbound SYN's reservation and the
// kernel timer that expires it after NetSYNReservation (bpf-1). Userspace only deletes these rows.
type NetReservation struct {
	_      structs.HostLayout
	Phase  uint64
	Cookie uint64
	Timer  [2]uint64
}

// NetSYNReservation is TEGO_NET_SYN_RESERVATION_NS: how long an admitted inbound SYN may hold its connection and
// pending reservation without completing its handshake.
const NetSYNReservation = 75 * time.Second

type NetFlow struct {
	_         structs.HostLayout
	ExpiresNS uint64
	Cookie    uint64
	Phase     uint64
	Inbound   uint8
	Pad       [7]uint8
}

type NetSocketKey struct {
	_           structs.HostLayout
	RunIdx, Gen uint32
	Cookie      uint64
}

type NetSocket struct {
	_       structs.HostLayout
	Phase   uint64 // 0 reserving, 1 pending, 2 established/UDP, 3 refused
	Inbound uint32
	Pad     uint32
	Flow    NetFlowKey
}

type BindAttemptKey struct {
	_      structs.HostLayout
	Socket NetSocketKey
	Task   uint64
}

type ConnectApprovalKey struct {
	_             structs.HostLayout
	RunIdx, Gen   uint32
	Cookie        uint64
	Family, Proto uint8
	Port          uint16
	Addr          [16]byte
	Pad           uint32
}

type ConnectCredit struct {
	_          structs.HostLayout
	Credit     uint64
	DeadlineNS uint64
}

// NetStats includes the kernel spinlock field, which is always zero in values
// read or initialized by userspace. Counters are shared across CPUs and bounded.
type NetStats struct {
	_                                                                             structs.HostLayout
	Lock, Pad                                                                     uint32
	Bytes, WindowNS, Datagrams, Connections, Pending                              uint64
	DeniedIngress, DeniedBytes, DeniedDatagrams, DeniedConnections, DeniedPending uint64
	BytesIn, DatagramsIn, DatagramsOut                                            uint64
}
