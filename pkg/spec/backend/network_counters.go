// SPDX-License-Identifier: Apache-2.0

package backend

// NetworkCounters is an atomic snapshot of the run's configured kernel
// network accounting. Nil values are unavailable, rather than measured zeros.
// Packet bytes include IP/transport headers and retransmissions, and count
// kernel admission before any later downstream queue loss. Packet/datagram
// totals and refusals are monotonic; connections are current reservations.
// ConnectionsActive includes pending TCP and socket-lifetime UDP reservations;
// ConnectionsPending includes conservative uncompleted inbound SYN reservations.
type NetworkCounters struct {
	Available          map[string]bool   `json:"available"`
	BytesIn            *uint64           `json:"bytes_in,omitempty"`
	BytesOut           *uint64           `json:"bytes_out,omitempty"`
	DatagramsIn        *uint64           `json:"datagrams_in,omitempty"`
	DatagramsOut       *uint64           `json:"datagrams_out,omitempty"`
	ConnectionsActive  *uint64           `json:"connections_active,omitempty"`
	ConnectionsPending *uint64           `json:"connections_pending,omitempty"`
	Refusals           map[string]uint64 `json:"refusals,omitempty"`
}
