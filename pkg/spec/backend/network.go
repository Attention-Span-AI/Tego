// SPDX-License-Identifier: Apache-2.0

package backend

// NetworkGuarantees reports mechanisms actually configured for this run.
// Optional fields require both the requested policy and its working attachments.
type NetworkGuarantees struct {
	TCPDestination      bool
	UDPDestination      bool
	UnixDestination     bool
	SocketImportsDenied bool
	ListenersDenied     bool
	ListenerBind        bool
	IngressSources      bool
	NetworkBytes        bool
	NetworkDatagrams    bool
	NetworkConnections  bool
	NetworkPending      bool
	// SocketFamilies is ADR 0018's bound under a net: section (CapSocketFamilies): every socket the run makes, or
	// turns another into with an upper-layer protocol (TCP_ULP, ADR 0018 (7)), is one the allowlist admits, decided in
	// the kernel on every path the run can take. False with no net: section.
	SocketFamilies bool
}
