// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func (k *bpfKernel) networkGuarantees() backend.NetworkGuarantees {
	a := k.netAttached
	tcp := a[bpf.ProgConnect4] && a[bpf.ProgConnect6]
	flags := k.networkFlags
	packet := a[bpf.ProgNetIngress] && a[bpf.ProgNetEgress] && a[bpf.ProgNetSockOps] && a[bpf.ProgNetRelease]
	return backend.NetworkGuarantees{
		TCPDestination:     tcp,
		UDPDestination:     tcp && a[bpf.ProgSendmsg4] && a[bpf.ProgSendmsg6],
		UnixDestination:    a[bpf.ProgConnectUnix] && a[bpf.ProgSendmsgUnix],
		ListenerBind:       flags&bpf.NetControlListen != 0 && k.bindCleanup && k.listenCleanup && a[bpf.ProgBind4] && a[bpf.ProgBind6] && a[bpf.ProgPostBind4] && a[bpf.ProgPostBind6] && a[bpf.ProgNetSockOps] && a[bpf.ProgNetRelease],
		IngressSources:     flags&bpf.NetControlIngress != 0 && packet && a[bpf.ProgPostBind4] && a[bpf.ProgPostBind6],
		NetworkBytes:       flags&bpf.NetControlBytes != 0 && a[bpf.ProgNetEgress],
		NetworkDatagrams:   flags&bpf.NetControlDatagrams != 0 && a[bpf.ProgNetEgress],
		NetworkConnections: flags&bpf.NetControlConnections != 0 && packet,
		NetworkPending:     flags&bpf.NetControlPending != 0 && packet,
		SocketFamilies:     a[bpf.ProgSockCreate] && a[bpf.ProgSetsockopt],
	}
}

// NetworkGuarantees reports attachment facts for this prepared run, including
// optional Unix fallback hooks and the inherited strict client filter.
func (h *Handle) NetworkGuarantees() backend.NetworkGuarantees {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.detached || h.closed {
		return backend.NetworkGuarantees{}
	}
	g := h.programGuarantees()
	if h.plane != nil && h.plane.decidesUnix() {
		hooks := h.plane.hooks()
		g.UnixDestination = g.UnixDestination || hooks["socket_connect"] && hooks["socket_sendmsg"]
	}
	// The pre-listen kernel hook is necessary for implicit autobind. Explicit
	// Unix declarations additionally need the copied-name/actual-create hooks.
	if g.ListenerBind {
		if h.plane == nil {
			g.ListenerBind = false
		} else {
			hooks := h.plane.hooks()
			g.ListenerBind = hooks["socket_listen"]
			if h.table != nil {
				for _, r := range h.table.Listen {
					if r.Proto == "unix" {
						g.ListenerBind = g.ListenerBind && hooks["socket_bind"] && hooks["path_mknod"]
					}
				}
			}
		}
	}
	g.IngressSources = g.IngressSources && g.ListenerBind
	filterSockets := false
	if inherited, ok := h.inherited.(interface {
		NetworkGuarantees() backend.NetworkGuarantees
	}); ok {
		client := inherited.NetworkGuarantees()
		g.SocketImportsDenied, g.ListenersDenied = client.SocketImportsDenied, client.ListenersDenied
		filterSockets = client.SocketFamilies
	}
	// ADR 0018's socket bound (§5 R4, ADR 0018 (7)). The run's own programs are its kernel half (programGuarantees):
	// cgroup/sock_create decides every inet socket on any path to inet_create, and cgroup/setsockopt every TCP_ULP on
	// any path to the protocol's setsockopt, io_uring's SOCKET_URING_OP_SETSOCKOPT included, the one way a socket the
	// allowlist admitted is turned into another family in place. Without io_uring the inherited filter's socket arm
	// decides socket(2), socketpair(2) and setsockopt(2)'s TCP_ULP for every family. With io_uring admitted the filter
	// reports none, and only the plane's socket_create, which every path to __sock_create reaches, decides an
	// IORING_OP_SOCKET of any family. A contract with no net: section bounds no socket (SEMANTICS §1), whatever is
	// loaded.
	restricted := h.table != nil && h.table.NetSocketPolicy().Restricted
	planeSockets := h.plane != nil && h.plane.hooks()["socket_create"]
	g.SocketFamilies = restricted && g.SocketFamilies && (planeSockets || filterSockets)
	return g
}

// programGuarantees is what the run's cgroup programs alone guarantee, without the plane's unix hooks or the
// inherited filter (NetworkGuarantees adds those). The caller holds netMu.
func (h *Handle) programGuarantees() backend.NetworkGuarantees {
	if k, ok := h.kern.(interface {
		networkGuarantees() backend.NetworkGuarantees
	}); ok {
		return k.networkGuarantees()
	}
	return backend.NetworkGuarantees{}
}
