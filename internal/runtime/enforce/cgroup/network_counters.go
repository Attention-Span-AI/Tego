// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/cilium/ebpf"
)

// NetworkCountersSnapshot reads all shared counters under the kernel map's
// spinlock (BPF_F_LOCK), so a transfer from pending to accepted cannot be torn.
func (h *Handle) NetworkCountersSnapshot() (backend.NetworkCounters, error) {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.detached || h.closed {
		return backend.NetworkCounters{}, ErrNotPrepared
	}
	k, ok := h.kern.(*bpfKernel)
	if !ok || k.networkFlags == 0 {
		return networkCounters(0, bpf.NetStats{}, false, false), nil
	}
	m := k.maps[bpf.MapNetStats]
	if m == nil {
		return backend.NetworkCounters{}, fmt.Errorf("network counter map unavailable")
	}
	var stats bpf.NetStats
	if err := m.LookupWithFlags(&h.slot, &stats, ebpf.LookupLock); err != nil {
		return backend.NetworkCounters{}, fmt.Errorf("network counter snapshot: %w", err)
	}
	return networkCounters(k.networkFlags, stats, k.netAttached[bpf.ProgNetIngress], k.netAttached[bpf.ProgNetEgress]), nil
}

func networkCounters(flags uint32, s bpf.NetStats, ingress, egress bool) backend.NetworkCounters {
	connections := flags&(bpf.NetControlConnections|bpf.NetControlPending) != 0 && ingress && egress
	availability := map[string]bool{"bytes_in": ingress, "bytes_out": egress, "datagrams_in": ingress, "datagrams_out": egress,
		"connections_active": connections, "connections_pending": connections,
		"refusals_ingress": ingress, "refusals_bytes": egress && flags&bpf.NetControlBytes != 0,
		"refusals_datagrams":   egress && flags&bpf.NetControlDatagrams != 0,
		"refusals_connections": connections && flags&bpf.NetControlConnections != 0,
		"refusals_pending":     connections && flags&bpf.NetControlPending != 0}
	out := backend.NetworkCounters{Available: availability, Refusals: map[string]uint64{}}
	if ingress {
		out.BytesIn = &s.BytesIn
		out.DatagramsIn = &s.DatagramsIn
		out.Refusals["ingress"] = s.DeniedIngress
	}
	if egress {
		out.BytesOut = &s.Bytes
		out.DatagramsOut = &s.DatagramsOut
	}
	if connections {
		out.ConnectionsActive = &s.Connections
		out.ConnectionsPending = &s.Pending
	}
	for _, r := range []struct {
		name  string
		value uint64
	}{{"bytes", s.DeniedBytes}, {"datagrams", s.DeniedDatagrams}, {"connections", s.DeniedConnections}, {"pending", s.DeniedPending}} {
		if availability["refusals_"+r.name] {
			out.Refusals[r.name] = r.value
		}
	}
	return out
}

// BindOutcomes proves the actual result producer and copied-name listener
// plane needed for Unix bind terminal handoff, even under record:off.
func (h *Handle) BindOutcomes() bool {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.detached || h.closed || h.plane == nil || h.table == nil || h.table.Listen == nil {
		return false
	}
	k, ok := h.kern.(*bpfKernel)
	if !ok || !k.bindCleanup {
		return false
	}
	hooks := h.plane.hooks()
	return hooks["socket_bind"] && hooks["path_mknod"]
}

// ListenOutcomes proves actual terminal listener recording and bound-socket
// policy enforcement; tier selection alone never authorizes the handoff.
func (h *Handle) ListenOutcomes() bool {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.detached || h.closed || h.plane == nil || h.table == nil || h.table.Listen == nil {
		return false
	}
	k, ok := h.kern.(*bpfKernel)
	return ok && k.listenCleanup && h.plane.hooks()["socket_listen"]
}
