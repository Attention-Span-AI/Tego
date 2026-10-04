// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
)

func TestNetworkCountersDistinguishUnavailableAndMeasuredZero(t *testing.T) {
	missing := networkCounters(0, bpf.NetStats{}, false, false)
	if missing.BytesIn != nil || missing.BytesOut != nil || missing.DatagramsOut != nil || missing.ConnectionsActive != nil || len(missing.Refusals) != 0 {
		t.Fatalf("fabricated zero measurements: %+v", missing)
	}
	s := bpf.NetStats{Bytes: 123, BytesIn: 456, Datagrams: 2, DatagramsOut: 19, DatagramsIn: 20, Connections: 3, Pending: 1, DeniedBytes: 4}
	got := networkCounters(bpf.NetControlBytes|bpf.NetControlPending, s, true, true)
	if got.BytesIn == nil || *got.BytesIn != 456 || got.BytesOut == nil || *got.BytesOut != 123 || got.DatagramsOut == nil || *got.DatagramsOut != 19 || *got.ConnectionsActive != 3 || *got.ConnectionsPending != 1 || got.Refusals["bytes"] != 4 || got.Available["refusals_connections"] {
		t.Fatalf("wrong units/availability: %+v", got)
	}
	zero := networkCounters(bpf.NetControlBytes, bpf.NetStats{}, false, true)
	if zero.BytesOut == nil || *zero.BytesOut != 0 || zero.DatagramsOut == nil || zero.BytesIn != nil {
		t.Fatalf("lost measured zero: %+v", zero)
	}
}
