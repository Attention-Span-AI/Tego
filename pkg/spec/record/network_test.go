// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestRunEndNetworkCountersRemainAdditiveInV1(t *testing.T) {
	t.Parallel()
	if Version != 1 || Minor < MinorNetworkControl || MinorNetworkControl != 5 {
		t.Fatal("network accounting must remain the optional minor-5 extension of v1")
	}
	legacy := `{"reason":"exit","supervisor":{"notifications":1,"held_ms":0}}`
	var end RunEndPayload
	if err := json.Unmarshal([]byte(legacy), &end); err != nil {
		t.Fatal(err)
	}
	if end.Network != nil {
		t.Fatal("legacy run end invented network measurements")
	}
	encoded, err := json.Marshal(end)
	if err != nil || string(encoded) != legacy {
		t.Fatalf("legacy run end changed: %s, %v", encoded, err)
	}
	zero, largest := uint64(0), uint64(math.MaxUint64)
	end.Network = &backend.NetworkCounters{
		Available: map[string]bool{"bytes_in": true, "bytes_out": false, "connections_active": true, "refusals_ingress": true},
		BytesIn:   &zero, ConnectionsActive: &largest, Refusals: map[string]uint64{"ingress": 0},
	}
	e := base(KindRunEnd, "")
	if err := e.SetPayload(end); err != nil {
		t.Fatal(err)
	}
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	var back RunEndPayload
	if err := decoded.DecodePayload(&back); err != nil {
		t.Fatal(err)
	}
	n := back.Network
	if n == nil || n.BytesIn == nil || *n.BytesIn != 0 || n.BytesOut != nil || n.DatagramsIn != nil ||
		n.ConnectionsActive == nil || *n.ConnectionsActive != math.MaxUint64 || n.ConnectionsPending != nil ||
		!n.Available["bytes_in"] || n.Available["bytes_out"] {
		t.Fatalf("unknown/zero/full-width accounting was lost: %+v", n)
	}
	if refused, present := n.Refusals["ingress"]; !present || refused != 0 {
		t.Fatal("measured zero refusal was omitted")
	}
	var fields struct {
		Network map[string]json.RawMessage `json:"network"`
	}
	if err := json.Unmarshal(decoded.Payload, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields.Network["bytes_in"]) != "0" || string(fields.Network["connections_active"]) != "18446744073709551615" {
		t.Fatalf("counters were rounded or omitted: %s", decoded.Payload)
	}
	if _, present := fields.Network["bytes_out"]; present {
		t.Fatal("unavailable byte count was serialized as a measurement")
	}
}
