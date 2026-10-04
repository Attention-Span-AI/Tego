// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestLandlockPortRightsRetainTransportUnion(t *testing.T) {
	entries := []agent.NetRule{inet(443), inet(8443), inet(9000), inet(9000)}
	entries[0].Proto = agent.ProtoTCP
	entries[1].Proto = agent.ProtoUDP
	entries[2].Proto = agent.ProtoTCP
	entries[3].Proto = agent.ProtoUDP
	for _, abi := range []int{4, 10} {
		rt := &agent.RuleTable{Contract: contractWith(true, true), Net: entries}
		_, fake := prepare(t, abi, rt)
		tcp, udp, bind := uint64(accessNetConnectTCP), uint64(accessNetConnectSendUDP), uint64(accessNetBindUDP)
		want := []netCall{{tcp, 53, 0}, {tcp, 443, 0}, {tcp, 9000, 0}}
		if abi == 10 {
			want = []netCall{{bind, 0, 0}, {tcp | udp, 53, 0}, {tcp, 443, 0}, {udp, 8443, 0}, {tcp | udp, 9000, 0}}
		}
		if !reflect.DeepEqual(fake.nets, want) {
			t.Fatalf("ABI %d: %+v want %+v", abi, fake.nets, want)
		}
	}
}
