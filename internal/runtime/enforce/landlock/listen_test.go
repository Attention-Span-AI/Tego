// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestListenerPortRightsAndLegacy(t *testing.T) {
	for _, abi := range []int{3, 4, 9, 10, 11} {
		for _, mode := range []string{"legacy", "empty", "explicit"} {
			t.Run(mode+"-"+strconv.Itoa(abi), func(t *testing.T) {
				rt := &agent.RuleTable{Contract: contractWith(true, true), Net: []agent.NetRule{{Proto: agent.ProtoTCP, Port: 8443}}}
				if mode == "empty" {
					rt.Listen = []agent.ListenRule{}
				}
				if mode == "explicit" {
					rt.Listen = []agent.ListenRule{{Raw: "tcp://127.0.0.1:9443", Proto: agent.ProtoTCP, Port: 9443}, {Raw: "udp://127.0.0.1:0", Proto: agent.ProtoUDP, Port: 0}, {Raw: "udp://127.0.0.1:9443", Proto: agent.ProtoUDP, Port: 9443}}
				}
				_, sc := prepare(t, abi, rt)
				got := map[uint64]uint64{}
				for _, rule := range sc.nets {
					got[rule.Port] |= rule.Access
				}
				wantBind := uint64(0)
				if mode == "explicit" && abi >= 4 {
					wantBind |= uint64(accessNetBindTCP)
				}
				if mode == "explicit" && abi >= 10 {
					wantBind |= uint64(accessNetBindUDP)
				}
				if got[9443] != wantBind {
					t.Fatalf("listener rights: got %#x want %#x", got[9443], wantBind)
				}
				wantEphemeral := uint64(0)
				if mode != "empty" && abi >= 10 {
					wantEphemeral = uint64(accessNetBindUDP)
				}
				if got[0] != wantEphemeral {
					t.Fatalf("ephemeral right: got %#x want %#x", got[0], wantEphemeral)
				}
				if mode != "explicit" {
					for _, access := range got {
						if access&uint64(accessNetBindTCP) != 0 {
							t.Fatal("legacy/empty TCP binds unexpectedly granted")
						}
					}
				}
			})
		}
	}
}

// TestPrepareNotifiesListenUnderANetSection: BIND_TCP is withheld with no tcp:// net.listen entry, but listen() on an
// unbound socket takes its port through the kernel's autobind, which never reaches security_socket_bind. So the filter
// of every net: section hands listen to the supervisor, a listener policy or none (R6), and a contract with no net:
// section keeps the kernel's: it decides nothing about a listener, and the unix-only state notifies bind alone.
func TestPrepareNotifiesListenUnderANetSection(t *testing.T) {
	arch := NativeArch()
	tab, err := tableFor(arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		rt     *agent.RuleTable
		notify bool
	}{
		{"net section, no listener policy", &agent.RuleTable{Contract: contractWith(true, true)}, true},
		{"net section, listen: []", &agent.RuleTable{Contract: contractWith(true, true), Listen: []agent.ListenRule{}}, true},
		{"net section, a declared listener", &agent.RuleTable{Contract: contractWith(true, true),
			Listen: []agent.ListenRule{{Raw: "tcp://127.0.0.1:9443", Proto: agent.ProtoTCP, Port: 9443}}}, true},
		{"no net section", &agent.RuleTable{Contract: contractWith(true, false)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := prepare(t, 7, tc.rt)
			want := uint32(retAllow)
			if tc.notify {
				want = retNotify
			}
			if got := planeVerdict(t, arch, h.filterOpts, tab.Listen, 3, 8); got != want {
				t.Fatalf("listen answered %#x, want %#x", got, want)
			}
		})
	}
}
