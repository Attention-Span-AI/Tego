// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// lpmVerdict is the trie's answer for one lookup over the built rows: the longest matching prefix.
func lpmVerdict(rows []CIDRRow, k bpf.NetLPMKey) (bpf.NetVerdict, bool) {
	best, ok := bpf.NetVerdict{}, false
	var bits uint32
	for _, r := range rows {
		if r.Key.Matches(k) && (!ok || r.Key.PrefixLen > bits) {
			best, ok, bits = r.Val, true, r.Key.PrefixLen
		}
	}
	return best, ok
}

func TestMappedDestinationsFollowTheIPv4Rows(t *testing.T) {
	for _, tc := range []struct {
		entries []string
		dst     string
		allow   bool
	}{
		{[]string{"::/0"}, "::ffff:127.0.0.1", false},
		{[]string{"::/0"}, "2001:db8::1", true},
		{[]string{"::/0", "0.0.0.0/0"}, "::ffff:127.0.0.1", true},
		{[]string{"::/0", "10.0.0.0/8"}, "::ffff:10.1.2.3", true},
		{[]string{"::/0", "10.0.0.0/8"}, "::ffff:11.1.2.3", false},
	} {
		var rules []agent.NetRule
		for _, e := range tc.entries {
			p := netip.MustParsePrefix(e)
			rules = append(rules, agent.NetRule{Raw: e + ":443", Port: 443, Proto: agent.ProtoInet,
				Verdict: agent.VerdictAllow, CIDR: &p, Static: true})
		}
		m, err := BuildRuleMaps(&agent.RuleTable{Net: rules}, 1, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := bpf.LookupLPMKey(1, bpf.ProtoTCP, netip.MustParseAddr(tc.dst), 443)
		v, ok := lpmVerdict(m.CIDR, k)
		got := ok && v.Verdict == uint8(bpf.VerdictAllow)
		if got != tc.allow {
			t.Errorf("%v: %s allowed=%v, want %v", tc.entries, tc.dst, got, tc.allow)
		}
	}
}
