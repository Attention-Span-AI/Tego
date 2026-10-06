// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestEvaluateListenerBinds(t *testing.T) {
	rt := &agent.RuleTable{Listen: []agent.ListenRule{
		{Raw: "tcp://0.0.0.0:8080", Proto: agent.ProtoTCP, Address: netip.MustParseAddr("0.0.0.0"), Port: 8080},
		{Raw: "udp://[::1]:0", Proto: agent.ProtoUDP, Address: netip.IPv6Loopback()},
		{Raw: "unix:/work/server", Proto: agent.ProtoUnix, UnixPath: "/work/server"},
		{Raw: "unix:@server", Proto: agent.ProtoUnix, UnixPath: "server", Abstract: true},
	}, FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Access: agent.AccessWriteSet}}}
	for _, c := range []struct {
		a    agent.Action
		want agent.Verdict
		rule string
	}{
		{agent.Action{Host: "127.0.0.1", Port: 8080}, agent.VerdictAllow, "net.listen[tcp://0.0.0.0:8080]"},
		{agent.Action{Host: "::ffff:127.0.0.1", Port: 8080}, agent.VerdictAllow, "net.listen[tcp://0.0.0.0:8080]"},
		{agent.Action{Host: "::1", Port: 8080}, agent.VerdictRefused, agent.UnmatchedRule},
		{agent.Action{Host: "127.0.0.1", Port: 8080, Proto: agent.ProtoUDP}, agent.VerdictRefused, agent.UnmatchedRule},
		{agent.Action{Host: "[::1]", Proto: agent.ProtoUDP}, agent.VerdictAllow, "net.listen[udp://[::1]:0]"},
		{agent.Action{Host: "::1", Port: 1, Proto: agent.ProtoUDP}, agent.VerdictRefused, agent.UnmatchedRule},
		{agent.Action{Host: "example.com", Port: 8080}, agent.VerdictRefused, agent.InvalidActionRule},
		{agent.Action{Host: "127.0.0.1", Port: 65536}, agent.VerdictRefused, agent.InvalidActionRule},
		{agent.Action{Proto: agent.ProtoUnix, Path: "/work/server"}, agent.VerdictAllow, "net.listen[unix:/work/server]"},
		{agent.Action{Proto: agent.ProtoUnix, Path: "/work/other"}, agent.VerdictRefused, agent.UnmatchedRule},
		{agent.Action{Proto: agent.ProtoUnix, Path: "@server"}, agent.VerdictAllow, "net.listen[unix:@server]"},
		{agent.Action{Proto: agent.ProtoUnix, Path: "@@server"}, agent.VerdictRefused, agent.UnmatchedRule},
	} {
		c.a.Kind = agent.ActionNetBind
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
			got := NewEvaluator(rt).Evaluate(c.a, tier)
			if got.Verdict != c.want || got.Rule != c.rule {
				t.Errorf("%s %+v: %+v, want %s %s", tier, c.a, got, c.want, c.rule)
			}
		}
	}
	// A declared pathname listener never invents the missing filesystem grant.
	rt.Listen[2].UnixPath = "/elsewhere/server"
	a := agent.Action{Kind: agent.ActionNetBind, Proto: agent.ProtoUnix, Path: "/elsewhere/server"}
	if got := Evaluate(rt, a, backend.TierLandlock); got.Verdict != agent.VerdictRefused || got.Rule != agent.UnmatchedRule {
		t.Fatalf("pathname without filesystem floor: %+v", got)
	}
	for _, rules := range [][]agent.ListenRule{nil, {}} {
		rt.Listen = rules
		a = agent.Action{Kind: agent.ActionNetBind, Host: "127.0.0.1", Port: 1234}
		got := Evaluate(rt, a, backend.TierLandlock)
		if (got.Verdict == agent.VerdictAllow) != (rules == nil) {
			t.Errorf("nil versus empty listener list: %+v", got)
		}
	}
}
