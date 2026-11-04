// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestBuiltinUnixRowsOverrideAllAllows(t *testing.T) {
	for _, netOpen := range []bool{false, true} {
		rt := &agent.RuleTable{Builtins: &agent.BuiltinRefusals{Runtime: []string{"/run/user/1000"}, TegoDirs: []string{"/run/user/1000/tego"}}, Contract: &agent.Contract{HostSockets: true}, FS: []agent.FSRule{{Path: "/run/user/1000", Kind: agent.FSWrite}, {Path: "/run/user/1000/systemd", Kind: agent.FSWrite}}, Net: []agent.NetRule{unixEntry("unix:/run/user/1000/bus"), unixEntry("unix:/run/user/1000/systemd/private"), unixEntry("unix:/run/user/1000/openssh_agent")}}
		if !netOpen {
			rt.Contract.Net = &agent.NetSection{}
		}
		maps, err := BuildRuleMaps(rt, 0, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"/run/user/1000/bus", "/run/user/1000/systemd/private", "/run/user/1000/new.sock"} {
			v, ok := lookupUnix(t, maps, p)
			if !ok || v.Verdict != uint8(bpf.VerdictRefused) || maps.Rules[v.RuleIdx] != agent.BuiltinHostIPC {
				t.Errorf("%s: %+v (%v), rules %v", p, v, ok, maps.Rules)
			}
		}
		v, ok := lookupUnix(t, maps, "/run/user/1000/openssh_agent")
		if !ok || v.Verdict != uint8(bpf.VerdictAllow) {
			t.Fatalf("SSH exception: %+v (%v)", v, ok)
		}
		if maps.Unrestricted || maps.UnixOnly != netOpen {
			t.Fatalf("attachment: unrestricted=%v unix-only=%v", maps.Unrestricted, maps.UnixOnly)
		}
	}
}
