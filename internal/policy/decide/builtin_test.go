// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBuiltinPrecedenceAtEveryTier(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{HostSockets: true}, Builtins: &agent.BuiltinRefusals{Runtime: []string{"/run/user/1000"}, TegoDirs: []string{"/run/user/1000/tego"}, ServePort: 7433}, Net: []agent.NetRule{{Proto: agent.ProtoUnix, UnixPath: "/run/user/1000/bus", Verdict: agent.VerdictAllow}}, FS: []agent.FSRule{{Kind: agent.FSWrite, Path: "/", Resolved: "/", Access: agent.AccessWriteSet}}}
	cases := []struct {
		action agent.Action
		rule   string
	}{
		{agent.Action{Kind: agent.ActionNetConnect, Path: "/run/user/1000/bus"}, agent.BuiltinHostIPC},
		{agent.Action{Kind: agent.ActionNetSend, Path: "/run/user/1000/bus"}, agent.BuiltinHostIPC},
		{agent.Action{Kind: agent.ActionNetConnect, Path: "/run/user/1000/tego/other/api.sock"}, agent.BuiltinTegoSurface},
		{agent.Action{Kind: agent.ActionFSRead, Path: "/dev/pts/1"}, agent.BuiltinOtherTTY},
		{agent.Action{Kind: agent.ActionFSWrite, Path: "/dev/tty2"}, agent.BuiltinOtherTTY},
		{agent.Action{Kind: agent.ActionFSWrite, Path: "/run/user/1000/bus"}, agent.BuiltinHostIPC},
		{agent.Action{Kind: agent.ActionNetConnect, Host: "127.1.2.3", Port: 7433, Proto: "tcp"}, agent.BuiltinTegoSurface},
		{agent.Action{Kind: agent.ActionNetConnect, Host: "::ffff:127.0.0.1", Port: 7433, Proto: "tcp"}, agent.BuiltinTegoSurface},
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		for _, tt := range cases {
			t.Run(string(tier)+"/"+string(tt.action.Kind)+"/"+tt.action.Path+tt.action.Host, func(t *testing.T) {
				got := Evaluate(rt, tt.action, tier)
				if got.Verdict != agent.VerdictRefused || got.Rule != tt.rule {
					t.Fatalf("got %+v, want refused %s", got, tt.rule)
				}
				if got.Reason == record.Reason("") {
					t.Fatal("missing reason")
				}
			})
		}
	}
}

func TestBuiltinPlanePrecedenceAndOwnRuntime(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{}, Builtins: &agent.BuiltinRefusals{Runtime: []string{"/session"}, TegoDirs: []string{"/session/tego"}, OwnRuntime: "/session/tego/own"},
		FS:        []agent.FSRule{{Path: "/", Kind: agent.FSWrite}, {Path: "/session/tego/own", Kind: agent.FSWrite}, {Path: "/session/systemd", Kind: agent.FSWrite}},
		DenyWrite: []agent.FSRule{{Path: "/session", Kind: agent.FSDenyWrite, BuiltIn: true, BuiltinRule: agent.BuiltinHostIPC}, {Path: "/session/tego", Kind: agent.FSDenyWrite, BuiltIn: true, BuiltinRule: agent.BuiltinTegoSurface}},
	}
	rows, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ path, rule string }{{"/session/systemd/private", agent.BuiltinHostIPC}, {"/session/tego/other/socket", agent.BuiltinTegoSurface}, {"/session/tego/own/socket", ""}} {
		v := rows.Decide(tt.path, PlaneModify)
		if v.Allow != (tt.rule == "") || tt.rule != "" && v.Rule.Name(rt) != tt.rule {
			t.Errorf("%s: %+v rule %s, want %s", tt.path, v, v.Rule.Name(rt), tt.rule)
		}
	}
}

func TestBuiltinControlPortLeavesUDPAllowed(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{HostSockets: true}, Builtins: &agent.BuiltinRefusals{ServePort: 7433}}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		got := Evaluate(rt, agent.Action{Kind: agent.ActionNetConnect, Host: "127.0.0.1", Port: 7433, Proto: "udp"}, tier)
		if got.Verdict != agent.VerdictAllow {
			t.Fatalf("UDP was treated as the TCP control surface: %+v", got)
		}
	}
}

func TestBuiltinLedgerRowsCarryOnlyControlClassification(t *testing.T) {
	rt := &agent.RuleTable{Builtins: &agent.BuiltinRefusals{Ledger: "/shared", LedgerResolved: "/data"}, FS: []agent.FSRule{{Path: "/shared/run", Kind: agent.FSImplicit}, {Path: "/elsewhere", Kind: agent.FSImplicit}}}
	rows, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows.FS {
		want := r.Path == "/shared" || r.Path == "/data" || r.Path == "/shared/run"
		if (r.BuiltinFlags&1 != 0) != want {
			t.Errorf("ledger classifier: %+v", r)
		}
		if r.Kind&PlaneBuiltinIPC != 0 {
			t.Errorf("ledger classifier became a whole-directory Unix refusal: %+v", r)
		}
	}
}

func TestBuiltinPlaneKeepsConfiguredAndResolvedNames(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{{Path: "/", Kind: agent.FSWrite}},
		DenyWrite: []agent.FSRule{{Path: "/work/configured", Resolved: "/actual/server", Kind: agent.FSDenyWrite, BuiltIn: true, BuiltinRule: agent.BuiltinHostIPC}},
		Builtins: &agent.BuiltinRefusals{Runtime: []string{"/work/configured", "/actual/server"}, Names: []agent.BuiltinName{{
			Path: "builtin:/work/configured", Parent: "/work", Name: "configured", Target: "/actual/server",
		}}}}
	rows, err := CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range rows.Protected {
		if r.Rule&0x8000 != 0 {
			names[r.Parent+"/"+r.Name] = true
		}
	}
	if len(names) != 2 || !names["/work/configured"] || !names["/actual/server"] {
		t.Fatalf("replacing a resolved target lost its name refusal: %v", names)
	}
	parents := map[string]bool{}
	for _, p := range rows.Keyed {
		parents[p] = true
	}
	if !parents["/work"] || !parents["/actual"] || rt.Builtins.Names[0].Name != "configured" {
		t.Fatalf("configured name changed or a parent is not keyed: %+v %v", rt.Builtins.Names, parents)
	}
}
