// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func TestBuiltinSocketIdentityDecisionTable(t *testing.T) {
	c := compile(&Policy{Rules: &agent.RuleTable{Builtins: &agent.BuiltinRefusals{Runtime: []string{"/run/user/1000"}, TegoDirs: []string{"/run/user/1000/tego"}, OwnRuntime: "/run/user/1000/tego/own"}}})
	id := fileID{dev: 2, ino: 3}
	c.builtinDirs = map[fileID]string{id: agent.BuiltinHostIPC}
	cases := []struct {
		name, path string
		file       unixFile
		rule       string
	}{
		{"allowed spelling", "/work/server", unixFile{nlink: 1}, ""},
		{"hard link", "/work/server", unixFile{nlink: 2}, agent.BuiltinHostIPC},
		{"moved directory", "/work/moved/server", unixFile{nlink: 1, parents: [64]fileID{id}, parentsN: 1}, agent.BuiltinHostIPC},
		{"SSH exception", "/run/user/1000/openssh_agent", unixFile{nlink: 1, parents: [64]fileID{id}, parentsN: 1}, ""},
		{"SSH hard link", "/run/user/1000/openssh_agent", unixFile{nlink: 2}, agent.BuiltinHostIPC},
		{"own runtime", "/run/user/1000/tego/own/server", unixFile{nlink: 2, parents: [64]fileID{id}, parentsN: 1}, ""},
		{"tego precedence", "/run/user/1000/tego/other/server", unixFile{nlink: 2}, agent.BuiltinTegoSurface},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.builtinFile(tt.path, tt.file); got != tt.rule {
				t.Fatalf("%s: %q want %q", tt.path, got, tt.rule)
			}
		})
	}
}

func TestBuiltinMovedLedgerIdentityDoesNotReserveOrdinarySockets(t *testing.T) {
	c := compile(&Policy{Rules: &agent.RuleTable{Builtins: &agent.BuiltinRefusals{Ledger: "/ledger"}}})
	id := fileID{dev: 2, ino: 3}
	c.builtinDirs = map[fileID]string{id: "ledger"}
	file := unixFile{nlink: 1, parents: [64]fileID{id}, parentsN: 1}
	for _, tt := range []struct{ path, want string }{{"/moved/run/ask.sock", agent.BuiltinTegoSurface}, {"/moved/run/operator.sock", agent.BuiltinTegoSurface}, {"/moved/ordinary.sock", ""}} {
		if got := c.builtinFile(tt.path, file); got != tt.want {
			t.Errorf("%s: %s want %s", tt.path, got, tt.want)
		}
	}
}

// The immutable bind relay runs outside Landlock. It must keep the contract's
// TCP listener floor and preserve the existing captured route-query path.
func TestBuiltinBindDecisionTable(t *testing.T) {
	for _, tt := range []struct {
		name    string
		netOpen bool
		route   bool
		port    uint16
		want    bool
		rule    string
	}{
		{"unrestricted ephemeral TCP", true, false, 0, true, ruleUnmatched},
		{"net section with no listener", false, false, 0, false, ruleUnmatched},
		{"configured control port", true, false, 7433, false, agent.BuiltinTegoSurface},
		{"legacy control port", true, false, 8484, false, agent.BuiltinTegoSurface},
		{"route query without net", true, true, 0, true, ruleRouteQuery},
		{"route query with net", false, true, 0, true, ruleRouteQuery},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain = unix.SOCK_STREAM, unix.AF_INET
			raw := sockaddrIn4("127.0.0.1", tt.port)
			if tt.route {
				f.sockType, f.sockDomain, f.sockProto = unix.SOCK_RAW, unix.AF_NETLINK, unix.NETLINK_ROUTE
				raw = sockaddrNL(0, 0)
			}
			f.put(0x40000, raw)
			p := testPolicy(nil, nil, nil)
			p.Rules.Builtins = &agent.BuiltinRefusals{ServePort: 7433}
			l, sink := newTestLoop(t, f, p)
			l.table.Load().netOpen = tt.netOpen
			binder := &bindFake{fakeKernel: f}
			l.k = binder
			handleBind(l, notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(raw))))
			resp, ok := f.lastResp()
			ev := sink.one(t)
			if !ok || resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || (len(binder.calls) == 1) != tt.want || ev.Rule != tt.rule || (ev.Verdict == record.VerdictAllow) != tt.want {
				t.Fatalf("bind calls=%d response=%+v event=%s/%s", len(binder.calls), resp, ev.Verdict, ev.Rule)
			}
			if f.fdBalance() != 0 {
				t.Fatal("bind duplicate leaked")
			}
		})
	}
}

func TestBuiltinObserveKeepsUnresolvedConnectDirect(t *testing.T) {
	p := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
	p.Rules.Builtins = &agent.BuiltinRefusals{Runtime: []string{"/runtime"}}
	p.Observe = true
	c := compile(p)
	if !c.passesUnresolved(&reader{failed: true}, dest{}, true) {
		t.Fatal("record-only run acquired C40's mandatory socket relay")
	}
	if p.Rules.Builtins == nil {
		t.Fatal("observation changed the enforcing caller's table")
	}
}
