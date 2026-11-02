// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestMCPRelayGate: with the relay's gate on (Options.MCPRelayed), a start of a relayed server's declared command is
// refused, rule mcp[<name>].relay, unless the gate vouches for it; an exec that starts no server, or the gate off,
// is decided as before (ADR 0126 §4 "The gate").
func TestMCPRelayGate(t *testing.T) {
	const py = "/usr/bin/python3"
	c := &agent.Contract{MCP: []agent.MCPServer{{Name: "files", Command: []string{"python3", "/opt/fake-mcp/server.py"}, Tools: &agent.MCPTools{}}}}
	for _, tc := range []struct {
		name     string
		gate     func(string, int) bool
		argv     []string
		verdict  record.Verdict
		rule     string
		wantMCP  bool
		asked    bool
		askedPID int
		notHere  bool // the walk did not reach the image in this view: matched by path and argv alone
	}{
		{"no shim parent: refused", func(string, int) bool { return false }, []string{"python3", "/opt/fake-mcp/server.py"}, record.VerdictRefused, "mcp[files].relay", false, true, 40, false},
		{"the admitted shim's start: allowed", func(string, int) bool { return true }, []string{"python3", "/opt/fake-mcp/server.py"}, record.VerdictAllow, "", true, true, 40, false},
		{"another program on the same image: not asked", func(string, int) bool { return false }, []string{"python3", "-c", "1"}, record.VerdictAllow, "", false, false, 0, false},
		{"gate off: unchanged", nil, []string{"python3", "/opt/fake-mcp/server.py"}, record.VerdictAllow, "", true, false, 0, false},
		{"image not reached in this view, no shim parent: still refused", func(string, int) bool { return false }, []string{"python3", "/opt/fake-mcp/server.py"}, record.VerdictRefused, "mcp[files].relay", false, true, 40, true},
		{"image not reached in this view, the admitted shim's start: allowed", func(string, int) bool { return true }, []string{"python3", "/opt/fake-mcp/server.py"}, record.VerdictAllow, "", true, true, 40, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := contractPolicy(c, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Raw: "python3", Path: py, Basename: "python3", ByName: true, Source: "mcp:files", Verdict: agent.VerdictAllow}}
			f := newFake()
			f.goneOnSend = true
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 7, start: 1234}
			f.images[py] = fakeImage(py)
			if tc.notHere {
				img := f.images[py]
				img.here = false
				f.images[py] = img
			}
			f.statIDs[py] = fakeID(py)
			asked, askedServer, askedPID := false, "", 0
			var gate func(string, int) bool
			if tc.gate != nil {
				gate = func(server string, pid int) bool {
					asked, askedServer, askedPID = true, server, pid
					return tc.gate(server, pid)
				}
			}
			l, sink := newTestLoopOpts(t, f, pol, Options{MCPRelayed: gate})
			execAt(l, f, nrFor(t, "execve"), 42, 0, py, tc.argv...)
			if asked != tc.asked || (asked && (askedServer != "files" || askedPID != tc.askedPID)) {
				t.Fatalf("gate asked %v (%q, pid %d), want %v (pid %d)", asked, askedServer, askedPID, tc.asked, tc.askedPID)
			}
			sawMCP := false
			for _, ev := range sink.all() {
				switch ev.Kind {
				case record.KindExec:
					if ev.Verdict != tc.verdict || (tc.rule != "" && ev.Rule != tc.rule) {
						t.Errorf("exec line %s rule %s, want %s %s", ev.Verdict, ev.Rule, tc.verdict, tc.rule)
					}
					if tc.verdict == record.VerdictRefused && ev.Reason != record.ReasonExecNotAllowed {
						t.Errorf("reason %s", ev.Reason)
					}
				case record.KindMCP:
					sawMCP = true
				}
			}
			if sawMCP != tc.wantMCP {
				t.Errorf("mcp line %v, want %v", sawMCP, tc.wantMCP)
			}
			wantExecAnswer(t, f, tc.verdict)
		})
	}
}

// TestMCPRelayGateUnreadArgv: a vector the loop could not read whole names no server, and it may still be the declared
// start, since a fault stops this read and not the kernel's copy. The relay is asked of each server the part read could
// be, and without its word the exec is refused, by the server when one is left and args-unreadable when several are. An
// admitted shim's start with a declared argument past the read's bound passes on that word. An exec of something else
// on the shared runner is not refused for being unreadable. A NULL argv is the vector [""], a start of a server with no
// arguments.
func TestMCPRelayGateUnreadArgv(t *testing.T) {
	const py = "/usr/bin/python3"
	const strAddr, argvAddr = 0x210000, 0x220000
	script := "/opt/fake-mcp/server.py"
	one := []agent.MCPServer{{Name: "files", Command: []string{"python3", script}, Tools: &agent.MCPTools{}}}
	two := append(one[:1:1], agent.MCPServer{Name: "web", Command: []string{"python3", "/opt/web.py"}, Tools: &agent.MCPTools{}})
	bare := []agent.MCPServer{{Name: "bare", Command: []string{"python3"}, Tools: &agent.MCPTools{}}}
	// ptrs lays out a pointer array of the given strings; "\x00fault" is a pointer to nothing, and a false end leaves
	// the array with no NULL before unmapped memory.
	ptrs := func(f *fakeKernel, end bool, argv ...string) uint64 {
		b := make([]byte, 8*len(argv), 8*(len(argv)+1))
		next := uint64(strAddr)
		for i, a := range argv {
			if a == "\x00fault" {
				putU64(b[i*8:], 0x900000)
				continue
			}
			putU64(b[i*8:], next)
			f.put(next, cstr(a))
			next += uint64(len(a)) + 1
		}
		if end {
			b = append(b, make([]byte, 8)...)
		}
		f.put(argvAddr, b)
		return argvAddr
	}
	for _, tc := range []struct {
		name    string
		servers []agent.MCPServer
		argv    func(*fakeKernel) uint64
		rule    string // "" for allowed
		asked   int    // how many servers the relay is asked of
	}{
		{"the declared argument faults", one, func(f *fakeKernel) uint64 { return ptrs(f, true, "python3", "\x00fault") }, "mcp[files].relay", 1},
		{"argv[0] faults, the declared argument reads", one, func(f *fakeKernel) uint64 { return ptrs(f, true, "\x00fault", script) }, "mcp[files].relay", 1},
		{"an argument faults after the declared one", one, func(f *fakeKernel) uint64 { return ptrs(f, true, "python3", script, "\x00fault") }, "", 0},
		{"the pointer array faults at once", one, func(*fakeKernel) uint64 { return 0x900000 }, "mcp[files].relay", 1},
		{"the pointer array faults after argv[0]", one, func(f *fakeKernel) uint64 { return ptrs(f, false, "python3") }, "mcp[files].relay", 1},
		{"the pointer array faults after the declared vector", one, func(f *fakeKernel) uint64 { return ptrs(f, false, "python3", script) }, "mcp[files].relay", 1},
		{"unread, and two servers could be it", two, func(*fakeKernel) uint64 { return 0x900000 }, ruleArgsUnreadable, 2},
		{"unread, and the part read leaves one of two", two, func(f *fakeKernel) uint64 { return ptrs(f, false, "python3", "/opt/w") }, "mcp[web].relay", 1},
		{"an empty vector", one, func(f *fakeKernel) uint64 { return ptrs(f, true) }, "mcp[files].relay", 1},
		{"another program on the runner, cut short: not this gate's", one, func(f *fakeKernel) uint64 { return ptrs(f, true, "python3", "-c", "\x00fault") }, "", 0},
		{"a NULL argv on a server with no arguments", bare, func(*fakeKernel) uint64 { return 0 }, "mcp[bare].relay", 1},
		{"a NULL argv on a server with arguments: not its start", one, func(*fakeKernel) uint64 { return 0 }, "", 0},
		{"unread, but the relay vouches: an admitted shim's start", one, func(f *fakeKernel) uint64 { return ptrs(f, true, "python3", "\x00fault") }, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := contractPolicy(&agent.Contract{MCP: tc.servers}, nil, nil)
			for _, s := range tc.servers {
				pol.Rules.Exec = append(pol.Rules.Exec, agent.ExecRule{Raw: "python3", Path: py, Basename: "python3", ByName: true, Source: "mcp:" + s.Name, Verdict: agent.VerdictAllow})
			}
			f := newFake()
			f.goneOnSend = true
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 7, start: 1234}
			f.images[py] = fakeImage(py)
			f.statIDs[py] = fakeID(py)
			asked := 0
			vouch := tc.rule == "" && tc.asked > 0
			l, sink := newTestLoopOpts(t, f, pol, Options{MCPRelayed: func(string, int) bool { asked++; return vouch }})
			const pathAddr = 0x200000
			f.put(pathAddr, cstr(py))
			l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, tc.argv(f), 0))
			if asked != tc.asked {
				t.Errorf("relay asked %d times, want %d", asked, tc.asked)
			}
			want := record.VerdictAllow
			if tc.rule != "" {
				want = record.VerdictRefused
			}
			for _, ev := range sink.all() {
				if ev.Kind == record.KindExec && (ev.Verdict != want || tc.rule != "" && (ev.Rule != tc.rule || ev.Reason != record.ReasonExecNotAllowed)) {
					t.Errorf("exec line %s rule %s reason %s, want %s %s", ev.Verdict, ev.Rule, ev.Reason, want, tc.rule)
				}
			}
			wantExecAnswer(t, f, want)
		})
	}
}

// TestMCPRelayGateAtAReadyPlane: a plane that decides a run's execs takes them through the fast handover, which
// returned before the gate, so a start of a relayed server around its shim was recorded and ran, at tier cgroup in a
// plane mode as well as at tier bpflsm. A relay running now costs the run its handover, as command rules do, so the gate
// decides at every tier. What continues keeps the owner the handover gave it: the kernel writes the exec's line and the
// server's mcp line from this loop's naming, and this loop writes neither, so a start has one of each.
func TestMCPRelayGateAtAReadyPlane(t *testing.T) {
	const py = "/usr/bin/python3"
	server := []string{"python3", "/opt/fake-mcp/server.py"}
	c := &agent.Contract{MCP: []agent.MCPServer{{Name: "files", Command: server, Tools: &agent.MCPTools{}}}}
	never := func(string, int) bool { return false }
	always := func(string, int) bool { return true }
	for _, tc := range []struct {
		name        string
		gate        func(string, int) bool
		argv        []string
		kernelExecs bool // the plane decides this run's execs (false: planeDecides alone, no exec: section)
		asked       bool
		refused     bool
		mcpName     string
	}{
		{"no shim parent: refused, plane deciding execs", never, server, true, true, true, ""},
		{"no shim parent: refused, plane deciding fs alone", never, server, false, true, true, ""},
		{"the admitted shim's start: the kernel's lines, plane deciding execs", always, server, true, true, false, "files"},
		{"the admitted shim's start: the kernel's lines, plane deciding fs alone", always, server, false, true, false, "files"},
		{"another program on the same image: not asked", never, []string{"python3", "-c", "1"}, true, false, false, ""},
		{"no relay in the run: the fast handover, unchanged", nil, server, true, false, false, "files"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := contractPolicy(c, nil, nil)
			pol.Rules.Exec = []agent.ExecRule{{Raw: "python3", Path: py, Basename: "python3", ByName: true, Source: "mcp:files", Verdict: agent.VerdictAllow}}
			f := newFake()
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 7, start: 1234}
			f.images[py] = fakeImage(py)
			f.statIDs[py] = fakeID(py)
			asked := false
			var gate func(string, int) bool
			if tc.gate != nil {
				gate = func(server string, pid int) bool {
					asked = true
					return tc.gate(server, pid)
				}
			}
			l, sink := newTestLoopOpts(t, f, pol, Options{MCPRelayed: gate})
			l.kernelExecHandoff = func() bool { return true }
			if tc.kernelExecs {
				l.kernelExecs = func() bool { return true }
			}
			l.mono = func() uint64 { return 100 }
			execAt(l, f, nrFor(t, "execve"), 42, 0, py, tc.argv...)
			if asked != tc.asked {
				t.Fatalf("gate asked %v, want %v", asked, tc.asked)
			}
			lines := sink.all()
			if tc.refused {
				wantExecAnswer(t, f, record.VerdictRefused)
				if len(lines) != 1 || lines[0].Kind != record.KindExec || lines[0].Verdict != record.VerdictRefused ||
					lines[0].Rule != "mcp[files].relay" || lines[0].Reason != record.ReasonExecNotAllowed {
					t.Fatalf("lines %+v, want one exec refused by mcp[files].relay", lines)
				}
				if n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick, 110); !ok || !n.SupervisorOwned {
					t.Fatalf("naming %+v, found=%v: the kernel's sample of the refused exec must be dropped, not written too", n, ok)
				}
				return
			}
			wantExecAnswer(t, f, record.VerdictAllow)
			if len(lines) != 0 {
				t.Fatalf("this loop wrote %d lines the recorder writes: %+v", len(lines), lines)
			}
			n, ok := l.ContinuedExec(42, 40, 1234*proc.NanosPerTick, 110)
			if !ok || n.SupervisorOwned || n.MCPName != tc.mcpName || len(n.Argv) != len(tc.argv) {
				t.Fatalf("naming %+v, found=%v: the kernel's lines need this loop's naming, MCP server %q", n, ok, tc.mcpName)
			}
		})
	}
}
