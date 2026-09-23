// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mcpTransportStdio is the transport of a server this package sees start: an MCP server launched as a
// child process speaks JSON-RPC on its stdio (spec/record/v1: transport stdio|http).
const mcpTransportStdio = "stdio"

// mcpServers indexes the contract's mcp[] entries by the resolved path of their command[0], the path an
// exec of that server reaches this loop with. Compile resolves each command[0] into an exec rule whose
// Source carries "mcp:<name>" (comma-joined when one binary serves several roles), so the path is taken
// from that rule rather than resolved again here: no filesystem read at policy time. Several servers may
// share one binary (npx, uvx), which is why a path maps to a list and mcpServerOf compares arguments too.
func mcpServers(rt *agent.RuleTable) map[string][]mcpServer {
	if rt == nil || rt.Contract == nil || len(rt.Contract.MCP) == 0 {
		return nil
	}
	pathOf := map[string]string{} // server name -> resolved command[0]
	for i := range rt.Exec {
		e := &rt.Exec[i]
		if e.Path == "" || e.IsDir {
			continue
		}
		for _, src := range strings.Split(e.Source, ",") {
			if name, ok := strings.CutPrefix(src, agent.ExecSourceMCP+":"); ok {
				pathOf[name] = cleanPath(e.Path)
			}
		}
	}
	var out map[string][]mcpServer
	for _, s := range rt.Contract.MCP {
		p, ok := pathOf[s.Name]
		if !ok || len(s.Command) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]mcpServer{}
		}
		out[p] = append(out[p], mcpServer{name: s.Name, args: s.Command[1:]})
	}
	return out
}

// mcpServerOf names the declared MCP server an exec starts, or "" when it starts none. A stdio server's
// messages pass through pipes no capture source reads (capture-derive.md R41), so the one start it can see is
// an exec matching a declared mcp[].command: the resolved command[0] as the path, and the declared arguments after it as
// argv[1:], exactly. Matching the path alone would name a server for every other use of a shared runner
// (the agent's own `npx prettier` is not the `npx @modelcontextprotocol/server-x` the contract declared),
// and an event naming a server that never started is worse for drift than none: limits-check-doctor-cli
// R15 counts one run's mcp events per declared name, and an invented one hides a server that never ran.
//
// Where the exec's walk reached its image in this process's view, the image itself is matched first: a command[0]'s
// file by identity, its inode and its symlink-resolved path both, as an exec entry's grant matches an image (mcpIDs,
// execGranted), so another name of the same inode (a hard link, another mount) is not the server. So a start spelled
// otherwise than its command[0] (through a ".." that reaches it, a symlinked directory, its link's target) is the same
// server's start, and is not lost from drift (2c6-1). Then the
// path is the exec line's name for it, which the same walk as the image's gave (execImage.name).
//
// A truncated argv is compared as read; it can only fail to match, never match a different server, and the relay's gate
// reads that case itself (mcpMaybeServers). An empty argv reads as [""], the vector the kernel gives the program for a
// NULL or empty one (execpin/pin.go), so a server declared with no arguments is named: that exec is its start.
func (c *compiled) mcpServerOf(path string, img execImage, argv []string) string {
	if len(argv) == 0 {
		argv = []string{""}
	}
	if img.here {
		for _, f := range c.mcpIDs[img.id] {
			if f.path == img.link {
				if name := serverOf(f.servers, argv); name != "" {
					return name
				}
			}
		}
	}
	return serverOf(c.mcp[path], argv)
}

// serverOf is the server of servers whose declared arguments are argv[1:], or "".
func serverOf(servers []mcpServer, argv []string) string {
	for _, s := range servers {
		if equalArgs(s.args, argv[1:]) {
			return s.name
		}
	}
	return ""
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// emitMCP records the start of a declared MCP server, which P0 derives from the exec that launched it
// (P0-DESIGN §2.2: P0 writers emit mcp). It rides on the exec it came from: same notification, same
// verdict, and the rule is the server as drift registers it, "mcp[<name>]". Only an allowed exec starts
// a server; a refused one started nothing, and its exec line already says so.
func (l *Loop) emitMCP(n *notif, pid int, name string, argv []string) {
	ev := action(l.event(n, record.KindMCP, record.SourceSeccomp), "mcp["+name+"]", record.VerdictAllow, "")
	ev.PID = pid
	l.emitFor(n, ev, record.MCPPayload{Name: name, Command: argv, Transport: mcpTransportStdio})
}
