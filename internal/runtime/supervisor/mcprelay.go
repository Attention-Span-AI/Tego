// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mcpStageGrant replaces only an unlisted command refusal, after the image/read floors. It adds no command
// pattern for the binary: explicit denies/asks, unreadable vectors, live blocks, fences and gates still apply.
// The relay authenticates the exact prepared child with its fresh socket and pidfd (ADR 0126).
func (l *Loop) mcpStageGrant(c *compiled, n *notif, r *reader, cmd execCommand, img execImage, argvAddr uint64) (execCommand, string) {
	if l.mcpStage == nil || !cmd.res.Unlisted || cmd.res.Outcome != execmatch.OutcomeRefused || cmd.res.Overflow || cmd.res.Match == execmatch.MatchAmbiguous ||
		cmd.unreadable || cmd.headless || cmd.interpErr != nil || cmd.loader != "" || cmd.form != execmatch.FormDirect {
		return cmd, ""
	}
	argv, truncated := r.argv(argvAddr, c.argvMax)
	if truncated || len(argv) == 0 || !r.ok() || !l.valid(n) {
		return cmd, ""
	}
	pid, err := l.k.Tgid(n.pid)
	if err != nil || pid <= 0 || !l.valid(n) {
		return cmd, ""
	}
	rule := l.mcpStage(pid, img.id.dev, img.id.ino, argv)
	if !l.valid(n) || rule == "" {
		return cmd, ""
	}
	// Keep the image walk, but replace the unlisted match with the grant's whole copied vector. A plane pin must
	// cover every element the runtime allowance checked, even if the normal staged match stopped at the prefix.
	cmd.argv, cmd.complete, cmd.staged, cmd.guarded, cmd.decided = argv, true, true, true, false
	cmd.res = execmatch.Result{K: len(argv)}
	return cmd, rule
}

// mcpRelayGate is ADR 0126 §4's gate: an exec this loop would continue that starts a declared MCP server
// (mcpServerOf) is asked of the relay (Options.MCPRelayed), and refused unless the relay vouches for it, rule
// mcp[<name>].relay, reason exec-not-allowed: the agent started the server around its relay. It reads the exec's
// argv only for an image that is some server's command[0], so every other exec costs one map lookup. A nil gate or
// an exec already refused leaves the decision as it was.
//
// A vector not read whole names no server, and the exec may still be the declared start: a faulting string or pointer
// array stops this loop's read, not the kernel's copy. So each server the part read could be (mcpMaybeServers) is asked
// of the relay, which holds for a declared argument past the read's bound, and it is refused unless one vouches: rule
// mcp[<name>].relay when that left one server, args-unreadable when it left several. An exec of something else on a
// shared runner, whose read part is no declared vector, is not this gate's.
//
// The gate asks of every exec the mcp line would name a server for, walked or not: mcpServerOf matches by the
// line's path and argv when the image was not reached in this view, so a guard on the walk would have the ledger
// record a relayed server's start the gate never judged (review of r11/MCPTOOLS, fail-open on an unwalked image).
// An exec whose lookup failed is never continued (d.answer.cont), so it needs no case of its own.
func (l *Loop) mcpRelayGate(c *compiled, n *notif, r *reader, d execDecision, name string, img execImage, argvAddr uint64) (execDecision, bool) {
	if l.mcpRelayed == nil || !d.answer.cont || d.verdict != record.VerdictAllow || !c.mayStartMCP(name, img) {
		return d, false
	}
	argv, truncated := r.argv(argvAddr, c.argvMax)
	if n.gone || !l.valid(n) {
		return d, false
	}
	var servers []string
	if truncated || len(argv) == 0 && argvAddr != 0 {
		servers = c.mcpMaybeServers(name, img, argv)
	} else if server := c.mcpServerOf(name, img, argv); server != "" {
		servers = []string{server}
	}
	if len(servers) == 0 {
		return d, false
	}
	pid := n.pid
	if tgid, err := l.k.Tgid(n.pid); err == nil && tgid > 0 {
		pid = tgid
	}
	for _, server := range servers {
		if !l.valid(n) || l.mcpRelayed(server, pid) {
			return d, false
		}
	}
	rule := ruleArgsUnreadable
	if len(servers) == 1 {
		rule = "mcp[" + servers[0] + "].relay"
	}
	return execDecision{rule: rule, verdict: record.VerdictRefused, reason: record.ReasonExecNotAllowed,
		answer: respErrno(refusalErrno)}, true
}

// mcpMaybeServers names the declared servers of this image whose vector an argv not read whole could still be. Every
// element is compared as a prefix, not only the last: a string that faulted reads as "" or as far as it went, and the
// read goes on past it. A complete element that only happens to begin a declared one is refused too, which costs that
// exec only when its vector could not be read.
func (c *compiled) mcpMaybeServers(path string, img execImage, argv []string) []string {
	var names []string
	add := func(servers []mcpServer) {
		for _, s := range servers {
			if !slices.Contains(names, s.name) && argsBegin(s.args, argv) {
				names = append(names, s.name)
			}
		}
	}
	if img.here {
		for _, f := range c.mcpIDs[img.id] {
			if f.path == img.link {
				add(f.servers)
			}
		}
	}
	add(c.mcp[path])
	return names
}

// argsBegin reports whether argv[1:], as far as it was read, could be the declared arguments.
func argsBegin(declared, argv []string) bool {
	if len(argv) > 0 {
		argv = argv[1:]
	}
	if len(argv) > len(declared) {
		return false
	}
	for i, a := range argv {
		if !strings.HasPrefix(declared[i], a) {
			return false
		}
	}
	return true
}

// mayStartMCP reports whether the image is some declared server's command[0], by path or by identity.
func (c *compiled) mayStartMCP(name string, img execImage) bool {
	if len(c.mcp[name]) > 0 {
		return true
	}
	if img.here {
		return len(c.mcpIDs[img.id]) > 0
	}
	return false
}
