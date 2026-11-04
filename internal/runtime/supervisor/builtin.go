// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func isBuiltinRule(rule string) bool {
	return rule == agent.BuiltinHostIPC || rule == agent.BuiltinTegoSurface || rule == agent.BuiltinOtherTTY
}

func (c *compiled) builtinNet(d dest, proto string) string {
	if d.isUnix() {
		return c.pol.Rules.BuiltinUnixRule(d.unixPath)
	}
	// Every loopback, unspecified and mapped loopback spelling is local. Other
	// interface addresses are captured in the compiled host address set below.
	if b := c.pol.Rules.Builtins; b != nil && proto != protoUDP && d.isInet() && (d.ap.Port() == b.ServePort || d.ap.Port() == 8484) {
		a := d.ap.Addr().Unmap()
		local, known := thisHost.Fresh().Has(a)
		if a.IsLoopback() || a.IsUnspecified() || local || !known {
			return agent.BuiltinTegoSurface
		}
	}
	return ""
}

func (c *compiled) builtinFile(p string, f unixFile) string {
	if c.pol.Rules.Builtins == nil {
		return ""
	}
	if rule := c.pol.Rules.BuiltinUnixRule(p); rule != "" {
		return rule
	}
	b := c.pol.Rules.Builtins
	if b.OwnPath(p) {
		return ""
	}
	if f.nlink > 1 {
		return agent.BuiltinHostIPC
	}
	if agent.IsContainerSocket(p, b.Runtime) && c.pol.Rules.BuiltinUnixRule(p) == "" {
		return ""
	}
	if rule := c.builtinDirs[f.id()]; rule != "" && rule != "ledger" {
		return rule
	}

	for i := 0; i < f.parentsN; i++ {
		if rule := c.builtinDirs[f.parents[i]]; rule != "" {
			if rule == "ledger" {
				if name := filepath.Base(p); name == "ask.sock" || name == "operator.sock" {
					return agent.BuiltinTegoSurface
				}
				continue
			}
			// A fixed SSH/container exception at its original pathname still applies.
			if rule == agent.BuiltinHostIPC && c.pol.Rules.BuiltinUnixRule(p) == "" {
				for _, d := range b.Runtime {
					if agent.Covers(d, p) {
						return ""
					}
				}
			}
			return rule
		}
	}
	return ""
}

// builtinBind continues pathname creation only after the immutable write floor
// was checked. IP binds go through handleBind's frozen-socket relay even when
// the contract has no listener policy.
func (l *Loop) builtinBind(n *notif, c *compiled) bool {
	r := l.newReader(n)
	raw := r.sockaddr(n.args[1], socklen(n.args[2]))
	if n.gone {
		return true
	}
	d := parseSockaddr(raw)
	// Netlink addresses are parsed by bindRoute, which freezes the socket
	// and address too. They must reach that handler even though parseSockaddr
	// deliberately does not decode their protocol-specific contents.
	if r.ok() && l.bindRoute(n, c, d, raw) {
		return true
	}
	if !r.ok() || !d.ok {
		l.finishBind(n, c, d, protoRaw, refuse(agent.BuiltinTegoSurface), nil, false)
		return true
	}
	if !d.isUnix() {
		return false
	}
	if d.unixPath != "" {
		p := r.resolve(atFDCWD, d.unixPath)
		if target, ok := c.pol.Rules.DenyWriteTarget(p, false); ok {
			l.finishBind(n, c, d, protoUnix, refuse(target.RuleName()), nil, false)
			return true
		}
		q := pathQuery{tid: n.pid, dirfd: atFDCWD, path: d.unixPath, joined: p}.as(agent.LookupParent)
		at, err := l.fsTarget(n, q)
		if err != nil {
			if lookupFailure(err) {
				// Returning the lookup error performs no bind and never hands
				// mutable arguments back to the kernel. A retry is decided afresh.
				l.respond(n, respResult(0, err))
				return true
			}
			l.finishBind(n, c, d, protoUnix, refuse(agent.BuiltinHostIPC), nil, false)
			return true
		}
		if target, ok := c.pol.Rules.DenyWriteTarget(at, false); ok {
			l.finishBind(n, c, d, protoUnix, refuse(target.RuleName()), nil, false)
			return true
		}
		l.recordRunSocket(n, d, p)
	} else if len(d.abstract) > 0 && (c.hostSockets || c.pol.Rules.Builtins != nil) {
		l.recordRunAbstract(n)
	}
	if c.pol.Rules.Listen == nil {
		l.respond(n, respContinue())
		return true
	}
	return false
}

// The ADR's abstract CONTINUE exception cannot freeze the descriptor/address:
// a sibling can replace both before the kernel reads them. Fail closed on the
// run's kernel-known binding identities instead, then retain the scope as a
// backstop (ADR 0113 implementation amendment).
func (l *Loop) builtinNet(c *compiled, d dest, proto string) string {
	if rule := c.builtinNet(d, proto); rule != "" {
		return rule
	}
	if c.pol.Rules.Builtins != nil && c.builtinABI >= 6 && len(d.abstract) > 0 {
		held, err := l.runSockets.holdsAbstract(l.k, string(d.abstract))
		if err != nil || !held {
			return agent.BuiltinHostIPC
		}
	}
	return ""
}

// socketBoundaryRule names a fail-closed relay-shape refusal at the active floor.
func (c *compiled) socketBoundaryRule() string {
	if c.pol.Rules.Builtins != nil {
		return agent.BuiltinHostIPC
	}
	return ruleHostSockets
}
