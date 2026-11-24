// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// MaxListenerRules bounds each listener/ingress list before kernel state exists.
const MaxListenerRules = 256

// ListenRule is a static bind grant. Port zero names ephemeral allocation only.
// A wildcard address admits narrower binds in the same address family.
type ListenRule struct {
	Raw, Proto string
	Address    netip.Addr
	Port       uint16
	UnixPath   string
	Abstract   bool
	Pos        Pos
}

// RuleName is the stable declaration attribution used across all backends.
func (r ListenRule) RuleName() string { return "net.listen[" + r.Raw + "]" }

// IngressRuleCompiled admits a source prefix to one declared listener. Replies
// to permitted outgoing traffic are handled separately by the kernel flow table.
type IngressRuleCompiled struct {
	From netip.Prefix
	To   ListenRule
}

// RuleName names the source and the listener without including packet payloads.
func (r IngressRuleCompiled) RuleName() string {
	return "net.ingress[" + r.From.String() + "->" + r.To.Raw + "]"
}

// MatchBind is the IP bind policy shared by evaluators and supervisors. A nil
// list adds no bind restriction to the legacy policy; an empty non-nil list denies.
// Port-zero grants never admit a fixed port. IPv4-mapped spellings normalize to
// IPv4, while IPv6 wildcard grants do not silently cover IPv4 sockets.
func MatchBind(rules []ListenRule, ap netip.AddrPort, proto string) (ListenRule, bool) {
	if !ap.IsValid() || (proto != ProtoTCP && proto != ProtoUDP) {
		return ListenRule{}, false
	}
	if rules == nil {
		return ListenRule{}, true
	}
	a := ap.Addr().Unmap().WithZone("")
	for _, r := range rules {
		if r.Proto != proto || r.Port != ap.Port() || !r.Address.IsValid() {
			continue
		}
		bound := r.Address.Unmap()
		if bound == a || bound.IsUnspecified() && bound.Is4() == a.Is4() {
			return r, true
		}
	}
	return ListenRule{}, false
}

// CompileListenerControl validates the static declarations and their references.
// resolve expands Unix filesystem names exactly as ordinary contract paths; nil
// retains their spelling for schema validation before compile knows HOME/cwd.
func CompileListenerControl(c *Contract, resolve func(string) string) ([]ListenRule, []IngressRuleCompiled, NetworkLimits, error) {
	var limits NetworkLimits
	if c == nil || c.Net == nil {
		return nil, nil, limits, nil
	}
	n := c.Net
	if len(n.Listen) > MaxListenerRules || len(n.Ingress) > MaxListenerRules {
		return nil, nil, limits, fmt.Errorf("net.listen/net.ingress exceed %d entries", MaxListenerRules)
	}
	var listeners []ListenRule
	if n.Listen != nil {
		listeners = make([]ListenRule, 0, len(n.Listen))
	}
	for i, raw := range n.Listen {
		e, err := ParseListenEndpoint(raw)
		if err != nil {
			return nil, nil, limits, fmt.Errorf("net.listen[%d]: %w", i, err)
		}
		r := ListenRule{Raw: raw, Proto: e.Proto, Address: e.IP, Port: uint16(e.Port), UnixPath: e.UnixPath, Abstract: e.Abstract}
		r.Pos, _ = c.Pos("net.listen." + strconv.Itoa(i))
		if r.Proto == ProtoUnix && !r.Abstract && resolve != nil {
			r.UnixPath = resolve(r.UnixPath)
		}
		listeners = append(listeners, r)
	}
	var ingress []IngressRuleCompiled
	if n.Ingress != nil {
		if n.Listen == nil {
			return nil, nil, limits, fmt.Errorf("net.ingress requires an explicit net.listen list")
		}
		ingress = make([]IngressRuleCompiled, 0, len(n.Ingress))
	}
	for i, raw := range n.Ingress {
		from, err := ingressPrefix(raw.From)
		if err != nil {
			return nil, nil, limits, fmt.Errorf("net.ingress[%d].from: %w", i, err)
		}
		to, err := ParseListenEndpoint(raw.To)
		if err != nil || to.Proto == ProtoUnix {
			return nil, nil, limits, fmt.Errorf("net.ingress[%d].to needs a declared TCP/UDP listener", i)
		}
		var found *ListenRule
		for j := range listeners {
			r := &listeners[j]
			if r.Proto == to.Proto && r.Address == to.IP && r.Port == uint16(to.Port) {
				found = r
				break
			}
		}
		if found == nil {
			return nil, nil, limits, fmt.Errorf("net.ingress[%d].to is not a declared net.listen endpoint", i)
		}
		if from.Addr().Is4() != found.Address.Is4() && !(found.Address.Is6() && found.Address.IsUnspecified() && from.Addr().Is4()) {
			return nil, nil, limits, fmt.Errorf("net.ingress[%d] source and listener address families differ", i)
		}
		ingress = append(ingress, IngressRuleCompiled{From: from, To: *found})
	}
	if n.Limits != nil {
		limits = *n.Limits
		limits.Connections = copyLimit(n.Limits.Connections)
		limits.PendingConnects = copyLimit(n.Limits.PendingConnects)
		limits.DatagramsPerSecond = copyLimit(n.Limits.DatagramsPerSecond)
		if n.Limits.Bytes != nil {
			value := *n.Limits.Bytes
			limits.Bytes = &value
		}
		if limits.Bytes != nil && *limits.Bytes < 0 {
			return nil, nil, limits, fmt.Errorf("net.limits.bytes cannot be negative")
		}
	}
	return listeners, ingress, limits, nil
}

func copyLimit(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func ingressPrefix(raw string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(raw); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil || p.Addr().Is4In6() || p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("want a literal source address or canonical CIDR without a zone")
	}
	return p, nil
}

func validateListenerControl(ds *diags, c *Contract, at func(string) Pos) {
	if _, _, _, err := CompileListenerControl(c, nil); err != nil {
		key := "net.listen"
		if strings.Contains(err.Error(), "net.ingress") {
			key = "net.ingress"
		} else if strings.Contains(err.Error(), "net.limits") {
			key = "net.limits"
		}
		ds.errorf(at(key), CodeSchema, "%v", err)
	}
}

func (k *compiler) listenerControl() {
	listen, ingress, limits, err := CompileListenerControl(k.c, func(raw string) string {
		absolute := k.abs(raw)
		// bind creates the final pathname itself; only its parent is resolved.
		// Following an existing final symlink would grant a different name.
		return filepath.Join(k.resolve(filepath.Dir(absolute)), filepath.Base(absolute))
	})
	if err != nil {
		k.ds.errorf(k.pos("net"), CodeSchema, "%v", err)
		return
	}
	k.rt.Listen, k.rt.Ingress, k.rt.NetLimits = listen, ingress, limits
}
