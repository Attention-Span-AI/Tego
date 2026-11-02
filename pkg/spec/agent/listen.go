// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
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

// ioUringListenUndecided warns where a ring can listen with nothing deciding it (GAPS C44). Under a net: section with
// no net.listen list a TCP listen is the supervisor's to refuse (enforce-landlock R6, R11c), since Landlock's BIND_TCP
// never sees the autobind of a listen() on an unbound socket. A ring's IORING_OP_LISTEN (Linux 6.11+) passes no
// seccomp notification, and the plane's socket_listen decides only a run whose net.listen is a list (enforce-plane
// §2.20), so where a root tier's plane admits io_uring (tier cgroup in a plane mode, tier bpflsm) a ring's listen on an
// unbound TCP socket takes an ephemeral port on every address and nothing refuses it. A list, net.listen: [] for none,
// has the plane decide it. Tier landlock keeps io_uring ENOSYS (Compile's other io-uring warning says so), so the
// finding holds at the root tiers alone; compile cannot tell whether tier cgroup gets a plane mode, so the message
// states that condition. The contract's list is read, not RuleTable.Listen, which a refused list leaves nil too.
func (k *compiler) ioUringListenUndecided() {
	if !k.c.IOUring || k.c.Net == nil || k.c.Net.Listen != nil {
		return
	}
	var roots []string
	var tiers []backend.Tier
	for _, t := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if k.mayLand(t) {
			roots, tiers = append(roots, string(t)), append(tiers, t)
		}
	}
	if len(tiers) == 0 {
		return
	}
	k.ds.warnf(k.pos("io_uring"), CodeIOUring, "io_uring: true under a net: section with no net.listen leaves a ring's "+
		"listen undecided at tier %s, where a decision plane admits io_uring: its IORING_OP_LISTEN (Linux 6.11+) never "+
		"reaches the supervisor that refuses a TCP listen here, and the plane decides a listen only against a net.listen "+
		"list, so a listen on an unbound TCP socket autobinds an ephemeral port on every address and nothing refuses it",
		strings.Join(roots, " or ")).
		fix("declare the run's listeners with net.listen, which the plane holds a ring's listen to as well (net.listen: [] " +
			"declares none, unix ones included), or drop io_uring:").
		only(tiers...)
}
