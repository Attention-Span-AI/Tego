// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"fmt"
	"sort"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// resolverPort is where the resolver is allowed on TCP and UDP in every tier (SEMANTICS §5).
const resolverPort = 53

// netRule is one landlock_add_rule(LANDLOCK_RULE_NET_PORT): the declared port with
// the union of its selected transport rights supported by the ABI, or, at ABI ≥ 10, the
// ephemeral port's BIND_UDP (port 0). R6 (corrected), R22.
type netRule struct {
	Access netAccess
	Port   uint16
}

// netRules is R6/R21/R22. A contract without a net: section restricts nothing: no net right is
// handled and no rule is built. Otherwise every distinct declared port becomes one rule (deduplicated
// by port: the kernel rule cannot see the host), the resolver port joins whenever any host/cidr entry
// exists, and explicit listener declarations add their selected bind rights. Without listener declarations,
// BIND_TCP is never granted and BIND_UDP is granted on port 0 only (a UDP client's explicit bind to an ephemeral
// port, R22). Below ABI 4 no rule exists at all (E4). unix: entries go to unixEntry.
func (bd *builder) netRules() error {
	if !bd.netRestricted {
		// The unix-only state (ADR 0070) handles RESOLVE_UNIX with no net right: tego's own endpoints, the unix: grants
		// the runtime adds (the DNS broker's socket), get their backstop as a declared entry would.
		if bd.unixRestricted {
			for _, r := range bd.rt.Net {
				if r.Proto == agent.ProtoUnix {
					if err := bd.unixEntry(r); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	ports := map[uint16]netAccess{}
	inet := false
	for _, r := range bd.rt.Net {
		switch r.Proto {
		case agent.ProtoUnix:
			if err := bd.unixEntry(r); err != nil {
				return err
			}
		case agent.ProtoInet, agent.ProtoTCP, agent.ProtoUDP:
			inet = true
			if r.Port > 0 && r.Port <= 0xffff {
				if r.Proto != agent.ProtoUDP {
					ports[uint16(r.Port)] |= accessNetConnectTCP
				}
				if r.Proto != agent.ProtoTCP {
					ports[uint16(r.Port)] |= accessNetConnectSendUDP
				}
			}
		default:
			return fmt.Errorf("%w: net rule %q: unknown proto %q", ErrRulesetBuild, r.Raw, r.Proto)
		}
	}
	if inet {
		ports[resolverPort] |= accessNetConnectTCP | accessNetConnectSendUDP
	}
	// Explicit listener declarations add only the selected transport's bind
	// right. Addresses are checked by the captured-address supervisor/kernel
	// guard; Landlock's port rule never claims destination or source confinement.
	for _, r := range bd.rt.Listen {
		switch r.Proto {
		case agent.ProtoTCP:
			ports[r.Port] |= accessNetBindTCP
		case agent.ProtoUDP:
			ports[r.Port] |= accessNetBindUDP
		case agent.ProtoUnix:
			// Creating a pathname socket still needs the filesystem MAKE_SOCK
			// authority. A listener entry grants no new filesystem rights.
		default:
			return fmt.Errorf("%w: listener %q: unknown proto %q", ErrRulesetBuild, r.Raw, r.Proto)
		}
	}
	if bd.profile.Net&(accessNetConnectTCP|accessNetConnectSendUDP) == 0 {
		return nil // ABI < 4: the supervisor decides alone (E4)
	}
	if bd.rt.Listen == nil && inet && bd.profile.Net&accessNetBindUDP != 0 {
		// Handled at ABI ≥ 10, so a UDP client that binds before it sends (net.ListenUDP(":0"), a QUIC
		// stack) would get EACCES from a refusal no layer records. Port 0 is the ephemeral range only: a fixed
		// UDP port stays refused when no listener declaration grants it.
		bd.net = append(bd.net, netRule{Access: accessNetBindUDP, Port: 0})
	}
	sorted := make([]int, 0, len(ports))
	for p := range ports {
		sorted = append(sorted, int(p))
	}
	sort.Ints(sorted)
	for _, p := range sorted {
		if access := ports[uint16(p)] & bd.profile.Net; access != 0 {
			bd.net = append(bd.net, netRule{Access: access, Port: uint16(p)})
		}
	}
	return nil
}

// unixEntry: an abstract entry never has an fd or a kernel rule (seccomp + supervisor only);
// a pathname entry is supervisor-only below ABI 9 and a RESOLVE_UNIX backstop on its held fd at ≥ 9.
// At ≥ 9 only, the build fails when the socket is a deny node's inode, because the seal would drop the
// backstop (holdGrant, E32 (c)). Below 9 nothing is held, so the same contract prepares.
func (bd *builder) unixEntry(r agent.NetRule) error {
	if r.Abstract {
		return nil // the supervisor holds the abstract list, from the rule table (R21)
	}
	if bd.profile.FS&accessResolveUnix == 0 {
		return nil
	}
	return bd.holdGrant(r.UnixPath, kindUnixSocket, accessResolveUnix)
}
