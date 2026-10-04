// SPDX-License-Identifier: Apache-2.0

package agent

// NetAssurance chooses the required strength of destination enforcement.
// Kernel refuses launch unless copied kernel destinations are checked against
// the complete requested transport policy. It does not enable ingress rules.
type NetAssurance string

const (
	NetAssuranceBestEffort NetAssurance = "best-effort"
	NetAssuranceKernel     NetAssurance = "kernel"
)

func validateNetAssurance(ds *diags, c *Contract, at func(string) Pos) {
	if c.Net == nil {
		return
	}
	switch c.Net.Assurance {
	case "", NetAssuranceBestEffort, NetAssuranceKernel:
	default:
		ds.errorf(at("net.assurance"), CodeSchema, "net.assurance %q: want best-effort or kernel", c.Net.Assurance)
	}
}

// IsIPProtocol reports whether a rule describes an IP destination.
func IsIPProtocol(proto string) bool {
	return proto == ProtoInet || proto == ProtoTCP || proto == ProtoUDP
}

// ProtocolMatches preserves the legacy bare endpoint's transport wildcard.
// Selected TCP and UDP rules match only their declared transport.
func ProtocolMatches(rule, action string) bool {
	return rule == action || rule == ProtoInet || rule == ""
}

// NetworkAssurance is the effective request. The contract fallback also keeps
// hand-built tables from silently losing an explicit kernel requirement.
func (rt *RuleTable) NetworkAssurance() NetAssurance {
	if rt.NetAssurance != "" {
		return rt.NetAssurance
	}
	if rt.Contract != nil && rt.Contract.Net != nil && rt.Contract.Net.Assurance != "" {
		return rt.Contract.Net.Assurance
	}
	return NetAssuranceBestEffort
}
