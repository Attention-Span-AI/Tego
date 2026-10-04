// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrNetAssurance refuses a requested network mechanism that is unavailable
// before the agent executes. Destination admission, listeners, packet controls
// and resource budgets each require their own attachment proof.
var ErrNetAssurance = errors.New("runtime: kernel network assurance unavailable")

func validateNetworkRequest(rt *agent.RuleTable, deps Deps) error {
	if rt.Contract != nil && rt.Contract.Net != nil && rt.Contract.Net.Assurance == agent.NetAssuranceKernel && rt.NetworkAssurance() != agent.NetAssuranceKernel {
		return fmt.Errorf("%w: compiled assurance contradicts the contract's kernel requirement", ErrNetAssurance)
	}
	switch rt.NetworkAssurance() {
	case agent.NetAssuranceBestEffort:
		return nil
	case agent.NetAssuranceKernel:
	default:
		return fmt.Errorf("%w: unknown net.assurance %q", ErrNetAssurance, rt.NetworkAssurance())
	}
	tier := deps.Enforce.Tier()
	if tier != backend.TierCgroup && tier != backend.TierBPFLSM {
		return fmt.Errorf("%w: net.assurance: kernel requires cgroup or bpflsm destination hooks; tier %s cannot provide it", ErrNetAssurance, tier)
	}
	if rt.NetUnrestricted() {
		return fmt.Errorf("%w: net.assurance: kernel requires a net section", ErrNetAssurance)
	}
	if rt.Contract != nil && rt.Contract.IOUring {
		return fmt.Errorf("%w: io_uring: true is unsupported with client-only kernel assurance; disable io_uring or use net.assurance: best-effort", ErrNetAssurance)
	}
	if rt.Contract != nil && rt.Contract.Setuid {
		return fmt.Errorf("%w: setuid: true can regain privileges outside the client boundary; disable setuid or use net.assurance: best-effort", ErrNetAssurance)
	}
	for _, r := range rt.Net {
		switch r.Proto {
		case agent.ProtoInet, agent.ProtoTCP, agent.ProtoUDP:
			if r.Port <= 0 || r.Port > 65535 {
				return fmt.Errorf("%w: %s is a raw/ICMP or invalid-port destination without complete kernel coverage", ErrNetAssurance, r.RuleName())
			}
		case agent.ProtoUnix:
			if !r.Abstract && len(r.UnixPath) > bpf.UnixNameMax {
				return fmt.Errorf("%w: %s exceeds the kernel Unix policy name limit (%d bytes)", ErrNetAssurance, r.RuleName(), bpf.UnixNameMax)
			}
		default:
			return fmt.Errorf("%w: %s has unsupported protocol %q", ErrNetAssurance, r.RuleName(), r.Proto)
		}
	}
	for _, st := range DescribeStdio(deps.Stdio) {
		switch st.Kind {
		case record.StdioNull, record.StdioTTY, record.StdioPipe, record.StdioFile:
		default:
			return fmt.Errorf("%w: %s is %s; use a terminal, pipe, regular file or /dev/null rather than an inherited socket", ErrNetAssurance, st.Name, st.Kind)
		}
	}
	return nil
}

func (r *runner) networkGuarantees() backend.NetworkGuarantees {
	if rep, ok := r.handle.(enforce.NetworkReporter); ok {
		return rep.NetworkGuarantees()
	}
	return backend.NetworkGuarantees{}
}

func (r *runner) requireNetworkAssurance() error {
	g := r.networkGuarantees()
	var missing []string
	if r.rt.NetworkAssurance() == agent.NetAssuranceKernel {
		if !g.TCPDestination {
			missing = append(missing, "TCP destination hooks")
		}
		if !g.UDPDestination {
			missing = append(missing, "UDP connect/addressed-send hooks")
		}
		// Undeclared Unix destinations are refused policy too. Both addressed
		// datagram and connect hooks must check the kernel-copied destination.
		if !g.UnixDestination {
			missing = append(missing, "Unix connect/addressed-send hooks")
		}
		if !g.SocketImportsDenied {
			missing = append(missing, "socket import filter")
		}
		// ADR 0018 PR 2 (A-0018-10): no socket outside the allowlist exists, on any path the run can make one by. It
		// holds wherever tier 2 or 3 runs with its programs attached; the guarantee makes the claim explicit.
		if !g.SocketFamilies {
			missing = append(missing, "socket family hooks")
		}
		if r.rt.Listen != nil {
			if !g.ListenerBind {
				missing = append(missing, "listener bind/listen hooks and terminal cleanup")
			}
		} else if !g.ListenersDenied {
			missing = append(missing, "client-only listener filter")
		}
	}
	// These fields explicitly request kernel mechanisms, even when destination
	// assurance keeps its default best-effort setting. Never silently downgrade.
	if r.rt.Ingress != nil && !g.IngressSources {
		missing = append(missing, "ingress source/reply packet hooks")
	}
	limits := r.rt.NetLimits
	if limits.Bytes != nil && !g.NetworkBytes {
		missing = append(missing, "network byte budget hooks")
	}
	if limits.DatagramsPerSecond != nil && !g.NetworkDatagrams {
		missing = append(missing, "network datagram budget hooks")
	}
	if limits.Connections != nil && !g.NetworkConnections {
		missing = append(missing, "network connection lifecycle hooks")
	}
	if limits.PendingConnects != nil && !g.NetworkPending {
		missing = append(missing, "pending-connect lifecycle hooks")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: this run lacks %s", ErrNetAssurance, strings.Join(missing, ", "))
	}
	return nil
}

func (r *runner) networkGuaranteeLine() map[string]bool {
	g := r.networkGuarantees()
	return map[string]bool{
		"tcp": g.TCPDestination, "udp": g.UDPDestination, "unix": g.UnixDestination,
		"socket_imports_denied": g.SocketImportsDenied, "listeners_denied": g.ListenersDenied,
		"listener_bind": g.ListenerBind, "ingress_sources": g.IngressSources,
		"network_bytes": g.NetworkBytes, "network_datagrams": g.NetworkDatagrams,
		"network_connections": g.NetworkConnections, "network_pending": g.NetworkPending,
		"socket_families": g.SocketFamilies, "dns_broker": r.dnsBrokerReady(),
	}
}
