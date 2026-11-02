// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
)

// The MCP relay's seams (ADR 0126 §4), found on Deps.Extra by interface so the runtime names no relay type.

// mcpAskSource is a source that holds a call for a person on the run's broker.
type mcpAskSource interface {
	ConfigureMCPAsk(func(context.Context, ask.Request) (ask.Decision, error))
}

// mcpGateSource is a source the supervisor asks whether a declared MCP server's start is the relay's.
type mcpGateSource interface {
	Relayed(server string, callerPID int) bool
	IsRelayed(server string) bool
}

// runtimeDirSource is a source that writes a file the agent reads into the run's runtime directory before the
// agent's environment is built (the relay's client config, TEGO_MCP_CONFIG).
type runtimeDirSource interface {
	UseRuntimeDir(dir string) error
}

// configureMCPAsk gives every relay the run's broker, once the broker exists. A run with no ask: section has no
// broker, and its relays refuse an asked tool ask-unavailable.
func (r *runner) configureMCPAsk() {
	for _, s := range r.deps.Extra {
		if a, ok := s.(mcpAskSource); ok {
			a.ConfigureMCPAsk(r.askRequest)
		}
	}
}

// mcpRelayedGate is the supervisor's Options.MCPRelayed: nil (the gate off, every path unchanged) unless a relay
// runs. A server the relay does not carry is never gated.
func (r *runner) mcpRelayedGate() func(server string, callerPID int) bool {
	var gates []mcpGateSource
	for _, s := range r.deps.Extra {
		if g, ok := s.(mcpGateSource); ok {
			gates = append(gates, g)
		}
	}
	if len(gates) == 0 {
		return nil
	}
	return func(server string, callerPID int) bool {
		for _, g := range gates {
			if g.IsRelayed(server) {
				return g.Relayed(server, callerPID)
			}
		}
		return true // not a relayed server: the gate has nothing to say
	}
}

// tellRuntimeDir hands the run's runtime directory to the sources that write into it, after it is made and before
// the child's environment is built.
func (r *runner) tellRuntimeDir() error {
	for _, s := range r.deps.Extra {
		if d, ok := s.(runtimeDirSource); ok {
			if err := d.UseRuntimeDir(r.runtimeDir); err != nil {
				return fmt.Errorf("runtime: %s: %w", s.Name(), err)
			}
		}
	}
	return nil
}
