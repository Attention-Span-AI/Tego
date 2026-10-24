// SPDX-License-Identifier: Apache-2.0

package scan

// Agent is an installed agent `maze` knows how to run.
type Agent struct {
	// Name is the agent's id, the word after `maze run`.
	Name string `json:"name"`
	// Path is where its executable was found on PATH.
	Path string `json:"path"`
}

// knownAgents are the agents Release 1 supports, in the order init proposes them.
var knownAgents = []string{"claude"}

// agentKeys are, per agent, the variables it authenticates with. They look like secrets and are,
// but the agent cannot reach its model without one, so the personal scan reports them as needed
// rather than proposing to strip them (Release 2 masks them through the proxy instead).
var agentKeys = map[string][]string{
	"claude": {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"},
}

// FindAgents returns the known agents installed on e.Path.
func FindAgents(e Env) []Agent {
	var out []Agent
	for _, name := range knownAgents {
		if p := e.LookPath(name); p != "" {
			out = append(out, Agent{Name: name, Path: p})
		}
	}
	return out
}
