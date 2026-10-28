// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

// MCPTools is an mcp[] entry's tools: mapping (agent-contract.md R16b, ADR 0126 §1): exact tool names the relay allows,
// denies or holds for a person. Allow present (even empty) denies every tool it does not list. A present tools: key,
// even `tools: {}`, puts the server behind Tego's MCP relay; the decision itself is internal/check/mcptool's.
type MCPTools struct {
	Allow []string `yaml:"allow,omitempty"`
	Deny  []string `yaml:"deny,omitempty"`
	Ask   []string `yaml:"ask,omitempty"`
}

// MarshalYAML keeps an explicit empty list in Canonical, as EnvSection keeps `pass: []`: `allow: []` denies every tool,
// and omitempty would drop it and hash the contract as one that allows them all (R13).
func (t MCPTools) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, l := range []struct {
		key  string
		list []string
	}{{"allow", t.Allow}, {"deny", t.Deny}, {"ask", t.Ask}} {
		if l.list == nil {
			continue
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if len(l.list) == 0 {
			seq.Style = yaml.FlowStyle
		}
		for _, v := range l.list {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: l.key}, seq)
	}
	if len(n.Content) == 0 {
		n.Style = yaml.FlowStyle
	}
	return n, nil
}

// Relayed reports whether the server's messages go through Tego's MCP relay: it declares tools:.
func (s MCPServer) Relayed() bool { return s.Tools != nil }

// mcpToolNameRE is a tool name the rules can name: MCP's own name rule widened by ':' and '/', which real servers use.
var mcpToolNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

// MCPToolNameOK reports whether name is a tool name a rule can name (^[A-Za-z0-9_.:/-]{1,128}$).
func MCPToolNameOK(name string) bool { return mcpToolNameRE.MatchString(name) }

// validateMCPTools checks every mcp[].tools: names by the tool rule, no name in two lists, and an ask list only where
// the contract has an ask: section, whose broker holds the call (ADR 0126 §1).
func validateMCPTools(ds *diags, c *Contract) {
	for i, s := range c.MCP {
		if s.Tools == nil {
			continue
		}
		key := "mcp." + strconv.Itoa(i) + ".tools"
		in := map[string]string{}
		for _, l := range []struct {
			name string
			list []string
		}{{"allow", s.Tools.Allow}, {"deny", s.Tools.Deny}, {"ask", s.Tools.Ask}} {
			for j, t := range l.list {
				at := c.origins[key+"."+l.name+"."+strconv.Itoa(j)]
				if !mcpToolNameRE.MatchString(t) {
					ds.errorf(at, CodeSchema, "mcp %q tools.%s %q is not a tool name (^[A-Za-z0-9_.:/-]{1,128}$)", s.Name, l.name, t)
					continue
				}
				if other, dup := in[t]; dup {
					ds.errorf(at, CodeSchema, "mcp %q tool %q is in tools.%s and tools.%s", s.Name, t, other, l.name).
						fix("keep %q in one list", t)
					continue
				}
				in[t] = l.name
			}
		}
		if len(s.Tools.Ask) > 0 && c.Ask.Kind == 0 {
			ds.errorf(c.origins[key+".ask"], CodeSchema, "mcp %q tools.ask needs the contract's ask: section, whose broker holds the call for a person", s.Name).
				fix("add ask: {timeout: 2m}")
		}
	}
}
