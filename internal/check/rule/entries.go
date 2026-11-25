// SPDX-License-Identifier: Apache-2.0

package rule

import "gopkg.in/yaml.v3"

// Entries is the entries the contract text spells in each list an edit may change (EditKeys), in file order: what the
// Change rules form offers to remove. Only plain string entries are listed, the ones OpRemove can name; a list the
// file does not have is absent from the map. An entry a profile or the built-in list adds is never here, since the
// file does not spell it and an edit cannot remove it.
func Entries(text []byte) (map[string][]string, error) {
	_, top, err := parse(text)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, k := range editKeys {
		if !has(top, k) {
			continue
		}
		var es []string
		for _, e := range list(top, k) {
			if hasString(top, k, e) {
				es = append(es, e)
			}
		}
		out[k] = es
	}
	return out, nil
}

// RunCommands is the commands the contract text starts by itself: its own command, then each MCP server's command, as
// the argument lists the file spells (only plain string arguments; a command or server that is not a list of strings is
// left out). Compile grants each one's program with any arguments (an implicit grant), so an exec.allow entry that names
// words of that program constrains nothing the run's own command does. The text is read as YAML only: no path is
// resolved here.
func RunCommands(text []byte) ([][]string, error) {
	_, top, err := parse(text)
	if err != nil {
		return nil, err
	}
	words := func(n *yaml.Node) []string {
		if n == nil || n.Kind != yaml.SequenceNode {
			return nil
		}
		out := make([]string, 0, len(n.Content))
		for _, a := range n.Content {
			if a.Kind != yaml.ScalarNode {
				return nil
			}
			out = append(out, a.Value)
		}
		return out
	}
	var out [][]string
	if c, _ := lookup(top, "command"); c != nil {
		if w := words(c); len(w) > 0 {
			out = append(out, w)
		}
	}
	if m, _ := lookup(top, "mcp"); m != nil && m.Kind == yaml.SequenceNode {
		for _, s := range m.Content {
			c, _ := lookup(s, "command")
			if w := words(c); len(w) > 0 {
				out = append(out, w)
			}
		}
	}
	return out, nil
}
