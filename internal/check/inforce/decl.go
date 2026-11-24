// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/attention-span-ai/tego/internal/check/compiledview"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"gopkg.in/yaml.v3"
)

type decl = compiledview.Declaration
type item = compiledview.Item
type limit = compiledview.Limit
type httpRule = compiledview.HTTPRule
type ingressRule = compiledview.IngressRule

var (
	newDecl    = compiledview.NewDeclaration
	limitKeys  = compiledview.LimitKeys
	readGate   = compiledview.ReadGate
	readAsk    = compiledview.ReadAsk
	mapGet     = compiledview.MapGet
	hostPort   = compiledview.HostPort
	sortLimits = compiledview.SortLimits
)

const kEnvSet = "env.set"
const kModels = "models"

// errNotMapping is a contract whose top level is not a mapping.
var errNotMapping = errors.New("inforce: the contract is not a YAML mapping")

// fromYAML reads a contract's text as written: the top file alone, never its profiles, and no value checked beyond
// what a sentence needs. It reads what LoadBytes would refuse, since it is the view of a contract that does not load.
func fromYAML(text []byte, path string) (decl, error) {
	d := newDecl(path)
	var doc yaml.Node
	if err := yaml.Unmarshal(text, &doc); err != nil {
		return d, fmt.Errorf("inforce: %w", err)
	}
	if len(doc.Content) == 0 {
		return d, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return d, errNotMapping
	}
	at := func(n *yaml.Node) agent.Pos { return agent.Pos{File: path, Line: n.Line, Col: n.Column} }
	scalar := func(n *yaml.Node, key string) string {
		if v := mapGet(n, key); v != nil && v.Kind == yaml.ScalarNode {
			return v.Value
		}
		return ""
	}
	seq := func(n *yaml.Node, section, key string) {
		v := mapGet(n, key)
		if v == nil || v.Kind != yaml.SequenceNode {
			return
		}
		full := section + "." + key
		for _, e := range v.Content {
			if e.Kind == yaml.ScalarNode {
				d.Lists[full] = append(d.Lists[full], item{Entry: e.Value, Pos: at(e)})
			}
		}
	}
	d.Name = scalar(root, "name")
	d.Tier = scalar(root, "tier")
	d.Record = scalar(root, "record")
	d.HostSockets = scalar(root, "host_sockets") == "true"
	d.Setuid = scalar(root, "setuid") == "true"
	if e := mapGet(root, "extends"); e != nil {
		switch e.Kind {
		case yaml.ScalarNode:
			d.Extends = []string{e.Value}
		case yaml.SequenceNode:
			for _, x := range e.Content {
				d.Extends = append(d.Extends, x.Value)
			}
		}
	}
	if c := mapGet(root, "command"); c != nil && c.Kind == yaml.SequenceNode {
		for _, x := range c.Content {
			d.Command = append(d.Command, x.Value)
		}
		d.CmdPos = at(c)
	}
	if m := mapGet(root, "mcp"); m != nil && m.Kind == yaml.SequenceNode {
		d.MCP = len(m.Content)
		for _, e := range m.Content {
			if e.Kind != yaml.MappingNode {
				continue
			}
			s := compiledview.MCPServer{Name: scalar(e, "name"), URL: scalar(e, "url"), Pos: at(e),
				Relayed: mapGet(e, "tools") != nil || mapGet(e, "business_rules") != nil, BusinessRules: mapGet(e, "business_rules") != nil}
			if c := mapGet(e, "command"); c != nil && c.Kind == yaml.SequenceNode {
				for _, x := range c.Content {
					s.Command = append(s.Command, x.Value)
				}
			}
			d.MCPServers = append(d.MCPServers, s)
		}
	}
	if fs := mapGet(root, "fs"); fs != nil && fs.Kind == yaml.MappingNode {
		d.HasFS = true
		for _, k := range []string{"write", "ask", "deny_read", "ask_read", "deny_write", "watch"} {
			seq(fs, "fs", k)
		}
		if dr := mapGet(fs, "deny_read"); dr != nil && dr.Kind == yaml.SequenceNode && len(dr.Content) == 0 {
			d.DenyReadOff = true
			d.DenyReadPos = at(dr)
		}
	}
	if ex := mapGet(root, "exec"); ex != nil && ex.Kind == yaml.MappingNode {
		d.HasExec = true
		d.ExecAllowKey = mapGet(ex, "allow") != nil || (mapGet(ex, "deny") == nil && mapGet(ex, "ask") == nil)
		for _, k := range []string{"allow", "deny", "ask", "privileged"} {
			seq(ex, "exec", k)
		}
	}
	if nt := mapGet(root, "net"); nt != nil && nt.Kind == yaml.MappingNode {
		d.HasNet = true
		for _, k := range []string{"allow", "ask", "listen"} {
			seq(nt, "net", k)
		}
		scalars := func(n *yaml.Node, key string) []string {
			var out []string
			if v := mapGet(n, key); v != nil && v.Kind == yaml.SequenceNode {
				for _, e := range v.Content {
					if e.Kind == yaml.ScalarNode {
						out = append(out, e.Value)
					}
				}
			}
			return out
		}
		if hs := mapGet(nt, "http"); hs != nil && hs.Kind == yaml.SequenceNode {
			for _, h := range hs.Content {
				if h.Kind == yaml.MappingNode {
					d.HTTP = append(d.HTTP, httpRule{Host: scalar(h, "host"), Allow: scalars(h, "allow"), Methods: scalars(h, "methods"), Pos: at(h)})
				}
			}
		}
		if in := mapGet(nt, "ingress"); in != nil && in.Kind == yaml.SequenceNode {
			d.IngressKey = true
			for _, r := range in.Content {
				if r.Kind == yaml.MappingNode {
					d.Ingress = append(d.Ingress, ingressRule{From: scalar(r, "from"), To: scalar(r, "to"), Pos: at(r)})
				}
			}
		}
	}
	if env := mapGet(root, "env"); env != nil && env.Kind == yaml.MappingNode {
		d.EnvPassKey = mapGet(env, "pass") != nil
		seq(env, "env", "pass")
		seq(env, "env", "deny")
		if set := mapGet(env, "set"); set != nil && set.Kind == yaml.MappingNode {
			// Names only: the value node is never read (TestNoEnvValues).
			for i := 0; i+1 < len(set.Content); i += 2 {
				k := set.Content[i]
				d.Lists[kEnvSet] = append(d.Lists[kEnvSet], item{Entry: k.Value, Pos: at(k)})
			}
			slices.SortStableFunc(d.Lists[kEnvSet], func(a, b item) int { return cmp.Compare(a.Entry, b.Entry) })
		}
	}
	if ms := mapGet(root, "models"); ms != nil && ms.Kind == yaml.SequenceNode {
		for _, m := range ms.Content {
			if m.Kind != yaml.MappingNode {
				continue
			}
			port, _ := strconv.Atoi(scalar(m, "port"))
			d.Lists[kModels] = append(d.Lists[kModels], item{Entry: hostPort(scalar(m, "host"), port), Pos: at(m)})
		}
	}
	if lm := mapGet(root, "limits"); lm != nil && lm.Kind == yaml.MappingNode {
		for _, k := range limitKeys {
			if v := mapGet(lm, k); v != nil && v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
				d.Limits = append(d.Limits, limit{Key: k, Value: v.Value, Pos: at(v)})
			}
		}
	}
	sortLimits(d.Limits)
	readAsk(&d, mapGet(root, "ask"), func(string) agent.Pos { return agent.Pos{} })
	if g := mapGet(root, "gate"); g != nil {
		d.Gate, d.GateBad = readGate(&agent.Contract{Gate: *g})
		if rs := mapGet(g, "rules"); rs != nil && rs.Kind == yaml.SequenceNode && len(rs.Content) == len(d.Gate.Rules()) {
			for _, n := range rs.Content {
				d.GatePos = append(d.GatePos, at(n))
			}
		}
	}
	return d, nil
}
