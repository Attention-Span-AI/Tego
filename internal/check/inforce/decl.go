// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// item is one declared entry and where it was written.
type item struct {
	entry string
	pos   agent.Pos
}

// limit is one declared limits key, its value as text.
type limit struct {
	key, value string
	pos        agent.Pos
}

// The list keys a decl holds, each a contract key (net.http's and net.ingress's entries, which are mappings, are held
// apart: decl.http, decl.ingress).
const (
	kFSWrite     = "fs.write"
	kFSAsk       = "fs.ask"
	kFSDenyRead  = "fs.deny_read"
	kFSAskRead   = "fs.ask_read"
	kFSDenyWrite = "fs.deny_write"
	kFSWatch     = "fs.watch"
	kExecAllow   = "exec.allow"
	kExecDeny    = "exec.deny"
	kExecAsk     = "exec.ask"
	kNetAllow    = "net.allow"
	kNetAsk      = "net.ask"
	kNetListen   = "net.listen"
	kNetHTTP     = "net.http"
	kNetIngress  = "net.ingress"
	kEnvPass     = "env.pass"
	kEnvDeny     = "env.deny"
	kEnvSet      = "env.set"
	kModels      = "models"
)

// httpRule is one net.http entry: the requests a model service may be sent (agent.HTTPRule).
type httpRule struct {
	host           string
	allow, methods []string
	pos            agent.Pos
}

// ingressRule is one net.ingress entry: a source a declared listener accepts (agent.IngressRule).
type ingressRule struct {
	from, to string
	pos      agent.Pos
}

// limitKeys are the limits keys in the order the limits group lists them.
var limitKeys = []string{"wall", "tokens", "cost_usd", "memory", "memory_high", "pids", "cpu", "cpu_weight", "stall_after", "repeats"}

// decl is what a contract declares, read from a merged agent.Contract (Of) or from YAML text (Declared): the one
// input build turns into a View, so both views say the same entry the same way.
type decl struct {
	file    string
	name    string
	extends []string
	tier    string
	record  string
	command []string
	cmdPos  agent.Pos

	lists map[string][]item

	// http is net.http's entries; ingress net.ingress's, and ingressKey says the key is present, even empty (then only
	// the sources listed reach the listeners).
	http       []httpRule
	ingress    []ingressRule
	ingressKey bool

	// gate is the gate's scored rules as agent.CompileGateConfig reads them, nil when there are none or they do not
	// read (gateBad); gatePos is each rule's position, in its Rules' order.
	gate    *gate.Policy
	gatePos []agent.Pos
	gateBad bool

	hasFS, hasNet, hasExec bool
	execAllowKey           bool // exec.allow is present (allow-list mode), even empty
	envPassKey             bool // env.pass is present
	denyReadOff            bool // deny_read: [] turns the built-in list off
	denyReadPos            agent.Pos
	hostSockets, setuid    bool
	mcp                    int

	limits     []limit
	askTimeout string
	askAlways  bool // ask.on_timeout: refuse_always (a timed-out question stays refused for the run)
	askPos     agent.Pos
}

func newDecl(file string) decl {
	return decl{file: file, lists: map[string][]item{}}
}

// fromContract reads a merged contract: its entries in merge order, each with the file and line it came from.
func fromContract(c *agent.Contract, file string) decl {
	d := newDecl(file)
	d.name = c.Name
	d.extends = slices.Clone([]string(c.Extends))
	d.tier = string(c.Tier)
	d.record = string(c.Record)
	d.command = slices.Clone(c.Command)
	d.cmdPos, _ = c.Pos("command")
	d.hostSockets = c.HostSockets
	d.setuid = c.Setuid
	d.mcp = len(c.MCP)
	add := func(key string, entries []string) {
		for i, e := range entries {
			p, _ := c.Pos(key + "." + strconv.Itoa(i))
			d.lists[key] = append(d.lists[key], item{entry: e, pos: p})
		}
	}
	if c.FS != nil {
		d.hasFS = true
		add(kFSWrite, c.FS.Write)
		add(kFSAsk, c.FS.Ask)
		add(kFSDenyRead, c.FS.DenyRead)
		add(kFSAskRead, c.FS.AskRead)
		add(kFSDenyWrite, c.FS.DenyWrite)
		add(kFSWatch, c.FS.Watch)
		if c.FS.DenyRead != nil && len(c.FS.DenyRead) == 0 {
			d.denyReadOff = true
			d.denyReadPos, _ = c.Pos(kFSDenyRead)
		}
	}
	// The section's presence only picks the default's words; its mode is the contract's one spelling (ADR 0048 (1)).
	if ex := c.Exec; ex != nil {
		d.hasExec = true
		d.execAllowKey = !c.ExecUnrestricted()
		add(kExecAllow, ex.Allow)
		add(kExecDeny, ex.Deny)
		add(kExecAsk, ex.Ask)
	}
	if c.Net != nil {
		d.hasNet = true
		add(kNetAllow, c.Net.Allow)
		add(kNetAsk, c.Net.Ask)
		add(kNetListen, c.Net.Listen)
		for i, h := range c.Net.HTTP {
			p, _ := c.Pos("net.http." + strconv.Itoa(i))
			d.http = append(d.http, httpRule{host: h.Host, allow: slices.Clone(h.Allow), methods: slices.Clone(h.Methods), pos: p})
		}
		d.ingressKey = c.Net.Ingress != nil
		for i, r := range c.Net.Ingress {
			p, _ := c.Pos("net.ingress." + strconv.Itoa(i))
			d.ingress = append(d.ingress, ingressRule{from: r.From, to: r.To, pos: p})
		}
	}
	d.envPassKey = c.Env.Pass != nil
	add(kEnvPass, c.Env.Pass)
	add(kEnvDeny, c.Env.Deny)
	for _, name := range sortedKeys(c.Env.Set) {
		p, _ := c.Pos("env.set." + name)
		d.lists[kEnvSet] = append(d.lists[kEnvSet], item{entry: name, pos: p})
	}
	for i, m := range c.Models {
		p, _ := c.Pos("models." + strconv.Itoa(i))
		d.lists[kModels] = append(d.lists[kModels], item{entry: hostPort(m.Host, m.Port), pos: p})
	}
	l := c.Limits
	vals := map[string]string{}
	if l.Wall != nil {
		vals["wall"] = l.Wall.String()
	}
	if l.Tokens != nil {
		vals["tokens"] = strconv.FormatInt(*l.Tokens, 10)
	}
	if l.CostUSD != nil {
		vals["cost_usd"] = strconv.FormatFloat(*l.CostUSD, 'f', -1, 64)
	}
	if l.Memory != nil {
		vals["memory"] = l.Memory.String()
	}
	if l.MemoryHigh != nil {
		vals["memory_high"] = l.MemoryHigh.String()
	}
	if l.Pids != nil {
		vals["pids"] = strconv.Itoa(*l.Pids)
	}
	if l.CPU != nil {
		vals["cpu"] = string(*l.CPU)
	}
	if l.CPUWeight != nil {
		vals["cpu_weight"] = strconv.Itoa(*l.CPUWeight)
	}
	if l.StallAfter != nil {
		vals["stall_after"] = l.StallAfter.String()
	}
	if l.Repeats != nil {
		vals["repeats"] = strconv.Itoa(*l.Repeats)
	}
	for _, k := range limitKeys {
		if v, ok := vals[k]; ok {
			p, _ := c.Pos("limits." + k)
			d.limits = append(d.limits, limit{key: k, value: v, pos: p})
		}
	}
	sortLimits(d.limits)
	readAsk(&d, &c.Ask, func(key string) agent.Pos { p, _ := c.Pos(key); return p })
	if c.Gate.Kind != 0 {
		d.gate, d.gateBad = readGate(c)
		for i := range d.gate.Rules() {
			p, _ := c.Pos("gate.rules." + strconv.Itoa(i))
			d.gatePos = append(d.gatePos, p)
		}
	}
	return d
}

// readGate reads a contract's gate as the compiler does (without the home: a read pattern keeps its ~), so the view
// lists the rules a run scores, in their order; bad is true for a gate: key whose rules do not read.
func readGate(c *agent.Contract) (p *gate.Policy, bad bool) {
	p, err := agent.CompileGateConfig(c)
	if err != nil {
		return nil, true
	}
	return p, false
}

// readAsk reads the ask: block's timeout and on_timeout, which the contract keeps as a node.
func readAsk(d *decl, n *yaml.Node, pos func(string) agent.Pos) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	if t := mapGet(n, "timeout"); t != nil && t.Kind == yaml.ScalarNode {
		d.askTimeout = t.Value
		d.askPos = pos("ask.timeout")
		if d.askPos.Line == 0 {
			d.askPos = agent.Pos{File: d.file, Line: t.Line, Col: t.Column}
		}
	}
	if o := mapGet(n, "on_timeout"); o != nil && o.Kind == yaml.ScalarNode {
		d.askAlways = o.Value == string(agent.AskOnTimeoutRefuseAlways)
	}
}

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
				d.lists[full] = append(d.lists[full], item{entry: e.Value, pos: at(e)})
			}
		}
	}
	d.name = scalar(root, "name")
	d.tier = scalar(root, "tier")
	d.record = scalar(root, "record")
	d.hostSockets = scalar(root, "host_sockets") == "true"
	d.setuid = scalar(root, "setuid") == "true"
	if e := mapGet(root, "extends"); e != nil {
		switch e.Kind {
		case yaml.ScalarNode:
			d.extends = []string{e.Value}
		case yaml.SequenceNode:
			for _, x := range e.Content {
				d.extends = append(d.extends, x.Value)
			}
		}
	}
	if c := mapGet(root, "command"); c != nil && c.Kind == yaml.SequenceNode {
		for _, x := range c.Content {
			d.command = append(d.command, x.Value)
		}
		d.cmdPos = at(c)
	}
	if m := mapGet(root, "mcp"); m != nil && m.Kind == yaml.SequenceNode {
		d.mcp = len(m.Content)
	}
	if fs := mapGet(root, "fs"); fs != nil && fs.Kind == yaml.MappingNode {
		d.hasFS = true
		for _, k := range []string{"write", "ask", "deny_read", "ask_read", "deny_write", "watch"} {
			seq(fs, "fs", k)
		}
		if dr := mapGet(fs, "deny_read"); dr != nil && dr.Kind == yaml.SequenceNode && len(dr.Content) == 0 {
			d.denyReadOff = true
			d.denyReadPos = at(dr)
		}
	}
	if ex := mapGet(root, "exec"); ex != nil && ex.Kind == yaml.MappingNode {
		d.hasExec = true
		d.execAllowKey = mapGet(ex, "allow") != nil || (mapGet(ex, "deny") == nil && mapGet(ex, "ask") == nil)
		for _, k := range []string{"allow", "deny", "ask"} {
			seq(ex, "exec", k)
		}
	}
	if nt := mapGet(root, "net"); nt != nil && nt.Kind == yaml.MappingNode {
		d.hasNet = true
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
					d.http = append(d.http, httpRule{host: scalar(h, "host"), allow: scalars(h, "allow"), methods: scalars(h, "methods"), pos: at(h)})
				}
			}
		}
		if in := mapGet(nt, "ingress"); in != nil && in.Kind == yaml.SequenceNode {
			d.ingressKey = true
			for _, r := range in.Content {
				if r.Kind == yaml.MappingNode {
					d.ingress = append(d.ingress, ingressRule{from: scalar(r, "from"), to: scalar(r, "to"), pos: at(r)})
				}
			}
		}
	}
	if env := mapGet(root, "env"); env != nil && env.Kind == yaml.MappingNode {
		d.envPassKey = mapGet(env, "pass") != nil
		seq(env, "env", "pass")
		seq(env, "env", "deny")
		if set := mapGet(env, "set"); set != nil && set.Kind == yaml.MappingNode {
			// Names only: the value node is never read (TestNoEnvValues).
			for i := 0; i+1 < len(set.Content); i += 2 {
				k := set.Content[i]
				d.lists[kEnvSet] = append(d.lists[kEnvSet], item{entry: k.Value, pos: at(k)})
			}
			slices.SortStableFunc(d.lists[kEnvSet], func(a, b item) int { return cmp.Compare(a.entry, b.entry) })
		}
	}
	if ms := mapGet(root, "models"); ms != nil && ms.Kind == yaml.SequenceNode {
		for _, m := range ms.Content {
			if m.Kind != yaml.MappingNode {
				continue
			}
			port, _ := strconv.Atoi(scalar(m, "port"))
			d.lists[kModels] = append(d.lists[kModels], item{entry: hostPort(scalar(m, "host"), port), pos: at(m)})
		}
	}
	if lm := mapGet(root, "limits"); lm != nil && lm.Kind == yaml.MappingNode {
		for _, k := range limitKeys {
			if v := mapGet(lm, k); v != nil && v.Kind == yaml.ScalarNode && v.Tag != "!!null" {
				d.limits = append(d.limits, limit{key: k, value: v.Value, pos: at(v)})
			}
		}
	}
	sortLimits(d.limits)
	readAsk(&d, mapGet(root, "ask"), func(string) agent.Pos { return agent.Pos{} })
	if g := mapGet(root, "gate"); g != nil {
		d.gate, d.gateBad = readGate(&agent.Contract{Gate: *g})
		if rs := mapGet(g, "rules"); rs != nil && rs.Kind == yaml.SequenceNode && len(rs.Content) == len(d.gate.Rules()) {
			for _, n := range rs.Content {
				d.gatePos = append(d.gatePos, at(n))
			}
		}
	}
	return d, nil
}

// mapGet is the value of key in a mapping node, nil when absent.
func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func hostPort(host string, port int) string {
	if port > 0 {
		return host + ":" + strconv.Itoa(port)
	}
	return host
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// sortLimits puts the limits in the order the file writes them; keys at one line (a flow mapping) keep limitKeys'.
func sortLimits(ls []limit) {
	slices.SortStableFunc(ls, func(a, b limit) int { return cmp.Compare(a.pos.Line, b.pos.Line) })
}
