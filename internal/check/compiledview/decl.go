// SPDX-License-Identifier: Apache-2.0

package compiledview

import (
	"cmp"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Item is one declared entry and where it was written.
type Item struct {
	Entry string
	Pos   agent.Pos
}

// Limit is one declared limits key, its value as text.
type Limit struct {
	Key, Value string
	Pos        agent.Pos
}

// The list keys a decl holds, each a contract key (net.http's and net.ingress's entries, which are mappings, are held
// apart: Declaration.HTTP, Declaration.Ingress).
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
	kExecPriv    = "exec.privileged"
	kExecArgs    = "exec.args" // no entry writes it: a constrained tool's refusal of an invocation no allow entry names
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

// HTTPRule is one net.http entry: the requests a model service may be sent (agent.HTTPRule).
type HTTPRule struct {
	Host           string
	Allow, Methods []string
	Pos            agent.Pos
}

// IngressRule is one net.ingress entry: a source a declared listener accepts (agent.IngressRule).
type IngressRule struct {
	From, To string
	Pos      agent.Pos
}

// LimitKeys are the limits keys in the order the limits group lists them.
var LimitKeys = []string{"wall", "tokens", "cost_usd", "memory", "memory_high", "pids", "cpu", "cpu_weight", "stall_after", "repeats"}

// MCPServer is one mcp: entry as the view says it: a stdio server the agent starts (Command) or an HTTP server it
// connects to (URL), and whether its tool calls are held to Tego's MCP relay.
type MCPServer struct {
	Name    string
	Command []string
	URL     string
	// Relayed: the server declares relay mediation (tools: or business_rules:), so the agent's route to it is the
	// relay, whose per-tool rules this view does not list. BusinessRules: its command gets no exec grant of the agent's.
	Relayed, BusinessRules bool
	Pos                    agent.Pos
}

// Declaration is what a contract declares, read from a merged agent.Contract (Of) or from YAML text (Declared): the one
// input build turns into a View, so both views say the same entry the same way.
type Declaration struct {
	File    string
	Name    string
	Extends []string
	Tier    string
	Record  string
	Command []string
	CmdPos  agent.Pos

	Lists map[string][]Item

	// HTTP is net.http's entries; Ingress net.ingress's, and IngressKey says the key is present, even empty (then only
	// the sources listed reach the listeners).
	HTTP       []HTTPRule
	Ingress    []IngressRule
	IngressKey bool

	// Gate is the gate's scored rules as agent.CompileGateConfig reads them, nil when there are none or they do not
	// read (GateBad); GatePos is each rule's position, in its Rules' order.
	Gate    *gate.Policy
	GatePos []agent.Pos
	GateBad bool

	HasFS, HasNet, HasExec bool
	ExecAllowKey           bool // exec.allow is present (allow-list mode), even empty
	EnvPassKey             bool // env.pass is present
	DenyReadOff            bool // deny_read: [] turns the built-in list off
	DenyReadPos            agent.Pos
	HostSockets, Setuid    bool
	MCP                    int
	// MCPServers are the mcp: entries in order (MCP is their count).
	MCPServers []MCPServer

	Limits     []Limit
	AskTimeout string
	AskAlways  bool // ask.on_timeout: refuse_always (a timed-out question stays refused for the run)
	AskPos     agent.Pos
}

// NewDeclaration prepares empty declaration data for one contract file.
func NewDeclaration(file string) Declaration {
	return Declaration{File: file, Lists: map[string][]Item{}}
}

// fromContract reads a merged contract: its entries in merge order, each with the file and line it came from.
func fromContract(c *agent.Contract, file string) Declaration {
	d := NewDeclaration(file)
	d.Name = c.Name
	d.Extends = slices.Clone([]string(c.Extends))
	d.Tier = string(c.Tier)
	d.Record = string(c.Record)
	d.Command = slices.Clone(c.Command)
	d.CmdPos, _ = c.Pos("command")
	d.HostSockets = c.HostSockets
	d.Setuid = c.Setuid
	d.MCP = len(c.MCP)
	for i, m := range c.MCP {
		p, _ := c.Pos("mcp." + strconv.Itoa(i))
		d.MCPServers = append(d.MCPServers, MCPServer{Name: m.Name, Command: slices.Clone(m.Command), URL: m.URL,
			Relayed: m.Relayed(), BusinessRules: m.BusinessRules != nil, Pos: p})
	}
	add := func(key string, entries []string) {
		for i, e := range entries {
			p, _ := c.Pos(key + "." + strconv.Itoa(i))
			d.Lists[key] = append(d.Lists[key], Item{Entry: e, Pos: p})
		}
	}
	if c.FS != nil {
		d.HasFS = true
		add(kFSWrite, c.FS.Write)
		add(kFSAsk, c.FS.Ask)
		add(kFSDenyRead, c.FS.DenyRead)
		add(kFSAskRead, c.FS.AskRead)
		add(kFSDenyWrite, c.FS.DenyWrite)
		add(kFSWatch, c.FS.Watch)
		if c.FS.DenyRead != nil && len(c.FS.DenyRead) == 0 {
			d.DenyReadOff = true
			d.DenyReadPos, _ = c.Pos(kFSDenyRead)
		}
	}
	// The section's presence only picks the default's words; its mode is the contract's one spelling (ADR 0048 (1)).
	if ex := c.Exec; ex != nil {
		d.HasExec = true
		d.ExecAllowKey = !c.ExecUnrestricted()
		add(kExecAllow, ex.Allow)
		add(kExecDeny, ex.Deny)
		add(kExecAsk, ex.Ask)
		add(kExecPriv, ex.Privileged)
	}
	if c.Net != nil {
		d.HasNet = true
		add(kNetAllow, c.Net.Allow)
		add(kNetAsk, c.Net.Ask)
		add(kNetListen, c.Net.Listen)
		for i, h := range c.Net.HTTP {
			p, _ := c.Pos("net.http." + strconv.Itoa(i))
			d.HTTP = append(d.HTTP, HTTPRule{Host: h.Host, Allow: slices.Clone(h.Allow), Methods: slices.Clone(h.Methods), Pos: p})
		}
		d.IngressKey = c.Net.Ingress != nil
		for i, r := range c.Net.Ingress {
			p, _ := c.Pos("net.ingress." + strconv.Itoa(i))
			d.Ingress = append(d.Ingress, IngressRule{From: r.From, To: r.To, Pos: p})
		}
	}
	d.EnvPassKey = c.Env.Pass != nil
	add(kEnvPass, c.Env.Pass)
	add(kEnvDeny, c.Env.Deny)
	for _, name := range SortedKeys(c.Env.Set) {
		p, _ := c.Pos("env.set." + name)
		d.Lists[kEnvSet] = append(d.Lists[kEnvSet], Item{Entry: name, Pos: p})
	}
	for i, m := range c.Models {
		p, _ := c.Pos("models." + strconv.Itoa(i))
		d.Lists[kModels] = append(d.Lists[kModels], Item{Entry: HostPort(m.Host, m.Port), Pos: p})
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
	for _, k := range LimitKeys {
		if v, ok := vals[k]; ok {
			p, _ := c.Pos("limits." + k)
			d.Limits = append(d.Limits, Limit{Key: k, Value: v, Pos: p})
		}
	}
	SortLimits(d.Limits)
	ReadAsk(&d, &c.Ask, func(key string) agent.Pos { p, _ := c.Pos(key); return p })
	if c.Gate.Kind != 0 {
		d.Gate, d.GateBad = ReadGate(c)
		for i := range d.Gate.Rules() {
			p, _ := c.Pos("gate.rules." + strconv.Itoa(i))
			d.GatePos = append(d.GatePos, p)
		}
	}
	return d
}

// ReadGate reads a contract's gate as the compiler does (without the home: a read pattern keeps its ~), so the view
// lists the rules a run scores, in their order; bad is true for a gate: key whose rules do not read.
func ReadGate(c *agent.Contract) (p *gate.Policy, bad bool) {
	p, err := agent.CompileGateConfig(c)
	if err != nil {
		return nil, true
	}
	return p, false
}

// ReadAsk reads the ask: block's timeout and on_timeout, which the contract keeps as a node.
func ReadAsk(d *Declaration, n *yaml.Node, pos func(string) agent.Pos) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	if t := MapGet(n, "timeout"); t != nil && t.Kind == yaml.ScalarNode {
		d.AskTimeout = t.Value
		d.AskPos = pos("ask.timeout")
		if d.AskPos.Line == 0 {
			d.AskPos = agent.Pos{File: d.File, Line: t.Line, Col: t.Column}
		}
	}
	if o := MapGet(n, "on_timeout"); o != nil && o.Kind == yaml.ScalarNode {
		d.AskAlways = o.Value == string(agent.AskOnTimeoutRefuseAlways)
	}
}

// MapGet is the value of key in a mapping node, nil when absent.
func MapGet(n *yaml.Node, key string) *yaml.Node {
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

// HostPort preserves the declared host and optional port in its entry spelling.
func HostPort(host string, port int) string {
	if port > 0 {
		return host + ":" + strconv.Itoa(port)
	}
	return host
}

// SortedKeys returns environment names in display order, without their values.
func SortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// SortLimits puts the limits in the order the file writes them; keys at one line (a flow mapping) keep limitKeys'.
func SortLimits(ls []Limit) {
	slices.SortStableFunc(ls, func(a, b Limit) int { return cmp.Compare(a.Pos.Line, b.Pos.Line) })
}
