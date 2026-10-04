// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"gopkg.in/yaml.v3"
)

func gateNode(n *yaml.Node) (*yaml.Node, error) {
	for depth := 0; n != nil && (n.Kind == yaml.DocumentNode || n.Kind == yaml.AliasNode); depth++ {
		if depth >= 16 {
			return nil, fmt.Errorf("gate: alias nesting exceeds 16")
		}
		switch {
		case n.Kind == yaml.AliasNode:
			n = n.Alias
		case len(n.Content) == 1:
			n = n.Content[0]
		default:
			return nil, fmt.Errorf("gate: malformed document")
		}
	}
	if n == nil {
		return nil, fmt.Errorf("gate: invalid alias")
	}
	return n, nil
}

func gateMapping(n *yaml.Node, name string) (map[string]*yaml.Node, error) {
	n, err := gateNode(n)
	if err != nil {
		return nil, err
	}
	if n.Kind != yaml.MappingNode || len(n.Content)%2 != 0 {
		return nil, fmt.Errorf("%s must be a mapping", name)
	}
	m := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || m[key.Value] != nil {
			return nil, fmt.Errorf("%s: invalid or duplicate field %q", name, key.Value)
		}
		value, e := gateNode(n.Content[i+1])
		if e != nil {
			return nil, e
		}
		m[key.Value] = value
	}
	return m, nil
}

func gateInteger(n *yaml.Node, name string) (int, error) {
	if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" || !intRE.MatchString(n.Value) {
		return 0, fmt.Errorf("%s requires a decimal integer", name)
	}
	v, err := strconv.Atoi(n.Value)
	if err != nil || v < 0 || v > gate.MaxScore {
		return 0, fmt.Errorf("%s must be 0..%d", name, gate.MaxScore)
	}
	return v, nil
}

func gateRule(key string, score int) (gate.Rule, error) {
	r := gate.Rule{Score: score}
	if len(key) > gate.MaxText+32 {
		return r, fmt.Errorf("gate predicate exceeds text bound")
	}
	switch {
	case key == "fs.write outside worktree":
		r.Predicate = gate.WriteOutsideWorktree
	case key == "net to undeclared host":
		r.Predicate = gate.NetUndeclared
	case strings.HasPrefix(key, "fs.read matches "):
		r.Predicate, r.Argument = gate.ReadMatches, strings.TrimPrefix(key, "fs.read matches ")
	case strings.HasPrefix(key, "exec matches "):
		r.Predicate, r.Argument = gate.ExecMatches, strings.TrimPrefix(key, "exec matches ")
	case strings.HasPrefix(key, "net to "):
		r.Predicate, r.Argument = gate.NetTo, strings.TrimPrefix(key, "net to ")
	default:
		return r, fmt.Errorf("unknown gate predicate %q", key)
	}
	if strings.HasPrefix(r.Argument, "\"") {
		arg, err := strconv.Unquote(r.Argument)
		if err != nil {
			return r, fmt.Errorf("invalid quoted gate argument: %w", err)
		}
		r.Argument = arg
	}
	if r.Predicate == gate.NetTo {
		e, err := ParseEndpoint(r.Argument)
		if err != nil || e.Kind != EndpointHost || e.Proto != ProtoInet || e.Port <= 0 {
			return r, fmt.Errorf("net gate requires a literal host:port, without a protocol selector")
		}
	}
	return r, nil
}

// CompileGateConfig decodes the retained merge-compatible YAML node without
// evaluating expressions. Only the five fixed predicate prefixes are accepted.
func CompileGateConfig(c *Contract) (*gate.Policy, error) { return compileGateConfig(c, "") }

func compileGateConfig(c *Contract, home string) (*gate.Policy, error) {
	if c == nil || c.Gate.Kind == 0 {
		return nil, nil
	}
	m, err := gateMapping(&c.Gate, "gate")
	if err != nil {
		return nil, err
	}
	held := false
	for key, value := range m {
		switch key {
		case "rules", "thresholds":
		case "completion":
			if value == nil || value.Kind != yaml.ScalarNode || (value.Value != gate.CompletionCopied && value.Value != gate.CompletionHeld) {
				return nil, fmt.Errorf("gate.completion is %s or %s", gate.CompletionCopied, gate.CompletionHeld)
			}
			held = value.Value == gate.CompletionHeld
		default:
			return nil, fmt.Errorf("gate: unknown field %q", key)
		}
	}
	allow, ask := 50, 80
	if n := m["thresholds"]; n != nil {
		thresholds, e := gateMapping(n, "gate.thresholds")
		if e != nil {
			return nil, e
		}
		for key, value := range thresholds {
			if key != "allow" && key != "ask" {
				return nil, fmt.Errorf("gate.thresholds: unknown field %q", key)
			}
			v, e := gateInteger(value, "gate.thresholds."+key)
			if e != nil {
				return nil, e
			}
			if key == "allow" {
				allow = v
			} else {
				ask = v
			}
		}
	}
	var rules []gate.Rule
	if n := m["rules"]; n != nil {
		if n.Kind != yaml.SequenceNode || len(n.Content) > gate.MaxRules {
			return nil, fmt.Errorf("gate.rules requires at most %d entries", gate.MaxRules)
		}
		for i, node := range n.Content {
			entry, e := gateMapping(node, fmt.Sprintf("gate.rules[%d]", i))
			if e != nil {
				return nil, e
			}
			if len(entry) != 1 {
				return nil, fmt.Errorf("gate.rules[%d] requires exactly one scored predicate", i)
			}
			for key, value := range entry {
				score, e := gateInteger(value, fmt.Sprintf("gate.rules[%d]", i))
				if e != nil {
					return nil, e
				}
				r, e := gateRule(key, score)
				if e != nil {
					return nil, e
				}
				if home != "" && r.Predicate == gate.ReadMatches && strings.HasPrefix(r.Argument, "~/") {
					// The home is cleaned and loses a trailing '/', so the expansion is a clean pattern (gate R1).
					r.Argument = strings.TrimSuffix(filepath.Clean(home), "/") + r.Argument[1:]
				}
				rules = append(rules, r)
			}
		}
	}
	p, err := gate.New(rules, allow, ask)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, nil
	}
	if held {
		p = p.WithHeldCompletion()
	}
	return p, nil
}

func gateRequiresBroker(c *Contract) bool {
	p, err := CompileGateConfig(c)
	// MayAskReadWrite covers each fs kind alone and a read-write open both score, their scores summed.
	return err == nil && (p.MayAskReadWrite() || p.MayAsk(gate.Net))
}

// checkGatePredicate is the schema check of a gate rule's key. Only a key that names no predicate is told to use one
// of the five; a refused argument of a known predicate is told to rewrite it as the message says, which names the
// spelling to write where it has one (a refused read pattern was told to change its predicate).
func checkGatePredicate(v string) (string, string) {
	r, err := gateRule(v, 0)
	if err != nil && r.Predicate == 0 && len(v) <= gate.MaxText+32 {
		return err.Error(), "use one of the five documented gate predicates"
	}
	if err == nil {
		_, err = gate.New([]gate.Rule{r}, 50, 80)
	}
	if err != nil {
		return err.Error(), "rewrite the argument as the message says, keeping the predicate"
	}
	return "", ""
}

func validateGate(ds *diags, c *Contract, at func(string) Pos) {
	p, err := CompileGateConfig(c)
	if err != nil {
		ds.errorf(at("gate"), CodeSchema, "%v", err)
		return
	}
	if p == nil {
		return
	}
	if c.IOUring || c.Setuid || backend.Tier(c.Tier) == backend.TierObserve {
		ds.errorf(at("gate"), CodeSchema, "gate requires an enforcing tier with io_uring and setuid disabled")
	}
	for _, raw := range p.HostEndpoints() {
		host, port, _ := net.SplitHostPort(raw)
		if _, e := netip.ParseAddr(host); e == nil {
			continue
		}
		present := false
		if c.Net != nil {
			for _, decl := range append(append([]string(nil), c.Net.Allow...), c.Net.Ask...) {
				ep, e := ParseEndpoint(decl)
				if e == nil && strings.EqualFold(strings.TrimSuffix(ep.Host, "."), strings.TrimSuffix(host, ".")) && strconv.Itoa(ep.Port) == port {
					present = true
				}
			}
		}
		for _, model := range c.Models {
			if strings.EqualFold(strings.TrimSuffix(model.Host, "."), strings.TrimSuffix(host, ".")) && strconv.Itoa(model.Port) == port {
				present = true
			}
		}
		if !present {
			ds.errorf(at("gate"), CodeSchema, "hostname gate %q requires a declared net.allow, net.ask or model endpoint; use a literal IP to score other destinations", raw)
		}
	}
	if p.MayAsk(gate.Net) {
		if cfg, e := CompileAskConfig(c); e == nil && cfg != nil && cfg.Hold == AskHoldRequest {
			ds.errorf(at("gate"), CodeSchema, "network gate approvals require connect or first_write holds; request inspection cannot approve raw destinations")
		}
	}
	if p.MayAsk(gate.Exec) {
		ds.warnf(at("gate"), CodeUnenforced, "gate exec approvals have no safe completion and fail closed; configure denial scores above the ask threshold")
	}
	// ADR 0041 D6: with no net: section the gate is the run's only network control. Its IP connects and sends
	// are relayed by the supervisor so a sibling cannot rewrite the scored address, and the unix connects and
	// datagrams it scores are continued best effort (D1).
	if p.Has(gate.Net) && c.Net == nil {
		ds.warnf(at("gate"), CodeUnenforced, "a net gate under a contract with no net: section is the run's only network control: "+
			"every IP connect and addressed send is relayed by the supervisor (up to its relay ceiling), and unix connects and datagrams the gate scores are best effort; "+
			"declare a net: section for a kernel network floor")
	}
}

func (k *compiler) gateConfig() {
	p, err := compileGateConfig(k.c, k.o.home)
	if err != nil {
		k.ds.errorf(k.pos("gate"), CodeSchema, "%v", err)
		return
	}
	if p == nil {
		return
	}
	if k.rt.Tier == backend.TierObserve {
		k.ds.errorf(k.pos("gate"), CodeUnenforced, "gate requires an enforcing tier")
		return
	}
	// The worktree relative read patterns are matched from is this compile's: a pattern needing more leading ".."
	// than it has ancestors never fires in this run, so it is refused.
	wd := k.resolve(k.o.cwd)
	if err := p.CheckWorktree(wd); err != nil {
		k.ds.errorf(k.pos("gate"), CodeSchema, "%v", err).fix("write the pattern as the message says, or with no more leading \"..\" than the worktree has ancestors")
		return
	}
	k.rt.Gate = p
	k.rt.Workdir = wd
	k.warnBestEffort()
}
