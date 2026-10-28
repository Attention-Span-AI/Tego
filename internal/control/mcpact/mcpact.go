// SPDX-License-Identifier: Apache-2.0

package mcpact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Errors a page turns into words.
var (
	ErrBadRun     = errors.New("mcpact: no such run")
	ErrNotRunning = errors.New("mcpact: the run is not running, so a live switch would apply to nothing")
	ErrNoServer   = errors.New("mcpact: the run declares no such MCP server")
	ErrNotRelayed = errors.New("mcpact: the server is not behind Tego's relay (no tools: in its contract entry)")
	ErrNoBroker   = errors.New("mcpact: the run has no approvals (no ask: section), so an asked tool would be refused every time")
	ErrGoverned   = errors.New("mcpact: a change that loosens a run's rules is refused from inside a run")
	ErrBadName    = errors.New("mcpact: not a server or tool name")
)

// opMCPTool is the ask op of a held tools/call (internal/runtime/mcprelay.OpMCPTool, which this package may not link).
const opMCPTool = "mcp_tool"

// maxContract bounds the contract copy read.
const maxContract = 1 << 20

// Tool is one tool of a server as the page shows it.
type Tool struct {
	Name string
	// Contract is what the contract alone decides; Decision what is decided now, by Rule.
	Contract, Decision, Rule string
	// Live is whether a live switch decides it.
	Live                  bool
	Calls, Refused, Asked int
}

// Server is one declared MCP server.
type Server struct {
	Name      string
	Transport string // stdio | http
	Relayed   bool
	Tools     []Tool
}

// State is the page's view of a run's MCP servers.
type State struct {
	Run     string
	Running bool
	// Broker is whether the run can hold a call for a person (run_start capabilities.ask).
	Broker  bool
	Servers []Server
}

// Plan is one previewed switch.
type Plan struct {
	Run, Server, Tool string
	// From is the decision now and the rule that makes it; To the decision after the change.
	From mcptool.Result
	To   string
	// Reset drops the live switch instead of setting one.
	Reset bool
	// Loosens is whether the change gives the agent more; only then is Ack needed.
	Loosens bool
	Ack     string
	// Changed is set by Set and Reset: whether the overlay changed.
	Changed bool

	rules mcptool.Rules // the contract's, for apply to decide again under the writers' lock
}

// Service is the MCP tools service over one ledger root.
type Service struct {
	Root string
	// Now stamps a change; nil is time.Now.
	Now func() time.Time
	// governed reports whether the caller is inside a run; nil is runact.SelfGoverned. Tests replace it.
	governed func() (bool, error)
	// beforeLock runs in apply between the preview's read and the writers' lock; nil in production. Tests use it to move
	// the overlay there.
	beforeLock func()
}

// New is the service over the ledger root.
func New(root string) *Service { return &Service{Root: root} }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) runDir(run string) (string, error) {
	if !ledger.IsRunID(run) {
		return "", fmt.Errorf("%q: %w", run, ErrBadRun)
	}
	dir := filepath.Join(s.Root, run)
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("%s: %w", run, ErrBadRun)
	}
	return dir, nil
}

// contractServer is one mcp[] entry of a contract copy, as much of it as this service reads.
type contractServer struct {
	Name    string              `yaml:"name"`
	Command []string            `yaml:"command"`
	URL     string              `yaml:"url"`
	Tools   map[string][]string `yaml:"tools"`
	hasTool bool
}

func (c contractServer) rules() mcptool.Rules {
	if c.Tools == nil {
		return mcptool.Rules{}
	}
	r := mcptool.Rules{Deny: c.Tools["deny"], Ask: c.Tools["ask"]}
	if a, ok := c.Tools["allow"]; ok {
		r.Allow = a
		if r.Allow == nil {
			r.Allow = []string{}
		}
	}
	return r
}

// servers reads the run's contract copy's mcp[] entries. The copy is the compiled, self-contained contract, so its
// mcp list is the run's.
func servers(dir string) ([]contractServer, error) {
	f, err := os.OpenFile(filepath.Join(dir, "contract.yaml"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxContract+1))
	if err != nil || len(b) > maxContract {
		return nil, fmt.Errorf("mcpact: contract copy unreadable or too large")
	}
	var doc struct {
		MCP []yaml.Node `yaml:"mcp"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("mcpact: contract copy: %w", err)
	}
	var out []contractServer
	for i := range doc.MCP {
		var cs contractServer
		if err := doc.MCP[i].Decode(&cs); err != nil {
			return nil, fmt.Errorf("mcpact: contract copy mcp: %w", err)
		}
		// A present tools: key, even {}, is what puts a server behind the relay.
		for j := 0; j+1 < len(doc.MCP[i].Content); j += 2 {
			if doc.MCP[i].Content[j].Value == "tools" {
				cs.hasTool = true
				if cs.Tools == nil {
					cs.Tools = map[string][]string{}
				}
			}
		}
		out = append(out, cs)
	}
	return out, nil
}

// facts is what the run's ledger says: its run_start capabilities.ask, and per tool its relay lines and asks.
type facts struct {
	broker                bool
	calls, refused, asked map[[2]string]int
}

func readFacts(dir string) facts {
	f := facts{calls: map[[2]string]int{}, refused: map[[2]string]int{}, asked: map[[2]string]int{}}
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return f
	}
	defer func() { _ = rd.Close() }()
	first := true
	for e, err := range rd.Iter() {
		if err != nil {
			break
		}
		if first {
			first = false
			if e.Kind == record.KindRunStart {
				var p struct {
					Capabilities map[string]bool `json:"capabilities"`
				}
				if json.Unmarshal(e.Payload, &p) == nil {
					f.broker = p.Capabilities["ask"]
				}
			}
			continue
		}
		switch {
		case e.Kind == record.KindMCP && e.Source == record.SourceProxy:
			var p record.MCPPayload
			if e.DecodePayload(&p) != nil || p.Tool == "" {
				continue
			}
			k := [2]string{p.Name, p.Tool}
			if e.Verdict == record.VerdictAllow {
				f.calls[k]++
			} else {
				f.refused[k]++
			}
		case e.Kind == record.KindAsk:
			var p struct {
				Op     string `json:"op"`
				Target string `json:"target"`
			}
			if e.DecodePayload(&p) != nil || p.Op != opMCPTool {
				continue
			}
			if sv, t, ok := strings.Cut(p.Target, " "); ok {
				f.asked[[2]string{sv, t}]++
			}
		}
	}
	return f
}

func readOverlay(dir, run string) (*mcptools.Overlay, error) {
	o, err := mcptools.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		return mcptools.New(run), nil
	}
	return o, err
}

// State is the run's MCP servers with every tool known (seen in a tools/list, named by the contract, switched live,
// or in the ledger), each with its decision now and its counts.
func (s *Service) State(run string) (*State, error) {
	dir, err := s.runDir(run)
	if err != nil {
		return nil, err
	}
	svs, err := servers(dir)
	if err != nil {
		return nil, err
	}
	o, err := readOverlay(dir, run)
	if err != nil {
		return nil, err
	}
	seen, _ := mcptools.ReadSeen(dir)
	fc := readFacts(dir)
	held, _, _ := runlock.ProbeLock(dir)
	st := &State{Run: run, Running: held, Broker: fc.broker}
	for _, cs := range svs {
		sv := Server{Name: cs.Name, Transport: "stdio", Relayed: cs.hasTool}
		if cs.URL != "" {
			sv.Transport = "http"
		}
		rules := cs.rules()
		names := map[string]bool{}
		for _, l := range [][]string{rules.Allow, rules.Deny, rules.Ask} {
			for _, t := range l {
				names[t] = true
			}
		}
		for _, t := range seen[cs.Name] {
			names[t] = true
		}
		for _, e := range o.Tools {
			if e.Server == cs.Name {
				names[e.Tool] = true
			}
		}
		for _, m := range []map[[2]string]int{fc.calls, fc.refused, fc.asked} {
			for k := range m {
				if k[0] == cs.Name && mcptools.ValidName(k[1]) {
					names[k[1]] = true
				}
			}
		}
		sorted := make([]string, 0, len(names))
		for t := range names {
			sorted = append(sorted, t)
		}
		sort.Strings(sorted)
		for _, t := range sorted {
			k := [2]string{cs.Name, t}
			tool := Tool{Name: t, Calls: fc.calls[k], Refused: fc.refused[k], Asked: fc.asked[k]}
			if !sv.Relayed {
				tool.Contract, tool.Decision, tool.Rule = mcptool.Allow, mcptool.Allow, "mcp["+cs.Name+"]"
			} else {
				live := ""
				if e, ok := o.Lookup(cs.Name, t); ok {
					live = e.Decision
				}
				now := mcptool.Decide(rules, live, cs.Name, t)
				tool.Contract = mcptool.Contract(rules, cs.Name, t).Decision
				tool.Decision, tool.Rule, tool.Live = now.Decision, now.Rule, live != ""
			}
			sv.Tools = append(sv.Tools, tool)
		}
		st.Servers = append(st.Servers, sv)
	}
	return st, nil
}

// overlayBase is the sha256 of the overlay file now, "" when there is none.
func overlayBase(dir string) (string, error) {
	b, err := mcptools.SHA256Base(dir)
	if err != nil || b == nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// plan is Plan's body: decision "" is a reset.
func (s *Service) plan(run, server, tool, decision string) (*Plan, string, error) {
	if !mcptools.ValidName(server) || !mcptools.ValidName(tool) || decision != "" && !mcptools.ValidDecision(decision) {
		return nil, "", ErrBadName
	}
	dir, err := s.runDir(run)
	if err != nil {
		return nil, "", err
	}
	svs, err := servers(dir)
	if err != nil {
		return nil, "", err
	}
	var cs *contractServer
	for i := range svs {
		if svs[i].Name == server {
			cs = &svs[i]
		}
	}
	switch {
	case cs == nil:
		return nil, "", ErrNoServer
	case !cs.hasTool:
		return nil, "", ErrNotRelayed
	}
	o, err := readOverlay(dir, run)
	if err != nil {
		return nil, "", err
	}
	live := ""
	if e, ok := o.Lookup(server, tool); ok {
		live = e.Decision
	}
	rules := cs.rules()
	p := &Plan{Run: run, Server: server, Tool: tool, From: mcptool.Decide(rules, live, server, tool), To: decision, rules: rules}
	if decision == "" {
		p.Reset, p.To = true, mcptool.Contract(rules, server, tool).Decision
	}
	if p.To == mcptool.Ask && !readFacts(dir).broker {
		return p, dir, ErrNoBroker
	}
	p.Loosens = mcptool.Loosens(p.From.Decision, p.To)
	base, err := overlayBase(dir)
	if err != nil {
		return nil, "", err
	}
	if p.Loosens {
		p.Ack = ackOf(run, server, tool, word(p), base)
	}
	return p, dir, nil
}

// word is the decision an acknowledgement binds: a reset's is "reset", so a reset ack is not a set's.
func word(p *Plan) string {
	if p.Reset {
		return "reset"
	}
	return p.To
}

// Plan previews setting server's tool to decision (allow, ask or deny) in run.
func (s *Service) Plan(run, server, tool, decision string) (*Plan, error) {
	if decision == "" {
		return nil, ErrBadName
	}
	p, _, err := s.plan(run, server, tool, decision)
	return p, err
}

// PlanReset previews dropping the live switch of server's tool.
func (s *Service) PlanReset(run, server, tool string) (*Plan, error) {
	p, _, err := s.plan(run, server, tool, "")
	return p, err
}

// Set puts decision in force for server's tool for the rest of the run. A change that loosens needs ack, Plan's
// acknowledgement against the overlay as it still stands, and is refused to a caller inside a run.
func (s *Service) Set(ctx context.Context, run, server, tool, decision, ack string) (*Plan, error) {
	if decision == "" {
		return nil, ErrBadName
	}
	return s.apply(ctx, run, server, tool, decision, ack)
}

// Reset drops the live switch of server's tool: the contract decides it again. A reset that loosens is a loosening.
func (s *Service) Reset(ctx context.Context, run, server, tool, ack string) (*Plan, error) {
	return s.apply(ctx, run, server, tool, "", ack)
}

func (s *Service) apply(ctx context.Context, run, server, tool, decision, ack string) (*Plan, error) {
	p, dir, err := s.plan(run, server, tool, decision)
	if err != nil {
		return p, err
	}
	if held, _, err := runlock.ProbeLock(dir); err != nil {
		return p, err
	} else if !held {
		return p, ErrNotRunning
	}
	governed := func() bool {
		gov := s.governed
		if gov == nil {
			gov = runact.SelfGoverned
		}
		in, _ := gov() // fails closed: a cgroup it cannot judge refuses too
		return in
	}
	// Refused here as well as under the lock: a caller inside a run cannot write the run directory, so it would not
	// get that far to be told why.
	if p.Loosens && governed() {
		return p, ErrGoverned
	}
	by := mcptools.By("dashboard")
	if s.beforeLock != nil {
		s.beforeLock()
	}
	var refused error
	_, err = mcptools.Update(ctx, dir, run, func(o *mcptools.Overlay) (bool, error) {
		// Whether it loosens is decided again on the overlay under the writers' lock: a Deny from another terminal between
		// plan's read and this lock must not be undone by a change nobody acknowledged as a loosening.
		live := ""
		if e, ok := o.Lookup(server, tool); ok {
			live = e.Decision
		}
		p.From = mcptool.Decide(p.rules, live, server, tool)
		p.Loosens = mcptool.Loosens(p.From.Decision, p.To)
		if p.Loosens {
			if governed() {
				refused = ErrGoverned
				return false, nil
			}
			// The acknowledgement binds the overlay the preview showed.
			base, err := overlayBase(dir)
			if err != nil {
				return false, err
			}
			if !ackOK(ack, run, server, tool, word(p), base) {
				refused = ErrAck
				return false, nil
			}
		}
		var changed bool
		var err error
		if p.Reset {
			changed, err = o.Reset(server, tool, by, s.now())
		} else {
			changed, err = o.Set(server, tool, decision, by, s.now())
		}
		p.Changed = changed
		return changed, err
	})
	if refused != nil {
		return p, refused
	}
	return p, err
}

// HasMCP reports whether run's contract declares any MCP server (the page's run picker).
func (s *Service) HasMCP(run string) bool {
	dir, err := s.runDir(run)
	if err != nil {
		return false
	}
	svs, err := servers(dir)
	return err == nil && len(svs) > 0
}
