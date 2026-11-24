// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Decision is an explicit grant in the draft, never an inferred permission.
type Decision struct {
	ID, Key, Entry, Sentence, Host, Err, Target string
	Drop, Address                               bool
	Line                                        int
}

func decisionID(key, entry string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(key+"\x00"+entry)))[:16]
}

func nodeAt(n *yaml.Node, keys ...string) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	for _, key := range keys {
		if n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		n = next
	}
	return n
}

func setNode(n *yaml.Node, key string, value any) error {
	if n.Kind == yaml.DocumentNode {
		n = n.Content[0]
	}
	parts := strings.Split(key, ".")
	for _, part := range parts[:len(parts)-1] {
		child := nodeAt(n, part)
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, child)
		}
		if child.Kind != yaml.MappingNode {
			return fmt.Errorf("%s is not a section; edit it in Full", part)
		}
		n = child
	}
	var v yaml.Node
	if err := v.Encode(value); err != nil {
		return err
	}
	k := parts[len(parts)-1]
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == k {
			n.Content[i+1] = &v
			return nil
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, &v)
	return nil
}

func (s *Service) builderSource(ctx context.Context, p *NewPlan, req NewReq) *setup.Result {
	text := req.Text
	if req.Text != nil && len(req.Text) == 0 {
		p.Problems = append(p.Problems, "The draft is empty. Add contract YAML in Full before checking.")
		return nil
	}
	var retained *setup.Result
	if req.Draft != "" {
		var err error
		retained, err = s.restoreDraft(req, p)
		if err != nil {
			p.Problems = append(p.Problems, err.Error())
			return nil
		}
		if len(req.Text) == 0 {
			p.Problems = append(p.Problems, "The draft is empty. Add contract YAML in Full before checking.")
			return nil
		}
		text = retained.Contract
	}
	if len(text) == 0 {
		text = []byte("version: 0\nname: " + strconv.Quote(p.Name) + "\ncommand: [true]\nfs:\n  write: []\nexec:\n  allow: []\nnet:\n  allow: []\nenv:\n  pass: []\n")
		// YAML true is a boolean, while a command is always a string.
		text = bytes.ReplaceAll(text, []byte("command: [true]"), []byte("command: [\"true\"]"))
	}
	if len(req.Text) == 0 && strings.TrimSpace(req.Command) != "" {
		argv := strings.Fields(req.Command)
		if strings.ContainsAny(req.Command, "|&;<>()$`\\\"'*?[]#~=%{}\n") {
			argv = []string{"/bin/sh", "-c", req.Command}
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(text, &doc); err != nil {
			return nil
		}
		if err := setNode(&doc, "command", argv); err != nil {
			return nil
		}
		var b bytes.Buffer
		e := yaml.NewEncoder(&b)
		e.SetIndent(2)
		if err := e.Encode(&doc); err != nil {
			return nil
		}
		if err := e.Close(); err != nil {
			return nil
		}
		text = b.Bytes()
	}
	if len(req.Text) == 0 && req.Blank && (len(req.Writes) > 0 || len(req.Hosts) > 0 || len(req.Pass) > 0 || len(req.AskRead) > 0) {
		var doc yaml.Node
		if err := yaml.Unmarshal(text, &doc); err != nil {
			return nil
		}
		for key, entries := range map[string][]string{"fs.write": req.Writes, "net.allow": req.Hosts, "env.pass": req.Pass, "fs.ask_read": req.AskRead} {
			if len(entries) > 0 {
				if err := setNode(&doc, key, entries); err != nil {
					return nil
				}
			}
		}
		var b bytes.Buffer
		e := yaml.NewEncoder(&b)
		e.SetIndent(2)
		if err := e.Encode(&doc); err != nil {
			return nil
		}
		if err := e.Close(); err != nil {
			return nil
		}
		text = b.Bytes()
	}
	if has, _ := rulesview.SetsEnv(string(text)); has && retained == nil {
		p.Problems = append(p.Problems, "New environment values cannot be saved from a page. Use env.pass names, or set env.set in a terminal.")
		return nil
	}
	if len(text) > agent.MaxContractSize {
		p.Problems = append(p.Problems, "The draft is too large. Use a contract under 1 MiB.")
		return nil
	}
	if retained != nil {
		return retained
	}
	return &setup.Result{Contract: bytes.Clone(text)}
}

// builderChoices edits only grants the posted draft already spells. A no-op preserves bytes and comments.
// Compilation is the product compiler below; this YAML walk is an editor, never a validator.
func (s *Service) builderChoices(ctx context.Context, p *NewPlan, req NewReq, res *setup.Result) error {
	p.Source = bytes.Clone(res.Contract)
	var doc yaml.Node
	parsed := yaml.Unmarshal(res.Contract, &doc) == nil && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode
	changed := false
	if parsed {
		for _, key := range []string{"fs.write", "exec.allow", "net.allow"} {
			seq := nodeAt(&doc, strings.Split(key, ".")...)
			if seq == nil || seq.Kind != yaml.SequenceNode {
				continue
			}
			kept := make([]*yaml.Node, 0, len(seq.Content))
			for _, v := range seq.Content {
				if v.Kind != yaml.ScalarNode {
					kept = append(kept, v)
					continue
				}
				d := Decision{ID: decisionID(key, v.Value), Key: key, Entry: v.Value, Line: v.Line, Address: key == "net.allow" && addressEntry(v.Value)}
				d.Drop = slices.Contains(req.Drop, d.ID)
				d.Target = v.Value
				switch key {
				case "fs.write":
					entry := v.Value
					if p.Dir != "" && filepath.IsAbs(entry) {
						if rel, err := filepath.Rel(p.Dir, entry); err == nil && filepath.IsLocal(rel) {
							entry = "./" + filepath.ToSlash(rel)
							if strings.HasSuffix(v.Value, "/") {
								entry += "/"
							}
						}
					}
					d.Sentence = "May write " + entry
					if p.FromRun != "" {
						d.Sentence = "Wrote files in " + entry
					}
				case "exec.allow":
					d.Sentence = "May run " + v.Value
					if p.FromRun != "" {
						d.Sentence = "Ran " + v.Value
					}
				case "net.allow":
					d.Sentence = "May connect to " + v.Value
					if p.FromRun != "" {
						d.Sentence = "Connected to " + v.Value
					}
				}
				if host := strings.TrimSpace(req.NameHosts[d.ID]); host != "" && d.Address {
					// The answer is explicit and keeps the original transport and port. The real compiler checks the endpoint.
					d.Host = host
					original := v.Value
					prefix := ""
					for _, scheme := range []string{"tcp://", "udp://"} {
						if strings.HasPrefix(original, scheme) {
							prefix = scheme
							original = strings.TrimPrefix(original, scheme)
						}
					}
					port := original[strings.LastIndex(original, ":")+1:]
					if strings.ContainsAny(host, "/:[] \t\r\n") {
						d.Err = "Type a host name without a port or scheme for " + d.Entry
						p.Decisions = append(p.Decisions, d)
						return fmt.Errorf("name it: %s", d.Err)
					}
					v.Value = prefix + host + ":" + port
					d.Target = v.Value
					changed = true
				}
				p.Decisions = append(p.Decisions, d)
				if d.Drop {
					changed = true
				} else {
					kept = append(kept, v)
				}
			}
			seq.Content = kept
		}
		if req.Switches {
			reads := "off"
			if req.Reads {
				reads = "on"
			}
			rn := nodeAt(&doc, "reason", "reads")
			// An unchecked switch preserves absent/auto (and invalid text for Full to fix).
			// Only an explicit change to or from on rewrites this field.
			if req.Reads && (rn == nil || rn.Value != "on") || !req.Reads && rn != nil && rn.Value == "on" {
				if err := setNode(&doc, "reason.reads", reads); err != nil {
					return err
				}
				changed = true
			}
			if req.Wall != "" {
				wn := nodeAt(&doc, "limits", "wall")
				if wn == nil || wn.Value != req.Wall {
					if err := setNode(&doc, "limits.wall", req.Wall); err != nil {
						return err
					}
					changed = true
				}
			}
		}
		if req.Switches && req.RemoveWall {
			if wn := nodeAt(&doc, "limits", "wall"); wn != nil && wn.Value == "2h" {
				parent := nodeAt(&doc, "limits")
				for i := 0; i+1 < len(parent.Content); i += 2 {
					if parent.Content[i].Value == "wall" {
						parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
						changed = true
						break
					}
				}
			}
		}
		if req.WantAsk && len(req.AskHosts) == 0 {
			return fmt.Errorf("type at least one host and port in Hosts to ask about")
		}
		if req.DropAsk {
			if an := nodeAt(&doc, "net", "ask"); an != nil && an.Kind == yaml.SequenceNode && len(an.Content) > 0 {
				if err := setNode(&doc, "net.ask", []string{}); err != nil {
					return err
				}
				changed = true
			}
		}
		if len(req.AskHosts) > 0 {
			var have []string
			if an := nodeAt(&doc, "net", "ask"); an != nil && an.Kind == yaml.SequenceNode {
				for _, entry := range an.Content {
					have = append(have, entry.Value)
				}
			}
			if !slices.Equal(have, req.AskHosts) {
				if err := setNode(&doc, "net.ask", req.AskHosts); err != nil {
					return err
				}
				changed = true
			}
		}
		if wn := nodeAt(&doc, "limits", "wall"); wn != nil {
			p.Wall = wn.Value
		}
		if an := nodeAt(&doc, "net", "ask"); an != nil && an.Kind == yaml.SequenceNode {
			for _, v := range an.Content {
				p.AskHosts = append(p.AskHosts, v.Value)
			}
		}
		p.Reads = false
		if rn := nodeAt(&doc, "reason", "reads"); rn != nil {
			p.Reads = rn.Value == "on"
		}
		if changed {
			var b bytes.Buffer
			e := yaml.NewEncoder(&b)
			e.SetIndent(2)
			if err := e.Encode(&doc); err != nil {
				return err
			}
			if err := e.Close(); err != nil {
				return err
			}
			res.Contract = b.Bytes()
		}
	}
	if changed {
		var rendered yaml.Node
		if yaml.Unmarshal(res.Contract, &rendered) == nil {
			for i := range p.Decisions {
				d := &p.Decisions[i]
				if d.Drop {
					d.Line = 0
					continue
				}
				if seq := nodeAt(&rendered, strings.Split(d.Key, ".")...); seq != nil && seq.Kind == yaml.SequenceNode {
					for _, entry := range seq.Content {
						if entry.Value == d.Target {
							d.Line = entry.Line
							break
						}
					}
				}
			}
		}
	}
	p.OK = true
	return nil
}

// EditDraft applies explicit Simple choices without saving or compiling. Callers must pass its result
// through PlanRaw/ApplyRaw or PlanNew/CreateNew; it grants no authority to write.
func EditDraft(req NewReq) ([]byte, []Decision, error) {
	p := &NewPlan{}
	res := &setup.Result{Contract: bytes.Clone(req.Text)}
	err := (&Service{}).builderChoices(context.Background(), p, req, res)
	return res.Contract, p.Decisions, err
}

// registryNoLinks rejects a configured contracts directory reached through a link. registry.Save's
// descriptor walk independently refuses links at every component, including agents/ at publication.
func registryNoLinks(path string) error {
	if path == "" {
		return nil
	}
	for p := filepath.Clean(path); p != "/" && p != "."; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("the contracts folder cannot be checked: %w", err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("the contracts folder uses a symbolic link at %s. Choose a real contracts folder; nothing was written", p)
		}
	}
	return nil
}
