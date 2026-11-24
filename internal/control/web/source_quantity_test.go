// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"fmt"
	stdhtml "html"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"text/template/parse"

	"golang.org/x/net/html"
)

// This is the complete source-audit vocabulary, including quantity inflections.
var quantityVocabulary = regexp.MustCompile(`(?i)([0-9]|\b(?:no|none|never|nothing|not once|empt(?:y|ies|ied|ying|ier|iest|iness)|zero(?:s|es|ed|ing)?|all|every|any|only|each|both|first(?:s|ly)?|last(?:s|ly)?|more|few(?:er|est)?|less(?:er|est)?|most(?:ly)?|many|several|once|twice)\b)`)

type sourceLiteral struct {
	Template  string
	Line      int
	Text      string
	Source    bool
	Attribute string `json:",omitempty"`
}
type literalElement struct {
	tag            string
	source, hidden bool
}
type literalContext struct {
	stack   []literalElement
	pending string
	line    int
}

func (c literalContext) clone() literalContext { c.stack = slices.Clone(c.stack); return c }
func literalWords(s string) string {
	return strings.Join(strings.Fields(stdhtml.UnescapeString(strings.ReplaceAll(s, "DYNAMIC", ""))), " ")
}

// Every branch is visited with its own HTML context; one branch's marker cannot
// excuse a sibling. Pending tags preserve attributes split by template actions.
func templateLiterals(name, src string) ([]sourceLiteral, error) {
	trees := map[string]*parse.Tree{}
	tree := parse.New(name)
	tree.Mode = parse.SkipFuncCheck
	if _, err := tree.Parse(src, "{{", "}}", trees); err != nil {
		return nil, err
	}
	defs, err := numberDefinitions()
	if err != nil {
		return nil, err
	}
	var invalid []string
	validSource := func(id string, line int) bool {
		ids := strings.Fields(id)
		valid := len(ids) > 0
		for _, field := range ids {
			valid = valid && (field == "DYNAMIC" || defs[field].ID != "")
		}
		if valid {
			return true
		}
		invalid = append(invalid, fmt.Sprintf("%s:%d: invalid quantity source %q", name, line, id))
		return false
	}
	var out []sourceLiteral
	var visit func(*parse.ListNode, []literalContext) []literalContext
	sites := map[string]int{}
	position, segment := 0, 0
	emit := func(c literalContext, line int, words string, own bool, attribute string) {
		segment++
		words = literalWords(words)
		if words == "" {
			return
		}
		sourced, hidden := own, false
		for _, e := range c.stack {
			sourced = sourced || e.source
			hidden = hidden || e.hidden
		}
		if !hidden {
			key := fmt.Sprintf("%d:%d:%s", position, segment, words)
			if i, ok := sites[key]; ok {
				out[i].Source = out[i].Source && sourced
			} else {
				sites[key] = len(out)
				out = append(out, sourceLiteral{Template: name, Line: line, Text: words, Source: sourced, Attribute: attribute})
			}
		}
	}
	feed := func(c literalContext, n *parse.TextNode) literalContext {
		position, segment = int(n.Position()), 0
		chunk := string(n.Text)
		line := 1 + strings.Count(src[:int(n.Position())], "\n")
		for len(chunk) > 0 {
			if c.pending == "" {
				i := strings.IndexByte(chunk, '<')
				if i < 0 {
					emit(c, line, chunk, false, "")
					break
				}
				emit(c, line, chunk[:i], false, "")
				line += strings.Count(chunk[:i], "\n")
				c.pending = "<"
				c.line = line
				chunk = chunk[i+1:]
			}
			// Find a tag end outside quoted attributes, including quotes opened in
			// earlier text nodes. HTML comments are consumed as one unit.
			joined := c.pending + chunk
			end := -1
			var quote byte
			for i := 1; i < len(joined); i++ {
				b := joined[i]
				if quote != 0 {
					if b == quote {
						quote = 0
					}
					continue
				}
				if b == '\'' || b == '"' {
					quote = b
					continue
				}
				if b == '>' {
					end = i
					break
				}
			}
			if end < 0 {
				c.pending = joined
				break
			}
			raw := joined[:end+1]
			consumed := end + 1 - len(c.pending)
			line += strings.Count(chunk[:consumed], "\n")
			chunk = chunk[consumed:]
			c.pending = ""
			z := html.NewTokenizer(strings.NewReader(raw))
			typ := z.Next()
			tok := z.Token()
			switch typ {
			case html.StartTagToken, html.SelfClosingTagToken:
				marked, hidden := false, tok.Data == "script" || tok.Data == "style"
				for _, a := range tok.Attr {
					if a.Key == "data-number" {
						marked = validSource(a.Val, c.line)
					}
				}
				inputType := ""
				for _, a := range tok.Attr {
					if a.Key == "type" {
						inputType = a.Val
					}
				}
				for _, a := range tok.Attr {
					shown := shownQuantityAttribute(tok.Data, inputType, a.Key)
					own := marked
					for _, m := range tok.Attr {
						if m.Key == "data-number-"+a.Key {
							own = validSource(m.Val, c.line)
						}
					}
					if shown {
						emit(c, c.line, a.Val, own, a.Key)
					}
				}
				if typ == html.StartTagToken && !slices.Contains([]string{"input", "img", "br", "hr", "link", "meta", "wbr", "area", "base", "col", "embed", "param", "source", "track"}, tok.Data) {
					c.stack = append(c.stack, literalElement{tok.Data, marked, hidden})
				}
			case html.EndTagToken:
				for i := len(c.stack) - 1; i >= 0; i-- {
					if c.stack[i].tag == tok.Data {
						c.stack = c.stack[:i]
						break
					}
				}
			case html.ErrorToken, html.TextToken, html.CommentToken, html.DoctypeToken:
				// These tokens introduce no element or audience-facing attribute.
			}
		}
		return c
	}

	visit = func(list *parse.ListNode, contexts []literalContext) []literalContext {
		if list == nil {
			return contexts
		}
		for _, node := range list.Nodes {
			var next []literalContext
			for _, c := range contexts {
				switch n := node.(type) {
				case *parse.TextNode:
					next = append(next, feed(c.clone(), n))
				case *parse.IfNode:
					next = append(next, visit(n.List, []literalContext{c.clone()})...)
					next = append(next, visit(n.ElseList, []literalContext{c.clone()})...)
				case *parse.WithNode:
					next = append(next, visit(n.List, []literalContext{c.clone()})...)
					next = append(next, visit(n.ElseList, []literalContext{c.clone()})...)
				case *parse.RangeNode:
					next = append(next, visit(n.List, []literalContext{c.clone()})...)
					next = append(next, visit(n.ElseList, []literalContext{c.clone()})...)
				default:
					if c.pending != "" {
						c.pending += "DYNAMIC"
					}
					next = append(next, c)
				}
			}
			contexts = nil
			unique := map[string]bool{}
			for _, c := range next {
				key := fmt.Sprintf("%v/%s", c.stack, c.pending)
				if !unique[key] {
					unique[key] = true
					contexts = append(contexts, c)
				}
			}
		}
		return contexts
	}

	for _, key := range slices.Sorted(func(yield func(string) bool) {
		for key := range trees {
			if !yield(key) {
				return
			}
		}
	}) {
		visit(trees[key].Root, []literalContext{{}})
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(invalid, "; "))
	}
	return out, nil
}

var sourceQuantityLayers []map[string]string

func TestSourceQuantityAudit(t *testing.T) {
	b, err := os.ReadFile("testdata/no_quantity_texts.json")
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]string{}
	if err := json.Unmarshal(b, &registered); err != nil {
		t.Fatal(err)
	}

	for _, layer := range sourceQuantityLayers {
		for words, reason := range layer {
			if registered[words] != "" {
				t.Fatalf("duplicate no-quantity registration: %q", words)
			}
			registered[words] = reason
		}
	}
	var report []sourceLiteral
	seen := map[string]bool{}
	walked, sourced, exempt, textNodes, attributes := 0, 0, 0, 0, 0
	files, err := fs.Glob(assets, "templates/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		b, err := fs.ReadFile(assets, file)
		if err != nil {
			t.Fatal(err)
		}
		literals, err := templateLiterals(file, string(b))
		if err != nil {
			t.Fatal(err)
		}
		report = append(report, literals...)
		for _, lit := range literals {
			walked++
			if lit.Attribute == "" {
				textNodes++
			} else {
				attributes++
			}
			seen[lit.Text] = true
			if lit.Source {
				sourced++
				continue
			}
			if registered[lit.Text] != "" {
				exempt++
				continue
			}
			t.Errorf("%s:%d: unregistered literal %q (quantity vocabulary: %t)", lit.Template, lit.Line, lit.Text, quantityVocabulary.MatchString(lit.Text))
		}
	}
	for words, reason := range registered {
		if !seen[words] || strings.TrimSpace(reason) == "" {
			t.Errorf("stale or unexplained no-quantity registration: %q", words)
		}
	}
	if path := os.Getenv("SOURCE_QUANTITY_REPORT"); path != "" {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("source literals: walked=%d text_nodes=%d attributes=%d with_source=%d registered_no_quantity=%d", walked, textNodes, attributes, sourced, exempt)
}

func TestSourceQuantityAuditUnrenderedBranch(t *testing.T) {
	literals, err := templateLiterals("scratch.tmpl", `<section>{{if .NeverRendered}}<p>Several requests vanished.</p>{{else}}<p data-number="approvals.waiting">Nothing waiting</p>{{end}}</section>`)
	if err != nil {
		t.Fatal(err)
	}
	for _, lit := range literals {
		if lit.Text == "Several requests vanished." && !lit.Source && quantityVocabulary.MatchString(lit.Text) {
			return
		}
	}
	t.Fatal(fmt.Sprint("source walker missed unrendered branch: ", literals))
}

func TestSourceQuantityBranchContexts(t *testing.T) {
	for _, src := range []string{
		`{{if .Never}}<p data-number="run.unused">{{else}}<p>{{end}}Several requests vanished.</p>`,
		`<p {{if .Never}}data-number="run.unused"{{end}}>Several requests vanished.</p>`,
		`<p>{{with .Never}}<span data-number="run.unused">Nothing</span>{{else}}Several requests vanished.{{end}}</p>`,
		`<p>{{range .Never}}<span data-number="run.unused">Nothing</span>{{else}}Several requests vanished.{{end}}</p>`,
		`<p title="Several requests vanished.">Label</p>`,
	} {
		literals, err := templateLiterals("scratch.tmpl", src)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, lit := range literals {
			if lit.Text == "Several requests vanished." && !lit.Source {
				found = true
			}
		}
		if !found {
			t.Fatalf("branch marker leaked into unmarked text: %s: %+v", src, literals)
		}
	}
}

// Keep the two collectors' audience fields aligned. Reference attributes such as
// aria-labelledby name nodes whose text is visited separately.
func shownQuantityAttribute(tag, inputType, key string) bool {
	switch key {
	case "title", "aria-label", "aria-description", "aria-roledescription", "aria-placeholder", "aria-valuenow", "aria-valuetext", "aria-valuemin", "aria-valuemax", "aria-keyshortcuts", "aria-rowcount", "aria-colcount", "aria-rowindex", "aria-colindex", "aria-rowspan", "aria-colspan", "aria-posinset", "aria-setsize", "aria-level", "aria-colindextext", "aria-rowindextext", "aria-braillelabel", "aria-brailleroledescription", "alt", "placeholder", "data-late", "abbr":
		return true
	case "label":
		return tag == "option" || tag == "optgroup" || tag == "track"
	case "value":
		return tag == "output" || tag == "meter" || tag == "progress" || tag == "li" || tag == "input" && !slices.Contains([]string{"hidden", "checkbox", "radio", "password"}, inputType)
	case "start":
		return tag == "ol"
	case "min", "max", "low", "high", "optimum":
		return tag == "meter" || tag == "progress" || tag == "input" && (inputType == "number" || inputType == "range")
	}
	return false
}

func TestSourceQuantitySpokenAttributes(t *testing.T) {
	for _, body := range []string{`<span aria-roledescription="12 waiting">Label</span>`, `<span aria-valuemin="12">Label</span>`, `<optgroup label="12 waiting"></optgroup>`, `<input type="number" min="12">`,
		`<div aria-rowcount="12"></div>`, `<div aria-colcount="12"></div>`,
		`<div aria-rowindex="12"></div>`, `<div aria-colindex="12"></div>`,
		`<div aria-rowspan="12"></div>`, `<div aria-colspan="12"></div>`,
		`<div aria-posinset="12"></div>`, `<div aria-setsize="12"></div>`, `<div aria-level="12"></div>`,
		`<div aria-colindextext="12 waiting"></div>`, `<div aria-rowindextext="12 waiting"></div>`,
		`<div aria-braillelabel="12 waiting"></div>`, `<div aria-brailleroledescription="12 waiting"></div>`,
		`<ol start="12"><li>Label</li></ol>`, `<ol><li value="12">Label</li></ol>`,
	} {
		literals, err := templateLiterals("unrendered.tmpl", body)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, lit := range literals {
			found = found || !lit.Source && quantityVocabulary.MatchString(lit.Text)
		}
		if !found || len(unmarkedNumbers(t, body)) == 0 {
			t.Errorf("collector accepted an unmarked spoken control field: %s", body)
		}
	}
}
