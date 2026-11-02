// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// Current is a contract of the set as the Change rules form shows it: its text now, read through every write guard,
// and the entries each list an edit may change spells (rule.Entries), the ones the form offers to remove.
type Current struct {
	ContractRef
	// Text is the file's text; Base (in ContractRef) its sha256, the base every form on the page carries back.
	Text []byte
	// Lists are the entries by edit key (fs.write, exec.allow, ...); a key the file lacks is absent.
	Lists map[string][]string
	// ListsErr says why the text gave no lists (it is not a YAML mapping); the raw editor still opens.
	ListsErr string
	// EnvSet says the text sets environment values (env.set), or could not be read as one YAML document and could
	// spell a "set" key (rulesview.SetsEnv).
	EnvSet bool
	// Editor is the text the advanced YAML editor opens on: Text, or Text with every env.set value replaced by
	// rulesview.Hidden, which PlanRaw and ApplyRaw put back (rulesview.EditableEnv). Nil when the editor is not
	// offered; EditorWhy says why.
	Editor    []byte
	EditorWhy string
}

// Current reads the contract ref names through the guards: ErrNoContract for a ref outside the set, ErrNotWritable
// for a file that fails a guard or whose folder now points elsewhere. It writes nothing.
func (s *Service) Current(ref string) (*Current, error) {
	c, f, err := s.writable(ref)
	if err != nil {
		return nil, err
	}
	cur := &Current{ContractRef: c.ContractRef, Text: f.Text}
	cur.Base, cur.Writable, cur.Why = f.SHA256, true, ""
	cur.Editor, cur.EnvSet, cur.EditorWhy = editorOf(f.Text)
	if cur.Lists, err = rule.Entries(f.Text); err != nil {
		cur.ListsErr = err.Error()
	}
	return cur, nil
}

// editorOf is the text the YAML editor opens on for a contract's text (Current.Editor; nil, with why, when the editor
// is not offered) and whether the text sets environment values (Current.EnvSet).
func editorOf(text []byte) (editor []byte, envSet bool, why string) {
	envSet, readable := rulesview.SetsEnv(string(text))
	switch {
	case !envSet:
		return text, false, ""
	case !readable:
		return nil, true, "This rules file could not be read as one YAML document and may set environment values (env.set), which a page never shows, so it is fixed in a terminal"
	}
	shown, err := rulesview.EditableEnv(string(text))
	if err != nil {
		return nil, true, "This rules file sets environment values (env.set) in a form a page cannot hide and put back (" + err.Error() + "), so its YAML is edited in a terminal"
	}
	return []byte(shown), true, ""
}

// shownDiff is the diff a page may show of a change from before to after: diff itself, unless either text sets
// environment values, when it is the diff of the two texts with every env.set value hidden line for line. A diff
// carries two lines of context around each change, so an fs or exec edit next to env: would otherwise put a value on
// the page that the Rules page hides (rulesview.Hidden).
func shownDiff(name string, before, after []byte, diff string) string {
	b, a := rulesview.RedactEnvText(string(before)), rulesview.RedactEnvText(string(after))
	if b == string(before) && a == string(after) {
		return diff
	}
	return rule.Diff(name, []byte(b), []byte(a))
}
