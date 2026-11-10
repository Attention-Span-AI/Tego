// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// A rules file is shared (the workspace file is committed) and the agent could write it, so nothing in it is
// trusted for display or for the contract until it is checked here: the fields must be ones Maze knows, the
// words must be printable (a control character could clear the screen and hide rules on the very page where
// changes are approved), and a rule Maze always enforces (a fixed rule) keeps its fixed effect whatever the file says.

// BadFileError is a rules file Maze won't use, with what is wrong in plain words.
type BadFileError struct {
	File   string
	Reason string
}

func (e *BadFileError) Error() string { return e.File + " " + e.Reason }

// errYAMLMergeKey is guardYAML's error for the input yaml.v3 panics on.
var errYAMLMergeKey = errors.New("yaml: a list or a mapping as a key, where a merge key (<<) applies")

// guardYAML is the engine's config.GuardYAML, which maze may not import (doc.go): it runs decode and returns as an
// error yaml.v3's panic on a key that is a list or a mapping where a merge key (<<) applies, a key its merge code
// puts in a Go map ("hash of unhashable type"). The workspace file is in the project, where an agent working there
// can write it. Any other panic is raised again.
func guardYAML(decode func() error) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if re, ok := r.(runtime.Error); ok && strings.Contains(re.Error(), "hash of unhashable type") {
			err = errYAMLMergeKey
			return
		}
		panic(r)
	}()
	return decode()
}

// decodeRules reads a rules file strictly: unknown fields and words with control characters are refused.
func decodeRules(file string, data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return &BadFileError{file, "is empty"}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := guardYAML(func() error { return dec.Decode(v) }); err != nil {
		msg := err.Error()
		msg = strings.TrimPrefix(msg, "yaml: ")
		if strings.Contains(msg, "not found in type") {
			msg = "has a field Maze doesn't know (" + strings.TrimSpace(msg[strings.LastIndex(msg, ":")+1:]) + ")"
			msg = strings.Replace(msg, "field ", "", 1)
		}
		return &BadFileError{file, "isn't valid: " + msg}
	}
	return nil
}

// categories and the verbs each takes.
var verbs = map[string][]string{
	"files":    {"read", "write"},
	"programs": {"run"},
	"websites": {"reach"},
	"logins":   {"see", "push", "publish", "commit"},
}

// checkRules refuses a rule with an unknown category or verb, or with a word Maze wouldn't print safely.
func checkRules(file string, rules []Rule) error {
	for i, r := range rules {
		ok := false
		for _, v := range verbs[r.Category] {
			ok = ok || v == r.Verb
		}
		if !ok {
			return &BadFileError{file, fmt.Sprintf("has a rule Maze doesn't know (rule %d: %s %s)", i+1, r.Category, r.Verb)}
		}
		words := append([]string{r.Value, r.Why}, append(append(append(append([]string(nil), r.Programs...), r.Hosts...), r.Paths...), r.From...)...)
		for _, w := range words {
			if !Printable(w) {
				return &BadFileError{file, fmt.Sprintf("has a rule with characters Maze won't show (rule %d)", i+1)}
			}
		}
	}
	return nil
}

// Printable reports whether s has no control characters: nothing that could move the cursor or clear the screen.
func Printable(s string) bool {
	for _, r := range s {
		if !printableRune(r) {
			return false
		}
	}
	return true
}

// printableRune is false for control characters and for the invisible marks that reorder text on screen.
func printableRune(r rune) bool {
	switch {
	case unicode.IsControl(r), r == 0x7f, r == 0x2028, r == 0x2029, r == 0x200e, r == 0x200f,
		r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return false
	}
	return true
}

// Clean replaces what Printable refuses with "?", for showing a name taken from disk (a file name, a rule in
// someone's settings) without letting it move the cursor or rewrite the screen.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if printableRune(r) {
			return r
		}
		return '?'
	}, s)
}

// LockedAllow is the fixed effect of a rule Maze always enforces: reading the project and committing as the
// agent are allowed; every other locked rule (secrets, key folders, hooks, outside the project, any other
// program or website, pushing and publishing as the person) is blocked.
func LockedAllow(r Rule) bool {
	return (r.Category == "files" && r.Verb == "read" && strings.HasPrefix(r.Value, "everything in ")) ||
		(r.Category == "logins" && r.Verb == "commit") ||
		(r.Category == "programs" && r.Value == Shell)
}

// Atom is one effect a rule set has: a program, a website, a file, a variable, a login action, each allowed or
// not. Two rule files that give the same atoms enforce the same thing, however their labels read; the approval
// check compares atoms, so a program slipped into a row's list shows, and a reworded note doesn't ask again.
type Atom struct {
	Category, Verb, Target string
	Allow                  bool
}

// Atoms lists the effects of rules, sorted.
func Atoms(rules []Rule) []Atom {
	var out []Atom
	add := func(r Rule, targets []string) {
		for _, t := range targets {
			out = append(out, Atom{r.Category, r.Verb, t, r.Allow})
		}
	}
	for _, r := range rules {
		switch {
		case r.Category == "programs" && len(r.Programs) > 0:
			add(r, r.Programs)
		case r.Category == "websites" && len(r.Hosts) > 0:
			add(r, r.Hosts)
		case r.Category == "files" && len(r.Paths) > 0:
			add(r, r.Paths)
		default:
			add(r, []string{r.Value})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Verb != b.Verb {
			return a.Verb < b.Verb
		}
		return a.Target < b.Target
	})
	return out
}

// AtomRule is a one-target rule standing for an atom, so it reads like any other rule ("run curl").
func AtomRule(a Atom) Rule {
	r := Rule{Category: a.Category, Verb: a.Verb, Value: a.Target, Allow: a.Allow}
	switch a.Category {
	case "programs":
		r.Programs = []string{a.Target}
	case "websites":
		r.Hosts = []string{a.Target}
	case "files":
		if a.Verb == "read" && !strings.HasPrefix(a.Target, "everything in ") {
			r.Paths = []string{a.Target}
		}
	}
	return r
}

// DiffAtoms lists what current enforces differently from before, one effect each (see diffAtoms).
func DiffAtoms(before, current []Rule) []Change { return diffAtoms(before, current) }

// diffAtoms lists what current allows or blocks that approved didn't: added (a new target), removed (a target
// gone) and flipped (the same target, the other effect). Riskiest first: anything newly allowed.
func diffAtoms(approved, current []Rule) []Change {
	// Fixed rows can't change (Maze rebuilds them), so they are never listed as changes.
	unfixed := func(rs []Rule) []Rule {
		var out []Rule
		for _, r := range rs {
			if !r.Always {
				out = append(out, r)
			}
		}
		return out
	}
	approved, current = unfixed(approved), unfixed(current)
	key := func(a Atom) string { return a.Category + "\x00" + a.Verb + "\x00" + a.Target }
	was := map[string]Atom{}
	for _, a := range Atoms(approved) {
		was[key(a)] = a
	}
	var out []Change
	seen := map[string]bool{}
	for _, a := range Atoms(current) {
		seen[key(a)] = true
		old, ok := was[key(a)]
		switch {
		case !ok:
			out = append(out, Change{Kind: "added", Rule: AtomRule(a)})
		case old.Allow != a.Allow:
			out = append(out, Change{Kind: "flipped", Rule: AtomRule(a)})
		}
	}
	for _, a := range Atoms(approved) {
		if !seen[key(a)] {
			out = append(out, Change{Kind: "removed", Rule: AtomRule(a)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return risk(out[i]) > risk(out[j]) })
	return out
}

// risk orders changes for the approval page: a newly allowed login, website or program first.
func risk(c Change) int {
	if c.Kind == "removed" || !c.Rule.Allow {
		return 0
	}
	switch c.Rule.Category {
	case "logins":
		return 4
	case "websites":
		return 3
	case "programs":
		return 2
	}
	return 1
}

// LinkedDirError names a folder Maze would write into that is a link: following it could write anywhere.
type LinkedDirError struct{ shown, target string }

// Unwrap lets errors.As find it through wrapping.
func (e *LinkedDirError) Unwrap() error { return nil }

func (e *LinkedDirError) Error() string {
	return e.shown + " is a link to " + e.target + ". Maze only writes real folders inside the project; remove the link and run maze again"
}

// realDirs checks that each folder along rel under root, where it exists, is a real folder and not a link.
func realDirs(root, rel string) error {
	p := root
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" {
			continue
		}
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			shown, _ := filepath.Rel(filepath.Dir(root), p)
			return &LinkedDirError{shown, target}
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is a file, not a folder", p)
		}
	}
	return nil
}
