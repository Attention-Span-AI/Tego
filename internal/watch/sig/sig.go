// SPDX-License-Identifier: Apache-2.0

// Package sig recognises an agent process from facts about it (docs/poc/agent-watcher.md, M2). It is pure: the
// caller reads /proc and hands over what it found, so the rules are tested without a process.
//
// A rule is one of four shapes, each a plain editable value, and the list of them is data:
//
//	claude                       a basename: the process's program, its argv[0] or its comm is exactly this name
//	/opt/agents/bin/claude       an exact path: the process's executable is this file
//	node .../claude-code/cli.js  an argv pattern: the program, then arguments, each matched in order (below)
//	file:259:1048577             a file identity: the executable is this device and inode, whatever it is called
//
// The shipped list (Default) names claude, codex, opencode and gemini, and nothing else in this package knows
// them: a user adds a rule, replaces a shipped one by giving it the same name, or removes it, through Merge.
// Tego never needs to know what an agent is; a rule only says which running programs the operator calls one.
//
// A match is only a name for a process. Nothing here, or in anything that uses it, moves, signals or blocks the
// process it recognised.
package sig

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// FileID is a file's identity: the device and inode of /proc/<pid>/exe, which names the binary whatever path it
// was started through (a symlink such as ~/.local/bin/claude, or a versions/2.1.290 file). The zero value is
// unknown, which no file rule matches.
type FileID struct{ Dev, Ino uint64 }

// Facts is what the caller read about one process. Any field may be empty: a process that exited mid-read leaves
// some of them unread, and a rule needing a missing fact simply does not match.
type Facts struct {
	Exe  string   // readlink /proc/<pid>/exe, the " (deleted)" suffix removed
	Argv []string // /proc/<pid>/cmdline split on NUL
	Comm string   // /proc/<pid>/comm, the kernel's 15-byte name
	File FileID   // the identity of the file /proc/<pid>/exe opens
}

// Rule is one signature. Exactly one of Basename, Path, Argv and File is set.
type Rule struct {
	// Name is what a sighting reports and what a replacement or removal names. Several rules may share a name
	// (a shipped agent has one for its native binary and one for its node entry point).
	Name     string
	Basename string
	Path     string
	Argv     []string
	File     FileID
}

// maxComm is the kernel's comm length (TASK_COMM_LEN less the NUL): a longer basename cannot equal a comm.
const maxComm = 15

// Match reports whether the facts are this rule's agent.
func (r Rule) Match(f Facts) bool {
	switch {
	case r.Basename != "":
		return base(f.Exe) == r.Basename || (len(f.Argv) > 0 && base(f.Argv[0]) == r.Basename) ||
			(len(r.Basename) <= maxComm && f.Comm == r.Basename)
	case r.Path != "":
		return f.Exe == r.Path
	case r.File != FileID{}:
		return f.File == r.File
	case len(r.Argv) > 0:
		return matchArgv(r.Argv, f)
	}
	return false
}

// matchArgv matches an argv pattern. Its first token names the program: it matches the executable or argv[0], by
// basename when it holds no slash and as a whole path when it does. Each later token must match an argument after
// argv[0], in order; arguments between two matched ones, flags for one, are skipped. A token is a path.Match glob,
// and one that starts with ".../" matches a path ending in the rest of it, whatever directory it is in.
func matchArgv(pat []string, f Facts) bool {
	if len(f.Argv) == 0 {
		return false
	}
	prog := func(s string) bool {
		if strings.Contains(pat[0], "/") {
			return matchToken(pat[0], s)
		}
		return s != "" && matchToken(pat[0], base(s))
	}
	if !prog(f.Exe) && !prog(f.Argv[0]) {
		return false
	}
	args := f.Argv[1:]
	for _, tok := range pat[1:] {
		for len(args) > 0 && !matchToken(tok, args[0]) {
			args = args[1:]
		}
		if len(args) == 0 {
			return false
		}
		args = args[1:]
	}
	return true
}

// matchToken is one argv-pattern token against one string.
func matchToken(tok, s string) bool {
	if rest, ok := strings.CutPrefix(tok, ".../"); ok {
		n := strings.Count(rest, "/") + 1
		parts := strings.Split(s, "/")
		if len(parts) < n {
			return false
		}
		tok, s = rest, strings.Join(parts[len(parts)-n:], "/")
	}
	ok, err := path.Match(tok, s)
	return err == nil && ok
}

func base(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(p)
}

// Validate reports why a rule cannot be used, or nil.
func (r Rule) Validate() error {
	if !nameRE.MatchString(r.Name) {
		return fmt.Errorf("rule name %q: lower-case letters, digits, '-' and '_', starting with a letter, at most 32", r.Name)
	}
	n := 0
	if r.Basename != "" {
		n++
		if strings.ContainsAny(r.Basename, "/ \t") {
			return fmt.Errorf("rule %s: a basename holds no slash or space", r.Name)
		}
	}
	if r.Path != "" {
		n++
		if !path.IsAbs(r.Path) || path.Clean(r.Path) != r.Path || strings.ContainsAny(r.Path, " \t") {
			return fmt.Errorf("rule %s: a path is absolute, clean, with no space", r.Name)
		}
	}
	if r.File != (FileID{}) {
		n++
		if r.File.Ino == 0 {
			return fmt.Errorf("rule %s: a file identity needs an inode", r.Name)
		}
	}
	if len(r.Argv) > 0 {
		n++
		for _, tok := range r.Argv {
			if tok == "" {
				return fmt.Errorf("rule %s: an empty argv token", r.Name)
			}
			if _, err := path.Match(strings.TrimPrefix(tok, ".../"), ""); err != nil {
				return fmt.Errorf("rule %s: token %q: %w", r.Name, tok, err)
			}
		}
	}
	if n != 1 {
		return fmt.Errorf("rule %s: exactly one of a basename, a path, an argv pattern and a file identity", r.Name)
	}
	return nil
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// specNameRE finds a "name=" prefix on a rule spelling. A token such as --flag=x cannot be read as one: it does
// not start with a letter.
var specNameRE = regexp.MustCompile(`^([a-z][a-z0-9_-]{0,31})=(.*)$`)

// ErrRemove is what Parse returns, with a nil error, for "name=" and nothing after it: the instruction to drop
// every rule of that name.
var ErrRemove = errors.New("sig: remove")

// Parse reads one rule from its spelling, "[name=]<spec>":
//
//	claude                    basename; the rule is named claude
//	/usr/bin/claude           exact path; named claude
//	cc=claude                 the same basename rule, named cc
//	web=node .../web/cli.js   an argv pattern, which needs a name
//	pinned=file:259:1048577   a file identity, which needs a name
//	gemini=                   not a rule: Parse returns ErrRemove and Rule.Name = gemini
func Parse(spec string) (Rule, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Rule{}, errors.New("an empty rule")
	}
	name, rest := "", spec
	if m := specNameRE.FindStringSubmatch(spec); m != nil {
		name, rest = m[1], strings.TrimSpace(m[2])
		if rest == "" {
			return Rule{Name: name}, ErrRemove
		}
	}
	r := Rule{Name: name}
	fields := strings.Fields(rest)
	switch {
	case strings.HasPrefix(rest, "file:"):
		parts := strings.Split(rest, ":")
		dev, e1 := strconv.ParseUint(get(parts, 1), 10, 64)
		ino, e2 := strconv.ParseUint(get(parts, 2), 10, 64)
		if len(parts) != 3 || e1 != nil || e2 != nil {
			return Rule{}, fmt.Errorf("%q: a file identity is file:<device>:<inode>, decimal", spec)
		}
		r.File = FileID{Dev: dev, Ino: ino}
		if name == "" {
			return Rule{}, fmt.Errorf("%q: a file identity needs a name (name=file:<device>:<inode>)", spec)
		}
	case len(fields) > 1:
		r.Argv = fields
		if name == "" {
			return Rule{}, fmt.Errorf("%q: an argv pattern needs a name (name=%s)", spec, rest)
		}
	case strings.HasPrefix(rest, "/"):
		r.Path = rest
		if name == "" {
			name = nameFrom(path.Base(rest))
		}
	case strings.ContainsAny(rest, "*?["):
		// A lone glob is an argv pattern of one token: the program's name, not a basename.
		r.Argv = fields
		if name == "" {
			return Rule{}, fmt.Errorf("%q: a glob needs a name (name=%s)", spec, rest)
		}
	case strings.Contains(rest, "/"):
		return Rule{}, fmt.Errorf("%q: a path rule is absolute; for a relative one write an argv pattern with .../", spec)
	default:
		r.Basename = rest
		if name == "" {
			name = nameFrom(rest)
		}
	}
	r.Name = name
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func get(p []string, i int) string {
	if i < len(p) {
		return p[i]
	}
	return ""
}

// nameFrom turns a program name into a rule name: lower case, anything outside [a-z0-9_-] a hyphen, no leading
// digit, hyphen or underscore, at most 32 characters; "agent" when nothing is left.
func nameFrom(s string) string {
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			b[i] = '-'
		}
	}
	out := strings.TrimLeft(string(b), "-_0123456789")
	if len(out) > 32 {
		out = out[:32]
	}
	if out = strings.TrimRight(out, "-_"); out == "" {
		return "agent"
	}
	return out
}

// List is an ordered list of rules; the first that matches names the process.
type List []Rule

// Match returns the first rule that matches.
func (l List) Match(f Facts) (Rule, bool) {
	for _, r := range l {
		if r.Match(f) {
			return r, true
		}
	}
	return Rule{}, false
}

// Default is the shipped list: claude, codex, opencode and gemini, each by the name of its program and by the
// node entry point an npm install runs. It is data, no more: a caller may use any other list.
func Default() List {
	return List{
		{Name: "claude", Basename: "claude"},
		{Name: "claude", Argv: []string{"node", ".../@anthropic-ai/claude-code/cli.js"}},
		{Name: "codex", Basename: "codex"},
		{Name: "codex", Argv: []string{"node", ".../@openai/codex/bin/codex.js"}},
		{Name: "opencode", Basename: "opencode"},
		{Name: "opencode", Argv: []string{"node", ".../opencode-ai/bin/opencode"}},
		{Name: "gemini", Basename: "gemini"},
		{Name: "gemini", Argv: []string{"node", ".../bin/gemini"}},
		{Name: "gemini", Argv: []string{"node", ".../@google/gemini-cli/dist/index.js"}},
	}
}

// Merge applies rule spellings to a list, in order, and returns the new list; base is not changed. The first
// spelling that names a rule the base holds replaces every base rule of that name, and a later spelling of the
// same name adds one more (so a user may give an agent two entry points); a name that no base rule has is added.
// "name=" with nothing after it removes the name. Any spelling Parse refuses is an error and nothing is applied.
func Merge(base List, specs []string) (List, error) {
	out := append(List(nil), base...)
	touched := map[string]bool{}
	for _, s := range specs {
		r, err := Parse(s)
		if errors.Is(err, ErrRemove) {
			out = dropName(out, r.Name)
			touched[r.Name] = true
			continue
		}
		if err != nil {
			return nil, err
		}
		if !touched[r.Name] {
			out = dropName(out, r.Name)
			touched[r.Name] = true
		}
		out = append(out, r)
	}
	return out, nil
}

func dropName(l List, name string) List {
	out := l[:0:0]
	for _, r := range l {
		if r.Name != name {
			out = append(out, r)
		}
	}
	return out
}
