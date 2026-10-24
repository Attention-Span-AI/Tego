// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ClaudeRule is one permission rule from Claude Code's settings: which file it came from, which list
// (allow, deny or ask) and the rule as written, e.g. "Bash(git push*)" or "Read(./.env)".
type ClaudeRule struct {
	// Source is the settings file, as a person would find it: .claude/settings.json or ~/.claude/settings.json.
	Source string `json:"source"`
	// List is "allow", "deny" or "ask".
	List string `json:"list"`
	// Rule is the rule exactly as written in the file.
	Rule string `json:"rule"`
}

// Tool is the rule's tool name ("Bash", "Read", "WebFetch", "mcp__github"), and Spec what is inside its
// parentheses, or "" when it has none.
func (c ClaudeRule) Tool() string {
	tool, _, _ := strings.Cut(c.Rule, "(")
	return strings.TrimSpace(tool)
}

// Spec is what is inside the rule's parentheses: "git push*" for "Bash(git push*)".
func (c ClaudeRule) Spec() string {
	_, spec, ok := strings.Cut(c.Rule, "(")
	if !ok {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(spec), ")")
}

// claudeSettings is the part of a Claude Code settings file Maze reads.
type claudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
		Ask   []string `json:"ask"`
	} `json:"permissions"`
}

// ClaudeRules reads the permission rules a person already gave Claude Code: the project's .claude/settings.json
// and .claude/settings.local.json, and ~/.claude/settings.json. A missing file is no rules. A file Maze can't use
// (a link, too large, not JSON) is reported in problems, by name, and the other files are still read: one broken
// file never hides the rules in the others.
func ClaudeRules(env Env, root string) (rules []ClaudeRule, problems []string) {
	var files []struct{ path, shown string }
	// The project's .claude must be the project's own folder: a link (to ~/.claude, a dotfiles setup, or wherever a
	// cloned repo points it) would have the person's own rules read as the team's shared file and copied into the
	// committed workspace file.
	if fi, err := os.Lstat(filepath.Join(root, ".claude")); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		problems = append(problems, ".claude is a link, so Maze didn't read the settings in it (put the folder itself there)")
	} else {
		files = append(files,
			struct{ path, shown string }{filepath.Join(root, ".claude", "settings.json"), ".claude/settings.json"},
			struct{ path, shown string }{filepath.Join(root, ".claude", "settings.local.json"), ".claude/settings.local.json"})
	}
	if env.Home != "" {
		files = append(files, struct{ path, shown string }{filepath.Join(env.Home, ".claude", "settings.json"), "~/.claude/settings.json"})
	}
	for _, f := range files {
		data, err := readRegular(f.path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, ErrOnlyInCloud):
			problems = append(problems, f.shown+" is only in iCloud, not on this disk, so Maze didn't read it")
			continue
		case errors.Is(err, errNotRegular):
			problems = append(problems, f.shown+" is a link, so Maze didn't read it (put the file itself there)")
			continue
		case err != nil:
			problems = append(problems, fmt.Sprintf("couldn't read %s: %v", f.shown, err))
			continue
		}
		var s claudeSettings
		if err := json.Unmarshal(data, &s); err != nil {
			var typeErr *json.UnmarshalTypeError
			if errors.As(err, &typeErr) {
				problems = append(problems, f.shown+": permissions isn't in the shape Claude Code uses, so Maze skipped it")
			} else {
				problems = append(problems, f.shown+" isn't valid JSON, so Maze skipped it")
			}
			continue
		}
		type list struct {
			name  string
			rules []string
		}
		for _, l := range []list{{"deny", s.Permissions.Deny}, {"ask", s.Permissions.Ask}, {"allow", s.Permissions.Allow}} {
			for _, r := range l.rules {
				if r = strings.TrimSpace(r); r != "" {
					rules = append(rules, ClaudeRule{Source: f.shown, List: l.name, Rule: r})
				}
			}
		}
	}
	return rules, problems
}
