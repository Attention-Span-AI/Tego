// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
)

// This file is the compile output and the predicates the supervisor's alternate guard (ADR 0057 D2) reads beyond the
// table's fs entries: a person's alternate is a file that may not exist when the table compiled, so the guard refuses
// by what a protected path is named, not only by the rows compile found.

// DenyReadPattern is one entry of RuleTable.DenyReadPatterns: a filepath.Match pattern, absolute, and the rule it
// stands for.
type DenyReadPattern struct {
	// Pattern is matched against a file's path and each of its ancestors (filepath.Match), ASCII case folded too.
	Pattern string
	// Rule names the entry: fs.deny_read[<glob as declared>], or fs.deny_read[<built-in path>] for the built-in list.
	Rule string
}

// denyReadGlob records a whole deny_read glob p (declared raw) in RuleTable.DenyReadPatterns: as declared, and with
// its literal base symlink-resolved where that differs, since the guard matches the path the kernel names a file by.
func (b *fsBuilder) denyReadGlob(p, raw string) {
	k := b.k
	rule := "fs." + string(FSDenyRead) + "[" + raw + "]"
	k.addDenyReadPattern(p, rule)
	base := globBase(p)
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return
	}
	if rb := k.resolve(base); rb != "" && rb != base {
		k.addDenyReadPattern(filepath.Join(escapeGlob(rb), rel), rule)
	}
}

// builtInDenyReadPatterns records the built-in deny_read list's paths under the home directory in
// RuleTable.DenyReadPatterns, whether each exists or not and whatever the contract's deny_read says: compile keys
// no rule on one that does not exist (RuleTable.AbsentDenyRead carries it to the Landlock ruleset), but a person's
// alternate can name one created later (a ~/.netrc written during the run), and a typo must not hand the agent a
// credential (ADR 0057 D2).
func (k *compiler) builtInDenyReadPatterns() {
	home := k.o.home
	if home == "" || !filepath.IsAbs(home) {
		return
	}
	rhome := k.resolve(home)
	for _, rel := range builtInDenyRead {
		p := filepath.Join(home, rel)
		rule := "fs." + string(FSDenyRead) + "[" + p + "]"
		k.addDenyReadPattern(escapeGlob(p), rule)
		if rhome != "" && rhome != home {
			k.addDenyReadPattern(escapeGlob(filepath.Join(rhome, rel)), rule)
		}
		if r := k.resolve(p); r != "" && r != p {
			k.addDenyReadPattern(escapeGlob(r), rule)
		}
		// A row that is a symlink leading nowhere yet: the file a login writing through it makes is where it leads, which
		// resolve names as the link itself.
		if d, ok := danglingPlace(p); ok {
			k.addDenyReadPattern(escapeGlob(d), rule)
		}
	}
}

func (k *compiler) addDenyReadPattern(pattern, rule string) {
	pattern = filepath.Clean(pattern)
	if !filepath.IsAbs(pattern) || pattern == "/" {
		return
	}
	if !slices.ContainsFunc(k.rt.DenyReadPatterns, func(d DenyReadPattern) bool { return d.Pattern == pattern }) {
		k.rt.DenyReadPatterns = append(k.rt.DenyReadPatterns, DenyReadPattern{Pattern: pattern, Rule: rule})
	}
}

// escapeGlob quotes filepath.Match's metacharacters in a literal path.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// DenyReadPatternOf returns the RuleTable.DenyReadPatterns entry that matches p or one of its ancestors: p is, or
// lies beneath, a file a declared deny_read glob names or a path of the built-in list, whether or not it existed when
// the table compiled. Matching is also made ASCII case folded, as ADR 0043's name entries are, so another spelling
// of a name on a case-insensitive filesystem is refused too. p must be absolute.
func (rt *RuleTable) DenyReadPatternOf(p string) (DenyReadPattern, bool) {
	if rt == nil || len(rt.DenyReadPatterns) == 0 || !filepath.IsAbs(p) {
		return DenyReadPattern{}, false
	}
	for q := filepath.Clean(p); ; q = filepath.Dir(q) {
		lq := strings.ToLower(q)
		for _, d := range rt.DenyReadPatterns {
			if ok, _ := filepath.Match(d.Pattern, q); ok {
				return d, true
			}
			if ok, _ := filepath.Match(strings.ToLower(d.Pattern), lq); ok {
				return d, true
			}
		}
		if q == "/" {
			return DenyReadPattern{}, false
		}
	}
}

// WriteAlternateClass names the built-in deny_write class a file falls in by its path's names alone, wherever it
// lies: a git hook or a git config (a file beneath a hooks/ beneath a .git, a config or config.worktree beneath a
// .git, a .git file itself, a file beneath a .husky or .githooks directory), harness or editor settings
// (a .claude, .mcp.json, .cursor, .codex, .gemini or .vscode anywhere on its path), a shell startup file (its name
// one of the startup names, or fish's config.fish) or a per-user git config (.gitconfig, git/config). The built-in
// deny_write set (R20) holds only the targets compile found beneath a write entry or an fs.ask scope; a person's
// alternate for a held write can name one anywhere, created later or in a repository no entry covers, and the
// supervisor would hand the agent a writable descriptor of code that runs outside the run (ADR 0057 D2).
func WriteAlternateClass(p string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/")
	n := len(parts)
	if n == 0 {
		return "", false
	}
	name := parts[n-1]
	if name == ".git" {
		return "git config", true // a .git file names the git directory, whose hooks then run
	}
	for i, c := range parts {
		for _, d := range denyWriteAtRepo {
			if c == d.name {
				return d.what, true
			}
		}
		if i < n-1 && (c == ".husky" || c == ".githooks") {
			return "git hooks", true // the directories core.hooksPath most often names
		}
		if c == ".git" && i < n-1 {
			if slices.Contains(parts[i+1:n-1], "hooks") {
				return "git hooks", true
			}
			if name == "config" || name == "config.worktree" {
				return "git config", true
			}
		}
	}
	for _, d := range denyWriteInHome {
		dp := strings.Split(d.name, "/")
		if len(dp) == 1 && name == d.name {
			return d.what, true
		}
		// .config/fish/config.fish and .config/git/config: by their last two names, wherever ~/.config resolves.
		if len(dp) > 1 && n >= len(dp)-1 && slices.Equal(parts[n-len(dp)+1:], dp[1:]) {
			return d.what, true
		}
	}
	return "", false
}
