// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
)

// What people type to add a rule (in the review's "Add a rule" or with maze allow/block) is checked here, once,
// for both. Everything is cut to the one name the engine uses (a pasted URL to its host, a path to its program),
// and anything Maze can't enforce as typed is refused with the reason.

// isNeverAllowed reports whether name (or the file it resolves to) is Maze or the engine, in any letter case:
// macOS's file system ignores case, so MAZE runs maze.
func isNeverAllowed(r Report, name string) bool {
	if neverAllowed[strings.ToLower(name)] {
		return true
	}
	if p := r.env.LookPath(name); p != "" {
		if real, err := filepath.EvalSymlinks(p); err == nil && neverAllowed[strings.ToLower(filepath.Base(real))] {
			return true
		}
	}
	return false
}

// addProgram is the rule "can run name". A path is cut to the program's name, which is what the engine allows; a
// script in the project is refused, since the engine allows programs by name and bash runs scripts.
func addProgram(r Report, value string) (Rule, string) {
	value = typedPath(value)
	switch {
	case value == "" || value == "." || value == "..":
		return Rule{}, "Name a program, like make."
	case strings.ContainsAny(value, " \t"):
		return Rule{}, "One program name, like make. Its arguments don't matter: Maze allows the whole program."
	case strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || (strings.Contains(value, "/") && !filepath.IsAbs(value)):
		return Rule{}, "Maze allows programs by name. To run a project script, have Claude Code run it with bash: bash " + value
	}
	name := filepath.Base(value)
	if strings.EqualFold(name, scope.Shell) {
		return Rule{}, "Claude Code can always run bash: it's the shell it runs every command in."
	}
	if why := scope.ProgramProblem(name); why != "" {
		return Rule{}, why
	}
	if isNeverAllowed(r, name) {
		return Rule{}, "Not " + name + ": it could change the rules Claude Code runs under."
	}
	why := "added"
	if r.env.LookPath(name) == "" {
		why = "added · not installed yet"
	}
	return Rule{Scope: "workspace", Category: "programs", Verb: "run", Value: name, Allow: true, Why: why, Programs: []string{name}, Added: true}, ""
}

// addWebsite is the rule "can connect to host". A pasted URL or git remote is cut to its host:
// https://api.github.com/repos and git@github.com:org/repo both become their host.
func addWebsite(value string) (Rule, string) {
	host := strings.ToLower(typedPath(value))
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host = strings.SplitN(host, "/", 2)[0]
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	host = strings.SplitN(host, ":", 2)[0]
	host = strings.SplitN(strings.SplitN(host, "?", 2)[0], "#", 2)[0]
	host = strings.TrimSuffix(host, ".")
	if why := scope.HostProblem(host); why != "" {
		return Rule{}, strings.Replace(why, host+" isn't", value+" isn't", 1)
	}
	return Rule{Scope: "workspace", Category: "websites", Verb: "reach", Value: host, Allow: true, Why: "added", Hosts: []string{host}, Added: true}, ""
}

// filePath resolves a typed path to an absolute one (relative paths start at base) and the form a rule keeps:
// relative inside the project, ~/… under the home folder, absolute elsewhere.
func filePath(r Report, base, typed string) (abs, stored string) {
	p := expandHome(r.Home, typedPath(typed))
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	abs = filepath.Clean(p)
	root := filepath.Clean(r.Workspace.Root)
	switch rel, err := filepath.Rel(root, abs); {
	case err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)):
		stored = filepath.ToSlash(rel)
	default:
		stored = tildePath(r.Home, abs)
	}
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() && !strings.HasSuffix(stored, "/") {
		stored += "/"
	}
	return abs, stored
}

// lockedFile says why Maze always blocks reading abs (a .env file, or anything in a key folder), or "".
// The name is compared without letter case (macOS ignores it), and a link is followed: a link to ~/.ssh is
// ~/.ssh.
func lockedFile(r Report, abs string) string {
	paths := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		paths = append(paths, real)
	}
	for _, p := range paths {
		if scan.IsEnvFile(strings.ToLower(filepath.Base(p))) {
			return ".env files are always blocked: they may hold secrets"
		}
		if key, ok := scan.KeyFolder(r.Home, p); ok {
			return key + " is always blocked: it holds keys"
		}
	}
	return ""
}

// addFile is the rule "can't read path". The engine blocks only what exists when the rules are saved, so a path
// with nothing at it is refused rather than shown as blocked.
func addFile(r Report, base, value string) (Rule, string) {
	abs, stored := filePath(r, base, value)
	switch {
	case abs == filepath.Clean(r.Workspace.Root):
		return Rule{}, "That's the whole project. Block files or folders inside it."
	case abs == filepath.Clean(r.Home) || abs == string(filepath.Separator):
		return Rule{}, "That's too broad. Block files or folders, like config/prod.json."
	case strings.HasPrefix(filepath.Clean(r.Workspace.Root), abs+string(filepath.Separator)):
		return Rule{}, "That folder holds the whole project. Block files or folders inside it."
	}
	if why := lockedFile(r, abs); why != "" {
		return Rule{}, "No need: " + why + "."
	}
	if _, err := os.Lstat(abs); err != nil {
		return Rule{}, "There's no file at " + value + ". Maze blocks files that exist; add the rule once it's there."
	}
	rl := Rule{Category: "files", Verb: "read", Value: stored, Allow: false, Why: "added", Paths: []string{strings.TrimSuffix(stored, "/")}, Added: true}
	rl.Scope = scopeOf(rl)
	return rl, ""
}

// isLoginToken reports whether a variable holds (or reaches) a login to push or publish with.
func isLoginToken(name string) bool { return scope.LoginToken(name) }

// envRule checks a typed variable name ("$OPENAI_API_KEY" or "OPENAI_API_KEY") and returns it bare.
func envRule(value string) (string, string) {
	name := strings.TrimPrefix(strings.TrimSpace(value), "$")
	if !envNameRE.MatchString(name) {
		return "", value + " isn't a variable name. Use one like OPENAI_API_KEY."
	}
	return name, ""
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// covers reports whether have already says what rl says: the same value, or a program, website or file it
// lists. Websites compare without letter case, as DNS does.
func covers(have, rl Rule) bool {
	eq := func(a, b string) bool { return a == b || (rl.Category == "websites" && strings.EqualFold(a, b)) }
	if eq(have.Value, rl.Value) {
		return true
	}
	for _, list := range [][]string{have.Programs, have.Hosts, have.Paths} {
		for _, x := range list {
			if eq(x, rl.Value) || eq(x, strings.TrimSuffix(rl.Value, "/")) {
				return true
			}
		}
	}
	return false
}

// shellQuote quotes s for a command line when it holds anything a shell would read specially.
func shellQuote(s string) string {
	if s != "" && regexp.MustCompile(`^[A-Za-z0-9._/~:@%+=,-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
