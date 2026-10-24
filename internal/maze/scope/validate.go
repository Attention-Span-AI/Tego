// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
)

// A rules file is read the way Maze would have written it, never the way it says it should be read. Which rows
// are fixed comes from Maze's own list, not from the file's `always` field; every row's label is rebuilt from
// the programs, websites and files it really lists; a note survives only if it is one Maze writes; and a rule
// that Maze's own "Add a rule" would refuse (maze itself, sudo, a key folder, an IP address, a login token) is
// dropped. Each change is reported, so the approval page can say what a file tried and what Maze kept.

// IgnoredRule is a rule from a file that Maze didn't take as written, and why.
type IgnoredRule struct {
	Rule   Rule
	Reason string
}

// NeverAllowed are programs no rule lets the agent run: Maze's own CLI and the engine, which could change or stop
// the rules the agent runs under. Compared without letter case: macOS's file system ignores it.
var NeverAllowed = map[string]bool{"maze": true, "tego": true}

// rootTools switch user: the agent never runs as root under Maze.
var rootTools = map[string]bool{"sudo": true, "su": true, "doas": true, "pkexec": true, "run0": true}

// loginPrograms use the person's saved logins to push: git's credential helpers and GitHub's CLI.
func loginProgram(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "git-credential-") || n == "gh" || n == "glab" || n == "hub"
}

// credentialTools reach saved logins and keys: the macOS keychain, SSH agents, password managers.
var credentialTools = map[string]bool{"security": true, "ssh-add": true, "ssh-agent": true, "op": true, "pass": true,
	"secret-tool": true, "keyring": true, "gopass": true, "bw": true, "lpass": true}

// publishTools only publish packages.
var publishTools = map[string]bool{"twine": true, "flit": true, "np": true}

// BasicTools are the everyday programs a coding agent's shell commands use; none reaches the network on its own.
var BasicTools = []string{
	"ls", "cat", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "grep", "find", "sed", "awk", "diff",
	"mkdir", "cp", "mv", "rm", "touch", "chmod", "ln", "pwd", "echo", "printf", "dirname", "basename",
	"xargs", "env", "which", "date", "sleep", "tee", "test", "true", "false",
}

// Shell is the program Claude Code runs every command through: always allowed, shown as a fixed row.
const Shell = "bash"

var programName = regexp.MustCompile(`^[A-Za-z0-9_+][A-Za-z0-9._+-]*$`)

// ProgramProblem says why name can't be a program rule, or "".
func ProgramProblem(name string) string {
	n := strings.ToLower(name)
	switch {
	case !programName.MatchString(name):
		return name + " isn't a program name. Use letters, numbers and . _ + - only, like make."
	case NeverAllowed[n]:
		return "Not " + name + ": it could change the rules Claude Code runs under."
	case rootTools[n]:
		return "Not " + name + ": Claude Code never runs as root under Maze."
	case loginProgram(n) || credentialTools[n]:
		return "Not " + name + ": it uses your saved logins, so Claude Code could push or publish as you."
	case publishTools[n]:
		return "Not " + name + ": it publishes packages, and Claude Code can't publish as you."
	}
	return ""
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// HostProblem says why host can't be a website rule, or "".
func HostProblem(host string) string {
	if host == "localhost" || net.ParseIP(host) != nil {
		return "Maze allows websites by name for now, like api.github.com; local services and IP addresses come later."
	}
	labels := strings.Split(host, ".")
	ok := len(labels) >= 2
	for _, l := range labels {
		ok = ok && hostLabel.MatchString(l)
	}
	if !ok || strings.Trim(labels[len(labels)-1], "abcdefghijklmnopqrstuvwxyz") != "" {
		return host + " isn't a website name. Use one like api.github.com."
	}
	if host == "upload.pypi.org" || host == "test.pypi.org" || host == "upload.pypi.io" {
		return "Not " + host + ": it's where Python packages are published, and Claude Code can't publish as you."
	}
	if host == "anthropic.com" || strings.HasSuffix(host, ".anthropic.com") {
		return "Not needed: Claude Code reaches its model through Maze already, and that route is recorded."
	}
	return ""
}

// LoginToken reports whether a variable holds a login to push or publish with, or reaches one (an SSH agent),
// or changes what every program loads: seeing it would break the promise that Claude Code can't push as you.
func LoginToken(name string) bool {
	n := strings.ToUpper(name)
	switch n {
	case "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GITLAB_TOKEN",
		"NPM_TOKEN", "NODE_AUTH_TOKEN", "PYPI_TOKEN", "PYPI_API_TOKEN", "TWINE_PASSWORD", "POETRY_PYPI_TOKEN_PYPI",
		"UV_PUBLISH_TOKEN", "CARGO_REGISTRY_TOKEN", "SSH_AUTH_SOCK", "GIT_ASKPASS", "SSH_ASKPASS", "LD_PRELOAD":
		return true
	}
	return strings.HasPrefix(n, "DYLD_")
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LockedPath says why reading path is always blocked, or "": see lockedPath.
func LockedPath(home, path string) string { return lockedPath(home, path) }

// lockedPath says why reading path is always blocked (a .env file, a key folder), or "". The name is compared
// without letter case, and home is where ~ points.
func lockedPath(home, path string) string {
	abs := path
	if strings.HasPrefix(path, "~") {
		abs = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
	}
	base := strings.ToLower(filepath.Base(path))
	if scan.IsEnvFile(base) {
		return ".env files are always blocked"
	}
	if base == ".npmrc" || base == ".pypirc" || base == ".yarnrc.yml" {
		return base + " may hold a publish token, so it's always blocked"
	}
	if key, ok := scan.KeyFolder(home, abs); ok {
		return key + " is always blocked"
	}
	return ""
}

// note is the hint Maze shows after a rule, worked out from what the rule is: a note from a file is never shown as
// written (a shared file could put "Claude Code signs in with it" next to any secret). Only the person's own marks
// ("added", "set with maze allow") are kept, and only where they describe the rule.
func note(r Rule) string {
	keep := strings.HasPrefix(r.Why, "added") || r.Why == "set with maze allow" || r.Why == "set with maze block"
	switch {
	case r.Category == "programs" && r.Value == Shell:
		return "Claude Code's shell"
	case r.Category == "programs" && r.Value == "basic tools":
		return few(r.Programs, 3)
	case r.Category == "websites":
		if tool := scan.RegistryTool(r.Hosts); tool != "" && !keep {
			return tool + " packages"
		}
	case r.Category == "logins" && r.Verb == "commit":
		return "signed with its own key"
	case r.Category == "logins" && r.Verb == "see" && LoginToken(r.Value):
		return "it could push or publish as you"
	case r.Category == "logins" && r.Verb == "see" && (r.Value == "ANTHROPIC_API_KEY" || r.Value == "CLAUDE_CODE_OAUTH_TOKEN"):
		if r.Allow {
			return "Claude Code signs in with it"
		}
		return "Claude Code can't sign in without it"
	case r.Category == "files" && r.Verb == "read" && r.Value == "any .env file" && len(r.Paths) > 0:
		return "found: " + few(r.Paths, 3)
	case r.Category == "files" && r.Verb == "read" && !r.Allow && !keep:
		if strings.HasPrefix(r.Why, "sets ") || strings.HasPrefix(r.Why, "has keys") || strings.HasPrefix(r.Why, "may hold") {
			return r.Why // describes the file, not what it may do
		}
	}
	if keep {
		return r.Why
	}
	return ""
}

// few names up to n items and counts the rest.
func few(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + " and " + strconv.Itoa(len(items)-n) + " more"
}

// normalize reads rules as Maze would have written them (see the top of this file), in place, and returns what
// it dropped or changed. home resolves ~ for the key-folder check.
// shared is set for the project's file: rules about the person's home folder or environment never come from it,
// since a commit would otherwise widen what Claude Code may read in every project.
func normalize(home string, rules []Rule, shared bool) ([]Rule, []IgnoredRule) {
	var out []Rule
	var ignored []IgnoredRule
	ignore := func(r Rule, why string) { ignored = append(ignored, IgnoredRule{r, why}) }
	for _, r := range rules {
		orig := r
		// A rule written by hand may give only its value: its list is that value, so it is checked and shown
		// like any other (a website with no hosts list is still a website).
		fromValue := func() []string {
			var out []string
			for _, v := range strings.Split(r.Value, ",") {
				if v = strings.TrimSpace(v); v != "" {
					out = append(out, v)
				}
			}
			return out
		}
		special := r.Value == "anything else" || r.Value == "basic tools" || r.Value == Shell ||
			strings.HasPrefix(r.Value, "everything in ") || strings.HasPrefix(r.Value, "anything outside ") ||
			r.Value == "any .env file" || r.Value == "~/.ssh, ~/.aws and other keys" || strings.HasPrefix(r.Value, ".git/hooks")
		switch {
		case special:
		case r.Category == "programs" && len(r.Programs) == 0:
			r.Programs = fromValue()
		case r.Category == "websites" && len(r.Hosts) == 0:
			r.Hosts = fromValue()
		case r.Category == "files" && r.Verb == "read" && len(r.Paths) == 0:
			r.Paths = fromValue()
		}
		r.Always = false
		if shared && r.Category == "logins" && r.Verb == "see" {
			ignore(orig, "settings in your environment belong in your own rules, not the project's shared file")
			continue
		}
		if shared && r.Category == "files" && r.Verb == "read" {
			outside := strings.HasPrefix(r.Value, "~") || strings.HasPrefix(r.Value, "/")
			for _, p := range r.Paths {
				outside = outside || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "/") || strings.HasPrefix(filepath.Clean(p), "..")
			}
			if outside && r.Value != "~/.ssh, ~/.aws and other keys" {
				ignore(orig, "files outside the project belong in your own rules, not the project's shared file")
				continue
			}
		}
		switch r.Category {
		case "files":
			switch {
			case strings.HasPrefix(r.Value, "everything in "):
				r.Always = r.Verb == "read"
				r.Paths = nil
			case r.Verb == "write" && (strings.HasPrefix(r.Value, "anything outside ") || strings.HasPrefix(r.Value, ".git/hooks")):
				r.Always, r.Paths = true, nil
			case r.Verb == "write":
				ignore(orig, "Maze can't block changes to one path yet, so this rule does nothing")
				continue
			case r.Value == "any .env file" || r.Value == "~/.ssh, ~/.aws and other keys":
				r.Always = true
			default:
				var paths []string
				locked := ""
				for _, p := range r.Paths {
					clean := filepath.ToSlash(filepath.Clean(p))
					if clean == "." || clean == "/" || clean == "~" || strings.HasPrefix(clean, "../") {
						ignore(orig, "it names "+p+", which is the whole project or outside it")
						continue
					}
					if why := lockedPath(home, clean); why != "" {
						locked = why
					}
					paths = append(paths, clean)
				}
				if len(paths) == 0 {
					continue
				}
				r.Paths = paths
				r.Value = strings.Join(paths, ", ")
				if locked != "" {
					r.Always = true
				}
			}
		case "programs":
			switch r.Value {
			case "anything else":
				r.Always, r.Programs = true, nil
			case Shell:
				r.Always, r.Programs = true, []string{Shell}
			default:
				var progs, extra []string
				for _, p := range r.Programs {
					if why := ProgramProblem(p); why != "" {
						ignore(AtomRule(Atom{"programs", "run", p, r.Allow}), why)
						continue
					}
					if strings.EqualFold(p, Shell) {
						continue // the shell has its own fixed row
					}
					if r.Value == "basic tools" && !slices.Contains(BasicTools, p) {
						extra = append(extra, p)
						continue
					}
					progs = append(progs, p)
				}
				if len(extra) > 0 {
					// Not a basic tool: shown on a row of its own, so nothing hides inside "basic tools".
					x := r
					x.Value, x.Programs, x.Why = strings.Join(extra, ", "), extra, ""
					out = append(out, x)
				}
				if len(progs) == 0 {
					continue
				}
				r.Programs = progs
				if r.Value != "basic tools" {
					r.Value = strings.Join(progs, ", ")
				}
			}
		case "websites":
			if r.Value == "anything else" {
				r.Always, r.Hosts = true, nil
				break
			}
			var hosts []string
			for _, h := range r.Hosts {
				h = strings.ToLower(h)
				if why := HostProblem(h); why != "" {
					ignore(AtomRule(Atom{"websites", "reach", h, r.Allow}), why)
					continue
				}
				hosts = append(hosts, h)
			}
			if len(hosts) == 0 {
				continue
			}
			r.Hosts, r.Value = hosts, strings.Join(hosts, ", ")
		case "logins":
			switch r.Verb {
			case "push", "publish", "commit":
				r.Always = true
			case "see":
				if !envName.MatchString(r.Value) {
					ignore(orig, r.Value+" isn't a variable name")
					continue
				}
				r.Always = LoginToken(r.Value)
			}
		}
		if r.Always && !(r.Category == "logins" && r.Verb == "commit") {
			// (The commit row follows git: its effect is worked out from the programs, never taken as a change.)
			if want := LockedAllow(r); r.Allow != want {
				ignore(orig, "it's a fixed rule")
				r.Allow = want
			}
		}
		r.Why = note(r)
		out = append(out, r)
	}
	return out, ignored
}
