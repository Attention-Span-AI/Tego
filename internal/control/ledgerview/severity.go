// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"path"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Severity ranks a refusal group or a secret touch for the dashboard: High first, Routine folded away. It is read
// from where the action happened (a secret, the agent's own folders, elsewhere) and what it was (a read, a
// program, a connection), never from how often it happened.
type Severity int

const (
	SevRoutine Severity = iota // system lookups, route probes, standard devices: folded away
	SevLow                     // the run's agent reading its own files, or writing its own caches and state
	SevMedium                  // another program, a change outside the project or in an agent's folder, another agent's files
	SevHigh                    // a secret, a connection the policy does not allow, a program that reaches out, a change to what runs code later
)

func (s Severity) String() string {
	return [...]string{"Routine", "Low", "Medium", "High"}[s]
}

// Channel is the policy channel a group's class belongs to, as the Rules page groups its rules.
func Channel(class string) string {
	switch class {
	case "net":
		return "Network"
	case "exec":
		return "Programs"
	}
	return "Files"
}

// agentNames are the coding agents agentFolders knows.
var agentNames = []string{"claude", "codex"}

// agentFolders are where coding agents keep their own files, as a path segment. A config folder steers the agent at
// its next start, so a change there is no routine write (and the files in it that name what runs are laterFiles); a
// state folder holds only what it writes for itself. ~/.local/share/claude is not one: it holds the Claude Code
// executable that runs next.
// shortcut: known names for Claude Code and Codex only, not the run's CLAUDE_CONFIG_DIR or CODEX_HOME; read those
// from the run's environment when run_start records it.
var agentFolders = []struct {
	agent, dir string
	state      bool
}{
	{"claude", "/.claude/", false}, {"claude", "/.claude.json/", false}, {"claude", "/.claude-state/", false},
	{"claude", "/.config/claude/", false}, {"claude", "/.cache/claude", true}, {"claude", "/.local/state/claude/", true},
	{"claude", "/.local/share/claude/", false}, {"codex", "/.codex/", false}, {"codex", "/.cache/codex", true},
}

// agentFolder is the agent whose folder p is in, "" for none, and whether that is a state folder.
func agentFolder(p string) (agent string, state bool) {
	for _, f := range agentFolders {
		if strings.Contains(p+"/", f.dir) {
			return f.agent, f.state
		}
	}
	return "", false
}

// AgentOwn reports whether p is in the folders of agent (CommandAgent); another agent's folder is not its own.
func AgentOwn(agent, p string) bool {
	owner, _ := agentFolder(p)
	return owner != "" && owner == agent
}

// CommandAgent says which coding agent a command starts (agentNames), "" for any other: its program, past env's
// assignments and flags and past the runtime that starts it.
func CommandAgent(command string) string {
	for _, w := range strings.Fields(command) {
		switch path.Base(w) {
		case "env", "node", "npx", "bun":
			continue
		}
		if strings.Contains(w, "=") || strings.HasPrefix(w, "-") {
			continue
		}
		for _, a := range agentNames {
			if strings.Contains(w, a) {
				return a
			}
		}
		return ""
	}
	return ""
}

// writeReasons are the refusals that say a file would change, for a refused line no action line stands beside.
var writeReasons = map[string]bool{string(record.ReasonWriteOutsideContract): true, string(record.ReasonDeleteOutsideContract): true,
	string(record.ReasonRenameOutsideContract): true, string(record.ReasonMkdirOutsideContract): true}

// writesFile reports whether a refused line would have changed a file.
func writesFile(e *Event) bool {
	if e.Kind == string(record.KindFS) {
		return e.Op != "read"
	}
	return e.write || writeReasons[e.Reason]
}

// reachOut are programs whose job is to reach another machine: refused, they are the attempt itself.
var reachOut = map[string]bool{"ssh": true, "scp": true, "sftp": true, "curl": true, "wget": true, "nc": true,
	"ncat": true, "netcat": true, "socat": true, "telnet": true, "ftp": true, "rsync": true}

// startupFiles are files that run code later, outside the agent: shell startup files and git hooks.
var startupFiles = []string{"/.bashrc", "/.bash_profile", "/.profile", "/.zshrc", "/.zprofile", "/.zshenv",
	"/.config/autostart/", "/.git/hooks/"}

func startupFile(p string) bool {
	for _, s := range startupFiles {
		if strings.Contains(p+"/", s) {
			return true
		}
	}
	return false
}

// laterFiles are the rest of what a write can turn into code that runs later, outside the run: what the engine's
// built-in deny_write set holds for that reason (agent.BuiltInDenyWriteNames: harness and editor settings, a shell's
// other startup files, git's config; and the hooks folders a core.hooksPath most often names), and an agent's own
// hooks and commands. Each is whole path segments, so settings.json elsewhere is not one, and an agent's name in a
// path does not make it one. An agent's caches and state are not: it writes those itself on every run, and a plugin
// folder keeps its caches beside its hooks, so of a folder the set holds whole (.claude, .vscode) only the files that
// name what runs are here. A name the set gains that this list and startupFiles leave out fails
// TestLaterFilesHoldTheEngineSet.
var laterFiles = []string{
	"/.claude/settings.json/", "/.claude/settings.local.json/", "/.claude.json/", "/.mcp.json/",
	"/.config/claude/settings.json/", "/.config/claude/settings.local.json/",
	"/.claude-state/settings.json/", "/.claude-state/settings.local.json/",
	"/.claude/hooks/", "/.claude/commands/", "/.claude/agents/", "/.claude/skills/",
	"/.codex/config.toml/", "/.codex/hooks.json/", "/.codex/hooks/", "/.codex/rules/", "/.codex/skills/",
	"/.cursor/mcp.json/", "/.cursor/hooks.json/", "/.cursor/hooks/",
	"/.gemini/settings.json/", "/.gemini/commands/", "/.gemini/extensions/",
	"/.vscode/settings.json/", "/.vscode/tasks.json/", "/.vscode/launch.json/", "/.vscode/mcp.json/",
	"/.bash_login/", "/.zlogin/", "/.config/fish/config.fish/",
	"/.gitconfig/", "/.config/git/config/", "/.git/config/", "/.git/config.worktree/", "/.husky/", "/.githooks/",
}

// RunsLater reports whether a change to the file target names would run code later, outside the run: target as a
// line holds it, a path relative or absolute, or a rename's two. Severity reads this for a refused write only, since
// reading such a file runs nothing.
func RunsLater(target string) bool {
	for _, p := range paths(target) {
		p = "/" + path.Clean(p) + "/"
		for _, s := range laterFiles {
			if strings.Contains(p, s) {
				return true
			}
		}
		if startupFile(p) {
			return true
		}
	}
	return false
}

// SevRule is a person's own severity rule (the dashboard's Severity page): a blocked action in Channel ("" for any)
// whose subject (path, program or host) or rule contains Match gets Severity, in place of the built-in rules. Routine
// stays routine, and a secret touch is never lowered (groupSeverity, secretSeverity). The rules come with a run's
// Sensitive, first match first.
type SevRule struct {
	Channel, Match string
	Severity       Severity
}

// ParseSeverity reads "High", "Medium" or "Low" (any case); false for anything else.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return SevHigh, true
	case "medium":
		return SevMedium, true
	case "low":
		return SevLow, true
	}
	return SevRoutine, false
}

// ownSeverity is the first of rules that matches an action in channel on subject or under rule.
func ownSeverity(rules []SevRule, channel, subject, rule string) (Severity, bool) {
	for _, r := range rules {
		if (r.Channel == "" || r.Channel == channel) && r.Match != "" && (strings.Contains(subject, r.Match) || strings.Contains(rule, r.Match)) {
			return r.Severity, true
		}
	}
	return 0, false
}

// groupSeverity is a refusal group's severity (classify must have run): the person's rules over the built-in ones,
// except that routine stays routine and a secret touch, or a send next to one, is never lowered.
func groupSeverity(g *Group, agent string, rules []SevRule) Severity {
	if g.Background {
		return SevRoutine
	}
	v := builtinSeverity(g, agent)
	if own, ok := ownSeverity(rules, Channel(g.Class), g.Subject, g.Rule); ok && (own > v || !(g.Secret || g.NearSecret)) {
		return own
	}
	return v
}

// builtinSeverity is a refusal group's severity by place and operation; agent is the run's (CommandAgent).
func builtinSeverity(g *Group, agent string) Severity {
	switch {
	case g.Secret || g.NearSecret:
		return SevHigh
	case g.Class == "net" && (g.Subject == "netlink" || strings.HasPrefix(g.Subject, "family(")):
		return SevLow // a netlink or other non-IP socket: the system's own network information
	case g.Class == "net":
		return SevHigh
	case g.Class == "exec" && reachOut[path.Base(g.Subject)]:
		return SevHigh
	case g.Class == "fs" && startupFile(g.Subject):
		return SevHigh
	case g.Class == "fs" && g.Write && (g.to != "" || RunsLater(g.Subject)):
		return SevHigh // any agent's, its own too: a hook in its settings runs as a line in .bashrc does
	case g.Class == "fs":
		if owner, state := agentFolder(g.Subject); owner != "" && owner == agent && (!g.Write || state) {
			return SevLow // reading its own files, or writing its own caches
		}
	}
	return SevMedium
}

// secretSeverity is a secret touch's severity: the run's agent's own login and settings are Low unless a send
// followed. A person's rule can raise it, never lower it.
func secretSeverity(st *SecretTouch, agent string, rules []SevRule) Severity {
	v := SevHigh
	if AgentOwn(agent, st.Path) && !st.NearSend {
		v = SevLow
	}
	if own, ok := ownSeverity(rules, "Files", st.Path, st.Rule); ok && own > v {
		return own
	}
	return v
}
