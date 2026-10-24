// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Input is what Compile needs: where the project and the home folder are, the approved rules from both
// scopes, and how to tell whether a program is installed.
type Input struct {
	Root     string
	Home     string
	Name     string
	Rules    []Rule
	LookPath func(name string) string
	// Agent is the agent's signing key; when set and git may run, git commits as the agent and signs.
	Agent *AgentKey
}

// Compiled is the engine contract and its verdict table, and what the person must be told about them.
type Compiled struct {
	Contract []byte
	Verdicts []byte
	// Gaps are rules shown as allowed or blocked that the engine doesn't enforce that way yet, in plain words.
	Gaps []string
	// Checks is how many verdict rows the table holds.
	Checks int
	// Writable is set when the contract lets the agent change the project.
	Writable bool
}

// harnessDir is Claude Code's project settings folder. The engine keeps a writable project's .claude/ out of the
// agent's reach only when it exists (an absent name has no inode to key, pkg/spec/agent/compile_denywrite.go), so
// SaveCompiled makes it: otherwise the agent could create .claude/settings.json, whose hooks run in the person's
// next session.
const harnessDir = ".claude"

// stateDir is where Claude Code keeps its settings and sessions during a run, relative to the project root
const stateDir = StateDir

// agentKeys are the variables Claude Code signs in with.
var agentKeys = []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"}

// engineBlocks reports whether the engine blocks reading path with no rule: a .env file (not .env.example and
// its kind) or something in a key folder. It mirrors the engine's built-in list loosely; scan has the full one.
func engineBlocks(path string) bool {
	base := filepath.Base(path)
	if base == ".env" || (strings.HasPrefix(base, ".env.") && !slices.Contains([]string{".env.example", ".env.sample", ".env.template", ".env.dist"}, base)) {
		return true
	}
	for _, k := range []string{"~/.ssh", "~/.aws", "~/.config/gh", "~/.gnupg", "~/.netrc", "~/.npmrc", "~/.git-credentials", "~/.docker/config.json", "~/.kube/config", "~/.config/gcloud"} {
		if path == k || strings.HasPrefix(path, k+"/") {
			return true
		}
	}
	return false
}

// baseEnv are the variables every run passes; the "see" rules the person left on are added to them.
var baseEnv = []string{"PATH", "HOME", "LANG", "TERM"}

// Compile turns approved rules into the engine contract (spec/agent/v0) and a verdict table with one check per
// rule. It never writes `deny_read: []` (which would switch off the engine's built-in secret list), always
// writes an `env.pass` allowlist, lists only installed programs, never lets the agent run Maze or the engine,
// and uses absolute paths, since the engine resolves relative ones against the contract's own folder.
func Compile(in Input) (Compiled, error) {
	root, err := filepath.Abs(in.Root)
	if err != nil {
		return Compiled{}, err
	}
	if !Printable(root) || !utf8.ValidString(root) {
		// The root is written raw into the contract's comments: a newline there would start a line of YAML.
		return Compiled{}, fmt.Errorf("the project's path %q holds a control character", root)
	}
	var (
		c        Compiled
		writable bool                                                   // the agent may change the project: .env inside it then needs a root tier to stay blocked
		write    = []string{filepath.Join(root, stateDir), "/dev/null"} // the project itself is added first when writable
		denyRead []string
		programs = []string{"bash"} // Claude Code's shell tool runs every command through bash
		hosts    []string
		pass     = append([]string(nil), baseEnv...)
		checks   []check
		readable []string // files the person allowed inside the blocked set: the engine can't open them yet
	)
	for _, r := range in.Rules {
		switch {
		case r.Category == "files" && r.Verb == "write" && strings.HasPrefix(r.Value, "everything in "):
			if r.Allow {
				writable = true
				write = []string{root, "/dev/null"} // the state folder is inside the project
				checks = append(checks, check{"the agent can change files in the project", "fs.write", filepath.Join(root, "maze-check.txt"), "", "allow"})
				// The engine's built-in list keeps these out of reach even in a writable project: code in them
				// runs later as the person, or turns Maze's pre-push check off.
				for _, p := range []string{".git/hooks/pre-push", ".git/config", ".claude/settings.json"} {
					checks = append(checks, check{"the agent can't change " + p, "fs.write", filepath.Join(root, p), "", "refused"})
				}
			} else {
				checks = append(checks, check{"the project is read-only", "fs.write", filepath.Join(root, "maze-check.txt"), "", "refused"})
			}
		case r.Category == "files" && r.Verb == "read" && r.Allow && !strings.HasPrefix(r.Value, "everything in "):
			// Only a file the engine blocks on its own needs the engine update to become readable; any other
			// allowed file simply isn't on the deny list.
			if engineBlocks(r.Value) {
				readable = append(readable, r.Value)
			}
		case r.Category == "files" && r.Verb == "read" && !r.Allow:
			for _, p := range r.Paths {
				abs := absPath(root, in.Home, p, r.Scope)
				if _, err := os.Lstat(abs); err != nil {
					continue // the engine refuses a missing entry; a file that comes later is a new rule
				}
				// A fixed block the engine already covers by name needs no entry; one it doesn't (.ENV.local, a
				// project .npmrc) gets its own, so "can't read" is true for it too.
				if !r.Always || !engineBlocks(p) {
					denyRead = appendOnce(denyRead, abs)
				}
				checks = append(checks, check{"the agent can't read " + p, "fs.read", abs, "", "refused"})
			}
		case r.Category == "programs" && r.Allow:
			for _, p := range r.Programs {
				switch {
				case NeverAllowed[filepath.Base(p)]:
				case in.LookPath != nil && in.LookPath(p) == "":
					c.Gaps = append(c.Gaps, "can run "+p+": not installed, so blocked until it is")
				default:
					programs = appendOnce(programs, p)
				}
			}
		case r.Category == "websites" && r.Allow:
			for _, h := range r.Hosts {
				hosts = appendOnce(hosts, h)
			}
		case r.Category == "logins" && r.Verb == "see" && r.Allow:
			pass = appendOnce(pass, r.Value)
		}
	}
	// The agent signs in with these: they pass unless a rule says otherwise (a Skip setup has no rule for them).
	for _, k := range agentKeys {
		said := false
		for _, r := range in.Rules {
			said = said || (r.Category == "logins" && r.Verb == "see" && r.Value == k)
		}
		if !said {
			pass = appendOnce(pass, k)
		}
	}
	checks = append(checks, check{"the agent can't change files outside the project", "fs.write", filepath.Join(filepath.Dir(root), "maze-check-outside.txt"), "", "refused"})
	for _, p := range programs[1:] {
		checks = append(checks, check{"the agent can run " + p, "exec", "", p, "allow"})
	}
	var net []string
	for _, h := range hosts {
		net = append(net, h+":443")
		checks = append(checks, check{"the agent can reach " + h, "net.connect", h + ":443", "", "allow"})
	}
	checks = append(checks, check{"the agent can't reach other websites", "net.connect", "example.com:443", "", "refused"})
	sort.Strings(denyRead)
	var identity [][2]string
	if in.Agent != nil && slices.Contains(programs, "git") {
		identity = GitIdentityEnv(*in.Agent)
		// git signs by running ssh-keygen with the agent's key; ~/.ssh stays blocked by the built-in list.
		if in.LookPath == nil || in.LookPath("ssh-keygen") != "" {
			programs = appendOnce(programs, "ssh-keygen")
			checks = append(checks, check{"git can sign the agent's commits", "exec", "", "ssh-keygen", "allow"})
		}
	}

	if len(readable) > 0 {
		c.Gaps = append([]string{"can read " + strings.Join(readable, ", ") + ": stays blocked until an engine update"}, c.Gaps...)
	}
	c.Contract = []byte(contractYAML(in.Name, root, write, denyRead, programs, net, pass, identity, writable))
	c.Verdicts = []byte(verdictsYAML(checks))
	c.Checks = len(checks)
	c.Writable = writable
	return c, nil
}

// SaveCompiled writes the contract and its verdicts to ~/.maze/projects/<project id>/ (outside the project, see
// projectsDir) and makes Claude Code's state folder in the project, which the contract lets the agent write,
// and, when the project is writable, its .claude/ settings folder (harnessDir), which the engine then refuses.
func SaveCompiled(home, root string, c Compiled, agent string) (contractPath string, err error) {
	dir := CompiledFolder(home, root)
	if err := realDirs(root, stateDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(root, stateDir), 0o700); err != nil {
		return "", fmt.Errorf("make %s: %w", stateDir, err)
	}
	if c.Writable {
		if err := realDirs(root, harnessDir); err != nil {
			return "", err
		}
		if err := os.Mkdir(filepath.Join(root, harnessDir), 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("make %s: %w", harnessDir, err)
		}
	}
	contractPath = filepath.Join(dir, agent+".yaml")
	if err := writeFile(contractPath, c.Contract, 0o644, 0o700); err != nil {
		return "", err
	}
	return contractPath, writeFile(filepath.Join(dir, agent+".verdicts.yaml"), c.Verdicts, 0o644, 0o700)
}

// absPath resolves a rule's path: ~/… against home, a workspace path against the project root.
func absPath(root, home, p, scope string) string {
	switch {
	case p == "~":
		return home
	case strings.HasPrefix(p, "~/"):
		return filepath.Join(home, p[2:])
	case filepath.IsAbs(p):
		return p
	case scope == "personal":
		return filepath.Join(home, p)
	}
	return filepath.Join(root, p)
}

// check is one verdict row: an action the compiled contract must answer allow or refused.
type check struct {
	name, action, target, argv0, expect string
}

// q quotes s for YAML: a double-quoted scalar with every control character escaped. Go's quoting is valid YAML
// double-quoted syntax: YAML has each of its escapes (\n, \t, \a, \v, \xXX, \uXXXX, \UXXXXXXXX), so a raw
// newline, which YAML would fold into a space and so name another path, never reaches the file.
func q(s string) string {
	return strconv.Quote(s)
}

// list renders strs as a YAML flow sequence of quoted strings.
func list(strs []string) string {
	qs := make([]string, len(strs))
	for i, s := range strs {
		qs[i] = q(s)
	}
	return "[" + strings.Join(qs, ", ") + "]"
}

// contractYAML is the contract, written by hand so every line can say why it is there.
func contractYAML(name, root string, write, denyRead, programs, net, pass []string, identity [][2]string, writable bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by Maze from %s/.maze/workspace.yaml and ~/.maze/personal.yaml. Don't edit: run `maze`.\n", root)
	fmt.Fprintf(&b, "# Start the engine from the project folder (%s), so its built-in .env protection covers it.\n", root)
	fmt.Fprintf(&b, "version: 0\n")
	fmt.Fprintf(&b, "name: %s\n", q(name))
	fmt.Fprintf(&b, "command: [\"claude\"]\n")
	fmt.Fprintf(&b, "models:\n  - { provider: anthropic, host: api.anthropic.com, port: 443 }\n")
	fmt.Fprintf(&b, "capture: forwarder   # Claude Code reaches the model only through the engine's recorder\n")
	fmt.Fprintf(&b, "fs:\n")
	fmt.Fprintf(&b, "  write: %s\n", list(write))
	if len(denyRead) > 0 {
		// Only extra entries: the built-in secret list (~/.ssh, ~/.aws, .env, …) still applies. An empty list here
		// would switch it off, so none is ever written.
		fmt.Fprintf(&b, "  deny_read: %s\n", list(denyRead))
	}
	fmt.Fprintf(&b, "exec:\n  allow: %s\n", list(programs))
	fmt.Fprintf(&b, "net:\n  allow: %s   # everything else is refused; the model is reached through the recorder\n", list(net))
	fmt.Fprintf(&b, "env:\n  pass: %s   # only these reach the agent; every other variable is dropped\n", list(pass))
	fmt.Fprintf(&b, "  set:\n")
	fmt.Fprintf(&b, "    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: \"1\"\n")
	fmt.Fprintf(&b, "    CLAUDE_CONFIG_DIR: %s\n", q(stateDir))
	fmt.Fprintf(&b, "    CLAUDE_CODE_TMPDIR: %s\n", q(stateDir+"/tmp"))
	fmt.Fprintf(&b, "    TMPDIR: %s\n", q(stateDir+"/tmp"))
	if len(identity) > 0 {
		fmt.Fprintf(&b, "    # git commits as the agent and signs with its own key; the person's git config is untouched\n")
		for _, kv := range identity {
			fmt.Fprintf(&b, "    %s: %s\n", kv[0], q(kv[1]))
		}
	}
	fmt.Fprintf(&b, "limits:\n  pids: 512\n  memory: 4GiB\n  wall: 8h\n  repeats: 5\n")
	fmt.Fprintf(&b, "record: full   # every refused read is recorded, so the receipt is complete\n")
	if writable {
		// Landlock (tier 1, no root) can't block a file inside a folder the agent may write, so .env would be
		// readable there. Pinning tier 2 makes the engine refuse to start without it, rather than run unprotected.
		fmt.Fprintf(&b, "tier: cgroup   # needs root: .env inside a writable project can only be blocked from tier 2 up\n")
	} else {
		fmt.Fprintf(&b, "tier: auto\n")
	}
	return b.String()
}

// verdictsYAML is the table `tego compile --test` checks the contract against.
func verdictsYAML(checks []check) string {
	var b strings.Builder
	b.WriteString("# Generated by Maze: one check per rule, run with `tego compile <contract> --test <this file>`.\n")
	b.WriteString("version: 0\ntests:\n")
	for _, c := range checks {
		fmt.Fprintf(&b, "  - name: %s\n    action: %s\n", q(c.name), c.action)
		switch c.action {
		case "exec":
			fmt.Fprintf(&b, "    argv: %s\n", list([]string{c.argv0}))
		case "net.connect":
			fmt.Fprintf(&b, "    host_port: %s\n", q(c.target))
		default:
			fmt.Fprintf(&b, "    path: %s\n", q(c.target))
		}
		fmt.Fprintf(&b, "    expect: %s\n", c.expect)
	}
	return b.String()
}

// appendOnce appends s unless it is already there.
func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
