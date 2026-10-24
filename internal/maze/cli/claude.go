// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
)

// Translation is what Maze makes of one of Claude Code's permission rules. A name-based rule such as
// Bash(git push*) is easy to get around (an alias, git -c, a script, a library), so it is mapped to the effect it
// protects, and that effect is what Maze enforces.
type Translation struct {
	scan.ClaudeRule
	// Covered is true when a Maze rule enforces the same effect, or a stricter one.
	Covered bool `json:"covered"`
	// How names the Maze rule that covers it ("can't push to GitHub as you"), or why it stays with Claude Code.
	How string `json:"how"`
	// Wider is true when the Maze rule allows more than the Claude Code rule did: Bash(npm run *) became "can run
	// npm", since Maze allows whole programs.
	Wider bool `json:"wider,omitempty"`
}

// Claude Code keeps applying its own rules under Maze; Maze enforces what it can underneath. A rule Maze doesn't
// cover still holds in Claude Code.
const stillClaude = "Claude Code still applies it; Maze doesn't: "

// publishers are commands that push or publish with the person's login, and the Maze rule that covers them.
var publishers = map[string]string{
	"npm publish":    "can't publish to npm as you",
	"yarn publish":   "can't publish to npm as you",
	"pnpm publish":   "can't publish to npm as you",
	"bun publish":    "can't publish to npm as you",
	"twine upload":   "can't publish to PyPI as you",
	"poetry publish": "can't publish to PyPI as you",
	"uv publish":     "can't publish to PyPI as you",
	"git push":       "can't push to GitHub as you",
}

// riskyPrograms reach the network or root on their own: an allow for one is listed, never added for the person.
var riskyPrograms = map[string]bool{
	"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true, "rsync": true, "nc": true, "ncat": true,
	"netcat": true, "telnet": true, "ftp": true, "sudo": true, "su": true, "doas": true, "socat": true,
}

// shellWords are shell builtins a Bash rule may start with: not programs Maze could allow or block.
var shellWords = map[string]bool{"export": true, "cd": true, "echo": true, "source": true, ".": true, "set": true,
	"unset": true, "alias": true, "eval": true, "exec": true, "if": true, "for": true, "while": true, "true": true, "false": true}

// secretInRule finds what looks like a secret value in a rule, each with what to keep before it: a password in a
// URL, NAME=VALUE, curl -u user:pass, mysql -pPASSWORD, an Authorization or API-key header, a Bearer or token
// word, a JWT, the key shapes of common services, and any long random string (an AWS secret, a hex key).
var secretInRule = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(://[^/\s:@]+:)[^@\s/]+@`), "${1}•••@"},
	{regexp.MustCompile(`(?i)((?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic|token|digest)?\s*)[^\s)'"]+`), "${1}•••"},
	{regexp.MustCompile(`(?i)((?:x-api-key|api-key|apikey|x-auth-token|private-token|x-access-token|cookie)\s*[:=]\s*)[^\s)'"]+`), "${1}•••"},
	{regexp.MustCompile(`(?i)(\b(?:bearer|token)\s+)[^\s)'"]+`), "${1}•••"},
	{regexp.MustCompile(`((?:^|\s)(?:-u|--user)(?:\s+|=)[^\s:]+:)[^\s)'"]+`), "${1}•••"},
	{regexp.MustCompile(`((?:^|\s)(?:-p|--password=))[^\s)'"-][^\s)'"]*`), "${1}•••"},
	{regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*=)("[^"]*"|'[^']*'|[^\s)'"]+)`), "${1}•••"},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`), "•••"},
	{regexp.MustCompile(`(sk-|sk_live_|sk_test_|ghp_|gho_|ghs_|ghu_|github_pat_|xox[abposr]-|AKIA|ASIA|glpat-|npm_|pypi-)[A-Za-z0-9_\-]{4,}`), "•••"},
	{regexp.MustCompile(`\b[A-Za-z0-9+/_-]{32,}={0,2}\b`), "•••"},
}

// maskSecrets hides secret-looking values in a rule before it is shown or saved anywhere: Claude Code saves whole
// commands, with the tokens typed into them, when someone picks "always allow". It masks by structure first (the
// value after a flag or setting named like a secret, whatever the value looks like: maskByName), then by the
// value shapes of secretInRule.
func maskSecrets(rule string) string {
	rule = maskByName(rule)
	for _, m := range secretInRule {
		rule = m.re.ReplaceAllString(rule, m.with)
	}
	return rule
}

// translation holds what translateClaude found besides the per-rule lines: rules to add, and suggested programs
// and websites a deny in Claude Code's settings turns off.
type translation struct {
	add          []Rule
	blockProgram map[string]string // program → the settings file that denies it
	blockHost    map[string]string
	lines        []Translation
}

// translateClaude maps Claude Code's rules onto the review's rules, the way Claude Code itself reads them: a
// deny wins over an allow anywhere. Only the project's shared .claude/settings.json adds rules to the project
// (its rules are committed with it); the person's own files (settings.local.json, ~/.claude/settings.json) are
// listed, never copied into the file the team shares. Nothing is dropped silently: every rule gets a line.
func translateClaude(r Report, rules []Rule) translation {
	tr := translation{blockProgram: map[string]string{}, blockHost: map[string]string{}}
	programs, hosts := map[string]bool{}, map[string]bool{}
	for _, rl := range rules {
		if !rl.Allow {
			continue
		}
		for _, p := range rl.Programs {
			programs[p] = true
		}
		for _, h := range rl.Hosts {
			hosts[h] = true
		}
	}
	// Whole-program and whole-website denies, from any file: they beat any allow.
	deniedProgram, deniedHost := map[string]bool{}, map[string]bool{}
	for _, cr := range r.Claude {
		if cr.List != "deny" {
			continue
		}
		switch cr.Tool() {
		case "Bash":
			if cmd, sub := command(cr.Spec()); cmd != "" && sub == "" {
				deniedProgram[cmd] = true
			}
		case "WebFetch":
			if host, ok := strings.CutPrefix(cr.Spec(), "domain:"); ok {
				deniedHost[strings.ToLower(host)] = true
			}
		}
	}
	name := r.Workspace.Name
	shared := func(cr scan.ClaudeRule) bool { return cr.Source == ".claude/settings.json" }
	imported := func(rl Rule, cr scan.ClaudeRule) Rule {
		rl.Why, rl.Added, rl.Suggested = "from "+cr.Source, false, rl.Allow
		return rl
	}
	for _, cr := range r.Claude {
		t := Translation{ClaudeRule: cr}
		t.Rule = maskSecrets(cr.Rule)
		stillClaude := stillClaude
		if cr.Source == "~/.claude/settings.json" {
			// Under maze run Claude Code keeps its settings in the project (.maze/state), so the person's own
			// ~/.claude rules don't reach it there yet.
			stillClaude = "Not applied under maze run yet (Claude Code gets its own settings folder there), and Maze doesn't: "
		}
		spec := cr.Spec()
		switch tool := cr.Tool(); {
		case cr.List == "ask":
			t.How = stillClaude + "it has no ask-each-time rules yet"
		case tool == "Bash":
			cmd, sub := command(spec)
			switch {
			case cmd == "":
				t.How = stillClaude + "it names no program"
			case shellWords[cmd]:
				t.How = stillClaude + cmd + " is a shell command, not a program"
			case cr.List == "deny" && publishers[cmd+" "+sub] != "":
				t.Covered, t.How = true, publishers[cmd+" "+sub]
			case cr.List == "deny" && sub == "" && programs[cmd] && !shared(cr):
				t.How = stillClaude + cr.Source + " is yours alone, so Maze keeps it out of the shared rules"
			case cr.List == "deny" && sub == "" && programs[cmd]:
				tr.blockProgram[cmd] = cr.Source
				t.Covered, t.How = true, "can't run "+cmd+" (Maze follows this deny)"
			case cr.List == "deny" && !programs[cmd]:
				t.Covered, t.How = true, "can't run any other program"
			case cr.List == "deny":
				t.How = stillClaude + "it allows " + cmd + " as a whole and can't block one way of using it"
			case deniedProgram[cmd]:
				t.How = "not added: a deny for " + cmd + " wins"
			case programs[cmd] && sub != "":
				t.Covered, t.Wider, t.How = true, true, "can run all of "+cmd+" (wider than "+cmd+" "+sub+": Maze allows whole programs)"
			case programs[cmd]:
				t.Covered, t.How = true, "can run "+cmd
			case isNeverAllowed(r, cmd):
				t.How = "never allowed under Maze: it could change the rules Claude Code runs under"
			case scope.ProgramProblem(cmd) != "":
				t.How = "not added: " + strings.TrimSuffix(scope.ProgramProblem(cmd), ".")
			case sub != "":
				t.How = "not added: this allows only " + cmd + " " + sub + ", and Maze allows whole programs. For all of " + cmd + ": maze allow program " + cmd
			case riskyPrograms[strings.ToLower(cmd)]:
				t.How = "not added: " + cmd + " reaches the network or root. If you mean it: maze allow program " + cmd
			case !shared(cr):
				t.How = "not added: " + cr.Source + " is yours alone, and the project's rules are shared. If you mean it: maze allow program " + cmd
			case strings.Contains(cmd, "/") || strings.HasPrefix(cmd, "."):
				t.How = stillClaude + "it allows programs by name; run project scripts through bash"
			case r.env.LookPath(cmd) == "":
				t.How = "not added: " + cmd + " isn't installed"
			default:
				rl, note := addProgram(r, cmd)
				if note != "" {
					t.How = "not added: " + note
					break
				}
				tr.add = append(tr.add, imported(rl, cr))
				programs[cmd] = true
				t.Covered, t.How = true, "added: can run "+cmd
			}
		case tool == "WebFetch":
			host, ok := strings.CutPrefix(spec, "domain:")
			host = strings.ToLower(host)
			switch {
			case !ok || host == "" || strings.Contains(host, "*"):
				t.How = stillClaude + "it allows websites by exact name"
			case cr.List == "deny" && hosts[host] && !shared(cr):
				t.How = stillClaude + cr.Source + " is yours alone, so Maze keeps it out of the shared rules"
			case cr.List == "deny" && hosts[host]:
				tr.blockHost[host] = cr.Source
				t.Covered, t.How = true, "can't connect to "+host+" (Maze follows this deny)"
			case cr.List == "deny":
				t.Covered, t.How = true, "can't connect to any other website"
			case deniedHost[host]:
				t.How = "not added: a deny for " + host + " wins"
			case hosts[host]:
				t.Covered, t.How = true, "can connect to "+host
			case !shared(cr):
				t.How = "not added: " + cr.Source + " is yours alone. If you mean it: maze allow website " + host
			default:
				rl, note := addWebsite(host)
				if note != "" {
					t.How = "not added: " + note
					break
				}
				tr.add = append(tr.add, imported(rl, cr))
				hosts[rl.Value] = true
				t.Covered, t.How = true, "added: can connect to "+rl.Value
			}
		case tool == "Read" || tool == "Edit" || tool == "Write" || tool == "MultiEdit":
			t.Covered, t.How = translatePath(r, cr, spec, &tr, name, imported, shared(cr))
		case tool == "WebSearch":
			t.How = stillClaude + "search runs on Anthropic's servers, not on this computer"
		case strings.HasPrefix(tool, "mcp__"):
			t.How = stillClaude + "MCP tools aren't covered yet"
		default:
			t.How = stillClaude + "it doesn't see " + tool
		}
		tr.lines = append(tr.lines, t)
	}
	return tr
}

// translatePath maps a file rule. Reads of .env files and the key folders are blocked already; a deny for one
// existing file in the project, from the shared settings, becomes a block. Changes outside the project are
// blocked already; changes to one path inside it stay with Claude Code.
func translatePath(r Report, cr scan.ClaudeRule, spec string, tr *translation, name string,
	imported func(Rule, scan.ClaudeRule) Rule, shared bool) (bool, string) {
	stillClaude := stillClaude
	if cr.Source == "~/.claude/settings.json" {
		stillClaude = "Not applied under maze run yet (Claude Code gets its own settings folder there), and Maze doesn't: "
	}
	glob := strings.ContainsAny(spec, "*?[")
	// "//abs" is Claude Code's absolute path, "~/x" the home folder; a trailing /** names the folder.
	path := strings.TrimSuffix(strings.TrimSuffix(spec, "/**"), "/*")
	switch {
	case strings.HasPrefix(path, "//"):
		path = path[1:]
	case strings.HasPrefix(path, "~/") || path == "~":
		path = expandHome(r.Home, path)
	default:
		path = filepath.Join(r.Workspace.Root, strings.TrimPrefix(path, "./"))
	}
	abs := filepath.Clean(path)
	rel, err := filepath.Rel(r.Workspace.Root, abs)
	inside := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	read := cr.Tool() == "Read"
	key, isKey := scan.KeyFolder(r.Home, abs)
	switch {
	case read && cr.List == "allow" && isKey:
		return true, "Maze is stricter: " + key + " stays blocked"
	case read && cr.List == "allow" && inside:
		return true, "can read files in " + name
	case read && cr.List == "allow":
		return true, "Maze doesn't block reading it either: outside " + name + " it blocks only your key folders"
	case cr.List == "allow" && inside:
		return true, "can change files in " + name
	case cr.List == "allow":
		return true, "Maze is stricter: Claude Code can't change files outside " + name
	case read && strings.Contains(filepath.Base(spec), ".env"):
		return true, "can't read .env files"
	case read && isKey:
		return true, "can't read " + key
	case !read && !inside:
		return true, "can't change files outside " + name
	case !read:
		return false, stillClaude + "blocking changes to one path inside " + name + " needs an engine update"
	case !inside:
		return false, stillClaude + "outside " + name + " it blocks only your key folders"
	case glob:
		return false, stillClaude + "it blocks files one by one, not by pattern"
	case !shared:
		return false, stillClaude + cr.Source + " is yours alone; to block it for everyone: maze block file " + filepath.ToSlash(rel)
	}
	rl, note := addFile(r, r.Workspace.Root, rel)
	if note != "" {
		return false, stillClaude + strings.TrimSuffix(strings.ToLower(note[:1])+note[1:], ".")
	}
	tr.add = append(tr.add, imported(rl, cr))
	return true, "added: can't read " + rl.Value
}

// command is the program a Bash rule names and its first argument: "git push*" is git and push, "npm run:*"
// is npm and run. Leading NAME=value settings and an "env" prefix are skipped, as a shell would.
func command(spec string) (cmd, sub string) {
	spec = strings.NewReplacer(":*", " ", "*", " ").Replace(spec)
	words := strings.Fields(spec)
	for len(words) > 0 && ((strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "=")) || words[0] == "env") {
		words = words[1:]
	}
	if len(words) == 0 {
		return "", ""
	}
	cmd = filepath.Base(words[0])
	if strings.HasPrefix(words[0], "./") || strings.HasPrefix(words[0], "../") {
		cmd = words[0]
	}
	if len(words) > 1 {
		sub = words[1]
	}
	return cmd, sub
}

// secretNames are the parts of a flag's or setting's name that say its value is a secret.
var secretNames = []string{"pass", "secret", "token", "credential", "creds", "apikey", "api-key", "api_key",
	"access-key", "access_key", "private-key", "private_key", "auth"}

// loginCommands take a password as "-p VALUE", where -p means something else to most programs (mkdir -p).
var loginCommands = map[string]bool{"mysql": true, "mysqladmin": true, "mysqldump": true, "mariadb": true,
	"mariadb-dump": true, "sshpass": true, "login": true}

// secretName reports whether name (a flag without its dashes, or a word such as aws_secret_access_key) names
// a secret. "author" (git commit --author) is not one, nor is a key's file or path (--key-file names a file).
func secretName(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "author") || strings.HasSuffix(n, "-file") || strings.HasSuffix(n, "_file") ||
		strings.HasSuffix(n, "-path") || strings.HasSuffix(n, "_path") {
		return false
	}
	if n == "key" || strings.HasSuffix(n, "-key") || strings.HasSuffix(n, "_key") {
		return true
	}
	for _, part := range secretNames {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

// ruleWord is one space-separated word of a rule.
var ruleWord = regexp.MustCompile(`\S+`)

// maskByName masks the value after a word that names a secret: --password VALUE, --api-key=VALUE, --secret
// VALUE, aws configure set aws_secret_access_key VALUE, and -p VALUE after a login command (docker login, mysql).
// A quoted value is masked to its closing quote; the rule's closing parenthesis and a trailing * are kept.
func maskByName(rule string) string {
	words := ruleWord.FindAllStringIndex(rule, -1)
	type span struct{ from, to int }
	var masks []span
	login := false
	for i := 0; i < len(words); i++ {
		w := rule[words[i][0]:words[i][1]]
		if j := strings.IndexByte(w, '('); i == 0 && j >= 0 {
			w = w[j+1:] // Bash(docker: the command is after the tool's name
		}
		if loginCommands[strings.Trim(w, `"'`)] {
			login = true
		}
		name, value, hasValue := strings.Cut(w, "=")
		flag := strings.HasPrefix(name, "-")
		bare := strings.TrimLeft(name, "-")
		secret := (flag && secretName(bare)) || (flag && bare == "p" && login && !hasValue) ||
			(!flag && !hasValue && strings.ContainsAny(bare, "_-") && secretName(bare))
		if !secret {
			continue
		}
		if hasValue {
			if value != "" {
				start := words[i][0] + strings.Index(rule[words[i][0]:words[i][1]], "=") + 1
				masks = append(masks, span{start, valueEnd(rule, start, words[i][1])})
			}
			continue
		}
		if i+1 < len(words) && !strings.HasPrefix(rule[words[i+1][0]:words[i+1][1]], "-") {
			start := words[i+1][0]
			end := valueEnd(rule, start, words[i+1][1])
			for i+1 < len(words) && words[i+1][1] <= end {
				i++
			}
			masks = append(masks, span{start, end})
		}
	}
	for k := len(masks) - 1; k >= 0; k-- {
		m := masks[k]
		if m.to > m.from {
			rule = rule[:m.from] + "•••" + rule[m.to:]
		}
	}
	return rule
}

// valueEnd is where a value starting at from ends: at its closing quote when it opens with one (across words),
// else at the end of its word, less a trailing ")" or "*" (the rule's own syntax).
func valueEnd(rule string, from, wordEnd int) int {
	if q := rule[from]; q == '"' || q == '\'' {
		if j := strings.IndexByte(rule[from+1:], q); j >= 0 {
			return from + 1 + j + 1
		}
		return len(strings.TrimRight(rule, ")"))
	}
	end := wordEnd
	for end > from && (rule[end-1] == ')' || rule[end-1] == '*') {
		end--
	}
	return end
}
