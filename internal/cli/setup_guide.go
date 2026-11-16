// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// guideAgent is one choice under "Connect your agent".
type guideAgent struct {
	label   string // what the person picks
	harness string // setup.Options.Agent; "" for another program
	command string // the program on PATH
	host    string // the model host its rules let it reach
	install string // how to install it, one line to type
}

var guideAgents = []guideAgent{
	{label: "Claude Code", harness: "claude-code", command: "claude", host: "api.anthropic.com",
		install: "curl -fsSL https://claude.ai/install.sh | bash"},
	{label: "Codex", harness: "codex", command: "codex", host: "api.openai.com",
		install: "npm install -g @openai/codex"},
	{label: "Another program"},
}

// guideLookPath finds a program; a variable so a test can say what is installed.
var guideLookPath = exec.LookPath

// guideInteractive reports whether tego setup talks to a person: both its input and its output are a terminal.
func guideInteractive(stdout io.Writer) bool {
	if o, ok := stdout.(*outputWriter); ok {
		stdout = o.dst
	}
	f, ok := stdout.(*os.File)
	return ok && isTerminalFile(os.Stdin) && isTerminalFile(f)
}

// walk is the terminal a setup guide talks on.
type walk struct {
	in                            *bufio.Reader
	out                           io.Writer
	green, red, dim, bold, offEsc string
}

func newWalk(in io.Reader, out io.Writer, color bool) *walk {
	g := &walk{in: bufio.NewReader(in), out: out}
	if color && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		g.green, g.red, g.dim, g.bold, g.offEsc = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
	}
	return g
}

func (g *walk) line(format string, a ...any) { fmt.Fprintf(g.out, format+"\n", a...) }
func (g *walk) ok(s string)                  { g.line("  %s✓%s %s", g.green, g.offEsc, s) }
func (g *walk) bad(s string)                 { g.line("  %s✗%s %s", g.red, g.offEsc, s) }
func (g *walk) todo(s string)                { g.line("  %s○%s %s", g.dim, g.offEsc, s) }
func (g *walk) note(s string)                { g.line("    %s%s%s", g.dim, s, g.offEsc) }
func (g *walk) cmd(s string)                 { g.line("      %s%s%s", g.bold, s, g.offEsc) }
func (g *walk) title(s string)               { g.line("\n  %s%s%s", g.bold, s, g.offEsc) }

// read reads one answer line; io.EOF reads as an empty answer, so a closed input takes the defaults.
func (g *walk) read() (string, error) {
	s, err := g.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// yes asks a [Y/n] question; an empty answer is yes.
func (g *walk) yes(q string) (bool, error) {
	fmt.Fprintf(g.out, "    %s [Y/n] ", q)
	a, err := g.read()
	return a == "" || strings.HasPrefix(strings.ToLower(a), "y"), err
}

// ask asks for a value, showing the default an empty answer takes.
func (g *walk) ask(q, def string) (string, error) {
	fmt.Fprintf(g.out, "    %s [%s] ", q, def)
	a, err := g.read()
	if a == "" {
		a = def
	}
	return a, err
}

// choose lists numbered options and returns the index picked; an empty answer is the first.
func (g *walk) choose(options []string) (int, error) {
	for i, o := range options {
		g.line("    %d. %s", i+1, o)
	}
	for {
		fmt.Fprintf(g.out, "    Pick one [1] ")
		a, err := g.read()
		if err != nil {
			return 0, err
		}
		if a == "" {
			return 0, nil
		}
		if n, err := strconv.Atoi(a); err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		g.note(fmt.Sprintf("Type a number from 1 to %d.", len(options)))
	}
}

// levelName is a tier as people see it.
func levelName(t backend.Tier) string {
	switch t {
	case backend.TierLandlock:
		return "Basic"
	case backend.TierCgroup:
		return "Plus"
	case backend.TierBPFLSM:
		return "Max"
	}
	return string(t)
}

// runSetupGuide is tego setup in a terminal: it walks a person from a checked machine to their first agent's rules
// file, one step at a time, asking before it changes anything.
func runSetupGuide(ctx context.Context, in io.Reader, stdout, stderr io.Writer, color bool) int {
	g := newWalk(in, stdout, color)
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego setup: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError
	}

	g.line("")
	pa, err := setupProbe(ctx, m)
	switch {
	case err != nil:
		message(stderr, "", 0, 0, "tego setup: "+err.Error(), codeIO)
		return identity.ExitError
	case pa.tier == "" && pa.outside:
		g.bad("Tego can't protect agents started from this shell.")
		if o := scopeOpener(); o.Command != "" {
			g.note("Open a shell where it can, then run tego setup again:")
			g.cmd(o.Command)
		}
		return identity.ExitFinding
	case pa.tier == "":
		g.bad("This computer can't run protected agents yet.")
		if pa.fix != "" {
			g.note(fixText(pa.fix))
		}
		g.note("tego doctor shows the details.")
		return identity.ExitFinding
	}
	g.ok(fmt.Sprintf("This computer can protect your agents (%s level, no admin needed)", levelName(pa.tier)))

	// Connect your agent.
	g.title("Connect your agent")
	labels := make([]string, len(guideAgents))
	for i, a := range guideAgents {
		labels[i] = a.label
	}
	pick, err := g.choose(labels)
	if err != nil {
		return identity.ExitError
	}
	a := guideAgents[pick]
	command := a.command
	if a.harness == "" {
		command, err = g.ask("The command you start it with", "")
		if err != nil {
			return identity.ExitError
		}
		if command == "" {
			g.note("No command given. Run tego setup again when you have one.")
			return identity.ExitUsage
		}
	}
	program := strings.Fields(command)[0]
	if _, err := guideLookPath(program); err != nil {
		g.bad(a.labelOr(program) + " isn't installed here")
		if a.install != "" {
			g.note("Install it, then run tego setup again:")
			g.cmd(a.install)
		}
		return identity.ExitFinding
	}
	g.ok(a.labelOr(program) + " is installed")

	// Your first project.
	g.title("Your first project")
	home := m.Home
	def := "~/my-project"
	if wd, err := os.Getwd(); err == nil && wd != home && unixWritable(wd) {
		def = tildeHome(wd, home)
	}
	var abs string
	for {
		dir, err := g.ask("Which folder should it work in?", def)
		if err != nil {
			return identity.ExitError
		}
		abs = expandHome(dir, home)
		if !filepath.IsAbs(abs) {
			if wd, err := os.Getwd(); err == nil {
				abs = filepath.Join(wd, abs)
			}
		}
		abs = filepath.Clean(abs)
		if abs == home || abs == "/" {
			g.note("Pick a project folder, not your whole home folder.")
			continue
		}
		break
	}
	if fi, err := os.Stat(abs); err != nil {
		create, err := g.yes(tildeHome(abs, home) + " doesn't exist. Create it?")
		if err != nil || !create {
			return identity.ExitUsage
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			g.bad("Couldn't create it: " + err.Error())
			return identity.ExitError
		}
	} else if !fi.IsDir() {
		g.bad(tildeHome(abs, home) + " is a file, not a folder.")
		return identity.ExitUsage
	}
	if !unixWritable(abs) {
		g.bad(tildeHome(abs, home) + " is read-only here. Pick a folder you can write to.")
		return identity.ExitFinding
	}

	// Its rules.
	name := agentNameFor(abs)
	path, code := guideSaveRules(ctx, m, a, command, name, abs, stderr)
	if code != identity.ExitOK {
		return code
	}
	g.ok("Rules written to " + tildeHome(path, home))
	g.note("may change    " + tildeHome(abs, home))
	g.note("never reads   ~/.ssh, ~/.aws, .env files and other secrets")
	if a.host != "" {
		g.note("may connect   " + a.host)
	} else {
		g.note("may connect   nowhere yet (add hosts to the rules file)")
	}

	g.title("Run it")
	g.cmd("cd " + tildeHome(abs, home) + " && tego run " + name)
	if a.harness == "claude-code" && os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		g.note("Claude Code needs a login under Tego: run claude setup-token, then")
		g.note("export CLAUDE_CODE_OAUTH_TOKEN=<the token> before tego run.")
	}
	g.line("")
	return identity.ExitOK
}

func (a guideAgent) labelOr(program string) string {
	if a.harness != "" {
		return a.label
	}
	return program
}

// guideSaveRules composes the agent's rules file the way tego init --agent does, with the whole project writable,
// and saves it in the user registry, outside the project, where tego run <name> finds it. A rules file already saved
// under that name is kept.
func guideSaveRules(ctx context.Context, m *config.Machine, a guideAgent, command, name, abs string, stderr io.Writer) (string, int) {
	dir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		message(stderr, abs, 0, 0, "tego setup: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	po := setup.Options{Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{dir + "/"},
		Agent: a.harness, Name: name, Dir: dir, Home: m.Home}
	if a.harness == "" {
		po.Command = command
	}
	env, code := initCheckEnv(stderr)
	if code != identity.ExitOK {
		return "", code
	}
	composed, err := setup.Compose(po)
	if err != nil {
		message(stderr, "", 0, 0, "tego setup: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	sv := registry.Save{Places: registry.Places{User: m.Registry.Value}, Name: name, Text: composed.Contract,
		Writes: []string{dir}}
	file, err := sv.Path()
	if err != nil {
		message(stderr, "", 0, 0, "tego setup: where to save the rules file: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	if _, err := os.Stat(file); err == nil {
		return file, identity.ExitOK // set up before: kept as it is
	}
	// The rules file lives in the user registry, outside the project, so it is checked as that file, run from the
	// project, once the folders it names exist.
	made, err := setup.Create(composed, dir)
	if err != nil {
		message(stderr, dir, 0, 0, "tego setup: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	if ds, ok := setup.CheckFile(composed.Contract, file, dir, env); !ok {
		setup.Remove(made, dir)
		_ = agent.WriteDiagnostics(stderr, ds)
		return "", identity.ExitFinding
	}
	path, err := sv.Write()
	if err != nil {
		message(stderr, path, 0, 0, "tego setup: saving the rules file: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	return path, identity.ExitOK
}

// unixWritable reports whether this user may create files in dir.
func unixWritable(dir string) bool { return accessW(dir) == nil }

// expandHome turns a leading ~ into home.
func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// tildeHome shows a path under home with ~.
func tildeHome(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// accessW is access(2) for writing, as this user.
func accessW(dir string) error { return unix.Access(dir, unix.W_OK) }
