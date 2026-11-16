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
		install: "mkdir -p ~/.local/bin && curl -fsSL https://github.com/openai/codex/releases/latest/download/codex-$(uname -m)-unknown-linux-musl.tar.gz | tar -xzO > ~/.local/bin/codex && chmod 0755 ~/.local/bin/codex"},
	{label: "Another program"},
}

// guideLookPath finds a program; a variable so a test can say what is installed.
var guideLookPath = exec.LookPath

// guideInstall runs an agent's install line with its output in log; a variable so a test installs nothing.
var guideInstall = func(ctx context.Context, line string, log io.Writer) error {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", line)
	c.Stdout, c.Stderr = log, log
	return c.Run()
}

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

// replace turns the last n lines (a step's status, its question and progress) into one ✓ line on a terminal, and adds
// the ✓ line below them elsewhere.
func (g *walk) replace(n int, s string) {
	if g.green != "" {
		fmt.Fprintf(g.out, "\033[%dA\r\033[J", n)
	}
	g.ok(s)
}

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
		if a.install == "" {
			g.note("Install it, then run tego setup again.")
			return identity.ExitFinding
		}
		install, err := g.yes("Install it now?")
		if err != nil {
			return identity.ExitError
		}
		if !install {
			g.note("Install it, then run tego setup again:")
			g.cmd(a.install)
			return identity.ExitFinding
		}
		g.note("Installing...")
		if !g.installAgent(ctx, a, m.Home) {
			return identity.ExitFinding
		}
		// The installers put the program in ~/.local/bin, which this shell's PATH may not have yet.
		_ = os.Setenv("PATH", filepath.Join(m.Home, ".local", "bin")+":"+os.Getenv("PATH"))
		if _, err := guideLookPath(program); err != nil {
			g.bad(a.label + " was installed, but tego can't find " + program + " on your PATH")
			return identity.ExitFinding
		}
		g.replace(3, a.label+" installed")
	} else {
		g.ok(a.labelOr(program) + " is installed")
	}

	// Your first project: the folder tego setup was started in when it is a project, else a sample made for trying
	// Tego, with a fake secret for the first run to be refused. No question either way.
	g.title("Your first project")
	home := m.Home
	abs := ""
	if wd, err := os.Getwd(); err == nil && wd != home && wd != "/" && !strings.HasPrefix(home, wd+"/") && unixWritable(wd) {
		abs = wd
		g.ok("Using this folder: " + tildeHome(abs, home))
	} else {
		abs = filepath.Join(home, guideSample)
		if err := makeSample(abs); err != nil {
			g.bad("Couldn't make the sample project: " + err.Error())
			return identity.ExitError
		}
		g.ok("Sample project ready to try Tego on: " + tildeHome(abs, home))
		g.note("It has a fake .env secret, so you can watch Tego keep it from your agent.")
	}

	// Its rules: the person picks which of the shipped presets apply, all on to start.
	g.title("Its rules")
	rules := []guideRule{
		{preset: "no-secrets", on: true, label: "Keep secrets away", detail: "~/.ssh, ~/.aws, .env files and other secrets"},
		{preset: "no-prod", on: true, label: "Reach only the hosts named", detail: "its model's API and nothing else"},
		{preset: "repo-only-writes", on: true, label: "Change only this project", detail: "nothing outside " + tildeHome(abs, home)},
	}
	if err := g.pickRules(rules); err != nil {
		return identity.ExitError
	}
	name := agentNameFor(abs)
	path, code := guideSaveRules(ctx, m, a, command, name, abs, rules, stderr)
	if code != identity.ExitOK {
		return code
	}
	g.ok("Rules written to " + tildeHome(path, home))
	if rules[2].on {
		g.note("may change    " + tildeHome(abs, home))
	} else {
		g.note("may change    any file you can")
	}
	if rules[0].on {
		g.note("never reads   ~/.ssh, ~/.aws, .env files and other secrets")
	} else {
		g.note("may read      your secret files too")
	}
	switch {
	case !rules[1].on:
		g.note("may connect   anywhere")
	case a.host != "":
		g.note("may connect   " + a.host)
	default:
		g.note("may connect   nowhere yet (add hosts to the rules file)")
	}

	g.title("Run it")
	g.cmd("cd " + tildeHome(abs, home) + " && tego run " + name)
	if abs == filepath.Join(home, guideSample) {
		g.note("For one of your own projects, run tego setup from inside it.")
	}
	if a.harness == "claude-code" && os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		g.note("Claude Code needs a login under Tego: run claude setup-token, then")
		g.note("export CLAUDE_CODE_OAUTH_TOKEN=<the token> before tego run.")
	}
	g.line("")
	return identity.ExitOK
}

// installAgent runs a's install line with its output in ~/.tego/setup-install.log; on failure it shows the log's last
// lines and where the whole log is.
func (g *walk) installAgent(ctx context.Context, a guideAgent, home string) bool {
	logPath := filepath.Join(home, ".tego", "setup-install.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o700)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		g.bad("Couldn't open the install log: " + err.Error())
		return false
	}
	defer func() { _ = f.Close() }()
	if err := guideInstall(ctx, a.install, f); err != nil {
		g.bad(a.label + " didn't install: " + err.Error())
		if b, err := os.ReadFile(logPath); err == nil {
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) > 5 {
				lines = lines[len(lines)-5:]
			}
			for _, l := range lines {
				g.note(l)
			}
		}
		g.note("The full log is in " + tildeHome(logPath, home))
		return false
	}
	return true
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
func guideSaveRules(ctx context.Context, m *config.Machine, a guideAgent, command, name, abs string, rules []guideRule, stderr io.Writer) (string, int) {
	dir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		message(stderr, abs, 0, 0, "tego setup: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	var on []string
	for _, r := range rules {
		if r.on {
			on = append(on, r.preset)
		}
	}
	po := setup.Options{Presets: []string{strings.Join(on, ",")}, Writes: []string{dir + "/"},
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

// tildeHome shows a path under home with ~.
func tildeHome(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// guideRule is one preset as the guide offers it: on or off, in plain words.
type guideRule struct {
	preset, label, detail string
	on                    bool
}

// pickRules shows the rules with their switches; a number turns one on or off, an empty answer keeps them. At least
// one stays on.
func (g *walk) pickRules(rules []guideRule) error {
	for {
		for i, r := range rules {
			mark := " "
			if r.on {
				mark = "x"
			}
			g.line("    %d. [%s] %-28s %s%s%s", i+1, mark, r.label, g.dim, r.detail, g.offEsc)
		}
		fmt.Fprintf(g.out, "    Type a number to switch it, or press Enter to keep these: ")
		a, err := g.read()
		if err != nil {
			return err
		}
		if a == "" {
			return nil
		}
		n, err := strconv.Atoi(a)
		if err != nil || n < 1 || n > len(rules) {
			g.note(fmt.Sprintf("Type a number from 1 to %d, or press Enter.", len(rules)))
			continue
		}
		rules[n-1].on = !rules[n-1].on
		some := false
		for _, r := range rules {
			some = some || r.on
		}
		if !some {
			rules[n-1].on = true
			g.note("Keep at least one rule on.")
		}
	}
}

// guideSample is the sample project's folder, under home.
const guideSample = "tego-sample"

// sampleFiles are the sample project's files. The .env is fake: it is there for the first run to show Tego keeping a
// secret file from the agent.
var sampleFiles = map[string]string{
	"README.md": "# Tego sample project\n\nA small project to try Tego on. Ask your agent to read `.env`: Tego refuses, and\n`tego receipt --last` shows the refusal.\n",
	"hello.py":  "print(\"Hello from the Tego sample project\")\n",
	".env":      "# Not a real secret. It is here so you can watch Tego keep it from your agent.\nSAMPLE_API_KEY=not-a-real-key\n",
}

// makeSample creates the sample project at dir, or fills in what is missing; it never replaces a file.
func makeSample(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, text := range sampleFiles {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		_, werr := f.WriteString(text)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	return nil
}

// accessW is access(2) for writing, as this user.
func accessW(dir string) error { return unix.Access(dir, unix.W_OK) }
