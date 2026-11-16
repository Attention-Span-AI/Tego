// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Links the guide shows for reading more.
const (
	presetsDocURL = "https://github.com/Attention-Span-AI/Tego/blob/main/docs/user/presets.md"
	sampleURL     = "https://github.com/Attention-Span-AI/Tego/tree/main/internal/setup/sample"
)

// guideLogin is one way an agent signs in: the variable its token goes in, and whether Tego starts the agent's own
// browser sign-in first (claude setup-token).
type guideLogin struct {
	label, envVar string
	setupToken    bool
}

// guideAgent is one answer to "Which agent do you want to supervise?".
type guideAgent struct {
	label   string // what the person picks
	harness string // setup.Options.Agent; "" for another program
	command string // the program on PATH
	host    string // the model host its rules reach
	install string // the line that installs it
	logins  []guideLogin
}

var guideAgents = []guideAgent{
	{label: "Claude Code", harness: "claude-code", command: "claude", host: "Claude's API",
		install: "curl -fsSL https://claude.ai/install.sh | bash",
		logins: []guideLogin{
			{label: "Claude subscription (opens a browser link)", envVar: "CLAUDE_CODE_OAUTH_TOKEN", setupToken: true},
			{label: "Anthropic API key", envVar: "ANTHROPIC_API_KEY"},
		}},
	{label: "Codex", harness: "codex", command: "codex", host: "OpenAI's API",
		install: "mkdir -p ~/.local/bin && curl -fsSL https://github.com/openai/codex/releases/latest/download/codex-$(uname -m)-unknown-linux-musl.tar.gz | tar -xzO > ~/.local/bin/codex && chmod 0755 ~/.local/bin/codex",
		logins:  []guideLogin{{label: "OpenAI API key", envVar: "CODEX_API_KEY"}}},
	{label: "Another program"},
}

// guideLookPath finds a program on PATH; a variable so a test can say what is installed.
var guideLookPath = func(name string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); dir != "" && err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New(name + " is not on PATH")
}

// guideInstall runs an agent's install line with its output in log; a variable so a test installs nothing.
var guideInstall = func(_ context.Context, line string, log io.Writer) error {
	c := proc.Command("/bin/sh", "-c", line)
	c.Stdout, c.Stderr = log, log
	if _, err := proc.Start(c); err != nil {
		return err
	}
	return c.Wait()
}

// guideSetupToken runs the agent's own browser sign-in (claude setup-token) on this terminal; a variable so a test
// signs in nothing.
var guideSetupToken = func(_ context.Context, program string) error {
	c := proc.Command(program, "setup-token")
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if _, err := proc.Start(c); err != nil {
		return err
	}
	return c.Wait()
}

// guideInteractive reports whether tego start talks to a person: both its input and its output are a terminal.
func guideInteractive(stdout io.Writer) bool {
	if o, ok := stdout.(*outputWriter); ok {
		stdout = o.dst
	}
	f, ok := stdout.(*os.File)
	return ok && isTerminalFile(os.Stdin) && isTerminalFile(f)
}

// walk is the terminal the guide talks on: questions through Huh, results as one ✓ or ✗ line.
type walk struct {
	in                            io.Reader
	out                           io.Writer
	accessible                    bool // Huh's plain prompts: no terminal drawing (tests, TERM=dumb)
	green, red, dim, bold, offEsc string
}

// newWalk talks on in and out. tty is a real terminal: colour and Huh's drawn prompts; otherwise plain prompts that read
// one line per answer.
func newWalk(in io.Reader, out io.Writer, tty bool) *walk {
	g := &walk{in: in, out: out, accessible: !tty || os.Getenv("TERM") == "dumb"}
	if g.accessible {
		lr := &lineReader{r: bufio.NewReader(in), fd: -1}
		if f, ok := in.(*os.File); ok && isTerminalFile(f) {
			lr.fd = int(f.Fd())
		}
		g.in = lr
	}
	if tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		g.green, g.red, g.dim, g.bold, g.offEsc = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
	}
	return g
}

func (g *walk) line(format string, a ...any) { fmt.Fprintf(g.out, format+"\n", a...) }
func (g *walk) ok(s string)                  { g.line("%s✓%s %s", g.green, g.offEsc, s) }
func (g *walk) bad(s string)                 { g.line("%s✗%s %s", g.red, g.offEsc, s) }
func (g *walk) note(s string)                { g.line("  %s%s%s", g.dim, s, g.offEsc) }
func (g *walk) cmd(s string)                 { g.line("    %s%s%s", g.bold, s, g.offEsc) }

// ask shows fields as one Huh form; a person who leaves it (Ctrl-C) gets errStopped.
func (g *walk) ask(fields ...huh.Field) error {
	err := huh.NewForm(huh.NewGroup(fields...)).WithInput(g.in).WithOutput(g.out).WithAccessible(g.accessible).
		WithShowHelp(!g.accessible).Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return errStopped
	}
	return err
}

// errStopped is the person leaving the guide.
var errStopped = errors.New("stopped")

// lineReader hands its reader over one line per Read, so each plain prompt, which opens its own scanner, reads only its
// own answer.
type lineReader struct {
	r    *bufio.Reader
	rest []byte
	fd   int // the terminal behind r, or -1
}

// Fd is the terminal behind the reader, which Huh's hidden input reads directly.
func (l *lineReader) Fd() uintptr { return uintptr(l.fd) }

// hiddenEcho is how a pasted token shows: hidden, except on plain input that is not a terminal (a test's answers),
// where nothing can hide it.
func (g *walk) hiddenEcho() huh.EchoMode {
	if lr, ok := g.in.(*lineReader); ok && lr.fd < 0 {
		return huh.EchoModeNormal
	}
	return huh.EchoModePassword
}

func (l *lineReader) Read(p []byte) (int, error) {
	if len(l.rest) == 0 {
		line, err := l.r.ReadBytes('\n')
		if len(line) == 0 {
			return 0, err
		}
		l.rest = line
	}
	n := copy(p, l.rest)
	l.rest = l.rest[n:]
	return n, nil
}

// levelName is a tier as people see it.
func levelName(t backend.Tier) string {
	if n, ok := map[backend.Tier]string{backend.TierLandlock: "Basic", backend.TierCgroup: "Plus", backend.TierBPFLSM: "Max"}[t]; ok {
		return n
	}
	return string(t)
}

// rulesChoice is what "Which rules should <agent> follow?" decided.
type rulesChoice struct {
	label        string
	presets      []string
	writeProject bool // the whole project; otherwise only Tego's own folder in it, .tego/
	hosts        []string
}

// runSetupGuide is tego start: it connects the agent the person wants to supervise, signs it in, picks its project and
// its rules, saves it as an agent, and shows how to start the first session. It asks before it changes anything and
// never starts the agent itself.
func runSetupGuide(ctx context.Context, in io.Reader, stdout, stderr io.Writer, tty bool) int {
	g := newWalk(in, stdout, tty)
	code, err := g.guide(ctx, stderr)
	switch {
	case errors.Is(err, errStopped):
		g.line("")
		g.bad("Stopped. Run tego start to pick up again.")
		return identity.ExitFinding
	case err != nil:
		message(stderr, "", 0, 0, "tego start: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return code
}

func (g *walk) guide(ctx context.Context, stderr io.Writer) (int, error) {
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego start: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError, nil
	}
	home := m.Home
	onMac := os.Getenv("TEGO_ON_MAC") == "1"

	g.line("")
	g.line("%sWelcome to Tego.%s", g.bold, g.offEsc)
	g.line("Tego supervises your AI agent: it blocks what your rules don't allow and records everything it does.")
	g.line("")
	pa, err := setupProbe(ctx, m)
	switch {
	case err != nil:
		return 0, err
	case pa.tier == "" && pa.outside:
		g.bad("Tego can't supervise agents started from this shell.")
		if o := scopeOpener(); o.Command != "" {
			g.note("Open one where it can, then run tego start again:")
			g.cmd(o.Command)
		}
		return identity.ExitFinding, nil
	case pa.tier == "":
		g.bad("This computer can't run supervised agents yet. tego doctor shows why.")
		return identity.ExitFinding, nil
	}

	// The agent.
	pick := 0
	opts := make([]huh.Option[int], len(guideAgents))
	for i, a := range guideAgents {
		opts[i] = huh.NewOption(a.label, i)
	}
	if err := g.ask(huh.NewSelect[int]().Title("Which agent do you want to supervise?").Options(opts...).Value(&pick)); err != nil {
		return 0, err
	}
	a := guideAgents[pick]
	command := a.command
	if a.harness == "" {
		if err := g.ask(huh.NewInput().Title("What command starts it?").Placeholder("python3 bot.py").Value(&command).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return errors.New("type the command, for example python3 bot.py")
				}
				return nil
			})); err != nil {
			return 0, err
		}
		command = strings.TrimSpace(command)
	}
	name := a.label
	program := strings.Fields(command)[0]
	if a.harness == "" {
		name = program
	}
	if code, err := g.installed(ctx, a, name, program, home); code != identity.ExitOK || err != nil {
		return code, err
	}

	// Its sign-in.
	if len(a.logins) > 0 {
		if code, err := g.signIn(ctx, a, home); code != identity.ExitOK || err != nil {
			return code, err
		}
	}

	// Its project.
	abs, test, err := g.project(name, home, onMac)
	if err != nil {
		return 0, err
	}

	// Its rules.
	rc, err := g.rules(name, a)
	if err != nil {
		return 0, err
	}
	agentName := agentNameFor(abs)
	if test {
		agentName = guideSample
	}
	path, code, err := g.saveAgent(ctx, m, a, command, agentName, abs, rc, test, stderr)
	if code != identity.ExitOK || err != nil {
		return code, err
	}
	g.note("Change its rules any time: tego edit agent " + agentName)

	// The first session: the person starts it.
	g.line("")
	g.line("%sDone.%s Start your first supervised session:", g.bold, g.offEsc)
	g.cmd("cd " + tildeHome(abs, home) + " && tego run " + agentName)
	switch {
	case test && a.harness != "":
		g.note(name + " opens with its own approval prompts off, so every block you see comes from Tego.")
		g.note(`Try this: ask ` + name + ` to "run the tests". Tego blocks the secret read and the upload.`)
	case a.harness != "":
		g.note(name + " opens as usual, with Tego supervising it.")
	}
	g.line("")
	g.line("Then:")
	g.line("    %-30s %s", "tego get sessions", "your sessions")
	g.line("    %-30s %s", "tego describe session --last", "what "+name+" did and what Tego blocked")
	g.line("    %-30s %s", "tego dashboard", "the same, in your browser")
	if onMac {
		g.note("Run tego dashboard on your Mac: type exit to get back to it.")
	}
	_ = path
	g.line("")
	return identity.ExitOK, nil
}

// installed makes sure the agent's program is on PATH, offering to install a known agent.
func (g *walk) installed(ctx context.Context, a guideAgent, name, program, home string) (int, error) {
	if _, err := guideLookPath(program); err == nil {
		g.ok(name + " is installed")
		return identity.ExitOK, nil
	}
	g.bad(name + " isn't installed")
	if a.install == "" {
		g.note("Install it, then run tego start again.")
		return identity.ExitFinding, nil
	}
	yes := true
	if err := g.ask(huh.NewConfirm().Title("Install " + name + " now?").Value(&yes)); err != nil {
		return 0, err
	}
	if !yes {
		g.note("Install it with this line, then run tego start again:")
		g.cmd(a.install)
		return identity.ExitFinding, nil
	}
	g.note("Installing " + name + "...")
	if !g.installAgent(ctx, a, home) {
		return identity.ExitFinding, nil
	}
	// The installers put the program in ~/.local/bin, which this shell's PATH may not have yet.
	_ = os.Setenv("PATH", filepath.Join(home, ".local", "bin")+":"+os.Getenv("PATH"))
	if _, err := guideLookPath(program); err != nil {
		g.bad(name + " was installed, but " + program + " isn't on your PATH")
		return identity.ExitFinding, nil
	}
	g.ok(name + " installed")
	return identity.ExitOK, nil
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

// agentEnvRel is where a saved sign-in lives, under home: one VAR='value' line per variable, mode 0600.
const agentEnvRel = ".config/tego/agent.env"

// bashrcLine loads the saved sign-ins in every new shell, so tego run passes them to the agent.
const bashrcLine = `[ -f "$HOME/.config/tego/agent.env" ] && { set -a; . "$HOME/.config/tego/agent.env"; set +a; } # added by tego start`

// signIn makes sure the agent has its sign-in: from this shell, from a saved one, or by asking for it.
func (g *walk) signIn(ctx context.Context, a guideAgent, home string) (int, error) {
	for _, l := range a.logins {
		if os.Getenv(l.envVar) != "" || savedLogin(home, l.envVar) != "" {
			g.ok("Signed in to " + a.label)
			return identity.ExitOK, nil
		}
	}
	login := a.logins[0]
	if len(a.logins) > 1 {
		pick := 0
		opts := make([]huh.Option[int], len(a.logins))
		for i, l := range a.logins {
			opts[i] = huh.NewOption(l.label, i)
		}
		if err := g.ask(huh.NewSelect[int]().Title("How do you sign in to " + a.label + "?").Options(opts...).Value(&pick)); err != nil {
			return 0, err
		}
		login = a.logins[pick]
	}
	title := "Paste your " + login.label
	if login.setupToken {
		g.note(a.label + " prints a link. Open it, sign in, then copy the token it shows.")
		if err := guideSetupToken(ctx, a.command); err != nil {
			g.bad(a.label + "'s sign-in didn't finish: " + err.Error())
			g.note("Run tego start again to try again.")
			return identity.ExitFinding, nil
		}
		title = "Paste the token"
	}
	token := ""
	save := true
	if err := g.ask(
		huh.NewInput().Title(title).EchoMode(g.hiddenEcho()).Value(&token).Validate(validToken),
		huh.NewConfirm().Title("Save it for later sessions?").Value(&save),
	); err != nil {
		return 0, err
	}
	token = strings.TrimSpace(token)
	_ = os.Setenv(login.envVar, token)
	if save {
		if err := saveLogin(home, login.envVar, token); err != nil {
			g.bad("Couldn't save the sign-in: " + err.Error())
			g.note("Before each session, run: export " + login.envVar + "=<your token>")
		}
	} else {
		g.note("Before each session, run: export " + login.envVar + "=<your token>")
	}
	g.ok("Signed in to " + a.label)
	return identity.ExitOK, nil
}

// validToken accepts one line with no quote, which saveLogin writes inside single quotes.
func validToken(s string) error {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return errors.New("paste the token")
	case strings.ContainsAny(s, "'\n\r"):
		return errors.New("that doesn't look like a token")
	}
	return nil
}

// savedLogin is the saved value of envVar, or "".
func savedLogin(home, envVar string) string {
	b, err := os.ReadFile(filepath.Join(home, agentEnvRel))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, envVar+"="); ok {
			return strings.Trim(v, "'")
		}
	}
	return ""
}

// saveLogin writes envVar's value to the agent.env file (mode 0600, replacing that variable's line) and adds the line
// that loads it to ~/.bashrc, once.
func saveLogin(home, envVar, value string) error {
	path := filepath.Join(home, agentEnvRel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var keep []string
	if b, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if l != "" && !strings.HasPrefix(l, envVar+"=") {
				keep = append(keep, l)
			}
		}
	}
	keep = append(keep, envVar+"='"+value+"'")
	if err := os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	rc := filepath.Join(home, ".bashrc")
	if b, err := os.ReadFile(rc); err == nil && strings.Contains(string(b), bashrcLine) {
		return nil
	}
	f, err := os.OpenFile(rc, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString("\n" + bashrcLine + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// project asks which project the agent works in: this folder (when tego start runs inside one), the test project, or
// another folder by its path. It reports the folder and whether it is the test project.
func (g *walk) project(name, home string, onMac bool) (string, bool, error) {
	const (
		here = iota
		test
		other
	)
	var opts []huh.Option[int]
	wd, _ := os.Getwd()
	inProject := wd != "" && wd != home && wd != "/" && !strings.HasPrefix(home, wd+"/") && unixWritable(wd) &&
		filepath.Base(wd) != guideSample
	if inProject {
		opts = append(opts, huh.NewOption("This folder: "+tildeHome(wd, home), here))
	}
	opts = append(opts, huh.NewOption("Test project   a small project made to show what Tego catches", test),
		huh.NewOption("One of my projects", other))
	pick := opts[0].Value
	if err := g.ask(huh.NewSelect[int]().Title("Which project should " + name + " work in?").Options(opts...).Value(&pick)); err != nil {
		return "", false, err
	}
	switch pick {
	case here:
		g.ok("Project: " + tildeHome(wd, home))
		return wd, false, nil
	case test:
		dir := filepath.Join(home, guideSample)
		if err := makeSample(dir); err != nil {
			return "", false, fmt.Errorf("making the test project: %w", err)
		}
		g.ok("Project: " + tildeHome(dir, home))
		g.note("Its test dependency is poisoned: when the tests run, it tries to read the project's secret and send it out.")
		g.note("See its files: " + sampleURL)
		return dir, true, nil
	}
	title := "Path to the project"
	if onMac {
		title = "Path to the project, inside Tego's VM"
	}
	path := ""
	if err := g.ask(huh.NewInput().Title(title).Placeholder("~/code/my-app").Value(&path).Validate(func(s string) error {
		_, err := projectPath(s, home, onMac)
		return err
	})); err != nil {
		return "", false, err
	}
	abs, _ := projectPath(path, home, onMac)
	g.ok("Project: " + tildeHome(abs, home))
	return abs, false, nil
}

// projectPath turns a typed path into the project folder, or says in one line what is wrong with it.
func projectPath(s, home string, onMac bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("type the project's path, for example ~/code/my-app")
	}
	abs := s
	if s == "~" || strings.HasPrefix(s, "~/") {
		abs = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(s, "~"), "/"))
	}
	if !filepath.IsAbs(abs) {
		wd, _ := os.Getwd()
		abs = filepath.Join(wd, abs)
	}
	abs = filepath.Clean(abs)
	fi, err := os.Stat(abs)
	switch {
	case err != nil && onMac:
		return "", fmt.Errorf("%s isn't in Tego's VM. Your Mac's folders aren't here: clone or copy the project into the VM first, e.g. git clone <url> %s", s, s)
	case err != nil:
		return "", fmt.Errorf("%s doesn't exist", s)
	case !fi.IsDir():
		return "", fmt.Errorf("%s is a file, not a folder", s)
	case abs == home || abs == "/":
		return "", errors.New("pick a project folder, not your whole home folder")
	case !unixWritable(abs):
		return "", fmt.Errorf("%s is read-only here", s)
	}
	return abs, nil
}

// rules asks which rules the agent follows: a preset, or the person's own pick of the same building blocks.
func (g *walk) rules(name string, a guideAgent) (rulesChoice, error) {
	all := []string{"no-secrets", "no-prod", "repo-only-writes"}
	choices := []rulesChoice{
		{label: "Base development", presets: all, writeProject: true},
		{label: "Read-only review", presets: all},
	}
	hostWord := "the hosts you name"
	if a.host != "" {
		hostWord = a.host
	}
	pick := 0
	g.note("Read more about rules and presets: " + presetsDocURL)
	if err := g.ask(huh.NewSelect[int]().Title("Which rules should "+name+" follow?").
		Options(
			huh.NewOption("Base development   edits the project, installs packages, runs tests · never reads your secrets", 0),
			huh.NewOption("Read-only review   reads files and git history · changes nothing", 1),
			huh.NewOption("Create my own", 2),
		).Value(&pick)); err != nil {
		return rulesChoice{}, err
	}
	if pick < len(choices) {
		g.ok("Rules: " + choices[pick].label)
		return choices[pick], nil
	}
	picked := []string{"no-secrets", "no-prod", "repo-only-writes"}
	if err := g.ask(huh.NewMultiSelect[string]().Title("Pick each rule").
		Options(
			huh.NewOption("Never read secrets (~/.ssh, ~/.aws, .env files)", "no-secrets").Selected(true),
			huh.NewOption("Connect only to "+hostWord, "no-prod").Selected(true),
			huh.NewOption("Change only the project folder", "repo-only-writes").Selected(true),
		).Value(&picked).Validate(func(s []string) error {
		if len(s) == 0 {
			return errors.New("keep at least one rule")
		}
		return nil
	})); err != nil {
		return rulesChoice{}, err
	}
	// The project stays writable either way: without "Change only the project folder" the agent may change any file
	// you can, which the rules file then says.
	rc := rulesChoice{label: "your own", presets: picked, writeProject: true}
	hosts := ""
	if containsString(picked, "no-prod") {
		if err := g.ask(huh.NewInput().Title("Other hosts it may reach (comma-separated, Enter for none)").
			Placeholder("api.github.com, pypi.org").Value(&hosts)); err != nil {
			return rulesChoice{}, err
		}
	}
	rc.hosts = splitList(hosts)
	g.ok("Rules: your own")
	return rc, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// splitList is a comma-separated answer as its trimmed, non-empty parts.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// saveAgent writes the agent's rules file. An agent of that name already there is kept unless the person replaces it.
func (g *walk) saveAgent(ctx context.Context, m *config.Machine, a guideAgent, command, name, abs string, rc rulesChoice, test bool, stderr io.Writer) (string, int, error) {
	replace := false
	if file, err := agentFile(m, name); err == nil {
		if _, err := os.Stat(file); err == nil {
			if err := g.ask(huh.NewConfirm().Title("Agent " + name + " already exists. Replace its rules?").Value(&replace)); err != nil {
				return "", 0, err
			}
			if !replace {
				g.ok("Agent " + name + " kept: " + tildeHome(file, m.Home))
				return file, identity.ExitOK, nil
			}
		}
	}
	path, code := guideSaveRules(ctx, m, a, command, name, abs, rc, test, replace, stderr)
	if code != identity.ExitOK {
		return "", code, nil
	}
	g.ok("Agent " + name + " created: " + tildeHome(path, m.Home))
	return path, identity.ExitOK, nil
}

// agentFile is where the agent named name's rules file lives in the user registry.
func agentFile(m *config.Machine, name string) (string, error) {
	return registry.Save{Places: registry.Places{User: m.Registry.Value}, Name: name}.Path()
}

// guideSaveRules composes an agent's rules file from rc, the way tego init --agent does, with the agent's own
// interactive program (its approval prompts off in the test project), and saves it in the user registry, outside the
// project, where tego run <name> finds it. replace removes an existing file of that name first.
func guideSaveRules(_ context.Context, m *config.Machine, a guideAgent, command, name, abs string, rc rulesChoice, test, replace bool, stderr io.Writer) (string, int) {
	dir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		message(stderr, abs, 0, 0, "tego start: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	po := setup.Options{Presets: []string{strings.Join(rc.presets, ",")}, Hosts: rc.hosts,
		Agent: a.harness, Name: name, Dir: dir, Home: m.Home, Writes: []string{dir + "/.tego/"}}
	if rc.writeProject {
		po.Writes = []string{dir + "/"}
	}
	if a.harness == "" {
		po.Command = command
	} else {
		po.Interactive, po.SkipApprovals = true, test
	}
	env, code := initCheckEnv(stderr)
	if code != identity.ExitOK {
		return "", code
	}
	composed, err := setup.Compose(po)
	if err != nil {
		message(stderr, "", 0, 0, "tego start: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	sv := registry.Save{Places: registry.Places{User: m.Registry.Value}, Name: name, Text: composed.Contract,
		Writes: []string{dir}}
	file, err := sv.Path()
	if err != nil {
		message(stderr, "", 0, 0, "tego start: where to save the rules file: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	// The rules file lives in the user registry, outside the project, so it is checked as that file, run from the
	// project, once the folders it names exist.
	made, err := setup.Create(composed, dir)
	if err != nil {
		message(stderr, dir, 0, 0, "tego start: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	if ds, ok := setup.CheckFile(composed.Contract, file, dir, env); !ok {
		setup.Remove(made, dir)
		_ = agent.WriteDiagnostics(stderr, ds)
		return "", identity.ExitFinding
	}
	if replace {
		if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			message(stderr, file, 0, 0, "tego start: replacing the rules file: "+err.Error(), codeIO)
			return "", identity.ExitError
		}
	}
	path, err := sv.Write()
	if err != nil {
		message(stderr, path, 0, 0, "tego start: saving the rules file: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	return path, identity.ExitOK
}

// unixWritable reports whether this user may create files in dir.
func unixWritable(dir string) bool { return unix.Access(dir, unix.W_OK) == nil }

// tildeHome shows a path under home with ~.
func tildeHome(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// guideSample is the test project's folder, under home.
const guideSample = "tego-sample"

// makeSample creates the test project at dir from setup.Sample, or fills in what is missing; it never replaces a file.
func makeSample(dir string) error {
	src := setup.Sample()
	return fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := fs.ReadFile(src, p)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		if err != nil {
			return err
		}
		_, werr := f.Write(b)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return werr
	})
}
