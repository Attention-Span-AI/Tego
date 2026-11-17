// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/internal/shellword"
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
	label, desc, envVar string
	example             string // the gray example in the field its key is pasted into
	setupToken          bool
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
			{label: "Claude subscription", desc: "Log in with your Claude account in a browser", envVar: "CLAUDE_CODE_OAUTH_TOKEN", setupToken: true},
			{label: "Anthropic API key", desc: "A key from console.anthropic.com", envVar: "ANTHROPIC_API_KEY", example: "sk-ant-api03-…"},
		}},
	{label: "Codex", harness: "codex", command: "codex", host: "OpenAI's API",
		install: "mkdir -p ~/.local/bin && curl -fsSL https://github.com/openai/codex/releases/latest/download/codex-$(uname -m)-unknown-linux-musl.tar.gz | tar -xzO > ~/.local/bin/codex && chmod 0755 ~/.local/bin/codex",
		logins:  []guideLogin{{label: "OpenAI API key", envVar: "CODEX_API_KEY", example: "sk-…"}}},
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

// guideSetupToken runs the agent's own browser sign-in (claude setup-token) on this terminal and returns the token it
// printed, or "" when it can't read one (the guide then asks for it). It runs under script(1), which keeps the
// terminal the sign-in needs and copies what it shows to an already-unlinked file (0600); the
// wide stty keeps the token on one line there. A variable so a test signs in nothing.
var guideSetupToken = func(ctx context.Context, program, home string) (string, error) {
	run := func(c *proc.Cmd) (err error) {
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		restore, err := foregroundGuideLogin(c)
		if err != nil {
			return err
		}
		defer func() {
			if e := restore(); err == nil {
				err = e
			}
		}()
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := proc.Start(c); err != nil {
			return err
		}
		return waitGuideLogin(ctx, c)
	}
	script, err := guideLookPath("script")
	if err != nil {
		err := run(proc.Command(program, "setup-token"))
		return "", err
	}
	dir := filepath.Join(home, ".tego")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "sign-in-*.log")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if err := os.Remove(f.Name()); err != nil {
		return "", err
	}
	var capture unix.Stat_t
	if err := sys.FstatFile(f, &capture); err != nil {
		return "", err
	}
	if capture.Nlink != 0 {
		return "", errors.New("login capture is still linked; sign-in was not started")
	}
	c := proc.Command(script, "-q", "-e", "-c", "stty cols 400 2>/dev/null; exec "+shellword.Quote(program)+" setup-token", "/proc/self/fd/3")
	c.ExtraFiles = []*os.File{f}
	err = run(c)
	if err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return lastToken(string(b)), nil
}

// waitGuideLogin lets script restore its terminal and terminate its child on cancellation, then bounds the wait.
func waitGuideLogin(ctx context.Context, c *proc.Cmd) error {
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = c.Wait(); close(done) }()
	select {
	case <-done:
		return waitErr
	case <-ctx.Done():
		_ = c.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = unix.Kill(-c.Process.Pid, unix.SIGKILL)
			<-done
		}
		_ = unix.Kill(-c.Process.Pid, unix.SIGKILL)
		return ctx.Err()
	}
}

// resetTerminal undoes what a full-screen program can leave behind when it exits (the kitty keyboard protocol, xterm's
// modifyOtherKeys, bracketed paste, the alternate screen, a hidden cursor) and puts the line settings back, so the
// guide's next question shows and reads Enter as Enter.
func resetTerminal() {
	if !isTerminalFile(os.Stdout) {
		return
	}
	// Keyboard modes off, the main screen back, the cursor shown, then a fresh line for the next question.
	_, _ = os.Stdout.WriteString("\x1b[<u\x1b[>4;0m\x1b[?2004l\x1b[?1049l\x1b[?25h\r\n")
	c := proc.Command("stty", "sane")
	c.Stdin = os.Stdin
	if _, err := proc.Start(c); err == nil {
		_ = c.Wait()
	}
	// What was typed for the sign-in (the Enter after the pasted code) must not answer the guide's next question.
	_ = sys.FileDo(os.Stdin, func(fd int) error { return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) })
}

// claudeToken is a Claude setup-token token as Claude prints it.
var claudeToken = regexp.MustCompile(`sk-ant-oat01-[A-Za-z0-9_-]{20,}`)

// lastToken is the last token in text, with terminal colour codes taken out, or "".
func lastToken(text string) string {
	text = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`).ReplaceAllString(text, "")
	all := claudeToken.FindAllString(text, -1)
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

// guideInteractive reports whether tego start talks to a person: both its input and its output are a terminal.
func guideInteractive(stdout io.Writer) bool {
	if o, ok := stdout.(*outputWriter); ok {
		stdout = o.dst
	}
	f, ok := stdout.(*os.File)
	return ok && isTerminalFile(os.Stdin) && isTerminalFile(f)
}

// The guide's columns: a step's label at column 3, its lines at column 8, an open input and its key hint at column 10,
// details at column 12. Each mark and colour means one thing: ? (cyan) a question, ! (yellow) do this now, ✓ (green)
// done, ✗ (red) a problem and its fix, dim a detail or a key hint, bold a command to type.
const (
	colTop    = "  "
	colStep   = "       "
	colInput  = "  " // under colStep: Huh's form is drawn at colStep
	colDetail = "           "
)

// walk is the terminal the guide talks on: questions through Huh, results as one line each.
type walk struct {
	ctx                                         context.Context
	terminal                                    *guideTerminal
	in                                          io.Reader
	out                                         io.Writer
	tty                                         bool   // a person at a terminal (not a test's plain input)
	accessible                                  bool   // Huh's plain prompts: no terminal drawing (tests, TERM=dumb)
	col                                         string // where results and questions start: colStep in the guide
	green, red, yellow, cyan, dim, bold, offEsc string
}

// newWalk talks on in and out. tty is a real terminal: colour and Huh's drawn prompts; otherwise plain prompts that read
// one line per answer.
func newWalk(in io.Reader, out io.Writer, tty bool) *walk {
	g := &walk{in: in, out: out, tty: tty, accessible: !tty || os.Getenv("TERM") == "dumb", col: colStep}
	if f, ok := in.(*os.File); g.accessible && !(ok && isTerminalFile(f)) {
		// Not a terminal (a test's answers): each plain prompt opens its own scanner, so each gets one line. A
		// terminal already hands over one line per read, and Huh's hidden input needs the terminal itself.
		g.in = &lineReader{r: bufio.NewReader(in)}
	}
	if tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		g.green, g.red, g.yellow, g.cyan, g.dim, g.bold, g.offEsc = "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"
	}
	return g
}

func (g *walk) line(format string, a ...any) { fmt.Fprintf(g.out, format+"\n", a...) }
func (g *walk) top(s string)                 { g.line("%s%s", colTop, s) }
func (g *walk) step(n int, title string) {
	g.line("\n%s%s%d/4  %s%s", colTop, g.bold, n, title, g.offEsc)
}
func (g *walk) ok(s string)     { g.line("%s%s✓%s %s", g.col, g.green, g.offEsc, s) }
func (g *walk) bad(s string)    { g.line("%s%s✗%s %s", g.col, g.red, g.offEsc, s) }
func (g *walk) todo(s string)   { g.line("%s%s!%s %s", g.col, g.yellow, g.offEsc, s) }
func (g *walk) detail(s string) { g.line("%s%s%s%s", colDetail, g.dim, s, g.offEsc) }
func (g *walk) cmd(s string)    { g.line("%s%s%s%s", colDetail, g.bold, s, g.offEsc) }

// question is a question as every input shows it: a cyan ? and the words.
func (g *walk) question(q string) string { return g.cyan + "?" + g.offEsc + " " + q }

// answered keeps a question and its answer on screen: Huh's drawn form clears itself once answered, and its plain
// prompts already show both.
func (g *walk) answered(q, a string) {
	if !g.accessible {
		g.line("%s%s  %s%s%s", g.col, g.question(q), g.bold, a, g.offEsc)
	}
}

// theme is the one look every input shares: drawn at colStep, no border, the input under the question at colInput,
// > as the cursor in lists and checklists, [x] for a checked item, a gray example in an empty field. The key hint and
// an error are drawn by hinted, under the input.
func (g *walk) theme() huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		t := huh.ThemeBase(isDark)
		t.Form.Base = lipgloss.NewStyle().MarginLeft(len(g.col))
		t.Focused.Base = lipgloss.NewStyle()
		t.Focused.Title = lipgloss.NewStyle()
		t.Focused.ErrorIndicator = lipgloss.NewStyle()
		t.Focused.ErrorMessage = lipgloss.NewStyle()
		t.Focused.SelectSelector = lipgloss.NewStyle().SetString(colInput + "> ")
		t.Focused.MultiSelectSelector = lipgloss.NewStyle().SetString(colInput + "> ")
		t.Focused.SelectedOption = lipgloss.NewStyle().Bold(true)
		t.Focused.UnselectedOption = lipgloss.NewStyle()
		t.Focused.SelectedPrefix = lipgloss.NewStyle().SetString("[x] ")
		t.Focused.UnselectedPrefix = lipgloss.NewStyle().SetString("[ ] ")
		t.Focused.TextInput.Prompt = lipgloss.NewStyle()
		t.Focused.TextInput.Placeholder = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
		t.Blurred = t.Focused
		t.Blurred.MultiSelectSelector = lipgloss.NewStyle().SetString(colInput + "  ")
		return t
	})
}

// hinted is an input with the guide's key hint under it, or, while the input refuses what was typed, the reason in red.
// Huh's own footer (help and errors, after a blank line) is off, so the hint sits right under the input.
type hinted struct {
	huh.Field
	g    *walk
	hint string
	mask bool // a secret: Huh masks it with *, shown here as •

	// A list longer than guideListRows scrolls; Huh scrolls only as far as keeps the cursor in view, so top follows the
	// hovered item the same way, and the hint says how many items are out of view.
	items   int
	hovered func() (int, bool)
	top     int
}

func (h *hinted) Update(msg tea.Msg) (huh.Model, tea.Cmd) {
	m, c := h.Field.Update(msg)
	if f, ok := m.(huh.Field); ok {
		h.Field = f
	}
	return h, c
}

func (h *hinted) View() string {
	v := h.Field.View()
	if h.mask {
		v = strings.ReplaceAll(v, "*", "•") // Huh's Input has no way to set its mask character
	}
	if err := h.Error(); err != nil {
		return v + "\n" + colInput + h.g.red + "✗ " + err.Error() + h.g.offEsc
	}
	return v + "\n" + colInput + h.g.dim + h.more() + h.hint + h.g.offEsc
}

// more is "↑ 2 more · ↓ 3 more · " for a list with items out of view, or "".
func (h *hinted) more() string {
	if h.items <= guideListRows || h.hovered == nil {
		return ""
	}
	c, _ := h.hovered()
	h.top = min(max(h.top, c-guideListRows+1), c)
	out := ""
	if h.top > 0 {
		out += fmt.Sprintf("↑ %d more · ", h.top)
	}
	if below := h.items - h.top - guideListRows; below > 0 {
		out += fmt.Sprintf("↓ %d more · ", below)
	}
	return out
}

// ask shows one input; a person who leaves it (Ctrl-C) gets errStopped.
func (g *walk) ask(h *hinted) error {
	h.g = g
	out := g.out
	if o, ok := out.(*outputWriter); ok {
		if f, ok := o.dst.(*os.File); ok {
			out = f // Huh draws only on the terminal's own file: through a writer that wraps it, it draws nothing
		}
	}
	form := huh.NewForm(huh.NewGroup(h)).WithInput(g.in).WithOutput(out).
		WithAccessible(g.accessible).WithTheme(g.theme()).WithShowHelp(false).WithShowErrors(false)
	ctx := g.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return errStopped
	}
	var err error
	if g.terminal != nil {
		err = g.terminal.runForm(ctx, form, h, out)
	} else {
		err = form.RunWithContext(ctx)
	}
	if ctx.Err() != nil {
		return errStopped
	}
	if errors.Is(err, huh.ErrUserAborted) {
		return errStopped
	}
	return err
}

// choice is one item of a list or a checklist: its name, and what it means in a few words.
type choice struct {
	name, desc  string
	recommended bool // the safe default: first, with the cursor on it
	checked     bool // in a checklist, checked to start with
}

// labels are the items' lines: the name (with "(recommended)"), then the description in a second, dim column.
func (g *walk) labels(items []choice) []string {
	names := make([]string, len(items))
	width := 0
	for i, c := range items {
		names[i] = c.name
		if c.recommended {
			names[i] += " (recommended)"
		}
		width = max(width, len(names[i]))
	}
	for i, c := range items {
		if c.desc != "" {
			names[i] = fmt.Sprintf("%-*s   %s%s%s", width, names[i], g.dim, c.desc, g.offEsc)
		}
	}
	return names
}

// chooseOne asks q with a list and returns the index picked. A yes/no question is a two-item list too.
func (g *walk) chooseOne(q string, items []choice) (int, error) {
	labels := g.labels(items)
	opts := make([]huh.Option[int], len(items))
	for i := range items {
		opts[i] = huh.NewOption(labels[i], i)
	}
	pick := 0
	sel := huh.NewSelect[int]().Title(g.question(q)).Options(opts...).Value(&pick)
	if len(items) > guideListRows {
		sel = sel.Height(guideListRows + 1) // and the question's line
	}
	if err := g.ask(&hinted{Field: sel, hint: "↑/↓ move · enter select", items: len(items), hovered: sel.Hovered}); err != nil {
		return 0, err
	}
	g.answered(q, items[pick].name)
	return pick, nil
}

// chooseSeveral asks q with a checklist and returns the indexes checked; one must stay checked.
func (g *walk) chooseSeveral(q string, items []choice) ([]int, error) {
	labels := g.labels(items)
	opts := make([]huh.Option[int], len(items))
	for i, c := range items {
		opts[i] = huh.NewOption(labels[i], i).Selected(c.checked)
	}
	var picked []int
	ms := huh.NewMultiSelect[int]().Title(g.question(q)).Options(opts...).Value(&picked).Validate(func(s []int) error {
		if len(s) == 0 {
			return errors.New("keep at least one checked")
		}
		return nil
	})
	ms = ms.Height(min(len(items), guideListRows) + 1) // Huh's own height leaves the last item out; +1 for the question
	if err := g.ask(&hinted{Field: ms, hint: "↑/↓ move · space toggle · enter done", items: len(items), hovered: ms.Hovered}); err != nil {
		return nil, err
	}
	names := make([]string, len(picked))
	for i, p := range picked {
		names[i] = items[p].name
	}
	g.answered(q, strings.Join(names, ", "))
	return picked, nil
}

// typeText asks q with a text field showing example in gray. A secret shows as dots, and its answer is never echoed.
// valid says in one line what is wrong with an answer; the field stays open until it passes.
func (g *walk) typeText(q, example string, secret bool, valid func(string) error) (string, error) {
	val := ""
	in := huh.NewInput().Title(g.question(q)).Placeholder(example).Prompt(colInput).Value(&val)
	if valid != nil {
		in = in.Validate(valid)
	}
	if secret {
		in = in.EchoMode(g.hiddenEcho())
	}
	if err := g.ask(&hinted{Field: in, hint: "enter confirm", mask: secret}); err != nil {
		return "", err
	}
	val = strings.TrimSpace(val)
	shown := val
	if secret {
		shown = "••••••••"
	}
	g.answered(q, shown)
	return val, nil
}

// guideListRows is how many items a list shows; a longer one scrolls inside them.
const guideListRows = 6

// yesNoItems is a yes/no question's two items, the recommended one first.
func yesNoItems(yesDesc, noDesc string, yesFirst bool) []choice {
	yes, no := choice{name: "Yes", desc: yesDesc}, choice{name: "No", desc: noDesc}
	if yesFirst {
		yes.recommended = true
		return []choice{yes, no}
	}
	no.recommended = true
	return []choice{no, yes}
}

// errStopped is the person leaving the guide.
var errStopped = errors.New("stopped")

// lineReader hands its reader over one line per Read, so each plain prompt, which opens its own scanner, reads only its
// own answer.
type lineReader struct {
	r    *bufio.Reader
	rest []byte
}

// hiddenEcho is how a pasted token shows: hidden, except on plain input that is not a terminal (a test's answers),
// where nothing can hide it.
func (g *walk) hiddenEcho() huh.EchoMode {
	if _, ok := g.in.(*lineReader); ok {
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
	writeProject bool // the whole project; otherwise only the agent state and temporary files
	hosts        []string
	summary      string // what the rules mean, in one line
	file         string // a rules file of the person's own, used as it is
}

// runSetupGuide is tego start: it connects the agent the person wants to supervise, logs it in, picks its project and
// its rules, saves it as an agent, opens the dashboard, and shows how to start the first session. It asks before it
// changes anything and never starts the agent itself.
func runSetupGuide(ctx context.Context, in io.Reader, stdout, stderr io.Writer, tty bool) int {
	g := newWalk(in, stdout, tty)
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	g.ctx = ctx
	if !g.accessible {
		term, err := openGuideTerminal(in, stop)
		if err != nil {
			message(stderr, "", 0, 0, "tego start: "+err.Error(), codeIO)
			return identity.ExitError
		}
		g.terminal = term
		if term != nil {
			defer func() { _ = term.close() }()
		}
	}
	code, err := g.guide(ctx, stderr)
	switch {
	case errors.Is(err, errStopped):
		g.line("")
		g.line("%s%s✗%s Stopped. Run tego start to pick up again.", colTop, g.red, g.offEsc)
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
	g.top(g.bold + "Welcome to Tego" + g.offEsc)
	g.top("Four steps to supervise your first agent.")
	pa, err := setupProbe(ctx, m)
	mark := func(color, sign, s string) { g.line("%s%s%s%s %s", colTop, color, sign, g.offEsc, s) }
	switch {
	case err != nil:
		return 0, err
	case pa.tier == "" && pa.outside:
		mark(g.red, "✗", "Tego can't supervise agents started from this shell.")
		if o := scopeOpener(); o.Command != "" {
			g.line("%s  Open one where it can, then run tego start again: %s%s%s", colTop, g.bold, o.Command, g.offEsc)
		}
		return identity.ExitFinding, nil
	case pa.tier == "":
		mark(g.red, "✗", "This machine can't run supervised agents yet. tego machine check shows why.")
		return identity.ExitFinding, nil
	}
	mark(g.green, "✓", fmt.Sprintf("This machine can run Tego · %s protection, no root needed", levelName(pa.tier)))

	// 1/4: the agent.
	g.step(1, "Agent")
	pick, err := g.chooseOne("Which agent do you want to supervise?", []choice{
		{name: "Claude Code", desc: "Anthropic's coding agent", recommended: true},
		{name: "Codex", desc: "OpenAI's coding agent"},
		{name: "Another program", desc: "Any command, such as a script or a bot"},
	})
	if err != nil {
		return 0, err
	}
	a := guideAgents[pick]
	command := a.command
	if a.harness == "" {
		if command, err = g.typeText("What command starts it?", "python3 bot.py", false, func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("type the command, for example python3 bot.py")
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}
	name := a.label
	program := strings.Fields(command)[0]
	if a.harness == "" {
		name = program
		a.command = program
	}
	if code, err := g.installed(ctx, a, name, program, home); code != identity.ExitOK || err != nil {
		return code, err
	}

	// 2/4: its login.
	g.step(2, "Login")
	if len(a.logins) == 0 {
		g.ok("Nothing to log in to: " + name + " brings its own")
	} else if code, err := g.signIn(ctx, a, home); code != identity.ExitOK || err != nil {
		return code, err
	}

	// 3/4: its project.
	g.step(3, "Project")
	abs, test, err := g.project(name, home, onMac)
	if err != nil {
		return 0, err
	}

	// 4/4: its rules.
	g.step(4, "Rules")
	agentName := agentNameFor(abs)
	if test {
		agentName = guideSample
	}
	rc, err := g.rules(ctx, m, name, a, abs)
	if err != nil {
		return 0, err
	}
	if rc.file != "" {
		if n := rulesFileName(rc.file); n != "" {
			agentName = n
		}
	}
	if code, err := g.saveAgent(ctx, m, a, command, agentName, abs, &rc, test, stderr); code != identity.ExitOK || err != nil {
		return code, err
	}
	rememberProject(home, abs)

	// The recap, the dashboard and what to type next. The person starts the session: Tego never starts the agent.
	url := ""
	if g.tty {
		url = guideDashboard(home)
	}
	g.line("")
	g.line("%s%s%s%s", colTop, g.dim, strings.Repeat("─", 62), g.offEsc)
	g.line("")
	g.top(g.bold + "Ready" + g.offEsc)
	row := func(k, v string) { g.line("%s  %-12s%s", colTop, k, v) }
	row("Agent", agentName+" · "+name)
	row("Project", tildeHome(abs, home))
	row("Rules", rc.label)
	switch {
	case url == "":
		row("Dashboard", "tego dashboard opens it")
	case onMac:
		row("Dashboard", url+"   "+g.dim+"opening in your browser"+g.offEsc)
	default:
		row("Dashboard", url)
	}
	if onMac {
		row("Shell", "Tego's Linux VM · type exit to return to your Mac")
	}
	g.line("")
	g.top(g.bold + "Next steps" + g.offEsc)
	next := func(what, c string) { g.line("%s  %-30s%s%s%s", colTop, what, g.bold, c, g.offEsc) }
	next("Run "+name+" under Tego", "cd "+shellword.Quote(abs)+" && tego run "+agentName)
	next("List your sessions", "tego session list")
	next("Show the last session", "tego session show --last")
	next("Edit the rules", "tego rules edit "+agentName)
	g.line("")
	return identity.ExitOK, nil
}

// guideDashboard starts the dashboard for this user as a systemd user unit (tego-dashboard), as the Mac's tego dashboard
// does, and returns its address from its log, or "" when it didn't start. On a Mac, the tego command there then opens
// it in the browser through Tego's VM. A variable so a test starts no unit.
var guideDashboard = func(home string) string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	if u := runningDashboard(home); u != "" {
		return u // restarting it would sign out the tabs already open
	}
	if _, err := readGuideFile(home, ".tego/dashboard.log"); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "Ignored dashboard log: %v\n", err)
	}
	if os.MkdirAll(filepath.Join(home, ".tego"), 0o700) != nil {
		return ""
	}
	quiet := func(argv ...string) ([]byte, error) {
		var out bytes.Buffer
		c := proc.Command(argv[0], argv[1:]...)
		c.Stdout = &out
		if _, err := proc.Start(c); err != nil {
			return nil, err
		}
		err := c.Wait()
		return out.Bytes(), err
	}
	_, _ = quiet("systemctl", "--user", "stop", "tego-dashboard")
	f, err := openDashboardLog(home)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	root, configFile, _, err := dashboardConfiguration()
	if err != nil {
		return ""
	}
	args := []string{"--user", "--unit=tego-dashboard", "--quiet", "--pipe", "--setenv=TEGO_CONFIG=" + configFile}
	// The option arrived in systemd 254. Probe its presence for backports too;
	// older service managers use the documented $$ escaping. --setenv is already literal.
	help, _ := quiet("systemd-run", "--help")
	command := []string{self, "serve", "--ledger", root}
	if strings.Contains(string(help), "--expand-environment") {
		args = append(args, "--expand-environment=no")
	} else {
		for i := range command {
			command[i] = strings.ReplaceAll(command[i], "$", "$$")
		}
	}
	c := proc.Command("systemd-run", append(args, command...)...)
	c.Stdout, c.Stderr = f, f
	if _, err := proc.Start(c); err != nil {
		return ""
	}
	go func() { _ = c.Wait() }()
	for range 60 {
		b := make([]byte, 64*1024)
		n, err := f.ReadAt(b, 0)
		if err == nil || errors.Is(err, io.EOF) {
			b = b[:n]
			if u := dashboardLink.Find(b); u != nil && probeDashboard(string(u)) {
				return string(u)
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return ""
}

// openDashboardLog creates the log privately before any sign-in link is written. The descriptor is handed to
// systemd-run --pipe, which passes it to the unit; no shell reopens a pathname.
func openDashboardLog(home string) (*os.File, error) {
	return publishGuideFile(home, ".tego/dashboard.log", nil, 0600)
}

// guideVersion is the version an installed program reports (claude --version), or ""; a variable so a test runs nothing.
var guideVersion = func(program string) string {
	c := proc.Command(program, "--version")
	var out bytes.Buffer
	c.Stdout = &out
	if _, err := proc.Start(c); err != nil {
		return ""
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return ""
		}
	case <-time.After(3 * time.Second):
		_ = c.Process.Kill()
		return ""
	}
	return regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`).FindString(out.String())
}

// installed makes sure the agent's program is on PATH, offering to install a known agent.
func (g *walk) installed(ctx context.Context, a guideAgent, name, program, home string) (int, error) {
	if _, err := guideLookPath(program); err == nil {
		g.ok(strings.TrimSpace(name+" "+guideVersion(program)) + " is installed")
		return identity.ExitOK, nil
	}
	if a.install == "" {
		g.bad(program + " isn't installed. Install it, then run tego start again.")
		return identity.ExitFinding, nil
	}
	if learnEUID() == 0 {
		g.bad("An agent installer cannot run as root; install it as yourself, then run tego start again:")
		g.cmd(a.install)
		return identity.ExitFinding, nil
	}
	g.detail("This fetches and runs the current upstream installer with your permissions:")
	g.cmd(a.install)
	pick, err := g.chooseOne("Install "+name+" now?", yesNoItems("Runs "+name+"'s own installer", "Shows the install line instead", true))
	if err != nil {
		return 0, err
	}
	if pick != 0 {
		g.todo("Install " + name + " with this line, then run tego start again:")
		g.cmd(a.install)
		return identity.ExitFinding, nil
	}
	g.detail("Installing " + name + "…")
	if !g.installAgent(ctx, a, home) {
		return identity.ExitFinding, nil
	}
	// The installers put the program in ~/.local/bin, which this shell's PATH may not have yet.
	_ = os.Setenv("PATH", filepath.Join(home, ".local", "bin")+":"+os.Getenv("PATH"))
	if _, err := guideLookPath(program); err != nil {
		g.bad(name + " was installed, but " + program + " isn't on your PATH")
		return identity.ExitFinding, nil
	}
	g.ok(strings.TrimSpace("Installed " + name + " " + guideVersion(program)))
	return identity.ExitOK, nil
}

// installAgent runs a's install line with its output in ~/.tego/setup-install.log; on failure it shows the log's last
// lines and where the whole log is.
func (g *walk) installAgent(ctx context.Context, a guideAgent, home string) bool {
	if learnEUID() == 0 {
		g.bad("An agent installer cannot run as root.")
		return false
	}
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
				g.detail(l)
			}
		}
		g.detail("The full log is in " + tildeHome(logPath, home))
		return false
	}
	return true
}

// agentEnvRel is where a saved sign-in lives, under home: one VAR='value' line per variable, mode 0600.
const agentEnvRel = ".config/tego/agent.env"

// bashrcLine loads the saved sign-ins in every new shell, so tego run passes them to the agent.
const bashrcLine = `[ -f "$HOME/.config/tego/agent.env" ] && { set -a; . "$HOME/.config/tego/agent.env"; set +a; } # added by tego start`

// signIn makes sure the agent has its login: a saved one the person keeps, one from this shell, or by asking for it.
func (g *walk) signIn(ctx context.Context, a guideAgent, home string) (int, error) {
	var vars []string
	for _, l := range a.logins {
		vars = append(vars, l.envVar)
	}
	saved := readSavedLogins(home, g.out)
	for _, l := range a.logins {
		if saved[l.envVar] == "" {
			continue
		}
		pick, err := g.chooseOne("Use your saved "+a.label+" login?", []choice{
			{name: "Yes", desc: l.label + ", saved on this machine", recommended: true},
			{name: "Log in again", desc: "Replaces the saved login"},
		})
		if err != nil {
			return 0, err
		}
		if pick == 0 {
			g.ok("Logged in to " + a.label)
			return identity.ExitOK, nil
		}
		if err := forgetLogins(home, vars); err != nil {
			g.bad("Couldn't remove the saved login: " + err.Error())
		}
		for _, v := range vars {
			_ = os.Unsetenv(v) // the shell loaded the saved login; this login replaces it
		}
		break
	}
	for _, v := range vars {
		if os.Getenv(v) != "" {
			g.ok("Logged in to " + a.label)
			return identity.ExitOK, nil
		}
	}
	login := a.logins[0]
	if len(a.logins) > 1 {
		items := make([]choice, len(a.logins))
		for i, l := range a.logins {
			items[i] = choice{name: l.label, desc: l.desc, recommended: i == 0}
		}
		pick, err := g.chooseOne("How do you want to log in to "+a.label+"?", items)
		if err != nil {
			return 0, err
		}
		login = a.logins[pick]
	}
	token := ""
	q, example := "Paste your "+login.label, login.example
	if login.setupToken {
		g.todo("Open the link " + a.label + " shows, log in, and paste the code back here.")
		got, err := g.setupToken(ctx, a.command, home)
		if err != nil {
			g.bad(a.label + "'s login didn't finish: " + err.Error() + ". Run tego start to try again.")
			return identity.ExitFinding, nil
		}
		token = got
		q, example = "Paste the token "+a.label+" printed", "sk-ant-oat01-…"
	}
	if token == "" {
		var err error
		if token, err = g.typeText(q, example, true, validToken); err != nil {
			return 0, err
		}
	}
	token = strings.TrimSpace(token)
	_ = os.Setenv(login.envVar, token)
	g.ok("Logged in to " + a.label)
	pick, err := g.chooseOne("Save the login for later sessions?",
		yesNoItems("Stays on this machine, readable only by you", "Asks again next time", true))
	if err != nil {
		return 0, err
	}
	if pick == 0 {
		if err := saveLogin(home, login.envVar, token); err != nil {
			g.bad("Couldn't save the login: " + err.Error())
			g.detail("Before each session, run: export " + login.envVar + "=<your token>")
		}
	} else {
		g.detail("Before each session, run: export " + login.envVar + "=<your token>")
	}
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

// forgetLogins removes vars from the agent.env file, leaving the other agents' logins.
func forgetLogins(home string, vars []string) error {
	b, err := readGuideFile(home, agentEnvRel)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		name, _, _ := strings.Cut(l, "=")
		if l != "" && !containsString(vars, name) {
			keep = append(keep, l)
		}
	}
	text := ""
	if len(keep) > 0 {
		text = strings.Join(keep, "\n") + "\n"
	}
	return replaceGuideFile(home, agentEnvRel, []byte(text), 0o600)
}

// saveLogin writes envVar's value to the agent.env file (mode 0600, replacing that variable's line) and adds the line
// that loads it to ~/.bashrc, once.
func saveLogin(home, envVar, value string) error {
	if err := validToken(value); err != nil {
		return err
	}
	// Validate both destinations before publishing the secret.
	old, err := readGuideFile(home, agentEnvRel)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errUnsafeGuideFile) {
		return err
	}
	rcHome, rcRel := home, ".bashrc"
	if target, resolveErr := filepath.EvalSymlinks(filepath.Join(home, rcRel)); resolveErr == nil {
		rcHome, rcRel = filepath.Dir(target), filepath.Base(target)
	} else if !errors.Is(resolveErr, os.ErrNotExist) {
		return resolveErr
	}
	rc, err := readGuideData(rcHome, rcRel, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(old), "\n"), "\n") {
		if l != "" && !strings.HasPrefix(l, envVar+"=") {
			keep = append(keep, l)
		}
	}
	keep = append(keep, envVar+"='"+value+"'")
	if err := replaceGuideFile(home, agentEnvRel, []byte(strings.Join(keep, "\n")+"\n"), 0600); err != nil {
		return err
	}
	if strings.Contains(string(rc), bashrcLine) {
		return nil
	}
	return replaceGuideFile(rcHome, rcRel, append(rc, []byte("\n"+bashrcLine+"\n")...), 0600)
}

// guideParent resolves the machine's directory layout, then pins the folder that holds the file.
// Only that folder must belong to the caller; its write permissions do not expose a private file.
func guideParent(home, rel string, create bool) (*os.File, error) {
	if !filepath.IsAbs(home) {
		return nil, errors.New("home must be absolute")
	}
	full := filepath.Join(home, filepath.Dir(rel))
	if create {
		if err := os.MkdirAll(full, 0700); err != nil {
			return nil, err
		}
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, err
	}
	owned, err := sys.Own(unix.Open(resolved, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, err
	}
	dir, err := owned.Release(resolved)
	if err != nil {
		_ = owned.Close()
		return nil, err
	}
	err = sys.FileDo(dir, func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("folder belongs to someone else: %s", full)
		}
		return nil
	})
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

// openGuideAt transfers the newly opened descriptor from its owner to the file used for I/O.
func openGuideAt(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	var f *os.File
	err := sys.FileDo(dir, func(fd int) error {
		owned, e := sys.Own(unix.Openat(fd, name, flags|unix.O_CLOEXEC, mode))
		if e != nil {
			return e
		}
		f, e = owned.Release(name)
		if e != nil {
			_ = owned.Close()
		}
		return e
	})
	return f, err
}

var errUnsafeGuideFile = errors.New("unsafe file")

func ownGuideFile(st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: file is not a regular file", errUnsafeGuideFile)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%w: file belongs to someone else", errUnsafeGuideFile)
	}
	return nil
}

func readGuideFile(home, rel string) ([]byte, error) {
	return readGuideData(home, rel, true)
}

func readGuideData(home, rel string, secret bool) ([]byte, error) {
	dir, err := guideParent(home, rel, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	f, err := openGuideAt(dir, filepath.Base(rel), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symbolic link", errUnsafeGuideFile, rel)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	err = sys.FileDo(f, func(fd int) error {
		var st unix.Stat_t
		if e := unix.Fstat(fd, &st); e != nil {
			return e
		}
		if err := ownGuideFile(&st); err != nil {
			return err
		}
		if secret && st.Mode&0044 != 0 {
			return fmt.Errorf("%w: %s is readable by group or others", errUnsafeGuideFile, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

func validateGuideDestination(dir *os.File, name string) error {
	return sys.FileDo(dir, func(fd int) error {
		var st unix.Stat_t
		err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK && st.Uid == uint32(os.Geteuid()) {
			return nil
		}
		return ownGuideFile(&st)
	})
}

func replaceGuideFile(home, rel string, text []byte, mode os.FileMode) error {
	f, err := publishGuideFile(home, rel, text, mode)
	if err != nil {
		return err
	}
	return f.Close()
}

func publishGuideFile(home, rel string, text []byte, mode os.FileMode) (*os.File, error) {
	dir, err := guideParent(home, rel, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	name := filepath.Base(rel)
	if err := validateGuideDestination(dir, name); err != nil {
		return nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	tmp := ".tego-save-" + hex.EncodeToString(random[:])
	f, err := openGuideAt(dir, tmp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	published := false
	defer func() {
		if !published {
			_ = f.Close()
		}
	}()
	defer func() { _ = sys.FileDo(dir, func(fd int) error { return unix.Unlinkat(fd, tmp, 0) }) }()
	err = f.Chmod(mode)
	if err == nil {
		_, err = f.Write(text)
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return nil, err
	}
	if err := validateGuideDestination(dir, name); err != nil {
		return nil, err
	}
	if err := sys.FileDo(dir, func(fd int) error { return unix.Renameat(fd, tmp, fd, name) }); err != nil {
		return nil, err
	}
	published = true
	return f, nil
}

// project asks which project the agent works in: the test project, this folder (when tego start runs inside one), or
// another folder by its path. It reports the folder and whether it is the test project.
func (g *walk) project(name, home string, onMac bool) (string, bool, error) {
	wd, _ := os.Getwd()
	inProject := wd != "" && wd != home && wd != "/" && !strings.HasPrefix(home, wd+"/") && unixWritable(wd) &&
		filepath.Base(wd) != guideSample
	items := []choice{{name: "Tego test project", desc: "A small app whose test dependency tries to steal a fake secret", recommended: true}}
	if inProject {
		items = append(items, choice{name: "This folder", desc: tildeHome(wd, home)})
	}
	items = append(items, choice{name: "My own project", desc: "A folder on this machine"})
	pick, err := g.chooseOne("Which project should "+name+" work in?", items)
	if err != nil {
		return "", false, err
	}
	switch items[pick].name {
	case "Tego test project":
		dir := filepath.Join(home, guideSample)
		_, statErr := os.Stat(dir)
		if err := makeSample(dir); err != nil {
			return "", false, fmt.Errorf("making the test project: %w", err)
		}
		if statErr == nil {
			g.ok("Using " + tildeHome(dir, home))
		} else {
			g.ok("Created " + tildeHome(dir, home))
		}
		g.detail("A small app whose test dependency tries to steal a fake secret.")
		g.detail("Files: " + sampleURL)
		return dir, true, nil
	case "This folder":
		g.ok("Using " + tildeHome(wd, home))
		return wd, false, nil
	}
	path, err := g.typeText("Path to the project", "~/code/my-app", false, func(s string) error {
		_, err := projectPath(s, home, onMac)
		return err
	})
	if err != nil {
		return "", false, err
	}
	abs, _ := projectPath(path, home, onMac)
	g.ok("Using " + tildeHome(abs, home))
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
		return "", fmt.Errorf("%s isn't in Tego's VM. Copy or clone it into the VM first", s)
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

// rules asks which rules the agent follows: a preset, the person's own pick of the same building blocks, or a rules
// file they wrote.
func (g *walk) rules(ctx context.Context, m *config.Machine, name string, a guideAgent, abs string) (rulesChoice, error) {
	all := []string{"no-secrets", "no-prod", "repo-only-writes"}
	host := a.host
	if host == "" {
		host = "the hosts you name"
	}
	pick, err := g.chooseOne("Which rules should "+name+" follow?", []choice{
		{name: "Base development", desc: "Edits and tests the project · never reads secrets", recommended: true},
		{name: "Read-only review", desc: "Project content stays read-only · agent state and temporary files stay writable"},
		{name: "Choose each rule", desc: "Pick the rules one by one"},
		{name: "Use my own rules file", desc: "A rules file you wrote"},
	})
	if err != nil {
		return rulesChoice{}, err
	}
	switch pick {
	case 0:
		return rulesChoice{label: "Base development", presets: all, writeProject: true,
			summary: "Edits and tests the project · never reads secrets · reaches only " + host}, nil
	case 1:
		return rulesChoice{label: "Read-only review", presets: all, summary: "Project content stays read-only · writes state and temporary files only in " + reviewState(a) + " · file attributes can change · reaches only " + host}, nil
	case 3:
		file, err := g.typeText("Path to the rules file", "~/code/my-app/agent.yaml", false, func(s string) error {
			_, err := rulesFile(ctx, m, s)
			return err
		})
		if err != nil {
			return rulesChoice{}, err
		}
		p, _ := rulesFile(ctx, m, file)
		return rulesChoice{label: "Your own file", file: p}, nil
	}
	items := []choice{
		{name: "no-secrets", desc: "Never read keys, tokens or .env files", checked: true},
		{name: "repo-only-writes", desc: "Change files only inside the project", checked: true},
		{name: "no-prod", desc: "Connect only to " + host + " and the hosts you add", checked: true},
	}
	picked, err := g.chooseSeveral("Which rules?", items)
	if err != nil {
		return rulesChoice{}, err
	}
	// The project stays writable either way: without repo-only-writes the agent may change any file you can, which the
	// rules file then says.
	rc := rulesChoice{label: "Your own choice", writeProject: true}
	for _, p := range picked {
		rc.presets = append(rc.presets, items[p].name)
	}
	if containsString(rc.presets, "no-prod") {
		hosts, err := g.typeText("Other hosts it may reach", "api.github.com, pypi.org  (enter for none)", false, func(s string) error { return setup.ValidateHosts(splitList(s)) })
		if err != nil {
			return rulesChoice{}, err
		}
		rc.hosts = splitList(hosts)
	}
	rc.summary = strings.Join(rc.presets, " · ")
	if len(rc.hosts) > 0 {
		rc.summary += " · also reaches " + strings.Join(rc.hosts, ", ")
	}
	return rc, nil
}

func reviewState(a guideAgent) string {
	switch filepath.Base(a.command) {
	case "claude":
		return ".tego/claude/"
	case "codex":
		return ".tego/codex/"
	}
	return ".tego/review/"
}

// rulesFile is a typed rules file's absolute path, once it reads and checks as tego run will compile it; otherwise the
// first thing wrong with it, in one line.
func rulesFile(ctx context.Context, m *config.Machine, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("type the rules file's path, for example ~/code/my-app/agent.yaml")
	}
	p := s
	if s == "~" || strings.HasPrefix(s, "~/") {
		p = filepath.Join(m.Home, strings.TrimPrefix(strings.TrimPrefix(s, "~"), "/"))
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	text, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("%s doesn't exist", s)
	}
	var diag bytes.Buffer
	if err := checkRules(ctx, m, p, text, &diag); err != nil {
		first, _, _ := strings.Cut(strings.TrimSpace(diag.String()), "\n")
		if m := diagLine.FindStringSubmatch(first); m != nil {
			return "", fmt.Errorf("%s line %s: %s", s, m[1], m[2])
		}
		return "", fmt.Errorf("%s has an error: %s", s, first)
	}
	return p, nil
}

// diagLine is a compile diagnostic as checkRules prints it: "error: <file>:<line>:<col>: <what> [<code>]".
var diagLine = regexp.MustCompile(`^(?:error: )?[^:]+:([0-9]+):[0-9]+: (.*?)(?: \[[a-z0-9-]+\])?$`)

// rulesFileName is the agent name a rules file gives itself (name:), or "" when it gives none that names an agent.
func rulesFileName(file string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	if l := rulesNameLine.Find(b); l != nil {
		if n := strings.Trim(strings.TrimSpace(strings.TrimPrefix(string(l), "name:")), `"'`); registry.IsName(n) {
			return n
		}
	}
	return ""
}

// withRulesLine puts the rules' name, as tego run's start line shows it, after the marker line every composed file opens with.
func withRulesLine(text []byte, rc rulesChoice) []byte {
	what := rc.label + " rules"
	if rc.label == "Your own choice" {
		what = "rules " + strings.Join(rc.presets, ", ")
	}
	first, rest, _ := strings.Cut(string(text), "\n")
	return []byte(first + "\n" + rulesLinePrefix + what + "\n" + rest)
}

// rulesLinePrefix opens the line withRulesLine writes; quietRun reads it back.
const rulesLinePrefix = "# Chosen in tego start: "

// rulesNameLine is a rules file's top-level name: line.
var rulesNameLine = regexp.MustCompile(`(?m)^name:.*$`)

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
func (g *walk) saveAgent(ctx context.Context, m *config.Machine, a guideAgent, command, name, abs string, rc *rulesChoice, test bool, stderr io.Writer) (int, error) {
	replace := false
	if file, err := agentFile(m, name); err == nil {
		if _, err := os.Stat(file); err == nil {
			items := yesNoItems("Writes the new rules over them", "Keeps the rules it has", false)
			pick, err := g.chooseOne("Agent "+name+" already exists. Replace its rules?", items)
			if err != nil {
				return 0, err
			}
			if items[pick].name == "No" {
				rc.label = "Kept file: " + tildeHome(file, m.Home)
				rc.file = file
				g.ok("Kept agent " + name)
				g.detail("Rules: " + tildeHome(file, m.Home))
				return identity.ExitOK, nil
			}
			replace = true
		}
	}
	var code int
	if rc.file != "" {
		_, code = saveOwnRules(m, name, abs, rc.file, replace, stderr)
	} else {
		_, code = guideSaveRules(ctx, m, a, command, name, abs, *rc, test, replace, stderr)
	}
	if code != identity.ExitOK {
		return code, nil
	}
	if rc.file != "" {
		g.ok("Created agent " + name + " from " + tildeHome(rc.file, m.Home))
		return identity.ExitOK, nil
	}
	g.ok("Created agent " + name)
	g.detail(rc.summary)
	g.detail("Presets: " + presetsDocURL)
	return identity.ExitOK, nil
}

// saveOwnRules saves a rules file the person wrote as the agent named name, in the user registry where tego run <name>
// finds it. Its name: line is set to name. replace atomically replaces an existing file.
func saveOwnRules(m *config.Machine, name, abs, file string, replace bool, stderr io.Writer) (string, int) {
	text, err := os.ReadFile(file)
	if err != nil {
		message(stderr, file, 0, 0, "tego start: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	if rulesNameLine.Match(text) {
		text = rulesNameLine.ReplaceAll(text, []byte("name: "+name))
	} else {
		text = append([]byte("name: "+name+"\n"), text...)
	}
	sv := registry.Save{Places: registry.Places{User: m.Registry.Value}, Name: name, Text: text, Writes: []string{abs}}
	path, err := saveGuideRules(sv, replace)
	if err != nil {
		message(stderr, path, 0, 0, "tego start: saving the rules file: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	return path, identity.ExitOK
}

// agentFile is where the agent named name's rules file lives in the user registry.
func agentFile(m *config.Machine, name string) (string, error) {
	return registry.Save{Places: registry.Places{User: m.Registry.Value}, Name: name}.Path()
}

// guideSaveRules composes an agent's rules file from rc, the way tego init --agent does, with the agent's own
// interactive program (its own approval prompts kept), and saves it in the user registry, outside the
// project, where tego run <name> finds it. replace atomically replaces an existing file.
func guideSaveRules(_ context.Context, m *config.Machine, a guideAgent, command, name, abs string, rc rulesChoice, test, replace bool, stderr io.Writer) (string, int) {
	dir, err := filepath.EvalSymlinks(abs)
	if err != nil {
		message(stderr, abs, 0, 0, "tego start: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	po := setup.Options{Presets: []string{strings.Join(rc.presets, ",")}, Hosts: rc.hosts,
		Agent: a.harness, Name: name, Dir: dir, Home: m.Home, ReadOnlyProject: !rc.writeProject}
	if rc.writeProject {
		po.Writes = []string{dir + "/"}
	}
	if a.harness == "" {
		po.Command = command
	} else {
		po.Interactive = true
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
	composed.Contract = withRulesLine(composed.Contract, rc)
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
	check := func() ([]agent.Diagnostic, bool) { return setup.CheckFile(composed.Contract, file, dir, env) }
	if po.ReadOnlyProject {
		check = func() ([]agent.Diagnostic, bool) {
			return setup.CheckReviewFile(composed.Contract, file, dir, env, reviewState(a))
		}
	}
	if ds, ok := check(); !ok {
		setup.Remove(made, dir)
		_ = agent.WriteDiagnostics(stderr, ds)
		return "", identity.ExitFinding
	}
	path, err := saveGuideRules(sv, replace)
	if err != nil {
		message(stderr, path, 0, 0, "tego start: saving the rules file: "+err.Error(), codeIO)
		return "", identity.ExitError
	}
	return path, identity.ExitOK
}

// saveGuideRules retains registry validation and publishes a replacement only after every byte is written.
func saveGuideRules(sv registry.Save, replace bool) (string, error) {
	if !replace {
		return sv.Write()
	}
	path, err := sv.Check()
	if err != nil {
		return path, err
	}
	if sv.Compile != nil {
		if err := sv.Compile(path, sv.Text); err != nil {
			return path, err
		}
	}
	err = replaceGuideFile(sv.Places.User, filepath.Join(registry.AgentsDir, sv.Name+".yaml"), sv.Text, 0600)
	return path, err
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

// lastProjectRel is where tego start keeps the project it set up last, under home: the Mac's tego shell opens there.
const lastProjectRel = ".config/tego/last-project"

// rememberProject records dir as the last project; a failure only means tego shell opens in home.
func rememberProject(home, dir string) {
	p := filepath.Join(home, lastProjectRel)
	if os.MkdirAll(filepath.Dir(p), 0o700) == nil {
		_ = os.WriteFile(p, []byte(dir+"\n"), 0o600)
	}
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
