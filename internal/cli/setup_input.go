// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	uv "github.com/charmbracelet/ultraviolet"
	"golang.org/x/sys/unix"
)

// guideTerminal keeps input raw across questions. Restoring canonical mode in
// between forms changes a typed-ahead Enter into LF. Output settings stay as
// they were, so the guide's ordinary lines still use the terminal's newlines.
type guideTerminal struct {
	file    *os.File
	saved   *unix.Termios
	input   *guideEvents
	stop    context.CancelFunc
	pending []tea.Msg
}

func openGuideTerminal(in io.Reader, stop context.CancelFunc) (*guideTerminal, error) {
	file, ok := in.(*os.File)
	if !ok || !isTerminalFile(file) {
		return nil, nil
	}
	term := &guideTerminal{file: file, stop: stop}
	if err := sys.FileDo(file, func(fd int) error {
		var err error
		term.saved, err = unix.IoctlGetTermios(fd, unix.TCGETS)
		return err
	}); err != nil {
		return nil, err
	}
	if err := term.raw(); err != nil {
		return nil, err
	}
	if err := term.start(); err != nil {
		_ = term.restore()
		return nil, err
	}
	return term, nil
}

func (t *guideTerminal) raw() error {
	raw := *t.saved
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	return sys.FileDo(t.file, func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, &raw) })
}
func (t *guideTerminal) restore() error {
	return sys.FileDo(t.file, func(fd int) error { return unix.IoctlSetTermios(fd, unix.TCSETS, t.saved) })
}

// guideInput is the guide's cancellable terminal source. Closing it wakes and
// joins the active Read without flushing terminal bytes or letting a Program
// close descriptors that Ultraviolet's nested reader is still using.
type guideInput struct {
	file               *os.File
	wakeRead, wakePeer *sys.FD
	mu                 sync.Mutex
	once               sync.Once
	finishOnce         sync.Once
	closed             bool
	remaining          int
}

func newGuideInput(file *os.File) (*guideInput, error) {
	r, w, err := sys.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return &guideInput{file: file, wakeRead: r, wakePeer: w, remaining: -1}, nil
}
func (r *guideInput) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, io.EOF
	}
	err = sys.FileDo(r.file, func(fd int) error {
		return r.wakeRead.Borrow(func(wake int) error {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(wake), Events: unix.POLLIN}}
			for {
				if _, err := unix.Poll(fds, -1); errors.Is(err, unix.EINTR) {
					continue
				} else if err != nil {
					return err
				}
				input := p
				if fds[1].Revents != 0 {
					// Finish the bytes already pending through the same decoder.
					// A blind flush could discard Ctrl-C, including CSI-u keys.
					// Snapshot the byte count so new input cannot prolong shutdown.
					if r.remaining < 0 {
						var err error
						r.remaining, err = unix.IoctlGetInt(fd, unix.TIOCINQ)
						if err != nil {
							return err
						}
					}
					if r.remaining == 0 || fds[0].Revents&unix.POLLIN == 0 {
						return io.EOF
					}
					input = p[:min(len(p), r.remaining)]
				}
				n, err = unix.Read(fd, input)
				if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
					continue
				}
				if n == 0 && err == nil {
					return io.EOF
				}
				if r.remaining >= 0 {
					r.remaining -= max(n, 0)
				}
				return err
			}
		})
	})
	return max(n, 0), err
}
func (r *guideInput) finish() {
	// Wake Poll without closing any descriptor still borrowed by Read.
	r.finishOnce.Do(func() { _ = r.wakePeer.Close() })
}
func (r *guideInput) close() {
	r.once.Do(func() {
		r.finish()
		r.mu.Lock()
		defer r.mu.Unlock()
		r.closed = true
		_ = r.wakeRead.Close()
	})
}

// guideEvents owns the decoder and its queue for the whole guide. A form takes
// one event at a time and stops taking events as soon as a valid answer submits.
// In particular, keys already decoded for the next question stay in this queue.
type guideEvents struct {
	events chan tea.Msg
	stop   chan struct{}
	done   chan struct{}
}

func (t *guideTerminal) start() error {
	reader, err := newGuideInput(t.file)
	if err != nil {
		return err
	}
	e := &guideEvents{events: make(chan tea.Msg), stop: make(chan struct{}), done: make(chan struct{})}
	t.input = e
	ctx, cancel := context.WithCancel(context.Background())
	decoded := make(chan uv.Event)
	parsed := make(chan struct{})
	go func() {
		defer close(parsed)
		// The guide, rather than a question's Program, owns this scanner and joins
		// both its event loop and the blocking Read before releasing the terminal.
		_ = uv.NewTerminalReader(reader, os.Getenv("TERM")).StreamEvents(ctx, decoded)
	}()
	go func() {
		defer close(e.done)
		queue := t.pending
		t.pending = nil
		enqueue := func(event tea.Msg) {
			if key, ok := event.(uv.KeyPressEvent); ok && tea.KeyPressMsg(key).String() == "ctrl+c" {
				t.stop()
				return
			}
			queue = append(queue, event)
		}
		for {
			var send chan tea.Msg
			var first tea.Msg
			if len(queue) > 0 {
				send = e.events
				first = queue[0]
			}
			select {
			case event := <-decoded:
				enqueue(event)
			case send <- first:
				queue[0] = nil
				queue = queue[1:]
			case <-parsed:
				t.stop()
				// Keep this goroutine available for close, including an input error.
				<-e.stop
				reader.close()
				cancel()
				t.pending = queue
				return
			case <-e.stop:
				reader.finish()
				// Read now returns EOF. Let the decoder finish naturally and
				// drain every event before canceling: canceling StreamEvents
				// first can discard bytes its nested goroutine already read.
				for {
					select {
					case event := <-decoded:
						enqueue(event)
					case <-parsed:
						reader.close()
						cancel()
						t.pending = queue
						return
					}
				}
			}
		}
	}()
	return nil
}
func (t *guideTerminal) pause() {
	if t.input != nil {
		close(t.input.stop)
		<-t.input.done
		t.input = nil
	}
}

// discardInput decodes pending terminal bytes before dropping the queue, so
// cancellation keys survive a secret boundary while secret tails do not.
func (t *guideTerminal) discardInput() error {
	if t.file == nil {
		return nil // an adapter-only caller has no terminal queue
	}
	if t.input == nil {
		if err := t.start(); err != nil {
			return err
		}
	}
	t.pause()
	t.pending = nil
	return t.start()
}

func (t *guideTerminal) close() error { t.pause(); return t.restore() }
func (e *guideEvents) next(ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		select {
		case event := <-e.events:
			return guideReadMsg{event}
		case <-ctx.Done():
			return nil
		}
	}
}

// guideForm leaves rendering and validation with Huh. Only the input command
// belongs to the guide: after Enter submits this single-field form, no
// further queued key is taken until the next question has initialized.
type guideForm struct {
	form    *huh.Form
	field   *hinted
	input   *guideEvents
	ctx     context.Context
	reading bool
}

func (m *guideForm) Init() tea.Cmd  { return tea.Batch(m.form.Init(), m.input.next(m.ctx)) }
func (m *guideForm) View() tea.View { v := tea.NewView(m.form.View()); v.ReportFocus = true; return v }

type guideReadMsg struct{ event tea.Msg }
type guideContinueMsg struct{}

func (m *guideForm) filter(_ tea.Model, msg tea.Msg) tea.Msg {
	if read, ok := msg.(guideReadMsg); ok {
		m.reading = true
		return guideEvent(read.event)
	}
	return msg
}
func (m *guideForm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(guideContinueMsg); ok {
		if m.form.State == huh.StateNormal && !m.field.finished {
			return m, m.input.next(m.ctx)
		}
		return m, nil
	}
	reading := m.reading
	m.reading = false
	_, cmd := m.form.Update(msg)
	if !reading || m.form.State != huh.StateNormal {
		return m, cmd
	}
	// Let the field's commands (including NextField) reach the form before
	// asking for another key. Blur is Huh's confirmation that this field
	// finished; Enter may merely finish a select or checklist filter.
	if key, ok := msg.(tea.KeyPressMsg); ok && key.String() == "enter" {
		return m, tea.Sequence(cmd, func() tea.Msg { return guideContinueMsg{} })
	}
	return m, tea.Batch(cmd, m.input.next(m.ctx))
}

// Events delivered by a command bypass Bubble Tea's input reader, so adapt the
// decoded events to the same public messages its reader normally supplies.
func guideEvent(event tea.Msg) tea.Msg {
	switch e := event.(type) {
	case uv.KeyPressEvent:
		return tea.KeyPressMsg(e)
	case uv.KeyReleaseEvent:
		return tea.KeyReleaseMsg(e)
	case uv.PasteEvent:
		return tea.PasteMsg(e)
	case uv.PasteStartEvent:
		return tea.PasteStartMsg(e)
	case uv.PasteEndEvent:
		return tea.PasteEndMsg(e)
	case uv.FocusEvent:
		return tea.FocusMsg(e)
	case uv.BlurEvent:
		return tea.BlurMsg(e)
	case uv.MouseClickEvent:
		return tea.MouseClickMsg(e)
	case uv.MouseReleaseEvent:
		return tea.MouseReleaseMsg(e)
	case uv.MouseWheelEvent:
		return tea.MouseWheelMsg(e)
	case uv.MouseMotionEvent:
		return tea.MouseMotionMsg(e)
	case uv.ClipboardEvent:
		return tea.ClipboardMsg(e)
	case uv.ForegroundColorEvent:
		return tea.ForegroundColorMsg(e)
	case uv.BackgroundColorEvent:
		return tea.BackgroundColorMsg(e)
	case uv.CursorColorEvent:
		return tea.CursorColorMsg(e)
	case uv.CursorPositionEvent:
		return tea.CursorPositionMsg(e)
	case uv.CapabilityEvent:
		return tea.CapabilityMsg(e)
	case uv.TerminalVersionEvent:
		return tea.TerminalVersionMsg(e)
	case uv.KeyboardEnhancementsEvent:
		return tea.KeyboardEnhancementsMsg(e)
	case uv.ModeReportEvent:
		return tea.ModeReportMsg(e)
	case uv.WindowSizeEvent:
		return tea.WindowSizeMsg(e)
	}
	return event
}
func (t *guideTerminal) runForm(ctx context.Context, form *huh.Form, field *hinted, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	form.SubmitCmd, form.CancelCmd = tea.Quit, tea.Interrupt
	model := &guideForm{form: form, field: field, input: t.input, ctx: ctx}
	_, err := tea.NewProgram(model, tea.WithInput(nil), tea.WithOutput(out), tea.WithContext(ctx), tea.WithoutSignalHandler(), tea.WithFilter(model.filter)).Run()
	if field.mask && form.State == huh.StateCompleted {
		if flushErr := t.discardInput(); err == nil {
			err = flushErr
		}
	}
	if form.State == huh.StateAborted || errors.Is(err, tea.ErrInterrupted) {
		return huh.ErrUserAborted
	}
	return err
}
func (g *walk) setupToken(ctx context.Context, program, home string) (string, error) {
	if g.terminal == nil {
		return guideSetupToken(ctx, program, home)
	}
	g.terminal.pause()
	g.terminal.pending = nil
	if err := g.terminal.restore(); err != nil {
		return "", err
	}
	token, err := guideSetupToken(ctx, program, home)
	if rawErr := g.terminal.raw(); err == nil {
		err = rawErr
	}
	if startErr := g.terminal.discardInput(); err == nil {
		err = startErr
	}
	return token, err
}

// readLine keeps accessible prompts on the same cancellable input owner. The
// tty itself never echoes a hidden entry, and no password reader can survive
// cancellation with echo disabled.
func (t *guideTerminal) readLine(ctx context.Context, out io.Writer, secret bool) (string, error) {
	var line []rune
	for {
		select {
		case <-ctx.Done():
			return "", errStopped
		case event := <-t.input.events:
			text := ""
			switch event := guideEvent(event).(type) {
			case tea.KeyPressMsg:
				switch event.String() {
				case "enter", "ctrl+j":
					fmt.Fprintln(out)
					return string(line), nil
				case "backspace", "ctrl+h", "ctrl+u":
					n := min(1, len(line))
					if event.String() == "ctrl+u" {
						n = len(line)
					}
					line = line[:len(line)-n]
					if !secret {
						fmt.Fprint(out, strings.Repeat("\b \b", n))
					}
					continue
				case "ctrl+d":
					if len(line) == 0 {
						t.stop()
						return "", errStopped
					}
				}
				text = event.Text
			case tea.PasteMsg:
				text = event.Content
			}
			line = append(line, []rune(text)...)
			if !secret {
				fmt.Fprint(out, text)
			}
		}
	}
}

func (g *walk) accessibleNumber(low, high int, defaultValue bool) (int, error) {
	for {
		fmt.Fprintf(g.out, "Enter a number between %d and %d: ", low, high)
		line, err := g.terminal.readLine(g.ctx, g.out, false)
		if err != nil {
			return 0, err
		}
		if strings.TrimSpace(line) == "" && defaultValue {
			return low, nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && n >= low && n <= high {
			return n, nil
		}
		fmt.Fprintf(g.out, "Invalid: must be a number between %d and %d\n", low, high)
	}
}
func (g *walk) accessibleSelect(q string, items []choice) (int, error) {
	fmt.Fprintln(g.out, g.question(q)+" ")
	for i, label := range g.labels(items) {
		fmt.Fprintf(g.out, "%d. %s\n", i+1, label)
	}
	pick, err := g.accessibleNumber(1, len(items), true)
	fmt.Fprintln(g.out)
	return pick - 1, err
}
func (g *walk) accessibleSeveral(q string, items []choice) ([]int, error) {
	fmt.Fprintln(g.out, g.question(q)+" ")
	fmt.Fprintf(g.out, "Select up to %d options.\n", len(items))
	checked := make([]bool, len(items))
	for i, item := range items {
		checked[i] = item.checked
	}
	labels := g.labels(items)
	for {
		for i, label := range labels {
			mark := " "
			if checked[i] {
				mark = "✓"
			}
			fmt.Fprintf(g.out, "%d. %s %s\n", i+1, mark, label)
		}
		fmt.Fprintln(g.out, "0.   Confirm selection")
		pick, err := g.accessibleNumber(0, len(items), false)
		if err != nil {
			return nil, err
		}
		if pick > 0 {
			checked[pick-1] = !checked[pick-1]
			fmt.Fprintln(g.out)
			continue
		}
		var selected []int
		for i, yes := range checked {
			if yes {
				selected = append(selected, i)
			}
		}
		if len(selected) > 0 {
			fmt.Fprintln(g.out)
			return selected, nil
		}
		fmt.Fprintln(g.out, "keep at least one checked")
	}
}
func (g *walk) accessibleText(q string, secret bool, valid func(string) error) (string, error) {
	for {
		fmt.Fprint(g.out, g.question(q)+" ")
		line, err := g.terminal.readLine(g.ctx, g.out, secret)
		if err != nil {
			return "", err
		}
		if valid != nil {
			if err := valid(line); err != nil {
				fmt.Fprintln(g.out, err)
				continue
			}
		}
		if secret {
			if err := g.terminal.discardInput(); err != nil {
				return "", err
			}
		}
		fmt.Fprintln(g.out)
		return strings.TrimSpace(line), nil
	}
}
