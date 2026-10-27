// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// How a person at the terminal learns that an ask waits (ADR 0122, G5). tego shares the terminal with the agent,
// often a full-screen TUI that owns every byte of it, so tego writes nothing into the terminal once the agent runs:
// a byte between two of the agent's writes can land inside one of its escape sequences and corrupt the screen, and
// tego cannot know when that is safe. It says what it has to say before the agent's first screen (askAnswerLine),
// and later only outside the terminal (the desktop notice below).

// askAnswerLine is the one line `tego run` prints, once the run exists and before its agent starts, when the
// contract can ask: the run id `tego ask` takes and the exact commands that answer. desktop says whether a desktop
// notice will also say when an ask waits.
func askAnswerLine(run identity.RunID, desktop bool) string {
	id := string(run)
	line := fmt.Sprintf("tego run: %s can hold an operation for your approval; answer from another terminal: tego ask %s, "+
		"then tego approve %s <ask_id> (or deny), or on the dashboard's Approvals page", id, id, id)
	if desktop {
		line += "; a desktop notice says when one waits"
	}
	return record.Printable(line) + "\n"
}

// askNotices says which notices a run gives: the answer line when the contract can ask and ask.notify holds cli, and
// the desktop notice when it holds desktop, the run is at tier landlock and its launcher is not root. Tier landlock's
// launcher places no fanotify mark (only enforce/cgroup arms, ADR 0021 (3)), so it may start a process during the
// run; and a root launcher does not start a program into the person's desktop session.
func askNotices(rt *agent.RuleTable, notify []string, tier backend.Tier, euid int) (line, desktop bool) {
	if rt == nil || rt.AskConfig == nil {
		return false, false
	}
	return slices.Contains(notify, "cli"), slices.Contains(notify, "desktop") && tier == backend.TierLandlock && euid != 0
}

// askNoticesFor is the run's two notices as runtime.Deps hooks (askNotices says which): started prints the answer
// line once the run exists, before its agent starts; askPending is the desktop notice's tell. stop ends the desktop
// notice once the run is over. A run whose desktop notice finds no notifier says why in tego's own log only, never on
// the terminal (the quiet start).
func askNoticesFor(rt *agent.RuleTable, m *config.Machine, tier backend.Tier, stderr io.Writer) (started func(tegoruntime.StartedRun) error,
	askPending func(tegoruntime.AskPending), stop func()) {
	stop = func() {}
	line, desktop := askNotices(rt, m.Ask.Notify.Value, tier, os.Geteuid())
	if desktop {
		bin, err := notifierPath(os.Getenv("PATH"))
		if err != nil {
			ownLogger(m).Info("run: no desktop notice for this run's asks", "why", err.Error())
			desktop = false
		} else {
			name := ""
			if rt.Contract != nil {
				name = rt.Contract.Name
			}
			n := newDesktopNotice(bin, notifierEnv(os.Environ()), name)
			askPending, stop = n.tell, n.stop
		}
	}
	if line {
		started = func(s tegoruntime.StartedRun) error {
			_, _ = io.WriteString(stderr, askAnswerLine(s.ID, desktop)) // a line that cannot be written does not end the run
			return nil
		}
	}
	return started, askPending, stop
}

// notifierPath finds the desktop notifier for a run whose environment's PATH is path: notify-send, trusted. A test
// build replaces it (asknotice_testhook.go), so no test reaches the person's own desktop.
var notifierPath = findNotifier

// errNoNotifier is a PATH with no trusted notify-send.
var errNoNotifier = errors.New("no notify-send owned by root and writable by root alone on PATH")

// findNotifier is the first notify-send on path (absolute entries only) that trustedExecutable accepts, by its real
// path, so the file run later is the one checked now, before the agent starts.
func findNotifier(path string) (string, error) {
	var why []string
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, "notify-send")
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err == nil {
			err = trustedExecutable(real)
		}
		if err == nil {
			return real, nil
		}
		why = append(why, err.Error())
	}
	if len(why) > 0 {
		return "", fmt.Errorf("%w (%s)", errNoNotifier, strings.Join(why, "; "))
	}
	return "", errNoNotifier
}

// trustedExecutable accepts a regular executable file that the run's agent cannot have written or replaced: it and
// every directory above it are owned by root and writable by no group or other. tego runs it outside the run, so a
// notify-send in a folder of the person's own (~/.local/bin, which a contract may let the agent write) is refused.
func trustedExecutable(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable regular file", p)
	}
	for at := p; ; at = filepath.Dir(at) {
		if at != p {
			if st, err = os.Lstat(at); err != nil {
				return err
			}
		}
		if !ownedByRoot(st) || st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not owned by root and writable by root alone", at)
		}
		if at == "/" {
			return nil
		}
	}
}

// ownedByRoot reports whether st's owner is root.
func ownedByRoot(st fs.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 0
}

// notifierEnv is the part of tego's own environment a desktop notifier needs to reach the session bus and show text:
// nothing else of the person's environment (a secret in it included) is handed to it.
func notifierEnv(environ []string) []string {
	keep := []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY", "HOME", "LANG", "LC_ALL", "LC_MESSAGES"}
	var env []string
	for _, kv := range environ {
		if k, _, ok := strings.Cut(kv, "="); ok && slices.Contains(keep, k) {
			env = append(env, kv)
		}
	}
	return env
}

// notifierTimeout bounds one notifier: one still running after it is killed.
const notifierTimeout = 5 * time.Second

// desktopNotice sends a desktop notice for each held request of one run, from tego's own process, outside the run.
// tell never waits: at most one notifier runs and one request waits behind it, and a request told while one waits is
// dropped (a burst of asks gives two notices, and `tego ask` lists them all).
type desktopNotice struct {
	bin, agent string
	env        []string
	queue      chan tegoruntime.AskPending
	cancel     context.CancelFunc
	done       sync.WaitGroup
}

// newDesktopNotice starts the notice's worker for notifier bin (an absolute path), run with env, naming agent.
func newDesktopNotice(bin string, env []string, agent string) *desktopNotice {
	ctx, cancel := context.WithCancel(context.Background())
	n := &desktopNotice{bin: bin, agent: agent, env: env, queue: make(chan tegoruntime.AskPending, 1), cancel: cancel}
	n.done.Go(func() { n.work(ctx) })
	return n
}

// tell queues p, or drops it when one already waits. It is Deps.AskPending.
func (n *desktopNotice) tell(p tegoruntime.AskPending) {
	select {
	case n.queue <- p:
	default:
	}
}

// stop ends the worker, killing a notifier still running, and waits for it.
func (n *desktopNotice) stop() {
	n.cancel()
	n.done.Wait()
}

// work runs one notifier per queued request until ctx ends.
func (n *desktopNotice) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-n.queue:
			n.send(ctx, p)
		}
	}
}

// send runs the notifier for p and waits for it, at most notifierTimeout or until ctx ends.
func (n *desktopNotice) send(ctx context.Context, p tegoruntime.AskPending) {
	summary := "Tego: approval waiting"
	body := fmt.Sprintf("%s waits for your answer (%s). Run: tego ask %s", markupText(n.agent), markupText(p.Op), markupText(string(p.Run)))
	cmd, err := startNotifier(n.bin, []string{"-a", "tego", "--", summary, body}, n.env)
	if err != nil {
		return
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	timer := time.NewTimer(notifierTimeout)
	defer timer.Stop()
	select {
	case <-exited:
		return
	case <-timer.C:
	case <-ctx.Done():
	}
	_ = cmd.Process.Kill() // a notifier that hangs (no session bus answering) is not the run's to wait for
	<-exited
}

// markupText is s with control bytes made visible (record.Printable) and the notification markup's three special
// characters escaped, so a name shows as text and never as markup a notification server would act on.
func markupText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(record.Printable(s))
}

// startNotifier starts the notifier: argv only, no shell; no standard stream of tego's (the null device), so it can
// neither write into the agent's terminal nor read from it; and a session of its own, outside the terminal's
// foreground group, so a Ctrl-C meant for the agent does not reach it. It runs only in a tier-landlock run of a
// non-root launcher (askNotices), whose process places no fanotify mark; proc.Start refuses it with ErrArmed while
// any exists.
func startNotifier(bin string, argv, env []string) (*proc.Cmd, error) {
	cmd := proc.Command(bin, argv...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if _, err := proc.Start(cmd); err != nil {
		return nil, err
	}
	return cmd, nil
}
