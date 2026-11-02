// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// heldMutations runs act on an expendable locked thread whose private filter notifies the syscalls nrs, and serves
// every notification with the production Loop and a real broker (ADR 0047). Each ask the broker publishes is shown to
// during (once, while the syscall is held, before the answer) and answered by approve. It returns the asks in
// the order they were published, the ledger lines and act's error.
func heldMutations(t *testing.T, nrs []uint32, pol *Policy, act func() error, during func(ask.Summary), approve func(ask.Summary) bool) ([]ask.Summary, *testSink, error) {
	t.Helper()
	return heldMutationsWith(t, nrs, pol, Options{}, act, during, approve)
}

// heldMutationsWith is heldMutations with the loop's other options (opts.Ask is the harness's broker).
func heldMutationsWith(t *testing.T, nrs []uint32, pol *Policy, opts Options, act func() error, during func(ask.Summary), approve func(ask.Summary) bool) ([]ask.Summary, *testSink, error) {
	t.Helper()
	insns := []bpf.Instruction{bpf.LoadAbsolute{Off: 0, Size: 4}}
	for i, nr := range nrs {
		insns = append(insns, bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipTrue: uint8(len(nrs) - i)})
	}
	insns = append(insns, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}, bpf.RetConstant{Val: unix.SECCOMP_RET_USER_NOTIF})
	raw, err := bpf.Assemble(insns)
	if err != nil {
		t.Fatal(err)
	}
	type readyResult struct {
		ln  *sys.FD
		err error
	}
	ready, done := make(chan readyResult, 1), make(chan error, 1)
	var actor func()
	actor = func() {
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			go actor()
			runtime.UnlockOSThread()
			return
		}
		if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
			ready <- readyResult{nil, e}
			return
		}
		ln, e := sys.Strict(sys.SeccompNewListenerFD(raw))
		ready <- readyResult{ln, e}
		if e != nil {
			return
		}
		done <- act()
		// Exiting locked destroys this thread and its private filter.
	}
	go actor()
	r := <-ready
	if r.err != nil {
		t.Fatalf("listener: %v", r.err)
	}
	defer r.ln.Close() //nolint:errcheck // New took it and no Run closes it; a second Close is a no-op
	runDir := t.TempDir()
	broker, err := ask.New(runDir, ask.Options{UID: uint32(os.Getuid()), Timeout: 3 * time.Second, Authorize: func(ask.Peer) error { return nil }, Emit: func(ask.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	sink := &testSink{}
	opts.Ask = broker.Request
	l, err := New(r.ln, pol, sink, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer l.closeAskScopes()
	var mu sync.Mutex
	var asked []ask.Summary
	stop := make(chan struct{})
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		seen := map[string]bool{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			pending, e := ask.ListFor(ctx, runDir, os.Getpid())
			if e != nil {
				continue
			}
			for _, p := range pending {
				if seen[p.AskID] {
					continue
				}
				seen[p.AskID] = true
				mu.Lock()
				asked = append(asked, p)
				mu.Unlock()
				if during != nil {
					during(p)
				}
				_, _ = ask.AnswerFor(ctx, runDir, os.Getpid(), p.AskID, approve(p), false)
			}
		}
	}()
	var handlers sync.WaitGroup
	var actErr error
	// Once the actor's thread is gone the listener polls POLLHUP at once and has nothing to receive, so the loop ends
	// on the actor's result, never on the poll.
	deadline := time.Now().Add(15 * time.Second)
	for finished := false; !finished; {
		pfd := []unix.PollFd{{Events: unix.POLLIN}}
		if e := r.ln.Borrow(func(fd int) error {
			pfd[0].Fd = int32(fd)
			_, e := unix.Poll(pfd, 20)
			return e
		}); e != nil && !errors.Is(e, unix.EINTR) {
			t.Fatal(e)
		}
		if pfd[0].Revents&unix.POLLIN != 0 {
			var raw sys.SeccompNotif
			if e := r.ln.Borrow(func(fd int) error { return sys.SeccompNotifRecv(fd, &raw) }); e == nil {
				handlers.Add(1)
				go func() { defer handlers.Done(); l.handle(newNotif(&raw)) }()
				continue
			}
		}
		select {
		case actErr = <-done:
			finished = true
		default:
			if time.Now().After(deadline) {
				t.Fatal("the held syscalls did not finish")
			}
			if pfd[0].Revents&unix.POLLHUP != 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}
	handlers.Wait()
	close(stop)
	<-answered
	return asked, sink, actErr
}

// askScopePolicy is a tier-1 table whose fs.ask scopes are scopes, compiled as the compiler places them: in FSAsk and,
// with no rights, in FS.
func askScopePolicy(scopes ...string) *Policy {
	var rules []agent.FSRule
	for _, s := range scopes {
		rules = append(rules, agent.FSRule{Path: s, Resolved: s, Kind: agent.FSAsk, Raw: s})
	}
	pol := testPolicy(nil, append([]agent.FSRule(nil), rules...), nil)
	pol.Rules.Tier = backend.TierLandlock
	pol.Rules.FSAsk = rules
	return pol
}

var mutationNRs = []uint32{unix.SYS_UNLINKAT, unix.SYS_MKDIRAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2, unix.SYS_SYMLINKAT, unix.SYS_LINKAT, unix.SYS_OPENAT}

type mutationLine struct {
	record.FSPayload
	GateFields
	OperationCompleted bool   `json:"operation_completed"`
	ResultUnknown      bool   `json:"result_unknown"`
	SyscallRet         *int64 `json:"syscall_ret"`
}

func lineOf(t *testing.T, ev *record.Event) mutationLine {
	t.Helper()
	var m mutationLine
	if err := json.Unmarshal(ev.Payload, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustWrite(t *testing.T, p, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// shown reports whether a listed ask's name is want as the list shows it: whole, or, for a name over the list's 128
// bytes, its first 128 bytes with the summary marked truncated.
func shown(s ask.Summary, got, want string) bool {
	if len(want) > 128 {
		return s.TargetTruncated && got == want[:128]
	}
	return got == want
}

func readOr(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

// An approved rename in an fs.ask scope is made on the directory the ask pinned: a symlink the agent swaps during the
// hold (here outside the scope, where the agent may write) cannot redirect it (ADR 0047 (2), the TOCTOU harness).
func TestAskMutationRenameIsMadeOnThePinnedParentAfterASymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	scope := filepath.Join(dir, "scope")
	a, b, link := filepath.Join(scope, "a"), filepath.Join(scope, "b"), filepath.Join(dir, "work", "link")
	mustWrite(t, filepath.Join(a, "tmp"), "approved bytes")
	mustWrite(t, filepath.Join(b, "tmp"), "decoy")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	act := func() error {
		return unix.Renameat(unix.AT_FDCWD, filepath.Join(link, "tmp"), unix.AT_FDCWD, filepath.Join(link, "final"))
	}
	swap := func(ask.Summary) {
		_ = os.Remove(link)
		_ = os.Symlink(b, link)
	}
	asked, sink, err := heldMutations(t, mutationNRs, askScopePolicy(scope), act, swap, func(ask.Summary) bool { return true })
	if err != nil {
		t.Fatalf("approved rename: %v", err)
	}
	if len(asked) != 1 || asked[0].Op != record.FSRename || asked[0].Hold != ask.HoldMutation || !shown(asked[0], asked[0].Target, filepath.Join(a, "tmp")) || !shown(asked[0], asked[0].Target2, filepath.Join(a, "final")) {
		t.Fatalf("asks %+v", asked)
	}
	if got := readOr(filepath.Join(a, "final")); got != "approved bytes" {
		t.Fatalf("pinned destination holds %q", got)
	}
	if _, err := os.Lstat(filepath.Join(a, "tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pinned source still there: %v", err)
	}
	if got := readOr(filepath.Join(b, "tmp")); got != "decoy" {
		t.Fatalf("swapped-in directory changed: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(b, "final")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the rename was redirected into the swapped directory: %v", err)
	}
	ev := sink.one(t)
	m := lineOf(t, ev)
	if ev.Kind != record.KindFS || ev.Authority != record.AuthorityHuman || ev.Verdict != record.VerdictAllow || m.Op != record.FSRename ||
		m.Path != filepath.Join(a, "tmp") || m.Path2 != filepath.Join(a, "final") || !m.OperationCompleted || m.SyscallRet == nil || *m.SyscallRet != 0 {
		t.Fatalf("line %+v %+v", ev, m)
	}
}

// Each mutation the person answers is completed or refused as answered, with one line saying which.
func TestAskMutationEachOpApprovedOrDenied(t *testing.T) {
	type tc struct {
		name    string
		op      string
		setup   func(t *testing.T, scope string)
		act     func(scope string) error
		approve bool
		check   func(t *testing.T, scope string)
	}
	exists := func(t *testing.T, p string, want bool) {
		t.Helper()
		_, err := os.Lstat(p)
		if (err == nil) != want {
			t.Fatalf("%s exists=%v, want %v (%v)", p, err == nil, want, err)
		}
	}
	cases := []tc{
		{"unlink approved", record.FSUnlink, func(t *testing.T, s string) { mustWrite(t, filepath.Join(s, "f"), "x") },
			func(s string) error { return unix.Unlinkat(unix.AT_FDCWD, filepath.Join(s, "f"), 0) }, true,
			func(t *testing.T, s string) { exists(t, filepath.Join(s, "f"), false) }},
		{"unlink denied", record.FSUnlink, func(t *testing.T, s string) { mustWrite(t, filepath.Join(s, "f"), "x") },
			func(s string) error { return unix.Unlinkat(unix.AT_FDCWD, filepath.Join(s, "f"), 0) }, false,
			func(t *testing.T, s string) { exists(t, filepath.Join(s, "f"), true) }},
		{"rmdir approved", record.FSUnlink, func(t *testing.T, s string) { _ = os.MkdirAll(filepath.Join(s, "d"), 0o755) },
			func(s string) error {
				return unix.Unlinkat(unix.AT_FDCWD, filepath.Join(s, "d")+"/", unix.AT_REMOVEDIR)
			}, true,
			func(t *testing.T, s string) { exists(t, filepath.Join(s, "d"), false) }},
		{"mkdir approved", record.FSMkdir, func(*testing.T, string) {},
			func(s string) error { return unix.Mkdirat(unix.AT_FDCWD, filepath.Join(s, "new"), 0o750) }, true,
			func(t *testing.T, s string) {
				st, err := os.Lstat(filepath.Join(s, "new"))
				if err != nil || !st.IsDir() || st.Mode().Perm()&^0o750 != 0 {
					t.Fatalf("mkdir made %v %v", st, err)
				}
			}},
		{"symlink approved", record.FSSymlink, func(*testing.T, string) {},
			func(s string) error { return unix.Symlinkat("target-text", unix.AT_FDCWD, filepath.Join(s, "ln")) }, true,
			func(t *testing.T, s string) {
				if got, err := os.Readlink(filepath.Join(s, "ln")); err != nil || got != "target-text" {
					t.Fatalf("symlink %q %v", got, err)
				}
			}},
		{"link approved", record.FSLink, func(t *testing.T, s string) { mustWrite(t, filepath.Join(s, "f"), "x") },
			func(s string) error {
				return unix.Linkat(unix.AT_FDCWD, filepath.Join(s, "f"), unix.AT_FDCWD, filepath.Join(s, "g"), 0)
			}, true,
			func(t *testing.T, s string) {
				if got := readOr(filepath.Join(s, "g")); got != "x" {
					t.Fatalf("link %q", got)
				}
			}},
		{"rename denied", record.FSRename, func(t *testing.T, s string) { mustWrite(t, filepath.Join(s, "f"), "x") },
			func(s string) error {
				return unix.Renameat(unix.AT_FDCWD, filepath.Join(s, "f"), unix.AT_FDCWD, filepath.Join(s, "g"))
			}, false,
			func(t *testing.T, s string) {
				exists(t, filepath.Join(s, "f"), true)
				exists(t, filepath.Join(s, "g"), false)
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope := filepath.Join(t.TempDir(), "scope")
			if err := os.MkdirAll(scope, 0o755); err != nil {
				t.Fatal(err)
			}
			c.setup(t, scope)
			asked, sink, err := heldMutations(t, mutationNRs, askScopePolicy(scope), func() error { return c.act(scope) }, nil, func(ask.Summary) bool { return c.approve })
			if len(asked) != 1 || asked[0].Op != c.op || asked[0].Hold != ask.HoldMutation {
				t.Fatalf("asks %+v", asked)
			}
			if c.approve != (err == nil) || (!c.approve && !errors.Is(err, unix.EACCES)) {
				t.Fatalf("syscall answered %v (approve %v)", err, c.approve)
			}
			c.check(t, scope)
			ev := sink.one(t)
			if c.approve && (ev.Authority != record.AuthorityHuman || ev.Verdict != record.VerdictAllow || !lineOf(t, ev).OperationCompleted) {
				t.Fatalf("approved line %+v", ev)
			}
			if !c.approve && (ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonAskDenied || lineOf(t, ev).Op != c.op) {
				t.Fatalf("denied line %+v", ev)
			}
		})
	}
}

// A rename or link whose ends lie in different entries is refused as unsupported, EXDEV, without asking anyone: the
// kernel's own answer to a move across what it cannot carry rights over, so a tool falls back to copy and unlink,
// each asked where it lands (ADR 0047 (3)).
func TestAskMutationCrossEntryRenameIsRefusedUnsupported(t *testing.T) {
	dir := t.TempDir()
	s1, s2, outside := filepath.Join(dir, "s1"), filepath.Join(dir, "s2"), filepath.Join(dir, "outside")
	mustWrite(t, filepath.Join(s1, "f"), "x")
	if err := os.MkdirAll(s2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{filepath.Join(s2, "f"), filepath.Join(outside, "f")} {
		act := func() error { return unix.Renameat(unix.AT_FDCWD, filepath.Join(s1, "f"), unix.AT_FDCWD, to) }
		asked, sink, err := heldMutations(t, mutationNRs, askScopePolicy(s1, s2), act, nil, func(ask.Summary) bool { return true })
		if !errors.Is(err, unix.EXDEV) || len(asked) != 0 {
			t.Fatalf("rename to %s: %v, asks %+v", to, err, asked)
		}
		if got := readOr(filepath.Join(s1, "f")); got != "x" {
			t.Fatalf("source moved: %q", got)
		}
		ev := sink.one(t)
		if m := lineOf(t, ev); ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonRenameOutsideContract || !m.CompletionUnsupported || m.Path2 != to {
			t.Fatalf("line %+v %+v", ev, m)
		}
	}
}

// A mutation beneath no scope keeps the path it had before ADR 0047, in a run with scopes too: it is continued for the
// kernel to decide (this harness has no Landlock, so it runs), nobody is asked, and a deny_read elsewhere does not turn
// it into the supervisor's own refusal.
func TestAskMutationBeneathNoScopeKeepsItsPath(t *testing.T) {
	dir := t.TempDir()
	scope, secret := filepath.Join(dir, "scope"), filepath.Join(dir, "secret")
	mustWrite(t, filepath.Join(scope, "f"), "x")
	mustWrite(t, filepath.Join(secret, "f"), "x")
	pol := askScopePolicy(scope)
	pol.Rules.FS = append(pol.Rules.FS, agent.FSRule{Path: secret, Resolved: secret, Kind: agent.FSDenyRead, Raw: secret})
	asked, _, err := heldMutations(t, mutationNRs, pol, func() error { return unix.Unlinkat(unix.AT_FDCWD, filepath.Join(secret, "f"), 0) }, nil, func(ask.Summary) bool { return true })
	if err != nil || len(asked) != 0 {
		t.Fatalf("unlink beneath no scope: %v, asks %+v", err, asked)
	}
}

// No approval reaches a protected target or a directory above one (deny_write's ancestors, space 4): the mutation is
// refused before anyone is asked.
func TestAskMutationNeverReachesADenyWriteTargetOrItsAncestor(t *testing.T) {
	var scope string // each case's own, made afresh below
	acts := map[string]func() error{
		"rename the target's parent": func() error {
			return unix.Renameat(unix.AT_FDCWD, filepath.Join(scope, ".claude"), unix.AT_FDCWD, filepath.Join(scope, "moved"))
		},
		"unlink inside the target": func() error {
			return unix.Unlinkat(unix.AT_FDCWD, filepath.Join(scope, ".claude", "settings.json"), 0)
		},
		"rename onto the target": func() error {
			return unix.Renameat(unix.AT_FDCWD, filepath.Join(scope, "f"), unix.AT_FDCWD, filepath.Join(scope, ".claude", "settings.json"))
		},
		"link into the target": func() error {
			return unix.Linkat(unix.AT_FDCWD, filepath.Join(scope, "f"), unix.AT_FDCWD, filepath.Join(scope, ".claude", "x"), 0)
		},
	}
	for name, act := range acts {
		t.Run(name, func(t *testing.T) {
			scope = filepath.Join(t.TempDir(), "scope")
			mustWrite(t, filepath.Join(scope, ".claude", "settings.json"), "{}")
			mustWrite(t, filepath.Join(scope, "f"), "x")
			pol := askScopePolicy(scope)
			target := filepath.Join(scope, ".claude")
			pol.Rules.AskDenyWrite = []agent.FSRule{{Path: target, Resolved: target, Kind: agent.FSDenyWrite, BuiltIn: true}}
			asked, sink, err := heldMutations(t, mutationNRs, pol, act, nil, func(ask.Summary) bool { return true })
			if !errors.Is(err, unix.EACCES) || len(asked) != 0 {
				t.Fatalf("%v, asks %+v", err, asked)
			}
			if got := readOr(filepath.Join(scope, ".claude", "settings.json")); got != "{}" {
				t.Fatalf("target changed: %q", got)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != pol.Rules.AskDenyWrite[0].RuleName() {
				t.Fatalf("line %+v", ev)
			}
		})
	}
}

// The owner's question (ADR 0047 (4)): Claude Code's Write tool writes a temporary file and renames it over the file.
// An approved open of the temporary file does not license the rename: the rename is asked by itself, naming both ends,
// and only its own approval makes it.
func TestAskMutationAnApprovedOpenDoesNotLicenseTheRename(t *testing.T) {
	scope := filepath.Join(t.TempDir(), "scope")
	mustWrite(t, filepath.Join(scope, "notes.md"), "old")
	tmp, final := filepath.Join(scope, "notes.md.tmp.1"), filepath.Join(scope, "notes.md")
	act := func() error {
		fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o644)
		if err != nil {
			return err
		}
		if _, err = unix.Write(fd, []byte("new")); err != nil {
			return err
		}
		if err = unix.Close(fd); err != nil {
			return err
		}
		return unix.Renameat(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final)
	}
	for _, renameApproved := range []bool{true, false} {
		_ = os.Remove(tmp)
		mustWrite(t, final, "old")
		asked, _, err := heldMutations(t, mutationNRs, askScopePolicy(scope), act, nil, func(s ask.Summary) bool { return s.Op != record.FSRename || renameApproved })
		if len(asked) != 2 || asked[0].Op != record.FSOpen || !shown(asked[0], asked[0].Target, tmp) || asked[1].Op != record.FSRename || !shown(asked[1], asked[1].Target, tmp) || !shown(asked[1], asked[1].Target2, final) {
			t.Fatalf("asks %+v", asked)
		}
		want := "new"
		if !renameApproved {
			want = "old"
			if !errors.Is(err, unix.EACCES) || readOr(tmp) != "new" {
				t.Fatalf("denied rename: %v, tmp %q", err, readOr(tmp))
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if got := readOr(final); got != want {
			t.Fatalf("rename approved=%v: final holds %q", renameApproved, got)
		}
	}
}

// A person's live block outranks the ask (liveFS, as for a held open): a mutation in an fs.ask scope under a write block
// is refused under the block before anyone is asked, and a block added while the person decides refuses the approved
// mutation, which is then not made.
func TestAskMutationALiveBlockRefusesBeforeAndAfterTheAsk(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "while held"}[during], func(t *testing.T) {
			scope := filepath.Join(t.TempDir(), "scope")
			f := filepath.Join(scope, "f")
			mustWrite(t, f, "x")
			block := liveSet(t, "write", scope)
			var set atomic.Pointer[liveblock.Set]
			var hook func(ask.Summary)
			if during {
				hook = func(ask.Summary) { set.Store(block) }
			} else {
				set.Store(block)
			}
			opts := Options{LiveBlocks: set.Load}
			asked, sink, err := heldMutationsWith(t, mutationNRs, askScopePolicy(scope), opts, func() error { return unix.Unlinkat(unix.AT_FDCWD, f, 0) }, hook, func(ask.Summary) bool { return true })
			if !errors.Is(err, unix.EACCES) || (len(asked) != 0) != during {
				t.Fatalf("unlink under a live block: %v, asks %+v", err, asked)
			}
			if got := readOr(f); got != "x" {
				t.Fatalf("the file was removed: %q", got)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || !strings.HasPrefix(ev.Rule, "live.block[write:") {
				t.Fatalf("line %+v", ev)
			}
		})
	}
}
