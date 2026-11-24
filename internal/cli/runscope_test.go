// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runscope"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	rtcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/selftest"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// scopeContract is a rules file that loads, in a folder of its own: since round 5 a run checks its rules file before it
// opens a user scope (rulesBeforeScope), so the scope's own tests name one that passes those checks.
func scopeContract(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte("version: 0\nname: scope\ncommand: [\"/bin/true\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scopeStands(t *testing.T) {
	t.Helper()
	a, b, c, d, e, f := scopePlacement, scopeExec, scopePaths, selfAnswer, scopeOpener, scopeInitCgroup
	scopeInitCgroup = func() bool { return true }
	scopePlacement = func() error { return rtcgroup.ErrBesideSubtree }
	selfAnswer = answerOutside
	scopePaths = func() (string, string, error) { return "/usr/bin/systemd-run", "/proc/123/exe", nil }
	scopeOpener = func() guide.Opening { return guide.Opening{Command: guide.DefaultScope} }
	t.Cleanup(func() {
		scopePlacement, scopeExec, scopePaths, selfAnswer, scopeOpener, scopeInitCgroup = a, b, c, d, e, f
	})
	hintsAt(t, false, "on")
}

// Every entry is intercepted before command startup. Even watch's generated contract and test's decoys must not
// exist yet. A stand-in re-exec returns an unusual agent exit code without ever reaching the run path.
func TestScopeBeforeAnyRunState(t *testing.T) {
	contract := scopeContract(t)
	for _, args := range [][]string{
		{"run", contract, "--offline", "--", "echo", "$HOME", "", "a\nb", string([]byte{0xff})},
		{"watch", "--", "echo", "$HOME"}, {"test"},
	} {
		t.Run(args[0], func(t *testing.T) {
			scopeStands(t)
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(root, "tego.yaml")
			if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(root, "runs")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEGO_CONFIG", cfg)
			before, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			oldGuard, oldSelfTest := machineGuard, selftestRun
			machineGuard = func(*config.Machine) error {
				if args[0] == "run" {
					return nil // read-only: the rules file is checked before the scope (rulesBeforeScope); no state is made
				}
				t.Error("configuration reached before scope; run state could be made")
				return errors.New("unexpected config load")
			}
			selftestRun = func(context.Context, selftest.Options) (selftest.Report, error) {
				t.Error("selftest reached before scope; decoys or run ids could be made")
				return selftest.Report{}, errors.New("unexpected selftest")
			}
			t.Cleanup(func() { machineGuard, selftestRun = oldGuard, oldSelfTest })
			called := 0
			scopeExec = func(_ context.Context, p scopePlan, _ io.Writer) (int, error) {
				called++
				want := append([]string{"tego"}, args...)
				if !reflect.DeepEqual(p.Request.Argv, want) {
					t.Errorf("argv %q, want %q", p.Request.Argv, want)
				}
				if !filepath.IsAbs(p.Runner) || !filepath.IsAbs(p.Binary) {
					t.Errorf("relative executable: %+v", p)
				}
				if !reflect.DeepEqual(p.Request.Env, os.Environ()) {
					t.Error("environment changed")
				}
				entries, _ := os.ReadDir(root)
				if !reflect.DeepEqual(entries, before) {
					t.Error("run state before scope")
				}
				return 37, nil
			}
			// These hooks fail the test before a ledger/id could be allocated, even if another path later ignores exit 37.
			prev := startRun
			startRun = func(ctx context.Context, rt *agent.RuleTable, command []string, deps tegoruntime.Deps) (tegoruntime.Result, error) {
				t.Error("runtime reached: a run id or ledger could be allocated")
				return tegoruntime.Result{}, errors.New("unexpected run")
			}
			t.Cleanup(func() { startRun = prev })
			code, _, errs := run(t, args...)
			if code != 37 || called != 1 || strings.Contains(errs, "next:") {
				t.Fatalf("exit=%d calls=%d stderr=%s", code, called, errs)
			}
		})
	}
}

func TestScopeFailuresKeepTheOldNextLine(t *testing.T) {
	for _, cause := range []string{"systemd-run missing", "manager refused", "user scope startup timed out", "re-entry still outside"} {
		t.Run(cause, func(t *testing.T) {
			scopeStands(t)
			scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { return 0, errors.New(cause) }
			if cause == "systemd-run missing" {
				scopePaths = func() (string, string, error) { return "", "", errors.New(cause) }
			}
			for _, args := range [][]string{{"run", scopeContract(t)}, {"watch", "--", "true"}, {"test"}} {
				code, _, errs := run(t, args...)
				want := "\nnext: open a shell in your user manager's cgroup, then run this again there:\n  " + guide.DefaultScope + "\n"
				if code != identity.ExitLauncher || !strings.Contains(errs, cause) || !strings.HasSuffix(errs, want) {
					t.Errorf("%s exit %d:\n%s", args[0], code, errs)
				}
			}
		})
	}
}

func TestScopeGuardAndNestedRun(t *testing.T) {
	for _, tc := range []struct {
		name  string
		once  bool
		self  func() runscope.Answer
		place error
	}{
		{name: "re-entry", once: true, self: answerOutside, place: rtcgroup.ErrBesideSubtree},
		{name: "nested", self: answerGoverned, place: rtcgroup.ErrBesideSubtree},
		{name: "the zero answer", self: func() runscope.Answer { return runscope.Answer{} }, place: rtcgroup.ErrBesideSubtree},
		{name: "an unreadable path", self: func() runscope.Answer {
			return answertest.Inside(runscope.CausePathUnreadable)
		}, place: rtcgroup.ErrBesideSubtree},
		{name: "already placed", self: answerOutside}, {name: "no manager", self: answerOutside, place: rtcgroup.ErrNoUserManager},
		{name: "unreadable placement", self: answerOutside, place: os.ErrPermission},
		{name: "unknown, already placed", self: answerUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scopeStands(t)
			scopePlacement = func() error { return tc.place }
			selfAnswer = tc.self
			scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) {
				t.Fatal("unexpected scope escape/retry")
				return 0, nil
			}
			ctx := context.WithValue(t.Context(), scopeKey{}, scopeInvocation{argv: []string{"tego", "run", "missing"}, once: tc.once})
			if _, done := enterUserScope(ctx, io.Discard); done {
				t.Fatal("changed existing path")
			}
		})
	}
	// A process beside the user's subtree that cannot be shown to be outside every run (the rule's unknown: a cgroup
	// namespace that is not the machine's first one, without its proof) is never moved, and is told why with exit
	// 125 [governed]. "A governed agent" is not said: its path shows no run. The lines a person can act on come
	// first; the gate on WSL says the launcher's refusal is not proven yet and names nothing to do.
	for _, tc := range []struct {
		cause      runscope.Cause
		want, deny []string
	}{
		{runscope.CauseUserNamespace, []string{"tego run: nothing was started: this process cannot be shown to be outside every tego run: ",
			"not owned by the machine's first user namespace", "run it from a terminal of the machine's own", "[governed]"}, []string{"a governed agent"}},
		{runscope.CauseWSLLauncherUnproven, []string{"tego run: nothing was started: this process cannot be shown to be outside every tego run: on WSL",
			"not proven yet", "[governed]"}, []string{"a governed agent", "run it from a terminal"}},
		{runscope.CauseInitNotAtRoot, []string{"tego run: the service manager (systemd) is not at the top of this cgroup tree",
			"until then tego cannot show that this process is outside every tego run, so nothing was started [governed]"}, []string{"a governed agent"}},
		{runscope.CauseNoUserManager, []string{"tego run: your user session is not up", "so nothing was started [governed]"}, []string{"a governed agent"}},
		{runscope.CauseManagerNotListening, []string{"tego run: your user session is not up", "so nothing was started [governed]"}, []string{"a governed agent"}},
		{runscope.CauseRootCaller, []string{"tego run: this is root in a cgroup namespace that is not the machine's first one",
			"without sudo", "so nothing was started [governed]"}, []string{"a governed agent"}},
	} {
		scopeStands(t)
		selfAnswer = func() runscope.Answer { return runscope.Unproven(tc.cause, nil) }
		scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) {
			t.Fatalf("%s: a process that cannot be shown to be outside every run was moved", tc.cause)
			return 0, nil
		}
		for _, args := range [][]string{{"run", scopeContract(t)}, {"watch", "--", "true"}, {"test"}, {"machine", "test"}} {
			code, out, errs := run(t, args...)
			if code != identity.ExitLauncher || out != "" {
				t.Errorf("%s, %v: exit %d stdout %q; want %d and nothing started", tc.cause, args, code, out, identity.ExitLauncher)
			}
			for _, w := range tc.want {
				if w = strings.Replace(w, "tego run:", "tego "+scopeName(append([]string{"tego"}, args...))+":", 1); !strings.Contains(errs, w) {
					t.Errorf("%s, %v: stderr lacks %q:\n%s", tc.cause, args, w, errs)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(errs, d) {
					t.Errorf("%s, %v: stderr says %q:\n%s", tc.cause, args, d, errs)
				}
			}
		}
	}
	// An agent can preset every plausible environment guard; none changes the kernel membership or the one attempt.
	scopeStands(t)
	for _, k := range []string{"TEGO_IN_SCOPE", "TEGO_SCOPE_REEXEC", "TEGO_RUN_ID"} {
		t.Setenv(k, "1")
	}
	calls := 0
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { calls++; return 19, nil }
	code, _, _ := run(t, "run", scopeContract(t))
	if code != 19 || calls != 1 {
		t.Fatalf("environment bypass: exit %d calls %d", code, calls)
	}
}

func TestScopeServiceAndUsageStayPut(t *testing.T) {
	scopeStands(t)
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) {
		t.Fatal("service/usage opened scope")
		return 0, nil
	}
	for _, args := range [][]string{{"run", "missing", "--service"}, {"run"}, {"run", "-h"}, {"watch"}, {"test", "extra"}} {
		run(t, args...)
	}
	// A --status-file that run refuses is a usage error before the handoff, as --tier and --record are.
	for _, args := range [][]string{
		{"run", "missing", "--status-file", "relative/status.json"},
		{"run", "missing", "--status-file", "/protected/run-status.json", "--observe"},
	} {
		if code, _, errs := run(t, args...); code != identity.ExitUsage || !strings.Contains(errs, "--status-file") {
			t.Errorf("%q: exit %d, want usage %d naming --status-file:\n%s", args, code, identity.ExitUsage, errs)
		}
	}
}

func TestScopePathsIgnorePATH(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"systemd-run", "tego"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	runner, binary, err := userScopePaths()
	if err != nil {
		t.Fatal(err)
	}
	if runner != "/usr/bin/systemd-run" && runner != "/bin/systemd-run" {
		t.Fatal(runner)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	if binary != want {
		t.Fatalf("binary %q, want the checked executable path %q", binary, want)
	}
	a, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat("/proc/self/exe")
	if err != nil || !os.SameFile(a, b) {
		t.Fatalf("wrong binary: %v", err)
	}
	env := scopeManagerEnv([]string{"XDG_RUNTIME_DIR=/hostile", "DBUS_SESSION_BUS_ADDRESS=unix:path=/hostile", "LANG=C.UTF-8", "KEEP=a=b"})
	if len(env) != 2 || env[0] != "LANG=C.UTF-8" || !strings.HasPrefix(env[1], "XDG_RUNTIME_DIR=/run/user/") {
		t.Fatalf("runner env %q", env)
	}
}

// The helper is the test binary itself, not a Tego product binary. It exercises the actual inherited-fd protocol.
func scopeProcessHelper(mode string) {
	if mode == "continued-stop-parent" {
		os.Exit(scopeContinuedStopParent())
	}
	if strings.HasPrefix(mode, "foreground-") {
		want := mode == "foreground-true"
		if controllingTerminalForeground() != want {
			os.Exit(88)
		}
		os.Exit(0)
	}
	if strings.HasPrefix(mode, "reraise-") {
		scopeReraiseHelper(mode)
	}
	if strings.HasPrefix(mode, "proxy-") {
		if mode == "proxy-signal-trap" {
			if err := scopeDisableCoreDump(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(93)
			}
		}
		childMode := strings.TrimPrefix(mode, "proxy-")
		_ = scopeWriteMarker(filepath.Join(os.Getenv("SCOPE_EXPECT_CWD"), "proxy"), []byte(fmt.Sprint(os.Getpid())))
		scopeCommandFor = func(string, ...string) *proc.Cmd { return proc.Command(os.Args[0]) }
		p := scopePlan{Runner: "/usr/bin/systemd-run", Binary: "/proc/self/exe", Env: append(os.Environ(), "TEGO_SCOPE_TEST_HELPER="+childMode), Request: scopeRequest{Argv: []string{"tego", "run", "$HOME", "", string([]byte{0xff})}, Env: []string{"EXACT=caller", "INVOCATION_ID=original", "SCOPE_EXPECT_CWD=" + os.Getenv("SCOPE_EXPECT_CWD")}}}
		code, err := executeUserScope(context.Background(), p, os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		os.Exit(code)
	}

	scopePlacement = func() error { return nil }
	selfAnswer = answerOutside
	switch mode {
	case "refuse":
		os.Exit(1)
	case "hang":
		f := os.NewFile(3, "scope-request")
		_, _ = io.Copy(io.Discard, f)
		os.Exit(1)
	case "nested":
		selfAnswer = answerGoverned
	case "outside":
		scopePlacement = func() error { return rtcgroup.ErrBesideSubtree }
	}
	// A tiny command observes exact argument bytes and environment after re-entry, including systemd's additions.
	commandTable = map[string]func() Command{}
	register(func() Command {
		return Command{Name: "run", Raw: func(ctx context.Context, args []string, _, _ io.Writer) int {
			if !reflect.DeepEqual(args, []string{"$HOME", "", string([]byte{0xff})}) || os.Getenv("EXACT") != "caller" || os.Getenv("INVOCATION_ID") != "original" {
				return 98
			}
			if code, handled := scopeControlCommand(ctx, mode); handled {
				return code
			}
			if mode == "signal-trap" {
				if err := scopeDisableCoreDump(); err != nil {
					fmt.Fprintln(os.Stderr, err)
					return 93
				}
				// Independent native stimulus: do not use the production re-raise
				// being tested. Same kernel layout as runtime/jobstop_integration_test.go.
				// A process-directed trap may be pending on another Go thread while
				// this helper returns 94. Deliver it on the unblocked calling thread.
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var action [4]uint64 // SIG_DFL, no flags/restorer, empty signal mask
				if _, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(syscall.SIGTRAP), uintptr(unsafe.Pointer(&action)), 0, 8, 0, 0); errno != 0 {
					fmt.Fprintln(os.Stderr, errno)
					return 93
				}
				mask := uint64(1) << (uint(syscall.SIGTRAP) - 1)
				if _, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_UNBLOCK, uintptr(unsafe.Pointer(&mask)), 0, 8, 0, 0); errno != 0 {
					fmt.Fprintln(os.Stderr, errno)
					return 93
				}
				if err := unix.Tgkill(os.Getpid(), unix.Gettid(), unix.SIGTRAP); err != nil {
					fmt.Fprintln(os.Stderr, err)
					return 93
				}
				return 94 // surviving the terminating signal must fail the native-status assertion
			}
			if strings.HasPrefix(mode, "signal-") && mode != "signal-term" {
				name := strings.ToUpper(strings.TrimPrefix(mode, "signal-"))
				_ = syscall.Exec("/bin/sh", []string{"sh", "-c", "kill -" + name + " $$"}, os.Environ())
				return 94
			}
			if mode == "signal" || mode == "signal-term" {
				sig := syscall.SIGKILL
				if mode == "signal-term" {
					sig = syscall.SIGTERM
				}
				_ = syscall.Kill(os.Getpid(), sig)
				select {}
			}
			if mode == "stdio" {
				b, err := io.ReadAll(os.Stdin)
				if err != nil || string(b) != "caller stdin" {
					return 96
				}
				cwd, err := os.Getwd()
				if err != nil || cwd != os.Getenv("SCOPE_EXPECT_CWD") {
					return 95
				}
				fmt.Fprint(os.Stdout, "caller stdout")
				fmt.Fprint(os.Stderr, "caller stderr")
			}
			in := ctx.Value(scopeKey{}).(scopeInvocation)
			if !in.once {
				return 97
			}
			return 37
		}}
	})
	os.Exit(scopedMain(context.Background(), io.Discard, io.Discard))
}

// The trap fixture tests native signal propagation, not the host's core collector.
// RLIMIT_CORE=0 does not prevent a piped collector (such as Apport) from running.
// Only the two disposable trap helpers are made non-dumpable; exec would reset it,
// so the child generates its signal here instead of execing a shell.
func scopeDisableCoreDump() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	value, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	if value != 0 {
		return fmt.Errorf("scope trap helper remains dumpable: %d", value)
	}
	return nil
}

func TestScopeProcessHandshake(t *testing.T) {
	for _, mode := range []string{"success", "refuse", "outside", "nested", "hang"} {
		t.Run(mode, func(t *testing.T) {
			old, timeout := scopeCommandFor, scopeTimeout
			var started *proc.Cmd
			if mode == "hang" {
				scopeTimeout = 100 * time.Millisecond
			}
			scopeCommandFor = func(name string, args ...string) *proc.Cmd {
				want := []string{"--user", "--scope", "--collect", "--quiet", "--no-ask-password", "--", "/proc/123/exe", scopeVerb}
				if name != "/usr/bin/systemd-run" || !reflect.DeepEqual(args, want) {
					t.Errorf("command %q %q", name, args)
				}
				started = proc.Command(os.Args[0], "-test.run=^TestScopeProcessHelper$")
				return started
			}
			t.Cleanup(func() { scopeCommandFor, scopeTimeout = old, timeout })
			p := scopePlan{Runner: "/usr/bin/systemd-run", Binary: "/proc/123/exe", Env: append(os.Environ(), "TEGO_SCOPE_TEST_HELPER="+mode, "INVOCATION_ID=systemd"),
				Request: scopeRequest{Argv: []string{"tego", "run", "$HOME", "", string([]byte{0xff})}, Env: []string{"EXACT=caller", "INVOCATION_ID=original", "SCOPE_EXPECT_CWD=" + os.Getenv("SCOPE_EXPECT_CWD")}}}
			var out bytes.Buffer
			code, err := executeUserScope(t.Context(), p, &out)
			if started.SysProcAttr == nil || started.SysProcAttr.Pdeathsig != syscall.SIGTERM || started.SysProcAttr.Setsid || started.SysProcAttr.Setpgid || started.SysProcAttr.Foreground {
				t.Error("scope changed session/job or lost parent-death cleanup")
			}
			if started.Stdin != os.Stdin || started.Stdout != os.Stdout || started.Stderr != os.Stderr || started.Dir != "" {
				t.Error("scope replaced streams or working directory")
			}
			if mode == "success" {
				if err != nil || code != 37 || out.String() != "tego: opened a user scope for this run\n" {
					t.Fatalf("exit %d err %v out %q", code, err, out.String())
				}
			} else if err == nil || out.Len() != 0 {
				t.Fatalf("failure started run: exit %d err %v out %q", code, err, out.String())
			}
		})
	}
}

// These subprocesses run the test helper only. The proxy exercises the parent's real wait and signal propagation.
func TestScopeProcessStatusAndStdio(t *testing.T) {
	for _, mode := range []string{"success", "signal", "signal-term", "signal-pipe", "signal-prof", "signal-trap", "stdio"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0])
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=proxy-"+mode, "SCOPE_EXPECT_CWD="+cmd.Dir)
			cmd.Stdin = strings.NewReader("caller stdin")
			var out, errs bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errs
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("no child status: %v %s", err, errs.String())
			}
			ws := ee.Sys().(syscall.WaitStatus)
			if strings.HasPrefix(mode, "signal") {
				want := syscall.SIGKILL
				if mode == "signal-term" {
					want = syscall.SIGTERM
				}
				if mode == "signal-pipe" {
					want = syscall.SIGPIPE
				}
				if mode == "signal-prof" {
					want = syscall.SIGPROF
				}
				if mode == "signal-trap" {
					want = syscall.SIGTRAP
				}
				if !ws.Signaled() || ws.Signal() != want {
					t.Fatalf("signal turned into exit: %v %s", ws, errs.String())
				}
			} else if !ws.Exited() || ws.ExitStatus() != 37 {
				t.Fatalf("exit=%v stderr=%s", ws, errs.String())
			}
			if mode == "stdio" && (out.String() != "caller stdout" || !strings.HasSuffix(errs.String(), "caller stderr")) {
				t.Fatalf("stdio: %q %q", out.String(), errs.String())
			}
		})
	}
}

func TestScopeProcessRequiresTheGoAhead(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	ready, reply, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer reply.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=success")
	cmd.ExtraFiles = []*os.File{rd, reply}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	_ = rd.Close()
	_ = reply.Close()
	if err := gob.NewEncoder(wr).Encode(scopeRequest{Argv: []string{"tego", "run"}}); err != nil {
		t.Fatal(err)
	}
	_ = ready.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(ready, b[:]); err != nil || b[0] != 1 {
		t.Fatalf("ready %v %v", b, err)
	}
	_ = wr.Close() // Parent died or refused the handoff after readiness. Never dispatch the command.
	err = cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 125 {
		t.Fatalf("started without permission: %v", err)
	}
}

// TestRehearsalFailureReachesTheCheck (ADR 0142, amended 2026-11-19, round 4): when the rehearsal of entry into a user
// scope fails, doctor, machine check, setup and start learn why (doctor.UserScopeFailure), so the stored check and the
// report say the reason instead of "run, watch and test can try a user scope"; one that worked records no failure.
func TestRehearsalFailureReachesTheCheck(t *testing.T) {
	scopeStands(t)
	in := context.WithValue(t.Context(), scopeKey{}, scopeInvocation{argv: []string{"tego", "setup"}})
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { return 0, errors.New("manager refused") }
	var errs strings.Builder
	if got := doctor.UserScopeFailure(rehearseUserScope(in, &errs)); got != "manager refused" ||
		!strings.Contains(errs.String(), "could not open a user scope: manager refused") {
		t.Errorf("failed rehearsal: recorded %q, said %q", got, errs.String())
	}
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { return 3, nil }
	if got := doctor.UserScopeFailure(rehearseUserScope(in, io.Discard)); got != "user scope rehearsal exited 3" {
		t.Errorf("a rehearsal that exited 3: recorded %q", got)
	}
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { return 0, nil }
	if got := doctor.UserScopeFailure(rehearseUserScope(in, io.Discard)); got != "" {
		t.Errorf("a rehearsal that worked recorded %q", got)
	}
}
