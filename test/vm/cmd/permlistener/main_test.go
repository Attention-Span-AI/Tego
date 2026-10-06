// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// The test binary is also the tool, and a helper that opens files, so the integration tests start the real
// thing as a process of their own without a build step (the KVM guests have no Go toolchain; go-shim.sh serves
// only the helpers root-suites.sh prebuilds). roleEnv names which one a child is.
const (
	roleEnv      = "PERMLISTENER_TEST_ROLE"
	roleListener = "listener" // main(), with the child's arguments
	roleOpener   = "opener"   // opens each file its arguments name, prints the result, exits
)

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "":
		os.Exit(testutil.LeakCheckMain(m))
	case roleListener:
		main()
	case roleOpener:
		os.Exit(opener(os.Args[1:], os.Stdout))
	default:
		fmt.Fprintf(os.Stderr, "unknown %s %q\n", roleEnv, os.Getenv(roleEnv))
		os.Exit(2)
	}
}

// opener opens each path, reads a byte, closes it, and prints "open <path> ok" or "open <path> <errno>
// <message>". It exits 0 whatever the results are: they are the parent's to judge.
func opener(paths []string, out *os.File) int {
	for _, p := range paths {
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			var en unix.Errno
			if errors.As(err, &en) {
				fmt.Fprintf(out, "open %s %d %v\n", p, int(en), err)
			} else {
				fmt.Fprintf(out, "open %s -1 %v\n", p, err)
			}
			continue
		}
		var b [1]byte
		_, _ = unix.Read(fd, b[:])
		_ = unix.Close(fd)
		fmt.Fprintf(out, "open %s ok\n", p)
	}
	return 0
}

// asTool returns a command that runs this binary as the tool with args.
func asTool(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), roleEnv+"="+roleListener)
	return cmd
}

// lockedBuffer is a bytes.Buffer a goroutine can write while the test reads.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// withGroup replaces the real fanotify group with a socketpair for the rest of the test. It returns the test's
// end. Tests that use it do not run in parallel: openGroup is one variable.
func withGroup(t *testing.T, unmark func() error) (kernel int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	prev := openGroup
	openGroup = func(config) (group, error) { return group{fd: fds[0], unmark: unmark}, nil }
	t.Cleanup(func() {
		openGroup = prev
		_ = unix.Close(fds[1])
	})
	return fds[1]
}

func waitForText(t *testing.T, buf *lockedBuffer, text string) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !strings.Contains(buf.String(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q within %v; output so far:\n%s", text, waitFor, buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunPrintsReadyOnceMarkedAndStatsOnceStopped(t *testing.T) {
	var unmarked atomic.Bool
	kernel := withGroup(t, func() error { unmarked.Store(true); return nil })
	dir := t.TempDir()
	touch := filepath.Join(dir, "touch")
	if err := os.WriteFile(touch, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr lockedBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-mark", dir, "-touch", touch, "-stat", dir, "-workers", "1"}, &stdout, &stderr)
	}()
	waitForText(t, &stdout, "PERMLISTENER-READY\n")

	// The listener answers an event of its own (the pid of this process is the listener's here) at once.
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(kernel, rec(3, unix.FAN_OPEN_PERM, int32(fd), int32(os.Getpid()), 0)); err != nil {
		t.Fatal(err)
	}
	var raw [8]byte
	if n, err := unix.Read(kernel, raw[:]); err != nil || n != 8 {
		t.Fatalf("response: %d bytes, %v", n, err)
	}
	if unmarked.Load() {
		t.Fatal("the marks were removed before the context ended")
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("run = %d, stderr:\n%s", code, stderr.String())
		}
	case <-time.After(waitFor):
		t.Fatal("run did not return after its context ended")
	}
	if !unmarked.Load() {
		t.Error("the marks were not removed on the way out")
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 2 || lines[0] != "PERMLISTENER-READY" ||
		!strings.HasPrefix(lines[1], "PERMLISTENER-STATS events=1 tego=0 self=1 ") ||
		!strings.HasSuffix(lines[1], " mode=allow-touch") {
		t.Errorf("stdout = %q, want the ready line and then the stats line of one own event", lines)
	}
}

func TestRunExitsOneAndPrintsNoReadyWhenTheGroupCannotBeMade(t *testing.T) {
	prev := openGroup
	openGroup = func(config) (group, error) { return group{}, unix.EPERM }
	t.Cleanup(func() { openGroup = prev })
	var stdout, stderr lockedBuffer
	code := run(context.Background(), []string{"-mark", t.TempDir(), "-touch", "/dev/null", "-stat", "/"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("run = %d, want 1", code)
	}
	if stdout.String() != "" {
		t.Errorf("stdout = %q, want nothing: a ready line for a group that does not exist", stdout.String())
	}
	if !strings.Contains(stderr.String(), "permlistener: ") {
		t.Errorf("stderr = %q, want a permlistener: message", stderr.String())
	}
}

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"a bad flag value is a usage error", []string{"-mode", "bogus"}, 2},
		{"deny without a path is a usage error", []string{"-mode", "deny"}, 2},
		{"help is not an error", []string{"-h"}, 0},
		{"a mark that does not exist fails the start", []string{"-mark", "/no/such/dir/permlistener"}, 1},
		{"a touch file that cannot be read fails the start", []string{"-mark", "/", "-touch", "/no/such/file/permlistener"}, 1},
	}
	for _, c := range cases {
		var stdout, stderr lockedBuffer
		if code := run(context.Background(), c.args, &stdout, &stderr); code != c.code {
			t.Errorf("%s: run(%v) = %d, want %d\nstderr: %s", c.name, c.args, code, c.code, stderr.String())
		}
		if c.code == 2 || c.code == 1 {
			if !strings.Contains(stderr.String(), "permlistener: ") {
				t.Errorf("%s: stderr %q names no tool", c.name, stderr.String())
			}
			if strings.Contains(stdout.String(), "READY") {
				t.Errorf("%s: printed a ready line", c.name)
			}
		}
	}
}

// TestTheCommandExitsWithRunsCodeAndPrintsNoReadyOnAFailedStart runs main() itself, as a process.
func TestTheCommandExitsWithRunsCodeAndPrintsNoReadyOnAFailedStart(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"-mode", "bogus"}, 2},
		{[]string{"-mark", "/no/such/dir/permlistener"}, 1},
	} {
		cmd := asTool(c.args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != c.code {
			t.Errorf("%v: %v, want exit %d\nstderr: %s", c.args, err, c.code, stderr.String())
		}
		if strings.Contains(stdout.String(), "READY") {
			t.Errorf("%v: printed READY: %q", c.args, stdout.String())
		}
	}
}

func TestPreflightNamesWhatIsMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := config{mode: modeAllowTouch, marks: []string{dir}, touch: []string{file}, stat: []string{dir}}
	if err := preflight(ok); err != nil {
		t.Fatalf("preflight of a working configuration: %v", err)
	}
	missing := filepath.Join(dir, "missing")
	for _, c := range []struct {
		name string
		cfg  config
		want string
	}{
		{"mark", config{mode: modeAllowTouch, marks: []string{missing}, touch: []string{file}, stat: []string{dir}}, "-mark " + missing},
		{"touch", config{mode: modeAllowTouch, marks: []string{dir}, touch: []string{missing}, stat: []string{dir}}, "-touch " + missing},
		{"touch is a directory", config{mode: modeAllowTouch, marks: []string{dir}, touch: []string{dir}, stat: []string{dir}}, "-touch " + dir},
		{"stat", config{mode: modeAllowTouch, marks: []string{dir}, touch: []string{file}, stat: []string{missing}}, "-stat " + missing},
		{"deny mark", config{mode: modeDeny, marks: []string{missing}, path: file}, "-mark " + missing},
	} {
		err := preflight(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: preflight = %v, want an error naming %q", c.name, err, c.want)
		}
	}
	// Deny mode does not need the path to exist yet, only its mount.
	if err := preflight(config{mode: modeDeny, marks: []string{dir}, path: missing}); err != nil {
		t.Errorf("deny mode with a path that does not exist yet: %v", err)
	}
}
