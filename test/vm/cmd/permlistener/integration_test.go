// SPDX-License-Identifier: Apache-2.0

//go:build integration

package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests run the tool as a process (this binary again, see TestMain) against the kernel's fanotify, as
// root. They mount a tmpfs of their own and mark only that, so the listener sees the test's opens and nothing
// else on the machine, and the machine, a CI runner included, is never put behind a permission group.

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: a fanotify permission group needs CAP_SYS_ADMIN, and the test mounts a tmpfs")
	}
}

// privateMount mounts a tmpfs on a new directory and returns it. The unmount is a cleanup; a mount the
// listener is still marking would be busy, so tests stop the tool first.
func privateMount(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "mnt")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=8m,mode=0755"); err != nil {
		t.Fatalf("mount a tmpfs on %s: %v", dir, err)
	}
	t.Cleanup(func() {
		for range 50 {
			if err := unix.Unmount(dir, 0); err == nil || errors.Is(err, unix.EINVAL) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		_ = unix.Unmount(dir, unix.MNT_DETACH)
	})
	return dir
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// tool is a running permlistener.
type tool struct {
	t      *testing.T
	cmd    *exec.Cmd
	lines  chan string
	stderr *lockedBuffer
	done   bool
}

// startTool starts the tool with args and returns once it has printed its ready line.
func startTool(t *testing.T, args ...string) *tool {
	t.Helper()
	cmd := asTool(args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	tl := &tool{t: t, cmd: cmd, lines: make(chan string, 64), stderr: &lockedBuffer{}}
	cmd.Stderr = tl.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the tool: %v", err)
	}
	go func() {
		defer close(tl.lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			tl.lines <- sc.Text()
		}
	}()
	t.Cleanup(tl.kill)
	select {
	case line, ok := <-tl.lines:
		if !ok || line != "PERMLISTENER-READY" {
			t.Fatalf("first line = %q (%v), want PERMLISTENER-READY; stderr:\n%s", line, ok, tl.stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no PERMLISTENER-READY in 15s; stderr:\n%s", tl.stderr.String())
	}
	return tl
}

// kill ends a tool a test left running, so its marks do not outlive the test.
func (tl *tool) kill() {
	if tl.done {
		return
	}
	tl.done = true
	_ = tl.cmd.Process.Kill()
	for range tl.lines {
	}
	_ = tl.cmd.Wait()
}

// stop sends SIGTERM and returns the stats line's fields and the exit status.
func (tl *tool) stop() (stats map[string]string, exit int) {
	tl.t.Helper()
	if err := tl.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		tl.t.Fatalf("SIGTERM: %v", err)
	}
	var last string
	timeout := time.After(15 * time.Second)
	for open := true; open; {
		select {
		case line, ok := <-tl.lines:
			if !ok {
				open = false
				break
			}
			last = line
		case <-timeout:
			_ = tl.cmd.Process.Kill()
			tl.t.Fatalf("the tool did not stop within 15s of SIGTERM; stderr:\n%s", tl.stderr.String())
		}
	}
	err := tl.cmd.Wait()
	tl.done = true
	exit = 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		exit = ee.ExitCode()
	} else if err != nil {
		tl.t.Fatalf("wait: %v", err)
	}
	stats = map[string]string{}
	fields := strings.Fields(last)
	if len(fields) == 0 || fields[0] != "PERMLISTENER-STATS" {
		tl.t.Fatalf("last line = %q, want a PERMLISTENER-STATS line; stderr:\n%s", last, tl.stderr.String())
	}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			tl.t.Fatalf("stats field %q is not key=value", f)
		}
		stats[k] = v
	}
	return stats, exit
}

func num(t *testing.T, stats map[string]string, key string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(stats[key], 10, 64)
	if err != nil {
		t.Fatalf("stats %s=%q: %v (stats %v)", key, stats[key], err, stats)
	}
	return n
}

func TestIntegrationDenyRefusesOneFileAndNoOther(t *testing.T) {
	requireRoot(t)
	mnt := privateMount(t)
	secret := filepath.Join(mnt, "secret")
	alias := filepath.Join(mnt, "alias")
	other := filepath.Join(mnt, "other")
	write(t, secret, "#!/bin/sh\nexit 0\n", 0o755)
	write(t, other, "x", 0o644)
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}

	tl := startTool(t, "-mode", "deny", "-path", secret) // the mount of secret's directory is marked by default

	if f, err := os.Open(secret); !errors.Is(err, unix.EPERM) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("open of the denied file = %v, want EPERM", err)
	}
	if f, err := os.Open(alias); !errors.Is(err, unix.EPERM) {
		if err == nil {
			_ = f.Close()
		}
		t.Errorf("open of its hard link = %v, want EPERM: the inode is the file", err)
	}
	if err := exec.Command(secret).Run(); !errors.Is(err, unix.EPERM) {
		t.Errorf("exec of the denied file = %v, want EPERM: the exec's open is an open", err)
	}
	f, err := os.Open(other)
	if err != nil {
		t.Errorf("open of another file on the marked mount: %v", err)
	} else {
		_ = f.Close()
	}

	stats, exit := tl.stop()
	if exit != 0 {
		t.Errorf("exit %d, stderr:\n%s", exit, tl.stderr.String())
	}
	if got := num(t, stats, "denied"); got != 3 {
		t.Errorf("denied = %d, want 3 (the file, its link, its exec); stats %v", got, stats)
	}
	if got := num(t, stats, "events"); got < 4 {
		t.Errorf("events = %d, want at least the 4 opens above; stats %v", got, stats)
	}
	if got := num(t, stats, "self"); got != 0 {
		t.Errorf("self = %d: deny mode opened something itself; stats %v", got, stats)
	}
	// The marks went with the stop: the same open now succeeds.
	f, err = os.Open(secret)
	if err != nil {
		t.Errorf("open of the denied file after the listener stopped: %v", err)
	} else {
		_ = f.Close()
	}
}

// TestIntegrationAllowTouchDecidesOnTheMarkedMountWithoutDeadlock is ADR 0021's shape on a real kernel: every
// decision opens a file on the mount it is a decision for. The listener's own opens are events of its own group;
// if the reader handed them to a worker (or waited for one) every decision would wait on itself until the
// deadline, so no event being late is the proof, and each decision's one touch is a self event.
func TestIntegrationAllowTouchDecidesOnTheMarkedMountWithoutDeadlock(t *testing.T) {
	requireRoot(t)
	mnt := privateMount(t)
	touch := filepath.Join(mnt, "touch-me")
	script := filepath.Join(mnt, "run.sh")
	write(t, touch, "hello\n", 0o644)
	write(t, script, "#!/bin/sh\nexit 0\n", 0o755)
	// A process whose comm is tego, as the launchers and their stages have: this binary under that name.
	link := filepath.Join(t.TempDir(), "tego")
	if err := os.Symlink(os.Args[0], link); err != nil {
		t.Fatal(err)
	}

	tl := startTool(t, "-mark", mnt, "-touch", touch, "-stat", mnt, "-workers", "2", "-decide-delay", "1ms", "-deadline", "10s")

	begin := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				f, err := os.Open(touch)
				if err != nil {
					t.Errorf("open on the marked mount: %v", err)
					return
				}
				_ = f.Close()
			}
		}()
	}
	wg.Wait()
	if err := exec.Command(script).Run(); err != nil {
		t.Errorf("exec from the marked mount: %v", err)
	}
	opener := exec.Command(link, touch)
	opener.Env = append(os.Environ(), roleEnv+"="+roleOpener)
	if out, err := opener.Output(); err != nil || string(out) != "open "+touch+" ok\n" {
		t.Errorf("opener = %q, %v", out, err)
	}
	if took := time.Since(begin); took > 8*time.Second {
		t.Errorf("the work took %v: decisions waited out a deadline", took)
	}

	stats, exit := tl.stop()
	if exit != 0 {
		t.Errorf("exit %d, stderr:\n%s", exit, tl.stderr.String())
	}
	events, self := num(t, stats, "events"), num(t, stats, "self")
	if got := num(t, stats, "late"); got != 0 {
		t.Errorf("late = %d: a decision waited for an answer nobody gave; stats %v", got, stats)
	}
	if got := num(t, stats, "failed"); got != 0 {
		t.Errorf("failed = %d; stats %v\nstderr:\n%s", got, stats, tl.stderr.String())
	}
	if got := num(t, stats, "tego"); got != 1 {
		t.Errorf("tego = %d, want the one open by the process named tego; stats %v", got, stats)
	}
	if got := num(t, stats, "exec"); got < 1 {
		t.Errorf("exec = %d, want the exec of the script seen; stats %v", got, stats)
	}
	if foreign := events - self; foreign < 42 || self != foreign {
		t.Errorf("events %d, of which %d its own: want at least 42 foreign events (40 opens, the opener, the exec) each decided by one touch of its own; stats %v",
			events, self, stats)
	}
}

// TestIntegrationADecisionThatStallsIsLetThroughAtTheDeadline: when decisions take longer than the deadline the
// opener is released by the deadline's answer, and the helper says so.
func TestIntegrationADecisionThatStallsIsLetThroughAtTheDeadline(t *testing.T) {
	requireRoot(t)
	mnt := privateMount(t)
	touch := filepath.Join(mnt, "touch-me")
	write(t, touch, "hello\n", 0o644)
	tl := startTool(t, "-mark", mnt, "-touch", touch, "-stat", mnt, "-workers", "1", "-decide-delay", "1h", "-deadline", "300ms")

	begin := time.Now()
	f, err := os.Open(touch)
	took := time.Since(begin)
	if err != nil {
		t.Fatalf("open under a stalled decision: %v", err)
	}
	_ = f.Close()
	if took < 250*time.Millisecond || took > 5*time.Second {
		t.Errorf("the open took %v, want it released by the 300ms deadline", took)
	}

	stopped := time.Now()
	stats, exit := tl.stop() // the worker is sleeping an hour: the stop must not wait for it
	if exit != 0 {
		t.Errorf("exit %d, stderr:\n%s", exit, tl.stderr.String())
	}
	if d := time.Since(stopped); d > 10*time.Second {
		t.Errorf("stop took %v with a decision sleeping an hour", d)
	}
	if got := num(t, stats, "late"); got != 1 {
		t.Errorf("late = %d, want 1; stats %v", got, stats)
	}
}

// TestIntegrationStopReleasesAnOpenerMidDecision: SIGTERM while an opener waits on a decision removes the marks,
// answers it, and the open completes: the stop is never the stall.
func TestIntegrationStopReleasesAnOpenerMidDecision(t *testing.T) {
	requireRoot(t)
	mnt := privateMount(t)
	touch := filepath.Join(mnt, "touch-me")
	write(t, touch, "hello\n", 0o644)
	tl := startTool(t, "-mark", mnt, "-touch", touch, "-stat", mnt, "-workers", "1", "-decide-delay", "1h", "-deadline", "1h")

	opened := make(chan error, 1)
	go func() {
		f, err := os.Open(touch)
		if err == nil {
			_ = f.Close()
		}
		opened <- err
	}()
	select {
	case err := <-opened:
		t.Fatalf("the open returned (%v) before the listener answered: the decision did not hold it", err)
	case <-time.After(300 * time.Millisecond):
	}

	stats, exit := tl.stop()
	if exit != 0 {
		t.Errorf("exit %d, stderr:\n%s", exit, tl.stderr.String())
	}
	select {
	case err := <-opened:
		if err != nil {
			t.Errorf("the open held by a stopped listener failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open is still blocked after the listener stopped")
	}
	if got := num(t, stats, "late"); got != 0 {
		t.Errorf("late = %d: the stop answered it, not the deadline; stats %v", got, stats)
	}
	if got, want := num(t, stats, "events"), int64(1); got != want {
		t.Errorf("events = %d, want %d; stats %v", got, want, stats)
	}
}
