// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"golang.org/x/sys/unix"
)

// TestIntegrationExitWatchReadsTheWholeProcessEnd: the exit status an adoption's run_end carries, from the real proc
// connector, for a process that ends by its main thread's exit_group(3) (3), and for one whose main thread exits first
// (code 0) and whose thread then ends it: with exit_group(3), which wait(2) reports as 3 while the events carry 0 and 3,
// the status is unknown (it was 0); with exit_group(0) the codes agree and it
// is 0.
func TestIntegrationExitWatchReadsTheWholeProcessEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the proc connector is a multicast netlink group that needs CAP_NET_ADMIN")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "agent")
	body := "#!" + python + `
import ctypes, os, sys, threading
libc = ctypes.CDLL(None)
def worker():
    open(sys.argv[2]).read()
    os._exit(int(sys.argv[3]))
if sys.argv[1] == "first":
    threading.Thread(target=worker).start()
open(sys.argv[2] if sys.argv[1] == "plain" else sys.argv[4]).read()
if sys.argv[1] == "first":
    libc.syscall(60, 0)
os._exit(int(sys.argv[3]))
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, mode string
		code       int
		wait       int // the status wait(2) reports
		ok         bool
	}{
		{"exit_group(3) of the main thread", "plain", 3, 3, true},
		{"the main thread first, then exit_group(3)", "first", 3, 3, false},
		{"the main thread first, then exit_group(0)", "first", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			goThread, goMain := filepath.Join(dir, "thread-"+tc.mode), filepath.Join(dir, "main-"+tc.mode)
			for _, f := range []string{goThread, goMain} {
				_ = os.Remove(f)
				if err := unix.Mkfifo(f, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(script, tc.mode, goThread, strconv.Itoa(tc.code), goMain)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			comm := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "comm")
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if b, err := os.ReadFile(comm); err == nil && strings.TrimSpace(string(b)) == "agent" {
					break // it runs the script
				}
				if time.Now().After(deadline) {
					t.Fatal("the agent did not start")
				}
			}
			p := adoptProc()
			root, err := adopt.Identify(p, cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			w := watchExit(p, root.Identity)
			defer w.stop()
			if tc.mode == "first" {
				openWrite(t, goMain)
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
					if st, err := p.Stat(root.PID); err == nil && st.LeaderExited() {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("its main thread did not exit")
					}
				}
			}
			openWrite(t, goThread)
			var ee *exec.ExitError
			if err := cmd.Wait(); tc.wait != 0 && (!errors.As(err, &ee) || ee.ExitCode() != tc.wait) || tc.wait == 0 && err != nil {
				t.Fatalf("wait status = %v, want %d", err, tc.wait)
			}
			code, sig, ok := w.status()
			if ok != tc.ok || ok && (code != tc.code || sig != 0) {
				t.Fatalf("status = code %d signal %d ok %v, want code %d ok %v", code, sig, ok, tc.code, tc.ok)
			}
		})
	}
}

// openWrite lets the process reading fifo go on.
func openWrite(t *testing.T, fifo string) {
	t.Helper()
	f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("go\n")
	_ = f.Close()
}

// TestIntegrationExitWatchGivesTheStatusOfAProgramAThreadRan: tego adopt's own exit watch, for an adopted root whose
// worker thread runs sh -c 'exit 3' (de_thread zaps its live main thread with code 0). run_end said 0 in some runs,
// the zap's exit read late having ended the root. Every run says 3.
func TestIntegrationExitWatchGivesTheStatusOfAProgramAThreadRan(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the proc connector is a multicast netlink group that needs CAP_NET_ADMIN")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "agent")
	body := "#!" + python + `
import os, sys, threading
def worker():
    open(sys.argv[1]).read()
    os.execv("/bin/sh", ["sh", "-c", "exit 3"])
threading.Thread(target=worker).start()
threading.Event().wait()
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	const runs = 30
	for i := range runs {
		fifo := filepath.Join(dir, "go-"+strconv.Itoa(i))
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(script, fifo)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		p := adoptProc()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			st, err := p.Stat(pid)
			if b, err2 := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil && err2 == nil &&
				strings.TrimSpace(string(b)) == "agent" && st.NumThreads >= 2 {
				break // it runs the script, its worker thread started
			}
			if time.Now().After(deadline) {
				t.Fatal("the agent did not start")
			}
		}
		root, err := adopt.Identify(p, pid)
		if err != nil {
			t.Fatal(err)
		}
		w := watchExit(p, root.Identity)
		openWrite(t, fifo)
		var ee *exec.ExitError
		if err := cmd.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 3 {
			t.Fatalf("run %d: wait status = %v, want 3", i, err)
		}
		code, sig, ok := w.status()
		w.stop()
		if !ok || code != 3 || sig != 0 {
			t.Fatalf("run %d: status = code %d signal %d ok %v, want 3", i, code, sig, ok)
		}
	}
}
