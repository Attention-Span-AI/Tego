// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

func TestGuideInterruptRestoresTerminal(t *testing.T) {
	if os.Getenv("TEGO_TEST_GUIDE_INTERRUPT") == "1" {
		f := onFixture(t, "fresh")
		t.Setenv("TERM", "xterm-256color")
		noLogins(t)
		t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-login")
		fakeProgram(t, "claude")
		ctx, stop := notifyContext()
		defer stop()
		code := runSetupGuide(ctx, os.Stdin, os.Stdout, os.Stderr, true)
		if code != identity.ExitFinding {
			t.Fatalf("interrupt exit %d", code)
		}
		for _, rel := range []string{agentEnvRel, lastProjectRel, guideSample} {
			if _, err := os.Stat(filepath.Join(f.Home, rel)); !os.IsNotExist(err) {
				t.Fatalf("interrupted guide left %s: %v", rel, err)
			}
		}
		return
	}
	for _, how := range []string{"key", "signal"} {
		t.Run(how, func(t *testing.T) {
			fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			master := os.NewFile(uintptr(fd), "pty")
			defer func() { _ = master.Close() }()
			if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
				t.Fatal(err)
			}
			n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
			if err != nil {
				t.Fatal(err)
			}
			slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = slave.Close() }()
			if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
				t.Fatal(err)
			}
			before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			c := exec.Command(self, "-test.run=^TestGuideInterruptRestoresTerminal$")
			c.Env = append(os.Environ(), "TEGO_TEST_GUIDE_INTERRUPT=1", "TERM=xterm-256color")
			c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
			c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var childErr error
			go func() { childErr = c.Wait(); close(done) }()
			defer func() { _ = c.Process.Kill(); <-done }()
			var trace bytes.Buffer
			var traceMu sync.Mutex
			snapshot := func() string { traceMu.Lock(); defer traceMu.Unlock(); return trace.String() }
			ready := make(chan string, 3)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				b := make([]byte, 4096)
				seen := map[string]bool{}
				for {
					n, e := master.Read(b)
					if n > 0 {
						traceMu.Lock()
						trace.Write(b[:n])
						current := trace.String()
						traceMu.Unlock()
						for _, prompt := range []string{"Which agent", "Which project", "Which rules"} {
							if at := strings.Index(current, prompt); !seen[prompt] && at >= 0 && strings.Contains(current[at:], "enter select") {
								ready <- prompt
								seen[prompt] = true
							}
						}
					}
					if e != nil {
						return
					}
				}
			}()
			defer func() {
				_ = master.Close()
				select {
				case <-readDone:
				case <-time.After(time.Second):
					t.Error("PTY reader did not finish")
				}
			}()
			for _, step := range []struct{ prompt, keys string }{{"Which agent", "\r"}, {"Which project", "\x1b[B\r"}, {"Which rules", ""}} {
				select {
				case got := <-ready:
					if got != step.prompt {
						t.Fatalf("prompt %q, wanted %q", got, step.prompt)
					}
				case <-done:
					t.Fatalf("helper ended before %s: %v\n%s", step.prompt, childErr, snapshot())
				case <-time.After(10 * time.Second):
					t.Fatalf("no %s prompt: %s", step.prompt, snapshot())
				}
				if step.keys != "" {
					if step.prompt == "Which project" {
						if _, err := master.Write([]byte("\x1b[B")); err != nil {
							t.Fatal(err)
						}
						time.Sleep(20 * time.Millisecond)
						step.keys = "\r"
					}
					if _, err := master.Write([]byte(step.keys)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if how == "key" {
				_, err = master.Write([]byte{3})
			} else {
				err = c.Process.Signal(os.Interrupt)
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				if childErr != nil {
					t.Fatalf("interrupted helper: %v\n%s", childErr, snapshot())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("guide ignored interrupt")
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("terminal not restored: before %+v after %+v", before, after)
			}
		})
	}
}
