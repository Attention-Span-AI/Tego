// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"golang.org/x/sys/unix"
)

func TestLoginControllingTerminal(t *testing.T) {
	for _, mode := range []string{"script-input", "direct-input", "script-context", "direct-context", "script-signal", "direct-signal", "script-ctrl-c", "direct-ctrl-c"} {
		t.Run(mode, func(t *testing.T) {
			if strings.HasPrefix(mode, "script-") {
				if _, err := exec.LookPath("script"); err != nil {
					t.Skip("script is needed for the controlling-terminal capture test")
				}
			}
			master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Skipf("pseudo-terminal unavailable: %v", err)
			}
			defer func() { _ = master.Close() }()
			if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
				t.Skipf("pseudo-terminal unlock unavailable: %v", err)
			}
			n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
			if err != nil {
				t.Fatal(err)
			}
			slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = slave.Close() }()
			dir := t.TempDir()
			program := filepath.Join(dir, "agent")
			text := "#!/bin/sh\necho $$ > \"$LOGIN_PID\"\nprintf 'LOGIN-READY\\n'\nIFS= read -r code\n[ \"$code\" = typed-after-start ] || exit 9\nprintf '%s\\n' sk-ant-oat01-abcdefghijklmnopqrstuvwxyz\n"
			if strings.HasSuffix(mode, "context") || strings.HasSuffix(mode, "signal") {
				text = "#!/bin/sh\ntrap '' TERM HUP\necho $$ > \"$LOGIN_PID\"\nprintf 'LOGIN-READY\\n'\nexec sleep 120\n"
			}
			if err := os.WriteFile(program, []byte(text), 0700); err != nil {
				t.Fatal(err)
			}
			c := exec.Command(os.Args[0], "-test.run=^TestLoginTerminalHelper$")
			c.Env = append(os.Environ(), "TEGO_LOGIN_TERMINAL_HELPER="+mode, "LOGIN_PROGRAM="+program, "LOGIN_HOME="+dir, "LOGIN_PID="+filepath.Join(dir, "pid"))
			c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
			c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.Wait() }()
			defer func() { _ = c.Process.Kill(); <-done }()
			chunks := make(chan string, 128)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				b := make([]byte, 4096)
				for {
					n, err := master.Read(b)
					if n > 0 {
						chunks <- string(b[:n])
					}
					if err != nil {
						return
					}
				}
			}()
			defer func() { _ = master.Close(); <-readDone }()
			deadline := time.NewTimer(20 * time.Second)
			defer deadline.Stop()
			transcript := ""
			ready, exited := false, false
			for !exited {
				select {
				case chunk := <-chunks:
					transcript += chunk
					if !ready && strings.Contains(transcript, "LOGIN-READY") {
						ready = true
						switch {
						case strings.HasSuffix(mode, "input"):
							_, err = io.WriteString(master, "typed-after-start\n")
						case strings.HasSuffix(mode, "ctrl-c"):
							_, err = master.Write([]byte{3})
						case strings.HasSuffix(mode, "signal"):
							err = c.Process.Signal(syscall.SIGTERM)
						default:
							err = c.Process.Signal(syscall.SIGUSR1)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
				case err := <-done:
					done <- err
					if err != nil {
						t.Fatalf("helper: %v\n%s", err, transcript)
					}
					exited = true
				case <-deadline.C:
					t.Fatalf("login did not finish with its controlling terminal (%s):\n%s", mode, transcript)
				}
			}
			result, err := os.ReadFile(filepath.Join(dir, "result"))
			if err != nil || string(result) != "restored" {
				t.Fatalf("terminal/capture: %q %v\n%s", result, err, transcript)
			}
			pidText, _ := os.ReadFile(filepath.Join(dir, "pid"))
			pid, _ := strconv.Atoi(strings.TrimSpace(string(pidText)))
			if pid > 0 {
				defer func() { _ = unix.Kill(pid, unix.SIGKILL) }()
				until := time.Now().Add(10 * time.Second)
				for {
					st, e := proc.New().Stat(pid)
					if errors.Is(e, proc.ErrGone) || (e == nil && st.State == 'Z') {
						break
					}
					if time.Now().After(until) {
						t.Fatalf("login child survived: %d %v", pid, e)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			matches, _ := filepath.Glob(filepath.Join(dir, ".tego/sign-in-*"))
			if len(matches) > 0 {
				t.Fatalf("named login captures remain: %v", matches)
			}
		})
	}
}

func TestLoginTerminalHelper(t *testing.T) {
	mode := os.Getenv("TEGO_LOGIN_TERMINAL_HELPER")
	if mode == "" {
		return
	}
	before, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	fg, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil || fg != unix.Getpgrp() {
		t.Fatalf("helper has no foreground controlling terminal: %d %v", fg, err)
	}
	if strings.HasPrefix(mode, "direct-") {
		guideLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGUSR1)
	defer cancel()
	token, loginErr := guideSetupToken(ctx, os.Getenv("LOGIN_PROGRAM"), os.Getenv("LOGIN_HOME"))
	if strings.HasSuffix(mode, "input") && (loginErr != nil || (strings.HasPrefix(mode, "script-") && token != "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz")) {
		t.Fatalf("input/capture: %q %v", token, loginErr)
	}
	if !strings.HasSuffix(mode, "input") && loginErr == nil {
		t.Fatal("canceled login succeeded")
	}
	after, err := unix.IoctlGetTermios(0, unix.TCGETS)
	afterFG, fgErr := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	if err != nil || fgErr != nil || !reflect.DeepEqual(before, after) || afterFG != fg {
		t.Fatalf("terminal not restored: %v %v, group %d/%d, modes %+v/%+v", err, fgErr, afterFG, fg, before, after)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("LOGIN_HOME"), "result"), []byte("restored"), 0600); err != nil {
		t.Fatal(err)
	}
}
