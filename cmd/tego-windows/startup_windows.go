// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

const scopeReadyLine = "TEGO_SCOPE_READY"

// linuxReady keeps a private WSL client alive while the person's command runs.
// WSL can start a command before the lingering user manager is ready and print
// a spurious failure first. Only this bootstrap's diagnostics are captured;
// the person's command keeps its original stdin, stdout, stderr and status.
// This is not a background service or a dashboard transport.
type linuxReady struct {
	cmd   *exec.Cmd
	input io.WriteCloser
	done  chan struct{}
	log   startupLog
}

type startupLog struct{ data []byte }

func (s *startupLog) Write(p []byte) (int, error) {
	if left := 4096 - len(s.data); left > 0 {
		s.data = append(s.data, p[:min(left, len(p))]...)
	}
	return len(p), nil
}

func (r *linuxReady) close() {
	_ = r.input.Close()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-r.done:
	case <-timer.C:
		// cmd retains this exact child's Windows process handle.
		_ = r.cmd.Process.Kill()
		<-r.done
	}
}

// startLinuxReady is a reviewed start before any engine arming: it launches
// fixed root-owned entry code as the tego user, with no caller payload. The
// entry must prove its required user scope before this client is accepted.
func startLinuxReady(interrupts <-chan os.Signal) (*linuxReady, int, error) {
	cmd := proc.Command(systemProgram("wsl.exe"), append(wslBaseArguments(), "--ready")...)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, 125, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, 125, err
	}
	r := &linuxReady{cmd: cmd, input: input, done: make(chan struct{})}
	cmd.Stderr = &r.log
	if err := startWindowsCommand(cmd); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, 125, err
	}
	go func() {
		_ = cmd.Wait()
		close(r.done)
	}()
	type answer struct {
		line string
		err  error
	}
	answered := make(chan answer, 1)
	go func() {
		line, readErr := bufio.NewReaderSize(output, 4096).ReadSlice('\n')
		answered <- answer{line: string(line), err: readErr}
	}()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	var failure string
	select {
	case <-interrupts:
		r.close()
		return nil, 130, nil
	case response := <-answered:
		if response.err == nil && strings.TrimRight(response.line, "\r\n") == scopeReadyLine {
			return r, 0, nil
		}
		failure = "Linux did not confirm its required user scope"
	case <-r.done:
		failure = "Linux exited before confirming its required user scope"
	case <-timer.C:
		failure = "Linux did not confirm its required user scope within 90 seconds"
	}
	r.close()
	// Wait completed all stderr copying before log is read. Ctrl-C can race
	// the bootstrap's EOF; a person's cancellation is never a repair error.
	select {
	case <-interrupts:
		return nil, 130, nil
	default:
	}
	if detail := strings.TrimSpace(string(r.log.data)); detail != "" {
		failure += ": " + detail
	}
	return nil, 125, errors.New(failure)
}
