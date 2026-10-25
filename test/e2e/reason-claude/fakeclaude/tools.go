// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// A toolRun is what one call did and how the harness reports it.
type toolRun struct {
	Name     string
	Input    map[string]any
	Response any    // PostToolUse tool_response
	Text     string // the tool_result content the model sees when the call succeeded
	Err      string // set when the call failed: PostToolUseFailure's error and the tool_result content
	Duration time.Duration
}

const (
	defaultBashTimeout = 120 * time.Second
	connectTimeout     = 10 * time.Second
	maxCapture         = 1 << 20
)

// Execute performs the call as this process, with real syscalls (open, rename, execve, connect). cwd resolves a
// relative path and is the working directory of a command; env is the environment a command gets.
func (c Call) Execute(cwd string, env []string) toolRun {
	start := time.Now()
	var r toolRun
	switch c.Verb() {
	case "write":
		r = execWrite(abs(cwd, c.Write), c.Content, c.Inplace)
	case "read":
		r = execRead(abs(cwd, c.Read))
	case "run":
		r = execCommand(c, cwd, env, c.Run[0], c.Run[1:], shellJoin(c.Run))
	case "bash":
		r = execCommand(c, cwd, env, bashShell(), []string{"-c", c.Bash}, c.Bash)
	case "connect":
		r = execConnect(c.Connect)
	}
	r.Duration = time.Since(start)
	return r
}

// bashShell is the shell a bash call runs in: /bin/bash, as the real binary's Bash tool reports itself ("/bin/bash:
// <path>: ..."; RESULTS.md), else bash or sh from PATH.
func bashShell() string {
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	if _, err := exec.LookPath("bash"); err == nil {
		return "bash"
	}
	return "sh"
}

func abs(cwd, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}

var errnoNames = map[syscall.Errno]string{
	syscall.EACCES: "EACCES", syscall.EPERM: "EPERM", syscall.ENOENT: "ENOENT", syscall.EEXIST: "EEXIST",
	syscall.EROFS: "EROFS", syscall.ENOTDIR: "ENOTDIR", syscall.EISDIR: "EISDIR", syscall.ENOSPC: "ENOSPC",
	syscall.EINVAL: "EINVAL", syscall.ECONNREFUSED: "ECONNREFUSED", syscall.ETIMEDOUT: "ETIMEDOUT",
	syscall.ENETUNREACH: "ENETUNREACH", syscall.EHOSTUNREACH: "EHOSTUNREACH", syscall.EXDEV: "EXDEV",
}

// errText is Node's spelling of a failed system call, which is what Claude Code's tools report:
// "EACCES: permission denied, open '/path'".
func errText(op, target string, err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		name, ok := errnoNames[en]
		if !ok {
			name = fmt.Sprintf("errno %d", int(en))
		}
		return fmt.Sprintf("%s: %s, %s '%s'", name, strings.ToLower(en.Error()), op, target)
	}
	return fmt.Sprintf("%s '%s': %v", op, target, err)
}

func execWrite(path, content string, inplace bool) toolRun {
	r := toolRun{Name: "Write", Input: map[string]any{"file_path": path, "content": content}}
	kind := "create"
	if _, err := os.Lstat(path); err == nil {
		kind = "update"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.Err = errText("mkdir", filepath.Dir(path), err)
		return r
	}
	if inplace {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			r.Err = errText("open", path, err)
			return r
		}
	} else if err := writeViaRename(path, content); err != nil {
		r.Err = err.Error()
		return r
	}
	r.Response = map[string]any{"filePath": path, "type": kind}
	if kind == "create" {
		r.Text = "File created successfully at: " + path + " (file state is current in your context — no need to Read it back)"
	} else {
		r.Text = "The file " + path + " has been updated."
	}
	return r
}

// oPath is Linux's O_PATH (asm-generic/fcntl.h), which package syscall does not export.
const oPath = 0x200000

// writeViaRename is Claude Code 2.1.310's Write tool as measured (RESULTS.md R3): the target's directory is opened
// O_PATH, the text goes to <name>.tmp.<pid>.<12 hex digits> created through /proc/self/fd/<that descriptor>/, and
// the temporary file is renamed over the target, so a contract judges an open and a rename under /proc/self/fd/N/.
// An error names the real directory, as the real binary's does. A failed write's temporary file is unlinked through
// the same path at once (the real binary's unlink came 0.4 ms after the refused open), so a contract judges that
// unlink too: one unlink(2), as Node's, not os.Remove's unlink then rmdir, which tego refuses as two unlinks of the
// same path, told twice when a hook reads the reason file between them.
func writeViaRename(path, content string) error {
	dir := filepath.Dir(path)
	dfd, err := syscall.Open(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New(errText("open", dir, err))
	}
	defer func() { _ = syscall.Close(dfd) }()
	var suffix [6]byte
	_, _ = rand.Read(suffix[:]) // crypto/rand.Read never fails (Go 1.24)
	name := fmt.Sprintf("%s.tmp.%d.%s", filepath.Base(path), os.Getpid(), hex.EncodeToString(suffix[:]))
	via, shown := fmt.Sprintf("/proc/self/fd/%d/%s", dfd, name), filepath.Join(dir, name)
	failed := func(op, target string, err error) error {
		_ = syscall.Unlink(via) // best effort: the write already failed, and its error is the one reported
		return errors.New(errText(op, target, err))
	}
	f, err := os.OpenFile(via, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return failed("open", shown, err)
	}
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return failed("write", shown, err)
	}
	if err := os.Rename(via, path); err != nil {
		return failed("rename", shown+"' -> '"+path, err)
	}
	return nil
}

func execRead(path string) toolRun {
	r := toolRun{Name: "Read", Input: map[string]any{"file_path": path}}
	data, err := readRegular(path, maxCapture)
	switch {
	case errors.Is(err, errNotRegular):
		// a directory is what Node reports; a FIFO or a device is refused rather than read (it could block the turn
		// or never end)
		if fi, serr := os.Stat(path); serr == nil && fi.IsDir() {
			r.Err = "EISDIR: illegal operation on a directory, read"
		} else {
			r.Err = "'" + path + "' is not a regular file"
		}
		return r
	case errors.Is(err, errTooBig):
		r.Err = fmt.Sprintf("File content (%s) exceeds the %d byte limit of this stand-in's Read tool", path, maxCapture)
		return r
	case err != nil:
		r.Err = errText("open", path, err)
		return r
	}
	content := string(data)
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	var b strings.Builder
	for i, l := range lines {
		fmt.Fprintf(&b, "%d\t%s\n", i+1, l)
	}
	r.Text = b.String()
	r.Response = map[string]any{"type": "text", "file": map[string]any{
		"filePath": path, "content": content, "numLines": len(lines), "startLine": 1, "totalLines": len(lines),
	}}
	return r
}

// cappedBuffer keeps the first maxCapture bytes and drops the rest, so a noisy command cannot grow this process.
type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxCapture - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// toolWaitDelay is how long a finished command's output pipes may stay open (a child it left behind) before they are
// closed on it; a variable so that a test can shorten it.
var toolWaitDelay = 2 * time.Second

func execCommand(c Call, cwd string, env []string, name string, args []string, shown string) toolRun {
	r := toolRun{Name: "Bash", Input: map[string]any{"command": shown, "description": c.Description, "run_in_background": false}}
	if c.TimeoutMS > 0 {
		r.Input["timeout"] = c.TimeoutMS
	}
	limit := defaultBashTimeout
	if c.TimeoutMS > 0 {
		limit = time.Duration(c.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env = cwd, env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = toolWaitDelay
	// One pipe for both streams, so the output and the error keep the order they were written in, as the real
	// binary's Bash tool shows them (RESULTS.md: a refused git push's tool result is the shell's error, then the
	// echo's output). How the real binary splits them in tool_response is not measured; this one says stdout.
	var out cappedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	interrupted := false
	var ee *exec.ExitError
	var pe *os.PathError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		code, interrupted = -1, true
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case errors.Is(err, exec.ErrWaitDelay):
		// The command exited with success and a background child it left holds the output pipes: the command
		// succeeded, with the output it wrote before then.
	case errors.As(err, &pe) && errors.Is(pe.Err, syscall.ENOENT), errors.Is(err, exec.ErrNotFound):
		code = 127 // what a shell reports for a command it cannot find
		out.WriteString(name + ": command not found\n")
	default:
		code = 126 // and for one it cannot run: a refused execve is EACCES or EPERM
		out.WriteString(name + ": " + errReason(err) + "\n")
	}
	if code == 0 {
		r.Response = map[string]any{"stdout": out.String(), "stderr": "", "interrupted": false, "isImage": false}
		r.Text = out.String()
		return r
	}
	if interrupted {
		r.Err = "Command timed out after " + limit.String() + "\n" + out.String()
		return r
	}
	r.Err = fmt.Sprintf("Exit code %d\n%s", code, out.String())
	return r
}

func errReason(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		s := en.Error()
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return err.Error()
}

func execConnect(addr string) toolRun {
	r := toolRun{Name: "Connect", Input: map[string]any{"address": addr}}
	conn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		r.Err = errText("connect", addr, err)
		return r
	}
	local := conn.LocalAddr().String()
	_ = conn.Close()
	r.Response = map[string]any{"address": addr, "connected": true, "local": local}
	r.Text = "connected to " + addr
	return r
}

// shellJoin quotes an argv as a shell would read it back, for tool_input.command.
func shellJoin(argv []string) string {
	words := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_") == "" {
			words[i] = a
			continue
		}
		words[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(words, " ")
}
