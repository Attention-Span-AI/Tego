// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/winpeer"
	"github.com/attention-span-ai/tego/internal/relaymux"
	"golang.org/x/sys/windows"
)

// relayVerb is the hidden mode the relay runs in (relayMain).
const relayVerb = "__relay"

// soExclusiveAddrUse is Winsock's SO_EXCLUSIVEADDRUSE, ((int)(~SO_REUSEADDR)): no other socket, of any account,
// may bind the address while this one holds it, with or without SO_REUSEADDR (WSL's wslrelay.exe binds with it).
const soExclusiveAddrUse = ^4

// listenExclusive binds [::1]:port with SO_EXCLUSIVEADDRUSE set before the bind. Never 127.0.0.1 (wslrelay.exe's
// address in NAT mode), never a wildcard.
func listenExclusive(port int) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			// The standard library's call, the one a lent number may be given to (tools/fdcheck): the same
			// setsockopt that x/sys/windows makes.
			serr = syscall.SetsockoptInt(syscall.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
}

// tegoFolder is %LOCALAPPDATA%\Tego, which the installer made and which holds bin\tego.exe.
func tegoFolder() (string, error) {
	d := os.Getenv("LOCALAPPDATA")
	if d == "" || !filepath.IsAbs(d) {
		return "", errors.New("LOCALAPPDATA is not set to an absolute folder")
	}
	return filepath.Join(d, "Tego"), nil
}

// relayLog is the relay's own log, %LOCALAPPDATA%\Tego\relay.log, emptied when it grows past 1 MiB.
type relayLog struct {
	mu sync.Mutex
	f  *os.File
}

func openRelayLog() *relayLog {
	dir, err := tegoFolder()
	if err != nil {
		return &relayLog{}
	}
	p := filepath.Join(dir, "relay.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 1<<20 {
		_ = os.Remove(p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return &relayLog{}
	}
	return &relayLog{f: f}
}

func (l *relayLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_, _ = fmt.Fprintf(l.f, "%s pid %d: %s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), fmt.Sprintf(format, args...))
	}
}

// Write takes the Linux end's standard error into the log, line by line as it comes.
func (l *relayLog) Write(p []byte) (int, error) {
	l.printf("linux: %s", oneLine(string(p)))
	return len(p), nil
}

// relayStatus is the one line the relay hands its starter on its standard output before closing it: "READY" or
// "FAIL <words for the person>".
func relayStatus(w io.WriteCloser, line string) {
	_, _ = io.WriteString(w, line+"\n")
	_ = w.Close()
}

// relayMain is `tego.exe __relay <port>`, started hidden by `tego dashboard` (startRelay). It starts the wsl.exe
// child, checks that the Linux end serves the expected port, binds [::1]:port exclusively, records itself, says
// READY and serves until the child ends (the distribution stopped, the dashboard stopped or moved) or it is stopped.
func relayMain(args []string) int {
	status := io.WriteCloser(os.Stdout)
	log := openRelayLog()
	port, err := strconv.Atoi(argOr(args, 0))
	if len(args) != 1 || err != nil || port <= 0 || port > 65535 {
		relayStatus(status, "FAIL usage: tego.exe __relay <port>")
		return 2
	}
	self, err := winpeer.SelfUser()
	if err != nil {
		relayStatus(status, "FAIL "+relayFailedWords("this Windows user could not be read: "+err.Error()))
		return 125
	}
	cmd := proc.Command(systemProgram("wsl.exe"), append(wslBaseArguments(), "--relay")...)
	in, err := cmd.StdinPipe()
	if err != nil {
		relayStatus(status, "FAIL "+relayFailedWords(err.Error()))
		return 125
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		relayStatus(status, "FAIL "+relayFailedWords(err.Error()))
		return 125
	}
	cmd.Stderr = log
	if err := startWindowsCommand(cmd); err != nil {
		relayStatus(status, "FAIL "+relayFailedWords("wsl.exe did not start: "+err.Error()))
		return 125
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop := func() {
		_ = in.Close()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	// A cold distribution starts systemd, the user manager and the scope first; never wait without bound.
	timer := time.AfterFunc(120*time.Second, func() { _ = cmd.Process.Kill() })
	sess, err := relaymux.Start(out, in, relaymux.Options{Opener: true})
	timer.Stop()
	if err != nil {
		stop()
		relayStatus(status, "FAIL "+relayFailedWords("Tego's Linux did not answer: "+err.Error()+"; details: "+filepath.Join("%LOCALAPPDATA%", "Tego", "relay.log")))
		return 125
	}
	if err := helloPort(sess.PeerPort(), port); err != nil {
		_ = sess.Close()
		stop()
		relayStatus(status, "FAIL "+relayFailedWords(err.Error()))
		return 125
	}
	ln, err := listenExclusive(port)
	if err != nil {
		_ = sess.Close()
		stop()
		words := portReservedWords(port)
		if owner, ok := portOwner(port); ok {
			words = portTakenWords(port, owner)
		}
		relayStatus(status, "FAIL "+words)
		log.printf("bind [::1]:%d: %v", port, err)
		return 3
	}
	defer func() { _ = ln.Close() }()
	if err := writeRelayState(port); err != nil {
		log.printf("relay record: %v", err)
	}
	defer removeRelayState()
	log.printf("serving [::1]:%d for %s", port, self)
	relayStatus(status, "READY")
	go func() {
		<-sess.Done()
		_ = ln.Close()
	}()
	serveRelay(ln, sess, windowsOwner(self), log.printf)
	_ = sess.Close()
	stop()
	why := sess.Err()
	if errors.Is(why, io.EOF) {
		log.printf("ended: Tego's Linux stopped (its wsl.exe child ended); run tego dashboard to open the dashboard again")
	} else {
		log.printf("ended: %v", why)
	}
	return 0
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// windowsOwner is R2 on Windows: the client end of c must belong to a process of self, the relay's own user.
func windowsOwner(self string) func(c net.Conn) (uint32, error) {
	return func(c net.Conn) (uint32, error) {
		client := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		server := c.LocalAddr().(*net.TCPAddr).AddrPort()
		owner, err := winpeer.Check(netip.AddrPortFrom(client.Addr().Unmap(), client.Port()),
			netip.AddrPortFrom(server.Addr().Unmap(), server.Port()), self)
		return owner.PID, err
	}
}

// portOwner names the program that listens on [::1] or [::] at port, for the person's message: "name (pid n)", and
// whether one listens there at all.
func portOwner(port int) (string, bool) {
	rows, err := winpeer.Listeners()
	if err != nil {
		return "", true // unknown: say another program, never that nothing listens
	}
	for _, r := range rows {
		if int(r.Local.Port()) == port {
			if exe := processImage(r.PID); exe != "" {
				if strings.EqualFold(filepath.Base(exe), "wslrelay.exe") {
					// WSL forwards a Linux listener on [::] or [::1] to Windows [::1]: the program to close is in Linux.
					return "a program inside WSL listening on [::] or [::1] (forwarded by wslrelay.exe, pid " + strconv.Itoa(int(r.PID)) + ")", true
				}
				return filepath.Base(exe) + " (pid " + strconv.Itoa(int(r.PID)) + ")", true
			}
			return "a program of another account (pid " + strconv.Itoa(int(r.PID)) + ")", true
		}
	}
	return "", false
}

// processImage is the full path of pid's program, or "" when it cannot be read.
func processImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// readProcess is what Windows says about pid: creation time, program and user; open is false when any of it could
// not be read.
func readProcess(pid uint32) processFacts {
	start, err := creationTime(pid)
	if err != nil {
		return processFacts{}
	}
	exe := processImage(pid)
	sid, err := winpeer.ProcessUser(pid)
	if exe == "" || err != nil {
		return processFacts{}
	}
	return processFacts{open: true, start: start, exe: exe, sid: sid}
}

func relayStatePath() (string, error) {
	dir, err := tegoFolder()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "relay.json"), nil
}

// writeRelayState records this relay; a same-folder temporary file and a rename, so a reader never sees half.
func writeRelayState(port int) error {
	p, err := relayStatePath()
	if err != nil {
		return err
	}
	start, err := creationTime(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	b, err := json.Marshal(relayState{PID: uint32(os.Getpid()), Start: start, Port: port, Exe: processImage(uint32(os.Getpid()))})
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// removeRelayState removes the record when it still names this process.
func removeRelayState() {
	p, err := relayStatePath()
	if err != nil {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if s, err := parseRelayState(b); err == nil && s.PID == uint32(os.Getpid()) {
		_ = os.Remove(p)
	}
}

// creationTime is pid's process creation FILETIME, its identity across pid reuse.
func creationTime(pid uint32) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}
