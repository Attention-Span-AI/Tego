// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/mcprelay"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// shimKillWait is how long the shim waits after SIGTERM before it kills the server.
const shimKillWait = 2 * time.Second

// shimHelloWait bounds the service's answer to the hello.
const shimHelloWait = 10 * time.Second

// relayShim is `tego mcp relay --server <name> [--run <id>] -- <command...>` (ADR 0126 §4 "Stdio shim"): run by
// the agent's MCP client inside a run in place of the declared server. It connects to the run's MCP relay service
// ($TEGO_MCP_RELAY), is admitted by it, starts the declared server with sockets only it holds, and forwards nothing on
// its own: every client line goes to the service, which answers what to pass to the server or to the client. If the
// service goes away, the shim kills the server and exits non-zero, so no line ever reaches the server undecided.
type relayShim struct {
	server string
	argv   []string
	in     io.Reader
	out    io.Writer
	stderr io.Writer
	env    func(string) string
	// start registers its waiting child before releasing it to exec cmd.
	start func(*proc.Cmd, func(mcprelay.Frame) error) (int, error)
}

// shimEnvRefused are variables the shim refuses to run under: a library preloaded into the shim could forward
// lines the service never saw.
var shimEnvRefused = []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"}

// run is the shim's whole life; it returns the exit code.
func (s *relayShim) run(ctx context.Context) int {
	for _, name := range shimEnvRefused {
		if s.env(name) != "" {
			fmt.Fprintf(s.stderr, "tego mcp relay: refusing to run with %s set: a preloaded library could pass MCP messages around Tego's relay\n", name)
			return identity.ExitUsage
		}
	}
	if s.server == "" || len(s.argv) == 0 {
		fmt.Fprintln(s.stderr, "tego mcp relay: usage: tego mcp relay --server <name> [--run <id>] -- <command...>")
		return identity.ExitUsage
	}
	addr, err := netip.ParseAddrPort(s.env(mcprelay.EnvRelay))
	if err != nil || !addr.Addr().IsLoopback() {
		fmt.Fprintf(s.stderr, "tego mcp relay: %s is not a loopback address (%q): this command runs inside a tego run whose contract puts server %s behind the relay\n",
			mcprelay.EnvRelay, s.env(mcprelay.EnvRelay), s.server)
		return identity.ExitError
	}
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, shimHelloWait)
	conn, err := d.DialContext(dctx, "tcp", addr.String())
	cancel()
	if err != nil {
		fmt.Fprintf(s.stderr, "tego mcp relay: cannot reach the run's MCP relay at %s: %v\n", addr, err)
		return identity.ExitError
	}
	defer func() { _ = conn.Close() }()
	fw := mcprelay.NewFrameWriter(conn)
	fr := mcprelay.NewFrameReader(conn, 0)
	if err := fw.Write(mcprelay.Frame{V: mcprelay.ProtocolVersion, Server: s.server, Argv: s.argv, PID: os.Getpid()}); err != nil {
		fmt.Fprintf(s.stderr, "tego mcp relay: hello: %v\n", err)
		return identity.ExitError
	}
	_ = conn.SetReadDeadline(time.Now().Add(shimHelloWait))
	ans, err := fr.Read()
	_ = conn.SetReadDeadline(time.Time{})
	switch {
	case err != nil:
		fmt.Fprintf(s.stderr, "tego mcp relay: the relay did not answer: %v\n", err)
		return identity.ExitError
	case !ans.OK:
		fmt.Fprintf(s.stderr, "tego mcp relay: the relay refused server %s: %s\n", s.server, ans.Error)
		return identity.ExitFinding
	}

	cmd := proc.Command(s.argv[0], s.argv[1:]...)
	toServer, serverIn, err := serverChannel()
	if err != nil {
		fmt.Fprintf(s.stderr, "tego mcp relay: %v\n", err)
		return identity.ExitError
	}
	defer func() { _ = toServer.Close() }()
	fromServer, serverOut, err := serverChannel()
	if err != nil {
		_ = serverIn.Close()
		fmt.Fprintf(s.stderr, "tego mcp relay: %v\n", err)
		return identity.ExitError
	}
	defer func() { _ = fromServer.Close() }()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = serverIn, serverOut, os.Stderr
	pid, err := s.start(cmd, func(frame mcprelay.Frame) error {
		acknowledged := false
		defer func() {
			if !acknowledged {
				// Invalidate admission before start reaps the child: a delayed registration must not pin a reused PID.
				_ = conn.Close()
			}
		}()
		if err := fw.Write(frame); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(shimHelloWait))
		ans, err := fr.Read()
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			return err
		}
		if !ans.OK {
			return fmt.Errorf("relay refused server child: %s", ans.Error)
		}
		acknowledged = true
		return nil
	})
	// The server's ends are the server's now: a copy kept here would keep its input and output from ever ending.
	_, _ = serverIn.Close(), serverOut.Close()
	if err != nil {
		fmt.Fprintf(s.stderr, "tego mcp relay: start server %s: %v\n", s.server, err)
		return identity.ExitError
	}
	exited := make(chan struct{})
	if err := fw.Write(mcprelay.Frame{Started: pid}); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		fmt.Fprintf(s.stderr, "tego mcp relay: the relay went away: %v\n", err)
		return identity.ExitError
	}

	var (
		outMu  sync.Mutex
		srvMu  sync.Mutex
		done   = make(chan int, 3)
		closed = make(chan struct{})
		once   sync.Once
	)
	finish := func(code int) {
		once.Do(func() { close(closed) })
		done <- code
	}
	// Client lines go to the service only.
	go func() {
		br := bufio.NewReaderSize(s.in, 64<<10)
		for {
			line, oversize, err := mcprelay.ReadLine(br, mcprelay.MaxLine)
			if err != nil {
				// The client closed its end: the server's input ends too.
				srvMu.Lock()
				_ = toServer.Close()
				srvMu.Unlock()
				return
			}
			f := mcprelay.Frame{C: line}
			if oversize {
				f = mcprelay.Frame{Oversize: "c"}
			}
			if err := fw.Write(f); err != nil {
				return // the control reader sees the loss
			}
		}
	}()
	// Server lines go to the service only.
	go func() {
		br := bufio.NewReaderSize(fromServer, 64<<10)
		for {
			line, oversize, err := mcprelay.ReadLine(br, mcprelay.MaxLine)
			if err != nil {
				break
			}
			f := mcprelay.Frame{S: line}
			if oversize {
				f = mcprelay.Frame{Oversize: "s"}
			}
			if err := fw.Write(f); err != nil {
				break
			}
		}
		code := 0
		err := cmd.Wait()
		close(exited)
		if err != nil {
			var ee interface{ ExitCode() int }
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				code = identity.ExitError
			}
		}
		_ = fw.Write(mcprelay.Frame{Exit: &code})
		finish(code)
	}()
	// The service's frames are the only thing written to either side.
	go func() {
		for {
			f, err := fr.Read()
			if err != nil {
				select {
				case <-closed:
					return
				default:
				}
				fmt.Fprintf(s.stderr, "tego mcp relay: the run's MCP relay went away (%v); stopping server %s\n", err, s.server)
				killServer(cmd, exited)
				finish(identity.ExitError)
				return
			}
			switch {
			case f.ToServer != nil:
				srvMu.Lock()
				_, err = toServer.Write(append(f.ToServer, '\n'))
				srvMu.Unlock()
			case f.ToClient != nil:
				outMu.Lock()
				_, err = s.out.Write(append(f.ToClient, '\n'))
				outMu.Unlock()
			}
			if err != nil && f.ToClient != nil {
				// The client is gone; the server's input is closed by the client reader.
				continue
			}
		}
	}()
	select {
	case code := <-done:
		return code
	case <-ctx.Done():
		killServer(cmd, exited)
		return identity.ExitError
	}
}

// serverChannel is one of the server's two stdio channels: an AF_UNIX socket pair, mine the shim's end and theirs the
// server's. Not a pipe, because a pipe can be opened again through /proc/<pid>/fd/N by anything allowed to read that
// link, which needs no ptrace attach and no rule of the run's refuses, and a run's write there is a line the relay never
// decided. A socket cannot be: sock_no_open answers ENXIO, so only pidfd_getfd or ptrace reach it, and both need ATTACH
// (ADR 0126's stated residual). Only mine is non-blocking, for the runtime's poller; the flag is per end, and the server
// gets the blocking descriptor a program expects. A server that opens /dev/stdin by name fails with the same ENXIO.
func serverChannel() (mine, theirs *os.File, err error) {
	a, b, err := sys.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("server channel: %w", err)
	}
	defer func() { _, _ = a.Close(), b.Close() }() // a no-op on an end released below
	if err := a.Borrow(func(n int) error { return unix.SetNonblock(n, true) }); err != nil {
		return nil, nil, fmt.Errorf("server channel: %w", err)
	}
	if mine, err = a.Release("mcp-server"); err != nil {
		return nil, nil, fmt.Errorf("server channel: %w", err)
	}
	if theirs, err = b.Release("mcp-server-stdio"); err != nil {
		_ = mine.Close()
		return nil, nil, fmt.Errorf("server channel: %w", err)
	}
	return mine, theirs, nil
}

// killServer stops the server: SIGTERM, then SIGKILL after shimKillWait, and waits a little for exited (closed once
// the server was reaped), so the server never outlives the relay.
func killServer(cmd *proc.Cmd, exited <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
		return
	case <-time.After(shimKillWait):
	}
	_ = cmd.Process.Kill()
	select {
	case <-exited:
	case <-time.After(500 * time.Millisecond):
	}
}

// startRelayedServer starts a waiting copy of tego, registers that exact child, then releases it to exec the server
// in place. The close-on-exec control socket keeps Started after the exec gate, and reports exec failures. Failure
// to register, release or exec kills and reaps the stage, so an uncertain child never reaches the server.
func startRelayedServer(cmd *proc.Cmd, register func(mcprelay.Frame) error) (int, error) {
	control, childControl, err := serverChannel()
	if err != nil {
		return 0, err
	}
	defer func() { _, _ = control.Close(), childControl.Close() }()
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	if cmd.Err != nil {
		return 0, cmd.Err
	}
	cmd.Args = append([]string{exe, mcprelay.ServerCommand, cmd.Path}, cmd.Args...)
	cmd.Path = exe
	cmd.ExtraFiles = []*os.File{childControl}
	var st unix.Stat_t
	if err := sys.FstatFile(childControl, &st); err != nil {
		return 0, err
	}
	// The child is not known until Start returns, which waits for exec. Register its fresh socket first: the
	// supervisor sees it at fd 3 while that exec is held, and pins the exact child before granting the stage.
	if err := register(mcprelay.Frame{Stage: &mcprelay.StageRequest{Socket: st.Ino, Argv: cmd.Args}}); err != nil {
		return 0, err
	}
	id, err := proc.Start(cmd)
	if err != nil {
		return 0, err
	}
	_ = childControl.Close()
	started := false
	defer func() {
		if !started {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := register(mcprelay.Frame{Child: id.PID}); err != nil {
		return 0, err
	}
	if err := control.SetDeadline(time.Now().Add(shimHelloWait)); err != nil {
		return 0, err
	}
	if _, err := control.Write([]byte{1}); err != nil {
		return 0, err
	}
	msg, err := io.ReadAll(io.LimitReader(control, 4096))
	if err != nil {
		return 0, err
	}
	if len(msg) != 0 {
		return 0, fmt.Errorf("server exec: %s", msg)
	}
	started = true
	return id.PID, nil
}
