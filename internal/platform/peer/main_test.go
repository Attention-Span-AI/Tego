// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// clientArg makes the test binary a client of a test's socket: clientArg <mode> <socket path>. It connects and writes
// one byte; in mode "stay" it then holds the connection until the server closes it, and in mode "exit" it exits at
// once. The integration test runs it as the agent of a real run. In mode "identify-self" it serves the socket at the
// path itself, connects to it, and prints what Identify, and the fallback below Linux 6.5, say of the connection
// (identifyReport lines).
const clientArg = "-tego-peer-test-client"

// identifyReport begins each line identify-self prints: "<prefix> <host> code=<code> peer=<peer>".
const identifyReport = "identify-report"

// leaderExitMode is the client whose first thread exits while another of its threads holds the connection
// (leaderExit): what a process looks like after pthread_exit in main.
const leaderExitMode = "leader-exit"

// init keeps the main goroutine on the process's first thread in leader-exit mode, so that leaderExit can end that
// thread alone: the runtime leaves the main goroutine on the first thread when an init function locks it there.
func init() {
	if len(os.Args) == 4 && os.Args[1] == clientArg && os.Args[2] == leaderExitMode {
		runtime.LockOSThread()
	}
}

// leaderExit connects from another thread, then ends the process's first thread with exit(2), which ends one thread
// and not the process: the leader is a zombie from then on, and the thread holding the connection runs until the
// server closes it.
func leaderExit(path string) int {
	connected := make(chan error, 1)
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			_, err = c.Write([]byte{1})
		}
		connected <- err
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		os.Exit(0)
	}()
	if err := <-connected; err != nil {
		fmt.Fprintln(os.Stderr, "peer test leader-exit:", err)
		return 2
	}
	_, _, _ = syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0) // this thread only; the process lives on in the other
	return 2
}

// handoffMode is the listener that hands its listening socket to a child and exits (handoff), and holdMode that
// child (hold): the socket stays served by a process that never called listen on it, so SO_PEERCRED on a connection
// to it still names the listener that is gone.
const (
	handoffMode = "listen-handoff"
	holdMode    = "hold-listener"
)

// handoff listens at path, starts the holder with the listening socket as its descriptor 3, says so and exits.
func handoff(path string) int {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer test listen-handoff:", err)
		return 2
	}
	ln.SetUnlinkOnClose(false)
	f, err := ln.File()
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer test listen-handoff:", err)
		return 2
	}
	cmd := exec.Command(os.Args[0], clientArg, holdMode, path)
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "peer test listen-handoff:", err)
		return 2
	}
	fmt.Println("handed off")
	return 0
}

// hold keeps the inherited listening socket open, without touching it, until the socket's file is removed (the
// test's cleanup) or a minute has passed.
func hold(path string) int {
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := os.Lstat(path); err != nil {
			return 0
		}
	}
	return 0
}

func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == clientArg && os.Args[2] == leaderExitMode {
		os.Exit(leaderExit(os.Args[3]))
	}
	if len(os.Args) == 4 && os.Args[1] == clientArg && os.Args[2] == handoffMode {
		os.Exit(handoff(os.Args[3]))
	}
	if len(os.Args) == 4 && os.Args[1] == clientArg && os.Args[2] == holdMode {
		os.Exit(hold(os.Args[3]))
	}
	if len(os.Args) == 4 && os.Args[1] == clientArg && os.Args[2] == "identify-self" {
		os.Exit(identifySelf(os.Args[3]))
	}
	if len(os.Args) == 4 && os.Args[1] == clientArg {
		os.Exit(client(os.Args[2], os.Args[3]))
	}
	os.Exit(testutil.GuardedMain(m))
}

// identifySelf connects this process to a socket it serves at path and reports what Identify says of the peer.
func identifySelf(path string) int {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer test identify-self:", err)
		return 2
	}
	defer func() { _ = ln.Close() }()
	cl, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer test identify-self:", err)
		return 2
	}
	defer func() { _ = cl.Close() }()
	server, err := ln.AcceptUnix()
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer test identify-self:", err)
		return 2
	}
	defer func() { _ = server.Close() }()
	fallback := kernel
	fallback.noPeerPidfd = true
	for name, h := range map[string]host{"kernel": kernel, "fallback": fallback} {
		p, err := h.identify(server)
		fmt.Printf("%s %s code=%s pid=%d peer=%+v err=%v\n", identifyReport, name, codeOf(err), os.Getpid(), p, err)
	}
	return 0
}

// undumpableMode is the client that makes itself undumpable first, as a process that holds a secret does, and then
// behaves as "stay" does.
const undumpableMode = "stay-undumpable"

func client(mode, path string) int {
	if mode == undumpableMode {
		if err := sys.MakeUndumpable(); err != nil {
			fmt.Fprintln(os.Stderr, "peer test client:", err)
			return 2
		}
		mode = "stay"
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer test client:", err)
		return 2
	}
	if _, err := c.Write([]byte{1}); err != nil {
		fmt.Fprintln(os.Stderr, "peer test client:", err)
		return 2
	}
	if mode == "stay" {
		_, _ = io.Copy(io.Discard, c)
	}
	return 0
}
