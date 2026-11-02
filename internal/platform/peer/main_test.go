// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"

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

func TestMain(m *testing.M) {
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

func client(mode, path string) int {
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
