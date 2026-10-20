// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationMCPURLAdmitsItsEndpoint is agent-contract.md R16a end to end at tier 1: a contract whose net:
// section lists nothing declares an HTTP MCP server by url, and the agent's connect to that URL's port is admitted
// and recorded under the server's rule, mcp[local], while a connect to another port of the same host is refused, and
// so is a UDP datagram to the URL's own port: both HTTP transports are TCP, and the derived rule admits TCP only.
func TestIntegrationMCPURLAdmitsItsEndpoint(t *testing.T) {
	for _, bin := range []string{"/bin/sh", "/bin/bash"} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("%s is not available: %v", bin, err)
		}
	}
	listen := func() (net.Listener, int, chan struct{}) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan struct{}, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				_ = c.Close()
				accepted <- struct{}{}
			}
		}()
		return ln, ln.Addr().(*net.TCPAddr).Port, accepted
	}
	server, port, accepted := listen()
	defer server.Close()
	other, otherPort, otherAccepted := listen()
	defer other.Close()
	udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("udp port %d, the server's, is taken: %v", port, err)
	}
	defer udp.Close()
	datagram := make(chan struct{}, 1)
	go func() {
		if _, _, err := udp.ReadFrom(make([]byte, 64)); err == nil {
			datagram <- struct{}{}
		}
	}()

	shPath, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	bashPath, err := filepath.EvalSymlinks("/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: imcpurl
command: [%q]
tier: landlock
mcp:
  - name: local
    url: "http://127.0.0.1:%d/mcp"
fs:
  write: ["./out/"]
exec:
  allow: [%q, %q]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: summary
`, shPath, port, shPath, bashPath)
	f := newFixture(t, contract)
	script := filepath.Join(f.dir, "mcpurl.sh")
	body := fmt.Sprintf(`#!/bin/sh
%s -c 'exec 3<>/dev/tcp/127.0.0.1/%d' || exit 12
%s -c 'exec 3<>/dev/tcp/127.0.0.1/%d' && exit 13
%s -c 'echo x >/dev/udp/127.0.0.1/%d' && exit 14
exit 0
`, bashPath, port, bashPath, otherPort, bashPath, port)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	res, err := Run(context.Background(), f.rt, []string{shPath, script}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d (reason %s): 12 is the server's connect refused, 13 the other port's admitted, 14 a datagram to the server's port admitted", res.ExitCode, res.Reason)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the connect to the server's url never reached it")
	}
	select {
	case <-otherAccepted:
		t.Fatal("a connect to a port no entry names reached its listener")
	default:
	}
	select {
	case <-datagram:
		t.Fatal("a UDP datagram to the server's port reached it")
	default:
	}
	var admitted, refused, udpRefused bool
	for _, e := range events(t, runDirs(t, f.root)[0]) {
		var p record.NetPayload
		if e.Kind != record.KindNet || e.DecodePayload(&p) != nil {
			continue
		}
		switch {
		case p.Dst == fmt.Sprintf("127.0.0.1:%d", port) && p.Proto == "udp":
			udpRefused = e.Verdict == record.VerdictRefused
		case p.Dst == fmt.Sprintf("127.0.0.1:%d", port):
			admitted = e.Verdict == record.VerdictAllow && e.Rule == "mcp[local]"
		case p.Dst == fmt.Sprintf("127.0.0.1:%d", otherPort):
			refused = e.Verdict == record.VerdictRefused
		}
	}
	if !admitted || !refused || !udpRefused {
		t.Fatalf("net lines: the server's connect allowed under mcp[local] %v, the other port's refused %v, the datagram to the server's port refused %v", admitted, refused, udpRefused)
	}
}
