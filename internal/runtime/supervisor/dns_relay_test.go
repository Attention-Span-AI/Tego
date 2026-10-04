// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// This uses the production credential/path relay and the original shared socket
// description. The launcher connects; the child supplies kernel packet creds.
// It proves the bounded broker exception, not a complete governed CLI launch.
func TestDNSBrokerRelayedOriginalSocketAuthenticatesActualWriter(t *testing.T) {
	for _, relay := range []bool{false, true} {
		t.Run(strconv.FormatBool(relay), func(t *testing.T) {
			u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			var wg sync.WaitGroup
			wg.Go(func() {
				for {
					buf := make([]byte, dnsbroker.MaxPacket)
					n, from, err := u.ReadFromUDP(buf)
					if err != nil {
						return
					}
					calls.Add(1)
					var q dnsmessage.Message
					if q.Unpack(buf[:n]) != nil {
						continue
					}
					q.Response = true
					out, _ := q.Pack()
					_, _ = u.WriteToUDP(out, from)
				}
			})
			t.Cleanup(func() { u.Close(); wg.Wait() })
			policy, err := dnspolicy.Compile([]string{"allowed.example"}, []string{"A"})
			if err != nil {
				t.Fatal(err)
			}
			var sender atomic.Int32
			opts := dnsbroker.Options{UID: uint32(os.Geteuid()), Policy: policy, Upstreams: []netip.AddrPort{u.LocalAddr().(*net.UDPAddr).AddrPort()}, Timeout: time.Second,
				Authorize: func(p dnsbroker.Peer) error {
					if p.PID != int(sender.Load()) {
						return dnsbroker.ErrUnauthorized
					}
					return nil
				}}
			if relay {
				opts.RelayPID = os.Getpid()
			}
			b, err := dnsbroker.New(shortTempDir(t), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "original-governed-socket")
			defer file.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDNSRelayActualWriterHelper$")
			cmd.ExtraFiles = []*os.File{file}
			cmd.Env = append(os.Environ(), "TEGO_DNS_RELAY_HELPER=1")
			gate, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			cmd.Stdout, cmd.Stderr = &out, &out
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			sender.Store(int32(cmd.Process.Pid))
			var k sysKernel
			task, err := k.TaskOf(cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(task.root)
			defer unix.Close(task.cwd)
			outcome, err := k.ConnectUnixAs(fd, task, nil, b.Endpoint(), func(path string, _ unixFile) bool { return path == b.Endpoint() })
			if err != nil || outcome != unixConnected {
				t.Fatalf("production relay=%d %v", outcome, err)
			}
			_, _ = gate.Write([]byte("go\n"))
			_ = gate.Close()
			err = cmd.Wait()
			if relay {
				if err != nil || calls.Load() != 1 || !strings.Contains(out.String(), "authenticated-response") {
					t.Fatalf("actual child delivery err=%v calls=%d output=%s", err, calls.Load(), out.String())
				}
			} else if err == nil || calls.Load() != 0 {
				t.Fatalf("disabled relay authorized outside connector: err=%v calls=%d", err, calls.Load())
			}
		})
	}
}

func TestDNSRelayActualWriterHelper(t *testing.T) {
	if os.Getenv("TEGO_DNS_RELAY_HELPER") != "1" {
		return
	}
	var gate [3]byte
	if _, err := os.Stdin.Read(gate[:]); err != nil {
		os.Exit(2)
	}
	name, _ := dnsmessage.NewName("allowed.example.")
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 91, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	raw, err := q.Pack()
	if err == nil {
		_, err = unix.Write(3, raw)
	}
	if err == nil {
		err = unix.SetsockoptTimeval(3, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	}
	buf := make([]byte, dnsbroker.MaxPacket)
	n := 0
	if err == nil {
		n, err = unix.Read(3, buf)
	}
	var answer dnsmessage.Message
	if err != nil || n == 0 || answer.Unpack(buf[:n]) != nil || answer.ID != q.ID || !answer.Response {
		os.Exit(2)
	}
	fmt.Println("authenticated-response", hex.EncodeToString(buf[:n]))
	os.Exit(0)
}
