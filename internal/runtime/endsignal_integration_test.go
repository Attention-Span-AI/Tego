// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationRunEndSignalOfAnEscalatedStop checks real cgroup.kill and the resulting ledger and receipt for
// grace expiry and immediate double-interrupt escalation. The readiness file proves both traps are installed.
func TestIntegrationRunEndSignalOfAnEscalatedStop(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grace      time.Duration
		marker     bool
		signals    []syscall.Signal
		wantSig    int
		wantReason string
	}{
		{"SIGTERM and the grace runs out", time.Second, false, []syscall.Signal{syscall.SIGTERM}, int(syscall.SIGTERM), record.RunEndSignal},
		{"tego stop and the grace runs out", time.Second, true, []syscall.Signal{syscall.SIGTERM}, int(syscall.SIGTERM), record.RunEndStopped},
		{"two SIGINT in a row under a grace of a minute", time.Minute, false, []syscall.Signal{syscall.SIGINT, syscall.SIGINT}, int(syscall.SIGINT), record.RunEndSignal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("iendsig", []string{"/bin/sh"}, []string{"/bin/sh", "/bin/sleep"}))
			f.machine.StopGrace = config.Setting[time.Duration]{Value: tc.grace}
			script := filepath.Join(f.dir, "deaf.sh")
			trapped := filepath.Join(f.out, "trapped")
			if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap '' TERM INT\n: > \"$1\"\nwhile true; do sleep 1; done\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			signals := make(chan os.Signal, 2)
			// This may build the helper binary. Finish it before starting the readiness deadline, and keep every
			// testing.T call on this goroutine. Run must be joined before deferred fixture cleanup can remove paths.
			deps := f.deps(t, signals)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			var res Result
			var runErr error
			go func() {
				defer close(done)
				res, runErr = Run(ctx, f.rt, []string{"/bin/sh", script, trapped}, deps)
			}()
			defer func() { cancel(); <-done }()

			ready := time.NewTicker(10 * time.Millisecond)
			defer ready.Stop()
			deadline := time.NewTimer(30 * time.Second)
			defer deadline.Stop()
			var dir string
		waiting:
			for {
				select {
				case <-done:
					t.Fatalf("Run ended before agent readiness: result %+v, error %v", res, runErr)
				case <-deadline.C:
					t.Fatal("agent did not install its signal traps within 30s")
				case <-ready.C:
					if _, err := os.Stat(trapped); err == nil {
						dir = liveRun(t, f.root, true)
						if dir != "" {
							break waiting
						}
					} else if !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
			}
			if tc.marker {
				if err := RequestStopGrace(dir, 0); err != nil {
					t.Fatalf("RequestStopGrace: %v", err)
				}
			}
			start := time.Now()
			for _, sig := range tc.signals {
				signals <- sig
			}
			select {
			case <-done:
				if runErr != nil || res.Reason != tc.wantReason {
					t.Fatalf("Run: result %+v, error %v, want reason %s", res, runErr, tc.wantReason)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the run did not end within 30s")
			}
			t.Logf("ended %v after the first signal", time.Since(start).Round(time.Millisecond))
			evs := events(t, dir)
			if len(evs) == 0 || evs[len(evs)-1].Kind != record.KindRunEnd {
				t.Fatal("the ledger has no final run_end")
			}
			var end record.RunEndPayload
			if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
				t.Fatal(err)
			}
			t.Logf("run_end: reason=%s signal=%d escalated=%v exit_code=%d", end.Reason, end.Signal, end.Escalated, end.ExitCode)
			if !end.Escalated || end.Signal != tc.wantSig || end.Reason != tc.wantReason {
				t.Fatalf("run_end %+v, want %s escalated with signal %d", end, tc.wantReason, tc.wantSig)
			}
			if tc.grace >= time.Minute && time.Since(start) >= tc.grace {
				t.Errorf("two interrupts waited %v, the grace is %v", time.Since(start), tc.grace)
			}
			var receipt struct {
				Signal    int  `json:"signal"`
				Escalated bool `json:"escalated"`
			}
			if err := json.Unmarshal(integrationReceipt(t, f, dir, true), &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.Signal != tc.wantSig || !receipt.Escalated {
				t.Errorf("receipt %+v, want signal %d escalated", receipt, tc.wantSig)
			}
			text := string(integrationReceipt(t, f, dir, false))
			if tc.wantReason == record.RunEndSignal && !strings.Contains(text, fmt.Sprintf("ended by signal %d, then killed by Tego", tc.wantSig)) {
				t.Errorf("receipt does not name the signal and neutral kill wording:\n%s", text)
			}
		})
	}
}

// integrationReceipt uses only the test-hook binary and isolated config/anchor/log paths. Keeping this a CLI
// boundary also respects runtime's prohibition on importing internal/check.
func integrationReceipt(t *testing.T, f *fixture, dir string, asJSON bool) []byte {
	t.Helper()
	args := []string{"receipt", dir}
	if asJSON {
		args = append(args, "--json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tegoBinary(t), args...)
	cmd.Dir = f.dir
	cmd.Env = isolatedEnv(t, f)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("receipt: %v\n%s", err, out)
	}
	return out
}

// TestIntegrationObserveNamesAnUnspecSend checks real sends with different kernel outcomes: an IPv4 datagram
// delivered to the supplied address, a connected IPv6 datagram delivered to its peer, and a failed IPv6 send.
// Every line records an attempted send whose destination and result were not established by the supervisor.
func TestIntegrationObserveNamesAnUnspecSend(t *testing.T) {
	python, resolved := pythonPaths(t)
	for _, tc := range []struct {
		name, network, host          string
		family, connected, delivered bool
	}{
		{"IPv4 supplied address", "udp4", "127.0.0.1", false, false, true},
		{"IPv6 connected peer", "udp6", "::1", true, true, true},
		{"IPv6 no peer", "udp6", "::1", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("iunspecsend", []string{python}, []string{python, resolved}))
			f.backend = enforce.Observe()
			pc, err := net.ListenPacket(tc.network, net.JoinHostPort(tc.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			port := pc.LocalAddr().(*net.UDPAddr).Port
			family := "socket.AF_INET"
			if tc.family {
				family = "socket.AF_INET6"
			}
			connect := ""
			if tc.connected {
				connect = fmt.Sprintf("s.connect((%q, %d))", tc.host, port)
			}
			expect := "n == 4"
			if !tc.delivered {
				expect = "n == -1"
			}
			script := filepath.Join(f.dir, "unspec.py")
			body := fmt.Sprintf(`import ctypes, socket, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
s = socket.socket(%s, socket.SOCK_DGRAM)
%s
# An IPv6 connected socket uses its existing peer, even though this address spells an IPv4 destination.
sa = struct.pack("<H", socket.AF_UNSPEC) + struct.pack("!H", %d) + socket.inet_aton("127.0.0.1") + bytes(8)
n = libc.sendto(s.fileno(), b"ping", 4, 0, sa, len(sa))
print("sendto result", n, "errno", ctypes.get_errno(), flush=True)
sys.exit(0 if %s else 7)
`, family, connect, port, expect)
			if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			deps := f.deps(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := Run(ctx, f.rt, []string{python, script}, deps)
			if err != nil || res.ExitCode != 0 {
				t.Fatalf("Run: result %+v, error %v: unexpected kernel send result", res, err)
			}
			if tc.delivered {
				if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 64)
				n, _, err := pc.ReadFrom(buf)
				if err != nil || string(buf[:n]) != "ping" {
					t.Fatalf("datagram: %q, error %v", buf[:n], err)
				}
			}
			dirs := runDirs(t, f.root)
			if len(dirs) != 1 {
				t.Fatalf("run directories %v, want one", dirs)
			}
			saw := 0
			for _, e := range events(t, dirs[0]) {
				if e.Kind == record.KindRefused {
					t.Errorf("an observe run wrote a refused event: %+v", e)
				}
				if e.Kind != record.KindNet {
					continue
				}
				var p record.NetPayload
				if err := e.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.Dst != "unspec" {
					continue
				}
				saw++
				t.Logf("net line: verdict=%s rule=%s dst=%s proto=%s", e.Verdict, e.Rule, p.Dst, p.Proto)
				if e.Verdict != record.VerdictObserved || e.Rule != "net.unspec-send" {
					t.Errorf("the send's line is %s rule %q, want observed net.unspec-send", e.Verdict, e.Rule)
				}
			}
			if saw != 1 {
				t.Errorf("%d AF_UNSPEC send lines, want one", saw)
			}
			text := string(integrationReceipt(t, f, dirs[0], false))
			if !strings.Contains(text, "unread address, AF_UNSPEC send") {
				t.Errorf("receipt omitted attempted send:\n%s", text)
			}
		})
	}
}
