// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/mcprelay"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func shimEnv(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// TestShimRefusesPreload: a preloaded library could pass lines around the relay, so the shim will not run under one.
func TestShimRefusesPreload(t *testing.T) {
	var stderr bytes.Buffer
	sh := &relayShim{server: "files", argv: []string{"cat"}, in: strings.NewReader(""), out: &bytes.Buffer{}, stderr: &stderr,
		env: shimEnv(map[string]string{"LD_PRELOAD": "/tmp/x.so", mcprelay.EnvRelay: "127.0.0.1:1"}), start: startRelayedServer}
	if code := sh.run(context.Background()); code != identity.ExitUsage || !strings.Contains(stderr.String(), "LD_PRELOAD") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestShimWaitsForChildRegistration(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(strconv.FormatBool(refuse), func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "server-ran")
			cmd := proc.Command("sh", "-c", `echo ran > "$1"`, "sh", marker)
			var child int
			denied := errors.New("registration refused")
			pid, err := startRelayedServer(cmd, func(f mcprelay.Frame) error {
				if f.Stage != nil {
					return nil
				}
				child = f.Child
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("server ran before child registration: %v", err)
				}
				if refuse {
					return denied
				}
				return nil
			})
			if refuse {
				if !errors.Is(err, denied) || child <= 0 {
					t.Fatalf("registration: child %d, err %v", child, err)
				}
				if err := syscall.Kill(child, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatalf("refused child was not reaped: %v", err)
				}
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("refused child ran the server: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			if pid != child {
				t.Fatalf("server pid %d differs from registered child %d", pid, child)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestShimReportsServerExecFailure(t *testing.T) {
	cmd := proc.Command(filepath.Join(t.TempDir(), "missing-server"))
	if _, err := startRelayedServer(cmd, func(mcprelay.Frame) error { return nil }); err == nil {
		t.Fatal("the child stage hid the server's exec failure")
	}
}

// A failed registration must invalidate the shim's admission before start cleans
// up/reaps its child, or a delayed pidfd_open could name a recycled PID.
func TestShimClosesAdmissionBeforeFailedChildCleanup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	closed := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			closed <- false
			return
		}
		defer func() { _ = c.Close() }()
		fr, fw := mcprelay.NewFrameReader(c, 0), mcprelay.NewFrameWriter(c)
		_, _ = fr.Read()
		_ = fw.Write(mcprelay.Frame{OK: true})
		_, _ = fr.Read()
		_ = fw.Write(mcprelay.Frame{Error: "registration refused"})
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b [1]byte
		_, err = c.Read(b[:])
		closed <- errors.Is(err, io.EOF)
	}()
	var stderr bytes.Buffer
	sh := &relayShim{server: "files", argv: []string{"cat"}, in: strings.NewReader(""), out: io.Discard,
		stderr: &stderr, env: shimEnv(map[string]string{mcprelay.EnvRelay: ln.Addr().String()}),
		start: func(_ *proc.Cmd, register func(mcprelay.Frame) error) (int, error) {
			err := register(mcprelay.Frame{Child: 7})
			if err == nil {
				t.Fatal("the refused registration succeeded")
			}
			// This is the point at which startRelayedServer would kill and reap the child.
			if !<-closed {
				t.Error("the admission was still live when the failed child would be reaped")
			}
			return 0, err
		}}
	if code := sh.run(context.Background()); code != identity.ExitError {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

// TestShimForwardsOnlyServiceFramesAndKillsServerOnDrop: the shim writes to the server only what a to_server frame
// says, and when the relay's connection drops it kills the server and exits non-zero.
func TestShimForwardsOnlyServiceFramesAndKillsServerOnDrop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	pidc := make(chan int, 1)
	lines := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		fr, fw := mcprelay.NewFrameReader(c, 0), mcprelay.NewFrameWriter(c)
		if h, err := fr.Read(); err != nil || h.Server != "files" {
			_ = c.Close()
			return
		}
		_ = fw.Write(mcprelay.Frame{OK: true})
		for {
			f, err := fr.Read()
			if err != nil {
				return
			}
			switch {
			case f.Stage != nil || f.Child != 0:
				_ = fw.Write(mcprelay.Frame{OK: true})
			case f.Started != 0:
				pidc <- f.Started
			case f.C != nil:
				// Pass the client's line to the server; cat echoes it back as a server line.
				_ = fw.Write(mcprelay.Frame{ToServer: f.C})
			case f.S != nil:
				lines <- string(f.S)
				// The relay goes away: the shim must stop the server.
				_ = c.Close()
				return
			}
		}
	}()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pw.Close() }()
	var stderr, stdout bytes.Buffer
	sh := &relayShim{server: "files", argv: []string{"cat"}, in: pr, out: &stdout, stderr: &stderr,
		env: shimEnv(map[string]string{mcprelay.EnvRelay: ln.Addr().String()}),
		start: func(c *proc.Cmd, register func(mcprelay.Frame) error) (int, error) {
			return startRelayedServer(c, register)
		}}
	done := make(chan int, 1)
	go func() { done <- sh.run(context.Background()) }()
	var pid int
	select {
	case pid = <-pidc:
	case <-time.After(5 * time.Second):
		t.Fatalf("the server never started: %s", stderr.String())
	}
	if _, err := pw.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case l := <-lines:
		if !strings.Contains(l, `"ping"`) {
			t.Fatalf("server line %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the allowed line never reached the server")
	}
	select {
	case code := <-done:
		if code == identity.ExitOK {
			t.Fatalf("exit 0 after the relay dropped: %s", stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the shim did not exit after the relay dropped")
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("server %d outlived the relay", pid)
	}
	if stdout.Len() != 0 {
		t.Fatalf("the shim wrote to the client on its own: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "went away") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

// TestMCPSwitchRecheckedUnderTheLock: a switch that did not loosen on its read, with another terminal's Deny landing
// before the writers' lock, is decided again under the lock. It loosens now and nobody confirmed that, so it changes
// nothing, says why, and the Deny stands. --yes answers the question it was asked, not this one.
func TestMCPSwitchRecheckedUnderTheLock(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"allow on allow", []string{"allow"}},
		{"ask on allow", []string{"ask"}},
		{"reset with no switch", []string{"reset"}},
		{"allow on allow with --yes", []string{"allow", "--yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, id, _ := liveRun(t)
			if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(mcpCLIContract), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ask.SocketName), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			old := selfInRun
			selfInRun = func() (bool, error) { return false, nil }
			t.Cleanup(func() { selfInRun = old })
			mcpBeforeLock = func() {
				if _, err := mcptools.Update(context.Background(), dir, id, func(o *mcptools.Overlay) (bool, error) {
					return o.Set("files", "read_file", mcptools.Deny, "uid:1 pid:3 cli", time.Now())
				}); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { mcpBeforeLock = nil })
			args := append([]string{"mcp"}, tc.args...)
			code, out, errs := run(t, append(args, id, "files", "read_file")...)
			if code != identity.ExitFinding || strings.Contains(out, "Go ahead?") || !strings.Contains(errs, "moved to deny while this ran") {
				t.Fatalf("stale switch: exit %d stdout %q stderr %q", code, out, errs)
			}
			o, err := mcptools.Read(dir, id)
			if err != nil {
				t.Fatal(err)
			}
			if e, ok := o.Lookup("files", "read_file"); !ok || e.Decision != mcptools.Deny {
				t.Fatalf("the Deny did not stand: %+v", o)
			}
		})
	}
}

const mcpCLIContract = `version: 0
name: t
command: [python3]
mcp:
  - name: files
    command: [python3, /opt/fake-mcp/server.py]
    tools: {}
`

// TestShimServerStdioCannotBeReopened: the server's stdin and stdout, and the shim's own ends of them, cannot be opened
// through /proc. As pipes they could: a run's write-open of /proc/<server>/fd/0 needs no ptrace attach, no rule refuses
// a nameless object, and what it wrote reached the server with no line ever decided.
func TestShimServerStdioCannotBeReopened(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	pidc := make(chan int, 1)
	lines := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		fr, fw := mcprelay.NewFrameReader(c, 0), mcprelay.NewFrameWriter(c)
		if _, err := fr.Read(); err != nil {
			return
		}
		_ = fw.Write(mcprelay.Frame{OK: true})
		for {
			f, err := fr.Read()
			if err != nil {
				return
			}
			switch {
			case f.Stage != nil || f.Child != 0:
				_ = fw.Write(mcprelay.Frame{OK: true})
			case f.Started != 0:
				pidc <- f.Started
			case f.C != nil:
				_ = fw.Write(mcprelay.Frame{ToServer: f.C})
			case f.S != nil:
				lines <- string(f.S)
			}
		}
	}()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pw.Close() }()
	var stderr, stdout bytes.Buffer
	sh := &relayShim{server: "files", argv: []string{"cat"}, in: pr, out: &stdout, stderr: &stderr,
		env: shimEnv(map[string]string{mcprelay.EnvRelay: ln.Addr().String()}), start: startRelayedServer}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- sh.run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	var pid int
	select {
	case pid = <-pidc:
	case <-time.After(5 * time.Second):
		t.Fatalf("the server never started: %s", stderr.String())
	}
	for _, path := range []string{"/proc/" + strconv.Itoa(pid) + "/fd/0", "/proc/" + strconv.Itoa(pid) + "/fd/1"} {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			_, _ = f.WriteString(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_file"}}` + "\n")
			_ = f.Close()
			t.Fatalf("%s opened for write: a run reaches the server around the relay", path)
		}
		if !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("%s: %v, want ENXIO", path, err)
		}
	}
	// The shim is this test's process here: every socket it holds, its ends of the channels among them, refuses too.
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	sockets := 0
	for _, e := range ents {
		path := "/proc/self/fd/" + e.Name()
		if l, err := os.Readlink(path); err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		sockets++
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
			t.Fatalf("%s opened for write", path)
		}
	}
	if sockets == 0 {
		t.Fatal("the shim holds no socket: the server's channels are not sockets")
	}
	// The relayed path still works over the sockets, in both directions.
	if _, err := pw.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case l := <-lines:
		if !strings.Contains(l, `"ping"`) {
			t.Fatalf("server line %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a relayed line never came back from the server")
	}
}

// TestShimClientEOFEndsTheServer: the client closing its end ends the server's input, so a server that stops at end of
// input exits and the shim exits with it, over the sockets as over the pipes they replaced.
func TestShimClientEOFEndsTheServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		fr, fw := mcprelay.NewFrameReader(c, 0), mcprelay.NewFrameWriter(c)
		if _, err := fr.Read(); err != nil {
			return
		}
		_ = fw.Write(mcprelay.Frame{OK: true})
		for {
			f, err := fr.Read()
			if err != nil {
				return
			}
			if f.Stage != nil || f.Child != 0 {
				_ = fw.Write(mcprelay.Frame{OK: true})
			}
		}
	}()
	var stderr, stdout bytes.Buffer
	sh := &relayShim{server: "files", argv: []string{"cat"}, in: strings.NewReader(""), out: &stdout, stderr: &stderr,
		env: shimEnv(map[string]string{mcprelay.EnvRelay: ln.Addr().String()}), start: startRelayedServer}
	done := make(chan int, 1)
	go func() { done <- sh.run(context.Background()) }()
	select {
	case code := <-done:
		if code != identity.ExitOK {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server never saw the end of its input")
	}
}
