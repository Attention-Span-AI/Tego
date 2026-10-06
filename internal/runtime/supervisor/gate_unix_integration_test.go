// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeUnixDgram runs the target's unix datagram sends in modeNoNet's abstract-scoped Landlock domain, under
// the same contract with no net: section.
const modeUnixDgram = "unixdgram"

// unixDgramChecks are the target's addressed AF_UNIX datagrams, each by sendto and by sendmsg: to an
// abstract name bound outside its domain, to a name relative to its cwd (<dir>/a) and to a pathname under
// the write directory; and dgram_own_*, to a socket the target bound itself there, read back by the target.
// dgram_pid reports the target's pid, which a receiver's SCM_CREDENTIALS must name.
func unixDgramChecks() []checkResult {
	dir := os.Getenv(helperDir)
	out := []checkResult{{Name: "dgram_pid", N: os.Getpid()}}
	if err := unix.Chdir(filepath.Join(dir, "a")); err != nil {
		return append(out, checkResult{Name: "dgram_chdir", Err: errText(err)})
	}
	for _, dst := range []struct{ name, addr string }{
		{"abstract", "@" + os.Getenv(helperAbstract)},
		{"relative", "rel.sock"},
		{"path", filepath.Join(dir, "p.sock")},
	} {
		for _, form := range []string{"sendto", "sendmsg"} {
			name := "dgram_" + dst.name + "_" + form
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err == nil {
				sa := &unix.SockaddrUnix{Name: dst.addr}
				if form == "sendto" {
					err = unix.Sendto(fd, []byte(name), 0, sa)
				} else {
					_, err = unix.SendmsgN(fd, []byte(name), nil, sa, 0)
				}
				_ = unix.Close(fd)
			}
			out = append(out, checkResult{Name: name, Err: errText(err)})
		}
	}
	own := &unix.SockaddrUnix{Name: filepath.Join(dir, "own.dgram")}
	rx, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Bind(rx, own)
	}
	for _, form := range []string{"sendto", "sendmsg"} {
		name, got := "dgram_own_"+form, ""
		if err == nil {
			fd, serr := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if serr == nil {
				if form == "sendto" {
					serr = unix.Sendto(fd, []byte(name), 0, own)
				} else {
					_, serr = unix.SendmsgN(fd, []byte(name), nil, own, 0)
				}
				_ = unix.Close(fd)
			}
			if serr == nil {
				buf := make([]byte, 64)
				var n int
				n, _, serr = unix.Recvfrom(rx, buf, unix.MSG_DONTWAIT)
				got = string(buf[:max(n, 0)])
			}
			out = append(out, checkResult{Name: name, Err: errText(serr), Out: got})
			continue
		}
		out = append(out, checkResult{Name: name, Err: errText(err)})
	}
	if rx >= 0 {
		_ = unix.Close(rx)
	}
	return out
}

// dgramReceiver is a unix datagram socket that asks for its senders' credentials (SO_PASSCRED).
type dgramReceiver struct{ c *net.UnixConn }

func listenDgram(t *testing.T, name string) *dgramReceiver {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || serr != nil {
		t.Fatal(err, serr)
	}
	return &dgramReceiver{c: c}
}

// drain returns every datagram queued on r, each mapped to the pid its SCM_CREDENTIALS name. A unix
// datagram is queued on the receiver by the sender's own syscall, so all of them are there once the
// target has reported.
func (r *dgramReceiver) drain(t *testing.T) map[string]int {
	t.Helper()
	got := map[string]int{}
	buf := make([]byte, 256)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	for {
		if err := r.c.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, oobn, _, _, err := r.c.ReadMsgUnix(buf, oob)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		pid := -1
		if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(msgs) == 1 {
			if cred, err := unix.ParseUnixCredentials(&msgs[0]); err == nil {
				pid = int(cred.Pid)
			}
		}
		got[string(buf[:n])] = pid
	}
}

// TestIntegrationGateNeverRelaysUnixDatagrams is TestGateNeverRelaysUnixDatagrams on a real kernel, real
// filter and real Landlock scope, under host_sockets: true (ADR 0070's opt-out): a `net` gate rule that scores a unix datagram Allow changes nothing about
// who sends it. Before, the gated loop sent each one itself: the abstract name outside the target's domain
// received it although the target's own scope refuses that send (EPERM), the relative name reached the
// socket in this process's cwd (<dir>/b) instead of the target's (<dir>/a), and every receiver read this
// process's pid in SCM_CREDENTIALS. Each run, with and without the gate, must see the target's own sends:
// EPERM and nothing received for the abstract name, the target's cwd and pid for the others, and every
// line allow with best_effort.
func TestIntegrationGateNeverRelaysUnixDatagrams(t *testing.T) {
	for _, gated := range []bool{false, true} {
		t.Run("gated="+strconv.FormatBool(gated), func(t *testing.T) {
			name := "tego-sup-dgram-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatBool(gated)
			abstract := listenDgram(t, "@"+name)
			var targetCwd, ownCwd, path *dgramReceiver
			o := harnessOpts{mode: modeUnixDgram, env: []string{helperAbstract + "=" + name}, hostSockets: true}
			o.prepare = func(dir string) {
				for _, sub := range []string{"a", "b"} {
					if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				targetCwd = listenDgram(t, filepath.Join(dir, "a", "rel.sock"))
				ownCwd = listenDgram(t, filepath.Join(dir, "b", "rel.sock"))
				path = listenDgram(t, filepath.Join(dir, "p.sock"))
				// The loop's relative name, were it to send one, resolves here and not in the package
				// directory.
				t.Chdir(filepath.Join(dir, "b"))
			}
			if gated {
				g, err := gate.New([]gate.Rule{{Predicate: gate.NetTo, Argument: "93.184.216.34:443", Score: 90}}, 50, 80)
				if err != nil {
					t.Fatal(err)
				}
				o.gate = g
			}
			h := startHarnessWith(t, o)
			h.stop(t)
			pid := h.check(t, "dgram_pid").N

			for _, form := range []string{"sendto", "sendmsg"} {
				if c := h.check(t, "dgram_abstract_"+form); !isErrno(c.Err, unix.EPERM) {
					t.Errorf("abstract %s outside the domain = %q, want EPERM from the target's own scope", form, c.Err)
				}
				for _, dst := range []string{"relative", "path"} {
					if c := h.check(t, "dgram_"+dst+"_"+form); c.Err != "" {
						t.Errorf("%s %s = %q, want success", dst, form, c.Err)
					}
				}
			}
			if got := abstract.drain(t); len(got) != 0 {
				t.Errorf("the abstract name outside the domain received %v, want nothing", got)
			}
			if got := ownCwd.drain(t); len(got) != 0 {
				t.Errorf("the relative name reached this process's cwd: %v", got)
			}
			for _, rx := range []struct {
				r    *dgramReceiver
				want string
			}{{targetCwd, "dgram_relative_"}, {path, "dgram_path_"}} {
				got := rx.r.drain(t)
				for _, form := range []string{"sendto", "sendmsg"} {
					if p, ok := got[rx.want+form]; !ok || p != pid {
						t.Errorf("%s%s: received %v, want it from the target (pid %d)", rx.want, form, got, pid)
					}
				}
			}
			for _, ev := range h.sink.all() {
				if ev.Kind != record.KindNet {
					continue
				}
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Verdict != record.VerdictAllow || !p.BestEffort {
					t.Errorf("net line %s/%s dst=%s best_effort=%v, want allow best_effort", ev.Verdict, ev.Rule, p.Dst, p.BestEffort)
				}
			}
		})
	}
}

// TestIntegrationUnixOnlyDatagrams is ADR 0070's unix-only state for addressed unix datagrams on a real kernel, real
// filter and real Landlock scope: with no net: section and no host_sockets: true, a datagram to a socket the test
// process bound (an abstract name outside the domain, a name relative to the target's cwd, a pathname under the write
// directory) is refused host-sockets and none arrives, while one to the socket the target bound itself is relayed as
// the task and reaches it, its line allow and not best effort.
func TestIntegrationUnixOnlyDatagrams(t *testing.T) {
	name := "tego-sup-dgram-only-" + strconv.Itoa(os.Getpid())
	abstract := listenDgram(t, "@"+name)
	var rel, path *dgramReceiver
	o := harnessOpts{mode: modeUnixDgram, env: []string{helperAbstract + "=" + name, helperScopeOptional + "=1"}}
	o.prepare = func(dir string) {
		for _, sub := range []string{"a", "b"} {
			if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		rel = listenDgram(t, filepath.Join(dir, "a", "rel.sock"))
		path = listenDgram(t, filepath.Join(dir, "p.sock"))
	}
	h := startHarnessWith(t, o)
	h.stop(t)
	for _, form := range []string{"sendto", "sendmsg"} {
		for _, dst := range []string{"abstract", "relative", "path"} {
			if c := h.check(t, "dgram_"+dst+"_"+form); !isErrno(c.Err, refusalErrno) {
				t.Errorf("%s %s to a socket the run did not bind = %q, want %v", dst, form, c.Err, refusalErrno)
			}
		}
		if c := h.check(t, "dgram_own_"+form); UnixDiagAvailable() && (c.Err != "" || c.Out != "dgram_own_"+form) {
			t.Errorf("%s to the target's own socket = %+v, want it delivered", form, c)
		}
	}
	for _, rx := range []*dgramReceiver{abstract, rel, path} {
		if got := rx.drain(t); len(got) != 0 {
			t.Errorf("a socket outside the run received %v, want nothing", got)
		}
	}
	own := "unix:" + filepath.Join(h.dir, "own.dgram")
	for _, ev := range h.sink.all() {
		if ev.Kind != record.KindNet {
			continue
		}
		var p netPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		want, rule := record.VerdictRefused, ruleHostSockets
		if p.Dst == own {
			want, rule = record.VerdictAllow, "fs.write["+h.dir+"]"
		}
		if !UnixDiagAvailable() && (p.Dst == own || strings.HasPrefix(p.Dst, "unix:@")) {
			// Without sock_diag for AF_UNIX, R11a cannot read which socket is bound to a file the run's own bind is
			// recorded at, nor which socket holds an abstract name; a pathname no recorded bind reaches is still
			// foreign for certain, and refused host-sockets.
			want, rule = record.VerdictRefused, ruleUnixOriginUnread
		}
		if ev.Verdict != want || ev.Rule != rule || p.BestEffort {
			t.Errorf("net line %s/%s dst=%s best_effort=%v, want %s/%s, not best effort", ev.Verdict, ev.Rule, p.Dst, p.BestEffort, want, rule)
		}
	}
}
