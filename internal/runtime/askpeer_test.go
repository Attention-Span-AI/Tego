// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// selfCgroupNS is the inode of this process's cgroup namespace.
func selfCgroupNS(t *testing.T) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/cgroup", &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// TestAskPeerAuthorizeRefusesEveryRunShape is ask.sock's rule over the peers the socket identified:
// the person's shell, of the run's uid or root, outside every run and in this process's cgroup namespace, is served;
// a peer in this run's cgroup, in any other run's or adoption's scope or a look-alike of one, in another or an
// unreadable cgroup namespace, above this one's root, of another uid, or not identified is unauthorized. Outside the
// initial cgroup namespace every peer is (peer.Refuse), and the table says so.
func TestAskPeerAuthorizeRefusesEveryRunShape(t *testing.T) {
	ns := selfCgroupNS(t)
	initial := ns == runscope.InitCgroupNS
	const user = "/user.slice/user-1000.slice/user@1000.service"
	own := user + "/tego.slice/tego-claude.slice/run-r-00000000-0000000000000-aaaaaa.scope"
	r := &runner{cg: cgroup.Cgroup{Path: "/sys/fs/cgroup" + own}, askOwner: 1000}
	shell := user + "/app.slice/app-org.gnome.Terminal.slice/vte-spawn-1.scope"
	for _, c := range []struct {
		name   string
		peer   ask.Peer
		served bool
	}{
		{"the person's shell", ask.Peer{PID: 7, UID: 1000, Cgroup: shell, CgroupNS: ns}, initial},
		{"root's shell", ask.Peer{PID: 7, UID: 0, Cgroup: "/user.slice/user-0.slice/session-3.scope", CgroupNS: ns}, initial},
		{"a systemd-run scope of the person's", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/app.slice/run-u42.scope", CgroupNS: ns}, initial},
		{"this run's agent", ask.Peer{PID: 7, UID: 1000, Cgroup: own, CgroupNS: ns}, false},
		{"a child cgroup of this run's", ask.Peer{PID: 7, UID: 1000, Cgroup: own + "/child", CgroupNS: ns}, false},
		{"another run's agent", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/tego.slice/tego-codex.slice/run-r-00000000-0000000000000-bbbbbb.scope", CgroupNS: ns}, false},
		{"a root run's agent", ask.Peer{PID: 7, UID: 1000, Cgroup: "/tego.slice/tego-claude.slice/run-r-00000000-0000000000000-cccccc.scope", CgroupNS: ns}, false},
		{"an adopted agent", ask.Peer{PID: 7, UID: 0, Cgroup: "/tego.slice/tego-claude.slice/adopt-r-00000000-0000000000000-dddddd.scope", CgroupNS: ns}, false},
		{"a watched agent", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/tego.slice/tego-python3.slice/run-r-00000000-0000000000000-eeeeee.scope/sub", CgroupNS: ns}, false},
		{"a run's container (cgroupfs Docker parent)", ask.Peer{PID: 7, UID: 0, Cgroup: "/tego/r-00000000-0000000000000-ffffff/abc", CgroupNS: ns}, false},
		{"a look-alike in the person's subtree", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/app.slice/tego.slice/run-x.scope", CgroupNS: ns}, false},
		{"another cgroup namespace", ask.Peer{PID: 7, UID: 1000, Cgroup: shell, CgroupNS: ns + 1}, false},
		{"an unreadable cgroup namespace", ask.Peer{PID: 7, UID: 0, Cgroup: shell, CgroupNS: 0}, false},
		{"above this namespace's root", ask.Peer{PID: 7, UID: 1000, Cgroup: "/../outside", CgroupNS: ns}, false},
		{"another uid", ask.Peer{PID: 7, UID: 1001, Cgroup: shell, CgroupNS: ns}, false},
		// The dashboard holds secrets and is undumpable, so /proc hides its namespace; Identify proved why. It is
		// judged on everything else as any peer is (ADR 0100 (7), amended 2026-11-22).
		{"an undumpable peer outside every run", ask.Peer{PID: 7, UID: 1000, Cgroup: shell, Undumpable: true}, initial},
		{"an undumpable systemd-run scope of the person's", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/app.slice/run-u42.scope", Undumpable: true}, initial},
		{"an undumpable peer in this run's cgroup", ask.Peer{PID: 7, UID: 1000, Cgroup: own, Undumpable: true}, false},
		{"an undumpable peer in a child cgroup of this run's", ask.Peer{PID: 7, UID: 1000, Cgroup: own + "/child", Undumpable: true}, false},
		{"an undumpable agent of another run", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/tego.slice/tego-codex.slice/run-r-00000000-0000000000000-bbbbbb.scope", Undumpable: true}, false},
		{"an undumpable adopted agent", ask.Peer{PID: 7, UID: 1000, Cgroup: "/tego.slice/tego-claude.slice/adopt-r-00000000-0000000000000-dddddd.scope", Undumpable: true}, false},
		{"an undumpable look-alike in the person's subtree", ask.Peer{PID: 7, UID: 1000, Cgroup: user + "/app.slice/tego.slice/run-x.scope", Undumpable: true}, false},
		{"an undumpable peer above this namespace's root", ask.Peer{PID: 7, UID: 1000, Cgroup: "/../outside", Undumpable: true}, false},
		{"an undumpable peer of another uid", ask.Peer{PID: 7, UID: 1001, Cgroup: shell, Undumpable: true}, false},
		{"an undumpable root is never proved so", ask.Peer{PID: 7, UID: 0, Cgroup: "/user.slice/user-0.slice/session-3.scope", Undumpable: true}, false},
		{"undumpable and a namespace shown", ask.Peer{PID: 7, UID: 1000, Cgroup: shell, CgroupNS: ns, Undumpable: true}, false},
		{"not identified", ask.Peer{PID: 7, UID: 1000}, false},
	} {
		err := r.askPeerAuthorize(c.peer)
		if (err == nil) != c.served {
			t.Errorf("%s (%+v): askPeerAuthorize = %v; want served %v (initial cgroup namespace: %v)", c.name, c.peer, err, c.served, initial)
		}
	}
	// A run with no cgroup of its own, or the root's, serves no one.
	for _, path := range []string{"", "/sys/fs/cgroup", "/sys/fs/cgroup/"} {
		r := &runner{cg: cgroup.Cgroup{Path: path}, askOwner: 1000}
		if err := r.askPeerAuthorize(ask.Peer{PID: 7, UID: 1000, Cgroup: shell, CgroupNS: ns}); err == nil {
			t.Errorf("a run whose cgroup is %q served the person's shell", path)
		}
	}
}

// otherNSAnswerEnv carries the run directory, the broker's pid and the ask id to TestOtherCgroupNamespaceRefusedHelper.
const otherNSAnswerEnv = "TEGO_TEST_OTHER_NS_ANSWER"

// TestOtherCgroupNamespaceRefusedHelper is TestOtherCgroupNamespaceRefused's child: in a cgroup namespace of its own,
// it approves the ask with tego's own client and prints what the broker said.
func TestOtherCgroupNamespaceRefusedHelper(t *testing.T) {
	v := os.Getenv(otherNSAnswerEnv)
	if v == "" {
		t.Skip("helper process for TestOtherCgroupNamespaceRefused")
	}
	parts := strings.SplitN(v, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("%s=%q", otherNSAnswerEnv, v)
	}
	pid, _ := strconv.Atoi(parts[1])
	_, err := askclient.Answer(context.Background(), parts[2], pid, parts[0], true, false)
	fmt.Printf("answer-report unauthorized=%v err=%q\n", errors.Is(err, ask.ErrUnauthorized), fmt.Sprint(err))
}

// TestOtherCgroupNamespaceRefused: a process of the run's uid that is in another cgroup namespace than the broker's
// (an agent that unshared one, a container's process) reads its cgroup relative to that namespace, so where it is
// cannot be told; its answer is unauthorized and the ask stays pending; the person, in the broker's namespace and
// outside the run, then answers it (peer.Refuse [peer-cgroupns]). The child runs as root of its
// user namespace and unmapped: both are the run's uid to the broker.
func TestOtherCgroupNamespaceRefused(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := &runner{cg: cgroup.Cgroup{Path: "/sys/fs/cgroup/user.slice/tego.slice/tego-a.slice/run-r-00000000-0000000000000-aaaaaa.scope"},
		askOwner: uint32(os.Getuid())}
	b, err := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Minute, Authorize: r.askPeerAuthorize, Emit: func(ask.Event) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	done := make(chan ask.Decision, 1)
	go func() {
		d, _ := b.Request(context.Background(), ask.Request{Op: "connect", Target: "10.0.0.9:443", Rule: "net.ask[0]", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()})
		done <- d
	}()
	initial := selfCgroupNS(t) == runscope.InitCgroupNS
	var id string
	for deadline := time.Now().Add(5 * time.Second); id == ""; time.Sleep(time.Millisecond) {
		list, err := ask.ListFor(context.Background(), dir, os.Getpid())
		if !initial {
			// Outside the initial cgroup namespace the broker serves no one, the test process included.
			if !errors.Is(err, ask.ErrUnauthorized) {
				t.Fatalf("outside the initial cgroup namespace the person's list came to %v %v; want unauthorized", list, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(list) == 1 {
			id = list[0].AskID
		}
		if time.Now().After(deadline) {
			t.Fatal("the request was not published")
		}
	}
	self := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	selfGID := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	for _, c := range []struct {
		name string
		attr *syscall.SysProcAttr
	}{
		{"unmapped", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP}},
		{"root of its user namespace", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP,
			UidMappings: self, GidMappings: selfGID}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestOtherCgroupNamespaceRefusedHelper$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), otherNSAnswerEnv+"="+id+":"+strconv.Itoa(os.Getpid())+":"+dir)
			cmd.SysProcAttr = c.attr
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				t.Skipf("no user and cgroup namespace to start the child in: %v", err)
			}
			if err != nil {
				t.Fatalf("child: %v\n%s%s", err, out, stderr.Bytes())
			}
			if !strings.Contains(string(out), "answer-report unauthorized=true ") {
				t.Fatalf("the child in another cgroup namespace answered: %s%s; want unauthorized", out, stderr.Bytes())
			}
			list, err := ask.ListFor(context.Background(), dir, os.Getpid())
			if err != nil || len(list) != 1 || list[0].AskID != id {
				t.Fatalf("after the child's answer the broker lists %v %v; want %s still pending", list, err, id)
			}
		})
	}
	d, err := ask.AnswerFor(context.Background(), dir, os.Getpid(), id, true, false)
	if err != nil || !d.Approved {
		t.Fatalf("the person's answer: %+v %v", d, err)
	}
	select {
	case got := <-done:
		if !got.Approved || got.By != fmt.Sprintf("uid:%d pid:%d", os.Getuid(), os.Getpid()) {
			t.Fatalf("the request ended %+v; want approved by the person", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the held request did not end")
	}
}

// undumpableAnswerEnv carries the run directory, the broker's pid and the ask id to TestUndumpableAnswerHelper.
const undumpableAnswerEnv = "TEGO_TEST_UNDUMPABLE_ANSWER"

// TestUndumpableAnswerHelper is TestUndumpableOperatorIsServedAnAgentIsNot's child: it makes itself undumpable, as the
// dashboard does before it reads a key, approves the ask with tego's own client and prints what the broker said.
func TestUndumpableAnswerHelper(t *testing.T) {
	v := os.Getenv(undumpableAnswerEnv)
	if v == "" {
		t.Skip("helper process for TestUndumpableOperatorIsServedAnAgentIsNot")
	}
	parts := strings.SplitN(v, ":", 3)
	if len(parts) != 3 {
		t.Fatalf("%s=%q", undumpableAnswerEnv, v)
	}
	if err := sys.MakeUndumpable(); err != nil {
		t.Fatal(err)
	}
	if dumpable, err := sys.Dumpable(); err != nil || dumpable {
		t.Fatalf("the helper is dumpable after MakeUndumpable: %v, %v", dumpable, err)
	}
	pid, _ := strconv.Atoi(parts[1])
	d, err := askclient.Answer(context.Background(), parts[2], pid, parts[0], true, false)
	fmt.Printf("answer-report approved=%v unauthorized=%v err=%q\n", d.Approved, errors.Is(err, ask.ErrUnauthorized), fmt.Sprint(err))
}

// TestUndumpableOperatorIsServedAnAgentIsNot: the dashboard makes itself undumpable before it reads a key, and /proc then
// hides its cgroup namespace from the broker. Over a real broker, a real socket and tego's own client:
//   - an undumpable process of the run's uid that is outside the run is served, and its approval releases the held
//     operation (the dashboard's answer path);
//   - the same undumpable process inside the run's cgroup (the run's cgroup being the one it is in) is refused, and
//     the ask stays pending: being undumpable moves no agent out of its run.
func TestUndumpableOperatorIsServedAnAgentIsNot(t *testing.T) {
	if selfCgroupNS(t) != runscope.InitCgroupNS {
		t.Skip("outside the initial cgroup namespace the broker serves no peer (peer.Refuse), so there is no operator to serve")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	mine, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	own, err := runscope.Unified(mine)
	if err != nil || own == "/" || runscope.LooksGoverned(own) {
		t.Skipf("this test needs an ordinary cgroup of its own outside every run (%q, %v)", own, err)
	}
	helper := func(dir, id string) (out string, stderr string) {
		t.Helper()
		cmd := exec.Command(exe, "-test.run=^TestUndumpableAnswerHelper$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), undumpableAnswerEnv+"="+id+":"+strconv.Itoa(os.Getpid())+":"+dir)
		var errb bytes.Buffer
		cmd.Stderr = &errb
		o, err := cmd.Output()
		if err != nil {
			t.Fatalf("helper: %v\n%s%s", err, o, errb.Bytes())
		}
		return string(o), errb.String()
	}
	for _, c := range []struct {
		name   string
		runCg  string // the cgroup the broker's run is in
		served bool
	}{
		{"outside the run", "/sys/fs/cgroup/user.slice/tego.slice/tego-a.slice/run-r-00000000-0000000000000-aaaaaa.scope", true},
		{"inside the run's cgroup", "/sys/fs/cgroup" + own, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			r := &runner{cg: cgroup.Cgroup{Path: c.runCg}, askOwner: uint32(os.Getuid())}
			ready := make(chan string, 1)
			b, err := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Minute, Authorize: r.askPeerAuthorize,
				Emit: func(ask.Event) error { return nil }, Pending: func(q ask.Request) { ready <- q.AskID }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.Close() })
			done := make(chan ask.Decision, 1)
			go func() {
				d, _ := b.Request(context.Background(), ask.Request{Op: "connect", Target: "10.0.0.9:443", Rule: "net.ask[0]", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()})
				done <- d
			}()
			var id string
			select {
			case id = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("the request was not published")
			}
			out, errs := helper(dir, id)
			if c.served {
				if !strings.Contains(out, "answer-report approved=true unauthorized=false ") {
					t.Fatalf("an undumpable process outside the run was not served: %s%s", out, errs)
				}
				select {
				case got := <-done:
					if !got.Approved {
						t.Fatalf("the request ended %+v; want approved", got)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the held request did not end")
				}
				return
			}
			if !strings.Contains(out, "answer-report approved=false unauthorized=true ") {
				t.Fatalf("an undumpable process inside the run's cgroup answered: %s%s; want unauthorized", out, errs)
			}
			if !b.Waiting() {
				t.Fatal("the ask is no longer pending after an undumpable agent's refused answer")
			}
			select {
			case got := <-done:
				t.Fatalf("the held operation ended %+v after an undumpable agent's answer", got)
			default:
			}
		})
	}
}
