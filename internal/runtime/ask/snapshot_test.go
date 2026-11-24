// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// snapshotFixture retains a real unprivileged process and pidfd. Its proc tree
// models root packet credentials and mutable kernel facts without root actions.
// PID reuse here is deterministic fixture replacement, not kernel qualification.
func snapshotFixture(t *testing.T) (Peer, func(), string) {
	t.Helper()
	p, stop, dir, _ := snapshotProcessFixture(t, exec.Command("/bin/cat"))
	return p, stop, dir
}

func snapshotProcessFixture(t *testing.T, cmd *exec.Cmd) (Peer, func(), string, io.WriteCloser) {
	t.Helper()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := false
	stop := func() {
		if !exited {
			exited = true
			_ = stdin.Close()
			if err := cmd.Wait(); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(stop)
	st, err := proc.New().Stat(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	p := Peer{PID: cmd.Process.Pid, UID: 0, GID: 0, StartBootNS: st.StartBootNS()}
	h, err := openSender(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.close)
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(p.PID))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0700); err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"stat": stat, "cgroup": []byte("0::/outside\n"), "status": []byte("Uid:\t0\t0\t0\t0\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"user", "cgroup"} {
		if err := os.Symlink("/proc/self/ns/"+name, filepath.Join(dir, "ns", name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.procDir.Close(); err != nil {
		t.Fatal(err)
	}
	h.procDir, err = sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	p.sender = h
	return p, stop, dir, stdin
}

func snapshotBroker(t *testing.T) *Broker {
	t.Helper()
	b, _ := localBroker(t, func(o *Options) {
		o.OwnerOnly.readSnapshot = readSenderSnapshot
		o.Authorize = func(p Peer) error {
			if p.Cgroup != "/outside" || p.CgroupNS == 0 {
				return ErrUnauthorized
			}
			return nil
		}
	})
	return b
}

func TestLocalRolesSnapshotExitAtEveryRead(t *testing.T) {
	// Include the second readings and final identity read; no liveness decision
	// is injected. The child exits and its real pidfd becomes readable.
	for _, phase := range []string{"policy-before/1", "pidfd/1", "stat/1", "status/1", "ns/user/1", "ns/cgroup/1", "cgroup/1", "governed-scopes/1", "status/2", "ns/user/2", "ns/cgroup/2", "cgroup/2", "pidfd/2", "stat/2", "policy-after/1"} {
		t.Run(phase, func(t *testing.T) {
			p, stop, dir := snapshotFixture(t)
			counts := map[string]int{}
			reached := false
			p.sender.afterRead = func(name string) {
				counts[name]++
				if name+"/"+strconv.Itoa(counts[name]) != phase {
					return
				}
				reached = true
				stop()
				// A root/outside replacement takes the modeled numerical PID.
				// The retained proc directory must never read its facts.
				if err := os.Rename(dir, dir+".exited"); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(dir, "ns"), 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"stat", "cgroup"} {
					data, err := os.ReadFile(filepath.Join(dir+".exited", name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"user", "cgroup"} {
					if err := os.Symlink("/proc/self/ns/"+name, filepath.Join(dir, "ns", name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			b := snapshotBroker(t)
			id, done := localHold(t, b)
			_, err := b.answer(t.Context(), id, true, false, nil, p)
			if !reached || !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
				t.Fatalf("%s: reached=%v err=%v pending=%v", phase, reached, err, b.Waiting())
			}
			b.shutdown()
			if d := <-done; d.Approved {
				t.Fatal("exited sender released operation")
			}
		})
	}
}

func pinSnapshotPolicy(t *testing.T, b *Broker) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "system.yaml")
	original := []byte("local_roles: owner_only\n")
	if err := os.WriteFile(file, original, 0644); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	b.opts.OwnerOnly.Check = func() error {
		st, err := os.Stat(file)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if !os.SameFile(pinned, st) || !bytes.Equal(original, data) {
			return errors.New("pinned inode or bytes changed")
		}
		return nil
	}
	return file
}

func TestLocalRolesSnapshotPolicyReplacement(t *testing.T) {
	for _, phase := range []string{"stat", "ns/user", "ns/cgroup", "cgroup", "governed-scopes"} {
		t.Run(phase, func(t *testing.T) {
			p, _, _ := snapshotFixture(t)
			b := snapshotBroker(t)
			file := pinSnapshotPolicy(t, b)
			replaced := false
			p.sender.afterRead = func(name string) {
				if name != phase || replaced {
					return
				}
				replaced = true
				if err := os.WriteFile(file+".new", []byte("local_roles: owner_only\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(file+".new", file); err != nil {
					t.Fatal(err)
				}
			}
			id, done := localHold(t, b)
			_, err := b.answer(t.Context(), id, true, false, nil, p)
			if !replaced || !errors.Is(err, askproto.ErrApprovalPolicyChanged) || !strings.Contains(err.Error(), "the approval policy file changed since this run started") || !b.Waiting() {
				t.Fatalf("replacement: reached=%v err=%v pending=%v", replaced, err, b.Waiting())
			}
			b.shutdown()
			<-done
		})
	}
}

func TestLocalRolesSnapshotFactChangeRefuses(t *testing.T) {
	p, _, dir := snapshotFixture(t)
	changed := false
	p.sender.afterRead = func(name string) {
		if name == "governed-scopes" && !changed {
			changed = true
			if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/tego/run\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	b := snapshotBroker(t)
	id, done := localHold(t, b)
	_, err := b.answer(t.Context(), id, true, false, nil, p)
	if !changed || !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
		t.Fatalf("mixed facts accepted: %v", err)
	}
	b.shutdown()
	<-done
}

func TestLocalRolesSnapshotMissingPeerFactsRefuse(t *testing.T) {
	for _, p := range []Peer{{}, {PID: 1}, {PID: 1, StartBootNS: 1}} {
		if _, err := readSenderSnapshot(p, func(Peer) error { return nil }); err == nil {
			t.Fatalf("unknown peer authorized: %+v", p)
		}
	}
}

func TestLocalRolesSnapshotAfterCompletionKeepsSendIdentity(t *testing.T) {
	p, stop, dir := snapshotFixture(t)
	b := snapshotBroker(t)
	var event Event
	final := false
	b.opts.Emit = func(e Event) error {
		if e.Kind == "answer" {
			event, final = e, true
		}
		return nil
	}
	// Change the sender only after the entire final snapshot has completed,
	// including the second policy reading and final nonblocking liveness poll.
	b.opts.OwnerOnly.afterSnapshot = func() {
		if final {
			if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/tego/run\n"), 0600); err != nil {
				t.Error(err)
			}
			stop()
		}
	}
	id, done := localHold(t, b)
	d, err := b.answer(t.Context(), id, true, false, nil, p)
	if err != nil || !d.Approved || !(<-done).Approved {
		t.Fatalf("post-snapshot change revoked approval: %+v %v", d, err)
	}
	for _, actor := range []*record.LocalApprovalActor{d.Actor, event.Decision.Actor} {
		if actor == nil || actor.UID != p.UID || actor.PID != p.PID || actor.StartBootNS != p.StartBootNS || actor.UserNamespace != record.InitialUserNamespace {
			t.Fatalf("record names another sender: %+v packet=%+v", actor, p)
		}
	}
}

func TestLocalRolesSnapshotPostRecordExitKeepsOperationPending(t *testing.T) {
	p, stop, _ := snapshotFixture(t)
	b := snapshotBroker(t)
	var events []Event
	var recorded bool
	b.opts.Emit = func(e Event) error {
		events = append(events, e)
		if e.Kind == "answer" {
			recorded = true
		}
		return nil
	}
	p.sender.afterRead = func(name string) {
		if recorded && name == "stat" {
			stop()
		}
	}
	// Observe both publications through the real pending callback. A recorded
	// selection that loses its sender must publish a distinct ready ask.
	ready := make(chan string, 2)
	b.opts.Pending = func(r Request) { ready <- r.AskID }
	done := make(chan Decision, 1)
	go func() { d, _ := b.Request(t.Context(), testRequest()); done <- d }()
	id := <-ready
	b.mu.Lock()
	started := b.pending[id].started
	b.mu.Unlock()
	_, err := b.answer(t.Context(), id, true, false, nil, p)
	if !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
		t.Fatalf("dead sender consumed held operation: %v", err)
	}
	newID := <-ready
	if newID == id {
		t.Fatal("recorded selection reused an already answered id")
	}
	b.mu.Lock()
	if !b.pending[newID].started.Equal(started) {
		t.Error("retry extended original deadline")
	}
	b.mu.Unlock()
	select {
	case d := <-done:
		t.Fatalf("held operation released: %+v", d)
	default:
	}
	p2, _, _ := snapshotFixture(t)
	d, err := b.answer(t.Context(), newID, true, false, nil, p2)
	if err != nil || !d.Approved || !(<-done).Approved {
		t.Fatalf("new sender could not answer: %+v %v", d, err)
	}
	if len(events) != 4 || events[0].Kind != "ask" || events[1].Kind != "answer" || events[2].Kind != "ask" || events[3].Kind != "answer" || events[0].Request.AskID != id || events[1].Decision.AskID != id || events[2].Request.AskID != newID || events[3].Decision.AskID != newID {
		t.Fatalf("retry lost one-answer-per-ask history: %+v", events)
	}
}

func TestLocalRolesPacketSenderHandle(t *testing.T) {
	for _, facility := range []string{"pidfd_open fallback", "SCM_PIDFD when supported"} {
		t.Run(facility, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) }()
			if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				t.Fatal(err)
			}
			supported := false
			if facility == "SCM_PIDFD when supported" {
				err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSPIDFD, 1)
				if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
					t.Fatal(err)
				}
				supported = err == nil
			}
			if err := unix.Sendmsg(fds[1], []byte("answer"), nil, nil, 0); err != nil {
				t.Fatal(err)
			}
			data, oob := make([]byte, 64), make([]byte, 256)
			_, on, flags, _, err := unix.Recvmsg(fds[0], data, oob, unix.MSG_CMSG_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			p, rights, err := packetPeer(oob[:on], flags)
			if err != nil {
				t.Fatal(err)
			}
			defer closeRights(rights)
			if p.PID != os.Getpid() || p.UID != uint32(os.Getuid()) || p.GID != uint32(os.Getgid()) || (p.packetFD != nil) != supported {
				t.Fatalf("wrong packet identity/handle: %+v supported=%v", p, supported)
			}
			st, err := proc.New().Stat(p.PID)
			if err != nil {
				t.Fatal(err)
			}
			p.StartBootNS = st.StartBootNS()
			h, err := openSender(p, p.packetFD)
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			p.sender = h
			got, err := readSenderSnapshot(p, func(Peer) error { return nil })
			if err != nil || got.PID != p.PID || got.UID != p.UID || got.GID != p.GID || got.StartBootNS != p.StartBootNS {
				t.Fatalf("packet snapshot: %+v %v", got, err)
			}
		})
	}
}

func TestLocalRolesSnapshotFinalPolicyReplacement(t *testing.T) {
	for _, phase := range []string{"stat", "ns/user", "ns/cgroup", "cgroup", "governed-scopes"} {
		t.Run(phase, func(t *testing.T) {
			p, _, _ := snapshotFixture(t)
			b := snapshotBroker(t)
			file := pinSnapshotPolicy(t, b)
			recorded, changed := false, false
			b.opts.Emit = func(e Event) error {
				if e.Kind == "answer" {
					recorded = true
				}
				return nil
			}
			p.sender.afterRead = func(name string) {
				if !recorded || changed || name != phase {
					return
				}
				changed = true
				if err := os.WriteFile(file+".new", []byte("local_roles: owner_only\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(file+".new", file); err != nil {
					t.Fatal(err)
				}
			}
			id, done := localHold(t, b)
			d, err := b.answer(t.Context(), id, true, false, nil, p)
			if !changed || !errors.Is(err, askproto.ErrApprovalPolicyChanged) || !strings.Contains(err.Error(), "the approval policy file changed since this run started") || b.Waiting() {
				t.Fatalf("final policy replacement: changed=%v decision=%+v err=%v", changed, d, err)
			}
			if d.Approved || (<-done).Approved {
				t.Fatal("policy replacement released operation")
			}
		})
	}
}

func TestLocalRolesSnapshotFinalFactChangeKeepsPending(t *testing.T) {
	p, _, dir := snapshotFixture(t)
	b := snapshotBroker(t)
	recorded, changed := false, false
	b.opts.Emit = func(e Event) error {
		if e.Kind == "answer" {
			recorded = true
		}
		return nil
	}
	p.sender.afterRead = func(name string) {
		if recorded && !changed && name == "governed-scopes" {
			changed = true
			if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/tego/run\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The retry notice is not needed here. Its callback must remain nonblocking.
	ready := make(chan string, 2)
	b.opts.Pending = func(r Request) { ready <- r.AskID }
	done := make(chan Decision, 1)
	go func() { d, _ := b.Request(t.Context(), testRequest()); done <- d }()
	id := <-ready
	d, err := b.answer(t.Context(), id, true, false, nil, p)
	if !changed || !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
		t.Fatalf("mixed final facts delivered: %+v %v", d, err)
	}
	b.shutdown()
	if (<-done).Approved {
		t.Fatal("incoherent snapshot released operation")
	}
}

func TestLocalRolesRejectedAnswerCannotReceiveRetrySuccess(t *testing.T) {
	p, stop, _ := snapshotFixture(t)
	b := snapshotBroker(t)
	recorded, recordResume := make(chan struct{}), make(chan struct{})
	replyEntered, replyResume := make(chan struct{}), make(chan struct{})
	releaseRecord := sync.OnceFunc(func() { close(recordResume) })
	releaseReply := sync.OnceFunc(func() { close(replyResume) })
	t.Cleanup(releaseRecord)
	t.Cleanup(releaseReply)
	var first atomic.Bool
	b.opts.Emit = func(e Event) error {
		if e.Kind == "answer" && first.CompareAndSwap(false, true) {
			close(recorded)
			<-recordResume
		}
		return nil
	}
	p.sender.afterRead = func(string) {
		if first.Load() {
			stop()
		}
	}
	b.opts.OwnerOnly.beforeReply = func() { close(replyEntered); <-replyResume }
	ready := make(chan string, 2)
	b.opts.Pending = func(r Request) { ready <- r.AskID }
	done := make(chan Decision, 1)
	go func() { d, _ := b.Request(t.Context(), testRequest()); done <- d }()
	id := <-ready
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type reply struct {
		decision Decision
		err      error
	}
	oldReply := make(chan reply, 1)
	go func() { d, err := b.answer(ctx, id, true, false, nil, p); oldReply <- reply{d, err} }()
	<-recorded
	cancel() // only this answer's ctx arm is ready; its Request is still held
	<-replyEntered
	releaseRecord() // actual sender exit now rejects the first admission
	newID := <-ready
	p2, _, _ := snapshotFixture(t)
	d, err := b.answer(t.Context(), newID, true, false, nil, p2)
	if err != nil || !d.Approved || d.Actor == nil || d.Actor.PID != p2.PID {
		t.Fatalf("retry: %+v %v", d, err)
	}
	if got := <-done; !got.Approved || got.Actor.PID != p2.PID {
		t.Fatalf("held operation: %+v", got)
	}
	releaseReply()
	got := <-oldReply
	if !errors.Is(got.err, askproto.ErrOwnerOnly) || got.decision.Approved || got.decision.Actor != nil {
		t.Fatalf("old rejected answer received a later success: %+v %v", got.decision, got.err)
	}
}

// The child really execs; mutable proc facts use the same explicit fixture as
// the other snapshot tests. Root/namespace transitions are owed in a guest.
func TestLocalRolesSnapshotExecBetweenReads(t *testing.T) {
	for _, change := range []string{"unchanged", "real-uid", "user-namespace", "cgroup-namespace", "governed-scope"} {
		t.Run(change, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", "read trigger; exec /bin/cat")
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			p, _, dir, input := snapshotProcessFixture(t, cmd)
			executed := false
			p.sender.afterRead = func(name string) {
				if name != "governed-scopes" || executed {
					return
				}
				executed = true
				// Only the exec'ed cat can echo this second line. No polling or sleep.
				if _, err := io.WriteString(input, "exec\nready\n"); err != nil {
					t.Fatal(err)
				}
				if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
					t.Fatalf("exec handshake: %q %v", line, err)
				}
				st, err := proc.New().Stat(p.PID)
				if err != nil || st.StartBootNS() != p.StartBootNS {
					t.Fatalf("exec changed process identity: %+v %v", st, err)
				}
				switch change {
				case "real-uid":
					if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t1001\t1001\t1001\t1001\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "user-namespace", "cgroup-namespace":
					ns := "user"
					if change == "cgroup-namespace" {
						ns = "cgroup"
					}
					path := filepath.Join(dir, "ns", ns)
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("private namespace inode"), 0600); err != nil {
						t.Fatal(err)
					}
				case "governed-scope":
					if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::/tego/run\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			b := snapshotBroker(t)
			id, done := localHold(t, b)
			d, err := b.answer(t.Context(), id, true, false, nil, p)
			if !executed {
				t.Fatal("exec barrier not reached")
			}
			if change == "unchanged" {
				if err != nil || !d.Approved || !(<-done).Approved || d.Actor.PID != p.PID || d.Actor.StartBootNS != p.StartBootNS {
					t.Fatalf("unchanged exec refused or switched identity: %+v %v", d, err)
				}
			} else {
				if !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
					t.Fatalf("exec changed %s but released ask: %+v %v pending=%v", change, d, err, b.Waiting())
				}
				b.shutdown()
				if (<-done).Approved {
					t.Fatal("changed exec facts released held operation")
				}
			}
		})
	}
}

func TestLocalRolesSnapshotDecisionRealUID(t *testing.T) {
	for _, status := range []string{"Uid:\t1001\t0\t0\t0\n", "", "Uid:\t0\t0\t0\n", "Uid:\tx\t0\t0\t0\n", "Uid:\t0\t0\t0\t0\nUid:\t0\t0\t0\t0\n"} {
		t.Run(fmt.Sprintf("%q", status), func(t *testing.T) {
			p, _, dir := snapshotFixture(t)
			if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0600); err != nil {
				t.Fatal(err)
			}
			b := snapshotBroker(t)
			id, done := localHold(t, b)
			_, err := b.answer(t.Context(), id, true, false, nil, p)
			if !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
				t.Fatalf("decision status %q admitted: %v pending=%v", status, err, b.Waiting())
			}
			b.shutdown()
			<-done
		})
	}
}

func TestLocalRolesSnapshotFinalRealUIDKeepsPending(t *testing.T) {
	p, _, dir := snapshotFixture(t)
	b := snapshotBroker(t)
	recorded, changed := false, false
	b.opts.Emit = func(e Event) error {
		if e.Kind == "answer" {
			recorded = true
		}
		return nil
	}
	p.sender.afterRead = func(name string) {
		if recorded && !changed && name == "governed-scopes" {
			changed = true
			if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t1001\t1001\t1001\t1001\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	id, done := localHold(t, b)
	d, err := b.answer(t.Context(), id, true, false, nil, p)
	if !changed || !errors.Is(err, askproto.ErrOwnerOnly) || !b.Waiting() {
		t.Fatalf("real UID loss after recording: changed=%v decision=%+v err=%v pending=%v", changed, d, err, b.Waiting())
	}
	b.shutdown()
	if (<-done).Approved {
		t.Fatal("non-root sender at final decision released operation")
	}
}
