// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package adopt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// leaderExitScript is an agent whose main thread exits (a raw exit(2), SYS_exit given as argv[1]) while a thread of
// it runs on: the thread holds argv[2] open for writing, maps argv[3] shared and writable, forks a sleep, prints the
// sleep's pid and its own thread id, and waits.
const leaderExitScript = `
import ctypes, mmap, os, sys, threading, time
libc = ctypes.CDLL(None, use_errno=True)
sys_exit, held, mapped = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def worker():
    keep = [os.open(held, os.O_RDWR)]
    f = open(mapped, "r+b")
    keep.append(mmap.mmap(f.fileno(), 4096, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE))
    f.close()
    pid = os.fork()
    if pid == 0:
        os.execvp("sleep", ["sleep", "300"])
    sys.stdout.write("%d %d\n" % (pid, threading.get_native_id()))
    sys.stdout.flush()
    while True:
        time.sleep(0.2)
threading.Thread(target=worker).start()
if len(sys.argv) > 4:
    sys.stdin.readline()
else:
    time.sleep(0.5)
libc.syscall(sys_exit, 0)
`

// cgroupMount is where root-suites.sh's guest mounts cgroup2.
const cgroupMount = "/sys/fs/cgroup"

// leaderExitAgent is leaderExitScript started as root in a fresh cgroup src, beside a fresh cgroup dst (src and dst
// absolute, srcRel and dstRel as /proc names them): tgid is its process, tid the thread that runs on, child the
// sleep the thread forked, held and mapped the files the thread holds. Its leader exits half a second after the
// start, or, started onCue, once a line is written to cue.
type leaderExitAgent struct {
	tgid, child, tid         int
	src, dst, srcRel, dstRel string
	held, mapped             string
	cue                      io.WriteCloser
}

func startLeaderExitAgent(t *testing.T, onCue bool) *leaderExitAgent {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: moves processes between cgroups (root-suites.sh)")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	sysExit := 60 // amd64
	if runtime.GOARCH == "arm64" {
		sysExit = 93
	}
	dir := t.TempDir()
	a := &leaderExitAgent{held: filepath.Join(dir, "held"), mapped: filepath.Join(dir, "mapped")}
	for _, p := range []string{a.held, a.mapped} {
		if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	name := fmt.Sprintf("tego-leaderexit-%d-%s", os.Getpid(), strings.ReplaceAll(t.Name(), "/", "-"))
	a.src, a.dst = filepath.Join(cgroupMount, name+"-src"), filepath.Join(cgroupMount, name+"-dst")
	a.srcRel, a.dstRel = strings.TrimPrefix(a.src, cgroupMount), strings.TrimPrefix(a.dst, cgroupMount)
	for _, d := range []string{a.src, a.dst} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(d) })
	}
	cgfd, err := syscall.Open(a.src, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-c", leaderExitScript, fmt.Sprint(sysExit), a.held, a.mapped}
	if onCue {
		args = append(args, "cue")
	}
	cmd := exec.Command(python, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgfd}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if a.cue, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(cgfd)
	a.tgid = cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(a.tgid, syscall.SIGKILL)
		if a.child > 0 {
			_ = syscall.Kill(a.child, syscall.SIGKILL)
		}
		_ = a.cue.Close()
		_ = cmd.Wait()
		for _, d := range []string{a.dst, a.src} {
			for range 50 {
				if err := os.Remove(d); err == nil || errors.Is(err, os.ErrNotExist) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	})
	if _, err := fmt.Fscan(bufio.NewReader(out), &a.child, &a.tid); err != nil {
		t.Fatalf("the agent printed no child and thread: %v", err)
	}
	return a
}

// waitLeaderExited waits until process tgid's leader has exited while its thread runs on.
func waitLeaderExited(t *testing.T, fs *FS, tgid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := fs.Stat(tgid)
		if err != nil {
			t.Fatal(err)
		}
		if st.LeaderExited() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent's leader did not exit: state %c, %d threads", st.State, st.NumThreads)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestIntegrationReleaseAfterTheLeaderExitedInTheScope: an agent adopted whole whose main thread then exits in the
// run's cgroup leaves its exited leader listed in that cgroup's cgroup.procs while its thread runs; once the release
// has moved the thread (and the child) back, the release leaves nothing in the scope, and the scope can be removed.
// The release once read the leader from cgroup.procs as a process left
// there, so the scope and its record were kept and run_end said a process stayed.
func TestIntegrationReleaseAfterTheLeaderExitedInTheScope(t *testing.T) {
	a := startLeaderExitAgent(t, true)
	fs := NewFS("")
	root, err := Identify(fs, a.tgid)
	if err != nil {
		t.Fatal(err)
	}
	env := Env{Proc: fs, FS: Cgroups{}, Live: Pidfds{}, Mount: cgroupMount}
	if res, err := Move(env, a.dst, root, nil); err != nil || len(res.Skipped) != 0 || res.Left != 0 {
		t.Fatalf("move: %+v, %v", res, err)
	}
	if _, err := io.WriteString(a.cue, "exit\n"); err != nil {
		t.Fatal(err)
	}
	waitLeaderExited(t, fs, a.tgid)
	procs, err := (Cgroups{}).Procs(a.dst)
	t.Logf("the run's cgroup.procs with the leader exited there: %v (%v)", procs, err)
	rel := Release(env, a.dst, []string{a.src})
	if len(rel.Left) != 0 || !slices.Contains(rel.To[a.src], a.tgid) {
		t.Errorf("release: to %v, left %v; want %d back in %s and nothing left", rel.To, rel.Left, a.tgid, a.src)
	}
	for _, id := range []int{a.tid, a.child} {
		if cg, err := fs.Cgroup(id); err != nil || cg != a.srcRel {
			t.Errorf("task %d is in %q (%v) after the release, want %s", id, cg, err, a.srcRel)
		}
	}
	if err := os.Remove(a.dst); err != nil {
		t.Errorf("the run's cgroup cannot be removed after the release: %v", err)
	}
}

// TestIntegrationAdoptMovesAProcessWhoseLeaderExited: an agent's process whose main thread has exited while another
// thread of it runs reads as a zombie in /proc/<pid>/stat. Such a
// process and its children were never moved and never counted, so they ran outside the boundary with a ledger that
// said the tree was adopted. Here, on the running kernel, it is identified through its thread, moved with its child
// (the write of its pid moves its live threads; the exited leader stays where it was), its held file and shared
// mapping are listed through the thread, and the release brings its thread and its child back. Moving cgroups needs
// root: root-suites.sh runs it in a KVM guest.
func TestIntegrationAdoptMovesAProcessWhoseLeaderExited(t *testing.T) {
	a := startLeaderExitAgent(t, false)
	tgid, child, tid, held, mapped := a.tgid, a.child, a.tid, a.held, a.mapped
	src, dst, srcRel, dstRel := a.src, a.dst, a.srcRel, a.dstRel
	fs := NewFS("")
	waitLeaderExited(t, fs, tgid)
	root, err := Identify(fs, tgid)
	if err != nil {
		t.Fatalf("identify the process whose leader exited: %v", err)
	}
	if root.Cgroup != srcRel || root.Tgid != tgid || !strings.Contains(root.Exe, "python") {
		t.Fatalf("identified %+v, want its program and cgroup %s, read through thread %d", root, srcRel, tid)
	}
	members, skipped, err := Members(fs, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(members); !slices.Contains(got, tgid) || !slices.Contains(got, child) || len(skipped) != 0 {
		t.Fatalf("members %v skipped %+v, want %d and its child %d, none skipped", got, skipped, tgid, child)
	}
	fds, err := fs.FDs(tgid)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(fds, func(fd FD) bool { return fd.Target == held && fd.Writes() }) {
		t.Errorf("FDs(%d) = %+v, want %s held for writing, through its thread's table", tgid, fds, held)
	}
	ms, err := fs.Maps(tgid)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(ms, func(m Mapping) bool { return m.Path == mapped && m.SharedWritable }) {
		t.Errorf("Maps(%d) = %+v, want %s mapped shared and writable, through its thread", tgid, ms, mapped)
	}
	env := Env{Proc: fs, FS: Cgroups{}, Live: Pidfds{}, Mount: cgroupMount}
	res, err := Move(env, dst, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(res.Moved); !slices.Contains(got, tgid) || !slices.Contains(got, child) ||
		len(res.Skipped) != 0 || res.Left != 0 || len(res.Misplaced) != 0 {
		t.Fatalf("moved %v, skipped %+v, left %d, misplaced %v: want %d and %d moved, nothing else", got, res.Skipped,
			res.Left, res.Misplaced, tgid, child)
	}
	for _, id := range []int{tid, child} {
		if cg, err := fs.Cgroup(id); err != nil || cg != dstRel {
			t.Errorf("task %d is in %q (%v) after the move, want the run's cgroup %s", id, cg, err, dstRel)
		}
	}
	if cg, err := CgroupOf(fs, tgid); err != nil || cg != dstRel {
		t.Errorf("CgroupOf(%d) = %q, %v after the move; want %s", tgid, cg, err, dstRel)
	}
	if pids, _ := scopeProcs(env, dst); !slices.Contains(pids, tgid) {
		t.Errorf("the run's cgroup lists processes %v, want %d among them through cgroup.threads", pids, tgid)
	}
	rel := Release(env, dst, []string{src})
	if len(rel.Left) != 0 || !slices.Contains(rel.To[src], tgid) {
		t.Errorf("release: to %v, left %v; want %d back in %s", rel.To, rel.Left, tgid, src)
	}
	for _, id := range []int{tid, child} {
		if cg, err := fs.Cgroup(id); err != nil || cg != srcRel {
			t.Errorf("task %d is in %q (%v) after the release, want %s", id, cg, err, srcRel)
		}
	}
	if threads, err := (Cgroups{}).Threads(dst); err != nil || len(threads) != 0 {
		t.Errorf("the run's cgroup holds tasks %v (%v) after the release, want none", threads, err)
	}
}
