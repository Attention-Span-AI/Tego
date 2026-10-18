// SPDX-License-Identifier: Apache-2.0

// Command adoptprobe measures, as root in a KVM guest, what adopting an already-running process into a fresh
// cgroup does with the tier-2 objects as they are (ADR 0055): whether a live
// process tree can be moved into a run cgroup and recorded from the kernel afterwards, what the programs see of
// descriptors and sockets opened before the move, how long the window between noticing a process and recording it
// is, that a process beside the agent in the same cgroup stays where it is, what liveness looks like to a process
// that is not the agent's parent, and what is left attached when the process that adopted it is killed.
//
// It prints one line per fact, `PROBE <name> <value>`, and exits 0 once every phase ran (a phase's own failure is a
// PROBE line, not an exit status). It is an experiment, not a test: test/vm/README.md says how to run it.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/observe"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	roleEnv = "ADOPTPROBE_ROLE"
	cgMount = "/sys/fs/cgroup"
	// probeDir holds the probe's run directories. The builds' locks stay in the host state directory, /run/tego: the
	// pins are under the host's bpffs, and the cgroup backend refuses a lock directory of the caller's own beside them.
	probeDir = "/run/tego-adoptprobe"
)

func say(name string, format string, args ...any) {
	fmt.Printf("PROBE %s %s\n", name, fmt.Sprintf(format, args...))
}

func main() {
	// The tier's detached helpers (the linger timer, the ring trim) and doctor's plane probe re-execute
	// /proc/self/exe with a hidden command: this binary dispatches them as tego's main does.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case doctor.PlaneProbeCommand:
			os.Exit(doctor.PlaneProbeMain(os.Args[2:]))
		case cgroupenforce.RingTrimCommand:
			os.Exit(cgroupenforce.RingTrimMain(os.Args[2:]))
		case cgroupenforce.LingerCommand:
			os.Exit(cgroupenforce.LingerMain(os.Args[2:]))
		}
		if strings.HasPrefix(os.Args[1], "__") {
			return
		}
	}
	switch os.Getenv(roleEnv) {
	case "agent":
		agentMain()
	case "adopter":
		adopterMain()
	default:
		probeMain()
	}
}

// ---- the fake agent ---------------------------------------------------------------------------------------

// agentMain is the process the probe adopts. Before anything else it opens a file and creates a socket it keeps,
// then answers one command per line on stdin with one line on stdout.
func agentMain() {
	pre, err := os.Open("/etc/hostname")
	if err != nil {
		pre, _ = os.Open("/proc/self/stat")
	}
	var pre2 *os.File
	if p := os.Getenv("ADOPTPROBE_PREOPEN"); p != "" {
		pre2, _ = os.Open(p)
	}
	sock, _ := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	usock, _ := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	fmt.Printf("ready %d\n", os.Getpid())
	var mu sync.Mutex
	var storm struct {
		stop  chan struct{}
		done  chan struct{}
		total int
		mark  int
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "fork":
			c := exec.Command("sleep", "600")
			if err := c.Start(); err != nil {
				fmt.Printf("err %v\n", err)
				continue
			}
			go func() { _ = c.Wait() }()
			fmt.Printf("child %d\n", c.Process.Pid)
		case "open":
			b, err := os.ReadFile(f[1])
			fmt.Printf("ok %d %v\n", len(b), err)
		case "write":
			err := os.WriteFile(f[1], []byte("x\n"), 0o644)
			fmt.Printf("ok %s\n", errnoOf(err))
		case "readpre2":
			if pre2 == nil {
				fmt.Println("ok none")
				continue
			}
			buf := make([]byte, 64)
			n, err := pre2.ReadAt(buf, 0)
			fmt.Printf("ok %d %v\n", n, err)
		case "uid":
			fmt.Printf("ok %d %d\n", os.Getuid(), os.Geteuid())
		case "readold":
			buf := make([]byte, 64)
			n, err := pre.ReadAt(buf, 0)
			fmt.Printf("ok %d %v\n", n, err)
		case "exec":
			err := exec.Command("/bin/true").Run()
			fmt.Printf("ok %s\n", errnoOf(err))
		case "connect":
			c, err := net.DialTimeout("tcp", f[1], 2*time.Second)
			if c != nil {
				_ = c.Close()
			}
			fmt.Printf("ok %s\n", errnoOf(err))
		case "connectold":
			ap, _ := net.ResolveTCPAddr("tcp4", f[1])
			sa := &unix.SockaddrInet4{Port: ap.Port}
			copy(sa.Addr[:], ap.IP.To4())
			err := unix.Connect(sock, sa)
			fmt.Printf("ok %s\n", errnoOf(err))
		case "sendold", "sendnew":
			ap, _ := net.ResolveUDPAddr("udp4", f[1])
			sa := &unix.SockaddrInet4{Port: ap.Port}
			copy(sa.Addr[:], ap.IP.To4())
			s := usock
			if f[0] == "sendnew" {
				s, _ = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
			}
			err := unix.Sendto(s, []byte("x"), 0, sa)
			if f[0] == "sendnew" {
				_ = unix.Close(s)
			}
			fmt.Printf("ok %s\n", errnoOf(err))
		case "storm":
			// Opens /etc/hostname in a tight loop (a busy agent) until "stop"; "mark" notes how many it had made.
			mu.Lock()
			storm.stop, storm.done = make(chan struct{}), make(chan struct{})
			mu.Unlock()
			go func() {
				defer close(storm.done)
				for {
					select {
					case <-storm.stop:
						return
					default:
					}
					if fd, err := unix.Open("/etc/hostname", unix.O_RDONLY, 0); err == nil {
						_ = unix.Close(fd)
					}
					mu.Lock()
					storm.total++
					mu.Unlock()
				}
			}()
			fmt.Println("ok")
		case "mark":
			mu.Lock()
			storm.mark = storm.total
			mu.Unlock()
			fmt.Printf("ok %d\n", storm.mark)
		case "stop":
			close(storm.stop)
			<-storm.done
			mu.Lock()
			fmt.Printf("ok %d %d\n", storm.total, storm.total-storm.mark)
			mu.Unlock()
		case "threads":
			ents, _ := os.ReadDir("/proc/self/task")
			fmt.Printf("ok %d\n", len(ents))
		case "exit":
			code, _ := strconv.Atoi(f[1])
			os.Exit(code)
		default:
			fmt.Printf("err unknown %q\n", f[0])
		}
	}
}

func errnoOf(err error) string {
	if err == nil {
		return "0"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return en.Error()
	}
	return err.Error()
}

// agentProc is the probe's handle on one fake agent and the shell that started it.
type agentProc struct {
	shell *exec.Cmd
	pid   int
	in    io.WriteCloser
	out   *bufio.Reader
}

func (a *agentProc) cmd(line string) string {
	fmt.Fprintln(a.in, line)
	s, err := a.out.ReadString('\n')
	if err != nil {
		return "EOF " + err.Error()
	}
	return strings.TrimSpace(s)
}

// startAgent starts `sh -c '<probe as agent>; sleep 600'` in the cgroup dir: the shell is the agent's parent and
// stays in that cgroup, as a terminal's shell does.
func startAgent(dir string) (*agentProc, error) { return startAgentAs(dir, -1, nil) }

// startAgentAs is startAgent with the shell and agent running as uid (and gid uid) when uid >= 0, and extra
// environment.
func startAgentAs(dir string, uid int, env []string) (*agentProc, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	sh := exec.Command("/bin/sh", "-c", `"$0"; exec sleep 600`, self)
	sh.Env = append(append(os.Environ(), roleEnv+"=agent"), env...)
	sh.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if uid >= 0 {
		sh.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}
		sh.Dir = "/"
	}
	in, err := sh.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := sh.StdoutPipe()
	if err != nil {
		return nil, err
	}
	sh.Stderr = os.Stderr
	if err := sh.Start(); err != nil {
		return nil, err
	}
	a := &agentProc{shell: sh, in: in, out: bufio.NewReader(out)}
	line, err := a.out.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("agent did not report: %w", err)
	}
	if _, err := fmt.Sscanf(line, "ready %d", &a.pid); err != nil {
		return nil, fmt.Errorf("agent said %q", line)
	}
	return a, nil
}

// ---- cgroup and /proc helpers ------------------------------------------------------------------------------

func cgroupOf(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "?" + err.Error()
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return p
		}
	}
	return "?"
}

func cgroupID(path string) uint64 {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}

func moveTo(dir string, pid int) error {
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0)
}

func procsOf(dir string) []int {
	b, _ := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func populated(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "cgroup.events"))
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "populated "); ok {
			return v
		}
	}
	return "?"
}

// children is every process whose parent is pid, read from /proc (a snapshot).
func children(pid int) []int {
	ents, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range ents {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", n))
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) > 1 {
			if pp, _ := strconv.Atoi(f[1]); pp == pid {
				out = append(out, n)
			}
		}
	}
	return out
}

// treeOf is pid and every descendant, parents first.
func treeOf(pid int) []int {
	out := []int{pid}
	for i := 0; i < len(out); i++ {
		out = append(out, children(out[i])...)
	}
	return out
}

func threadsIn(pid int, dir string) (in, total int) {
	ents, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	for _, e := range ents {
		total++
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/cgroup", pid, e.Name()))
		if strings.Contains(string(b), "0::"+dir+"\n") {
			in++
		}
	}
	return in, total
}

// ---- the record --------------------------------------------------------------------------------------------

type sink struct {
	mu  sync.Mutex
	evs []*record.Event
}

func (s *sink) Emit(ev *record.Event) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
}

func (s *sink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.evs...)
}

func summarize(evs []*record.Event, pids map[int]string) {
	type key struct {
		kind record.Kind
		who  string
	}
	n := map[key]int{}
	for _, ev := range evs {
		who := pids[ev.PID]
		if who == "" {
			who = "pid" + strconv.Itoa(ev.PID)
		}
		n[key{ev.Kind, who}]++
	}
	var keys []key
	for k := range n {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].who < keys[j].who
	})
	for _, k := range keys {
		say("record.count", "kind=%s process=%s n=%d", k.kind, k.who, n[k])
	}
}

func payloadHas(ev *record.Event, sub string) bool { return strings.Contains(string(ev.Payload), sub) }

// ---- the probe ---------------------------------------------------------------------------------------------

func machine() *config.Machine {
	m := config.Builtin()
	m.BPF.Linger.Value = 0
	return m
}

// table compiles a contract for tier cgroup: record-only when net is "", else net.allow: [net].
func table(net string) (*agent.RuleTable, error) {
	y := "version: 0\nname: adoptprobe\ncommand: [\"/bin/true\"]\nrecord: full\nfs:\n  deny_read: []\n"
	if net != "" {
		y += "net:\n  allow: [\"" + net + "\"]\n"
	}
	c, _, err := agent.LoadBytes("adoptprobe.yaml", []byte(y), nil)
	if err != nil {
		return nil, err
	}
	rt, _, err := agent.Compile(c, config.Builtin(), agent.WithCwd("/"), agent.WithHome("/root"))
	if err != nil {
		return nil, err
	}
	return rt.AtTier(backend.TierCgroup), nil
}

type run struct {
	id    string
	dir   string
	cgid  uint64
	h     *cgroupenforce.Handle
	rec   *observe.Recorder
	sink  *sink
	start time.Time
}

// prepare makes a run's cgroup under /sys/fs/cgroup/tego-adoptprobe and prepares tier 2 for it. Nothing is armed.
func prepare(id string, rt *agent.RuleTable) (*run, error) {
	r := &run{id: id, sink: &sink{}}
	base := filepath.Join(cgMount, "tego-adoptprobe")
	_ = os.MkdirAll(base, 0o755)
	r.dir = filepath.Join(base, "adopt-"+id+".scope")
	if err := os.Mkdir(r.dir, 0o755); err != nil {
		return nil, err
	}
	r.cgid = cgroupID(r.dir)
	rel := strings.TrimPrefix(r.dir, cgMount)
	runDir := filepath.Join(probeDir, "runs", id)
	_ = os.MkdirAll(runDir, 0o700)
	b := cgroupenforce.New(cgroupenforce.Options{Machine: machine(), Events: r.sink})
	t0 := time.Now()
	h, err := b.Prepare(context.Background(), rt, cgroupenforce.Run{ID: id, Agent: "adoptprobe", CgroupID: r.cgid,
		CgroupPath: rel, CgroupMount: cgMount, Dir: runDir, Contract: filepath.Join(runDir, "contract.yaml")})
	if err != nil {
		_ = os.Remove(r.dir)
		return nil, err
	}
	say("time.prepare", "run=%s ms=%.1f", id, float64(time.Since(t0).Microseconds())/1000)
	r.h = h
	return r, nil
}

// arm attaches and arms the run and starts its recorder.
func (r *run) arm() error {
	t0 := time.Now()
	if err := r.h.Attach(r.cgid); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	if err := r.h.Arm(); err != nil {
		return fmt.Errorf("arm: %w", err)
	}
	rec, err := observe.New(observe.Options{Rules: &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup},
		BPFHash: r.h.BPFHash(), FlushInterval: 100 * time.Millisecond})
	if err != nil {
		return fmt.Errorf("recorder: %w", err)
	}
	if err := rec.Start(context.Background(), source.RunRef{ID: r.id, Agent: "adoptprobe", CgroupID: r.cgid}, r.sink); err != nil {
		return fmt.Errorf("recorder start: %w", err)
	}
	r.rec = rec
	r.start = time.Now()
	say("time.arm", "run=%s ms=%.1f", r.id, float64(time.Since(t0).Microseconds())/1000)
	return nil
}

func (r *run) close() {
	if r.rec != nil {
		_ = r.rec.Stop()
		say("record.gaps", "run=%s %+v", r.id, r.rec.Gaps())
	}
	if r.h != nil {
		if err := r.h.Close(); err != nil {
			say("close.err", "run=%s %v", r.id, err)
		}
	}
	if err := os.Remove(r.dir); err != nil {
		say("rmdir.err", "run=%s %v", r.id, err)
	}
}

// adopt moves pid and its descendants that are in from into r's cgroup, rounds until none is left there; it returns
// how many it moved and the rounds it took.
func adopt(r *run, pid int, from string) (moved []int, rounds int) {
	seen := map[int]bool{}
	for rounds = 1; rounds <= 16; rounds++ {
		var todo []int
		for _, p := range treeOf(pid) {
			if !seen[p] && cgroupOf(p) == from {
				todo = append(todo, p)
			}
		}
		if len(todo) == 0 {
			return moved, rounds
		}
		for _, p := range todo {
			seen[p] = true
			if err := moveTo(r.dir, p); err != nil {
				say("move.err", "pid=%d %v", p, err)
				continue
			}
			moved = append(moved, p)
		}
	}
	return moved, rounds
}

func probeMain() {
	if os.Geteuid() != 0 {
		say("skip", "needs root")
		return
	}
	say("kernel", "%s", kernelRelease())
	say("bpf.objects", "%v", ebpfbindings.Available())
	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	say("lsm", "%s", strings.TrimSpace(string(lsm)))
	if err := os.MkdirAll(probeDir, 0o700); err != nil {
		say("fatal", "state dir: %v", err)
		return
	}
	_ = os.Chmod(probeDir, 0o700)

	// The user's terminal: a session cgroup holding a shell (the agent's parent) and a sibling (another tab).
	session := filepath.Join(cgMount, "probe-session.scope")
	_ = os.Mkdir(session, 0o755)
	sessRel := strings.TrimPrefix(session, cgMount)
	fd, _ := unix.Open(session, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	sib := exec.Command("sleep", "600")
	sib.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if err := sib.Start(); err != nil {
		say("fatal", "sibling: %v", err)
		return
	}
	_ = unix.Close(fd)
	defer func() { _ = sib.Process.Kill(); _ = sib.Wait() }()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		say("fatal", "listen: %v", err)
		return
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	allowed := ln.Addr().String()
	ln2, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer func() { _ = ln2.Close() }()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	other := ln2.Addr().String()
	udp, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer func() { _ = udp.Close() }()
	udpOther := udp.LocalAddr().String()

	// A run that holds the build for the phases below, so their Prepare is a warm one; this one is cold.
	keeperTable, _ := table("")
	keeper, err := prepare("keeper", keeperTable)
	if err != nil {
		say("fatal", "keeper: %v", err)
		return
	}
	phaseRecordAndNet(session, sessRel, sib.Process.Pid, allowed, other, udpOther)
	phaseRelease(session, sessRel)
	phaseStorm(session, sessRel)
	phasePlane(session, sessRel)
	keeper.close()
	phaseKill(session, sessRel, allowed)
	phaseKill(session, sessRel, "")
	_ = os.Remove(session)
	say("done", "ok")
}

// phaseRecordAndNet adopts an agent mid-life under a contract that allows one TCP destination, and reports what
// the record shows and what the network programs decide, for sockets made before and after the move.
func phaseRecordAndNet(session, sessRel string, sibling int, allowed, other, udpOther string) {
	a, err := startAgent(session)
	if err != nil {
		say("fatal", "agent: %v", err)
		return
	}
	defer func() { _ = a.shell.Process.Kill(); _ = a.shell.Wait() }()
	shellPID := a.shell.Process.Pid
	detected := time.Now()
	k1 := 0
	_, _ = fmt.Sscanf(a.cmd("fork"), "child %d", &k1)
	say("before", "shell=%d agent=%d child=%d sibling=%d all in %s", shellPID, a.pid, k1, sibling, cgroupOf(a.pid))

	rt, err := table(allowed)
	if err != nil {
		say("fatal", "table: %v", err)
		return
	}
	r, err := prepare("netrun", rt)
	if err != nil {
		say("fatal", "prepare: %v", err)
		return
	}
	defer r.close()
	tm := time.Now()
	moved, rounds := adopt(r, a.pid, sessRel)
	say("time.move", "processes=%d rounds=%d ms=%.3f", len(moved), rounds, float64(time.Since(tm).Microseconds())/1000)
	if err := r.arm(); err != nil {
		say("fatal", "arm: %v", err)
		return
	}
	say("time.window", "detected-to-recording ms=%.1f", float64(r.start.Sub(detected).Microseconds())/1000)
	rel := strings.TrimPrefix(r.dir, cgMount)
	say("after.cgroup", "agent=%v child=%v shell=%v sibling=%v",
		cgroupOf(a.pid) == rel, cgroupOf(k1) == rel, cgroupOf(shellPID) == sessRel, cgroupOf(sibling) == sessRel)
	in, total := threadsIn(a.pid, rel)
	say("after.threads", "agent threads in run cgroup %d of %d", in, total)
	say("after.fds", "%s", fdSummary(a.pid))

	// After the move: a fork, a new open, a read of the descriptor opened before, an exec, connects.
	k2 := 0
	_, _ = fmt.Sscanf(a.cmd("fork"), "child %d", &k2)
	say("after.fork", "new child %d in run cgroup=%v", k2, cgroupOf(k2) == rel)
	say("act.open-new", "%s", a.cmd("open /etc/passwd"))
	say("act.read-old-fd", "%s", a.cmd("readold"))
	say("act.exec", "%s", a.cmd("exec"))
	say("act.connect-new-allowed", "%s", a.cmd("connect "+allowed))
	say("act.connect-new-other", "%s", a.cmd("connect "+other))
	say("act.connect-old-socket-other", "%s", a.cmd("connectold "+other))
	say("act.udp-old-socket-other", "%s", a.cmd("sendold "+udpOther))
	say("act.udp-new-socket-other", "%s", a.cmd("sendnew "+udpOther))
	time.Sleep(700 * time.Millisecond)

	// Liveness without being the parent: a pidfd says the agent ended, the cgroup says the tree did; no status.
	pfd, err := unix.PidfdOpen(a.pid, 0)
	if err != nil {
		say("pidfd.err", "%v", err)
	}
	fmt.Fprintln(a.in, "exit 7")
	t0 := time.Now()
	n, _ := unix.Poll([]unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}, 3000)
	say("liveness.pidfd", "readable=%v after ms=%.1f", n > 0, float64(time.Since(t0).Microseconds())/1000)
	var info unix.Siginfo
	werr := unix.Waitid(unix.P_PIDFD, pfd, &info, unix.WEXITED|unix.WNOHANG, nil)
	say("liveness.waitid", "not the parent: %v", errnoOf(werr))
	_ = unix.Close(pfd)
	say("liveness.populated", "with the children alive=%s", populated(r.dir))
	_ = syscall.Kill(k1, syscall.SIGKILL)
	_ = syscall.Kill(k2, syscall.SIGKILL)
	time.Sleep(300 * time.Millisecond)
	say("liveness.populated", "after the children ended=%s", populated(r.dir))
	time.Sleep(300 * time.Millisecond)

	names := map[int]string{a.pid: "agent", k1: "child1", k2: "child2"}
	evs := r.sink.all()
	summarize(evs, names)
	for _, ev := range evs {
		switch ev.Kind {
		case record.KindNet, record.KindExec, record.KindRefused, record.KindGap:
			say("record.line", "kind=%s pid=%d verdict=%s rule=%s payload=%s", ev.Kind, ev.PID, ev.Verdict, ev.Rule, ev.Payload)
		case record.KindFS:
			if payloadHas(ev, "/etc/hostname") || payloadHas(ev, "/etc/passwd") {
				say("record.line", "kind=%s pid=%d verdict=%s rule=%s payload=%s", ev.Kind, ev.PID, ev.Verdict, ev.Rule, ev.Payload)
			}
		}
	}
	_ = a.shell.Process.Kill()
	_ = a.shell.Wait()
}

// phaseStorm adopts an agent that is opening a file in a tight loop and compares what the record holds with what
// the agent made after the recording began.
func phaseStorm(session, sessRel string) {
	a, err := startAgent(session)
	if err != nil {
		say("fatal", "storm agent: %v", err)
		return
	}
	defer func() { _ = a.shell.Process.Kill(); _ = a.shell.Wait() }()
	rt, err := table("")
	if err != nil {
		say("fatal", "table: %v", err)
		return
	}
	r, err := prepare("storm", rt)
	if err != nil {
		say("fatal", "prepare: %v", err)
		return
	}
	defer r.close()
	say("storm.start", "%s", a.cmd("storm"))
	time.Sleep(300 * time.Millisecond)
	moved, _ := adopt(r, a.pid, sessRel)
	if err := r.arm(); err != nil {
		say("fatal", "arm: %v", err)
		return
	}
	say("storm.moved", "%d", len(moved))
	say("storm.mark", "%s", a.cmd("mark"))
	time.Sleep(1500 * time.Millisecond)
	say("storm.stop", "total and since-mark: %s", a.cmd("stop"))
	time.Sleep(500 * time.Millisecond)
	_ = r.rec.Stop()
	opens := 0
	for _, ev := range r.sink.all() {
		if ev.Kind == record.KindFS && ev.PID == a.pid && payloadHas(ev, "/etc/hostname") {
			var c struct {
				Count int `json:"count"`
			}
			_ = json.Unmarshal(ev.Payload, &c)
			if c.Count == 0 {
				c.Count = 1
			}
			opens += c.Count
		}
	}
	say("storm.recorded", "opens of /etc/hostname recorded=%d gaps=%+v", opens, r.rec.Gaps())
	fmt.Fprintln(a.in, "exit 0")
}

// phaseKill starts a separate adopter process that adopts a sleeping process and arms a run (with a net rule when
// netRule is set, so the cgroup programs are attached), SIGKILLs it, and reports what is left in the kernel.
func phaseKill(session, sessRel, netRule string) {
	target := exec.Command("sleep", "600")
	fd, _ := unix.Open(session, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	target.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if err := target.Start(); err != nil {
		say("fatal", "kill target: %v", err)
		return
	}
	_ = unix.Close(fd)
	defer func() { _ = target.Process.Kill(); _ = target.Wait() }()
	self, _ := os.Executable()
	ad := exec.Command(self)
	ad.Env = append(os.Environ(), roleEnv+"=adopter", "ADOPTPROBE_TARGET="+strconv.Itoa(target.Process.Pid),
		"ADOPTPROBE_FROM="+sessRel, "ADOPTPROBE_NET="+netRule)
	out, _ := ad.StdoutPipe()
	ad.Stderr = os.Stderr
	if err := ad.Start(); err != nil {
		say("fatal", "adopter: %v", err)
		return
	}
	br := bufio.NewReader(out)
	var line string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			say("fatal", "adopter said nothing: %v", err)
			_ = ad.Process.Kill()
			_ = ad.Wait()
			return
		}
		if strings.HasPrefix(l, "armed ") {
			line = l
			break
		}
		fmt.Print(l)
	}
	var hash, dir string
	var cgid uint64
	if _, err := fmt.Sscanf(line, "armed %s %d %s", &hash, &cgid, &dir); err != nil {
		say("fatal", "adopter said %q", line)
		_ = ad.Process.Kill()
		_ = ad.Wait()
		return
	}
	tag := "kill.record-only"
	if netRule != "" {
		tag = "kill.with-net"
	}
	say(tag+".before", "%s", leftovers(hash, cgid, dir))
	_ = ad.Process.Signal(syscall.SIGKILL)
	_ = ad.Wait()
	time.Sleep(200 * time.Millisecond)
	say(tag+".after-sigkill", "%s; target in %s", leftovers(hash, cgid, dir), cgroupOf(target.Process.Pid))

	// What root does to remove it: move the process back, remove the cgroup, purge the run's kernel state.
	_ = moveTo(filepath.Join(cgMount, sessRel), target.Process.Pid)
	if err := os.Remove(dir); err != nil {
		say(tag+".rmdir", "%v", err)
	}
	res, err := cgroupenforce.PurgeRun(cgroupenforce.PurgeOptions{Hash: hash, RunID: "killed",
		CgroupID: cgid, CgroupMount: cgMount})
	say(tag+".purge", "links=%v slots=%v rings=%d err=%v", res.Links, res.Slots, res.Rings, err)
	say(tag+".after-purge", "%s; target alive=%v in %s", leftovers(hash, cgid, dir),
		syscall.Kill(target.Process.Pid, 0) == nil, cgroupOf(target.Process.Pid))
}

// leftovers says what of a run is still in the kernel: its run-set row, its pinned link directory and the programs
// attached to its cgroup.
func leftovers(hash string, cgid uint64, dir string) string {
	var parts []string
	m, err := ebpf.LoadPinnedMap(filepath.Join(cgroupenforce.DefaultBPFFS, "tego", hash, "maps", ebpfbindings.MapRunSet), nil)
	if err != nil {
		parts = append(parts, "run-set: "+err.Error())
	} else {
		var v ebpfbindings.Run
		err := m.Lookup(&cgid, &v)
		parts = append(parts, fmt.Sprintf("run-set row=%v", err == nil))
		_ = m.Close()
	}
	links, _ := os.ReadDir(filepath.Join(cgroupenforce.DefaultBPFFS, "tego", hash, "links"))
	var runLinks []string
	for _, l := range links {
		if strings.HasPrefix(l.Name(), "run-") {
			sub, _ := os.ReadDir(filepath.Join(cgroupenforce.DefaultBPFFS, "tego", hash, "links", l.Name()))
			runLinks = append(runLinks, fmt.Sprintf("%s(%d)", l.Name(), len(sub)))
		}
	}
	parts = append(parts, fmt.Sprintf("pinned run links=%v", runLinks))
	if fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		q, err := link.QueryPrograms(link.QueryOptions{Target: fd, Attach: ebpf.AttachCGroupInet4Connect})
		if err == nil {
			parts = append(parts, fmt.Sprintf("connect4 programs on the cgroup=%d", len(q.Programs)))
		}
		_ = unix.Close(fd)
	} else {
		parts = append(parts, "cgroup gone")
	}
	builds, _ := os.ReadDir(filepath.Join(cgroupenforce.DefaultBPFFS, "tego"))
	var names []string
	for _, b := range builds {
		names = append(names, b.Name())
	}
	parts = append(parts, fmt.Sprintf("pin dirs=%v", names))
	return strings.Join(parts, "; ")
}

// adopterMain is the separate adopter phaseKill kills: it adopts ADOPTPROBE_TARGET, arms, says so, and waits.
func adopterMain() {
	pid, _ := strconv.Atoi(os.Getenv("ADOPTPROBE_TARGET"))
	rt, err := table(os.Getenv("ADOPTPROBE_NET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "adopter table:", err)
		os.Exit(1)
	}
	r, err := prepare("killed", rt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "adopter prepare:", err)
		os.Exit(1)
	}
	if err := moveTo(r.dir, pid); err != nil {
		fmt.Fprintln(os.Stderr, "adopter move:", err)
		os.Exit(1)
	}
	if err := r.arm(); err != nil {
		fmt.Fprintln(os.Stderr, "adopter arm:", err)
		os.Exit(1)
	}
	fmt.Printf("armed %s %d %s\n", r.h.BPFHash(), r.cgid, r.dir)
	select {}
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "?"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// fdSummary is what /proc says a process holds open: what an adopter can list, and the record never shows.
func fdSummary(pid int) string {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return err.Error()
	}
	var files, sockets, other []string
	for _, e := range ents {
		t, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "socket:"):
			sockets = append(sockets, e.Name()+"="+t)
		case strings.HasPrefix(t, "/"):
			files = append(files, e.Name()+"="+t)
		default:
			other = append(other, e.Name()+"="+t)
		}
	}
	return fmt.Sprintf("files=%v sockets=%v other=%v", files, sockets, other)
}

// phaseRelease adopts an agent with a child, then releases it: the run's cgroup is frozen so nothing forks
// during the move, every process goes back to the cgroup it came from, the cgroup is thawed and removed, and
// the agent must still answer.
func phaseRelease(session, sessRel string) {
	a, err := startAgent(session)
	if err != nil {
		say("fatal", "release agent: %v", err)
		return
	}
	defer func() { _ = a.shell.Process.Kill(); _ = a.shell.Wait() }()
	k1 := 0
	_, _ = fmt.Sscanf(a.cmd("fork"), "child %d", &k1)
	rt, _ := table("")
	r, err := prepare("release", rt)
	if err != nil {
		say("fatal", "release prepare: %v", err)
		return
	}
	moved, _ := adopt(r, a.pid, sessRel)
	if err := r.arm(); err != nil {
		say("fatal", "release arm: %v", err)
		r.close()
		return
	}
	k2 := 0
	_, _ = fmt.Sscanf(a.cmd("fork"), "child %d", &k2)
	say("release.adopted", "moved=%v later child %d in run=%v", moved, k2, cgroupOf(k2) == strings.TrimPrefix(r.dir, cgMount))
	t0 := time.Now()
	if err := os.WriteFile(filepath.Join(r.dir, "cgroup.freeze"), []byte("1"), 0); err != nil {
		say("release.freeze", "%v", err)
	}
	var back []int
	for round := 0; round < 8; round++ {
		ps := procsOf(r.dir)
		if len(ps) == 0 {
			break
		}
		for _, p := range ps {
			if err := moveTo(session, p); err != nil {
				say("release.move.err", "pid=%d %v", p, err)
				continue
			}
			back = append(back, p)
		}
	}
	_ = os.WriteFile(filepath.Join(r.dir, "cgroup.freeze"), []byte("0"), 0)
	say("time.release", "moved back %v in ms=%.2f; run cgroup populated=%s", back, float64(time.Since(t0).Microseconds())/1000, populated(r.dir))
	r.close()
	say("release.after", "agent answers %q; agent in session=%v child1=%v child2=%v; agent state %s",
		a.cmd("threads"), cgroupOf(a.pid) == sessRel, cgroupOf(k1) == sessRel, cgroupOf(k2) == sessRel, procState(a.pid))
	_ = syscall.Kill(k1, syscall.SIGKILL)
	_ = syscall.Kill(k2, syscall.SIGKILL)
	fmt.Fprintln(a.in, "exit 0")
}

func procState(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "gone"
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return "?"
	}
	return s[i+2 : i+3]
}

// phasePlane adopts an agent running as an unprivileged user under a boundary, with the backend `tego run --tier
// cgroup` selects (the decision plane in the mode doctor picks, tier 1 composed but never installed), and reports
// what is refused and what is recorded.
func phasePlane(session, sessRel string) {
	ws, secret := "/tmp/probe-ws", "/tmp/probe-secret"
	_ = os.MkdirAll(ws, 0o777)
	_ = os.Chmod(ws, 0o777)
	_ = os.WriteFile(secret, []byte("secret\n"), 0o644)
	self, _ := os.Executable()
	_ = os.Chmod(self, 0o755)
	_ = os.Chmod(filepath.Dir(self), 0o755)
	a, err := startAgentAs(session, 65534, []string{"ADOPTPROBE_PREOPEN=" + secret})
	if err != nil {
		say("fatal", "plane agent: %v", err)
		return
	}
	defer func() { _ = a.shell.Process.Kill(); _ = a.shell.Wait() }()
	say("plane.agent", "uid %s", a.cmd("uid"))
	y := fmt.Sprintf("version: 0\nname: adoptplane\ncommand: [%q]\nrecord: full\nfs:\n  write: [%q, \"/dev/null\"]\n  deny_read: [%q]\nexec:\n  allow: [\"/usr/bin/sleep\"]\n", self, ws, secret)
	c, _, err := agent.LoadBytes("plane.yaml", []byte(y), nil)
	if err != nil {
		say("fatal", "plane contract: %v", err)
		return
	}
	m := machine()
	rt, _, err := agent.Compile(c, m, agent.WithCwd("/"), agent.WithHome("/root"))
	if err != nil {
		say("fatal", "plane compile: %v", err)
		return
	}
	rep, err := doctor.ForRun(context.Background(), m, backend.TierCgroup)
	if err != nil {
		say("fatal", "plane doctor: %v", err)
		return
	}
	if rep.Plane != nil {
		js, _ := json.Marshal(rep.Plane)
		say("plane.doctor", "%s", js)
	}
	b, ds := rep.Select(m, rt, backend.TierCgroup)
	for _, d := range ds {
		say("plane.select", "%s", d.String())
	}
	if b == nil {
		say("fatal", "plane: no backend")
		return
	}
	rt = rt.AtTier(b.Tier())
	base := filepath.Join(cgMount, "tego-adoptprobe")
	dir := filepath.Join(base, "adopt-plane.scope")
	if err := os.Mkdir(dir, 0o755); err != nil {
		say("fatal", "plane cgroup: %v", err)
		return
	}
	defer func() { _ = os.Remove(dir) }()
	cgid := cgroupID(dir)
	runDir := filepath.Join(probeDir, "runs", "plane")
	_ = os.MkdirAll(runDir, 0o700)
	sk := &sink{}
	t0 := time.Now()
	h, err := b.Prepare(context.Background(), rt, enforce.RunRef{ID: "plane", Agent: "adoptplane", CgroupID: cgid,
		RunDir: runDir, Contract: filepath.Join(runDir, "contract.yaml"), CgroupPath: strings.TrimPrefix(dir, cgMount),
		CgroupMount: cgMount, Events: sk, Drop: true, DropUID: 65534, DropGID: 65534})
	if err != nil {
		say("fatal", "plane prepare: %v", err)
		return
	}
	defer func() {
		if err := h.Close(); err != nil {
			say("plane.close", "%v", err)
		}
	}()
	say("time.prepare", "run=plane ms=%.1f", float64(time.Since(t0).Microseconds())/1000)
	mode := ""
	if pr, ok := h.(enforce.DecisionPlaneReporter); ok {
		mode, _ = pr.DecisionPlane()
	}
	say("plane.mode", "%q (empty: the fanotify fallback)", mode)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if l, ok := h.(api.Listener); ok {
		go func() { _ = l.RunListener(ctx) }()
	}
	k := 0
	_, _ = fmt.Sscanf(a.cmd("fork"), "child %d", &k)
	from := cgroupOf(a.pid)
	moved := []int{}
	for _, p := range treeOf(a.pid) {
		if cgroupOf(p) == from {
			if err := moveTo(dir, p); err == nil {
				moved = append(moved, p)
			}
		}
	}
	if err := h.Attach(cgid); err != nil {
		say("fatal", "plane attach: %v", err)
		return
	}
	if ar, ok := h.(interface{ Arm() error }); ok {
		if err := ar.Arm(); err != nil {
			say("fatal", "plane arm: %v", err)
			return
		}
	}
	rec, err := observe.New(observe.Options{Rules: rt, BPFHash: h.(enforce.KernelRecorder).BPFHash(),
		FlushInterval: 100 * time.Millisecond, DecisionPlane: mode})
	if err != nil {
		say("fatal", "plane recorder: %v", err)
		return
	}
	if err := rec.Start(ctx, source.RunRef{ID: "plane", Agent: "adoptplane", CgroupID: cgid, Contract: rt}, sk); err != nil {
		say("fatal", "plane recorder start: %v", err)
		return
	}
	say("plane.moved", "%v", moved)
	say("plane.read-denied-new-open", "%s", a.cmd("open "+secret))
	say("plane.read-denied-fd-opened-before", "%s", a.cmd("readpre2"))
	say("plane.write-inside", "%s", a.cmd("write "+ws+"/a"))
	say("plane.write-outside", "%s", a.cmd("write /tmp/probe-outside"))
	say("plane.exec-unlisted", "%s", a.cmd("exec"))
	say("plane.exec-listed", "%s", a.cmd("fork"))
	time.Sleep(800 * time.Millisecond)
	_ = rec.Stop()
	for _, ev := range sk.all() {
		if ev.Kind == record.KindFS && !payloadHas(ev, "/tmp/") && ev.Verdict != record.VerdictRefused {
			continue
		}
		say("plane.line", "kind=%s pid=%d verdict=%s rule=%s reason=%s payload=%s", ev.Kind, ev.PID, ev.Verdict, ev.Rule, ev.Reason, ev.Payload)
	}
	say("plane.gaps", "%+v", rec.Gaps())
	if pc, ok := h.(enforce.PlaneCounterReporter); ok {
		c, err := pc.PlaneCounters()
		say("plane.counters", "%+v %v", c, err)
	}
	// Released: out of the run's cgroup, the agent writes outside the workspace again.
	for _, p := range procsOf(dir) {
		_ = moveTo(filepath.Join(cgMount, sessRel), p)
	}
	say("plane.after-release.write-outside", "%s", a.cmd("write /tmp/probe-outside2"))
	_ = syscall.Kill(k, syscall.SIGKILL)
	fmt.Fprintln(a.in, "exit 0")
}
