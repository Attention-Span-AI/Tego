// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The per-slot activity stamp on a real kernel (limits R4, A-REC-1, A-REC-6): trace_proc's allowed opens, file
// operations, creates and connects of a run whose row says record: off and carries RunActivity write the run's slot
// of tego_activity with bpf_ktime_get_ns, and nothing else; a run without the flag, or one that records, is never
// stamped by them, and no other slot is ever written. The agent is activityHelper, this test binary re-executed into
// a child cgroup, so every action is a process of the run's own cgroup.

const activityHelperEnv = "TEGO_ACTIVITY_HELPER"

func init() {
	if os.Getenv(activityHelperEnv) != "1" {
		return
	}
	os.Exit(activityHelperMain())
}

// activityHelperMain answers one command per line, "<op> <arg>", with "ok" or "err <reason>": open (a read-only open
// of arg), openloop ("<path> <n>": n of them, each closed), mkdir, mknod (a regular file, the shape an O_CREAT open's
// create asks in) and connect (TCP to 127.0.0.1:arg).
func activityHelperMain() int {
	in := bufio.NewScanner(os.Stdin)
	fmt.Println("ready")
	for in.Scan() {
		verb, arg, _ := strings.Cut(in.Text(), " ")
		if err := activityOp(verb, arg); err != nil {
			fmt.Println("err " + err.Error())
			continue
		}
		fmt.Println("ok")
	}
	return 0
}

func activityOp(verb, arg string) error {
	switch verb {
	case "open":
		fd, err := unix.Open(arg, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		return unix.Close(fd)
	case "mkdir":
		return unix.Mkdir(arg, 0o755)
	case "mknod":
		return unix.Mknod(arg, unix.S_IFREG|0o644, 0)
	case "openloop":
		path, count, _ := strings.Cut(arg, " ")
		n, err := strconv.Atoi(count)
		if err != nil {
			return err
		}
		for range n {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			_ = unix.Close(fd)
		}
		return nil
	case "connect":
		port, err := strconv.Atoi(arg)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
	}
	return fmt.Errorf("unknown op %q", verb)
}

type activityHelper struct {
	in  io.WriteCloser
	out *bufio.Reader
}

func (h *activityHelper) do(t *testing.T, cmd string) {
	t.Helper()
	if _, err := fmt.Fprintln(h.in, cmd); err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	line, err := h.out.ReadString('\n')
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	if got := strings.TrimSpace(line); got != "ok" {
		t.Fatalf("%s in the run: %s", cmd, got)
	}
}

func startActivityHelper(t *testing.T, cgroupFD int) *activityHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), activityHelperEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the helper in its cgroup: %v", err)
	}
	h := &activityHelper{in: in, out: bufio.NewReader(out)}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if line, err := h.out.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper did not start: %q %v", line, err)
	}
	return h
}

func monoNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

// activityPrograms are the trace_proc programs whose record: off gates stamp: an open, the file operations through
// tego_fsop_begin (mkdir's), the regular-file create held at mknod, and the connect fentry.
var activityPrograms = []string{ProgFileOpen, ProgPathMkdir, ProgPathMknod, ProgSocketConnect}

func TestActivityStampPerSlot(t *testing.T) {
	requireBPF(t)
	choice := KernelReader()
	ran := 0
	for _, r := range Readers {
		t.Run(string(r), func(t *testing.T) {
			switch {
			case r == ReaderRdonly && choice.Reader != ReaderRdonly:
				t.Skip("this kernel's BTF lacks bpf_rdonly_cast or bpf_loop: " + choice.Why)
			case r == ReaderProbe && choice.Confidentiality:
				t.Skip("lockdown=confidentiality refuses bpf_probe_read_kernel")
			}
			activityCells(t, r)
			ran++
		})
	}
	if ran == 0 {
		t.Fatal("no build of trace_proc ran on this kernel")
	}
}

func activityCells(t *testing.T, r Reader) {
	const slot, gen = 11, 4242
	spec, err := LoadReader(ObjectTraceProc, r)
	if err != nil {
		t.Fatal(err)
	}
	keep := map[string]bool{}
	for _, name := range activityPrograms {
		keep[name] = true
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	unpin(spec)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load %s's %s build: %+v", ObjectTraceProc, r, ve)
		}
		t.Fatalf("load %s's %s build: %v", ObjectTraceProc, r, err)
	}
	t.Cleanup(coll.Close)
	for _, name := range activityPrograms {
		l, err := AttachTrace(name, coll.Programs[name])
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	activity, lost, runSet := coll.Maps[MapActivity], coll.Maps[MapLost], coll.Maps[MapRunSet]
	if activity == nil || lost == nil || runSet == nil {
		t.Fatal("trace_proc lacks tego_activity, tego_lost or tego_run_set")
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	// The files live under /tmp, whatever TMPDIR says: the helper creates in a directory both processes can name.
	base, err := os.MkdirTemp("/tmp", "eya")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	file := filepath.Join(base, "read-me")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, cgfd, cgid := planeChildCgroup(t, "activity-"+string(r))
	helper := startActivityHelper(t, cgfd)
	t.Cleanup(func() { _ = runSet.Delete(cgid) })

	n := 0
	action := func(verb string) string {
		n++
		switch verb {
		case "open":
			return "open " + file
		case "mkdir":
			return "mkdir " + filepath.Join(base, "d"+strconv.Itoa(n))
		case "mknod":
			return "mknod " + filepath.Join(base, "f"+strconv.Itoa(n))
		}
		return "connect " + strconv.Itoa(port)
	}
	arm := func(record RecordMode, flags uint8) {
		t.Helper()
		if err := runSet.Put(cgid, Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(record), Gen: gen, Flags: flags}); err != nil {
			t.Fatalf("arm: %v", err)
		}
		for _, m := range []*ebpf.Map{activity, lost} {
			if err := ZeroSlot(m, slot); err != nil {
				t.Fatal(err)
			}
		}
	}
	// onlySlot reads every slot of tego_activity and fails on any written other than slot, whose reading it returns.
	onlySlot := func(t *testing.T) uint64 {
		t.Helper()
		var got uint64
		for i := uint32(0); i < MaxSlots; i++ {
			v, err := ActivityAt(activity, i)
			if err != nil {
				t.Fatalf("read slot %d: %v", i, err)
			}
			if i == slot {
				got = v
			} else if v != 0 {
				t.Fatalf("slot %d of tego_activity was written (%d): only the run's own slot %d may be", i, v, slot)
			}
		}
		return got
	}

	for _, verb := range []string{"open", "mkdir", "mknod", "connect"} {
		t.Run("off-flagged/"+verb, func(t *testing.T) {
			arm(RecordOff, RunActivity)
			before := monoNow(t)
			helper.do(t, action(verb))
			after := monoNow(t)
			got := onlySlot(t)
			if got < before || got > after {
				t.Fatalf("the run's slot reads %d after an allowed %s under record: off, want a stamp in [%d, %d]",
					got, verb, before, after)
			}
			if l, err := SlotCount(lost, slot); err != nil || l != 0 {
				t.Fatalf("tego_lost[%d] = %d (%v): an allowed action under record: off touched the ring", slot, l, err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		record RecordMode
		flags  uint8
	}{
		{"off-unflagged", RecordOff, 0},
		{"off-listener-flag-only", RecordOff, RunListenerResults},
		{"summary-flagged", RecordSummary, RunActivity},
		{"full-flagged", RecordFull, RunActivity},
	} {
		for _, verb := range []string{"open", "mkdir", "mknod", "connect"} {
			t.Run(tc.name+"/"+verb, func(t *testing.T) {
				arm(tc.record, tc.flags)
				helper.do(t, action(verb))
				if got := onlySlot(t); got != 0 {
					t.Fatalf("the run's slot reads %d after an allowed %s (record %d, flags %#x): trace_proc stamps only a "+
						"flagged run under record: off", got, verb, tc.record, tc.flags)
				}
			})
		}
	}
	// Actions of a process outside the run set stamp nothing, whatever the run's row says.
	t.Run("not-a-run", func(t *testing.T) {
		arm(RecordOff, RunActivity)
		if f, err := os.Open(file); err == nil {
			_ = f.Close()
		}
		if got := onlySlot(t); got != 0 {
			t.Fatalf("an open by a process of no run stamped the run's slot: %d", got)
		}
	})
}

// TestActivityStampCost is the stamp's cost on the open path (record-off plan §5's budget): tego_file_open's own
// run time, from the kernel's BPF run-time statistics, for a record: off run whose row carries RunActivity against
// one whose row does not, the two alternated over 9 rounds of 200,000 opens by a process of the run, each read as
// its best round. The program's run time is what the stamp adds to (a flag test, an inlined array lookup,
// bpf_jiffies64 and a compare, the clock read and two stores once a jiffy): the trampoline around it is the same
// either way, so this is the stamp's cost per open without the open loop's noise. Target +25 ns, and +40 ns below
// 6.2 (6.1, 5.14), with TARGET-MISS above it; the test fails only past 100 ns, a stamp that is no longer what the
// source says it is.
func TestActivityStampCost(t *testing.T) {
	requireBPF(t)
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Skipf("BPF run-time statistics are not available here: %v", err)
	}
	defer stats.Close()
	const slot, gen, opens, rounds = 12, 4343, 200000, 9
	spec, err := Load(ObjectTraceProc)
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != ProgFileOpen {
			delete(spec.Programs, name)
		}
	}
	unpin(spec)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load %s: %v", ObjectTraceProc, err)
	}
	defer coll.Close()
	prog := coll.Programs[ProgFileOpen]
	l, err := AttachTrace(ProgFileOpen, prog)
	if err != nil {
		t.Fatalf("attach %s: %v", ProgFileOpen, err)
	}
	defer l.Close()
	base, err := os.MkdirTemp("/tmp", "eyc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	file := filepath.Join(base, "read-me")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, cgfd, cgid := planeChildCgroup(t, "activity-cost")
	helper := startActivityHelper(t, cgfd)
	runSet := coll.Maps[MapRunSet]
	t.Cleanup(func() { _ = runSet.Delete(cgid) })
	perRun := func(flags uint8) float64 {
		t.Helper()
		if err := runSet.Put(cgid, Run{RunIdx: slot, Descendants: 1, Tier: 2, Record: uint8(RecordOff), Gen: gen, Flags: flags}); err != nil {
			t.Fatal(err)
		}
		before, err := prog.Stats()
		if err != nil {
			t.Fatalf("program statistics: %v", err)
		}
		helper.do(t, "openloop "+file+" "+strconv.Itoa(opens))
		after, err := prog.Stats()
		if err != nil {
			t.Fatal(err)
		}
		n := after.RunCount - before.RunCount
		if n < opens {
			t.Fatalf("%s ran %d times for %d opens", ProgFileOpen, n, opens)
		}
		return float64(after.Runtime-before.Runtime) / float64(n)
	}
	best := map[uint8]float64{}
	for round := range rounds {
		order := []uint8{0, RunActivity}
		if round%2 == 1 {
			order = []uint8{RunActivity, 0}
		}
		for _, flags := range order {
			ns := perRun(flags)
			if b, ok := best[flags]; !ok || ns < b {
				best[flags] = ns
			}
		}
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	var major, minor int
	_, _ = fmt.Sscanf(release, "%d.%d", &major, &minor)
	target := 25.0
	if major < 6 || major == 6 && minor < 2 {
		target = 40
	}
	delta := best[RunActivity] - best[0]
	t.Logf("%s under record: off on %s: %.1f ns a run without the stamp, %.1f ns with it: %+.1f ns an open "+
		"(target %.0f ns; best of %d rounds of %d opens)", ProgFileOpen, release, best[0], best[RunActivity], delta, target,
		rounds, opens)
	if delta > target {
		t.Logf("TARGET-MISS open.activity_stamp_ns %.1f over its target %.0f on %s", delta, target, release)
	}
	if delta > 100 {
		t.Errorf("the activity stamp costs %+.1f ns an open, over the 100 ns limit", delta)
	}
}
