// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// pinIdentOf is a file's identity as the plane holds it, read as the supervisor reads it (ADR 0048 (3) "Pin value"):
// fdinfo's ino of an O_PATH descriptor of p (symlinks followed) and its mount's device from mountinfo, in the kernel's
// encoding; and the file's final name.
func pinIdentOf(t *testing.T, p string) (execpin.Ident, string) {
	t.Helper()
	fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this test opened
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	var mnt, ino string
	for _, line := range strings.Split(string(info), "\n") {
		k, v, _ := strings.Cut(line, ":")
		switch k {
		case "mnt_id":
			mnt = strings.TrimSpace(v)
		case "ino":
			ino = strings.TrimSpace(v)
		}
	}
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(bytes.NewReader(mi))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[0] != mnt {
			continue
		}
		maj, min, _ := strings.Cut(f[2], ":")
		a, _ := strconv.ParseUint(maj, 10, 32)
		b, _ := strconv.ParseUint(min, 10, 32)
		i, err := strconv.ParseUint(ino, 10, 64)
		if err != nil {
			t.Fatalf("fdinfo of %s: %q", p, info)
		}
		return execpin.Ident{Dev: execpin.KernelDev(uint32(a), uint32(b)), Ino: i}, filepath.Base(link)
	}
	t.Fatalf("mount %s of %s is not in mountinfo", mnt, p)
	return execpin.Ident{}, ""
}

// pinSample is one plane sample of a pinned exec: a bprm_check refusal (KindPlaneExec), a kill (KindPlaneExecKill) or
// the held sample (KindPlaneExecHeld) the ledger's fold reads as kernel_pinned (ADR 0048 (8)).
type pinSample struct {
	kind   ebpfbindings.Kind
	reason ebpfbindings.ReasonCode
}

// pinSamples drains the run's ring of the plane's exec refusals, kills and held samples of cgroup id.
func pinSamples(rd *ringbuf.Reader, id uint64) []pinSample {
	var out []pinSample
	rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		rec, err := rd.Read()
		if err != nil {
			return out
		}
		hdr, err := ebpfbindings.DecodeHeader(rec.RawSample)
		if err != nil || hdr.CgroupID != id {
			continue
		}
		if k := ebpfbindings.Kind(hdr.Kind); k == ebpfbindings.KindPlaneExec || k == ebpfbindings.KindPlaneExecKill || k == ebpfbindings.KindPlaneExecHeld {
			out = append(out, pinSample{k, ebpfbindings.ReasonCode(hdr.Reason)})
		}
	}
}

// procStart is /proc/<pid>/stat's start time, in clock ticks.
func procStart(t *testing.T, pid int) uint64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return start
}

// TestPlaneExecPinsOnRealKernel is ADR 0048 (3) P2 through the backend: a run Prepare pins has its slot's key, pin map
// and header written, and the plane holds each exec of the run to the pin the supervisor's half wrote for it
// (execpin.Build, Handle.PinExec). A shell started outside the run is moved into it and then execs: with the pin of
// that exec it runs, and the plane says so with its held sample; with no pin, or a pin of another image, bprm_check
// refuses it (EACCES, the shell's 126); with a
// pin whose argv[0] differs, sched_process_exec kills it before its first instruction (SIGKILL); a #! script runs
// under a script pin that names its interpreter's file and binfmt_script's vector, and is refused under one that names
// another interpreter.
func TestPlaneExecPinsOnRealKernel(t *testing.T) {
	requireBPFCaps(t)
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects: %v", err)
	}
	mode, build := hostPlane(t)
	base, err := os.MkdirTemp("", "eyp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	script := filepath.Join(base, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{},
		FS: []agent.FSRule{{Path: base, Kind: agent.FSWrite, Resolved: base}}}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("p2pins%09d", os.Getpid())
	b := New(Options{Machine: machineLinger(0), BPFFS: DefaultBPFFS, StateDir: pinState(t), Hash: hash,
		Events: &sink{}, Plane: PlaneSetup{Mode: mode, Build: build}})
	b.opts.planeHeld = holdPaths(t, rows.Keyed...).held
	t.Cleanup(func() {
		if pins, err := newPinLayout(DefaultBPFFS, hash); err == nil {
			_ = pins.remove()
		}
	})
	rel, _, id := runCgroupUnderSelf(t, "pins")
	h, err := b.Prepare(context.Background(), rt, Run{ID: "p2-pins", Agent: "a", CgroupID: id, CgroupPath: rel,
		CgroupMount: "/sys/fs/cgroup", PlaneRows: rows, ExecPin: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	key, ok := h.ExecPins()
	if !ok && !h.ExecOutcomes() {
		t.Skipf("this kernel's recorder has no exec outcomes (sys_exit_execve and sys_exit_execveat), so Prepare pins no " +
			"run here: a kill would have no line (ADR 0048 K4)")
	}
	if !ok {
		t.Fatalf("a run asked to be pinned on a %s plane is not pinned", mode)
	}
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	runDir := filepath.Join("/sys/fs/cgroup", rel)
	rd, err := ringbuf.NewReader(runRing(t, h))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rd.Close() })
	trueID, trueName := pinIdentOf(t, "/usr/bin/true")
	shID, _ := pinIdentOf(t, "/bin/sh")
	scriptID, scriptName := pinIdentOf(t, script)
	direct := func(argv0 string, id execpin.Ident) *execpin.Exec {
		return &execpin.Exec{Form: execpin.FormDirect, Image: id, Name: trueName, Filename: "/usr/bin/true",
			Argv: []string{argv0}, K: 1}
	}
	scriptPin := func(interp execpin.Ident) *execpin.Exec {
		return &execpin.Exec{Form: execpin.FormScript, Image: scriptID, Name: scriptName, Filename: script,
			Argv: []string{script}, Complete: true, Chain: []execpin.Stage{{Path: "/bin/sh", ID: interp}}}
	}
	wrongID := trueID
	wrongID.Ino++
	cells := []struct {
		name   string
		target string
		pin    *execpin.Exec
		code   int // the exit status, or -1 for SIGKILL
		sample []pinSample
	}{
		{"pinned", "/usr/bin/true x", direct("/usr/bin/true", trueID), 0, []pinSample{{ebpfbindings.KindPlaneExecHeld, 0}}},
		{"no pin", "/usr/bin/true x", nil, 126, []pinSample{{ebpfbindings.KindPlaneExec, ebpfbindings.ReasonPinMissing}}},
		{"another image", "/usr/bin/true x", direct("/usr/bin/true", wrongID), 126,
			[]pinSample{{ebpfbindings.KindPlaneExec, ebpfbindings.ReasonPinMismatch}}},
		{"argv0 changed", "/usr/bin/true x", direct("/usr/bin/false", trueID), -1,
			[]pinSample{{ebpfbindings.KindPlaneExecKill, ebpfbindings.ReasonArgvChanged}}},
		{"script", script, scriptPin(shID), 3, []pinSample{{ebpfbindings.KindPlaneExecHeld, 0}}},
		{"another interpreter", script, scriptPin(trueID), 126,
			[]pinSample{{ebpfbindings.KindPlaneExec, ebpfbindings.ReasonPinMismatch}}},
	}
	// Each cell runs pinRounds times, interleaved, so an outcome that holds only some of the time fails the test.
	for round := range pinRounds {
		for _, c := range cells {
			pinCell(t, fmt.Sprintf("%s/%d", c.name, round), h, key, rd, id, runDir, c.target, c.pin, c.code, c.sample)
		}
	}
	counts, err := h.plane.counts(h.slot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("slot counters after the cells: %+v", counts)
}

// pinRounds is how often TestPlaneExecPinsOnRealKernel runs each cell.
const pinRounds = 20

// pinCell starts a shell outside the run, moves it into the run's cgroup, writes the pin (if any) of the exec it is
// about to make, lets it exec target, and checks the exec's exit status (-1: SIGKILL) and the plane's samples.
func pinCell(t *testing.T, name string, h *Handle, key execpin.Key, rd *ringbuf.Reader, id uint64, runDir, target string,
	pin *execpin.Exec, want int, wantSamples []pinSample) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		cmd := exec.Command("/bin/sh", "-c", "read x; exec "+target)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		moveTask(t, runDir, pid)
		if pin != nil {
			p, err := execpin.Build(key, *pin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.PinExec(uint32(pid), procStart(t, pid), p.Encode()); err != nil {
				t.Fatalf("PinExec: %v", err)
			}
		}
		_, _ = stdin.Write([]byte("\n"))
		err = cmd.Wait()
		code := cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			if ws.Signal() != syscall.SIGKILL {
				t.Fatalf("killed by %v: %s", ws.Signal(), out.String())
			}
			code = -1
		}
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatal(err)
		}
		samples := pinSamples(rd, id)
		if code != want || !slices.Equal(samples, wantSamples) {
			t.Fatalf("exit %d with the plane's samples %+v, want %d and %+v (%s)", code, samples, want, wantSamples,
				strings.TrimSpace(out.String()))
		}
	})
}
