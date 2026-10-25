// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	enforcecg "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
)

// The plane's exec pin cell, plane.exec_pin (ADR 0048 (7)). Once a mode's known answers all matched, doctor fills
// their slot again, at the next gen, as Prepare fills a pinned run's (enforce/cgroup ProbeRows.FillPinned: a key of
// doctor's own, the pin flag and doctor's pid namespace in the header; the slot's maps, its pin map included, were
// made by the known answers' preload, off the probe's path), starts one gate per try into a scratch
// cgroup of its own, arms that cgroup as the slot's run, and has each gate exec under the pin doctor wrote for it, or
// none. A gate is a static image that says it is ready, waits for one byte on its stdin, then makes
// execveat(4, "", argv[1:], envp, AT_EMPTY_PATH): descriptor 4 is the try's target, so the exec's spelling is
// "/dev/fd/4", and an exec the kernel refuses ends the gate with the errno as its status. The target is the probe, a
// static image whose first instruction writes one byte to descriptor 3 (a pipe doctor reads) and which then waits for
// its stdin to end, or a #! script whose interpreter is the probe, spelled /proc/self/fd/5. The answers are (7)'s:
//
//  1. a pinned exec of identical facts runs (the byte arrives, status 0);
//  2. an exec with no pin is refused EACCES;
//  3. a pin whose covered vector differs is killed with SIGKILL before the probe's first instruction (the pipe stays
//     empty);
//  4. a pin whose image identity differs is refused EACCES;
//  5. a pin whose interpreter identity differs is refused EACCES at the interpreter's stage, while the same script
//     under its interpreter's identity runs;
//  6. a guarded exec doctor traces (PTRACE_SEIZE) is refused EACCES, for a k = 1 dashed-form vector and a long one;
//  7. process_vm_writev from a peer in the run into a running guarded probe is refused, into the long vector and into
//     argv[0] of a k = 1 probe, while the same write into an unguarded probe passes (process_vm_writev reports the
//     hook's EACCES as EPERM, as it does every refusal of its access check, so the control is what ties the refusal
//     to the guard);
//  8. the start time doctor reads from /proc is the plane's: answer 1 found its pin by it, and no time namespace
//     offsets the boottime of a launcher's children (enforce/cgroup BootOffsetZero, Prepare's own check).
//
// A cell that fails any answer is the mode's "pins off": no run of it claims that the kernel holds its execs.

const (
	// planePinGen is the cell's gen of the known answers' slot: the rows of their gens read as absent.
	planePinGen = planeKnownGen + 1
	// The cell's memfd names: the kernel's dentry name is "memfd:" and the name, which a pin's name MAC covers.
	planePinGateName   = "tego-pin-gate"
	planePinProbeName  = "tego-pin-probe"
	planePinScriptName = "tego-pin-script"
	// planePinWriterRole is the writer child's role (planePinWriterMain).
	planePinWriterRole = "pin-writer"
	// planePinRan and planePinKilled are a try's outcomes besides planeRefused.
	planePinRan    = "ran"
	planePinKilled = "killed"
	// planePinLongArgs is how many 49-byte arguments the long vector carries: about 100 KiB, below execpin.MaxArea.
	planePinLongArgs = 2000
	// planePinInterp is the script's interpreter: the probe, the gate's descriptor 5.
	planePinInterp = "/proc/self/fd/5"
	// planePinFilename is bprm->filename of every try: execveat of descriptor 4 with AT_EMPTY_PATH.
	planePinFilename = "/dev/fd/4"
)

// planePinGateImage is the gate (x86-64): write(1, "r", 1); read(0, sp-8, 1);
// execveat(4, "", argv+1, envp, AT_EMPTY_PATH); exit(-result). nil on another architecture.
func planePinGateImage() []byte {
	if runtime.GOARCH != "amd64" {
		return nil
	}
	return planePinELF([]byte{
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
		0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
		0x48, 0x8d, 0x35, 0x49, 0x00, 0x00, 0x00, // lea rsi, [rip+73]: the 'r' after the code
		0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
		0x0f, 0x05, // syscall: ready
		0x31, 0xc0, // xor eax, eax (read)
		0x31, 0xff, // xor edi, edi
		0x48, 0x8d, 0x74, 0x24, 0xf8, // lea rsi, [rsp-8]
		0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
		0x0f, 0x05, // syscall: the go-ahead
		0xb8, 0x42, 0x01, 0x00, 0x00, // mov eax, 322 (execveat)
		0xbf, 0x04, 0x00, 0x00, 0x00, // mov edi, 4
		0x48, 0x8d, 0x35, 0x22, 0x00, 0x00, 0x00, // lea rsi, [rip+34]: the "" after the 'r'
		0x48, 0x8d, 0x54, 0x24, 0x10, // lea rdx, [rsp+16]: argv+1
		0x48, 0x8b, 0x0c, 0x24, // mov rcx, [rsp]: argc
		0x4c, 0x8d, 0x54, 0xcc, 0x10, // lea r10, [rsp+rcx*8+16]: envp
		0x41, 0xb8, 0x00, 0x10, 0x00, 0x00, // mov r8d, 0x1000 (AT_EMPTY_PATH)
		0x0f, 0x05, // syscall
		0x89, 0xc7, // mov edi, eax
		0xf7, 0xdf, // neg edi: the errno
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
		0x0f, 0x05, // syscall
		'r', 0,
	})
}

// planePinProbeImage is the probe (x86-64): write(3, "x", 1) as its first instruction's syscall; read(0, sp-8, 1);
// exit(0). nil on another architecture.
func planePinProbeImage() []byte {
	if runtime.GOARCH != "amd64" {
		return nil
	}
	return planePinELF([]byte{
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
		0xbf, 0x03, 0x00, 0x00, 0x00, // mov edi, 3
		0x48, 0x8d, 0x35, 0x20, 0x00, 0x00, 0x00, // lea rsi, [rip+32]: the 'x' after the code
		0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
		0x0f, 0x05, // syscall
		0x31, 0xc0, // xor eax, eax (read)
		0x31, 0xff, // xor edi, edi
		0x48, 0x8d, 0x74, 0x24, 0xf8, // lea rsi, [rsp-8]
		0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
		0x0f, 0x05, // syscall: until stdin ends
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
		0x31, 0xff, // xor edi, edi
		0x0f, 0x05, // syscall
		'x',
	})
}

// planePinELF is a static ELF64 x86-64 executable of code: one PT_LOAD maps the whole file read and execute at
// 0x400000, and the entry is right after the two headers.
func planePinELF(code []byte) []byte {
	const ehdr, phdr, base = 64, 56, 0x400000
	size := uint64(ehdr + phdr + len(code))
	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	for _, v := range []any{
		uint16(2), uint16(0x3e), uint32(1), uint64(base + ehdr + phdr), uint64(ehdr), uint64(0), uint32(0),
		uint16(ehdr), uint16(phdr), uint16(1), uint16(0), uint16(0), uint16(0),
		uint32(1), uint32(5), uint64(0), uint64(base), uint64(base), size, size, uint64(0x1000),
	} {
		_ = binary.Write(&b, binary.LittleEndian, v)
	}
	b.Write(code)
	return b.Bytes()
}

// planePinMemfd is a close-on-exec memfd named name that holds b, executable where vm.memfd_noexec would seal it.
func planePinMemfd(name string, b []byte) (*sys.FD, error) {
	const mfdExec = 0x10 // MFD_EXEC, 6.3+; older kernels refuse the flag
	fd, err := sys.Own(unix.MemfdCreate(name, unix.MFD_CLOEXEC|mfdExec))
	if errors.Is(err, unix.EINVAL) {
		fd, err = sys.Own(unix.MemfdCreate(name, unix.MFD_CLOEXEC))
	}
	if err != nil {
		return nil, fmt.Errorf("memfd %s: %w", name, err)
	}
	if err := fd.Borrow(func(n int) error {
		if w, err := unix.Write(n, b); err != nil || w != len(b) {
			return fmt.Errorf("%d of %d bytes: %w", w, len(b), err)
		}
		return nil
	}); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("write memfd %s: %w", name, err)
	}
	return fd, nil
}

// planePinIdent is fd's file's identity as a pin holds it: its super block's s_dev in the kernel's encoding, and its
// inode.
func planePinIdent(fd *sys.FD) (execpin.Ident, error) {
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return execpin.Ident{}, err
	}
	return execpin.Ident{Dev: execpin.KernelDev(unix.Major(st.Dev), unix.Minor(st.Dev)), Ino: st.Ino}, nil
}

// planePinTry is one exec of the cell: the gate's target (the script or the probe at descriptor 4) and vector, the
// pin doctor writes for it (none when nil), whether doctor traces the gate, whether the writer writes into the
// running probe, and the outcome (7) wants.
type planePinTry struct {
	answer int
	name   string
	script bool
	argv   []string
	pin    *execpin.Exec
	trace  bool
	write  bool
	want   string
}

// planePinLongVector is the long vector: the probe's name and planePinLongArgs arguments of 48 bytes each.
func planePinLongVector() []string {
	v := []string{planePinProbeName}
	for i := range planePinLongArgs {
		v = append(v, fmt.Sprintf("%048d", i))
	}
	return v
}

// planePinTries is the cell's tries, in (7)'s order, for the probe's and the script's identities.
func planePinTries(probe, script execpin.Ident) []planePinTry {
	probeName, scriptName := "memfd:"+planePinProbeName, "memfd:"+planePinScriptName
	whole := func(argv []string, id execpin.Ident, guard bool) *execpin.Exec {
		return &execpin.Exec{Form: execpin.FormDirect, Guard: guard, Image: id, Name: probeName,
			Filename: planePinFilename, Argv: argv, Complete: true, K: len(argv)}
	}
	interp := func(id execpin.Ident) *execpin.Exec {
		return &execpin.Exec{Form: execpin.FormScript, Image: script, Name: scriptName, Filename: planePinFilename,
			Argv: []string{planePinScriptName}, Complete: true, Chain: []execpin.Stage{{Path: planePinInterp, ID: id}}}
	}
	vec, other := []string{planePinProbeName, "a"}, probe
	other.Ino++
	dashed, long := []string{"git-status"}, planePinLongVector()
	k1 := &execpin.Exec{Form: execpin.FormDirect, Guard: true, Image: probe, Name: probeName, Filename: planePinFilename,
		Argv: dashed, K: 1}
	written, control := planePinRan+"; write "+planeRefused, planePinRan+"; write "+planePassed
	return []planePinTry{
		{answer: 1, name: "pinned", argv: vec, pin: whole(vec, probe, false), want: planePinRan},
		{answer: 2, name: "no pin", argv: vec, want: planeRefused},
		{answer: 3, name: "covered vector differs", argv: []string{planePinProbeName, "b"}, pin: whole(vec, probe, false),
			want: planePinKilled},
		{answer: 4, name: "image differs", argv: vec, pin: whole(vec, other, false), want: planeRefused},
		{answer: 5, name: "script", script: true, argv: []string{planePinScriptName}, pin: interp(probe), want: planePinRan},
		{answer: 5, name: "interpreter differs", script: true, argv: []string{planePinScriptName}, pin: interp(other),
			want: planeRefused},
		{answer: 6, name: "traced k = 1 dashed form", argv: dashed, pin: k1, trace: true, want: planeRefused},
		{answer: 6, name: "traced long vector", argv: long, pin: whole(long, probe, true), trace: true, want: planeRefused},
		{answer: 7, name: "unguarded probe written", argv: vec, pin: whole(vec, probe, false), write: true, want: control},
		{answer: 7, name: "guarded long vector written", argv: long, pin: whole(long, probe, true), write: true, want: written},
		{answer: 7, name: "guarded k = 1 argv[0] written", argv: dashed, pin: k1, write: true, want: written},
	}
}

// planePinGate is one started gate: its process, its stdin (the go-ahead, then the probe's wait), and the read end of
// the probe's descriptor 3.
type planePinGate struct {
	cmd     *proc.Cmd
	stdin   *os.File
	mark    *os.File
	done    chan struct{} // closed once Wait has returned; waitErr then holds its error
	waitErr error
	ended   bool
}

// startPinGate starts a gate in cg (in this process's cgroup when nil) whose descriptor 3 is a fresh pipe, 4 is
// target and 5 is probe, with argv as its argv[1:], and waits until it says ready. The gate's own exec happens before
// the cell arms cg, from its descriptor 6, a duplicate of gate: the child's descriptors are its ExtraFiles by then.
func startPinGate(cg *planeCgroup, gate, target, probe *sys.FD, argv []string) (g *planePinGate, err error) {
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()
	pipe := func() (r, w *os.File, err error) {
		if r, w, err = os.Pipe(); err == nil {
			closers = append(closers, w)
		}
		return r, w, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	closers = append(closers, inR)
	outR, outW, err := pipe()
	if err != nil {
		_ = inW.Close()
		return nil, err
	}
	defer func() { _ = outR.Close() }()
	markR, markW, err := pipe()
	if err != nil {
		_ = inW.Close()
		return nil, err
	}
	files := []*os.File{markW}
	for _, fd := range []*sys.FD{target, probe, gate} {
		dup, err := fd.Dup()
		var f *os.File
		if err == nil {
			f, err = dup.Release("pin-image")
		}
		if err != nil {
			_ = inW.Close()
			_ = markR.Close()
			return nil, err
		}
		closers, files = append(closers, f), append(files, f)
	}
	cmd := proc.Command("/proc/self/fd/6", argv...)
	cmd.Args[0] = planePinGateName
	cmd.Stdin, cmd.Stdout, cmd.ExtraFiles = inR, outW, files
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if cg != nil {
		cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, cg.fd
	}
	if _, err := proc.Start(cmd); err != nil {
		_ = inW.Close()
		_ = markR.Close()
		return nil, fmt.Errorf("start a gate: %w", err)
	}
	g = &planePinGate{cmd: cmd, stdin: inW, mark: markR, done: make(chan struct{})}
	go func() { g.waitErr = cmd.Wait(); close(g.done) }()
	_ = outR.SetReadDeadline(time.Now().Add(planeProbeTimeout))
	b := make([]byte, 1)
	if n, err := outR.Read(b); n != 1 || b[0] != 'r' {
		g.stop()
		return nil, fmt.Errorf("the gate did not say ready: %q %v", b[:n], err)
	}
	return g, nil
}

// wait waits for the gate's process to end and returns its status.
func (g *planePinGate) wait() (syscall.WaitStatus, error) {
	select {
	case <-g.done:
	case <-time.After(planeProbeTimeout):
		g.stop()
		return 0, errors.New("the gate did not end")
	}
	g.ended = true
	// For a gate that exited or was signalled, Wait's error only restates the status read below. A Wait that
	// failed before it reaped the gate leaves no ProcessState, and its error is then the only answer.
	if g.cmd.ProcessState == nil {
		return 0, fmt.Errorf("wait for the gate: %w", g.waitErr)
	}
	ws, _ := g.cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ws, nil
}

// stop kills a gate that has not ended and releases its pipes.
func (g *planePinGate) stop() {
	if !g.ended {
		_ = g.cmd.Process.Kill()
		<-g.done
		g.ended = true
	}
	_ = g.stdin.Close()
	_ = g.mark.Close()
}

// planePinStat reads pid's start time (field 22 of /proc/<pid>/stat, in clock ticks) and arg_start (field 48).
func planePinStat(pid int) (start, argStart uint64, err error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, 0, fmt.Errorf("/proc/%d/stat: no command", pid)
	}
	f := strings.Fields(string(b[i+1:])) // f[0] is field 3
	if len(f) < 46 {
		return 0, 0, fmt.Errorf("/proc/%d/stat: %d fields", pid, len(f)+2)
	}
	if start, err = strconv.ParseUint(f[19], 10, 64); err != nil {
		return 0, 0, err
	}
	argStart, err = strconv.ParseUint(f[45], 10, 64)
	return start, argStart, err
}

// planePinCell is one mode's cell while it runs.
type planePinCell struct {
	rows   *enforcecg.ProbeRows
	slot   uint32
	key    execpin.Key
	seq    uint32
	writer *planeChild
}

// try runs one try on its gate and returns its outcome. An error is a try that could not run to its end.
func (c *planePinCell) try(t planePinTry, g *planePinGate) (string, error) {
	pid := g.cmd.Process.Pid
	if t.pin != nil {
		start, _, err := planePinStat(pid)
		if err != nil {
			return "", err
		}
		p, err := execpin.Build(c.key, *t.pin)
		if err != nil {
			return "", err
		}
		c.seq++
		if err := c.rows.PutPin(c.slot, planePinGen, c.seq, uint32(pid), start, p.Encode()); err != nil {
			return "", err
		}
	}
	if t.trace {
		// The tracer is this thread until the gate ends; with PTRACE_SEIZE an exec that passes stops nothing.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := unix.PtraceSeize(pid); err != nil {
			return "", fmt.Errorf("PTRACE_SEIZE the gate: %w", err)
		}
	}
	if _, err := g.stdin.Write([]byte{'g'}); err != nil {
		return "", fmt.Errorf("the gate's go-ahead: %w", err)
	}
	var mark []byte
	wrote := ""
	if t.write {
		_ = g.mark.SetReadDeadline(time.Now().Add(planeProbeTimeout))
		b := make([]byte, 1)
		n, _ := g.mark.Read(b)
		if mark = b[:n]; n == 1 {
			_, arg, err := planePinStat(pid)
			if err != nil {
				return "", err
			}
			res, err := c.writer.ask("write " + strconv.Itoa(pid) + " " + strconv.FormatUint(arg, 10))
			if err != nil {
				return "", err
			}
			wrote = "; write " + res
		}
		_ = g.mark.SetReadDeadline(time.Time{})
	}
	_ = g.stdin.Close()
	ws, err := g.wait()
	if err != nil {
		return "", err
	}
	_ = g.mark.SetReadDeadline(time.Now().Add(planeProbeTimeout))
	rest, _ := io.ReadAll(g.mark)
	mark = append(mark, rest...)
	switch {
	case ws.Exited() && ws.ExitStatus() == 0 && string(mark) == "x":
		return planePinRan + wrote, nil
	case ws.Exited() && ws.ExitStatus() == int(unix.EACCES) && len(mark) == 0:
		return planeRefused + wrote, nil
	case ws.Signaled() && ws.Signal() == syscall.SIGKILL && len(mark) == 0:
		return planePinKilled + wrote, nil
	}
	return fmt.Sprintf("status %#x, the probe wrote %q%s", int(ws), mark, wrote), nil
}

// exercisePlaneExecPin runs mode m's exec pin cell on an attached rig whose maps are known's, after its known answers
// matched. The cell is nil with an error when it could not run to its end; otherwise it says whether every answer
// held, and the first that did not.
func exercisePlaneExecPin(rig *planeRig, known *planeKnownRows, uid int) (cell *PlaneExecPinCell, err error) {
	gateImg, probeImg := planePinGateImage(), planePinProbeImage()
	switch {
	case gateImg == nil:
		return &PlaneExecPinCell{Detail: "the cell's gate and probe are x86-64 code; this is " + runtime.GOARCH}, nil
	case rig.execPinWhy != "":
		return &PlaneExecPinCell{Detail: rig.execPinWhy}, nil
	}
	if err := enforcecg.BootOffsetZero(); err != nil {
		return &PlaneExecPinCell{Detail: "8 (time namespace): " + err.Error()}, nil
	}
	c := &planePinCell{rows: known.rows, slot: planeKnownSlot(rig.mode)}
	if _, err := unix.Getrandom(c.key[:], 0); err != nil {
		return nil, fmt.Errorf("exec pin cell: getrandom: %w", err)
	}
	// The slot's table is one read-deny row on a directory of doctor's that nothing opens.
	base, err := makeFixtureDir(planeScratchPrefix)
	if err != nil {
		return nil, fmt.Errorf("exec pin cell: fixtures: %w", err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	deny := filepath.Join(base, "pd")
	if err := os.Mkdir(deny, 0o700); err != nil {
		return nil, fmt.Errorf("exec pin cell: fixtures: %w", err)
	}
	table := &decide.PlaneRows{FS: []decide.PlaneRow{{Path: deny, Kind: decide.PlaneReadDeny}}}
	held := planeKnownHeld{}
	defer held.close()
	if err := held.open(table); err != nil {
		return nil, fmt.Errorf("exec pin cell: %w", err)
	}
	if err := c.rows.FillPinned(c.slot, planePinGen, table, held.held, c.key); err != nil {
		return nil, fmt.Errorf("exec pin cell: fill slot %d: %w", c.slot, err)
	}
	var fds []*sys.FD
	defer func() {
		for _, fd := range fds {
			_ = fd.Close()
		}
	}()
	for _, img := range []struct {
		name string
		b    []byte
	}{{planePinGateName, gateImg}, {planePinProbeName, probeImg}, {planePinScriptName, []byte("#!" + planePinInterp + "\n")}} {
		fd, err := planePinMemfd(img.name, img.b)
		if err != nil {
			return nil, fmt.Errorf("exec pin cell: %w", err)
		}
		fds = append(fds, fd)
	}
	gate, probe, script := fds[0], fds[1], fds[2]
	probeID, err := planePinIdent(probe)
	if err != nil {
		return nil, fmt.Errorf("exec pin cell: %w", err)
	}
	scriptID, err := planePinIdent(script)
	if err != nil {
		return nil, fmt.Errorf("exec pin cell: %w", err)
	}
	cg, err := newPlaneCgroup(uid)
	if err != nil {
		return nil, fmt.Errorf("exec pin cell: scratch cgroup: %w", err)
	}
	defer cg.remove()
	// Every process of the cell execs into cg before it is armed: an exec once it is would need a pin.
	tries := planePinTries(probeID, scriptID)
	type started struct {
		c   *planeChild
		err error
	}
	writer := make(chan started, 1)
	go func() {
		c, err := startPlaneChildAs(cg, planePinWriterRole, "-", -1)
		writer <- started{c, err}
	}()
	// The gates start side by side: each start waits for its gate to say ready.
	gates, gateErrs := make([]*planePinGate, len(tries)), make([]error, len(tries))
	var wg sync.WaitGroup
	for i, t := range tries {
		target := probe
		if t.script {
			target = script
		}
		wg.Go(func() { gates[i], gateErrs[i] = startPinGate(cg, gate, target, probe, t.argv) })
	}
	wg.Wait()
	defer func() {
		for _, g := range gates {
			if g != nil {
				g.stop()
			}
		}
	}()
	if err := errors.Join(gateErrs...); err != nil {
		if w := <-writer; w.c != nil {
			w.c.stop()
		}
		return nil, fmt.Errorf("exec pin cell: %w", err)
	}
	w := <-writer
	if w.err != nil {
		return nil, fmt.Errorf("exec pin cell: %w", w.err)
	}
	c.writer = w.c
	defer c.writer.stop()
	if err := rig.runSet.Put(cg.id, bpfobj.Run{RunIdx: c.slot, Tier: 3, Plane: bpfobj.RunPlaneOf(rig.mode), Gen: planePinGen}); err != nil {
		return nil, fmt.Errorf("exec pin cell: arm slot %d: %w", c.slot, err)
	}
	defer func() {
		if derr := rig.runSet.Delete(cg.id); derr != nil && err == nil {
			cell, err = nil, fmt.Errorf("exec pin cell: disarm slot %d: %w", c.slot, derr)
		}
	}()
	for i, t := range tries {
		got, err := c.try(t, gates[i])
		if err != nil {
			return nil, fmt.Errorf("exec pin cell: answer %d (%s): %w", t.answer, t.name, err)
		}
		if got != t.want {
			return &PlaneExecPinCell{Detail: fmt.Sprintf("answer %d (%s): %s, want %s", t.answer, t.name, got, t.want)}, nil
		}
	}
	return &PlaneExecPinCell{OK: true}, nil
}

// planePinWriterMain is the cell's writer, `tego __doctor-plane-probe pin-writer -`: a peer in the cell's run that,
// for each line "write <pid> <addr>", writes one byte at addr in pid with process_vm_writev and prints the line, a
// tab and the outcome, until its input ends.
func planePinWriterMain() int {
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		return 1
	}
	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadString('\n')
		if errors.Is(err, io.EOF) && line == "" {
			return 0
		}
		if err != nil {
			return 1
		}
		line = strings.TrimSuffix(line, "\n")
		out := "failed: not write <pid> <addr>"
		if f := strings.Fields(line); len(f) == 3 && f[0] == "write" {
			pid, perr := strconv.Atoi(f[1])
			addr, aerr := strconv.ParseUint(f[2], 10, 64)
			if perr == nil && aerr == nil {
				b := []byte{'y'}
				local := []unix.Iovec{{Base: &b[0]}}
				local[0].SetLen(1)
				_, err := unix.ProcessVMWritev(pid, local, []unix.RemoteIovec{{Base: uintptr(addr), Len: 1}}, 0)
				if errors.Is(err, unix.EPERM) {
					// mm/process_vm_access.c maps mm_access's EACCES, a refused access check, to EPERM.
					err = unix.EACCES
				}
				out = planeOutcome(err)
			}
		}
		if _, err := os.Stdout.WriteString(line + "\t" + out + "\n"); err != nil {
			return 1
		}
	}
}
