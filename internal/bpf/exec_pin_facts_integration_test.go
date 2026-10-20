// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/execpin"
)

// ADR 0048 P2's K0: the kernel facts exec pins rest on, measured on this kernel before any pin code relies on them,
// in each reader build of the probe (bpf/testonly/exec_pin_facts.bpf.c) this kernel loads and each plane mode it
// offers. Every cell is a fact the ADR's design states; a cell that fails decides the row's fallback (the pin flag
// off, the cell disclosed), never a weaker test.
//
// The probe's watched tasks are this test's children in a child cgroup. The exec target is pinFactsProbe, a static
// x86-64 program of two system calls whose first is write(3, "x", 1): a byte in the pipe on descriptor 3 means the
// program ran an instruction past the exec.

const (
	// pinFactsKills is K0's kill count per row: zero bpf_send_signal failures over this many kills.
	pinFactsKills = 10000
	// pinFactsEntry is the probe's entry point: its first instruction.
	pinFactsEntry = 0x400078
	// pinFactsTimensHelper names the helper this test binary becomes in a new time namespace.
	pinFactsTimensHelper = "TEGO_PIN_TIMENS_HELPER"
	// pinFactsClockTicks is USER_HZ, the unit of /proc/<pid>/stat's start time, on every architecture tego ships.
	pinFactsClockTicks = 100
	// pinFactsBoottimeOffset is the helper's time-namespace boottime offset, in seconds.
	pinFactsBoottimeOffset = 86400
)

func init() {
	target := os.Getenv(pinFactsTimensHelper)
	if target == "" {
		return
	}
	runtime.LockOSThread()
	os.Exit(pinFactsTimensMain(target))
}

// pinFactsTimensMain enters a new time namespace for its children with a boottime offset, then has /bin/cat print
// /proc/<target>/stat from inside it: the start time a supervisor in such a namespace would read.
func pinFactsTimensMain(target string) int {
	if err := unix.Unshare(unix.CLONE_NEWTIME); err != nil {
		fmt.Fprintln(os.Stderr, "unshare(CLONE_NEWTIME):", err)
		return 2
	}
	off := fmt.Sprintf("boottime %d 0\n", pinFactsBoottimeOffset)
	if err := os.WriteFile("/proc/self/timens_offsets", []byte(off), 0); err != nil {
		fmt.Fprintln(os.Stderr, "timens_offsets:", err)
		return 2
	}
	// A child that shares the parent's memory cannot enter another time namespace (copy_process: EINVAL for CLONE_VM
	// while time_ns differs from time_ns_for_children, as on 6.1), and Go forks with CLONE_VFORK|CLONE_VM unless the
	// child gets a new user namespace. cat needs no mapped id to read a world-readable stat file.
	cmd := exec.Command("/bin/cat", "/proc/"+target+"/stat")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER}
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cat:", err)
		return 2
	}
	_, _ = os.Stdout.Write(out)
	return 0
}

// pinFactsProbe is a static ELF64 x86-64 executable: write(3, "x", 1), then exit(0). One PT_LOAD maps the whole file
// at 0x400000 and the code starts right after the two headers.
func pinFactsProbe() []byte {
	code := []byte{
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
		0xbf, 0x03, 0x00, 0x00, 0x00, // mov edi, 3
		0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, // lea rsi, [rip+16] (the 'x' after the code)
		0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
		0x0f, 0x05, // syscall
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
		0x31, 0xff, // xor edi, edi
		0x0f, 0x05, // syscall
		'x',
	}
	const ehdr, phdr = 64, 56
	size := uint64(ehdr + phdr + len(code))
	var b bytes.Buffer
	le := binary.LittleEndian
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	for _, v := range []any{
		uint16(2), uint16(0x3e), uint32(1), uint64(pinFactsEntry), uint64(ehdr), uint64(0), uint32(0),
		uint16(ehdr), uint16(phdr), uint16(1), uint16(0), uint16(0), uint16(0),
		uint32(1), uint32(5), uint64(0), uint64(0x400000), uint64(0x400000), size, size, uint64(0x1000),
	} {
		_ = binary.Write(&b, le, v)
	}
	b.Write(code)
	return b.Bytes()
}

type pinFacts struct {
	t      *testing.T
	coll   *ebpf.Collection
	cgFD   int
	cgID   uint64
	key    execpin.Key
	nsDev  uint64
	nsIno  uint64
	probe  string
	pipeR  int
	pipeW  int
	nullFD int
}

// TestExecPinKernelFacts is K0 (ADR 0048, Implementation plan P2) on this kernel. Per reader build and plane mode:
//   - the probe's sched_process_exec, bprm_check and syscall programs load (verified instruction counts logged);
//   - the pin MAC in BPF equals internal/execpin.MAC on the 64 published SipHash vectors, in each domain;
//   - bpf_probe_read_user over [arg_start, arg_end) reads the vector the exec passed, the whole area or a covered
//     prefix, in chunks up to the 128 KiB bound, and an area past the bound is not read;
//   - each later binfmt stage reaches bprm_check with the interpreter's file, and only the first has interp ==
//     filename; the area after a two-stage #! chain is binfmt_script's vector;
//   - bpf_get_ns_current_pid_tgid in the mode's bprm_check answers the task's ids in the launcher's namespace, and
//     -EINVAL for a task in a child pid namespace;
//   - current->ptrace at bprm_check says PT_PTRACED for a traced exec only;
//   - current->start_boottime at bprm_check, in clock ticks, is /proc/<pid>/stat's start time read outside a time
//     namespace, and differs by the offset inside one with a boottime offset;
//   - bpf_send_signal(SIGKILL) from sched_process_exec kills before the probe's first instruction, with zero send
//     failures over pinFactsKills kills, and a traced exec killed there never lets its tracer PTRACE_POKEDATA.
func TestExecPinKernelFacts(t *testing.T) {
	requireBPF(t)
	if runtime.GOARCH != "amd64" {
		t.Skipf("the K0 probe program is x86-64 machine code; this is %s", runtime.GOARCH)
	}
	ran := 0
	for _, build := range []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
		o    Object
	}{{"rd", loadPinfactsrd, ObjectPlaneRdonly}, {"pr", loadPinfactspr, ObjectPlaneProbe}} {
		t.Run(build.name, func(t *testing.T) {
			if ok, why := pinFactsReaderUsable(build.o); !ok {
				t.Skip(why)
			}
			for _, mode := range PlaneModes {
				t.Run(string(mode), func(t *testing.T) {
					if ok, why := planeModeUsable(mode); !ok {
						t.Skip(why)
					}
					pinFactsCells(t, build.load, mode)
					ran++
				})
			}
		})
	}
	if ran == 0 {
		t.Fatal("no probe build ran in any mode on this kernel")
	}
}

// pinFactsReaderUsable is planeReaderUsable for the probe: its rd build makes only direct BTF loads (no
// bpf_rdonly_cast), so only the pr build's bpf_probe_read_kernel can be refused, by lockdown=confidentiality.
func pinFactsReaderUsable(o Object) (bool, string) {
	if o == ObjectPlaneProbe {
		if b, err := os.ReadFile("/sys/kernel/security/lockdown"); err == nil && strings.Contains(string(b), "[confidentiality]") {
			return false, "lockdown=confidentiality refuses bpf_probe_read_kernel"
		}
	}
	return true, ""
}

func pinFactsCells(t *testing.T, load func() (*ebpf.CollectionSpec, error), mode PlaneMode) {
	spec, err := load()
	if err != nil {
		t.Fatal(err)
	}
	bprm := "tego_pf_bprm_fmod"
	if mode == PlaneLSM {
		bprm = "tego_pf_bprm_lsm"
		delete(spec.Programs, "tego_pf_bprm_fmod")
	} else {
		delete(spec.Programs, "tego_pf_bprm_lsm")
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load: %+v", ve)
		}
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(coll.Close)
	for name, p := range coll.Programs {
		if info, err := p.Info(); err == nil {
			if n, ok := info.VerifiedInstructions(); ok {
				t.Logf("K0 %s/%s verified instructions: %d", mode, name, n)
			}
		}
	}
	for _, name := range []string{"tego_pf_exec_check", bprm} {
		var l link.Link
		if name == bprm && mode == PlaneLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: coll.Programs[name]})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
		}
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}

	f := &pinFacts{t: t, coll: coll}
	_, f.cgFD, f.cgID = planeChildCgroup(t, "pinfacts-"+string(mode))
	for i := range f.key {
		f.key[i] = byte(0xa0 + i)
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		t.Fatal(err)
	}
	// The helper compares dev with nsfs's super block s_dev, the kernel's dev_t (major << 20 | minor), not stat's
	// st_dev encoding; the two agree only for a minor below 256, as nsfs's anonymous device usually has.
	f.nsDev, f.nsIno = uint64(unix.Major(st.Dev))<<20|uint64(unix.Minor(st.Dev)), st.Ino
	f.probe = filepath.Join(t.TempDir(), "probe")
	mustWrite(t, f.probe, pinFactsProbe(), 0o755)
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	f.pipeR, f.pipeW = p[0], p[1]
	if f.nullFD, err = unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(f.pipeR); _ = unix.Close(f.pipeW); _ = unix.Close(f.nullFD) })

	t.Run("siphash-vectors", f.sipVectors)
	t.Run("argv-area", f.argvArea)
	t.Run("binfmt-stages", f.stages)
	t.Run("pid-namespace", f.pidNamespace)
	t.Run("ptrace-flag", f.ptraceFlag)
	t.Run("start-time", f.startTime)
	t.Run("kill-before-first-instruction", f.kills)
	t.Run("traced-kill", f.tracedKill)
}

// configure writes the probe's config and zeroes its counters and records.
func (f *pinFacts) configure(cfg pinfactsrdTegoPfCfg) {
	f.t.Helper()
	cfg.Cgroup = f.cgID
	cfg.K0 = binary.LittleEndian.Uint64(f.key[0:8])
	cfg.K1 = binary.LittleEndian.Uint64(f.key[8:16])
	cfg.NsDev, cfg.NsIno = f.nsDev, f.nsIno
	zero := uint32(0)
	if err := f.coll.Maps["tego_pf_counters"].Put(zero, pinfactsrdTegoPfCounts{}); err != nil {
		f.t.Fatal(err)
	}
	for i := uint32(0); i < 64; i++ {
		if err := f.coll.Maps["tego_pf_execs"].Put(i, pinfactsrdTegoPfExec{}); err != nil {
			f.t.Fatal(err)
		}
		if err := f.coll.Maps["tego_pf_stages"].Put(i, pinfactsrdTegoPfStage{}); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := f.coll.Maps["tego_pf_config"].Put(zero, cfg); err != nil {
		f.t.Fatal(err)
	}
}

func (f *pinFacts) counts() pinfactsrdTegoPfCounts {
	f.t.Helper()
	var c pinfactsrdTegoPfCounts
	if err := f.coll.Maps["tego_pf_counters"].Lookup(uint32(0), &c); err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *pinFacts) exec(i uint32) pinfactsrdTegoPfExec {
	f.t.Helper()
	var r pinfactsrdTegoPfExec
	if err := f.coll.Maps["tego_pf_execs"].Lookup(i, &r); err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *pinFacts) stage(i uint32) pinfactsrdTegoPfStage {
	f.t.Helper()
	var r pinfactsrdTegoPfStage
	if err := f.coll.Maps["tego_pf_stages"].Lookup(i, &r); err != nil {
		f.t.Fatal(err)
	}
	return r
}

// run execs path with argv in the watched cgroup, descriptor 3 the pipe, and waits for it.
func (f *pinFacts) run(path string, argv []string, attr *syscall.SysProcAttr) (int, unix.WaitStatus) {
	f.t.Helper()
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	}
	attr.UseCgroupFD, attr.CgroupFD = true, f.cgFD
	pid, err := syscall.ForkExec(path, argv, &syscall.ProcAttr{
		Env:   []string{},
		Files: []uintptr{uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.pipeW)},
		Sys:   attr,
	})
	if err != nil {
		f.t.Fatalf("exec %s: %v", path, err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		f.t.Fatal(err)
	}
	return pid, ws
}

// drained reads what the probe wrote to the pipe since the last call.
func (f *pinFacts) drained() int {
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := unix.Read(f.pipeR, buf)
		if n <= 0 || err != nil {
			return total
		}
		total += n
	}
}

// area is the argument area the kernel maps for argv: each string NUL-terminated, back to back.
func area(argv []string) []byte {
	var b []byte
	for _, a := range argv {
		b = append(b, a...)
		b = append(b, 0)
	}
	return b
}

func (f *pinFacts) sipVectors(t *testing.T) {
	prog := f.coll.Programs["tego_pf_sip"]
	var ref execpin.Key
	for i := range ref {
		ref[i] = byte(i)
	}
	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	for _, key := range []execpin.Key{ref, f.key} {
		for _, dom := range []byte{execpin.DomainCovered, execpin.DomainScript, execpin.DomainTail} {
			for n := 0; n <= 64; n++ {
				in := pinfactsrdTegoPfSipCtx{
					K0: binary.LittleEndian.Uint64(key[0:8]), K1: binary.LittleEndian.Uint64(key[8:16]),
					Len: uint32(n), Domain: dom,
				}
				for w := range in.Data {
					in.Data[w] = binary.LittleEndian.Uint64(msg[w*8 : w*8+8])
				}
				var out pinfactsrdTegoPfSipCtx
				ret, err := prog.Run(&ebpf.RunOptions{Context: in, ContextOut: &out})
				if err != nil || ret != 0 {
					t.Fatalf("run the syscall program: ret %d, %v", ret, err)
				}
				if want := execpin.MAC(key, dom, msg[:n]); out.Mac != want {
					t.Fatalf("domain %d, %d bytes: BPF MAC %016x, Go %016x", dom, n, out.Mac, want)
				}
			}
		}
	}
}

func (f *pinFacts) argvArea(t *testing.T) {
	long := func(total int) []string {
		// "probe", then 1000-byte arguments, then one that brings the area to total bytes.
		argv := []string{"probe"}
		left := total - len(area(argv))
		for left > 1001 {
			argv = append(argv, strings.Repeat("a", 1000))
			left -= 1001
		}
		return append(argv, strings.Repeat("b", left-1))
	}
	cases := []struct {
		name string
		argv []string
		cov  int // bytes covered; 0: the whole area
	}{
		{"short", []string{"probe", "a", "bc"}, 0},
		{"covered-prefix", []string{"git", "-C", ".", "push", "origin", "main"}, len(area([]string{"git", "-C", ".", "push"}))},
		{"unaligned-chunks", long(1000*7 + 13), 0},
		{"one-chunk", long(256), 0},
		{"chunk-and-one", long(257), 0},
		{"the-bound", long(execpinMaxLen), 0},
	}
	for _, c := range cases {
		f.configure(pinfactsrdTegoPfCfg{Domain: execpin.DomainCovered, CovLen: uint32(c.cov)})
		_, ws := f.run(f.probe, c.argv, nil)
		if !ws.Exited() || ws.ExitStatus() != 0 || f.drained() != 1 {
			t.Fatalf("%s: the probe did not run to its write and exit: %v", c.name, ws)
		}
		r := f.exec(0)
		a := area(c.argv)
		cov := a
		if c.cov != 0 {
			cov = a[:c.cov]
		}
		if r.ReadErr != 0 || r.Span != uint64(len(a)) || r.Argc != uint32(len(c.argv)) || r.Interpreted != 0 {
			t.Fatalf("%s: read_err %d span %d argc %d interpreted %d; want 0, %d, %d, 0",
				c.name, r.ReadErr, r.Span, r.Argc, r.Interpreted, len(a), len(c.argv))
		}
		if want := execpin.MAC(f.key, execpin.DomainCovered, cov); r.Mac != want {
			t.Fatalf("%s: the kernel's area MACs to %016x, the passed vector to %016x", c.name, r.Mac, want)
		}
	}
	// One byte past the bound is not read: the plane refuses a pin past it (R7), never MACs a prefix as the whole.
	f.configure(pinfactsrdTegoPfCfg{Domain: execpin.DomainCovered})
	argv := long(execpinMaxLen + 1)
	if _, ws := f.run(f.probe, argv, nil); !ws.Exited() {
		t.Fatalf("past the bound: %v", ws)
	}
	f.drained()
	if r := f.exec(0); r.ReadErr != -int32(unix.E2BIG) || r.Span != uint64(execpinMaxLen+1) {
		t.Fatalf("past the bound: read_err %d span %d; want -E2BIG, %d", r.ReadErr, r.Span, execpinMaxLen+1)
	}
}

// execpinMaxLen is bpf/include/exec_pin.h's TEGO_PIN_MAX_LEN, supervisor.md R16's DefaultMaxArgv.
const execpinMaxLen = 128 << 10

func (f *pinFacts) stages(t *testing.T) {
	dir := filepath.Dir(f.probe)
	s2 := filepath.Join(dir, "s2")
	s1 := filepath.Join(dir, "s1")
	mustWrite(t, s2, []byte("#!"+f.probe+"\n"), 0o755)
	mustWrite(t, s1, []byte("#!"+s2+" opt\n"), 0o755)
	f.configure(pinfactsrdTegoPfCfg{Domain: execpin.DomainScript})
	pid, ws := f.run(s1, []string{"anything", "arg"}, nil)
	if !ws.Exited() || f.drained() != 1 {
		t.Fatalf("the two-stage script did not run the probe: %v", ws)
	}
	if c := f.counts(); c.Stages != 3 || c.Execs != 1 {
		t.Fatalf("stages %d, sched_process_exec %d; want 3 bprm_check stages and one exec", c.Stages, c.Execs)
	}
	for i, want := range []struct {
		path          string
		first, script uint8
	}{{s1, 1, 1}, {s2, 0, 1}, {f.probe, 0, 0}} {
		var st unix.Stat_t
		if err := unix.Stat(want.path, &st); err != nil {
			t.Fatal(err)
		}
		r := f.stage(uint32(i))
		dev := uint64(unix.Mkdev(r.Dev>>20, r.Dev&0xfffff))
		if r.Ino != st.Ino || dev != st.Dev || r.First != want.first || r.Shebang != want.script || r.Storage != 1 {
			t.Fatalf("stage %d: ino %d dev %#x first %d shebang %d storage %d; want %s (ino %d dev %#x), first %d, shebang %d, storage 1",
				i, r.Ino, dev, r.First, r.Shebang, r.Storage, want.path, st.Ino, st.Dev, want.first, want.script)
		}
		if r.Tid != uint32(pid) || r.NsRet != 0 || r.NsTid != uint32(pid) || r.NsTgid != uint32(pid) {
			t.Fatalf("stage %d: tid %d, ns answer %d (%d/%d); want %d and 0 (%d/%d)", i, r.Tid, r.NsRet, r.NsTid, r.NsTgid, pid, pid, pid)
		}
	}
	// binfmt_script's vector: each stage drops argv[0] and puts its interpreter, its optional argument and the
	// filename the stage was asked to run in front.
	want := area([]string{f.probe, s2, "opt", s1, "arg"})
	r := f.exec(0)
	if r.Interpreted != 1 || r.Span != uint64(len(want)) || r.Mac != execpin.MAC(f.key, execpin.DomainScript, want) {
		t.Fatalf("after the chain: interpreted %d span %d (want 1, %d); the area does not MAC as %q", r.Interpreted, r.Span, len(want), want)
	}
}

func (f *pinFacts) pidNamespace(t *testing.T) {
	f.configure(pinfactsrdTegoPfCfg{})
	if _, ws := f.run(f.probe, []string{"probe"}, &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}); !ws.Exited() {
		t.Fatalf("the probe in a child pid namespace: %v", ws)
	}
	f.drained()
	if r := f.stage(0); r.NsRet != -int32(unix.EINVAL) {
		t.Fatalf("bpf_get_ns_current_pid_tgid for a task in a child pid namespace answered %d (%d/%d); the pin key assumes -EINVAL",
			r.NsRet, r.NsTid, r.NsTgid)
	}
}

func (f *pinFacts) ptraceFlag(t *testing.T) {
	f.configure(pinfactsrdTegoPfCfg{})
	f.run(f.probe, []string{"probe"}, nil)
	f.drained()
	if r := f.stage(0); r.Ptrace&1 != 0 {
		t.Fatalf("an untraced exec reads ptrace %#x", r.Ptrace)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f.configure(pinfactsrdTegoPfCfg{})
	pid := f.startTraced()
	if err := unix.PtraceCont(pid, 0); err != nil {
		t.Fatal(err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil || !ws.Exited() {
		t.Fatalf("the traced probe: %v %v", ws, err)
	}
	f.drained()
	if r := f.stage(0); r.Ptrace&1 != 1 {
		t.Fatalf("a traced exec reads ptrace %#x at bprm_check; want PT_PTRACED", r.Ptrace)
	}
}

// startTraced starts the probe under PTRACE_TRACEME (the caller holds its OS thread) and returns once it is stopped
// at its exec, or has died.
func (f *pinFacts) startTraced() int {
	f.t.Helper()
	pid, err := syscall.ForkExec(f.probe, []string{"probe"}, &syscall.ProcAttr{
		Env:   []string{},
		Files: []uintptr{uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.pipeW)},
		Sys:   &syscall.SysProcAttr{Ptrace: true, UseCgroupFD: true, CgroupFD: f.cgFD},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		f.t.Fatal(err)
	}
	if !ws.Stopped() {
		f.t.Fatalf("the traced probe did not stop at its exec: %v", ws)
	}
	return pid
}

func (f *pinFacts) startTime(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatalf("no sleep(1) to hold a process: %v", err)
	}
	f.configure(pinfactsrdTegoPfCfg{})
	pid, err := syscall.ForkExec(sleep, []string{"sleep", "30"}, &syscall.ProcAttr{
		Env:   []string{},
		Files: []uintptr{uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.nullFD)},
		Sys:   &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: f.cgFD},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = unix.Kill(pid, unix.SIGKILL)
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, 0, nil)
	}()
	r := f.stage(0)
	if r.Tid != uint32(pid) {
		t.Fatalf("stage 0 is tid %d, not sleep's %d", r.Tid, pid)
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	outside := statStart(t, stat)
	kernel := r.StartBoottime / (1e9 / pinFactsClockTicks)
	if outside != kernel {
		t.Fatalf("/proc/%d/stat start time %d ticks; current->start_boottime at bprm_check %d ns = %d ticks", pid, outside, r.StartBoottime, kernel)
	}
	cmd := exec.Command("/proc/self/exe", "-test.run=^$")
	cmd.Env = append(os.Environ(), pinFactsTimensHelper+"="+strconv.Itoa(pid))
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("the time-namespace helper: %v: %s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	inside := statStart(t, out)
	if inside-outside != pinFactsBoottimeOffset*pinFactsClockTicks {
		t.Fatalf("inside a time namespace with a %d s boottime offset /proc/<pid>/stat says %d ticks, outside %d: not shifted by the offset",
			pinFactsBoottimeOffset, inside, outside)
	}
	t.Logf("K0 start time: %d ticks outside, %d inside a +%d s boottime namespace, kernel %d", outside, inside, pinFactsBoottimeOffset, kernel)
}

// statStart is field 22 of a /proc/<pid>/stat line, read after the comm's closing parenthesis.
func statStart(t *testing.T, stat []byte) uint64 {
	t.Helper()
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		t.Fatalf("no comm in %q", s)
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		t.Fatalf("short stat line %q", s)
	}
	v, err := strconv.ParseUint(f[19], 10, 64) // fields 3.. start at f[0]
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *pinFacts) kills(t *testing.T) {
	// Control: the MAC matches, nothing is killed, the probe writes.
	a := area([]string{"probe", "ok"})
	f.configure(pinfactsrdTegoPfCfg{Domain: execpin.DomainCovered, Kill: 1, ExpectMac: execpin.MAC(f.key, execpin.DomainCovered, a)})
	if _, ws := f.run(f.probe, []string{"probe", "ok"}, nil); !ws.Exited() || f.drained() != 1 {
		t.Fatalf("a matching exec did not run: %v", ws)
	}
	if c := f.counts(); c.Kills != 0 || c.Mismatches != 0 {
		t.Fatalf("a matching exec was counted: %+v", c)
	}
	// Every exec of a vector other than the pinned one is killed before its first instruction.
	f.configure(pinfactsrdTegoPfCfg{Domain: execpin.DomainCovered, Kill: 1, ExpectMac: execpin.MAC(f.key, execpin.DomainCovered, a)})
	for i := 0; i < pinFactsKills; i++ {
		_, ws := f.run(f.probe, []string{"probe", "changed"}, nil)
		if !ws.Signaled() || ws.Signal() != unix.SIGKILL {
			t.Fatalf("kill %d: %v, want SIGKILL", i, ws)
		}
	}
	if n := f.drained(); n != 0 {
		t.Fatalf("%d of %d killed probes wrote: the kill came after the first instruction", n, pinFactsKills)
	}
	c := f.counts()
	if c.Kills != pinFactsKills || c.KillFailed != 0 || c.Execs != pinFactsKills {
		t.Fatalf("kills %d, send failures %d (last %d), execs %d; want %d, 0, %d", c.Kills, c.KillFailed, c.LastKillErr, c.Execs, pinFactsKills, pinFactsKills)
	}
	t.Logf("K0 kills: %d sent, %d send failures, the pipe empty", c.Kills, c.KillFailed)
}

func (f *pinFacts) tracedKill(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f.configure(pinfactsrdTegoPfCfg{Domain: execpin.DomainCovered, Kill: 1, ExpectMac: 1})
	pid, err := syscall.ForkExec(f.probe, []string{"probe"}, &syscall.ProcAttr{
		Env:   []string{},
		Files: []uintptr{uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.nullFD), uintptr(f.pipeW)},
		Sys:   &syscall.SysProcAttr{Ptrace: true, UseCgroupFD: true, CgroupFD: f.cgFD},
	})
	if err != nil {
		t.Fatal(err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		t.Fatal(err)
	}
	stopped := ws.Stopped()
	if stopped {
		// The tracer holds a stop with SIGKILL pending: it must not be able to write the new image.
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], 0xccccccccccccccc)
		if _, err := unix.PtracePokeData(pid, pinFactsEntry, word[:]); err == nil {
			t.Fatal("PTRACE_POKEDATA into an exec killed at sched_process_exec succeeded")
		}
		_ = unix.PtraceCont(pid, 0)
		if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !ws.Signaled() || ws.Signal() != unix.SIGKILL || f.drained() != 0 {
		t.Fatalf("the traced exec ended %v; want SIGKILL before its first instruction", ws)
	}
	if c := f.counts(); c.Kills != 1 || c.KillFailed != 0 {
		t.Fatalf("kills %d, send failures %d", c.Kills, c.KillFailed)
	}
	t.Logf("K0 traced kill: the tracer saw a stop first: %v", stopped)
}
