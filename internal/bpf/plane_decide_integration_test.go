// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"bufio"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/uring"
)

// TIER3-PLAN T3's root cells: every Step A hook of both plane builds, in each mode this kernel offers, refuses inside
// a run and allows outside it, against rows the test writes into a scratch slot. T4's fill does not exist yet, so a
// test-only iter/task_file program (bpf/testonly/plane_fill.bpf.c) writes the inode-keyed rows from the test's own
// O_PATH descriptors, and the policy and name rows, which no inode keys, are written from here.
//
// The agent is planeHelper: this test binary re-executed with TEGO_PLANE_HELPER=1 into a child cgroup, which runs
// its commands in init on the main thread (so the task storage the plane records into is the thread group
// leader's, which a pidfd names) and never reaches the tests. Its run-set row is written after its exec, as a
// real run's is (enforce-plane R15).

const planeHelperEnv = "TEGO_PLANE_HELPER"

func init() {
	if os.Getenv(planeHelperEnv) != "1" {
		return
	}
	runtime.LockOSThread()
	os.Exit(planeHelperMain())
}

// planeHelperMain answers one command per line on stdin with one line on stdout: "0", an errno number, or
// "exit <status>" for an exec whose program ran and failed.
func planeHelperMain() int {
	in := bufio.NewScanner(os.Stdin)
	fmt.Println("ready")
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		fmt.Println(planeHelperDo(f))
	}
	return 0
}

func errnoString(err error) string {
	if err == nil {
		return "0"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return strconv.Itoa(int(en))
	}
	return "err " + err.Error()
}

func planeHelperDo(f []string) string {
	switch f[0] {
	case "open":
		flags, _ := strconv.Atoi(f[1])
		fd, err := unix.Open(f[2], flags|unix.O_CLOEXEC, 0o644)
		if err == nil {
			_ = unix.Close(fd)
		}
		return errnoString(err)
	case "unlink":
		return errnoString(unix.Unlink(f[1]))
	case "rmdir":
		return errnoString(unix.Rmdir(f[1]))
	case "rename":
		return errnoString(unix.Rename(f[1], f[2]))
	case "link":
		return errnoString(unix.Link(f[1], f[2]))
	case "exec":
		return planeRunExec(f[1], f[1:], nil)
	case "execfd":
		return planeExecFD(f[1], f[2], f[3])
	case "openhandle":
		return planeOpenHandle(f[1], f[2], f[3], f[4])
	case "execmemfd":
		src, err := os.ReadFile(f[1])
		if err != nil {
			return "err " + err.Error()
		}
		mfd, err := unix.MemfdCreate("tego-plane-test", 0)
		if err != nil {
			return errnoString(err)
		}
		defer unix.Close(mfd)
		if _, err := unix.Write(mfd, src); err != nil {
			return errnoString(err)
		}
		return planeRunExec("/proc/self/fd/0", []string{"memfd"}, []uintptr{uintptr(mfd)})
	}
	if out, ok := planeHelperStepB(f); ok {
		return out
	}
	if do, ok := planeMapCommands[f[0]]; ok {
		return do(f) // step C's (plane_map_integration_test.go)
	}
	if do, ok := planeNameCommands[f[0]]; ok {
		return do(f) // ADR 0043's (plane_name_integration_test.go)
	}
	return "err unknown command " + f[0]
}

// planeOpenHandle is open_by_handle_at(2) of a handle "type:hex" on the mount of dir, as name_to_handle_at gave it.
func planeOpenHandle(flags, dir, typ, hexBytes string) string {
	fl, _ := strconv.Atoi(flags)
	t, err := strconv.Atoi(typ)
	if err != nil {
		return "err " + err.Error()
	}
	raw, err := hex.DecodeString(hexBytes)
	if err != nil {
		return "err " + err.Error()
	}
	mfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errnoString(err)
	}
	defer unix.Close(mfd)
	fd, err := unix.OpenByHandleAt(mfd, unix.NewFileHandle(int32(t), raw), fl|unix.O_CLOEXEC)
	if err == nil {
		_ = unix.Close(fd)
	}
	return errnoString(err)
}

// planeExecFD execs a copy of the program src through a descriptor whose name is gone: how is "unlink" (a file made
// in dir, opened, and unlinked) or "tmpfile" (an O_TMPFILE in dir, reopened read-only through /proc, as linkat's
// idiom does), so bprm_check meets an image whose dentry is unhashed (R9's exec.anonymous, the arm tego_is_anonymous
// decides by d_hash.pprev). The exec reads the same file through the /proc spelling, as execmemfd does (Go has no
// execveat(fd, "", AT_EMPTY_PATH) for a child); the write descriptor is closed first (a writable image is ETXTBSY).
func planeExecFD(src, dir, how string) string {
	bin, err := os.ReadFile(src)
	if err != nil {
		return "err " + err.Error()
	}
	var wfd, rfd int
	switch how {
	case "unlink":
		p := filepath.Join(dir, "execfd-"+strconv.Itoa(os.Getpid()))
		if wfd, err = unix.Open(p, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o755); err != nil {
			return errnoString(err)
		}
		if _, err = unix.Write(wfd, bin); err == nil {
			_ = unix.Close(wfd)
			if rfd, err = unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
				err = unix.Unlink(p)
			}
		}
	case "tmpfile":
		if wfd, err = unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o755); err != nil {
			return errnoString(err)
		}
		if _, err = unix.Write(wfd, bin); err == nil {
			rfd, err = unix.Open("/proc/self/fd/"+strconv.Itoa(wfd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		}
		_ = unix.Close(wfd)
	default:
		return "err unknown execfd variant " + how
	}
	if err != nil {
		return errnoString(err)
	}
	defer unix.Close(rfd)
	return planeRunExec("/proc/self/fd/0", []string{"execfd"}, []uintptr{uintptr(rfd)})
}

// planeRunExec runs one program to its end: its exec's errno, or "exit <status>" for a non-zero exit.
func planeRunExec(path string, argv []string, files []uintptr) string {
	pid, err := syscall.ForkExec(path, argv, &syscall.ProcAttr{Files: files})
	if err != nil {
		return errnoString(err)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return errnoString(err)
	}
	if ws.ExitStatus() != 0 {
		return "exit " + strconv.Itoa(ws.ExitStatus())
	}
	return "0"
}

// planeHelper is the test's side of one helper process.
type planeHelper struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	out   *bufio.Reader
	pidfd int
}

func startPlaneHelper(t *testing.T, cgroupFD int) *planeHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), planeHelperEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the helper in its cgroup: %v", err)
	}
	h := &planeHelper{cmd: cmd, in: in, out: bufio.NewReader(outPipe), pidfd: -1}
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if h.pidfd >= 0 {
			_ = unix.Close(h.pidfd)
		}
	})
	if line, err := h.out.ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("helper did not start: %q %v", line, err)
	}
	if h.pidfd, err = unix.PidfdOpen(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("pidfd_open: %v", err)
	}
	return h
}

func (h *planeHelper) do(t *testing.T, args ...string) string {
	t.Helper()
	if _, err := fmt.Fprintln(h.in, strings.Join(args, " ")); err != nil {
		t.Fatalf("helper: %v", err)
	}
	line, err := h.out.ReadString('\n')
	if err != nil {
		t.Fatalf("helper died on %v: %v", args, err)
	}
	return strings.TrimSpace(line)
}

// planeFillTmpl mirrors struct tego_test_fill_tmpl (bpf/testonly/plane_fill.bpf.c).
type planeFillTmpl struct {
	Exec    uint8
	Corrupt uint8
	Pad     [6]uint8
	NameKey uint64
	Row     PlaneRow
	Xrow    PlaneExecRow
}

// planeFillCfg mirrors struct tego_test_fill_cfg.
type planeFillCfg struct {
	Tgid    uint32
	RunIdx  uint32
	Written uint32
	Failed  uint32
}

// planeTree is the scratch tree the cells act on, with the rows written for it.
type planeTree struct {
	w, o, e, d, trueBin, loader string
	tmpls                       map[uint32]planeFillTmpl
	// keeper, when set, is the test whose end closes the holds, in place of the test that took them: the one that
	// armed the slot. A cell run as a subtest writes its rows at that test's gen, and they stay in the slot after the
	// subtest ends; a hold closed then frees the inode a row of the live gen is keyed by, and the next inode the
	// allocator puts at that address meets the row and is refused identity-mismatch (enforce-plane §6 E3), whatever
	// the later cell asserts. A run's domain holds every keyed inode while its gen is live (R17), and so do the cells.
	keeper *testing.T
}

// The rows' rule_idx: an fs row's is its position in the row compiler's rows, an exec row's its exec entry's.
const (
	ruleW      = 1
	ruleSecret = 2
	ruleDrop   = 3
	ruleHooks  = 4
	ruleStale  = 5
	ruleBad    = 6
	ruleGit    = 7
	ruleAnc    = 8
	ruleDir    = 9
	ruleExecT1 = 10
	ruleExecT5 = 11
	ruleExecT8 = 12
	ruleName   = 30
)

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// hold opens path O_PATH for the fill and keeps it open for the test, or for p.keeper (the domain's hold, in a run).
func (p *planeTree) hold(t *testing.T, path string, tmpl planeFillTmpl) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	p.keep(t, fd)
	p.tmpls[uint32(fd)] = tmpl
}

// keep closes a hold's descriptor when p.keeper ends, or t, the test that took it, when p has no keeper.
func (p *planeTree) keep(t *testing.T, fd int) {
	owner := t
	if p.keeper != nil {
		owner = p.keeper
	}
	owner.Cleanup(func() { _ = unix.Close(fd) })
}

func fsRow(gen uint32, rule uint16, kind uint8) planeFillTmpl {
	return planeFillTmpl{Row: PlaneRow{Gen: gen, RuleIdx: rule, Kind: kind, ExecRule: PlaneRuleNone}}
}

func execRow(t *testing.T, gen uint32, rule uint16, name string) planeFillTmpl {
	t.Helper()
	n, l, ok := PlaneExecName(name)
	if !ok {
		t.Fatalf("name %q", name)
	}
	k, _ := PlaneNameKey(name)
	return planeFillTmpl{Exec: 1, NameKey: k, Xrow: PlaneExecRow{Gen: gen, RuleIdx: rule, NameLen: l, Name: n}}
}

// buildPlaneTree lays out the tree and names the rows of each object: W a write entry holding a deny_read secret/,
// a write-only drop/, a deny_write target .git/hooks with its ancestor .git and a second ancestor anc/, a stale
// deny_read stale/ and a deny_read bad/ whose identity is corrupted; O no entry; E the exec rows' directory; D an
// exec.allow directory.
func buildPlaneTree(t *testing.T, gen uint32) *planeTree {
	t.Helper()
	root := t.TempDir()
	p := &planeTree{w: filepath.Join(root, "w"), o: filepath.Join(root, "o"), e: filepath.Join(root, "e"),
		d: filepath.Join(root, "d"), tmpls: map[uint32]planeFillTmpl{}}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true(1) to exec: %v", err)
	}
	if p.trueBin, err = filepath.EvalSymlinks(trueBin); err != nil {
		t.Fatal(err)
	}
	if ef, err := elf.Open(p.trueBin); err == nil {
		for _, prog := range ef.Progs {
			if prog.Type == elf.PT_INTERP {
				b, _ := io.ReadAll(prog.Open())
				p.loader = strings.TrimRight(string(b), "\x00")
			}
		}
		_ = ef.Close()
	}
	bin, err := os.ReadFile(p.trueBin)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"f", "f4", "u1", "secret/f", "secret/f2", "secret/f3", ".git/hooks/pre-commit",
		".git/hooks/h1", ".git/config", "drop/f", "drop/g", "stale/f", "bad/f", ".git/hooks/h2", ".git/hooks/h3",
		"attr", "f5", "f6"} {
		mustWrite(t, filepath.Join(p.w, f), []byte("x\n"), 0o644)
	}
	for _, d := range []string{"d1", "d2", "anc", "secret/rd"} {
		if err := os.MkdirAll(filepath.Join(p.w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(p.o, "f"), []byte("x\n"), 0o644)
	if err := os.Mkdir(filepath.Join(p.o, "rd"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"e/t1", "e/t5", "o/t3", "o/t4", "d/t6", "d/sub/t7"} {
		mustWrite(t, filepath.Join(root, f), bin, 0o755)
	}
	// t2 and t8 are hard links of t1, a multi-call binary's shape (uutils, busybox): t1 and t8 each have an exec row,
	// t2 none (ADR 0025's 2026-09-30 note).
	for _, l := range []string{"t2", "t8"} {
		if err := os.Link(filepath.Join(p.e, "t1"), filepath.Join(p.e, l)); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(p.e, "s1.sh"), []byte("#!"+filepath.Join(p.e, "t1")+"\n"), 0o755)
	mustWrite(t, filepath.Join(p.e, "s2.sh"), []byte("#!"+p.trueBin+"\n"), 0o755)

	// Complete rows, as the row compiler writes them (decide.PlaneKind): drop/ refuses reads and allows
	// modifications, which no contract compiles to, so that REFER is the only refusal of a move out of it.
	p.hold(t, p.w, fsRow(gen, ruleW, PlaneRowModifyAllow))
	p.hold(t, filepath.Join(p.w, "secret"), fsRow(gen, ruleSecret, PlaneRowReadDeny))
	p.hold(t, filepath.Join(p.w, "drop"), fsRow(gen, ruleDrop, PlaneRowReadDeny|PlaneRowModifyAllow))
	p.hold(t, filepath.Join(p.w, ".git/hooks"), fsRow(gen, ruleHooks, PlaneRowRenameRefused|PlaneRowProtected))
	p.hold(t, filepath.Join(p.w, ".git"), fsRow(gen, ruleGit, PlaneRowModifyAllow|PlaneRowRenameRefused))
	p.hold(t, filepath.Join(p.w, "anc"), fsRow(gen, ruleAnc, PlaneRowModifyAllow|PlaneRowRenameRefused))
	p.hold(t, filepath.Join(p.w, "stale"), fsRow(gen-1, ruleStale, PlaneRowReadDeny))
	bad := fsRow(gen, ruleBad, PlaneRowReadDeny)
	bad.Corrupt = 1
	p.hold(t, filepath.Join(p.w, "bad"), bad)
	dir := fsRow(gen, ruleDir, PlaneRowExecDir)
	dir.Row.ExecRule = ruleDir // this hand-built fixture's exec.allow directory entry
	p.hold(t, p.d, dir)
	p.hold(t, filepath.Join(p.e, "t1"), execRow(t, gen, ruleExecT1, "t1"))
	p.hold(t, filepath.Join(p.e, "t5"), execRow(t, gen-1, ruleExecT5, "t5"))
	p.hold(t, filepath.Join(p.e, "t8"), execRow(t, gen, ruleExecT8, "t8"))
	return p
}

// planeFill runs the test-only fill over this process's descriptors into slot runIdx's maps.
func planeFill(t *testing.T, coll *ebpf.Collection, runIdx uint32, p *planeTree) {
	t.Helper()
	spec, err := loadPlanetestfill()
	if err != nil {
		t.Fatalf("load the fill spec: %v", err)
	}
	unpin(spec)
	var objs struct {
		Prog  *ebpf.Program `ebpf:"tego_test_fill"`
		Tmpls *ebpf.Map     `ebpf:"tego_test_fill_tmpls"`
		Cfgs  *ebpf.Map     `ebpf:"tego_test_fill_cfgs"`
	}
	if unsafe.Sizeof(planeFillTmpl{}) != unsafe.Sizeof(planetestfillTegoTestFillTmpl{}) ||
		unsafe.Sizeof(planeFillCfg{}) != unsafe.Sizeof(planetestfillTegoTestFillCfg{}) {
		t.Fatal("the fill mirrors drifted from bpf/testonly/plane_fill.bpf.c")
	}
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		MapPlaneRows: coll.Maps[MapPlaneRows], MapPlaneExecRows: coll.Maps[MapPlaneExecRows],
	}})
	if err != nil {
		t.Fatalf("load the fill: %v", err)
	}
	defer objs.Prog.Close()
	defer objs.Tmpls.Close()
	defer objs.Cfgs.Close()
	for fd, tmpl := range p.tmpls {
		if err := objs.Tmpls.Put(fd, tmpl); err != nil {
			t.Fatalf("template %d: %v", fd, err)
		}
	}
	if err := objs.Cfgs.Put(uint32(0), planeFillCfg{Tgid: uint32(os.Getpid()), RunIdx: runIdx}); err != nil {
		t.Fatal(err)
	}
	it, err := link.AttachIter(link.IterOptions{Program: objs.Prog})
	if err != nil {
		t.Fatalf("attach the fill: %v", err)
	}
	defer it.Close()
	rd, err := it.Open()
	if err != nil {
		t.Fatalf("open the fill: %v", err)
	}
	_, err = io.Copy(io.Discard, rd)
	_ = rd.Close()
	if err != nil {
		t.Fatalf("run the fill: %v", err)
	}
	var cfg planeFillCfg
	if err := objs.Cfgs.Lookup(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Failed != 0 || int(cfg.Written) < len(p.tmpls) {
		t.Fatalf("the fill wrote %d rows and failed %d, want %d", cfg.Written, cfg.Failed, len(p.tmpls))
	}
}

// planeCell is one action: the helper's answer inside the run.
type planeCell struct {
	name string
	args []string
	want string
}

const eacces = "13"

// TestPlaneStepAHooksDecide is TIER3-PLAN §9's per-hook cells for step A (T3), enforce-plane R1, R7, R8, R9, R10
// and R11 on a real kernel, with enforce-plane.md §6 E2 (a reused slot) and E3 (a recycled pointer): in each build and mode this kernel
// offers, file_open, bprm_check, path_rename, path_link, path_unlink and path_rmdir refuse inside a run by the rows
// of its slot and allow the same action outside it; a stale row counts as absent, a row whose identity no longer
// matches refuses and counts, and each decision is recorded in the task's scratch value. It logs each program's
// verified instruction count against planeBudget.
func TestPlaneStepAHooksDecide(t *testing.T) {
	requireBPF(t)
	ran := 0
	for _, o := range PlaneObjects() {
		t.Run(o.String(), func(t *testing.T) {
			if ok, why := planeReaderUsable(t, o); !ok {
				t.Skip(why)
			}
			for _, mode := range PlaneModes {
				t.Run(string(mode), func(t *testing.T) {
					if ok, why := planeModeUsable(mode); !ok {
						t.Skip(why)
					}
					planeCells(t, o, mode, false)
					ran++
				})
			}
		})
	}
	if ran == 0 {
		t.Fatal("no plane build ran in any mode on this kernel")
	}
}

// TestPlaneStepBHooksDecide is TIER3-PLAN T13's per-hook cells (enforce-plane R12, R13, R14; §6 E5, E8, E14), on
// the tree and slot TestPlaneStepAHooksDecide's cells use, in each build and mode this kernel offers: path_mknod,
// path_mkdir and path_symlink refuse a create under a row that refuses modifications and leave no file, path_truncate
// and file_truncate refuse a deny_write target's file, the attribute hooks (chmod, chown, the xattr hooks, setfacl)
// refuse beneath the deny_write target only, also on a tmpfs mounted below it through the mounted root's row, and
// fail closed on a corrupted row; socket_create applies ADR 0018's allowlist under a net: section, by socket(2) and
// io_uring's IORING_OP_SOCKET; and a symlink repointed during chmod and truncate never changes the target (TOCTOU).
// An optional hook this kernel lacks (file_truncate, the ACL hooks, below 6.2) is not loaded, and its rule is
// decided by the hook that decides it there.
func TestPlaneStepBHooksDecide(t *testing.T) {
	requireBPF(t)
	ran := 0
	for _, o := range PlaneObjects() {
		t.Run(o.String(), func(t *testing.T) {
			if ok, why := planeReaderUsable(t, o); !ok {
				t.Skip(why)
			}
			for _, mode := range PlaneModes {
				t.Run(string(mode), func(t *testing.T) {
					if ok, why := planeModeUsable(mode); !ok {
						t.Skip(why)
					}
					planeCells(t, o, mode, true)
					ran++
				})
			}
		})
	}
	if ran == 0 {
		t.Fatal("no plane build ran in any mode on this kernel")
	}
}

// planeCells loads build o in mode, fills a scratch slot for buildPlaneTree's tree, starts the helper in a child
// cgroup armed as a run, and runs step A's cells, or step B's.
func planeCells(t *testing.T, o Object, mode PlaneMode, stepB bool) {
	const runIdx, gen = 7, 4242
	spec, err := Load(o)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unpin(spec)
	keep := map[string]bool{}
	for _, p := range PlaneProgramsHere(mode) {
		keep[p] = true
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load %s %s: %+v", o, mode, ve)
		}
		t.Fatalf("load %s %s: %v", o, mode, err)
	}
	t.Cleanup(coll.Close)

	// The slot's row maps, as T6's backend keeps them: created once, put in the outers at run_idx.
	for _, name := range []string{MapPlaneRows, MapPlaneExecRows} {
		inner, err := ebpf.NewMap(spec.Maps[name].InnerMap)
		if err != nil {
			t.Fatalf("inner %s: %v", name, err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		if err := coll.Maps[name].Put(uint32(runIdx), inner); err != nil {
			t.Fatalf("outer %s: %v", name, err)
		}
	}
	tree := buildPlaneTree(t, gen)
	planeFill(t, coll, runIdx, tree)
	var execInner *ebpf.Map
	if err := coll.Maps[MapPlaneExecRows].Lookup(uint32(runIdx), &execInner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = execInner.Close() })
	// The slot's header, written last, as Prepare does (enforce-plane R6): this run's gen and an exec: section.
	setSlot := func(gen, flags uint32) {
		t.Helper()
		if err := coll.Maps[MapPlaneSlots].Put(uint32(runIdx), PlaneSlot{Gen: gen, Flags: flags}); err != nil {
			t.Fatal(err)
		}
	}
	nameKey, _ := PlaneNameKey("t3")
	nm, nl, _ := PlaneExecName("t3")
	if err := execInner.Put(nameKey, PlaneExecRow{Gen: gen, RuleIdx: ruleName, NameLen: nl, Name: nm}); err != nil {
		t.Fatal(err)
	}
	if err := coll.Maps[MapPlaneCounters].Put(uint32(runIdx), PlaneCounts{}); err != nil {
		t.Fatal(err)
	}
	setSlot(gen, PlaneSlotExecDecides)

	var links []link.Link
	t.Cleanup(func() {
		for _, l := range links {
			_ = l.Close()
		}
	})
	for _, h := range PlaneHooksHere(mode) {
		p := coll.Programs[h.Program(mode)]
		if info, err := p.Info(); err == nil {
			if n, ok := info.VerifiedInstructions(); ok {
				t.Logf("%s: %d instructions verified", h.Program(mode), n)
				if b := planeBudget(t, o, h.Name); n > b {
					t.Errorf("%s: %d instructions verified, over the budget of %d", h.Program(mode), n, b)
				}
			}
		}
		var l link.Link
		if mode == PlaneLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: p})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachModifyReturn})
		}
		if err != nil {
			t.Fatalf("attach %s: %v", h.Program(mode), err)
		}
		links = append(links, l)
	}

	_, cgfd, cgid := planeChildCgroup(t, string(o)+"-"+string(mode))
	helper := startPlaneHelper(t, cgfd)
	runSet := coll.Maps[MapRunSet]
	arm := func(gen uint32) {
		t.Helper()
		if err := runSet.Put(cgid, Run{RunIdx: runIdx, Tier: 3, Plane: RunPlaneOf(mode), Gen: gen}); err != nil {
			t.Fatalf("arm: %v", err)
		}
	}
	arm(gen)
	t.Cleanup(func() { _ = runSet.Delete(cgid) })

	w := func(p string) string { return filepath.Join(tree.w, p) }
	ro, wo := strconv.Itoa(unix.O_RDONLY), strconv.Itoa(unix.O_WRONLY)
	trunc := strconv.Itoa(unix.O_RDONLY | unix.O_TRUNC)
	create := strconv.Itoa(unix.O_WRONLY | unix.O_CREAT)
	check := func(c planeCell) {
		t.Helper()
		if got := helper.do(t, c.args...); got != c.want {
			t.Errorf("%s: in the run %v answered %s, want %s", c.name, c.args, got, c.want)
		}
	}
	// scratch checks the helper's last recorded decision (ADR 0024 (11)).
	scratch := func(what string, hook uint16, verdict, reason uint8, rule uint32) {
		t.Helper()
		var d PlaneDecision
		if err := coll.Maps[MapPlaneScratch].Lookup(int32(helper.pidfd), &d); err != nil {
			t.Errorf("%s: no scratch value for the helper: %v", what, err)
			return
		}
		if d.Hook != hook || d.Verdict != verdict || d.Reason != reason || d.RuleIdx != rule {
			t.Errorf("%s: recorded hook %d verdict %d reason %d rule %d, want %d %d %d %d", what, d.Hook, d.Verdict,
				d.Reason, d.RuleIdx, hook, verdict, reason, rule)
		}
	}
	outside := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s outside the run: %v", what, err)
		}
	}
	openOutside := func(path string, flags int) error {
		fd, err := unix.Open(path, flags|unix.O_CLOEXEC, 0o644)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}

	if stepB {
		planeStepBCells(t, coll, mode, runIdx, gen, helper, tree, arm, setSlot, scratch)
		return
	}

	// file_open (R8).
	check(planeCell{"read in a write entry", []string{"open", ro, w("f")}, "0"})
	scratch("read in a write entry", uint16(1), uint8(0), uint8(0), ruleW)
	check(planeCell{"read under deny_read", []string{"open", ro, w("secret/f")}, eacces})
	scratch("read under deny_read", 1, 1, uint8(ReasonReadDenied), ruleSecret)
	outside("read under deny_read", openOutside(w("secret/f"), unix.O_RDONLY))
	check(planeCell{"write under deny_read", []string{"open", wo, w("secret/f")}, eacces})
	check(planeCell{"write in a write entry", []string{"open", wo, w("f")}, "0"})
	check(planeCell{"write to a deny_write target", []string{"open", wo, w(".git/hooks/pre-commit")}, eacces})
	scratch("write to a deny_write target", 1, 1, uint8(ReasonWriteOutsideContract), ruleHooks)
	outside("write to a deny_write target", openOutside(w(".git/hooks/pre-commit"), unix.O_WRONLY))
	check(planeCell{"read a deny_write target (its row decides no read)", []string{"open", ro, w(".git/hooks/pre-commit")}, "0"})
	check(planeCell{"O_TRUNC of a deny_write target", []string{"open", trunc, w(".git/hooks/pre-commit")}, eacces})
	check(planeCell{"create in a write entry", []string{"open", create, w("new")}, "0"})
	check(planeCell{"create in a deny_write target", []string{"open", create, w(".git/hooks/new")}, eacces})
	check(planeCell{"read with no entry", []string{"open", ro, filepath.Join(tree.o, "f")}, "0"})
	check(planeCell{"write with no entry", []string{"open", wo, filepath.Join(tree.o, "f")}, eacces})
	scratch("write with no entry", 1, 1, uint8(ReasonWriteOutsideContract), uint32(PlaneRuleNone))
	outside("write with no entry", openOutside(filepath.Join(tree.o, "f"), unix.O_WRONLY))
	check(planeCell{"read under a stale deny_read row", []string{"open", ro, w("stale/f")}, "0"})
	check(planeCell{"read under a row whose identity is gone", []string{"open", ro, w("bad/f")}, eacces})
	scratch("read under a row whose identity is gone", 1, 1, uint8(ReasonIdentityMismatch), uint32(PlaneRuleNone))
	check(planeCell{"write to a pipe through /proc (no path)", []string{"open", wo, "/proc/self/fd/1"}, "0"})

	// path_unlink, path_rmdir (R11).
	check(planeCell{"unlink in a write entry", []string{"unlink", w("u1")}, "0"})
	check(planeCell{"unlink in a deny_write target", []string{"unlink", w(".git/hooks/h1")}, eacces})
	scratch("unlink in a deny_write target", 5, 1, uint8(ReasonDeleteOutsideContract), ruleHooks)
	check(planeCell{"unlink under deny_read", []string{"unlink", w("secret/f2")}, eacces})
	check(planeCell{"rmdir in a write entry", []string{"rmdir", w("d1")}, "0"})
	// path_rmdir refuses too (hook 6): under no entry (unmatched, no rule) and under deny_read (its row, which
	// allows no modification), and the directory stays.
	check(planeCell{"rmdir with no entry", []string{"rmdir", filepath.Join(tree.o, "rd")}, eacces})
	scratch("rmdir with no entry", 6, 1, uint8(ReasonDeleteOutsideContract), uint32(PlaneRuleNone))
	check(planeCell{"rmdir under deny_read", []string{"rmdir", w("secret/rd")}, eacces})
	scratch("rmdir under deny_read", 6, 1, uint8(ReasonDeleteOutsideContract), ruleSecret)
	for _, d := range []string{filepath.Join(tree.o, "rd"), w("secret/rd")} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("a refused rmdir removed %s: %v", d, err)
		}
	}
	outside("rmdir with no entry", unix.Rmdir(filepath.Join(tree.o, "rd")))
	outside("rmdir under deny_read", unix.Rmdir(w("secret/rd")))
	check(planeCell{"unlink a deny_write target's file", []string{"unlink", w(".git/hooks/pre-commit")}, eacces})

	// path_rename (R10, R11).
	check(planeCell{"mv .git .git.old", []string{"rename", w(".git"), w(".git.old")}, eacces})
	scratch("mv .git .git.old", 3, 1, uint8(ReasonDenyWriteAncestor), ruleGit)
	check(planeCell{"rename a deny_write ancestor", []string{"rename", w("anc"), w("anc2")}, eacces})
	check(planeCell{"rename onto a deny_write ancestor", []string{"rename", w("d2"), w("anc")}, eacces})
	scratch("rename onto a deny_write ancestor", 3, 1, uint8(ReasonDenyWriteAncestor), ruleAnc)
	check(planeCell{"rename out of a write-only drop box (REFER)", []string{"rename", w("drop/f"), w("f3")}, eacces})
	scratch("rename out of a write-only drop box", 3, 1, uint8(ReasonRefer), ruleDrop)
	check(planeCell{"rename into a stricter directory", []string{"rename", w("f4"), w("drop/f4")}, "0"})
	check(planeCell{"rename out of deny_read", []string{"rename", w("secret/f3"), w("x")}, eacces})
	check(planeCell{"rename over a deny_write target's file", []string{"rename", w("f"), w(".git/hooks/pre-commit")}, eacces})

	// path_link (R10).
	check(planeCell{"link in a write entry", []string{"link", w("f"), w("l1")}, "0"})
	check(planeCell{"link a deny_write target's file out (REFER)", []string{"link", w(".git/hooks/pre-commit"), w("l2")}, eacces})
	scratch("link a deny_write target's file out", 4, 1, uint8(ReasonRefer), ruleHooks)
	check(planeCell{"link out of a drop box (REFER)", []string{"link", w("drop/g"), w("l3")}, eacces})

	// The same mutations outside the run pass.
	outside("unlink in a deny_write target", unix.Unlink(w(".git/hooks/h1")))
	outside("rename a deny_write ancestor", unix.Rename(w("anc"), w("anc2")))
	outside("mv .git .git.old", unix.Rename(w(".git"), w(".git.old")))
	outside("mv .git.old .git", unix.Rename(w(".git.old"), w(".git")))
	outside("rename out of a drop box", unix.Rename(w("drop/f"), w("f3")))
	outside("link a deny_write target's file out", unix.Link(w(".git/hooks/pre-commit"), w("l2")))

	// bprm_check (R9).
	e := func(p string) string { return filepath.Join(tree.e, p) }
	check(planeCell{"exec an allowed file", []string{"exec", e("t1")}, "0"})
	check(planeCell{"exec a second hard link an entry names", []string{"exec", e("t8")}, "0"})
	check(planeCell{"exec a hard link under another name", []string{"exec", e("t2")}, eacces})
	outside("exec a hard link under another name", exec.Command(e("t2")).Run())
	check(planeCell{"exec an unlisted file", []string{"exec", tree.trueBin}, eacces})
	outside("exec an unlisted file", exec.Command(tree.trueBin).Run())
	check(planeCell{"a #! stage whose interpreter is allowed", []string{"exec", e("s1.sh")}, "0"})
	check(planeCell{"a #! stage whose interpreter is not", []string{"exec", e("s2.sh")}, eacces})
	if tree.loader != "" {
		check(planeCell{"a directly invoked loader", []string{"exec", tree.loader, e("t1")}, eacces})
		outside("a directly invoked loader", exec.Command(tree.loader, e("t1")).Run())
	} else {
		t.Logf("%s is static: no PT_INTERP loader to invoke", tree.trueBin)
	}
	check(planeCell{"exec by a name row", []string{"exec", filepath.Join(tree.o, "t3")}, "0"})
	check(planeCell{"exec another name in that directory", []string{"exec", filepath.Join(tree.o, "t4")}, eacces})
	check(planeCell{"exec in an exec.allow directory", []string{"exec", filepath.Join(tree.d, "t6")}, "0"})
	check(planeCell{"exec beneath an exec.allow directory", []string{"exec", filepath.Join(tree.d, "sub/t7")}, "0"})
	check(planeCell{"exec by a stale row", []string{"exec", e("t5")}, eacces})
	check(planeCell{"exec a memfd without exec.anonymous", []string{"execmemfd", tree.trueBin}, eacces})
	setSlot(gen, PlaneSlotExecDecides|PlaneSlotExecAnon)
	check(planeCell{"exec a memfd with exec.anonymous", []string{"execmemfd", tree.trueBin}, "0"})
	planeAnonExecCells(t, coll, runIdx, gen, helper, tree, setSlot)
	setSlot(gen, 0)
	check(planeCell{"exec with no exec: section (the header's flag clear)", []string{"exec", tree.trueBin}, "0"})
	setSlot(gen, PlaneSlotExecDecides)

	// A second run in the slot, whose header its Prepare wrote, meets the first one's rows at another gen: absent,
	// so a read the first refused is unmatched (allowed) and a write it allowed is unmatched (refused).
	arm(gen + 1)
	setSlot(gen+1, PlaneSlotExecDecides)
	check(planeCell{"next run: read under the previous run's deny_read", []string{"open", ro, w("secret/f")}, "0"})
	check(planeCell{"next run: write under the previous run's write entry", []string{"open", wo, w("f3")}, eacces})
	arm(gen)
	setSlot(gen, PlaneSlotExecDecides)

	var counts PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &counts); err != nil {
		t.Fatal(err)
	}
	t.Logf("counters: %+v", counts)
	if counts.Mismatch == 0 {
		t.Error("the corrupted row's refusal did not count a mismatch")
	}
	// The stale rows walked past above are not counted: they sit on the allow path (tego_walk_step).
	if counts.Unresolved != 0 || counts.Bound != 0 || counts.NoRows != 0 {
		t.Errorf("fail-closed counts nothing should have raised: %+v", counts)
	}

	planeDeepCells(t, coll, runIdx, gen, helper, scratch)
	planeSymlinkCells(t, coll, runIdx, gen, helper, scratch)
	// Subtests, so that each can skip where its filesystem is missing. Their rows are written at this test's gen, so
	// this test keeps their holds (planeTree.keeper).
	keeper := t
	t.Run("overlay", func(t *testing.T) { planeOverlayCell(t, keeper, coll, runIdx, gen, helper) })
	t.Run("disconnected", func(t *testing.T) { planeDisconnectedCell(t, keeper, coll, runIdx, gen, helper, scratch) })
	planeClearedHeaderCells(t, coll, runIdx, gen, helper, tree, setSlot, scratch)
}

// planeClearedHeaderCells is enforce-plane R6's header, fail closed: a run-set row still live over a slot whose
// header was cleared (Detach's or the reaper's clear, which zeroes the header first) or names another run is decided
// by nothing the slot holds. The run's rows are all still there, at its gen, yet every decided hook refuses, an exec
// and a read under a nested deny_read included, and each refusal counts norows. Before the header, bprm_check read
// a missing policy row as "no exec: section" and let the exec run.
func planeClearedHeaderCells(t *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper,
	tree *planeTree, setSlot func(gen, flags uint32), scratch func(string, uint16, uint8, uint8, uint32)) {
	t.Helper()
	counts := func() PlaneCounts {
		t.Helper()
		var c PlaneCounts
		if err := coll.Maps[MapPlaneCounters].Lookup(runIdx, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	ro := strconv.Itoa(unix.O_RDONLY)
	for _, h := range []struct {
		name string
		gen  uint32
	}{{"cleared", 0}, {"another run's", gen + 1}} {
		setSlot(h.gen, PlaneSlotExecDecides)
		before := counts()
		for _, c := range []planeCell{
			{h.name + " header: exec an allowed file", []string{"exec", filepath.Join(tree.e, "t1")}, eacces},
			{h.name + " header: exec with the exec flag clear", []string{"exec", tree.trueBin}, eacces},
			{h.name + " header: read under a nested deny_read", []string{"open", ro, filepath.Join(tree.w, "secret/f")}, eacces},
			{h.name + " header: read in a write entry", []string{"open", ro, filepath.Join(tree.w, "f")}, eacces},
		} {
			if got := helper.do(t, c.args...); got != c.want {
				t.Errorf("%s: in the run %v answered %s, want %s", c.name, c.args, got, c.want)
			}
		}
		scratch(h.name+" header: the read's record", 1, 1, uint8(ReasonPathUnresolved), uint32(PlaneRuleNone))
		if after := counts(); after.NoRows < before.NoRows+4 {
			t.Errorf("%s header: norows %d -> %d, want every refusal counted", h.name, before.NoRows, after.NoRows)
		}
	}
	setSlot(gen, PlaneSlotExecDecides)
	if got := helper.do(t, "open", ro, filepath.Join(tree.w, "f")); got != "0" {
		t.Errorf("the run's own header back: a read in a write entry answered %s", got)
	}
}

// planeAnonExecCells is bprm_check's unhashed-image arm (R9's exec.anonymous; tego_is_anonymous's d_hash.pprev
// half, which a memfd's own-parent dentry never reaches): an image whose name was dropped after it was opened, by
// unlink and as an O_TMPFILE, is refused without exec.anonymous and runs with it. Its file lives on a tmpfs below a
// write row, so the helper's own create is allowed. The refusal is the exec'd child's, whose scratch value the test
// cannot name; the recorder cells (observe's TestIntegrationPlaneRefusalIsOneLine) assert its line. It leaves the
// header at exec.anonymous set.
func planeAnonExecCells(t *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper, tree *planeTree,
	setSlot func(gen, flags uint32)) {
	t.Helper()
	const ruleAnon = 14
	dir := t.TempDir()
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount a tmpfs for the unlinked-image cells: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	p := &planeTree{tmpls: map[uint32]planeFillTmpl{}}
	p.hold(t, dir, fsRow(gen, ruleAnon, PlaneRowModifyAllow))
	planeFill(t, coll, runIdx, p)
	for _, how := range []string{"unlink", "tmpfile"} {
		setSlot(gen, PlaneSlotExecDecides)
		if got := helper.do(t, "execfd", tree.trueBin, dir, how); got != eacces {
			t.Errorf("exec of an unlinked image (%s) without exec.anonymous answered %s, want EACCES", how, got)
		}
		setSlot(gen, PlaneSlotExecDecides|PlaneSlotExecAnon)
		if got := helper.do(t, "execfd", tree.trueBin, dir, how); got != "0" {
			t.Errorf("exec of an unlinked image (%s) with exec.anonymous answered %s, want 0", how, got)
		}
	}
}

// planeChain is base with n more levels of "a" below it, made.
func planeChain(t *testing.T, base string, n int) string {
	t.Helper()
	p := base
	for range n {
		p = filepath.Join(p, "a")
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// planeDeepCells is enforce-plane R7's bound on a real kernel. Under a write row, a file TEGO_PLANE_WALK_MAX levels
// below it is decided by the row, and one a level deeper is refused path-unresolved and counted bound for every
// hook: the read too, which a walk that met no row would allow, so an exhausted walk that fell through to ROOT
// fails here. A mount crossing costs the walk no level (decide.PlaneRows.Find counts path components only), so a
// file 64 components below a row with a tmpfs between them is still the row's.
func planeDeepCells(t *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper,
	scratch func(string, uint16, uint8, uint8, uint32)) {
	t.Helper()
	const ruleDeep, ruleMnt = 12, 13
	root := t.TempDir()
	top, mtop := filepath.Join(root, "top"), filepath.Join(root, "mtop")
	at := planeChain(t, top, PlaneWalkMax-1) // at/f is PlaneWalkMax levels below top
	past := planeChain(t, at, 1)             // past/g is one more
	for _, f := range []string{filepath.Join(at, "f"), filepath.Join(past, "g"), filepath.Join(past, "u")} {
		mustWrite(t, f, []byte("x\n"), 0o644)
	}
	// mtop/a^30 is a tmpfs's mountpoint; inside it, 33 levels and a file: 30 + 33 + 1 = 64 components below mtop.
	mp := planeChain(t, mtop, 30)
	if err := unix.Mount("tmpfs", mp, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount a tmpfs for the crossing cell: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mp, unix.MNT_DETACH) })
	mat := planeChain(t, mp, PlaneWalkMax-1-30)
	mpast := planeChain(t, mat, 1)
	mustWrite(t, filepath.Join(mat, "f"), []byte("x\n"), 0o644)
	mustWrite(t, filepath.Join(mpast, "g"), []byte("x\n"), 0o644)

	p := &planeTree{tmpls: map[uint32]planeFillTmpl{}}
	p.hold(t, top, fsRow(gen, ruleDeep, PlaneRowModifyAllow))
	p.hold(t, mtop, fsRow(gen, ruleMnt, PlaneRowModifyAllow))
	planeFill(t, coll, runIdx, p)

	var before PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &before); err != nil {
		t.Fatal(err)
	}
	ro, wo := strconv.Itoa(unix.O_RDONLY), strconv.Itoa(unix.O_WRONLY)
	check := func(name string, want string, args ...string) {
		t.Helper()
		if got := helper.do(t, args...); got != want {
			t.Errorf("%s: in the run %v answered %s, want %s", name, args, got, want)
		}
	}
	unresolved := uint8(ReasonPathUnresolved)
	check("read 64 levels below a write row", "0", "open", ro, filepath.Join(at, "f"))
	check("write 64 levels below a write row", "0", "open", wo, filepath.Join(at, "f"))
	scratch("write 64 levels below a write row", 1, 0, 0, ruleDeep)
	check("link 64 levels below a write row", "0", "link", filepath.Join(at, "f"), filepath.Join(at, "l"))
	check("read 65 levels below a write row (bound)", eacces, "open", ro, filepath.Join(past, "g"))
	scratch("read 65 levels below a write row", 1, 1, unresolved, uint32(PlaneRuleNone))
	check("write 65 levels below a write row (bound)", eacces, "open", wo, filepath.Join(past, "g"))
	check("unlink 65 levels below a write row (bound)", eacces, "unlink", filepath.Join(past, "u"))
	scratch("unlink 65 levels below a write row", 5, 1, unresolved, uint32(PlaneRuleNone))
	check("rename from 65 levels below a write row (bound)", eacces, "rename", filepath.Join(past, "g"), filepath.Join(at, "g"))
	check("link from 65 levels below a write row (bound)", eacces, "link", filepath.Join(past, "g"), filepath.Join(at, "g"))
	check("write 64 components below a write row across a mount", "0", "open", wo, filepath.Join(mat, "f"))
	scratch("write 64 components below a write row across a mount", 1, 0, 0, ruleMnt)
	check("write 65 components below a write row across a mount (bound)", eacces, "open", wo, filepath.Join(mpast, "g"))

	var after PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &after); err != nil {
		t.Fatal(err)
	}
	// rename and link walk their source first and refuse at its bound: one count each.
	if got := after.Bound - before.Bound; got < 6 {
		t.Errorf("the bound refusals counted %d, want at least 6: %+v", got, after)
	}
	if after.Unresolved != before.Unresolved || after.Mismatch != before.Mismatch {
		t.Errorf("the deep cells counted other refusals: before %+v, after %+v", before, after)
	}
}

// holdLink is hold for a path's own inode, a final symlink not followed (PlaneRows.NoFollow's key: O_PATH|O_NOFOLLOW).
func (p *planeTree) holdLink(t *testing.T, path string, tmpl planeFillTmpl) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	p.keep(t, fd)
	p.tmpls[uint32(fd)] = tmpl
}

// planeSymlinkCells is enforce-plane R11's symlinked deny_write target on a real kernel: .git/hooks is a symlink to
// a directory elsewhere, and the rows decide.CompilePlane writes for it are the link's own inode (RenameRefused and
// Protected, held O_PATH|O_NOFOLLOW), the directory above it (.git, a rename-refused ancestor) and the resolved
// target (Protected, keyed following). Rename of the link (or of .git), a rename over it, and its unlink are
// refused, each decided by the link's row (rule ruleLink, not the target's ruleTarget: the row is at the link's own
// inode), and the target's files stay protected and reachable through the link.
func planeSymlinkCells(t *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper,
	scratch func(string, uint16, uint8, uint8, uint32)) {
	t.Helper()
	const ruleTop, ruleDotGit, ruleLink, ruleReal, ruleTarget = 15, 16, 17, 18, 19
	root := t.TempDir()
	top, real := filepath.Join(root, "top"), filepath.Join(root, "real")
	target := filepath.Join(real, "hooks")
	link := filepath.Join(top, ".git", "hooks")
	for _, d := range []string{filepath.Join(top, ".git"), target, filepath.Join(top, "repl")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(target, "pre-commit"), []byte("x\n"), 0o755)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	p := &planeTree{tmpls: map[uint32]planeFillTmpl{}}
	p.hold(t, top, fsRow(gen, ruleTop, PlaneRowModifyAllow))
	p.hold(t, filepath.Join(top, ".git"), fsRow(gen, ruleDotGit, PlaneRowModifyAllow|PlaneRowRenameRefused))
	p.holdLink(t, link, fsRow(gen, ruleLink, PlaneRowRenameRefused|PlaneRowProtected))
	p.hold(t, real, fsRow(gen, ruleReal, PlaneRowModifyAllow))
	p.hold(t, target, fsRow(gen, ruleTarget, PlaneRowRenameRefused|PlaneRowProtected))
	planeFill(t, coll, runIdx, p)

	wo := strconv.Itoa(unix.O_WRONLY)
	check := func(name, want string, args ...string) {
		t.Helper()
		if got := helper.do(t, args...); got != want {
			t.Errorf("%s: in the run %v answered %s, want %s", name, args, got, want)
		}
	}
	ancestor := uint8(ReasonDenyWriteAncestor)
	check("write to the target's file through the link", eacces, "open", wo, filepath.Join(link, "pre-commit"))
	scratch("write to the target's file through the link", 1, 1, uint8(ReasonWriteOutsideContract), ruleTarget)
	check("write to the target's file directly", eacces, "open", wo, filepath.Join(target, "pre-commit"))
	check("unlink the link", eacces, "unlink", link)
	scratch("unlink the link", 5, 1, uint8(ReasonDeleteOutsideContract), ruleLink)
	check("rename the link away", eacces, "rename", link, filepath.Join(top, ".git", "hooks.old"))
	scratch("rename the link away", 3, 1, ancestor, ruleLink)
	check("rename a directory over the link", eacces, "rename", filepath.Join(top, "repl"), link)
	scratch("rename a directory over the link", 3, 1, ancestor, ruleLink)
	check("rename .git, which holds the link", eacces, "rename", filepath.Join(top, ".git"), filepath.Join(top, ".git.old"))
	scratch("rename .git, which holds the link", 3, 1, ancestor, ruleDotGit)
	// Every refusal left the link and the target as they were.
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Errorf("the link is now %q, %v: a refused action changed it", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(link, "pre-commit")); err != nil || string(b) != "x\n" {
		t.Errorf("the target's file through the link: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(top, "repl")); err != nil {
		t.Errorf("the directory renamed over the link is gone: %v", err)
	}
}

// planeOverlayCell writes to overlayfs files whose layers lie where no row is: the user's open is decided on the
// merged file (a write row), and the kernel's own opens are skipped: the backing open of an upper file
// (FMODE_BACKING, 6.6+, R8), and the copy-up's plain open of the new upper file and of the lower one on overlayfs'
// private clones of the layers' mounts (mnt_ns MNT_NS_INTERNAL; enforce-plane §2.7's condition 1, settled at T13),
// which before T13 refused every write to a lower file under a write row as an unmatched modification. keeper, the
// test whose gen the rows are written at, keeps the holds, so the merged root they key outlives this subtest.
func planeOverlayCell(t, keeper *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper) {
	t.Helper()
	root := t.TempDir()
	lower, upper, work, merged := filepath.Join(root, "l"), filepath.Join(root, "u"), filepath.Join(root, "wk"), filepath.Join(root, "m")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(upper, "uf"), []byte("x\n"), 0o644)
	mustWrite(t, filepath.Join(lower, "lf"), []byte("lower\n"), 0o644)
	opts := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Skipf("no overlayfs here (%v): the backing-open cell cannot run; the guest loads it with VM_MODULES=overlay", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
	p := &planeTree{tmpls: map[uint32]planeFillTmpl{}, keeper: keeper}
	p.hold(t, merged, fsRow(gen, ruleW, PlaneRowModifyAllow))
	planeFill(t, coll, runIdx, p)
	if got := helper.do(t, "open", strconv.Itoa(unix.O_WRONLY), filepath.Join(merged, "uf")); got != "0" {
		t.Errorf("a write to an overlay file under a write row answered %s: the backing open was decided", got)
	}
	if got := helper.do(t, "open", strconv.Itoa(unix.O_WRONLY), filepath.Join(merged, "lf")); got != "0" {
		t.Errorf("a write to a lower overlay file under a write row answered %s: the copy-up's own open was decided", got)
	}
	if _, err := os.Stat(filepath.Join(upper, "lf")); err != nil {
		t.Errorf("the lower file was not copied up: %v", err)
	}
	p = &planeTree{tmpls: map[uint32]planeFillTmpl{}, keeper: keeper}
	p.hold(t, merged, fsRow(gen, ruleW, 0))
	planeFill(t, coll, runIdx, p)
	mustWrite(t, filepath.Join(lower, "lf2"), []byte("lower\n"), 0o644)
	if got := helper.do(t, "open", strconv.Itoa(unix.O_WRONLY), filepath.Join(merged, "lf2")); got != eacces {
		t.Errorf("a write to a lower overlay file under a row that refuses modifications answered %s, want EACCES", got)
	}
}

// planeDisconnectedCell is enforce-plane R7's disconnected root on a real kernel: a file opened by handle
// (open_by_handle_at) after the dentry cache was dropped gets a dentry no path reaches (DCACHE_DISCONNECTED: it is its
// own parent and not its mount's root), so the walk climbs no row and refuses path-unresolved and counts it, where a
// walk that took "no row" for "allowed" would let the read through; the same file by its path is the row's. It needs
// an overlayfs exported for handles (nfs_export=on, over tmpfs layers), whose dentries the cache drops. The handle's
// file is a new overlayfs inode, which the slab may put where a freed one was: the overlay cell's merged root was
// one, keyed by a row of this gen, which is why keeper holds that root, and this cell's root as well.
func planeDisconnectedCell(t, keeper *testing.T, coll *ebpf.Collection, runIdx, gen uint32, helper *planeHelper,
	scratch func(string, uint16, uint8, uint8, uint32)) {
	t.Helper()
	const ruleDisc = 20
	root := t.TempDir()
	if err := unix.Mount("tmpfs", root, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount a tmpfs for the layers: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(root, unix.MNT_DETACH) })
	dirs := map[string]string{}
	for _, d := range []string{"l", "u", "wk", "m"} {
		dirs[d] = filepath.Join(root, d)
		if err := os.Mkdir(dirs[d], 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(dirs["l"], "lf"), []byte("lower\n"), 0o644)
	opts := "lowerdir=" + dirs["l"] + ",upperdir=" + dirs["u"] + ",workdir=" + dirs["wk"] + ",index=on,nfs_export=on"
	if err := unix.Mount("overlay", dirs["m"], "overlay", 0, opts); err != nil {
		t.Skipf("no overlayfs exported for handles here (%v): the disconnected-dentry cell cannot run", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dirs["m"], unix.MNT_DETACH) })
	file := filepath.Join(dirs["m"], "lf")
	fh, _, err := unix.NameToHandleAt(unix.AT_FDCWD, file, 0)
	if err != nil {
		t.Skipf("no file handle for an overlayfs file (%v): the disconnected-dentry cell cannot run", err)
	}
	arg := []string{strconv.Itoa(int(fh.Type())), hex.EncodeToString(fh.Bytes())}
	drop := func() {
		t.Helper()
		if err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o200); err != nil {
			t.Fatalf("drop the dentry cache: %v", err)
		}
	}
	// Outside the run the handle opens: it is not stale, and the plane decides nothing for this process.
	drop()
	mfd, err := unix.Open(dirs["m"], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.OpenByHandleAt(mfd, fh, unix.O_RDONLY|unix.O_CLOEXEC)
	_ = unix.Close(mfd)
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
		t.Skipf("open_by_handle_at of an overlayfs file: %v: the cell cannot run", err)
	} else if err != nil {
		t.Fatalf("open_by_handle_at of an overlayfs file after drop_caches: %v", err)
	}
	_ = unix.Close(fd)

	p := &planeTree{tmpls: map[uint32]planeFillTmpl{}, keeper: keeper}
	p.hold(t, dirs["m"], fsRow(gen, ruleDisc, PlaneRowModifyAllow))
	planeFill(t, coll, runIdx, p)
	var before PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &before); err != nil {
		t.Fatal(err)
	}
	ro := strconv.Itoa(unix.O_RDONLY)
	if got := helper.do(t, "open", ro, file); got != "0" {
		t.Errorf("read of the file by path under a write row answered %s, want 0", got)
	}
	drop()
	if got := helper.do(t, "openhandle", ro, dirs["m"], arg[0], arg[1]); got != eacces {
		t.Errorf("read of a disconnected dentry (open_by_handle_at after drop_caches) answered %s, want EACCES", got)
	}
	scratch("read of a disconnected dentry", 1, 1, uint8(ReasonPathUnresolved), uint32(PlaneRuleNone))
	var after PlaneCounts
	if err := coll.Maps[MapPlaneCounters].Lookup(uint32(runIdx), &after); err != nil {
		t.Fatal(err)
	}
	if after.Unresolved-before.Unresolved != 1 || after.Bound != before.Bound || after.Mismatch != before.Mismatch {
		t.Errorf("the disconnected read counted before %+v, after %+v, want one unresolved", before, after)
	}
}

// planeChildCgroup makes a cgroup under this process's own and returns its path, an O_PATH descriptor for
// CLONE_INTO_CGROUP and its id.
func planeChildCgroup(t *testing.T, suffix string) (string, int, uint64) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var rel string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			rel = p
		}
	}
	if rel == "" {
		t.Fatal("not on a cgroup v2 hierarchy")
	}
	dir := filepath.Join("/sys/fs/cgroup", rel, "tego-plane-test-"+strconv.Itoa(os.Getpid())+"-"+suffix)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("make a child cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	return dir, fd, st.Ino
}

// planeACLValue is a POSIX ACL equivalent to mode 0644 in its xattr form (version 2; user::rw-, group::r--,
// other::r--): what setfacl writes to system.posix_acl_access.
var planeACLValue = []byte{
	2, 0, 0, 0,
	0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
	0x04, 0, 4, 0, 0xff, 0xff, 0xff, 0xff,
	0x20, 0, 4, 0, 0xff, 0xff, 0xff, 0xff,
}

// planeHelperHeld are descriptors the helper opened on command and keeps for a later one (ftruncate of a file opened
// before the run was armed).
var planeHelperHeld = map[string]int{}

// planeHelperStepB answers step B's commands: creates, truncates, attribute changes, sockets (socket(2) and
// io_uring's IORING_OP_SOCKET), a stat, and the TOCTOU loops.
func planeHelperStepB(f []string) (string, bool) {
	switch f[0] {
	case "mkdir":
		return errnoString(unix.Mkdir(f[1], 0o755)), true
	case "mknod":
		return errnoString(unix.Mknod(f[1], unix.S_IFIFO|0o644, 0)), true
	case "symlink":
		return errnoString(unix.Symlink(f[1], f[2])), true
	case "truncate":
		return errnoString(unix.Truncate(f[1], 0)), true
	case "hold":
		fd, err := unix.Open(f[1], unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			planeHelperHeld[f[1]] = fd
		}
		return errnoString(err), true
	case "ftruncate":
		fd, ok := planeHelperHeld[f[1]]
		if !ok {
			return "err not held", true
		}
		return errnoString(unix.Ftruncate(fd, 0)), true
	case "chmod":
		mode, _ := strconv.ParseUint(f[2], 8, 32)
		return errnoString(unix.Chmod(f[1], uint32(mode))), true
	case "chown":
		return errnoString(unix.Chown(f[1], -1, -1)), true
	case "setxattr":
		return errnoString(unix.Setxattr(f[1], f[2], []byte("1"), 0)), true
	case "removexattr":
		return errnoString(unix.Removexattr(f[1], f[2])), true
	case "uring-setxattr-personality":
		// The personality holds this thread's credentials from before setgroups replaced them (with the same groups),
		// so the worker issues the entry with credentials that are not its own.
		res, err := uring.SetxattrPersonality(f[1], f[2], []byte("1"), func() error {
			groups, err := unix.Getgroups()
			if err != nil {
				return err
			}
			return unix.Setgroups(groups)
		})
		if err != nil {
			return "err " + err.Error(), true
		}
		return strconv.Itoa(int(-res)), true
	case "setacl":
		return errnoString(unix.Setxattr(f[1], "system.posix_acl_access", planeACLValue, 0)), true
	case "removeacl":
		return errnoString(unix.Removexattr(f[1], "system.posix_acl_access")), true
	case "stat":
		var st unix.Stat_t
		return errnoString(unix.Lstat(f[1], &st)), true
	case "setsockopt", "uring-setsockopt":
		// setsockopt LEVEL OPTNAME HEXVALUE OPTLEN [MODE] on a fresh AF_INET TCP socket: "<errno> <SO_DOMAIN after>",
		// the family the socket ended with (ADR 0018 (7): TCP_ULP "smc" turned it into AF_SMC, 43).
		level, _ := strconv.Atoi(f[1])
		optname, _ := strconv.Atoi(f[2])
		val, err := hex.DecodeString(f[3])
		if err != nil || len(val) == 0 {
			return "err value " + f[3], true
		}
		optlen, _ := strconv.Atoi(f[4])
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return "err socket " + errnoString(err), true
		}
		defer unix.Close(fd)
		var answer string
		if f[0] == "setsockopt" {
			_, _, en := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(optname),
				uintptr(unsafe.Pointer(&val[0])), uintptr(optlen), 0)
			runtime.KeepAlive(val)
			answer = strconv.Itoa(int(en))
		} else {
			mode, err := uring.ParseMode(f[5])
			if err != nil {
				return "err " + err.Error(), true
			}
			res, err := uring.Setsockopt(mode, fd, level, optname, val, optlen)
			if err != nil {
				return "err " + err.Error(), true
			}
			answer = strconv.Itoa(int(-res))
		}
		domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			return answer + " err " + errnoString(err), true
		}
		return answer + " " + strconv.Itoa(domain), true
	case "socket", "uring-socket":
		var n [3]int
		for i := range n {
			n[i], _ = strconv.Atoi(f[1+i])
		}
		if f[0] == "socket" {
			fd, err := unix.Socket(n[0], n[1]|unix.SOCK_CLOEXEC, n[2])
			if err == nil {
				_ = unix.Close(fd)
			}
			return errnoString(err), true
		}
		res, err := uring.Socket(n[0], n[1], n[2])
		if err != nil {
			return "err " + err.Error(), true
		}
		return strconv.Itoa(int(-res)), true
	case "chmodloop", "truncloop":
		// Count the answers of n tries through a name another thread keeps repointing (the TOCTOU cells).
		n, _ := strconv.Atoi(f[2])
		ok, refused, other := 0, 0, 0
		for range n {
			var err error
			if f[0] == "chmodloop" {
				err = unix.Chmod(f[1], 0o600)
			} else {
				err = unix.Truncate(f[1], 0)
			}
			switch {
			case err == nil:
				ok++
			case errors.Is(err, unix.EACCES):
				refused++
			default:
				other++
			}
		}
		return fmt.Sprintf("ok=%d refused=%d other=%d", ok, refused, other), true
	}
	return "", false
}

// planeStepBCells is TIER3-PLAN T13's cells (enforce-plane R12, R13, R14) on the tree and slot planeCells filled:
// every create hook refuses under a row that refuses modifications and leaves no file, and passes in a write
// entry; truncate by path and by a descriptor opened before the run refuses on a deny_write target; chmod, chown,
// the xattr hooks and setfacl refuse beneath the deny_write target only (a write entry, no entry and a deny_read
// pass); a tmpfs mounted below the target is protected through its mounted root's row, which the crossing walk
// passes; a corrupted row fails the attribute walk closed; socket_create refuses a family outside ADR 0018's
// allowlist under a net: section, by socket(2) and by io_uring, and passes it without one; and a thread repointing
// a symlink during chmod and truncate never gets the deny_write target changed (the TOCTOU cells).
func planeStepBCells(t *testing.T, coll *ebpf.Collection, mode PlaneMode, runIdx, gen uint32, helper *planeHelper,
	tree *planeTree, arm func(uint32), setSlot func(gen, flags uint32),
	scratch func(string, uint16, uint8, uint8, uint32)) {
	t.Helper()
	w := func(p string) string { return filepath.Join(tree.w, p) }
	check := func(name string, want string, args ...string) {
		t.Helper()
		if got := helper.do(t, args...); got != want {
			t.Errorf("%s: in the run %v answered %s, want %s", name, args, got, want)
		}
	}
	absent := func(name, path string) {
		t.Helper()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %s exists after the refused create (%v): a refused create leaves no file (R13)", name, path, err)
		}
	}
	hook := func(name string) uint16 {
		for i, h := range PlaneHooks {
			if h.Name == name {
				return uint16(i + 1)
			}
		}
		t.Fatalf("no hook %s", name)
		return 0
	}
	create := strconv.Itoa(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL)

	// Creates (R13): path_mknod runs in may_o_create, before the O_CREAT open makes its inode.
	check("O_CREAT under deny_read", eacces, "open", create, w("secret/new"))
	absent("O_CREAT under deny_read", w("secret/new"))
	scratch("O_CREAT under deny_read", hook("path_mknod"), 1, uint8(ReasonWriteOutsideContract), ruleSecret)
	check("O_CREAT in a deny_write target", eacces, "open", create, w(".git/hooks/new2"))
	absent("O_CREAT in a deny_write target", w(".git/hooks/new2"))
	check("O_CREAT with no entry", eacces, "open", create, filepath.Join(tree.o, "new"))
	absent("O_CREAT with no entry", filepath.Join(tree.o, "new"))
	check("O_CREAT in a write entry", "0", "open", create, w("new-b"))
	check("mkdir under deny_read", eacces, "mkdir", w("secret/sub"))
	absent("mkdir under deny_read", w("secret/sub"))
	scratch("mkdir under deny_read", hook("path_mkdir"), 1, uint8(ReasonMkdirOutsideContract), ruleSecret)
	check("mkdir in a write entry", "0", "mkdir", w("sub-b"))
	check("mknod under deny_read", eacces, "mknod", w("secret/fifo"))
	absent("mknod under deny_read", w("secret/fifo"))
	check("mknod in a write entry", "0", "mknod", w("fifo-b"))
	check("symlink in a deny_write target", eacces, "symlink", "x", w(".git/hooks/lnk"))
	absent("symlink in a deny_write target", w(".git/hooks/lnk"))
	scratch("symlink in a deny_write target", hook("path_symlink"), 1, uint8(ReasonWriteOutsideContract), ruleHooks)
	check("symlink in a write entry", "0", "symlink", "x", w("lnk-b"))
	if err := unix.Mkdir(w("secret/sub"), 0o755); err != nil {
		t.Errorf("mkdir under deny_read outside the run: %v", err)
	}

	// Truncates (R13).
	check("truncate a deny_write target's file", eacces, "truncate", w(".git/hooks/h2"))
	scratch("truncate a deny_write target's file", hook("path_truncate"), 1, uint8(ReasonWriteOutsideContract), ruleHooks)
	check("truncate in a write entry", "0", "truncate", w("f6"))
	// A descriptor opened before the run was armed: ftruncate reaches file_truncate (6.2+) or path_truncate.
	if err := coll.Maps[MapRunSet].Delete(planeHelperCgroup(t, helper)); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	check("open a deny_write target's file before the run", "0", "hold", w(".git/hooks/h3"))
	arm(gen)
	check("ftruncate a descriptor opened before the run", eacces, "ftruncate", w(".git/hooks/h3"))
	for _, f := range []string{".git/hooks/h2", ".git/hooks/h3"} {
		if b, err := os.ReadFile(w(f)); err != nil || string(b) != "x\n" {
			t.Errorf("%s after the refused truncates: %q, %v", f, b, err)
		}
	}

	// Attribute changes (R12): deny_write protection only.
	target := w(".git/hooks/pre-commit")
	check("chmod a deny_write target's file", eacces, "chmod", target, "600")
	scratch("chmod a deny_write target's file", hook("path_chmod"), 1, uint8(ReasonWriteOutsideContract), ruleHooks)
	check("chown a deny_write target's file", eacces, "chown", target)
	check("chmod the deny_write target itself", eacces, "chmod", w(".git/hooks"), "700")
	check("chmod in a write entry", "0", "chmod", w("attr"), "600")
	check("chmod with no entry (Landlock governs no chmod)", "0", "chmod", filepath.Join(tree.o, "f"), "600")
	check("chmod under deny_read (not a deny_write target)", "0", "chmod", w("secret/f"), "600")
	check("chmod above the target (.git)", "0", "chmod", w(".git"), "755")
	check("chmod under a row whose identity is gone", eacces, "chmod", w("bad/f"), "600")
	if err := unix.Setxattr(w("attr"), "user.tego", []byte("1"), 0); err != nil {
		t.Logf("user xattrs are not supported here (%v): the xattr cells are not run", err)
	} else {
		check("setxattr on a deny_write target's file", eacces, "setxattr", target, "user.tego")
		scratch("setxattr on a deny_write target's file", hook("inode_setxattr"), 1, uint8(ReasonWriteOutsideContract), ruleHooks)
		check("setxattr in a write entry", "0", "setxattr", w("f"), "user.tego")
		if err := unix.Setxattr(target, "user.tego", []byte("1"), 0); err != nil {
			t.Fatalf("setxattr outside the run: %v", err)
		}
		check("removexattr on a deny_write target's file", eacces, "removexattr", target, "user.tego")
		check("removexattr in a write entry", "0", "removexattr", w("f"), "user.tego")
		// NET09's capability floor precedes the inode hook for trusted.*.
		// Keep that negative control separate from the filesystem row checks.
		if err := unix.Setxattr(w("attr"), "trusted.tego", []byte("1"), 0); err == nil {
			check("trusted xattr needs the refused CAP_SYS_ADMIN", "1", "setxattr", w("attr"), "trusted.tego")
			check("trusted xattr removal needs the refused CAP_SYS_ADMIN", "1", "removexattr", w("attr"), "trusted.tego")
			// A registered io_uring personality is an override_creds window userspace chose: the floor holds there,
			// unlike for a filesystem's own backing work (ADR 0055's CI portability amendment).
			switch got := helper.do(t, "uring-setxattr-personality", w("attr"), "trusted.tego"); {
			case strings.HasPrefix(got, "err ") || got == strconv.Itoa(int(unix.EINVAL)):
				t.Logf("no io_uring IORING_OP_SETXATTR under a personality here (%s): that floor cell is not run", got)
			case got != "1":
				t.Errorf("a trusted xattr set by an io-wq worker under a registered personality answered %s, want EPERM (1)", got)
			}
		}
	}
	if err := unix.Setxattr(w("attr"), "system.posix_acl_access", planeACLValue, 0); err != nil {
		t.Logf("POSIX ACLs are not supported here (%v): the setfacl cells are not run", err)
	} else {
		check("setfacl on a deny_write target's file", eacces, "setacl", target)
		check("remove an ACL on a deny_write target's file", eacces, "removeacl", target)
		check("setfacl in a write entry", "0", "setacl", w("f"))
	}
	var st unix.Stat_t
	if err := unix.Stat(target, &st); err != nil || st.Mode&0o7777 != 0o644 {
		t.Errorf("the deny_write target's file after the refused changes: mode %o, %v", st.Mode&0o7777, err)
	}
	for _, c := range []struct{ name, cmd string }{{"chmod", "chmod"}, {"chown", "chown"}} {
		args := []string{c.cmd, target}
		if c.cmd == "chmod" {
			args = append(args, "644")
		}
		if got := helper.do(t, args...); got != eacces {
			t.Errorf("%s again: %s", c.name, got)
		}
	}

	// A tmpfs mounted below the deny_write target: the attribute walk stays in the tmpfs and meets its mounted
	// root's row (TEGO_ROW_MOUNT_ONLY); the crossing walk passes that row and meets the target's above the mount.
	mnt := w(".git/hooks/mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Logf("no tmpfs mount here (%v): the mounted-root cells are not run", err)
	} else {
		t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
		mustWrite(t, filepath.Join(mnt, "m"), []byte("x\n"), 0o644)
		check("chmod on a tmpfs below the target, no mounted-root row", "0", "chmod", filepath.Join(mnt, "m"), "600")
		p := &planeTree{tmpls: map[uint32]planeFillTmpl{}}
		// The mount row allows modifications, which no compiled mount row does: a refused write-open below proves
		// the crossing walk passed it.
		p.hold(t, mnt, fsRow(gen, ruleHooks, PlaneRowProtected|PlaneRowModifyAllow|PlaneRowMountOnly))
		planeFill(t, coll, runIdx, p)
		check("chmod on a tmpfs below the target", eacces, "chmod", filepath.Join(mnt, "m"), "644")
		check("chown on a tmpfs below the target", eacces, "chown", filepath.Join(mnt, "m"))
		check("write on a tmpfs below the target (the crossing walk passes the mount row)", eacces,
			"open", strconv.Itoa(unix.O_WRONLY), filepath.Join(mnt, "m"))
	}

	// socket_create (R14; ADR 0018 (5)).
	vsock, inet, stream, dgram, raw := strconv.Itoa(unix.AF_VSOCK), strconv.Itoa(unix.AF_INET), strconv.Itoa(unix.SOCK_STREAM),
		strconv.Itoa(unix.SOCK_DGRAM), strconv.Itoa(unix.SOCK_RAW)
	notPlane := func(name string, args ...string) {
		t.Helper()
		if got := helper.do(t, args...); got == eacces {
			t.Errorf("%s: %v refused with EACCES; the plane decides no socket without a net: section", name, args)
		}
	}
	notPlane("AF_VSOCK with no net: section", "socket", vsock, stream, "0")
	setSlot(gen, PlaneSlotExecDecides|PlaneSlotNetDecides)
	check("AF_VSOCK under a net: section", eacces, "socket", vsock, stream, "0")
	scratch("AF_VSOCK under a net: section", hook("socket_create"), 1, uint8(ReasonNetNotAllowed), uint32(PlaneRuleNone))
	check("a TCP socket under a net: section", "0", "socket", inet, stream, "0")
	check("a UDP socket under a net: section", "0", "socket", inet, dgram, "0")
	check("a raw socket under a net: section", eacces, "socket", inet, raw, "1")
	check("an SCTP stream socket under a net: section", eacces, "socket", inet, stream, "132")
	check("a unix socket under a net: section", "0", "socket", strconv.Itoa(unix.AF_UNIX), stream, "0")
	check("a route netlink socket under a net: section", "0", "socket", strconv.Itoa(unix.AF_NETLINK), raw, strconv.Itoa(unix.NETLINK_ROUTE))
	check("a generic netlink socket under a net: section", eacces, "socket", strconv.Itoa(unix.AF_NETLINK), raw, strconv.Itoa(unix.NETLINK_GENERIC))
	check("a sock_diag netlink socket under a net: section", eacces, "socket", strconv.Itoa(unix.AF_NETLINK), raw, strconv.Itoa(unix.NETLINK_SOCK_DIAG))
	if res, err := uring.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); err != nil || res == -int32(unix.EINVAL) {
		t.Logf("no io_uring IORING_OP_SOCKET here (%d, %v): the io_uring cells are not run", res, err)
	} else {
		check("io_uring AF_VSOCK under a net: section", eacces, "uring-socket", vsock, stream, "0")
		check("io_uring TCP under a net: section", "0", "uring-socket", inet, stream, "0")
		if res, err := uring.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0); err != nil || res == -int32(unix.EACCES) {
			t.Errorf("io_uring AF_VSOCK outside the run: %d, %v", res, err)
		}
	}
	setSlot(gen, PlaneSlotExecDecides)
	notPlane("AF_VSOCK with the header's net flag clear", "socket", vsock, stream, "0")

	// TOCTOU (§6 E8): a symlink repointed during the decisions between a write entry's file and the deny_write
	// target's; every decision is on the object the kernel resolved, so the target never changes.
	lnk := w("toctou")
	if err := os.Symlink(w("f5"), lnk); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	swapped := make(chan int)
	go func() {
		n := 0
		defer func() { swapped <- n }()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			dst := w("f5")
			if i%2 == 1 {
				dst = target
			}
			tmp := lnk + ".tmp"
			_ = os.Remove(tmp)
			if os.Symlink(dst, tmp) == nil && os.Rename(tmp, lnk) == nil {
				n++
			}
		}
	}()
	chmods := helper.do(t, "chmodloop", lnk, "3000")
	truncs := helper.do(t, "truncloop", lnk, "3000")
	close(stop)
	n := <-swapped
	t.Logf("TOCTOU: %d swaps; chmod %s; truncate %s", n, chmods, truncs)
	if err := unix.Stat(target, &st); err != nil || st.Mode&0o7777 != 0o644 {
		t.Errorf("TOCTOU: the deny_write target's mode after the races: %o, %v", st.Mode&0o7777, err)
	}
	if after, err := os.ReadFile(target); err != nil || string(after) != string(before) {
		t.Errorf("TOCTOU: the deny_write target's content after the races: %q, %v", after, err)
	}
	if !strings.Contains(chmods, "refused=") || strings.Contains(chmods, "refused=0 ") && strings.Contains(truncs, "refused=0 ") {
		t.Logf("TOCTOU: no decision landed on the target this time (%s, %s); the target's state is what the cell asserts", chmods, truncs)
	}
	_ = mode
}

// planeHelperCgroup is the run-set key of the helper's cgroup: its cgroup id, read from its /proc entry.
func planeHelperCgroup(t *testing.T, h *planeHelper) uint64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", h.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			var st unix.Stat_t
			if err := unix.Stat(filepath.Join("/sys/fs/cgroup", p), &st); err != nil {
				t.Fatal(err)
			}
			return st.Ino
		}
	}
	t.Fatal("the helper is on no cgroup v2 hierarchy")
	return 0
}
