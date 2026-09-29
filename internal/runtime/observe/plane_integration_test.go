// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"bufio"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// planeChildEnv makes the test binary planeChild: the base directory its actions are under. planeChildSetEnv
// "fallback" makes it take planeFallbackActions instead of planeActions.
const (
	planeChildEnv    = "TEGO_OBSERVE_PLANE_CHILD"
	planeChildSetEnv = "TEGO_OBSERVE_PLANE_SET"
)

func init() {
	if base := os.Getenv(planeChildEnv); base != "" {
		os.Exit(planeChild(base))
	}
}

// planeActions are planeChild's actions, in order: each an operation and its paths relative to the base.
var planeActions = []struct{ name, op, a, b string }{
	{"read-denied", "read", "w/s/k", ""},
	{"rename-out", "rename", "w/s/k", "w/k2"},
	{"mv-git", "rename", "w/.git", "w/.git.old"},
	{"unlink-denied", "unlink", "w/s/k", ""},
	{"write-outside", "write", "o/f", ""},
	{"exec-unlisted", "exec", "o/t3", ""},
	{"exec-dir", "exec", "tools/x", ""},
	{"exec-file", "exec", "bin/t", ""},
	{"link-out", "link", "w/s/k", "w/l1"},
	{"rmdir-denied", "rmdir", "w/s/d", ""},
	{"trunc-deny-write", "trunc", "w/.git/hooks/pre-commit", ""},
	{"exec-hardlink", "exec", "bin/t2", ""},
	{"exec-loader", "loader", "bin/t", ""},
	{"exec-memfd", "memfd", "bin/t", ""},
	{"read-bad-identity", "read", "w/bad/k", ""},
	{"read-deep", "read", deepRel, ""},
}

// planeFallbackActions are planeChild's actions for TestIntegrationPlaneFallbackIsOneLine: a refusal on each hook
// a recorder fexit wraps, step A's (file_open, rename, link, unlink, rmdir) and step B's (mknod through an O_CREAT
// open, mkdir, symlink, truncate, and ftruncate of a descriptor opened before the run was armed), and an unlisted
// exec for the exec sample beside them.
var planeFallbackActions = []struct{ name, op, a, b string }{
	{"read-denied", "read", "w/s/k", ""},
	{"rename-out", "rename", "w/s/k", "w/k2"},
	{"mv-git", "rename", "w/.git", "w/.git.old"},
	{"link-out", "link", "w/s/k", "w/k3"},
	{"unlink-denied", "unlink", "w/s/k", ""},
	{"rmdir-denied", "rmdir", "w/s/d", ""},
	{"write-outside", "write", "o/f", ""},
	{"creat-denied", "creat", "w/s/n", ""},
	{"mkdir-denied", "mkdir", "w/s/m", ""},
	{"symlink-denied", "symlink", "w/s/l", "k"},
	{"truncate-denied", "truncate", "w/s/k", ""},
	{"ftruncate-outside", "ftruncate", "o/f", ""},
	{"exec-unlisted", "exec", "o/t3", ""},
}

// deepRel is a file 65 levels below the write entry w: the plane's walk refuses it path-unresolved (R7's bound of
// 64), which a walk that met no row would have let through as a read.
var deepRel = "w/" + strings.Repeat("a/", 64) + "f"

// planeLoaderEnv names the dynamic loader planeChild runs directly for its exec-loader action; empty when the
// program is static and the action is skipped.
const planeLoaderEnv = "TEGO_OBSERVE_PLANE_LOADER"

// planeChild is the agent of TestIntegrationPlaneRefusalIsOneLine and TestIntegrationPlaneFallbackIsOneLine: it
// opens o/f for writing (ftruncate's descriptor) and says ready before the run is armed, waits for a line on stdin (the run is
// armed after its own exec, as a real run's is), makes its actions and prints each one's errno on stdout, a pipe,
// which no plane row decides. An exec's child inherits stdout and opens nothing to write.
func planeChild(base string) int {
	p := func(rel string) string { return filepath.Join(base, rel) }
	held, _ := unix.Open(p("o/f"), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	fmt.Println("ready") // the parent arms the run only after this line
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		return 2
	}
	actions := planeActions
	if os.Getenv(planeChildSetEnv) == "fallback" {
		actions = planeFallbackActions
	}
	for _, a := range actions {
		var err error
		switch a.op {
		case "link":
			err = unix.Link(p(a.a), p(a.b))
		case "rmdir":
			err = unix.Rmdir(p(a.a))
		case "creat":
			err = openClose(p(a.a), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)
		case "mkdir":
			err = unix.Mkdir(p(a.a), 0o755)
		case "symlink":
			err = unix.Symlink(a.b, p(a.a))
		case "truncate":
			err = unix.Truncate(p(a.a), 0)
		case "ftruncate":
			err = unix.Ftruncate(held, 0)
		case "read":
			err = openClose(p(a.a), unix.O_RDONLY, 0)
		case "write":
			err = openClose(p(a.a), unix.O_WRONLY, 0)
		case "rename":
			err = unix.Rename(p(a.a), p(a.b))
		case "unlink":
			err = unix.Unlink(p(a.a))
		case "trunc":
			err = openClose(p(a.a), unix.O_RDONLY|unix.O_TRUNC, 0)
		case "loader":
			loader := os.Getenv(planeLoaderEnv)
			if loader == "" {
				fmt.Printf("%s skipped\n", a.name)
				continue
			}
			cmd := exec.Command(loader, p(a.a))
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			err = cmd.Run()
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				err = fmt.Errorf("exit %d", ee.ExitCode())
			}
		case "memfd":
			err = planeExecMemfd(p(a.a))
		case "exec":
			cmd := exec.Command(p(a.a))
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			err = cmd.Run()
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				err = fmt.Errorf("exit %d", ee.ExitCode())
			}
		}
		var errno unix.Errno
		switch {
		case err == nil:
		case errors.As(err, &errno):
		default:
			fmt.Printf("%s %s\n", a.name, strings.ReplaceAll(err.Error(), " ", "_"))
			continue
		}
		fmt.Printf("%s %d\n", a.name, int(errno))
	}
	return 0
}

// planeExecMemfd copies the program at src into a memfd and execs it by /proc/self/fd/3, an image no path names
// (exec.anonymous, which the fixture's exec: section does not set).
func planeExecMemfd(src string) error {
	bin, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fd, err := unix.MemfdCreate("tego-observe-plane", unix.MFD_CLOEXEC)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()
	if _, err := f.Write(bin); err != nil {
		return err
	}
	cmd := exec.Command("/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		err = fmt.Errorf("exit %d", ee.ExitCode())
	}
	return err
}

// planeFixture is the tree the child acts on: w a write entry holding a deny_read s/ and the deny_write target
// .git/hooks, o no entry, bin/t an exec file entry and tools/ an exec.allow directory, each executable a copy of
// true(1). Every row's path is held O_PATH for the test, as the run's Landlock domain holds it in a run.
func planeFixture(t *testing.T) (string, *agent.RuleTable, *decide.PlaneRows, map[string]int) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no true(1): %v", err)
	}
	bin, err := os.ReadFile(trueBin)
	if err != nil {
		t.Fatal(err)
	}
	for rel, data := range map[string][]byte{"w/f": []byte("x"), "w/s/k": []byte("x"), "w/.git/hooks/pre-commit": nil,
		"o/f": []byte("x"), "o/t3": bin, "tools/x": bin, "bin/t": bin, "w/bad/k": []byte("x"),
		deepRel: []byte("x")} {
		path := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := func(rel string) string { return filepath.Join(base, rel) }
	if err := os.Mkdir(p("w/s/d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// bin/t2 is a hard link of the exec entry's file that no entry names (a multi-call binary's other name).
	if err := os.Link(p("bin/t"), p("bin/t2")); err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Record: agent.RecordFull,
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: p("w"), Raw: "./w", Resolved: p("w"), Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: p("w/s"), Raw: "./w/s", Resolved: p("w/s")},
			{Kind: agent.FSDenyRead, Path: p("w/bad"), Raw: "./w/bad", Resolved: p("w/bad")},
		},
		DenyWrite: []agent.FSRule{{Kind: agent.FSDenyWrite, Path: p("w/.git/hooks"), Resolved: p("w/.git/hooks"), BuiltIn: true}},
		Exec: []agent.ExecRule{
			{Path: p("bin/t"), Resolved: p("bin/t"), Raw: "./bin/t", Basename: "t", Verdict: agent.VerdictAllow},
			{Path: p("tools"), Resolved: p("tools"), Raw: "./tools", IsDir: true, Verdict: agent.VerdictAllow},
		},
	}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]int{}
	for _, path := range rows.Keyed {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("hold %s: %v", path, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		held[path] = fd
	}
	return base, rt, rows, held
}

// fillSlot writes the rows into the slot's inner maps through the fill build that goes with plane (bpf/
// decide_fill.bpf.c, T4), unscoped, and checks every row was written. The fill declares three row outers, the fs rows,
// the exec rows and the Unix listener rows, each pinned by name, so a loader names all three as replacements (as
// newPlaneFiller does) and the slot gets an inner map in each, as Prepare gives it, though this fill writes no
// listener row: without the third the load fails with "pin by name: missing MapOptions.PinPath".
func fillSlot(t *testing.T, plane bpf.Object, coll *ebpf.Collection, slot, gen uint32, rows *decide.PlaneRows, held map[string]int) {
	t.Helper()
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{bpf.MapPlaneRows, bpf.MapPlaneExecRows, bpf.MapPlaneListenRows} {
		spec, err := bpf.Load(plane)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := ebpf.NewMap(spec.Maps[name].InnerMap)
		if err != nil {
			t.Fatalf("inner %s: %v", name, err)
		}
		t.Cleanup(func() { _ = inner.Close() })
		if err := coll.Maps[name].Put(slot, inner); err != nil {
			t.Fatalf("outer %s: %v", name, err)
		}
		replacements[name] = coll.Maps[name]
	}
	fill, _ := bpf.PlaneFillFor(plane)
	spec, err := bpf.Load(fill)
	if err != nil {
		t.Fatal(err)
	}
	var objs struct {
		Fill   *ebpf.Program `ebpf:"tego_plane_fill"`
		Config *ebpf.Map     `ebpf:"tego_plane_fill_config"`
		Wants  *ebpf.Map     `ebpf:"tego_plane_fill_wants"`
	}
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{MapReplacements: replacements}); err != nil {
		t.Fatalf("load %s: %v", fill, err)
	}
	defer objs.Fill.Close()
	defer objs.Config.Close()
	defer objs.Wants.Close()
	tgid := uint32(os.Getpid())
	if err := objs.Config.Put(tgid, &bpf.PlaneFillCfg{Tgid: tgid, RunIdx: slot, Gen: gen}); err != nil {
		t.Fatal(err)
	}
	var keys []uint64
	for i, r := range rows.FS {
		key := bpf.PlaneFillKey(tgid, bpf.PlaneFillFS, uint32(held[r.Path]))
		execRule := uint16(bpf.PlaneRuleNone)
		if r.Exec >= 0 {
			execRule = uint16(r.Exec)
		}
		if err := objs.Wants.Put(key, &bpf.PlaneFillRow{What: bpf.PlaneFillFS, Kind: uint8(r.Kind), RuleIdx: uint16(i), ExecRule: execRule, Gen: gen}); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	for _, r := range rows.Exec {
		name, n, _ := bpf.PlaneExecName(r.Name)
		key := bpf.PlaneFillKey(tgid, bpf.PlaneFillExec, uint32(held[r.Path]))
		if err := objs.Wants.Put(key, &bpf.PlaneFillRow{What: bpf.PlaneFillExec, RuleIdx: uint16(r.Rule), NameLen: n, Name: name, Gen: gen}); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	it, err := link.AttachIter(link.IterOptions{Program: objs.Fill})
	if err != nil {
		t.Fatalf("attach the fill: %v", err)
	}
	defer it.Close()
	rd, err := it.Open()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, rd)
	_ = rd.Close()
	if err != nil {
		t.Fatalf("run the fill: %v", err)
	}
	for _, k := range keys {
		var got bpf.PlaneFillRow
		if err := objs.Wants.Lookup(k, &got); err != nil || got.Status != bpf.PlaneFillOK {
			t.Fatalf("fill of descriptor %d: %v %s", uint32(k), err, got.Status)
		}
	}
	// The slot's header, last, as Prepare writes it (enforce-plane R6): the run's gen and an exec: section.
	if err := coll.Maps[bpf.MapPlaneSlots].Put(slot, bpf.PlaneSlot{Gen: gen, Flags: bpf.PlaneSlotExecDecides}); err != nil {
		t.Fatal(err)
	}
}

// corruptRow changes the identity (i_generation) the slot's row for path holds, as an inode number reused for another
// file would: the kernel's compare on the hit then fails, and the plane refuses identity-mismatch.
func corruptRow(t *testing.T, coll *ebpf.Collection, slot uint32, rows *decide.PlaneRows, path string) {
	t.Helper()
	idx := -1
	for i, r := range rows.FS {
		if r.Path == path {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("no plane row for %s", path)
	}
	var inner *ebpf.Map
	if err := coll.Maps[bpf.MapPlaneRows].Lookup(slot, &inner); err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	var key uint64
	var row bpf.PlaneRow
	it, n := inner.Iterate(), 0
	for it.Next(&key, &row) {
		if int(row.RuleIdx) == idx {
			row.Generation ^= 1
			if err := inner.Update(&key, &row, ebpf.UpdateExist); err != nil {
				t.Fatal(err)
			}
			n++
			break
		}
	}
	if n != 1 {
		t.Fatalf("the slot holds no row for rule %d (%s)", idx, path)
	}
}

// TestIntegrationPlaneRefusalIsOneLine is TIER3-PLAN T9 on a real kernel (enforce-plane.md R23 and I8: at most one
// verdict line per action; I9: each line carries what compile --test's bpflsm column gives the same action), in each plane mode this kernel offers
// (lsm where bpf is an active LSM, fmod_ret everywhere): the plane's refusal of a read, a rename, `mv .git`, an
// unlink, a write-open and an unlisted exec, and its allow of an exec by an exec.allow directory (the bit-16 rule)
// and by a file entry, are each exactly one ledger line, the fs ones the recorder fexit's own with the plane's
// verdict stamped on it, the refused exec the plane's own sample, the allowed ones sched_process_exec named by the
// plane's rule. Each line carries mechanism plane, the mode, and the rule and reason compile --test's bpflsm column
// (decide.PlaneEvaluator) gives the same action. It runs under each build of trace_proc this kernel loads
// (eachTraceReader).
func TestIntegrationPlaneRefusalIsOneLine(t *testing.T) {
	if !bpf.Available() || len(bpf.PlaneObjects()) == 0 {
		t.Skipf("needs the compiled objects and the plane builds (-tags tegobpf): %v", bpf.ErrNotGenerated)
	}
	modes := []bpf.PlaneMode{bpf.PlaneFmodRet}
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil && strings.Contains(","+strings.TrimSpace(string(b))+",", ",bpf,") {
		modes = append(modes, bpf.PlaneLSM)
	} else {
		t.Logf("bpf is not an active LSM here: lsm mode is not run")
	}
	slot := uint32(30)
	eachTraceReader(t, func(t *testing.T, r bpf.Reader) {
		hash := "plane-" + string(r)
		root, maps := pinRoot(t, hash)
		coll := loadTraceProcWhereItLoads(t, maps, r)
		for _, mode := range modes {
			slot++
			t.Run(string(mode), func(t *testing.T) {
				planeOneLine(t, coll, root, maps, hash, mode, slot)
			})
		}
	})
}

func planeOneLine(t *testing.T, trace *ebpf.Collection, root, maps, hash string, mode bpf.PlaneMode, slot uint32) {
	const gen = 77
	// Every recorder fexit of trace is attached (loadTraceProcWhereItLoads), and the plane is told so, as the
	// backend tells it: each fs refusal is the fexit's line, never a second from the plane.
	plane, coll := loadPlaneBeside(t, maps, mode, bpf.PlaneRecordedMask(func(prog string) bool { return trace.Programs[prog] != nil }))

	base, rt, rows, held := planeFixture(t)
	fillSlot(t, plane, coll, slot, gen, rows, held)
	corruptRow(t, coll, slot, rows, filepath.Join(base, "w/bad"))
	placeRunRings(t, trace, slot)

	_, fd, cg := childCgroup(t, "plane-"+string(mode))
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^$")
	cmd.Env = append(os.Environ(), planeChildEnv+"="+base, planeLoaderEnv+"="+planeLoader(t, base))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
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
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	sc := bufio.NewScanner(out)
	if !sc.Scan() || sc.Text() != "ready" {
		t.Fatalf("the plane child did not say ready: %q %v", sc.Text(), sc.Err())
	}
	// Armed after the child's own exec, as a real run is (ADR 0021 (2)).
	row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 3, Record: uint8(bpf.RecordFull), Plane: bpf.RunPlaneOf(mode), Gen: gen}
	if err := trace.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trace.Maps[bpf.MapRunSet].Delete(&cg) })
	modeName := record.DecisionPlaneFmodRet
	if mode == bpf.PlaneLSM {
		modeName = record.DecisionPlaneLSM
	}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour, DecisionPlane: modeName})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-plane", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	if _, err := io.WriteString(in, "go\n"); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for sc.Scan() {
		if name, v, ok := strings.Cut(sc.Text(), " "); ok {
			got[name] = v
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("plane child: %v", err)
	}
	eacces := fmt.Sprint(int(unix.EACCES))
	wantLoader := eacces
	if planeLoader(t, base) == "" {
		wantLoader = "skipped"
	}
	for name, want := range map[string]string{"read-denied": eacces, "rename-out": eacces, "mv-git": eacces,
		"unlink-denied": eacces, "write-outside": eacces, "exec-unlisted": eacces, "exec-dir": "0", "exec-file": "0",
		"link-out": eacces, "rmdir-denied": eacces, "trunc-deny-write": eacces, "exec-hardlink": eacces,
		"read-bad-identity": eacces, "read-deep": eacces, "exec-memfd": eacces, "exec-loader": wantLoader} {
		if got[name] != want {
			t.Fatalf("the child's %s answered %q, want %s: the cell is not what it says (%v)", name, got[name], want, got)
		}
	}
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}

	// The model each line must agree with: compile --test's bpflsm column.
	eval := decide.NewPlaneEvaluator(rt)
	p := func(rel string) string { return filepath.Join(base, rel) }
	want := func(k agent.ActionKind, a, b string) agent.EvalResult {
		return eval.Evaluate(agent.Action{Kind: k, Path: a, DestPath: b}, decide.Env{})
	}
	type line struct {
		ev *record.Event
		fs record.FSPayload
	}
	byPath := map[string][]line{}
	for _, ev := range sink.byKind(record.KindFS) {
		pl := payload[record.FSPayload](t, ev)
		byPath[pl.Op+" "+pl.Path] = append(byPath[pl.Op+" "+pl.Path], line{ev, pl})
		t.Logf("fs %s %s %s %s rule=%s mechanism=%s plane=%s plane_reason=%s", pl.Op, pl.Path, pl.Path2, ev.Verdict,
			ev.Rule, pl.Mechanism, pl.DecisionPlane, pl.PlaneReason)
	}
	for _, tc := range []struct {
		path, op    string
		res         agent.EvalResult
		planeReason string
	}{
		{p("w/s/k"), record.FSOpen, want(agent.ActionFSRead, p("w/s/k"), ""), ""},
		{p("w/.git"), record.FSRename, want(agent.ActionFSRename, p("w/.git"), p("w/.git.old")), record.PlaneReasonDenyWriteAncestor},
		{p("o/f"), record.FSOpen, want(agent.ActionFSWrite, p("o/f"), ""), ""},
	} {
		ls := byPath[tc.op+" "+tc.path]
		if len(ls) != 1 {
			t.Errorf("%s %s: %d lines, want the plane's one: %+v", tc.op, tc.path, len(ls), ls)
			continue
		}
		l := ls[0]
		if l.fs.Op != tc.op || l.ev.Verdict != record.VerdictRefused || tc.res.Verdict != agent.VerdictRefused ||
			l.ev.Rule != tc.res.Rule || l.ev.Reason != tc.res.Reason || l.fs.DecisionPlane != modeName ||
			l.fs.PlaneReason != tc.planeReason {
			t.Errorf("%s: %s %s rule %s reason %s plane %s/%s; want %s refused rule %s reason %s plane %s/%s", tc.path,
				l.fs.Op, l.ev.Verdict, l.ev.Rule, l.ev.Reason, l.fs.DecisionPlane, l.fs.PlaneReason, tc.op, tc.res.Rule,
				tc.res.Reason, modeName, tc.planeReason)
		}
	}
	// The rename out of the deny_read tree and the unlink in it are file operations the recorder names by their
	// directory; w/s is an entry, so the index names them.
	var renameOut, unlink int
	for _, ev := range sink.byKind(record.KindFS) {
		pl := payload[record.FSPayload](t, ev)
		if pl.Path != p("w/s/k") {
			continue
		}
		switch pl.Op {
		case record.FSRename:
			renameOut++
			if w := want(agent.ActionFSRename, p("w/s/k"), p("w/k2")); ev.Rule != w.Rule || ev.Reason != w.Reason || pl.Mechanism != record.MechanismPlane {
				t.Errorf("rename out of deny_read: rule %s reason %s, want %s %s", ev.Rule, ev.Reason, w.Rule, w.Reason)
			}
		case record.FSUnlink:
			unlink++
			if w := want(agent.ActionFSDelete, p("w/s/k"), ""); ev.Rule != w.Rule || ev.Reason != w.Reason || pl.Mechanism != record.MechanismPlane {
				t.Errorf("unlink under deny_read: rule %s reason %s, want %s %s", ev.Rule, ev.Reason, w.Rule, w.Reason)
			}
		}
	}
	if renameOut != 1 || unlink != 1 {
		t.Errorf("%d rename and %d unlink plane lines under w/s, want one each", renameOut, unlink)
	}

	execs := map[string][]*record.Event{}
	for _, ev := range sink.byKind(record.KindExec) {
		pl := payload[record.ExecPayload](t, ev)
		execs[pl.Path] = append(execs[pl.Path], ev)
		t.Logf("exec %s %s rule=%s reason=%s mechanism=%s plane=%s", pl.Path, ev.Verdict, ev.Rule, ev.Reason,
			pl.Mechanism, pl.DecisionPlane)
	}
	for _, tc := range []struct {
		rel     string
		verdict record.Verdict
		rule    string
		reason  record.Reason
	}{
		{"o/t3", record.VerdictRefused, agent.UnmatchedRule, record.ReasonExecNotAllowed},
		{"tools/x", record.VerdictAllow, "exec[./tools]", ""}, // the bit-16 rule: the exec.allow directory's entry
		{"bin/t", record.VerdictAllow, "exec[./bin/t]", ""},
	} {
		evs := execs[p(tc.rel)]
		if len(evs) != 1 {
			t.Errorf("%s: %d exec lines, want one", tc.rel, len(evs))
			continue
		}
		pl := payload[record.ExecPayload](t, evs[0])
		if evs[0].Verdict != tc.verdict || evs[0].Rule != tc.rule || evs[0].Reason != tc.reason ||
			pl.Mechanism != record.MechanismPlane || pl.DecisionPlane != modeName {
			t.Errorf("%s: %s rule %s reason %s mechanism %s/%s, want %s %s %s plane/%s", tc.rel, evs[0].Verdict,
				evs[0].Rule, evs[0].Reason, pl.Mechanism, pl.DecisionPlane, tc.verdict, tc.rule, tc.reason, modeName)
		}
		if tc.verdict == record.VerdictAllow {
			if w := eval.Evaluate(agent.Action{Kind: agent.ActionExec, Path: p(tc.rel)}, decide.Env{}); w.Rule != tc.rule {
				t.Errorf("%s: compile --test names %s, the ledger %s", tc.rel, w.Rule, tc.rule)
			}
		}
	}
	planeMoreLines(t, sink, eval, base, modeName)
}

// planeMoreLines is the rest of the actions' lines: a link out of a deny_read tree, an rmdir under it, an O_TRUNC of
// a deny_write target, a row whose identity no longer matches, a file past the walk's bound, and the execs of a hard
// link no entry names, of the dynamic loader run directly and of a memfd. Each is exactly one line with verdict
// refused, the rule and reason compile --test's bpflsm column (decide.PlaneEvaluator) names where it models the
// action, plane_reason, mechanism plane and decision_plane the mode; and no refused line is left over.
// (The ledger has no gen field, and run_start no decision_plane, in this tree: P3's, not asserted here.)
func planeMoreLines(t *testing.T, sink *fakeSink, eval *decide.PlaneEvaluator, base, modeName string) {
	t.Helper()
	p := func(rel string) string { return filepath.Join(base, rel) }
	type fsLine struct {
		ev *record.Event
		fs record.FSPayload
	}
	var refused []fsLine
	for _, ev := range sink.byKind(record.KindFS) {
		if ev.Verdict == record.VerdictRefused {
			refused = append(refused, fsLine{ev, payload[record.FSPayload](t, ev)})
		}
	}
	model := func(k agent.ActionKind, a, b string) agent.EvalResult {
		return eval.Evaluate(agent.Action{Kind: k, Path: a, DestPath: b}, decide.Env{})
	}
	for _, tc := range []struct {
		name        string
		match       func(record.FSPayload) bool
		rule        string
		reason      record.Reason
		planeReason string
	}{
		{"link out of deny_read", func(f record.FSPayload) bool { return f.Op == record.FSLink },
			model(agent.ActionFSRename, p("w/s/k"), p("w/l1")).Rule, record.ReasonWriteOutsideContract, record.PlaneReasonRefer},
		{"rmdir under deny_read", func(f record.FSPayload) bool { return f.Op == record.FSUnlink && f.Path == p("w/s/d") },
			model(agent.ActionFSDelete, p("w/s/d"), "").Rule, model(agent.ActionFSDelete, p("w/s/d"), "").Reason, ""},
		{"O_TRUNC of a deny_write target", func(f record.FSPayload) bool {
			return f.Op == record.FSOpen && f.Path == p("w/.git/hooks/pre-commit")
		}, model(agent.ActionFSWrite, p("w/.git/hooks/pre-commit"), "").Rule,
			model(agent.ActionFSWrite, p("w/.git/hooks/pre-commit"), "").Reason, ""},
		{"read under a row whose identity is gone", func(f record.FSPayload) bool {
			return f.PlaneReason == record.PlaneReasonIdentityMismatch
		}, agent.UnmatchedRule, record.ReasonPathUnresolved, record.PlaneReasonIdentityMismatch},
		{"read 65 levels below a write entry", func(f record.FSPayload) bool {
			return f.Op == record.FSOpen && f.PlaneReason == "" && strings.HasSuffix(f.Path, "/a/f")
		}, agent.UnmatchedRule, record.ReasonPathUnresolved, ""},
	} {
		var got []fsLine
		for _, l := range refused {
			if tc.match(l.fs) {
				got = append(got, l)
			}
		}
		if len(got) != 1 {
			t.Errorf("%s: %d refused lines, want one: %+v", tc.name, len(got), got)
			continue
		}
		l := got[0]
		if l.ev.Rule != tc.rule || l.ev.Reason != tc.reason || l.fs.PlaneReason != tc.planeReason ||
			l.fs.Mechanism != record.MechanismPlane || l.fs.DecisionPlane != modeName {
			t.Errorf("%s: rule %s reason %s plane_reason %q mechanism %s/%s; want rule %s reason %s plane_reason %q plane/%s (%+v)",
				tc.name, l.ev.Rule, l.ev.Reason, l.fs.PlaneReason, l.fs.Mechanism, l.fs.DecisionPlane, tc.rule, tc.reason,
				tc.planeReason, modeName, l.fs)
		}
	}
	// Ten refused fs actions in all (planeActions less the execs): none has two lines, none is extra.
	if len(refused) != 10 {
		for _, l := range refused {
			t.Logf("refused fs line: %s %s -> %s rule=%s reason=%s plane_reason=%s", l.fs.Op, l.fs.Path, l.fs.Path2, l.ev.Rule,
				l.ev.Reason, l.fs.PlaneReason)
		}
		t.Errorf("%d refused fs lines, want 10 (one per refused action)", len(refused))
	}

	type execLine struct {
		ev *record.Event
		ex record.ExecPayload
	}
	var refusedExec []execLine
	for _, ev := range sink.byKind(record.KindExec) {
		if ev.Verdict == record.VerdictRefused {
			refusedExec = append(refusedExec, execLine{ev, payload[record.ExecPayload](t, ev)})
		}
	}
	type execWant struct {
		name  string
		match func(string) bool
	}
	wants := []execWant{
		{"exec of the unlisted o/t3", func(s string) bool { return s == p("o/t3") }},
		{"exec of a hard link no entry names", func(s string) bool { return s == p("bin/t2") }},
		{"exec of a memfd", func(s string) bool { return s == "/proc/self/fd/3" }},
	}
	if loader := planeLoader(t, base); loader != "" {
		wants = append(wants, execWant{"exec of the loader run directly", func(s string) bool { return s == loader }})
	}
	for _, w := range wants {
		var got []execLine
		for _, l := range refusedExec {
			if w.match(l.ex.Path) {
				got = append(got, l)
			}
		}
		if len(got) != 1 {
			t.Errorf("%s: %d refused exec lines, want one: %+v", w.name, len(got), got)
			continue
		}
		l := got[0]
		if l.ev.Rule != agent.UnmatchedRule || l.ev.Reason != record.ReasonExecNotAllowed || l.ex.PlaneReason != "" ||
			l.ex.Mechanism != record.MechanismPlane || l.ex.DecisionPlane != modeName {
			t.Errorf("%s: rule %s reason %s plane_reason %q mechanism %s/%s; want rule %s reason %s plane/%s", w.name,
				l.ev.Rule, l.ev.Reason, l.ex.PlaneReason, l.ex.Mechanism, l.ex.DecisionPlane, agent.UnmatchedRule,
				record.ReasonExecNotAllowed, modeName)
		}
	}
	if len(refusedExec) != len(wants) {
		for _, l := range refusedExec {
			t.Logf("refused exec line: %s rule=%s reason=%s", l.ex.Path, l.ev.Rule, l.ev.Reason)
		}
		t.Errorf("%d refused exec lines, want %d (one per refused exec)", len(refusedExec), len(wants))
	}
}

// planeLoader is the dynamic loader of the fixture's executables, "" for a static program.
func planeLoader(t *testing.T, base string) string {
	t.Helper()
	ef, err := elf.Open(filepath.Join(base, "bin/t"))
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_INTERP {
			b, _ := io.ReadAll(prog.Open())
			return strings.TrimRight(string(b), "\x00")
		}
	}
	t.Logf("the fixture's executable is static: no loader is invoked directly")
	return ""
}

// loadPlaneBeside loads the plane build this kernel takes in mode, pinned beside the recorder's maps as the backend
// pins it (tego_run_set, the rings and the decision scratch the recorder's fexit reads are one map each), writes
// its recorder mask (bpf.MapPlaneRecorded) before any program is attached, as the backend does, and attaches every
// hook this kernel has.
func loadPlaneBeside(t *testing.T, maps string, mode bpf.PlaneMode, recorded uint32) (bpf.Object, *ebpf.Collection) {
	t.Helper()
	var (
		plane bpf.Object
		coll  *ebpf.Collection
	)
	for _, o := range bpf.PlaneObjects() {
		spec, err := bpf.Load(o)
		if err != nil {
			t.Fatal(err)
		}
		keep := map[string]bool{}
		for _, h := range planeHooksHere(mode) {
			keep[h.Program(mode)] = true
		}
		for name := range spec.Programs {
			if !keep[name] {
				delete(spec.Programs, name)
			}
		}
		// Pinned beside the recorder's maps, as the backend pins it: tego_run_set, the rings and the decision
		// scratch the recorder's fexit reads are one map each.
		c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: maps}})
		if err != nil {
			t.Logf("%s does not load here: %v", o, err)
			continue
		}
		plane, coll = o, c
		break
	}
	if coll == nil {
		t.Skip("no plane build loads on this kernel")
	}
	t.Cleanup(coll.Close)
	if err := coll.Maps[bpf.MapPlaneRecorded].Put(uint32(0), recorded); err != nil {
		t.Fatalf("write the recorder mask: %v", err)
	}
	for _, h := range planeHooksHere(mode) {
		p := coll.Programs[h.Program(mode)]
		var l link.Link
		var err error
		if mode == bpf.PlaneLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: p})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachModifyReturn})
		}
		if err != nil {
			t.Fatalf("attach %s: %v", h.Program(mode), err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	return plane, coll
}

// TestIntegrationPlaneFallbackIsOneLine is TIER3-PLAN T9b on a real kernel (enforce-plane §7, R23 and I8: exactly one
// verdict line per action, never none, never two), in each plane mode this kernel offers and under record: full and
// off: with trace_proc loaded but none of its fexit programs attached (the recorder detached from every hook it
// wraps, sched_process_exec and exit still attached), and the plane's mask saying so, a refusal on each hook a
// fexit wraps, step A's (a read, a rename out of deny_read, mv .git, a link out of it, an unlink, an rmdir, a
// write-open outside every entry) and step B's (an O_CREAT open's mknod, a mkdir, a symlink, a truncate, an
// ftruncate), is exactly one fs line, the plane's own sample, with mechanism plane, the mode, and the rule and reason
// compile --test's bpflsm column gives the same action; the unlisted exec is its one exec line as before. It runs
// under each build of trace_proc this kernel loads (eachTraceReader).
func TestIntegrationPlaneFallbackIsOneLine(t *testing.T) {
	if !bpf.Available() || len(bpf.PlaneObjects()) == 0 {
		t.Skipf("needs the compiled objects and the plane builds (-tags tegobpf): %v", bpf.ErrNotGenerated)
	}
	modes := []bpf.PlaneMode{bpf.PlaneFmodRet}
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil && strings.Contains(","+strings.TrimSpace(string(b))+",", ",bpf,") {
		modes = append(modes, bpf.PlaneLSM)
	} else {
		t.Logf("bpf is not an active LSM here: lsm mode is not run")
	}
	slot := uint32(40)
	eachTraceReader(t, func(t *testing.T, r bpf.Reader) {
		hash := "fallback-" + string(r)
		root, maps := pinRoot(t, hash)
		fexit := map[string]bool{}
		for _, prog := range bpf.PlaneFexitPrograms {
			fexit[prog] = true
		}
		trace := loadTraceProcAttaching(t, maps, r, func(prog string) bool { return !fexit[prog] })
		for _, mode := range modes {
			for _, rec := range []agent.RecordMode{agent.RecordFull, agent.RecordOff} {
				slot++
				t.Run(string(mode)+"/"+string(rec), func(t *testing.T) {
					planeFallback(t, trace, root, maps, hash, mode, rec, slot)
				})
			}
		}
	})
}

func planeFallback(t *testing.T, trace *ebpf.Collection, root, maps, hash string, mode bpf.PlaneMode, recMode agent.RecordMode, slot uint32) {
	const gen = 91
	// No fexit of trace is attached: the mask the backend computes from its links is 0.
	plane, coll := loadPlaneBeside(t, maps, mode, bpf.PlaneRecordedMask(func(string) bool { return false }))
	base, rt, rows, held := planeFixture(t)
	rt.Record = recMode
	fillSlot(t, plane, coll, slot, gen, rows, held)
	placeRunRings(t, trace, slot)

	_, fd, cg := childCgroup(t, "fallback-"+string(mode)+"-"+string(recMode))
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^$")
	cmd.Env = append(os.Environ(), planeChildEnv+"="+base, planeChildSetEnv+"=fallback")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
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
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	sc := bufio.NewScanner(out)
	if !sc.Scan() || sc.Text() != "ready" {
		t.Fatalf("the plane child did not say ready: %q %v", sc.Text(), sc.Err())
	}
	kmode := bpf.RecordFull
	if recMode == agent.RecordOff {
		kmode = bpf.RecordOff
	}
	row := bpf.Run{RunIdx: slot, Descendants: 1, Tier: 3, Record: uint8(kmode), Plane: bpf.RunPlaneOf(mode), Gen: gen}
	if err := trace.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trace.Maps[bpf.MapRunSet].Delete(&cg) })
	modeName := record.DecisionPlaneFmodRet
	if mode == bpf.PlaneLSM {
		modeName = record.DecisionPlaneLSM
	}
	rec, err := New(Options{Rules: rt, BPFHash: hash, PinRoot: root, FlushInterval: time.Hour, DecisionPlane: modeName})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-fallback", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	if _, err := io.WriteString(in, "go\n"); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for sc.Scan() {
		if name, v, ok := strings.Cut(sc.Text(), " "); ok {
			got[name] = v
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("plane child: %v", err)
	}
	eacces := fmt.Sprint(int(unix.EACCES))
	for _, a := range planeFallbackActions {
		if got[a.name] != eacces {
			t.Fatalf("the child's %s answered %q, want %s: the cell is not what it says (%v)", a.name, got[a.name], eacces, got)
		}
	}
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}

	eval := decide.NewPlaneEvaluator(rt)
	p := func(rel string) string { return filepath.Join(base, rel) }
	// o is no entry, so the directory index cannot name o/f: its lines carry the raw dev:ino/f identifier.
	oDir := func(name string) string {
		var st unix.Stat_t
		if err := unix.Stat(p("o"), &st); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%d:%d/%s", st.Dev, st.Ino, name)
	}
	type cell struct {
		op, path    string
		flags       int
		action      agent.Action
		planeReason string
	}
	cells := map[string]cell{
		"read-denied":       {record.FSOpen, p("w/s/k"), unix.O_RDONLY, agent.Action{Kind: agent.ActionFSRead, Path: p("w/s/k")}, ""},
		"rename-out":        {record.FSRename, p("w/s/k"), 0, agent.Action{Kind: agent.ActionFSRename, Path: p("w/s/k"), DestPath: p("w/k2")}, ""},
		"mv-git":            {record.FSRename, p("w/.git"), 0, agent.Action{Kind: agent.ActionFSRename, Path: p("w/.git"), DestPath: p("w/.git.old")}, record.PlaneReasonDenyWriteAncestor},
		"link-out":          {record.FSLink, p("w/s/k"), 0, agent.Action{}, record.PlaneReasonRefer},
		"unlink-denied":     {record.FSUnlink, p("w/s/k"), 0, agent.Action{Kind: agent.ActionFSDelete, Path: p("w/s/k")}, ""},
		"rmdir-denied":      {record.FSUnlink, p("w/s/d"), 0, agent.Action{Kind: agent.ActionFSDelete, Path: p("w/s/d")}, ""},
		"write-outside":     {record.FSOpen, oDir("f"), unix.O_WRONLY, agent.Action{Kind: agent.ActionFSWrite, Path: p("o/f")}, ""},
		"creat-denied":      {record.FSOpen, p("w/s/n"), unix.O_CREAT, agent.Action{Kind: agent.ActionFSWrite, Path: p("w/s/n")}, ""},
		"mkdir-denied":      {record.FSMkdir, p("w/s/m"), 0, agent.Action{Kind: agent.ActionFSMkdir, Path: p("w/s/m")}, ""},
		"symlink-denied":    {record.FSSymlink, p("w/s/l"), 0, agent.Action{}, ""},
		"truncate-denied":   {record.FSTruncate, p("w/s/k"), 0, agent.Action{Kind: agent.ActionFSWrite, Path: p("w/s/k")}, ""},
		"ftruncate-outside": {record.FSTruncate, oDir("f"), 0, agent.Action{Kind: agent.ActionFSWrite, Path: p("o/f")}, ""},
	}
	lines := map[string][]*record.Event{}
	for _, ev := range sink.byKind(record.KindFS) {
		pl := payload[record.FSPayload](t, ev)
		lines[pl.Op+" "+pl.Path] = append(lines[pl.Op+" "+pl.Path], ev)
		t.Logf("fs %s %s %s rule=%s reason=%s mechanism=%s plane=%s plane_reason=%s flags=%#x", pl.Op, pl.Path, ev.Verdict,
			ev.Rule, ev.Reason, pl.Mechanism, pl.DecisionPlane, pl.PlaneReason, pl.Flags)
	}
	// Each (op, path) is one action's here but for w/s/k's truncate and o/f's two, counted apart below.
	want := map[string]int{}
	for _, c := range cells {
		want[c.op+" "+c.path]++
	}
	for key, n := range want {
		if len(lines[key]) != n {
			t.Errorf("%s: %d lines, want %d, the plane's own sample per refused action", key, len(lines[key]), n)
		}
	}
	if total := len(sink.byKind(record.KindFS)); total != len(cells) {
		t.Errorf("%d fs lines for %d refused fs actions", total, len(cells))
	}
	for name, c := range cells {
		for _, ev := range lines[c.op+" "+c.path] {
			pl := payload[record.FSPayload](t, ev)
			if ev.Verdict != record.VerdictRefused || pl.Mechanism != record.MechanismPlane || pl.DecisionPlane != modeName ||
				pl.PlaneReason != c.planeReason || (c.op == record.FSOpen && pl.Flags&(unix.O_ACCMODE|unix.O_CREAT) != c.flags) {
				t.Errorf("%s: %s mechanism %s/%s plane_reason %q flags %#x, want refused plane/%s %q flags %#x", name,
					ev.Verdict, pl.Mechanism, pl.DecisionPlane, pl.PlaneReason, pl.Flags, modeName, c.planeReason, c.flags)
			}
			if c.action.Kind == "" {
				continue
			}
			if w := eval.Evaluate(c.action, decide.Env{}); w.Verdict != agent.VerdictRefused || ev.Rule != w.Rule ||
				(c.op != record.FSTruncate && ev.Reason != w.Reason) {
				t.Errorf("%s: rule %s reason %s, compile --test %s rule %s reason %s", name, ev.Rule, ev.Reason, w.Verdict,
					w.Rule, w.Reason)
			}
		}
	}
	var refusedExec int
	for _, ev := range sink.byKind(record.KindExec) {
		if pl := payload[record.ExecPayload](t, ev); pl.Path == p("o/t3") {
			refusedExec++
			if ev.Verdict != record.VerdictRefused || pl.Mechanism != record.MechanismPlane {
				t.Errorf("the unlisted exec: %s mechanism %s", ev.Verdict, pl.Mechanism)
			}
		}
	}
	if refusedExec != 1 {
		t.Errorf("%d lines for the unlisted exec, want one", refusedExec)
	}
	for _, ev := range sink.events {
		if err := ev.Validate(); err != nil {
			t.Errorf("a line the ledger would refuse: %v: %+v", err, ev)
		}
	}
}

// planeHooksHere is bpf.PlaneHooksFor this kernel's BTF: an optional hook it lacks is not loaded (enforce-plane R3).
func planeHooksHere(mode bpf.PlaneMode) []bpf.PlaneHook {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return bpf.PlaneHooks
	}
	return bpf.PlaneHooksFor(mode, func(fn string) bool {
		var f *btf.Func
		return spec.TypeByName(fn, &f) == nil
	})
}
