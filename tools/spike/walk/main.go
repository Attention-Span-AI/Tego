// SPDX-License-Identifier: Apache-2.0

//go:build tegospike

// Command spike is the TIER3-PLAN T0 spike's loader. SPIKE: it is built only with -tags tegospike by
// tools/spike/walk/build.sh, never by make build, and nothing in tego imports it. It runs as root inside a
// test/vm KVM guest (never on a host, never against ~/.tego) and prints tab-separated result lines:
//
//	spike env                       kernel, lsm list, lockdown, LTO evidence, BTF of the hooked functions
//	spike load  -dir D [-reps N]    verifier accept/reject, verified insns and load time per form and program
//	spike bench -dir D [-n N]       per-call cost of each form and program, in a governed cgroup and outside
//	spike rowmap -dir D [-reps N]   a per-run inner rows map (create, outer insert, outer delete) against a
//	                                slot that keeps its map (gen bump, in-kernel clear off the run's path)
package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var forms = []string{"a-rd", "a-pr", "b-rd", "b-pr", "c-rd", "c-pr", "d-rd", "d-pr"}
var hookProgs = []string{"lsm_file_open", "fmr_file_open", "lsm_path_rename", "fmr_path_rename"}

const (
	cgIn     = "/sys/fs/cgroup/spike-in"
	cgOut    = "/sys/fs/cgroup/spike-out"
	tree     = "/tmp/spike/a/b/c/d/e/f/g/h"
	denyDir  = "/tmp/spike/a/b/c"
	openFile = tree + "/file"
	slot     = 1
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: spike env|load|bench|rowmap|loop ...")
		os.Exit(2)
	}
	var err error
	if os.Args[1] != "loop" && os.Args[1] != "env" {
		if kernelTypes, err = btf.LoadKernelSpec(); err != nil {
			fmt.Fprintln(os.Stderr, "spike:", err)
			os.Exit(1)
		}
	}
	switch os.Args[1] {
	case "env":
		err = cmdEnv()
	case "load":
		err = cmdLoad(os.Args[2:])
	case "bench":
		err = cmdBench(os.Args[2:])
	case "rowmap":
		err = cmdRowmap(os.Args[2:])
	case "loop":
		err = cmdLoop(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "spike:", err)
		os.Exit(1)
	}
}

// ---- env -------------------------------------------------------------------------------------------------

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "(" + err.Error() + ")"
	}
	return strings.TrimSpace(string(b))
}

func cmdEnv() error {
	var u unix.Utsname
	_ = unix.Uname(&u)
	fmt.Printf("ENV\trelease\t%s\n", unix.ByteSliceToString(u.Release[:]))
	fmt.Printf("ENV\tlsm\t%s\n", readTrim("/sys/kernel/security/lsm"))
	fmt.Printf("ENV\tlockdown\t%s\n", readTrim("/sys/kernel/security/lockdown"))
	fmt.Printf("ENV\tcmdline\t%s\n", readTrim("/proc/cmdline"))
	if f, err := os.Open("/proc/config.gz"); err == nil {
		zr, err := gzip.NewReader(f)
		if err == nil {
			sc := bufio.NewScanner(zr)
			for sc.Scan() {
				l := sc.Text()
				for _, k := range []string{"CONFIG_LTO", "CONFIG_BPF_LSM", "CONFIG_FUNCTION_ERROR_INJECTION", "CONFIG_LSM=", "CONFIG_SECURITY_PATH", "CONFIG_PREEMPT", "CONFIG_HZ="} {
					if strings.HasPrefix(l, k) || strings.HasPrefix(l, "# "+k) {
						fmt.Printf("ENV\tconfig\t%s\n", l)
					}
				}
			}
		}
		f.Close()
	} else {
		fmt.Printf("ENV\tconfig\tno /proc/config.gz\n")
	}
	// Clang LTO renames promoted locals with a .llvm.<hash> suffix; a count above 0 is LTO's fingerprint.
	llvm := 0
	if f, err := os.Open("/proc/kallsyms"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if strings.Contains(sc.Text(), ".llvm.") {
				llvm++
			}
		}
		f.Close()
	}
	fmt.Printf("ENV\tkallsyms_llvm_suffixed\t%d\n", llvm)
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		fmt.Printf("ENV\tbtf\t%v\n", err)
		return nil
	}
	for _, fn := range []string{"security_file_open", "security_path_rename", "bpf_lsm_file_open", "bpf_lsm_path_rename", "bpf_rdonly_cast", "bpf_loop"} {
		var f *btf.Func
		ok := spec.TypeByName(fn, &f) == nil
		fmt.Printf("ENV\tbtf_func\t%s\t%v\n", fn, ok)
	}
	return nil
}

// ---- load ------------------------------------------------------------------------------------------------

// kernelTypes is loaded once and handed to every load, so a timed load does not include cilium's copy of the
// kernel's BTF (about 150 ms a load on 6.17 without it; tego would hold one spec too).
var kernelTypes *btf.Spec

type obj struct {
	spec *ebpf.CollectionSpec
	maps map[string]*ebpf.Map
}

func openObj(dir, form string) (*obj, error) {
	spec, err := ebpf.LoadCollectionSpec(filepath.Join(dir, "walk-"+form+".o"))
	if err != nil {
		return nil, err
	}
	o := &obj{spec: spec, maps: map[string]*ebpf.Map{}}
	for name, ms := range spec.Maps {
		m, err := ebpf.NewMap(ms)
		if err != nil {
			o.close()
			return nil, fmt.Errorf("map %s: %w", name, err)
		}
		o.maps[name] = m
	}
	return o, nil
}

func (o *obj) close() {
	for _, m := range o.maps {
		m.Close()
	}
}

// loadOne loads one program of the object against the object's shared maps.
func (o *obj) loadOne(name string, logLevel ebpf.LogLevel) (*ebpf.Program, time.Duration, error) {
	cs := o.spec.Copy()
	for n := range cs.Programs {
		if n != name {
			delete(cs.Programs, n)
		}
	}
	if _, ok := cs.Programs[name]; !ok {
		return nil, 0, fmt.Errorf("no program %s", name)
	}
	t0 := time.Now()
	coll, err := ebpf.NewCollectionWithOptions(cs, ebpf.CollectionOptions{
		MapReplacements: o.maps,
		Programs:        ebpf.ProgramOptions{LogLevel: logLevel, LogSizeStart: 1 << 20, KernelTypes: kernelTypes},
	})
	dt := time.Since(t0)
	if err != nil {
		return nil, dt, err
	}
	p := coll.DetachProgram(name)
	coll.Close()
	return p, dt, nil
}

var reProcessed = regexp.MustCompile(`processed (\d+) insns`)
var reVerifTime = regexp.MustCompile(`verification time (\d+) usec`)

func errTail(err error) string {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && len(ve.Log) > 0 {
		// The last two lines before the stats trailer, which is where the verifier says why.
		var keep []string
		for _, l := range ve.Log {
			if strings.HasPrefix(l, "verification time") || strings.HasPrefix(l, "stack depth") || strings.HasPrefix(l, "processed ") {
				continue
			}
			keep = append(keep, l)
		}
		if len(keep) > 2 {
			keep = keep[len(keep)-2:]
		}
		return strings.Join(keep, " | ")
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func ms(d time.Duration) string { return strconv.FormatFloat(float64(d)/1e6, 'f', 2, 64) }

func cmdLoad(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	dir := fs.String("dir", ".", "objects")
	reps := fs.Int("reps", 5, "timed loads per program")
	_ = fs.Parse(args)
	fmt.Println("LOAD\tform\tprog\tresult\tverified_insns\tverif_ms_min\tverif_ms_median\tload_ms_min\tload_ms_median\tdetail")
	for _, form := range forms {
		o, err := openObj(*dir, form)
		if err != nil {
			fmt.Printf("LOAD\t%s\t*\topen-failed\t\t\t\t\t\t%v\n", form, err)
			continue
		}
		for _, name := range append(append([]string{}, hookProgs...), "fill_row", "clear_rows") {
			// Every load asks for the stats line: the kernel's own verification time is the number that matters;
			// the wall time adds the attach-target resolution every tracing program pays (fill_row shows it).
			var ds, vs []time.Duration
			insns := ""
			rejected := false
			for i := 0; i < *reps; i++ {
				p, dt, err := o.loadOne(name, ebpf.LogLevelStats)
				if err != nil {
					fmt.Printf("LOAD\t%s\t%s\treject\t\t\t\t\t\t%s\n", form, name, errTail(err))
					rejected = true
					break
				}
				if m := reProcessed.FindStringSubmatch(p.VerifierLog); m != nil {
					insns = m[1]
				}
				if m := reVerifTime.FindStringSubmatch(p.VerifierLog); m != nil {
					us, _ := strconv.Atoi(m[1])
					vs = append(vs, time.Duration(us)*time.Microsecond)
				}
				p.Close()
				ds = append(ds, dt)
			}
			if rejected {
				continue
			}
			fmt.Printf("LOAD\t%s\t%s\taccept\t%s\t%s\t%s\t%s\t%s\t\n", form, name, insns, ms(minDur(vs)), ms(median(vs)), ms(minDur(ds)), ms(median(ds)))
		}
		o.close()
	}
	return nil
}

func minDur(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	m := d[0]
	for _, x := range d {
		if x < m {
			m = x
		}
	}
	return m
}

// ---- bench -----------------------------------------------------------------------------------------------

func cgID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func setupTree() error {
	if err := os.MkdirAll(tree, 0o755); err != nil {
		return err
	}
	for _, f := range []string{openFile, tree + "/x"} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			return err
		}
	}
	os.Remove(tree + "/y")
	for _, c := range []string{cgIn, cgOut} {
		if err := os.MkdirAll(c, 0o755); err != nil {
			return err
		}
	}
	return nil
}

type loopResult struct {
	nsPerOp float64
	errno   string
}

// runLoop runs `spike loop` in cgroup cg and returns its ns/op (or the first error it met).
func runLoop(cg, op string, n int) (loopResult, error) {
	out, err := exec.Command("/proc/self/exe", "loop", "-cg", cg, "-op", op, "-n", strconv.Itoa(n)).CombinedOutput()
	if err != nil {
		return loopResult{}, fmt.Errorf("loop: %v: %s", err, out)
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		return loopResult{}, fmt.Errorf("loop output %q", out)
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return loopResult{nsPerOp: v, errno: f[1]}, nil
}

func cmdLoop(args []string) error {
	fs := flag.NewFlagSet("loop", flag.ExitOnError)
	cg := fs.String("cg", "", "cgroup to join")
	op := fs.String("op", "open", "open|rename|probe-open|probe-rename|fill")
	n := fs.Int("n", 100000, "iterations")
	_ = fs.Parse(args)
	runtime.LockOSThread()
	if *cg != "" {
		if err := os.WriteFile(*cg+"/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			return err
		}
	}
	once := func() error {
		switch *op {
		case "open", "probe-open":
			fd, err := unix.Open(openFile, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			return unix.Close(fd)
		case "rename", "probe-rename":
			if err := unix.Rename(tree+"/x", tree+"/y"); err != nil {
				return err
			}
			return unix.Rename(tree+"/y", tree+"/x")
		case "fill":
			fd, err := unix.Open(denyDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			return unix.Close(fd)
		}
		return fmt.Errorf("op %s", *op)
	}
	if strings.HasPrefix(*op, "probe") || *op == "fill" {
		err := once()
		e := "ok"
		if err != nil {
			e = err.(syscall.Errno).Error()
		}
		fmt.Printf("0 %s\n", strings.ReplaceAll(e, " ", "_"))
		return nil
	}
	for i := 0; i < 2000; i++ {
		if err := once(); err != nil {
			fmt.Printf("0 %s\n", strings.ReplaceAll(err.Error(), " ", "_"))
			return nil
		}
	}
	t0 := time.Now()
	for i := 0; i < *n; i++ {
		if err := once(); err != nil {
			fmt.Printf("0 %s\n", strings.ReplaceAll(err.Error(), " ", "_"))
			return nil
		}
	}
	per := float64(time.Since(t0).Nanoseconds()) / float64(*n)
	if *op == "rename" {
		per /= 2 // two renames per iteration
	}
	fmt.Printf("%.1f ok\n", per)
	return nil
}

type runVal struct{ RunIdx, Gen uint32 }

type rowVal struct {
	Kind, RuleIdx uint32
	Ino           uint64
	IGen, SDev    uint32
	Gen, Pad      uint32
}

func statsSum(m *ebpf.Map) ([9]uint64, error) {
	var out [9]uint64
	for i := uint32(0); i < 9; i++ {
		var vs []uint64
		if err := m.Lookup(i, &vs); err != nil {
			return out, err
		}
		for _, v := range vs {
			out[i] += v
		}
	}
	return out, nil
}

func statsZero(m *ebpf.Map) {
	n, _ := ebpf.PossibleCPU()
	z := make([]uint64, n)
	for i := uint32(0); i < 9; i++ {
		_ = m.Put(i, z)
	}
}

func attach(p *ebpf.Program, name string) (link.Link, error) {
	if strings.HasPrefix(name, "lsm_") {
		return link.AttachLSM(link.LSMOptions{Program: p})
	}
	return link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachModifyReturn})
}

func newInner(o *obj) (*ebpf.Map, error) {
	return ebpf.NewMap(o.spec.Maps["rows"].InnerMap)
}

func cmdBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	dir := fs.String("dir", ".", "objects")
	n := fs.Int("n", 20000, "operations per sample")
	reps := fs.Int("reps", 7, "samples per cell")
	only := fs.String("forms", strings.Join(forms, ","), "forms")
	_ = fs.Parse(args)
	if err := setupTree(); err != nil {
		return err
	}
	cid, err := cgID(cgIn)
	if err != nil {
		return err
	}
	// The kernel's own per-program run time (bpf_stats): what one invocation of the program costs, in the
	// governed cgroup (a walk) and outside it (the run-set miss), free of the guest's scheduling noise that the
	// wall-clock loop carries on a loaded host.
	stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		return fmt.Errorf("enable stats: %w", err)
	}
	defer stats.Close()
	fmt.Println("BENCH\tform\tprog\top\tprog_ns_in\tprog_ns_out\twall_bare_min\twall_in_min\twall_out_min\tin_minus_bare\tout_minus_bare\tavg_steps\tfunctional")
	for _, form := range strings.Split(*only, ",") {
		o, err := openObj(*dir, form)
		if err != nil {
			fmt.Printf("BENCH\t%s\t*\topen-failed %v\n", form, err)
			continue
		}
		inner, err := newInner(o)
		if err != nil {
			return err
		}
		if err := o.maps["rows"].Put(uint32(slot), inner); err != nil {
			return err
		}
		if err := o.maps["run_set"].Put(cid, runVal{RunIdx: slot, Gen: 7}); err != nil {
			return err
		}
		for _, name := range hookProgs {
			op := "open"
			if strings.Contains(name, "rename") {
				op = "rename"
			}
			p, _, err := o.loadOne(name, 0)
			if err != nil {
				fmt.Printf("BENCH\t%s\t%s\t%s\treject\n", form, name, op)
				continue
			}
			var bare, in, out []float64
			var walks, steps uint64
			var inNs, outNs time.Duration
			var inCnt, outCnt uint64
			failed := ""
			for r := 0; r < *reps && failed == ""; r++ {
				b, err := runLoop(cgIn, op, *n)
				if err != nil {
					return err
				}
				bare = append(bare, b.nsPerOp)
				l, err := attach(p, name)
				if err != nil {
					failed = "attach: " + err.Error()
					break
				}
				statsZero(o.maps["stats"])
				s0, _ := p.Stats()
				i, err := runLoop(cgIn, op, *n)
				if err != nil {
					return err
				}
				s1, _ := p.Stats()
				s, _ := statsSum(o.maps["stats"])
				walks += s[0]
				steps += s[6]
				x, err := runLoop(cgOut, op, *n)
				if err != nil {
					return err
				}
				s2, _ := p.Stats()
				l.Close()
				if s0 != nil && s1 != nil && s2 != nil {
					inNs += s1.Runtime - s0.Runtime
					inCnt += s1.RunCount - s0.RunCount
					outNs += s2.Runtime - s1.Runtime
					outCnt += s2.RunCount - s1.RunCount
				}
				if i.errno != "ok" || x.errno != "ok" {
					failed = "loop errno in=" + i.errno + " out=" + x.errno
					break
				}
				in = append(in, i.nsPerOp)
				out = append(out, x.nsPerOp)
			}
			if failed != "" {
				fmt.Printf("BENCH\t%s\t%s\t%s\tfailed\t\t\t\t\t\t\t\t%s\n", form, name, op, failed)
				p.Close()
				continue
			}
			fn, err := functional(o, p, name, op, inner)
			if err != nil {
				fn = "error: " + err.Error()
			}
			avg := 0.0
			if walks > 0 {
				avg = float64(steps) / float64(walks)
			}
			per := func(d time.Duration, c uint64) string {
				if c == 0 {
					return "0-runs"
				}
				return strconv.FormatFloat(float64(d.Nanoseconds())/float64(c), 'f', 0, 64)
			}
			mb, mi, mo := fmin(bare), fmin(in), fmin(out)
			fmt.Printf("BENCH\t%s\t%s\t%s\t%s\t%s\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\t%.1f\t%s\n", form, name, op, per(inNs, inCnt), per(outNs, outCnt), mb, mi, mo, mi-mb, mo-mb, avg, fn)
			p.Close()
		}
		inner.Close()
		o.close()
	}
	return nil
}

func fmin(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	m := v[0]
	for _, x := range v {
		if x < m {
			m = x
		}
	}
	return m
}

// functional fills a deny row on denyDir (through the test-only fentry fill) and checks the attached hook
// refuses inside the governed cgroup and passes outside it; then it makes the row stale (gen) and checks
// the walk passes it; then clears the rows in the kernel.
func functional(o *obj, p *ebpf.Program, name, op string, inner *ebpf.Map) (string, error) {
	fp, _, err := o.loadOne("fill_row", 0)
	if err != nil {
		return "fill-reject", nil
	}
	defer fp.Close()
	fl, err := link.AttachTracing(link.TracingOptions{Program: fp, AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		return "", err
	}
	// This process (outside the governed cgroup) opens denyDir once; fill_row keys a deny row on its inode.
	cfg := struct{ Tgid, RunIdx, Gen, Kind uint32 }{uint32(os.Getpid()), slot, 7, 1}
	if err := o.maps["fill"].Put(uint32(0), cfg); err != nil {
		fl.Close()
		return "", err
	}
	fd, err := unix.Open(denyDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
	}
	fl.Close()
	cnt := 0
	it := inner.Iterate()
	var k uint64
	var v rowVal
	for it.Next(&k, &v) {
		cnt++
	}
	l, err := attach(p, name)
	if err != nil {
		return "", err
	}
	defer l.Close()
	probe := "probe-" + op
	in, err := runLoop(cgIn, probe, 1)
	if err != nil {
		return "", err
	}
	out, err := runLoop(cgOut, probe, 1)
	if err != nil {
		return "", err
	}
	// Stale: bump the run's gen, the row (gen 7) must count as absent.
	cid, _ := cgID(cgIn)
	_ = o.maps["run_set"].Put(cid, runVal{RunIdx: slot, Gen: 8})
	stale, err := runLoop(cgIn, probe, 1)
	if err != nil {
		return "", err
	}
	_ = o.maps["run_set"].Put(cid, runVal{RunIdx: slot, Gen: 7})
	// Clear in the kernel.
	cleared := "clear-reject"
	if cp, _, err := o.loadOne("clear_rows", 0); err == nil {
		ctx := struct{ RunIdx, Deleted uint32 }{slot, 0}
		ret, err := cp.Run(&ebpf.RunOptions{Context: ctx, ContextOut: &ctx})
		if err != nil {
			cleared = "clear-run:" + err.Error()
		} else {
			cleared = fmt.Sprintf("cleared=%d(ret %d)", ctx.Deleted, ret)
		}
		cp.Close()
	}
	return fmt.Sprintf("rows=%d deny_in=%s out=%s stale_in=%s %s", cnt, in.errno, out.errno, stale.errno, cleared), nil
}

// ---- rowmap ----------------------------------------------------------------------------------------------

func cmdRowmap(args []string) error {
	fs := flag.NewFlagSet("rowmap", flag.ExitOnError)
	dir := fs.String("dir", ".", "objects")
	reps := fs.Int("reps", 20, "runs")
	nrows := fs.Int("rows", 64, "rows per run")
	form := fs.String("form", "b-pr", "object whose program is attached while measuring")
	_ = fs.Parse(args)
	if err := setupTree(); err != nil {
		return err
	}
	o, err := openObj(*dir, *form)
	if err != nil {
		return err
	}
	defer o.close()
	// A program referencing the outer is loaded and attached, as it would be for a live build.
	p, _, err := o.loadOne("fmr_file_open", 0)
	if err != nil {
		return err
	}
	defer p.Close()
	l, err := attach(p, "fmr_file_open")
	if err != nil {
		return err
	}
	defer l.Close()
	outer := o.maps["rows"]
	fill := func(m *ebpf.Map, gen uint32) error {
		for i := 0; i < *nrows; i++ {
			if err := m.Put(uint64(0xffff888000000000+uint64(i)*4096), rowVal{Kind: 1, Gen: gen}); err != nil {
				return err
			}
		}
		return nil
	}
	fmt.Println("ROWMAP\tscheme\tstep\tmedian_ms\tmin_ms\tmax_ms\treps")
	pr := func(scheme, step string, d []time.Duration) {
		s := append([]time.Duration(nil), d...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		fmt.Printf("ROWMAP\t%s\t%s\t%s\t%s\t%s\t%d\n", scheme, step, ms(median(d)), ms(s[0]), ms(s[len(s)-1]), len(d))
	}
	// A: a new inner map per run.
	var cr, ins, fl, del, tot []time.Duration
	for r := 0; r < *reps; r++ {
		t0 := time.Now()
		m, err := newInner(o)
		if err != nil {
			return err
		}
		t1 := time.Now()
		if err := outer.Put(uint32(100+r), m); err != nil {
			return err
		}
		t2 := time.Now()
		if err := fill(m, 1); err != nil {
			return err
		}
		t3 := time.Now()
		if err := outer.Delete(uint32(100 + r)); err != nil {
			return err
		}
		m.Close()
		t4 := time.Now()
		cr = append(cr, t1.Sub(t0))
		ins = append(ins, t2.Sub(t1))
		fl = append(fl, t3.Sub(t2))
		del = append(del, t4.Sub(t3))
		tot = append(tot, t2.Sub(t0)+t4.Sub(t3))
	}
	pr("per-run-inner", "create", cr)
	pr("per-run-inner", "outer-insert", ins)
	pr("per-run-inner", fmt.Sprintf("fill-%d-rows", *nrows), fl)
	pr("per-run-inner", "outer-delete+close", del)
	pr("per-run-inner", "total-excl-fill", tot)
	// B: the slot keeps its inner map; a run bumps gen in its run-set row; the clear runs off the path.
	m, err := newInner(o)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := outer.Put(uint32(2), m); err != nil {
		return err
	}
	cp, _, err := o.loadOne("clear_rows", 0)
	clearOK := err == nil
	if err != nil {
		fmt.Printf("ROWMAP\treuse\tclear_rows\treject\t%s\n", errTail(err))
	} else {
		defer cp.Close()
	}
	cid, _ := cgID(cgIn)
	var gen, fl2, clr, clrU []time.Duration
	for r := 0; r < *reps; r++ {
		t0 := time.Now()
		if err := o.maps["run_set"].Put(cid, runVal{RunIdx: 2, Gen: uint32(10 + r)}); err != nil {
			return err
		}
		t1 := time.Now()
		if err := fill(m, uint32(10+r)); err != nil {
			return err
		}
		t2 := time.Now()
		gen = append(gen, t1.Sub(t0))
		fl2 = append(fl2, t2.Sub(t1))
		if clearOK {
			ctx := struct{ RunIdx, Deleted uint32 }{2, 0}
			t3 := time.Now()
			if _, err := cp.Run(&ebpf.RunOptions{Context: ctx, ContextOut: &ctx}); err != nil {
				return err
			}
			clr = append(clr, time.Since(t3))
			if int(ctx.Deleted) != *nrows {
				fmt.Printf("ROWMAP\treuse\tclear-count\t%d of %d\n", ctx.Deleted, *nrows)
			}
		} else {
			// Userspace clear, for comparison only (it reads kernel-address keys, which ADR 0025 rejects).
			t3 := time.Now()
			var k uint64
			var keys []uint64
			it := m.Iterate()
			var v rowVal
			for it.Next(&k, &v) {
				keys = append(keys, k)
			}
			for _, k := range keys {
				_ = m.Delete(k)
			}
			clrU = append(clrU, time.Since(t3))
		}
	}
	pr("reuse", "run_set-gen-update", gen)
	pr("reuse", fmt.Sprintf("fill-%d-rows", *nrows), fl2)
	if clearOK {
		pr("reuse", "clear-in-kernel(off-path)", clr)
	} else {
		pr("reuse", "clear-userspace(off-path)", clrU)
	}
	return nil
}
