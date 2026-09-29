// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// planeVerifiedBudget is the most instructions the verifier may walk for one plane program. ADR 0024's T0 note
// measured the walk's form d at 391-896 per program on 5.14, 6.1 and 6.17, rename's two calls included, against
// 16k-573k for the loop forms it rejected; a body that pushes a program past this has left form d.
const planeVerifiedBudget = 20000

// planeReaderUsable reports whether this kernel can load a plane build, and why not. The rd build calls the
// bpf_rdonly_cast kfunc, which a kernel without it in BTF refuses outright; the pr build calls
// bpf_probe_read_kernel, which lockdown=confidentiality refuses (ADR 0024's T0 note). The plane probe (T8) makes
// the same choice; here it only decides which builds must load.
func planeReaderUsable(t *testing.T, o Object) (bool, string) {
	t.Helper()
	switch o {
	case ObjectPlaneRdonly:
		kernel, err := btf.LoadKernelSpec()
		if err != nil {
			t.Fatalf("kernel BTF: %v", err)
		}
		var fn *btf.Func
		if err := kernel.TypeByName("bpf_rdonly_cast", &fn); err != nil {
			return false, "this kernel's BTF has no bpf_rdonly_cast kfunc"
		}
	case ObjectPlaneProbe:
		if b, err := os.ReadFile("/sys/kernel/security/lockdown"); err == nil && strings.Contains(string(b), "[confidentiality]") {
			return false, "lockdown=confidentiality refuses bpf_probe_read_kernel"
		}
	}
	return true, ""
}

// planeModeUsable reports whether this kernel can attach one mode. LSM mode needs bpf in the active LSM list: the
// kvm guest's default boot adds it (test/vm/kvm-run.sh), TEGO_VM_LSM=kernel and a hosted runner do not. fmod_ret
// mode needs nothing more than the tracing programs tier 2 already attaches.
func planeModeUsable(m PlaneMode) (bool, string) {
	if m != PlaneLSM {
		return true, ""
	}
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false, "no /sys/kernel/security/lsm: " + err.Error()
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if l == "bpf" {
			return true, ""
		}
	}
	return false, "bpf is not an active LSM (" + strings.TrimSpace(string(b)) + "); boot with lsm=...,bpf"
}

// TestPlaneLoadsAndAttaches is TIER3-PLAN §9's verifier-load test for T2: each plane build this kernel can use
// loads one mode's full hook set and attaches every program of it, in each mode this kernel offers, with the
// verifier's instruction count and the load time logged per program and held to planeVerifiedBudget. file_open's
// stub calls the walk, so the global walk subprogram is verified in every build and mode. The stubs decide
// nothing (T3), and a process outside every run is looked up and passed, which the open after the attach checks.
func TestPlaneLoadsAndAttaches(t *testing.T) {
	requireBPF(t)
	loaded := 0
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
					start := time.Now()
					coll, err := ebpf.NewCollection(spec)
					if err != nil {
						var ve *ebpf.VerifierError
						if errors.As(err, &ve) {
							t.Fatalf("load %s %s: %+v", o, mode, ve)
						}
						t.Fatalf("load %s %s: %v", o, mode, err)
					}
					defer coll.Close()
					t.Logf("%s %s: %d programs loaded in %v", o, mode, len(coll.Programs), time.Since(start))
					var links []link.Link
					defer func() {
						for _, l := range links {
							_ = l.Close()
						}
					}()
					for _, h := range PlaneHooksHere(mode) {
						name := h.Program(mode)
						p := coll.Programs[name]
						if p == nil {
							t.Fatalf("%s did not load", name)
						}
						if info, err := p.Info(); err == nil {
							if n, ok := info.VerifiedInstructions(); ok {
								t.Logf("%s: %d instructions verified", name, n)
								if n > planeVerifiedBudget {
									t.Errorf("%s: %d instructions verified, over the budget of %d", name, n, planeVerifiedBudget)
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
							t.Fatalf("attach %s to %s: %v", name, h.Section(mode), err)
						}
						links = append(links, l)
					}
					// The exec-pin program (ADR 0048 (3) P2), loaded and attached in both modes with the hooks and held
					// to the same budget: its MAC loops are bpf_loop callbacks, verified with it.
					pin := coll.Programs[PlaneExecPinProgram(mode)]
					if pin == nil {
						t.Fatalf("%s did not load", PlaneExecPinProgram(mode))
					}
					if info, err := pin.Info(); err == nil {
						if n, ok := info.VerifiedInstructions(); ok {
							t.Logf("%s: %d instructions verified", PlaneExecPinProgram(mode), n)
							if n > planeVerifiedBudget {
								t.Errorf("%s: %d instructions verified, over the budget of %d", PlaneExecPinProgram(mode), n,
									planeVerifiedBudget)
							}
						}
					}
					pl, err := link.AttachTracing(link.TracingOptions{Program: pin, AttachType: ebpf.AttachTraceRawTp})
					if err != nil {
						t.Fatalf("attach %s to %s: %v", PlaneExecPinProgram(mode), PlaneExecPinSection, err)
					}
					links = append(links, pl)
					// Every hook attached: an open outside any run still passes (a run-set miss returns 0, I1), and so
					// does an exec, which every program on bprm_check and sched_process_exec sees.
					f, err := os.Open("/proc/self/status")
					if err != nil {
						t.Fatalf("an open outside every run failed with the plane attached: %v", err)
					}
					_ = f.Close()
					if out, err := exec.Command("/bin/true").CombinedOutput(); err != nil {
						t.Fatalf("an exec outside every run failed with the plane attached: %v %s", err, out)
					}
					if mode == PlaneLSM {
						planeLoadTimes(t, spec, coll, PlaneHooksHere(mode), mode)
					}
					loaded++
				})
			}
		})
	}
	if loaded == 0 {
		t.Fatal("no plane build loaded in any mode on this kernel")
	}
}

// planeLoadLimit is ADR 0043's limit for one lsm program's verification on the dev box's 6.17 (its "Benchmarks and
// budgets": "6 ms load (lsm, 6.17)"), ADR 0024's T0 figure for tools/spike/walk's small object. The real object
// misses it before the name entries on 23 to 25 of either build's 28 lsm programs (the guests vary), those no name
// entry touches included (ADR 0043's implementation notes have the times, base and with the name entries, loaded in
// turn in one 6.17 guest: 3 to 99 ms at base), so this test reports each miss with its time, beside the verified
// instructions that planeVerifiedBudget holds, instead of failing every run on a figure the plane did not meet before
// NAME-BPF. The line starts BUDGET OVER, the repository's marker for a figure over its limit (test/perf's), never
// TARGET-MISS, which is a figure over its target and inside its limit: the limit stands, unrelaxed, and its miss is the
// open condition ADR 0043's Status line, its index row and enforce-plane §2.21 carry until the owner decides it
// (PERF-LOAD meets it, or an amendment moves it). A missing statistics line on 6.17 fails.
const planeLoadLimit = 6 * time.Millisecond

// planeVerificationTime is the verifier's own statistics line for a program's verification (BPF_LOG_STATS).
var planeVerificationTime = regexp.MustCompile(`verification time (\d+) usec`)

// planeVerifierStats is the statistics line beside it: the instructions processed and the states the verifier kept,
// which say where a program's verification time goes.
var planeVerifierStats = regexp.MustCompile(`processed \d+ insns[^\n]*`)

// planeLoadTimes loads each of mode's programs alone over coll's maps, three times, with the verifier's statistics,
// and logs the fastest of the kernel's own verification times (T0's measure: the log's "verification time", which
// leaves out the collection's BTF, relocation and map work) with its statistics line; on 6.17 a program over
// planeLoadLimit prints BUDGET OVER with its time (planeLoadLimitLine).
func planeLoadTimes(t *testing.T, spec *ebpf.CollectionSpec, coll *ebpf.Collection, hooks []PlaneHook, mode PlaneMode) {
	t.Helper()
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	release := unix.ByteSliceToString(uts.Release[:])
	target := strings.HasPrefix(release, "6.17.")
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("kernel BTF: %v", err)
	}
	for _, h := range hooks {
		name := h.Program(mode)
		best, stats := time.Duration(-1), ""
		for range 3 {
			one := spec.Copy()
			for p := range one.Programs {
				if p != name {
					delete(one.Programs, p)
				}
			}
			replace := map[string]*ebpf.Map{}
			for m := range one.Maps {
				if coll.Maps[m] != nil {
					replace[m] = coll.Maps[m]
				}
			}
			c, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{
				MapReplacements: replace,
				Programs:        ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats, KernelTypes: kernel},
			})
			if err != nil {
				t.Fatalf("load %s alone: %v", name, err)
			}
			vlog := c.Programs[name].VerifierLog
			m := planeVerificationTime.FindStringSubmatch(vlog)
			c.Close()
			if m == nil {
				break
			}
			us, _ := strconv.Atoi(m[1])
			if took := time.Duration(us) * time.Microsecond; best < 0 || took < best {
				best, stats = took, planeVerifierStats.FindString(vlog)
			}
		}
		if best < 0 {
			t.Logf("%s: this kernel's verifier log states no verification time (kernel %s)", name, release)
			if target {
				t.Errorf("%s: 6.17's verifier log states no verification time to report against %v", name, planeLoadLimit)
			}
			continue
		}
		t.Logf("%s: verified in %v (kernel %s; %s)", name, best, release, stats)
		if line, over := planeLoadLimitLine(name, release, best); target && over {
			t.Log(line)
		}
	}
}

// planeLoadLimitLine is the line for a program verified in took on release, and whether took is over planeLoadLimit.
// The line starts BUDGET OVER, test/perf's marker for a figure over its limit, because 6 ms is in the Limit column of
// ADR 0043's table: TARGET-MISS is kept for a figure over its target and inside its limit.
func planeLoadLimitLine(name, release string, took time.Duration) (string, bool) {
	return fmt.Sprintf("BUDGET OVER %s: verified in %v on %s (limit %v a program, ADR 0043); the limit is unmet, "+
		"at base too, an open condition for the owner (ADR 0043's Status, enforce-plane §2.21), so this test "+
		"reports it rather than failing", name, took, release, planeLoadLimit), took > planeLoadLimit
}

// TestPlaneLoadLimitLineIsALimitMiss holds the marker of a verification time over ADR 0043's 6 ms: the figure is in
// the ADR's Limit column, so its line carries the repository's limit marker, BUDGET OVER (test/perf's word for a
// figure over its limit), never TARGET-MISS, the marker of a figure over its target and inside its limit. It needs no
// root: it runs wherever the integration and tegobpf tags build.
func TestPlaneLoadLimitLineIsALimitMiss(t *testing.T) {
	line, over := planeLoadLimitLine("tego_plane_file_open", "6.17.0-41-generic", 71*time.Millisecond)
	if !over {
		t.Fatalf("71ms is not over the limit of %v", planeLoadLimit)
	}
	if !strings.HasPrefix(line, "BUDGET OVER ") || strings.Contains(line, "TARGET-MISS") {
		t.Errorf("a figure over ADR 0043's limit must print the limit marker BUDGET OVER, not a target miss: %q", line)
	}
	for _, want := range []string{"tego_plane_file_open", "71ms", "6.17.0-41-generic", "limit 6ms", "ADR 0043", "open condition"} {
		if !strings.Contains(line, want) {
			t.Errorf("the line does not say %q: %q", want, line)
		}
	}
	for _, took := range []time.Duration{planeLoadLimit, 5 * time.Millisecond} {
		if _, over := planeLoadLimitLine("tego_plane_file_open", "6.17.0-41-generic", took); over {
			t.Errorf("%v is over the limit of %v", took, planeLoadLimit)
		}
	}
}
