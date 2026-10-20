// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/test/perf"
)

// The exec check (ADR 0048 P2's K7; docs/p0/enforce-plane.md §10). Each round runs, in every mode, execbench's loop
// under four contracts, the modes rotated and the contracts alternated: 512 bytes of argv and 128 KiB, each without
// command rules and with one (deny: ["./true push"], a tool no row knows, so the generic fallback reads the whole
// vector and the exec is pinned whole at a plane mode). Each figure is the best round (Min-of-N), as in the open check.
//
//   - exec.pinned.<mode>.p50_excess_us and p99_excess_us: the 512-byte exec with rules over without, per plane mode;
//     landlock's same difference is P1's supervisor cost (p1.landlock, printed), and a plane mode's excess less it is
//     P2's kernel cost (p2.<mode>, printed);
//   - exec.argv128k.<mode>.excess_ms: the 128 KiB exec, with rules over without;
//   - exec.norules.<mode>.pin_check_ns: the sched_process_exec pin programs' own time per exec (kernel bpf_stats,
//     both programs summed over the count of one) while a run without rules execs: what P2 adds to an unpinned exec,
//     the programs' trampoline entry aside;
//   - doctor.exec_pin.<mode>.cold_ms: doctor's exec pin cell in each plane mode the boot has, from a doctor run's
//     phases (TEGO_TEST_PHASE_TIMING); doctor's own scope keeps no cell answer, so every run's cell is cold.
var (
	execN      = flag.Int("exec-n", 10000, "execs per sample of the exec check (a tenth at 128 KiB of argv)")
	execRounds = flag.Int("exec-rounds", 5, "rounds of the exec check; each runs every mode under its four contracts")
)

// execSections are the exec check's contracts' exec: lines, without command rules and with one.
var execSections = map[bool]string{
	false: "  allow: [\"./execbench\", \"./true\"]\n",
	true:  "  allow: [\"./execbench\", \"./true\"]\n  deny: [\"./true push\"]\n",
}

type execConf struct {
	argv  int
	rules bool
}

var execConfs = []execConf{{512, false}, {512, true}, {128 << 10, false}, {128 << 10, true}}

// setupExec puts execbench and the minimal image (perf.TrueImage) in the project.
func (s *suite) setupExec() error {
	img, err := perf.TrueImage(runtime.GOARCH)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.proj, "true"), img, 0o755); err != nil {
		return err
	}
	in, err := os.ReadFile(*execBin)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.proj, "execbench"), in, 0o755)
}

func (s *suite) execCheck() {
	if s.pinStats == nil {
		stop, err := enableBPFStats()
		if err != nil {
			s.fail("exec-fail", map[string]any{"operation": "bpf_stats", "err": err.Error()})
		}
		defer stop()
	}
	key := func(m perf.Mode, c execConf) string { return fmt.Sprintf("%s/%d/%v", m.Name, c.argv, c.rules) }
	p50, p99 := map[string][]float64{}, map[string][]float64{}
	pinNS, pinRuns := map[string]uint64{}, map[string]uint64{}
	for round := 0; round < *execRounds; round++ {
		for k := range s.modes {
			m := s.modes[(k+round)%len(s.modes)]
			for _, c := range execConfs {
				n := *execN
				if c.argv > 512 {
					n = max(n/10, 1)
				}
				var ns0, runs0 uint64
				var serr error
				measurePin := !c.rules && c.argv == 512 && m.Plane != "auto"
				if measurePin {
					ns0, runs0, serr = s.readPinStats()
				}
				r, rerr := s.one(spec{mode: m, record: "summary", tag: "exec-" + m.Name, command: "./execbench",
					exec: execSections[c.rules], args: []string{"-n", strconv.Itoa(n), "-cpu", strconv.Itoa(*cpu), "-argv",
						strconv.Itoa(c.argv), "./true"}})
				rerr = sampleError(r, rerr, "exec_p50", "exec_p99")
				if failed, ok := r.res["exec_failed"]; rerr == nil && (!ok || failed != 0) {
					rerr = fmt.Errorf("%v of %d execs did not run and exit 0 (or no count)", failed, n)
				}
				if rerr != nil {
					s.fail("exec-fail", map[string]any{"mode": m.Name, "argv": c.argv, "rules": c.rules, "err": rerr.Error(),
						"tail": tailOf(r)})
					continue
				}
				p50[key(m, c)] = append(p50[key(m, c)], r.res["exec_p50"])
				p99[key(m, c)] = append(p99[key(m, c)], r.res["exec_p99"])
				if measurePin && serr == nil {
					ns1, runs1, err1 := s.readPinStats()
					if err1 == nil && runs1 > runs0 {
						pinNS[m.Name] += ns1 - ns0
						pinRuns[m.Name] += runs1 - runs0
					}
					serr = err1
				}
				if serr != nil {
					s.fail("exec-fail", map[string]any{"mode": m.Name, "operation": "bpf_stats", "err": serr.Error()})
				}
			}
		}
	}
	best := func(xs map[string][]float64, k string) (float64, bool) {
		v := xs[k]
		if len(v) != *execRounds {
			s.fail("exec-fail", map[string]any{"sample": k, "samples": len(v), "required": *execRounds})
			return 0, false
		}
		return perf.Min(v), true
	}
	out := map[string]any{"execs": *execN, "rounds": *execRounds, "cpu": *cpu}
	var p1 float64
	for _, m := range s.modes {
		var b50, b99 [4]float64
		ok := true
		for i, c := range execConfs {
			var ok1, ok2 bool
			b50[i], ok1 = best(p50, key(m, c))
			b99[i], ok2 = best(p99, key(m, c))
			ok = ok && ok1 && ok2
			out[key(m, c)+".p50_min_ns"], out[key(m, c)+".p99_min_ns"] = b50[i], b99[i]
		}
		if !ok {
			continue
		}
		e50, e99, e128 := (b50[1]-b50[0])/1e3, (b99[1]-b99[0])/1e3, (b50[3]-b50[2])/1e6
		if m.Plane == "auto" {
			p1 = e50
			out["p1.landlock.p50_excess_us"], out["p1.landlock.p99_excess_us"] = e50, e99
			out["p1.landlock.argv128k_excess_ms"] = e128
			continue
		}
		s.record("exec.pinned."+m.Name+".p50_excess_us", e50)
		s.record("exec.pinned."+m.Name+".p99_excess_us", e99)
		s.record("exec.argv128k."+m.Name+".excess_ms", e128)
		out["p2."+m.Name+".p50_excess_us"] = e50 - p1
		if pinRuns[m.Name] > 0 {
			v := float64(pinNS[m.Name]) / float64(pinRuns[m.Name])
			out["pin_check."+m.Name+".runs"] = pinRuns[m.Name]
			s.record("exec.norules."+m.Name+".pin_check_ns", v)
		} else {
			s.fail("exec-fail", map[string]any{"mode": m.Name, "err": "no pin check program ran during the runs without rules"})
		}
	}
	s.emit("exec", out)
	s.doctorExecPin()
}

// pinProgPrefix is the kernel's name of the plane's sched_process_exec pin programs (tego_exec_pin_lsm and _fmr,
// cut to the kernel's 15 characters).
const pinProgPrefix = "tego_exec_pin"

// readPinStats sums the pin programs' run time and takes the larger run count: both run on every exec where both
// are attached, so the count of one is the execs, and the sum of their times is what an exec spends in them.
func (s *suite) readPinStats() (runNS, runs uint64, err error) {
	if s.pinStats != nil {
		return s.pinStats()
	}
	var id ebpf.ProgramID
	found := false
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		id = next
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue // unloaded since
		}
		info, err := p.Info()
		if err != nil || !strings.HasPrefix(info.Name, pinProgPrefix) {
			_ = p.Close()
			continue
		}
		st, err := p.Stats()
		_ = p.Close()
		if err != nil {
			return 0, 0, fmt.Errorf("program %s: %w", info.Name, err)
		}
		found = true
		runNS += uint64(st.Runtime.Nanoseconds())
		runs = max(runs, st.RunCount)
	}
	if !found {
		return 0, 0, errors.New("no " + pinProgPrefix + " program is loaded")
	}
	return runNS, runs, nil
}

// enableBPFStats turns on the kernel's per-program run statistics and returns the function that restores the setting.
func enableBPFStats() (func(), error) {
	const knob = "/proc/sys/kernel/bpf_stats_enabled"
	was, err := os.ReadFile(knob)
	if err != nil {
		return func() {}, err
	}
	if err := os.WriteFile(knob, []byte("1\n"), 0o644); err != nil {
		return func() {}, err
	}
	return func() { _ = os.WriteFile(knob, was, 0o644) }, nil
}

// doctorExecPin runs `tego doctor` once and records its exec pin cell's phase in each plane mode the boot has.
func (s *suite) doctorExecPin() {
	run := s.doctorRun
	if run == nil {
		run = func() ([]byte, error) {
			st := filepath.Join(*base, "state-doctor")
			if err := os.MkdirAll(filepath.Join(st, "home"), 0o755); err != nil {
				return nil, err
			}
			defer func() { _ = os.RemoveAll(st) }()
			cmd := exec.Command(*tegoBin, "doctor")
			cmd.Dir = s.proj
			cmd.Env = append(os.Environ(), "TEGO_CONFIG="+s.config(st), "TEGO_TEST_PHASE_TIMING=1",
				"TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(st, "chain.log"), "TEGO_TEST_OWN_LOG_HOME="+filepath.Join(st, "home"))
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				err = nil // a doctor that finds a FAIL elsewhere still timed the cell
			}
			return out, err
		}
	}
	out, err := run()
	if err != nil {
		s.fail("exec-fail", map[string]any{"operation": "doctor", "err": err.Error()})
		return
	}
	phases := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		if m := phaseRE.FindStringSubmatch(line); m != nil {
			us, _ := strconv.ParseFloat(m[2], 64)
			phases[m[1]] = us / 1000
		}
	}
	for _, m := range s.modes {
		if m.Tier != "cgroup" {
			continue
		}
		v, ok := phases["probe.plane."+m.Plane+".exec_pin"]
		if !ok {
			s.fail("exec-fail", map[string]any{"operation": "doctor", "mode": m.Plane, "err": "no exec_pin phase", "phases": phases})
			continue
		}
		s.record("doctor.exec_pin."+m.Name+".cold_ms", v)
	}
	s.emit("doctor-exec-pin", map[string]any{"phases": phases})
}
