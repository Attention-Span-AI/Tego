// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/test/perf"
)

// TestExecCheckIsEachModesBestExcess (ADR 0048 P2's K7): each mode's figure is its best round with rules over its best
// round without, per argv size; the pin check's cost is the pin programs' time over their runs during the runs without
// rules; doctor's cell is its phase in each plane mode; and every contract with rules carries the deny entry.
func TestExecCheckIsEachModesBestExcess(t *testing.T) {
	s, out := samplingSuite(t)
	var specs []spec
	round := 0
	s.oneRun = func(sp spec) (*run, error) {
		specs = append(specs, sp)
		r := goodSample()
		big := slices.Contains(sp.args, "131072")
		p50, p99 := 300000.0, 900000.0
		if big {
			p50, p99 = 1000000, 2000000
		}
		if sp.mode.Plane != "auto" && strings.Contains(sp.exec, "deny") {
			p50, p99 = p50+20000, p99+60000 // a pinned exec: +20 us, +60 us
			if big {
				p50 += 1000000 // +1 ms at 128 KiB
			}
		} else if strings.Contains(sp.exec, "deny") {
			p50 += 8000 // P1's supervisor cost at landlock
		}
		round++
		r.res["exec_p50"], r.res["exec_p99"], r.res["exec_failed"] = p50+float64(round%3), p99, 0
		return r, nil
	}
	var calls uint64
	s.pinStats = func() (uint64, uint64, error) { calls++; return calls * 9000, calls * 100, nil }
	s.doctorRun = func() ([]byte, error) {
		return []byte("doctor: ok\ntego-phase probe.plane.lsm.exec_pin 21000\ntego-phase probe.plane.fmod_ret.exec_pin 18500\n"), nil
	}
	s.execCheck()
	if s.failed {
		t.Fatalf("the exec check failed:\n%s", out)
	}
	for _, m := range perf.Modes[1:] {
		if v := s.got["exec.pinned."+m.Name+".p50_excess_us"]; v < 19.9 || v > 20.1 {
			t.Errorf("%s p50 excess %v, want 20 us", m.Name, v)
		}
		if v := s.got["exec.pinned."+m.Name+".p99_excess_us"]; v != 60 {
			t.Errorf("%s p99 excess %v, want 60 us", m.Name, v)
		}
		if v := s.got["exec.argv128k."+m.Name+".excess_ms"]; v < 1.019 || v > 1.021 {
			t.Errorf("%s 128 KiB excess %v, want 1.02 ms", m.Name, v)
		}
		if v := s.got["exec.norules."+m.Name+".pin_check_ns"]; v != 90 {
			t.Errorf("%s pin check %v, want 90 ns", m.Name, v)
		}
	}
	if s.got["doctor.exec_pin.cgroup-lsm.cold_ms"] != 21 || s.got["doctor.exec_pin.cgroup-fmod_ret.cold_ms"] != 18.5 {
		t.Errorf("doctor's cell: %v", s.got)
	}
	if _, ok := s.got["exec.pinned.landlock.p50_excess_us"]; ok {
		t.Error("landlock, P1's control, has a pinned budget figure")
	}
	if !strings.Contains(out.String(), `"p1.landlock.p50_excess_us"`) {
		t.Errorf("P1's supervisor cost is not printed:\n%s", out)
	}
	if want := *execRounds * len(perf.Modes) * len(execConfs); len(specs) != want {
		t.Errorf("%d runs, want %d", len(specs), want)
	}
	for _, sp := range specs {
		if sp.command != "./execbench" || !slices.Contains(sp.args, "./true") {
			t.Fatalf("an exec run %+v", sp)
		}
	}
	if c := s.contract(specs[1]); !strings.Contains(c, `command: ["./execbench"`) || !strings.Contains(c, `deny: ["./true push"]`) {
		t.Errorf("a contract with rules:\n%s", c)
	}

	// A missing sample, an exec that failed, or no doctor phase fails the check and records nothing for it.
	s, out = samplingSuite(t)
	s.pinStats = func() (uint64, uint64, error) { calls++; return calls * 9000, calls * 100, nil }
	s.doctorRun = func() ([]byte, error) { return []byte("tego-phase probe.plane.lsm.exec_pin 21000\n"), nil }
	s.oneRun = func(sp spec) (*run, error) {
		r := goodSample()
		r.res["exec_p50"], r.res["exec_p99"], r.res["exec_failed"] = 1, 2, 0
		if sp.mode.Name == "bpflsm" && strings.Contains(sp.exec, "deny") {
			r.res["exec_failed"] = 3
		}
		return r, nil
	}
	s.execCheck()
	if !s.failed {
		t.Fatalf("failed execs and a missing doctor phase passed:\n%s", out)
	}
	if _, ok := s.got["exec.pinned.bpflsm.p50_excess_us"]; ok {
		t.Errorf("a mode whose samples failed recorded %v", s.got)
	}
	if _, ok := s.got["doctor.exec_pin.cgroup-fmod_ret.cold_ms"]; ok {
		t.Errorf("a missing doctor phase recorded %v", s.got)
	}
}
