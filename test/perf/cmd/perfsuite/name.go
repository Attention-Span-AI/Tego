// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/test/perf"
)

// The name check (ADR 0043 C10): what deny_read's name entries cost an open, a refusal, a directory rename, a warm
// start and Prepare's fill, in each plane mode the boot offers. Two contracts alternate, round after round with the
// mode order rotated as in the open check: "set" is the suite's contract, whose built-in .env entries set the slot
// header's name flag, and "clear" the same contract with deny_read: [], which switches the built-in list off, so the
// flag is clear and no name check runs. A set run's agent prints its readiness, the suite then makes a .env.local at
// two depths (a name entry's file created after compile, which only the name check refuses) and releases it.
//
// The check runs only when asked (-checks name): its first guest run (6.17, 2026-10-20, ADR 0043's notes) put the
// set and clear contracts' medians several hundred ns apart in either direction from one plane mode to the next, so
// a 30 ns or 300 ns figure is below what two runs of different contracts resolve; its limits stand and it fails
// over them.
const (
	nameGate   = "out/name-go"
	nameRename = "out/r1:out/r2"
	// nameDeepLevels is open.name.refused.deep's depth below the scope (the project): out and 31 directories.
	nameDeepLevels = 32
	// nameDeclared is how many declared deny_read globs fill.name's contract adds to the built-in pair to make the
	// plane's 64 name rows (the built-in pair is six), over seven glob bases, which with the project make its 8
	// scope rows (pkg/spec/agent's NameRowsMax and NameScopesMax).
	nameDeclared = 58
	nameBases    = 7
)

// nameShallow and nameDeep are the directories of the refused pairs: a .env.prod there exists at compile, so its own
// row refuses it with no name check (the control), and the .env.local the suite makes after the agent is ready is
// refused by the name check and its climb to the scope.
var nameShallow = filepath.Join("out", "a", "b")

func nameDeep() string {
	parts := []string{"out"}
	for i := 1; i < nameDeepLevels; i++ {
		parts = append(parts, fmt.Sprintf("n%02d", i))
	}
	return filepath.Join(parts...)
}

// nameTree makes the files and directories the name check opens and renames, owned by the agent's user.
func (s *suite) nameTree() error {
	for _, d := range []string{nameShallow, nameDeep(), "out/r1"} {
		if err := os.MkdirAll(filepath.Join(s.proj, d), 0o755); err != nil {
			return err
		}
	}
	for i := 0; i < nameBases; i++ {
		if err := os.MkdirAll(filepath.Join(s.proj, "out", "s"+strconv.Itoa(i)), 0o755); err != nil {
			return err
		}
	}
	for _, f := range []string{".envrc", filepath.Join(nameShallow, ".env.prod"), filepath.Join(nameDeep(), ".env.prod")} {
		if err := os.WriteFile(filepath.Join(s.proj, f), []byte("x"), 0o644); err != nil {
			return err
		}
	}
	return s.chownTree(filepath.Join(s.proj, "out"))
}

// nameTreeRemove takes the name check's files away again, so no later check's table holds their rows.
func (s *suite) nameTreeRemove() {
	_ = os.Remove(filepath.Join(s.proj, ".envrc"))
	for _, d := range []string{"out/a/b/.env.prod", "out/n01", "out/r1", "out/r2", "out/name-go"} {
		_ = os.RemoveAll(filepath.Join(s.proj, d))
	}
	for i := 0; i < nameBases; i++ {
		_ = os.RemoveAll(filepath.Join(s.proj, "out", "s"+strconv.Itoa(i)))
	}
}

// nameLate is the .env.local files a set run's agent is refused by name: made after its readiness, so compile never
// saw them.
func nameLate() []string {
	return []string{filepath.Join(nameShallow, ".env.local"), filepath.Join(nameDeep(), ".env.local")}
}

// nameArgs is a run's openbench line: the rename loop, then out/f (no lead) and .envrc (a lead, no row), and for a
// set run each refused pair, control first.
func nameArgs(set bool) []string {
	args := []string{"-n", strconv.Itoa(*opens), "-nref", "2000", "-reps", "3", "-cpu", strconv.Itoa(*cpu), "-up", "-rename", nameRename}
	if !set {
		return append(args, "out/f", ".envrc")
	}
	args = append(args, "-gate", nameGate, "out/f", ".envrc")
	for i, late := range nameLate() {
		dir := nameShallow
		if i == 1 {
			dir = nameDeep()
		}
		args = append(args, "!"+filepath.Join(dir, ".env.prod"), "!"+late)
	}
	return args
}

// nameResults are a run's openbench figures by name.
var nameResults = map[bool][]string{false: {"rename_0", "open_0", "open_1"},
	true: {"rename_0", "open_0", "open_1", "open_2", "open_3", "open_4", "open_5"}}

// nameRun is one run of the name check: a set run is released once the late files exist, and they are removed
// after it.
func (s *suite) nameRun(m perf.Mode, set bool) (*run, error) {
	sp := spec{mode: m, record: "off", tag: "name-" + m.Name, args: nameArgs(set), noBuiltIn: !set}
	if !set {
		r, err := s.one(sp)
		return r, sampleError(r, err, nameResults[set]...)
	}
	gate := filepath.Join(s.proj, nameGate)
	_ = os.Remove(gate)
	defer func() {
		_ = os.Remove(gate)
		for _, f := range nameLate() {
			_ = os.Remove(filepath.Join(s.proj, f))
		}
	}()
	r, err := s.launch(sp)
	if err != nil {
		return nil, err
	}
	select {
	case <-r.upCh:
	case <-time.After(120 * time.Second):
	}
	r.mu.Lock()
	up := r.up
	r.mu.Unlock()
	var errs []error
	if up == 0 {
		errs = append(errs, errors.New("the agent was not ready within 120 s"))
	}
	for _, f := range append(nameLate(), nameGate) {
		errs = append(errs, os.WriteFile(filepath.Join(s.proj, f), []byte("x"), 0o644))
	}
	r.wait(240 * time.Second)
	if err := errors.Join(errs...); err != nil {
		return r, err
	}
	return r, sampleError(r, nil, nameResults[set]...)
}

// nameCheck: *rounds rounds; each runs every plane mode set and clear. A figure is the median over the rounds of
// each run's best loop (the ADR's p50s), the best rounds printed beside it.
func (s *suite) nameCheck() {
	if err := s.nameTree(); err != nil {
		s.fail("name-fail", map[string]any{"operation": "tree", "err": err.Error()})
		return
	}
	defer s.nameTreeRemove()
	modes := s.modes[1:]
	vals := map[string][]float64{} // mode/set|clear/result -> per round
	ups := map[string][]float64{}  // mode/set|clear -> per round, ms
	for round := 0; round < *rounds; round++ {
		for k := range modes {
			m := modes[(k+round)%len(modes)]
			for _, set := range []bool{round%2 == 0, round%2 != 0} {
				key := m.Name + "/" + map[bool]string{true: "set", false: "clear"}[set]
				r, err := s.nameRun(m, set)
				if err != nil {
					s.fail("name-fail", map[string]any{"mode": m.Name, "contract": key, "err": err.Error(), "tail": tailOf(r)})
					continue
				}
				for _, res := range nameResults[set] {
					vals[key+"/"+res] = append(vals[key+"/"+res], r.res[res])
				}
				ups[key] = append(ups[key], ms(r.up))
			}
		}
	}
	for _, m := range modes {
		set, clear := m.Name+"/set/", m.Name+"/clear/"
		out := map[string]any{"mode": m.Name, "opens": *opens, "rounds": *rounds, "cpu": *cpu}
		figure := func(name, a, b string) {
			xa, xb := vals[a], vals[b]
			if len(xa) != *rounds || len(xb) != *rounds {
				s.fail("name-fail", map[string]any{"mode": m.Name, "figure": name, "samples": []int{len(xa), len(xb)}, "required": *rounds})
				return
			}
			v := perf.Median(xa) - perf.Median(xb)
			out[name+"_ns"], out[name+"_min_ns"] = v, perf.Min(xa)-perf.Min(xb)
			s.record(name+"."+m.Name+"_ns", v)
		}
		figure("open.name.miss", set+"open_0", clear+"open_0")
		figure("open.name.lead", set+"open_1", clear+"open_1")
		figure("open.name.refused", set+"open_3", set+"open_2")
		figure("open.name.refused.deep", set+"open_5", set+"open_4")
		figure("rename.dir", set+"rename_0", clear+"rename_0")
		if len(ups[m.Name+"/set"]) > 0 && len(ups[m.Name+"/clear"]) > 0 {
			v := perf.Min(ups[m.Name+"/set"]) - perf.Min(ups[m.Name+"/clear"])
			out["start_excess_ms"] = round1(v)
			s.record("start.name."+m.Name+".excess_ms", v)
		}
		s.emit("name", out)
	}
	s.nameFill()
}

// nameFillGlobs is fill.name's declared deny_read: nameDeclared globs whose final components share one lead (a
// name's first eight bytes) over nameBases bases.
func nameFillGlobs() []string {
	var gs []string
	for i := 0; i < nameDeclared; i++ {
		gs = append(gs, fmt.Sprintf("./out/s%d/*/secretkey%02d.pem", i%nameBases, i))
	}
	return gs
}

// nameFill: Prepare's fill phase with the plane's 64 name rows and 8 scope rows over the same contract with
// deny_read: [], three each alternated, in the fill check's mode (the last).
func (s *suite) nameFill() {
	m := s.modes[len(s.modes)-1]
	fills := map[bool][]float64{}
	for i := 0; i < 6; i++ {
		set := i%2 == 0
		sp := spec{mode: m, record: "off", tag: "name-fill", args: []string{"-n", "1", "-reps", "1", "-up", "notes.txt"}, noBuiltIn: !set}
		if set {
			sp.denyRead = nameFillGlobs()
		}
		r, err := s.one(sp)
		err = sampleError(r, err, "open_0")
		if err == nil {
			if _, ok := r.phases["prepare.fill"]; !ok {
				err = errors.New("missing phase prepare.fill")
			}
		}
		if err != nil {
			s.fail("name-fail", map[string]any{"operation": "fill", "set": set, "err": err.Error(), "tail": tailOf(r)})
			return
		}
		fills[set] = append(fills[set], r.phases["prepare.fill"])
	}
	v := perf.Median(fills[true]) - perf.Median(fills[false])
	s.record("fill.name.ms", v)
	s.emit("name-fill", map[string]any{"mode": m.Name, "set_ms": roundAll(fills[true]), "clear_ms": roundAll(fills[false]), "excess_ms": v})
}

// nameBudget says whether a budget belongs to the name check.
func nameBudget(name string) bool {
	for _, p := range []string{"open.name.", "rename.dir.", "start.name.", "fill.name."} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
