// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestInterpreterCoveredBySameFile: an exec.allow script's #! interpreter is covered only by the same file (or
// its symlinked spelling, or a directory entry above it), as tiers 1 and 2 match an exec by inode; a same-named
// binary elsewhere is no cover, and a bare-name entry's basename covers it only where no run lands below tier 3.
func TestInterpreterCoveredBySameFile(t *testing.T) {
	f := newFixture(t)
	real, other := filepath.Join(f.root, "real"), filepath.Join(f.root, "other")
	for _, d := range []string{real, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(d, "shx"), "not a script\n", 0o755)
	}
	if err := os.Symlink(real, filepath.Join(f.root, "link")); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.bin, "run.sh"), "#!"+filepath.Join(real, "shx")+"\necho\n", 0o755)
	f.file(filepath.Join(f.bin, "vialink.sh"), "#!"+filepath.Join(f.root, "link", "shx")+"\necho\n", 0o755)
	f.file(filepath.Join(f.bin, "shx"), "not a script\n", 0o755)
	for _, c := range []struct {
		name, allow string
		tier3       bool
		warn        bool
	}{
		{"same-named-elsewhere", "[" + filepath.Join(other, "shx") + ", run.sh]", false, true},
		{"bare-name-elsewhere", "[shx, run.sh]", false, true},
		{"bare-name-tier3", "[shx, run.sh]", true, false},
		{"same-file", "[" + filepath.Join(real, "shx") + ", run.sh]", false, false},
		{"dir-entry", "[" + real + ", run.sh]", false, false},
		{"link-spelling", "[" + filepath.Join(real, "shx") + ", vialink.sh]", false, false},
		{"link-dir-entry", "[" + filepath.Join(f.root, "link") + ", run.sh]", false, false},
		// "/" covers every absolute path, as the run's matchExec (agent.Covers) has it; an e+"/" prefix
		// test looked for "//" and warned that an entry the run admits covered nothing.
		{"root-dir-entry", "[/, run.sh]", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			tier, opts := "tier: landlock\n", []CompileOption{WithTiers(backend.TierLandlock, backend.TierBPFLSM)}
			if c.tier3 {
				tier, opts = "tier: bpflsm\n", []CompileOption{WithTiers(backend.TierBPFLSM)}
			}
			ct := f.load("version: 0\nname: a\ncommand: [python]\n" + tier + "exec:\n  allow: " + c.allow + "\n")
			rt, ds, _ := Compile(ct, f.machine, f.opts(opts...)...)
			if got := hasCode(ds, CodeInterpreter); got != c.warn {
				var reach []backend.Tier
				if rt != nil {
					reach = rt.Reach
				}
				t.Errorf("interpreter warning = %v, want %v (reach %v)\n%s", got, c.warn, reach, render(ds))
			}
		})
	}
}

// TestExecSourceWholeElements: provenance de-duplicates whole elements, so mcp:foo is kept beside mcp:foo-bar.
func TestExecSourceWholeElements(t *testing.T) {
	f := newFixture(t)
	ct := f.load("version: 0\nname: a\ncommand: [python]\nmcp:\n  - name: foo-bar\n    command: [python]\n  - name: foo\n    command: [python]\n")
	rt, _ := f.compile(ct)
	r := findExec(rt, "python")
	if r == nil {
		t.Fatal("no python rule")
	}
	parts := strings.Split(r.Source, ",")
	for _, want := range []string{ExecSourceCommand, "mcp:foo-bar", "mcp:foo"} {
		if !slices.Contains(parts, want) {
			t.Errorf("source %q lacks %q", r.Source, want)
		}
	}
}

// TestInterpreterCheckCostIsLinear: the #! check of a contract of n exec.allow scripts costs about n, not n²
// (E24): each rule is resolved once and each distinct interpreter asked once, where each script's check
// resolved every rule again (8.6 s at 1,500 scripts). The answers stay per interpreter: a script whose
// interpreter no entry covers still warns, once per script, among hundreds whose interpreter is covered.
func TestInterpreterCheckCostIsLinear(t *testing.T) {
	// contract writes n scripts and returns the compile of a contract allowing them, which checks its warnings.
	contract := func(n int) func() time.Duration {
		f := newFixture(t)
		shx, lone := filepath.Join(f.root, "shx"), filepath.Join(f.root, "lone")
		f.file(shx, "not a script\n", 0o755)
		f.file(lone, "not a script\n", 0o755)
		var sb strings.Builder
		sb.WriteString("version: 0\nname: a\ncommand: [python]\ntier: landlock\nexec:\n  allow:\n")
		for i := range n {
			p := filepath.Join(f.bin, fmt.Sprintf("s%d.sh", i))
			f.file(p, "#!"+shx+"\necho\n", 0o755)
			fmt.Fprintf(&sb, "    - %s\n", p)
		}
		for i := range 2 {
			p := filepath.Join(f.bin, fmt.Sprintf("lone%d.sh", i))
			f.file(p, "#!"+lone+"\necho\n", 0o755)
			fmt.Fprintf(&sb, "    - %s\n", p)
		}
		sb.WriteString("    - " + shx + "\n") // last, so a check that scans the rules meets it last
		ct := f.load(sb.String())
		return func() time.Duration {
			start := processCPU(t)
			_, ds, _ := Compile(ct, f.machine, f.opts(WithTiers(backend.TierLandlock))...)
			took := processCPU(t) - start
			var warned []string
			for _, d := range ds {
				if d.Code == CodeInterpreter {
					warned = append(warned, d.Message)
				}
			}
			if len(warned) != 2 || !strings.Contains(warned[0], lone) || !strings.Contains(warned[1], lone) {
				t.Fatalf("n=%d: interpreter warnings %q, want the two lone scripts'", n, warned)
			}
			return took
		}
	}
	// The least CPU time of three compiles of each size (processCPU), the sizes interleaved, so a change in the
	// machine's load lands on both.
	small, large := bestInterleaved(3, contract(100), contract(800))
	t.Logf("compile: %v of CPU at 100 scripts, %v at 800", small, large)
	if large > 20*small+100*time.Millisecond {
		t.Errorf("compile costs %v at 800 scripts against %v at 100: it grows faster than the scripts", large, small)
	}
}
