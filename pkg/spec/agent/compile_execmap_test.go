// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIsELFRefusesAFIFO: the scan beneath a write entry reads what the agent put there (I6), so a FIFO swapped in
// for a *.so name after it was listed must be refused, not opened: os.Open of a FIFO with no writer waited for one,
// and the compile, perhaps under sudo, hung.
func TestIsELFRefusesAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "libx.so")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan bool, 1)
	go func() { done <- isELF(fifo) }()
	select {
	case got := <-done:
		if got {
			t.Error("a FIFO read as an ELF file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("isELF waited on a FIFO named like a shared object")
	}
}

// TestNativeCodeScanBoundedWarns: the scan beneath a write entry is bounded by entries and by time (I6), and says
// when it stopped short. filepath.WalkDir listed a directory whole before its count was asked and had no time
// limit, and a scan that stopped named nothing past where it did, in silence.
func TestNativeCodeScanBoundedWarns(t *testing.T) {
	setup := func(t *testing.T) *fixture {
		f := newFixture(t)
		plant := filepath.Join(f.project, "out", "plant")
		if err := os.MkdirAll(plant, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 40; i++ {
			f.file(filepath.Join(plant, "f"+strconv.Itoa(i)), "", 0o644)
		}
		return f
	}
	contract := "version: 0\nname: a\ncommand: [python]\ntier: bpflsm\nfs:\n  write: [\"./out/\"]\nexec:\n  allow: [\"python\"]\n"
	t.Run("entries", func(t *testing.T) {
		defer func(n int) { execMapScanMax = n }(execMapScanMax)
		execMapScanMax = 10
		f := setup(t)
		c := f.load(contract)
		var asked []int
		defer func(r func(*os.File, int) ([]os.DirEntry, error)) { readDirN = r }(readDirN)
		readDirN = func(f *os.File, n int) ([]os.DirEntry, error) {
			asked = append(asked, n)
			return f.ReadDir(n)
		}
		_, ds := f.compile(c)
		if !strings.Contains(render(ds), "read its 10 directory entries and left more unread") {
			t.Errorf("a scan cut at its entry bound said nothing:\n%s", render(ds))
		}
		for _, n := range asked {
			if n <= 0 {
				t.Errorf("a listing asked for every entry (ReadDir(%d)), unbounded", n)
			}
		}
	})
	t.Run("time", func(t *testing.T) {
		defer func(d time.Duration) { execMapScanMaxTime = d }(execMapScanMaxTime)
		execMapScanMaxTime = -time.Second
		f := setup(t)
		_, ds := f.compile(f.load(contract))
		if !strings.Contains(render(ds), "ran out of its time limit") {
			t.Errorf("a scan out of time said nothing:\n%s", render(ds))
		}
	})
}

// TestNativeCodeUnderWriteEntryWarns is ADR 0027's compile warning (agent-contract.md E39, enforce-plane R26): at the
// tiers a decision plane may decide (cgroup, bpflsm, auto), a write entry that holds native code the agent will map
// executable (an ELF shared object, a Node addon) or a known native-module tree (a Python virtual environment, a
// Rust target/) that no exec.allow entry covers warns exec-map, naming the subtree and the exec.allow line to add:
// the plane refuses that PROT_EXEC map, so the import or dlopen fails at run time. The tree is named by its nearest
// known root (.venv, site-packages, node_modules, target, build), else the file's own directory. Tier landlock, which
// decides no mapping (SEMANTICS §4), a covered tree and a contract with no exec: section say nothing.
func TestNativeCodeUnderWriteEntryWarns(t *testing.T) {
	elf := string(elf64("/lib64/ld-fake.so.2", 3))
	setup := func(t *testing.T) *fixture {
		f := newFixture(t)
		out := filepath.Join(f.project, "out")
		file := func(p, content string, mode os.FileMode) {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			f.file(p, content, mode)
		}
		file(filepath.Join(out, ".venv", "lib", "python3.13", "site-packages", "markupsafe", "_speedups.cpython-313-x86_64-linux-gnu.so"), elf, 0o755)
		file(filepath.Join(out, "web", "node_modules", "addon", "build", "Release", "addon.node"), elf, 0o755)
		file(filepath.Join(out, "plugins", "libplug.so.1"), elf, 0o644)
		if err := os.MkdirAll(filepath.Join(out, "crate", "target"), 0o755); err != nil {
			t.Fatal(err)
		}
		file(filepath.Join(out, "notes", "readme.so.txt"), "not code\n", 0o644)
		return f
	}
	wants := []string{"./out/.venv/", "./out/web/node_modules/", "./out/plugins/", "./out/crate/target/"}
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			f := setup(t)
			_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: " + tier +
				"\nfs:\n  write: [\"./out/\"]\nexec:\n  allow: [\"python\"]\n"))
			got := diagsWith(ds, CodeExecMap)
			if len(got) != len(wants) {
				t.Fatalf("%d %s warnings, want %d:\n%s", len(got), CodeExecMap, len(wants), render(ds))
			}
			out := render(ds)
			for _, w := range wants {
				if !strings.Contains(out, "exec.allow: add \""+w+"\"") {
					t.Errorf("no fix naming exec.allow %q:\n%s", w, out)
				}
			}
			if strings.Contains(out, "readme.so.txt") {
				t.Errorf("a file named like a shared object that is none warned:\n%s", out)
			}
		})
	}
	t.Run("covered", func(t *testing.T) {
		f := setup(t)
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: bpflsm\nfs:\n  write: [\"./out/\"]\n" +
			"exec:\n  allow: [\"python\", \"./out/.venv/\", \"./out/web/\", \"./out/plugins/\", \"./out/crate/target/\"]\n"))
		if got := diagsWith(ds, CodeExecMap); len(got) != 0 {
			t.Errorf("covered trees still warn:\n%s", render(ds))
		}
	})
	t.Run("landlock", func(t *testing.T) {
		f := setup(t)
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"./out/\"]\nexec:\n  allow: [\"python\"]\n"))
		if got := diagsWith(ds, CodeExecMap); len(got) != 0 {
			t.Errorf("tier landlock decides no mapping but warned:\n%s", render(ds))
		}
	})
	t.Run("no exec section", func(t *testing.T) {
		f := setup(t)
		_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: bpflsm\nfs:\n  write: [\"./out/\"]\n"))
		if got := diagsWith(ds, CodeExecMap); len(got) != 0 {
			t.Errorf("a contract with no exec: section decides no mapping but warned:\n%s", render(ds))
		}
	})
}

// diagsWith is the diagnostics of one code.
func diagsWith(ds []Diagnostic, code string) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Code == code {
			out = append(out, d)
		}
	}
	return out
}
