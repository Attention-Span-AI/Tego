// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

func scanOf(t testing.TB, f *fixture) *runScan {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := cachedScan(f.dir, r)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// TestScanExecFoldersAreTheProgramsOfTheExecLines: the folders the scan keeps for a compile that needs the run's own
// PATH are those of the exec lines' absolute program paths, first seen first, each once, from the first maxExecScan
// exec lines; a relative path, a line of another kind and a line after the bound add none.
func TestScanExecFoldersAreTheProgramsOfTheExecLines(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000017-execdr")
	exec := func(path string) {
		f.add(`"kind":"exec","source":"seccomp","rule":"exec[x]","verdict":"allow","authority":"rule","argv":["x"],"exec_id":"x/10/1","path":` + strconv.Quote(path))
	}
	exec("/usr/bin/git")
	exec("/opt/py/bin/python3")
	exec("tool") // relative: no folder
	exec("/usr/bin/curl")
	f.add(`"kind":"fs","source":"seccomp","rule":"fs.read","verdict":"allow","authority":"rule","op":"open","path":"/srv/data/x"`)
	for i := 0; i < maxExecScan-4; i++ {
		exec("/usr/bin/git")
	}
	exec("/after/the/bound/prog") // exec line 5001 (the relative one counts): not read
	sc := scanOf(t, f)
	if want := []string{"/usr/bin", "/opt/py/bin"}; !slices.Equal(sc.execDirs, want) {
		t.Errorf("exec folders %v, want %v", sc.execDirs, want)
	}
	if got := sc.moreDirs("/usr/bin"); got != "/opt/py/bin" {
		t.Errorf("moreDirs with /usr/bin on the PATH: %q, want /opt/py/bin", got)
	}
}

// TestScanOfExecLinesDecodesNoPayload: a scan of a run the read model holds takes each exec line's program from
// what the read model decoded, not from its text again: its allocations do not grow with the exec lines.
func TestScanOfExecLinesDecodesNoPayload(t *testing.T) {
	f := bigRun(t, 20000) // a fifth of its lines are execs (4,000)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cachedScan(f.dir, r); err != nil {
		t.Fatal(err)
	}
	n := testing.AllocsPerRun(3, func() {
		if _, err := cachedScan(f.dir, r); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("%.0f allocations for a scan of 20,000 lines, 4,000 of them execs", n)
	if n > 2000 {
		t.Errorf("a scan allocated %.0f objects: it decodes each exec line again", n)
	}
}

// BenchmarkCachedScan55k is the scan InForce makes of a 55k-line run the read model holds, once per version of a run
// that is still being written.
func BenchmarkCachedScan55k(b *testing.B) {
	f := bigRun(b, 55000)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		b.Fatal(err)
	}
	r, err := ledgerview.Open(f.root).Run(f.run)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := cachedScan(f.dir, r); err != nil {
			b.Fatal(err)
		}
	}
}
