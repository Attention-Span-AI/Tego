// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ancestorTree is a scope with the three cgroups above it that a real run has (agent slice, tego.slice and the root the
// manager is built on). The slices hold every limit file at no ceiling; the root holds none, as the cgroup2 root.
func ancestorTree(t *testing.T) (c Cgroup, agent, top, root string) {
	t.Helper()
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	agent = filepath.Dir(c.Path)
	top = filepath.Dir(agent)
	for _, d := range []string{agent, top} {
		setAncestor(t, d, "cpu.max", "max 100000")
		setAncestor(t, d, "memory.max", "max")
		setAncestor(t, d, "memory.high", "max")
		setAncestor(t, d, "pids.max", "max")
	}
	return c, agent, top, fs.Root()
}

func setAncestor(t *testing.T, dir, file, v string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(v+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// scopeWrote puts the scope's own files at what a launch's limits wrote.
func scopeWrote(t *testing.T, c Cgroup) Limits {
	t.Helper()
	writeCtl(t, c, "cpu.max", "200000 100000\n")
	writeCtl(t, c, "cpu.weight", "50\n")
	writeCtl(t, c, "memory.max", "1000000\n")
	writeCtl(t, c, "memory.high", "800000\n")
	writeCtl(t, c, "pids.max", "64\n")
	return Limits{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1_000_000, MemoryHigh: 800_000, PidsMax: 64}
}

// TestReadEffectiveIsTheLowestCeilingOfTheChain: each limit the run wrote reads as the smallest along the
// chain, wherever in it the smallest is; "max" above is no ceiling; a limit lower than every ancestor's is its own.
func TestReadEffectiveIsTheLowestCeilingOfTheChain(t *testing.T) {
	c, agent, top, root := ancestorTree(t)
	l := scopeWrote(t, c)

	// No ancestor holds a ceiling: the scope's own values, unchanged.
	got, err := ReadEffective(c, l, root)
	if err != nil {
		t.Fatal(err)
	}
	want := Applied{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1_000_000, WroteMemoryMax: true,
		MemoryHigh: 800_000, WroteMemoryHigh: true, PidsMax: 64, WrotePidsMax: true}
	if got != want {
		t.Fatalf("no ceiling above: %+v, want %+v", got, want)
	}

	// Nested ceilings: the nearer one lower for memory, the farther one lower for pids, both set for cpu.
	setAncestor(t, agent, "memory.max", "600000")
	setAncestor(t, top, "memory.max", "900000")
	setAncestor(t, agent, "pids.max", "128") // above the scope's own 64: not a ceiling for it
	setAncestor(t, top, "pids.max", "16")
	setAncestor(t, agent, "cpu.max", "150000 100000")
	setAncestor(t, top, "cpu.max", "120000 100000")
	setAncestor(t, top, "memory.high", "max")
	setAncestor(t, agent, "memory.high", "900000") // above the scope's own 800000
	got, err = ReadEffective(c, l, root)
	if err != nil {
		t.Fatal(err)
	}
	want = Applied{CPUMax: "120000 100000", CPUWeight: 50, MemoryMax: 600_000, WroteMemoryMax: true,
		MemoryHigh: 800_000, WroteMemoryHigh: true, PidsMax: 16, WrotePidsMax: true}
	if got != want {
		t.Fatalf("nested ceilings: %+v, want %+v", got, want)
	}

	// The scope's "max" is still bounded by an ancestor: the run wrote it, and the kernel holds it to the ancestor's.
	writeCtl(t, c, "pids.max", "max\n")
	got, err = ReadEffective(c, Limits{PidsMaxSet: true, PidsMax: 1}, root)
	if err != nil || !got.WrotePidsMax || got.PidsMax != 16 {
		t.Fatalf("scope max under an ancestor's 16: %+v (%v)", got, err)
	}
	// And a limit the run never wrote stays unread, whatever the ancestors hold.
	if got.WroteMemoryMax || got.CPUMax != "" || got.WroteMemoryHigh {
		t.Fatalf("a file the run did not write was read: %+v", got)
	}
}

// TestReadEffectiveComparesCPUByBandwidth: cpu.max is quota over period, so a smaller number with a smaller period is
// not necessarily the smaller ceiling; "max" is none; a tie keeps the scope's own words.
func TestReadEffectiveComparesCPUByBandwidth(t *testing.T) {
	c, agent, top, root := ancestorTree(t)
	l := scopeWrote(t, c)
	l.MemoryMax, l.MemoryHigh, l.PidsMax = 0, 0, 0
	for _, tc := range []struct{ name, agent, top, own, want string }{
		{"own has the larger number and the lower bandwidth", "max 100000", "60000 100000", "70000 200000", "70000 200000"},        // 0.35 against 0.6
		{"ancestor has the smaller number and the larger bandwidth", "40000 50000", "max 100000", "70000 200000", "70000 200000"},  // 0.8 against 0.35
		{"ancestor has the larger number and the lower bandwidth", "90000 1000000", "max 100000", "70000 200000", "90000 1000000"}, // 0.09 against 0.35
		{"own is lower", "max 100000", "60000 100000", "30000 100000", "30000 100000"},
		{"ancestor half a core over a longer period", "50000 100000", "max 100000", "200000 100000", "50000 100000"},
		{"tie keeps own", "100000 100000", "100000 100000", "200000 200000", "200000 200000"},
		{"own max, ancestor bounded", "max 100000", "250000 1000000", "max 100000", "250000 1000000"},
		{"all max", "max 100000", "max 100000", "max 100000", "max 100000"},
		{"huge quotas do not overflow", "18446744073709551615 1", "max 100000", "18446744073709551615 2", "18446744073709551615 2"},
	} {
		setAncestor(t, agent, "cpu.max", tc.agent)
		setAncestor(t, top, "cpu.max", tc.top)
		writeCtl(t, c, "cpu.max", tc.own+"\n")
		l.CPUMax = tc.own
		got, err := ReadEffective(c, l, root)
		if err != nil || got.CPUMax != tc.want {
			t.Errorf("%s: cpu.max = %q (%v), want %q", tc.name, got.CPUMax, err, tc.want)
		}
	}
}

// TestReadEffectiveDoesNotGuessWhenAnAncestorIsUnreadable: a ceiling that cannot be read leaves the member out and the
// error names the ancestor file; the members it does not touch are kept.
func TestReadEffectiveDoesNotGuessWhenAnAncestorIsUnreadable(t *testing.T) {
	c, agent, top, root := ancestorTree(t)
	l := scopeWrote(t, c)

	// A file that is not a limit.
	setAncestor(t, top, "pids.max", "lots")
	got, err := ReadEffective(c, l, root)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(top, "pids.max")) || got.WrotePidsMax {
		t.Fatalf("garbled pids.max above: %+v (%v), want pids left out and the error naming %s", got, err, top)
	}
	if !got.WroteMemoryMax || got.MemoryMax != 1_000_000 || got.CPUMax != "200000 100000" {
		t.Fatalf("members the ancestor does not touch were lost: %+v", got)
	}
	setAncestor(t, top, "pids.max", "max")

	// A file a lower ancestor lacks: a scope that holds the file has every ancestor hold it, so its absence is not "no ceiling".
	if err := os.Remove(filepath.Join(agent, "memory.high")); err != nil {
		t.Fatal(err)
	}
	got, err = ReadEffective(c, l, root)
	if err == nil || got.WroteMemoryHigh || !got.WroteMemoryMax {
		t.Fatalf("missing memory.high above: %+v (%v)", got, err)
	}
	setAncestor(t, agent, "memory.high", "max")

	// A file that cannot be opened (a mode a reader without privilege is refused by; root reads it, so skip there).
	if os.Geteuid() != 0 {
		p := filepath.Join(agent, "cpu.max")
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		got, err = ReadEffective(c, l, root)
		if err == nil || got.CPUMax != "" || got.PidsMax != 64 {
			t.Fatalf("unopenable cpu.max above: %+v (%v)", got, err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A garbled cpu.max above, and a scope cpu.max that cannot be compared with a bounded one.
	setAncestor(t, top, "cpu.max", "fast")
	if got, err = ReadEffective(c, l, root); err == nil || got.CPUMax != "" {
		t.Fatalf("garbled cpu.max above: %+v (%v)", got, err)
	}
	setAncestor(t, top, "cpu.max", "50000 100000")
	writeCtl(t, c, "cpu.max", "garbage\n")
	if got, err = ReadEffective(c, Limits{CPUMax: "garbage"}, root); err == nil || got.CPUMax != "" {
		t.Fatalf("garbled own cpu.max under a ceiling: %+v (%v)", got, err)
	}

	// No root to read up to, or a scope that is not below it: every ceiling is left out, the weight stays.
	for _, bad := range []string{"", filepath.Join(t.TempDir(), "elsewhere")} {
		got, err = ReadEffective(c, l, bad)
		if err == nil || got.CPUMax != "" || got.WroteMemoryMax || got.WrotePidsMax || got.WroteMemoryHigh || got.CPUWeight != 50 {
			t.Errorf("top %q: %+v (%v), want every ceiling left out and the weight kept", bad, got, err)
		}
	}
}

// TestReadEffectiveIsTheChainAtTheCall: the read is one look at the tree, so a ceiling changed later shows in the next
// read and not in an earlier result (the launcher reads once, at the run's start).
func TestReadEffectiveIsTheChainAtTheCall(t *testing.T) {
	c, _, top, root := ancestorTree(t)
	l := scopeWrote(t, c)
	first, err := ReadEffective(c, l, root)
	if err != nil || first.MemoryMax != 1_000_000 {
		t.Fatalf("first read: %+v (%v)", first, err)
	}
	setAncestor(t, top, "memory.max", "300000")
	second, err := ReadEffective(c, l, root)
	if err != nil || second.MemoryMax != 300_000 || first.MemoryMax != 1_000_000 {
		t.Fatalf("after the ancestor changed: first %+v, second %+v (%v)", first, second, err)
	}
}

// TestReadEffectiveStopsAtTheRoot: a ceiling above top is not read, and the root of the tree having no limit files is no
// ceiling; EffectiveTop reaches the cgroup2 mount for a scope under it and the manager's root otherwise.
func TestReadEffectiveStopsAtTheRoot(t *testing.T) {
	c, _, top, root := ancestorTree(t)
	l := scopeWrote(t, c)
	setAncestor(t, filepath.Dir(root), "memory.max", "1") // outside the tree: never read
	got, err := ReadEffective(c, l, root)
	if err != nil || got.MemoryMax != 1_000_000 {
		t.Fatalf("a file above the root was read: %+v (%v)", got, err)
	}
	// Stopping lower reads fewer cgroups.
	setAncestor(t, top, "memory.max", "5")
	if got, err = ReadEffective(c, l, filepath.Dir(c.Path)); err != nil || got.MemoryMax != 1_000_000 {
		t.Fatalf("top = the agent slice: %+v (%v)", got, err)
	}

	for _, tc := range []struct{ scope, root, want string }{
		{Mount + "/user.slice/user-1000.slice/user@1000.service/tego.slice/x.scope", Mount + "/user.slice/user-1000.slice/user@1000.service", Mount},
		{Mount + "/tego.slice/tego-a.slice/run-1.scope", Mount, Mount},
		{"/tmp/t/tego.slice/x.scope", "/tmp/t", "/tmp/t"},
		{Mount + "x/y.scope", "/q", "/q"}, // a sibling spelling is not under the mount
	} {
		if got := EffectiveTop(tc.scope, tc.root); got != tc.want {
			t.Errorf("EffectiveTop(%q, %q) = %q, want %q", tc.scope, tc.root, got, tc.want)
		}
	}
}

// TestReadEffectiveLeavesOutWhatTheNamespaceRootHides (review F1): in a private cgroup namespace the mount is a cgroup
// with its own limit files, and the pod and node cgroups above it are not visible although the kernel applies them. A
// chain that ends at such a top is not the whole chain: the folded members are left out and the error says why, never
// the namespace root's number as the one that holds. The real cgroup2 root has neither cgroup.type nor cgroup.events.
func TestReadEffectiveLeavesOutWhatTheNamespaceRootHides(t *testing.T) {
	for _, marker := range []string{"cgroup.type", "cgroup.events"} {
		c, _, _, root := ancestorTree(t)
		l := scopeWrote(t, c)
		setAncestor(t, root, "memory.max", "5000000") // the namespace root's own ceiling
		setAncestor(t, root, marker, "domain")
		got, err := ReadEffective(c, l, root)
		if err == nil || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), "above") {
			t.Fatalf("%s at the top: error %v, want one naming %s and what is above it", marker, err, root)
		}
		if got.CPUMax != "" || got.WroteMemoryMax || got.WroteMemoryHigh || got.WrotePidsMax || got.CPUWeight != 50 {
			t.Fatalf("%s at the top: %+v, want every ceiling left out and the weight kept", marker, got)
		}
	}
	// The root of a tree that holds neither file is the real root: its absent limit files are no ceiling.
	c, _, _, root := ancestorTree(t)
	if got, err := ReadEffective(c, scopeWrote(t, c), root); err != nil || got.MemoryMax != 1_000_000 {
		t.Fatalf("real root: %+v (%v)", got, err)
	}
}
