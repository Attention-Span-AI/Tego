// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"
)

// TestReadAppliedIsWhatTheKernelHolds (GAPS C221): the limits a run is recorded under are read back from its scope, so
// a value the kernel rounded (memory is held in pages) reads as the kernel holds it and not as the contract asked; a file
// the run never wrote is not read, whatever it holds; and a limit that reads "max" is no limit.
func TestReadAppliedIsWhatTheKernelHolds(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	l := Limits{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1_000_000, PidsMax: 64}
	// What the kernel stores: memory.max to a page (1_000_000 is 244 pages and a bit), the rest as written.
	writeCtl(t, c, "cpu.max", "200000 100000\n")
	writeCtl(t, c, "cpu.weight", "50\n")
	writeCtl(t, c, "memory.max", "999424\n")
	writeCtl(t, c, "pids.max", "64\n")
	writeCtl(t, c, "memory.high", "4096\n") // an ancestor's or a past run's: this run wrote none
	got, err := ReadApplied(c, l)
	if err != nil {
		t.Fatal(err)
	}
	want := Applied{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 999424, WroteMemoryMax: true, PidsMax: 64, WrotePidsMax: true}
	if got != want {
		t.Fatalf("ReadApplied = %+v, want %+v", got, want)
	}
	if got.WroteMemoryHigh {
		t.Error("memory.high was read though the run wrote none")
	}

	// A cap written as 0 reads as 0, a limit the kernel holds as max reads -1.
	writeCtl(t, c, "memory.max", "0\n")
	writeCtl(t, c, "pids.max", "max\n")
	got, err = ReadApplied(c, Limits{MemoryMaxSet: true, PidsMaxSet: true})
	if err != nil || !got.WroteMemoryMax || got.MemoryMax != 0 || !got.WrotePidsMax || got.PidsMax != -1 || got.None() {
		t.Fatalf("zero cap and max: %+v (%v)", got, err)
	}
}

// TestReadAppliedKeepsWhatItReadWhenAFileIsUnreadable: a file that cannot be read is left out and reported, and the others
// are still read, so the record holds what is known rather than nothing; a run that wrote no limit reads none.
func TestReadAppliedKeepsWhatItReadWhenAFileIsUnreadable(t *testing.T) {
	fs := newTestFS(t)
	c, err := fs.Create("a", "r-2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	writeCtl(t, c, "cpu.max", "max 100000\n")
	got, err := ReadApplied(c, Limits{CPUMax: "max 100000", PidsMax: 8}) // pids.max does not exist
	if err == nil || got.CPUMax != "max 100000" || got.WrotePidsMax {
		t.Fatalf("got %+v (%v), want cpu.max read, pids.max left out and the error returned", got, err)
	}
	if got, err := ReadApplied(c, Limits{}); err != nil || !got.None() {
		t.Fatalf("a run that wrote no limit: %+v (%v)", got, err)
	}
	writeCtl(t, c, "cpu.weight", "heavy\n")
	if _, err := ReadApplied(c, Limits{CPUWeight: 5}); err == nil {
		t.Error("a weight that is not a number was read")
	}
}

// None reports whether no file was read back: the run wrote no limit.
func (a Applied) None() bool {
	return a.CPUMax == "" && a.CPUWeight == 0 && !a.WroteMemoryMax && !a.WroteMemoryHigh && !a.WrotePidsMax
}
