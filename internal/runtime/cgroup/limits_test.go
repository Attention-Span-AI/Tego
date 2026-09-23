// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Also pins runtime-launch.md E30: an omitted limit writes nothing, an explicit 0 is written.
func TestLimitFiles(t *testing.T) {
	tests := []struct {
		name string
		in   Limits
		want []limitFile
	}{
		{"zero writes nothing (E30: never a literal 0)", Limits{}, nil},
		{"all", Limits{CPUMax: "200000 100000", CPUWeight: 50, MemoryMax: 1 << 30, MemoryHigh: 1 << 29, PidsMax: 64},
			[]limitFile{
				{"cpu.max", "200000 100000", "cpu", false},
				{"cpu.weight", "50", "cpu", false},
				{"memory.max", "1073741824", "memory", false},
				{"memory.swap.max", "0", "memory", true},
				{"memory.high", "536870912", "memory", false},
				{"pids.max", "64", "pids", false},
			}},
		{"pids only", Limits{PidsMax: 3}, []limitFile{{"pids.max", "3", "pids", false}}},
		{"memory.high above memory.max passes through (case 23)", Limits{MemoryMax: 10, MemoryHigh: 20},
			[]limitFile{{"memory.max", "10", "memory", false}, {"memory.swap.max", "0", "memory", true},
				{"memory.high", "20", "memory", false}}},
		// A memory cap with no swap cap beside it let the kernel swap the agent out instead of OOM-killing it,
		// and the agent grew to the size of the host's swap (TestMainProcessOOMIsReasonOOM skipped wherever the
		// host had free swap). memory.high alone caps nothing, so it leaves swap alone.
		{"memory.high alone leaves swap alone", Limits{MemoryHigh: 20},
			[]limitFile{{"memory.high", "20", "memory", false}}},
		// E16 against E30: the same zero value, one asked for and one not. Only the presence flag
		// tells them apart, and without it the tightest cap an operator can write is silently dropped.
		{"an explicit zero cap is written (E16)", Limits{MemoryMax: 0, MemoryMaxSet: true, PidsMax: 0, PidsMaxSet: true},
			[]limitFile{{"memory.max", "0", "memory", false}, {"memory.swap.max", "0", "memory", true},
				{"pids.max", "0", "pids", false}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := limitFiles(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("limitFiles(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestFormatCPUMax(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "max 100000", false},
		{"2.0", "200000 100000", false},
		{"0.5", "50000 100000", false},
		{"1", "100000 100000", false},
		{"0.333333", "33333 100000", false},
		{"0", "", true},
		{"-1", "", true},
		{"nan", "", true},
		{"inf", "", true},
		{"two", "", true},
		{"1e300", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := FormatCPUMax(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("FormatCPUMax(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidLimit) {
				t.Fatalf("error %v does not wrap ErrInvalidLimit", err)
			}
			if got != tc.want {
				t.Fatalf("FormatCPUMax(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFromResolved(t *testing.T) {
	got, err := FromResolved(agent.ResolvedLimits{CPU: "1.5", CPUWeight: 100, MemoryB: 5, MemoryHigh: 4, Pids: 9})
	if err != nil {
		t.Fatal(err)
	}
	// The three Set flags come with the positive values: a cap that was asked for stays asked for,
	// whatever its number, which is what lets a 0 through in the E16 case below.
	want := Limits{CPUMax: "150000 100000", CPUWeight: 100, MemoryMax: 5, MemoryHigh: 4, PidsMax: 9,
		MemoryMaxSet: true, MemoryHighSet: true, PidsMaxSet: true}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if got, err := FromResolved(agent.ResolvedLimits{}); err != nil || got != (Limits{}) {
		t.Fatalf("zero limits must stay zero: %+v %v", got, err)
	}
	if _, err := FromResolved(agent.ResolvedLimits{CPU: "x"}); !errors.Is(err, ErrInvalidLimit) {
		t.Fatalf("bad cpu: %v", err)
	}

	// E16 against E30: a cap asked for as exactly 0 keeps its flag, so it reaches the control file
	// as the literal "0"; the omitted case above keeps the file untouched.
	zero := agent.ResolvedLimits{Set: agent.BudgetMemory | agent.BudgetPids}
	l, err := FromResolved(zero)
	if err != nil {
		t.Fatal(err)
	}
	if !l.MemoryMaxSet || !l.PidsMaxSet || l.MemoryHighSet {
		t.Fatalf("explicit zero caps lost their presence: %+v", l)
	}
}

func TestMissing(t *testing.T) {
	c := Cgroup{Controllers: []string{"memory", "pids"}}
	l := Limits{CPUMax: "max 100000", CPUWeight: 10, MemoryMax: 1, PidsMax: 1}
	if got := Missing(c, l); !reflect.DeepEqual(got, []string{"cpu"}) {
		t.Fatalf("Missing = %v, want [cpu]", got)
	}
	if got := Missing(Cgroup{}, Limits{}); got != nil {
		t.Fatalf("no limits needs nothing, got %v", got)
	}
	if got := Missing(Cgroup{}, Limits{MemoryMax: 1, PidsMax: 1}); !reflect.DeepEqual(got, []string{"memory", "pids"}) {
		t.Fatalf("Missing = %v", got)
	}
}
