// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"math"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// cpuPeriod is the cpu.max period in microseconds every quota is expressed against (§4 SetLimits).
const cpuPeriod = 100000

// Controller names as they appear in cgroup.controllers.
const (
	ControllerCPU    = "cpu"
	ControllerMemory = "memory"
	ControllerPids   = "pids"
)

// limitFile is one control-file write SetLimits performs.
type limitFile struct {
	Name       string
	Value      string
	Controller string
	// Optional is a file the kernel may not have: its absence is not a missing controller, and the write is
	// skipped (memory.swap.max without swap accounting, where the run records the bypass: UncappedSwap).
	Optional bool
}

// limitFiles lists the writes for l in the fixed order cpu.max, cpu.weight, memory.max, memory.swap.max,
// memory.high, pids.max, skipping fields nobody asked for (§2 Limits, E30). A field whose Set flag is on is
// written even at 0, because that 0 is the cap the operator asked for (E16). Pure.
//
// A memory cap bounds the agent's memory, not only the RAM it holds: memory.max alone lets the kernel reclaim
// the agent's anonymous pages to swap instead of OOM-killing it, so on a host with swap a 64 MiB agent grew to
// the size of the swap space (runtime-launch.md R10, ADR 0038). memory.swap.max goes to 0 with it.
func limitFiles(l Limits) []limitFile {
	var out []limitFile
	if l.CPUMax != "" {
		out = append(out, limitFile{Name: "cpu.max", Value: l.CPUMax, Controller: ControllerCPU})
	}
	if l.CPUWeight != 0 {
		out = append(out, limitFile{Name: "cpu.weight", Value: strconv.Itoa(l.CPUWeight), Controller: ControllerCPU})
	}
	if l.MemoryMax != 0 || l.MemoryMaxSet {
		out = append(out,
			limitFile{Name: "memory.max", Value: strconv.FormatInt(l.MemoryMax, 10), Controller: ControllerMemory},
			limitFile{Name: fileSwapMax, Value: "0", Controller: ControllerMemory, Optional: true})
	}
	if l.MemoryHigh != 0 || l.MemoryHighSet {
		out = append(out, limitFile{Name: "memory.high", Value: strconv.FormatInt(l.MemoryHigh, 10), Controller: ControllerMemory})
	}
	if l.PidsMax != 0 || l.PidsMaxSet {
		out = append(out, limitFile{Name: "pids.max", Value: strconv.Itoa(l.PidsMax), Controller: ControllerPids})
	}
	return out
}

// liftFiles lists the writes that put every file limitFiles can write back to the kernel's default, which is no
// limit: "max" (cpu.max keeps its period), and cpu.weight's 100. LiftLimits writes them on a scope that keeps
// processes tego no longer governs, so that none of them keeps a limit tego wrote (an adoption's release that left
// processes there: ADR 0055, the 2026-11-11 limits amendment). Pure.
func liftFiles() []limitFile {
	return []limitFile{
		{Name: "cpu.max", Value: fmt.Sprintf("max %d", cpuPeriod), Controller: ControllerCPU},
		{Name: "cpu.weight", Value: "100", Controller: ControllerCPU},
		{Name: "memory.max", Value: "max", Controller: ControllerMemory},
		{Name: fileSwapMax, Value: "max", Controller: ControllerMemory},
		{Name: "memory.high", Value: "max", Controller: ControllerMemory},
		{Name: "pids.max", Value: "max", Controller: ControllerPids},
	}
}

// fileSwapMax is the memory controller's swap cap, present only where the kernel accounts swap to cgroups
// (CONFIG_SWAP and CONFIG_MEMCG, and no cgroup.memory=noswap or swapaccount=0 on the boot line). Its absence
// does not mean the cgroup cannot swap: with swap accounting off and a swap area active, the kernel still
// reclaims the cgroup's anonymous pages to swap, uncapped and unaccounted, so memory.max alone is exceeded
// into swap. A run with a memory cap records that as a limits gap (UncappedSwap, ADR 0038's 2026-09-24 note).
const fileSwapMax = "memory.swap.max"

// FormatCPUMax renders a core count as the cpu.max line "<round(cores*100000)> 100000"; "" is
// "max 100000" (§4 SetLimits). A non-positive or non-numeric value is an error, never written.
func FormatCPUMax(cores string) (string, error) {
	if cores == "" {
		return fmt.Sprintf("max %d", cpuPeriod), nil
	}
	f, err := strconv.ParseFloat(cores, 64)
	if err != nil {
		return "", fmt.Errorf("cgroup: cpu %q: %w", cores, ErrInvalidLimit)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return "", fmt.Errorf("cgroup: cpu %q: %w", cores, ErrInvalidLimit)
	}
	quota := math.Round(f * cpuPeriod)
	if quota < 1 || quota > math.MaxInt64/2 {
		return "", fmt.Errorf("cgroup: cpu %q: %w", cores, ErrInvalidLimit)
	}
	return fmt.Sprintf("%d %d", int64(quota), cpuPeriod), nil
}

// FromResolved converts a compiled contract's clamped limits into control-file values. A field
// nobody asked for stays untouched (the kernel default "max"); a field asked for as exactly 0 keeps
// its presence flag, so it is written as the cap it is (E16). CPU goes through FormatCPUMax.
func FromResolved(r agent.ResolvedLimits) (Limits, error) {
	l := Limits{
		CPUWeight:     r.CPUWeight,
		MemoryMax:     r.MemoryB,
		MemoryHigh:    r.MemoryHigh,
		PidsMax:       r.Pids,
		MemoryMaxSet:  r.Bounded(agent.BudgetMemory),
		MemoryHighSet: r.Bounded(agent.BudgetMemoryHigh),
		PidsMaxSet:    r.Bounded(agent.BudgetPids),
	}
	if r.CPU != "" {
		s, err := FormatCPUMax(r.CPU)
		if err != nil {
			return Limits{}, err
		}
		l.CPUMax = s
	}
	return l, nil
}
