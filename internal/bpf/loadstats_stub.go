// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package bpf

import (
	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/platform/startphase"
)

// LoadOptions is the program options every load of this binary's objects takes. A product build's are cilium/ebpf's
// zero options: no verifier log on the first attempt, the branch-level log only on a refusal
// (TestProductLoadOptionsHaveNoLog). A test build asks for the verifier's statistics while its phases are timed
// (loadstats_tegotesthooks.go).
func LoadOptions() ebpf.ProgramOptions { return ebpf.ProgramOptions{} }

// LoadTrace attributes one collection load in a test build; a product build has none.
type LoadTrace struct{}

// BeginLoad starts a collection load's attribution: always nil in a product build.
func BeginLoad(startphase.Sink, string, string) *LoadTrace { return nil }

// End ends a load's attribution; on a product build's nil trace it does nothing.
func (*LoadTrace) End(map[string]*ebpf.Program) {}

// ReportProgram reports one loaded program's verifier statistics in a test build; a product build has none.
func ReportProgram(string, *ebpf.Program) {}
