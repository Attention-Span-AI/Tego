// SPDX-License-Identifier: Apache-2.0

package agent

import "github.com/attention-span-ai/tego/pkg/policy/gate"

// ExecAssurance chooses how a table's exec command rules and exec gate must hold the facts they decided (ADR 0048
// (3), P2). Best effort, the default, decides on the supervisor's copy of argv and the image's names and continues
// the exec: the kernel copies them again, and a racing thread can change them between the two copies, which run_start
// discloses (best_effort exec.rules/argv, gate.exec). Kernel refuses the run before its child starts (exit 125) unless
// the kernel holds every exec of the run to the decided facts: a decision plane whose mode passed doctor's exec pin
// cell, with the run's slot pinned (the handle's ExecPinClaim).
type ExecAssurance string

const (
	ExecAssuranceBestEffort ExecAssurance = "best-effort"
	ExecAssuranceKernel     ExecAssurance = "kernel"
)

func validateExecAssurance(ds *diags, c *Contract, at func(string) Pos) {
	if c.Exec == nil {
		return
	}
	switch c.Exec.Assurance {
	case "", ExecAssuranceBestEffort, ExecAssuranceKernel:
	default:
		ds.errorf(at("exec.assurance"), CodeSchema, "exec.assurance %q: want best-effort or kernel", c.Exec.Assurance)
	}
}

// ExecutionAssurance is the effective exec.assurance: kernel when either the compiled value or the contract's says
// so, so a hand-built table, or one whose compiled value was lost, never reads as weaker than its contract.
func (rt *RuleTable) ExecutionAssurance() ExecAssurance {
	if rt.ExecAssurance == ExecAssuranceKernel ||
		(rt.Contract != nil && rt.Contract.Exec != nil && rt.Contract.Exec.Assurance == ExecAssuranceKernel) {
		return ExecAssuranceKernel
	}
	return ExecAssuranceBestEffort
}

// ExecFactsDecided reports whether the table decides execs on facts a pin could hold: it has command rules, or an
// exec gate that can escalate (ADR 0048 (3) P2 "When"). Only such a run asks to be pinned.
func (rt *RuleTable) ExecFactsDecided() bool {
	return rt != nil && (rt.ExecCommands.HasRules() || rt.Gate.MayEscalate(gate.Exec))
}

// execAssurance compiles exec.assurance, and warns at a kernel requirement with nothing for it to hold: a table with
// no command rules and no exec gate that can escalate decides no exec on a copied fact.
func (k *compiler) execAssurance() {
	k.rt.ExecAssurance = ExecAssuranceBestEffort
	if k.c.Exec == nil || k.c.Exec.Assurance == "" {
		return
	}
	k.rt.ExecAssurance = k.c.Exec.Assurance
	if k.rt.ExecAssurance == ExecAssuranceKernel && !k.rt.ExecFactsDecided() {
		k.ds.warnf(k.pos("exec.assurance"), CodeRedundantRule, "exec.assurance: kernel holds nothing here: the "+
			"contract has no exec command rules and no exec gate, so no exec is decided on a copied argv; the run "+
			"still needs a tier whose decision plane pins execs").
			fix("remove exec.assurance, or add the exec.allow, exec.deny or gate rules it should hold")
	}
}
