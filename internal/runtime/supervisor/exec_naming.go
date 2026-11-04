// SPDX-License-Identifier: Apache-2.0

package supervisor

// ExecNaming is metadata captured while an exec notification is blocked. It
// carries naming and grant provenance; the kernel names the executed object and outcome.
type ExecNaming struct {
	GateFields
	Path, ExecID, ParentExecID       string
	RawPath                          string
	MCPName, MCPPath                 string
	Argv                             []string
	ArgvTruncated, Fileless, Dropped bool
	SupervisorOwned                  bool
	AttemptMonoNS                    uint64
	CwdDev, CwdIno                   uint64
	// The command-rule fields of an exec a command rule admitted (ADR 0048 (8)), for the kernel's line to carry.
	CommandRule, CommandList, CommandMatch, CommandVia, ClosureOf, ArgvFacts string
	ArgvRead                                                                 int
	// PinSeq is the seq of the pin this loop wrote for the exec in a pinned run (ADR 0048 (8)), 0 for none: the
	// kernel's line is folded with the plane's kill sample by (run, seq).
	PinSeq uint32
	// RuntimeRule names process-bound authority for this exact vector (the MCP stage). It changes the rule of a
	// confirmed successful exec only; a kernel refusal, lost proof or pin kill remains the kernel's outcome.
	RuntimeRule string
}
