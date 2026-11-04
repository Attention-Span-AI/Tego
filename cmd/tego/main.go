// SPDX-License-Identifier: Apache-2.0

// Command tego is the single binary: the runtime, the checks and the page.
package main

import (
	"os"

	"github.com/attention-span-ai/tego/internal/adapters/claudecode"
	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/mcprelay"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/internal/selftest"
)

func main() {
	// A launcher that gained privilege without being root (a file-capability or setuid copy, a privileged
	// inherited capability set) is refused before anything else runs, the child stage and the helpers included,
	// and one holding only incidental capabilities has them cleared (ADR 0042 (3)(a)). A stage or helper a root
	// launcher starts has real uid 0, and a tier-1 stage holds no capabilities, so neither is touched.
	if code, ok := cli.GuardPrivilege(os.Args, os.Stderr); !ok {
		os.Exit(code)
	}
	// The child stage is dispatched before anything else so no CLI setup runs inside the run's process.
	if len(os.Args) > 1 && os.Args[1] == childCommand {
		os.Exit(childMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == mcprelay.ServerCommand {
		os.Exit(mcprelay.ServerMain(os.Args[2:]))
	}
	// So is the run's open deputy, which the child stage starts in the run's own domain and cgroup (ADR 0041 D2): it
	// confines itself before it says hello, and walks with the supervisor's own walk.
	if len(os.Args) > 1 && os.Args[1] == deputy.Command {
		os.Exit(deputy.Main(os.Args[2:], supervisor.DeputyPinner()))
	}
	// So is a tier-2 build's linger timer, which the last launcher out of a build starts and which outlives it
	// (ADR 0022): it reads no machine config and writes nothing but the build's pins.
	if len(os.Args) > 1 && os.Args[1] == cgroupenforce.LingerCommand {
		os.Exit(cgroupenforce.LingerMain(os.Args[2:]))
	}
	// And the unpinning of a library's capture probes, which the last run out of the library hands off so the
	// kernel's detach is not on its path (ADR 0026 (7)).
	if len(os.Args) > 1 && os.Args[1] == uprobe.DetachCommand {
		os.Exit(uprobe.DetachMain(os.Args[2:]))
	}
	// And the removal of a run's rings above its build's ring pool, which the run hands off once its slot is
	// free, so the kernel's grace periods are not on its path (ADR 0026 (6) as amended).
	if len(os.Args) > 1 && os.Args[1] == cgroupenforce.RingTrimCommand {
		os.Exit(cgroupenforce.RingTrimMain(os.Args[2:]))
	}
	// And a tier-2 run's reaper, which its launcher starts after Prepare and which ends the run at once should the
	// launcher die (ADR 0020): it reads no config and acts on the one run its launcher named.
	if len(os.Args) > 1 && os.Args[1] == runtime.ReapCommand {
		os.Exit(runtime.ReapMain(os.Args[2:]))
	}
	// And an adoption's reaper, which its adopter starts before it moves the agent and which releases the agent
	// should the adopter die (ADR 0055): it acts on the one adoption record root wrote for it.
	if len(os.Args) > 1 && os.Args[1] == runtime.AdoptReapCommand {
		os.Exit(runtime.AdoptReapMain(os.Args[2:]))
	}
	// And doctor's plane probe child, whose syscalls in its scratch cgroup must be the probe's own (docs/p0/
	// enforce-plane.md R21).
	if len(os.Args) > 1 && os.Args[1] == doctor.PlaneProbeCommand {
		os.Exit(doctor.PlaneProbeMain(os.Args[2:]))
	}
	// And a harness's hook, which Claude Code runs as the agent, inside the run, on every tool call (ADR 0063): it
	// reads no machine config, no ledger and no home, so it makes no system call the run refuses.
	if len(os.Args) > 1 && os.Args[1] == claudecode.Verb {
		os.Exit(claudecode.Run(os.Stdin, os.Stdout, os.Stderr, os.Args[2:]))
	}
	// And tego test's check (ADR 0074), which runs as the agent of a self-test run: it performs one harmless action
	// on the decoys of a tree tego test made, so its system calls are the check's alone.
	if len(os.Args) > 1 && os.Args[1] == selftest.CheckVerb {
		os.Exit(selftest.CheckMain(os.Args[2:], os.Stdout, os.Stderr))
	}
	os.Exit(cli.Main(os.Args, os.Stdout, os.Stderr))
}
