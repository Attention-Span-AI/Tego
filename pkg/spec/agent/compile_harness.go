// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// harness resolves the contract's harness: key into the table (agent-contract.md R27, ADR 0062): a named harness is
// itself, and auto (the key absent) is the one the command the run executes names (harness.Detect): the command
// `tego run` was given after the contract (WithRunCommand) when there is one, else the contract's own. A contract
// with no command keeps auto. The launcher resolves auto again from the command it runs, by the same rule, so the
// table's name is what compile prints and never overrides the run's command. The schema has refused any other value.
func (k *compiler) harness() {
	n := k.c.Harness
	if n == "" {
		n = harness.Auto
	}
	switch {
	case n != harness.Auto:
	case k.o.runCommand != "":
		n = n.Resolve(k.o.runCommand)
	case len(k.c.Command) > 0:
		n = n.Resolve(k.c.Command[0])
	}
	k.rt.Harness = n
}

// harness prints the run's harness: the resolved name, or auto when only the run's command can resolve it. What a
// provisioner would make for it is the command line's to print (internal/cli), which knows the provisioners.
func (p *printer) harness(rt *RuleTable) {
	switch {
	case rt.Harness == "" || rt.Harness == harness.Auto:
		p.line("harness   auto (detected when the run starts, from its command's name)")
	case rt.Contract != nil && (rt.Contract.Harness == "" || rt.Contract.Harness == harness.Auto):
		p.line("harness   %s (auto, from the contract's command)", rt.Harness)
	default:
		p.line("harness   %s", rt.Harness)
	}
}

// HarnessHookRule is the rule of the harness hook's exec grant the runtime made (WithHarnessHook, ADR 0064),
// exec.harness-hook[<tego binary>], which its image rule and its command rule both carry; "" when it made none.
func (rt *RuleTable) HarnessHookRule() string {
	if len(rt.HarnessHook) == 0 {
		return ""
	}
	return "exec." + HarnessHookGrant + "[" + rt.HarnessHook[0] + "]"
}

// HarnessHookNote is compile's line for a harness hook a run of rt would grant (ADR 0064): the grant is the exact
// argv, and it holds as every command rule holds at the table's tier. At tier landlock (and on tier cgroup's
// fanotify listener) argv is a copied fact, so a racing thread can run the tego binary with another vector (ADR 0048
// R5); a decision plane that pins execs holds the exec to the vector decided.
func (rt *RuleTable) HarnessHookNote() string {
	if rt.Tier == backend.TierLandlock {
		return "harness hook: exact argv; best effort against a racing thread at tier landlock (ADR 0048 R5)"
	}
	return "harness hook: exact argv; kernel-pinned where the run's decision plane pins execs, best effort against a racing thread elsewhere (ADR 0048 R5)"
}
