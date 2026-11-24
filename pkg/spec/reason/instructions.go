// SPDX-License-Identifier: Apache-2.0

package reason

// Instructions is the paragraph that tells an agent the reason file exists, for a harness to put where the agent
// reads its setup: facts about what a refusal looks like and where its reason is, never a command. reasonPath is
// the file (TEGO_REASON), quoted as every path the agent may have chosen is.
func Instructions(reasonPath string) string {
	return "This run is governed by Tego, which enforces the run's contract in the kernel. When Tego refuses an " +
		"action, the system call fails with EACCES or EPERM (a refused command commonly exits with status 126), and " +
		"the reason is written to " + Quote(reasonPath) + ": a JSON file (v 1) whose top level is the latest " +
		"refusal, with refusals counting every refusal of the run and recent listing up to the newest 32, each with its " +
		"seq, reason, rule and a one-sentence text. The run's contract decides what is allowed, and the run cannot " +
		"change it."
}

// scopeNote prevents a run's refusal from being mistaken for a verdict on the
// tool beside which the hook delivered it. Neither a PID nor delivery time proves
// tool ownership (ADR 0063, amendment of 2026-11-11).
const scopeNote = "Scope: whole run, including startup and background work; tool call and session attribution unavailable."

// HookNote tells the agent when refusals appear and what their scope is (ADR 0063).
const HookNote = "Pending refusals are reported at session start and after tools or at turn end. Later session starts may repeat pending refusals before a tool or turn-end hook reports them. " + scopeNote

// HookInstructions is Instructions(reasonPath) and then HookNote: what such a hook tells the agent when a session
// starts.
func HookInstructions(reasonPath string) string { return Instructions(reasonPath) + " " + HookNote }
