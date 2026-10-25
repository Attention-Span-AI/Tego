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

// HookNote is the sentence a harness hook that shows the agent each new refusal adds to Instructions (ADR 0063): a
// fact about where refusals appear, never a command.
const HookNote = "Each refusal is also reported once, in a note beside the tool result that follows it or at the end of the turn."

// HookInstructions is Instructions(reasonPath) and then HookNote: what such a hook tells the agent when a session
// starts.
func HookInstructions(reasonPath string) string { return Instructions(reasonPath) + " " + HookNote }
