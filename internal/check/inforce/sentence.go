// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"strings"

	"github.com/attention-span-ai/tego/internal/check/compiledview"
	"github.com/attention-span-ai/tego/internal/check/livestatus"
)

var (
	groupCopy = compiledview.GroupCopy
	isDir     = compiledview.IsDir
	netTarget = compiledview.NetTarget
)

const textLive = "Refused by tego until the run ends"
const (
	// An ended run's live block (EndedLiveRule), by what it did while the run ran. None says it refuses anything now,
	// and only a block the run put in force is said to have refused.
	textEndedInForce      = "Ended with the run: tego refused it while it was in force"
	textEndedPartial      = "Ended with the run: tego refused changes while it was in force; reads were not seen in this run"
	textEndedPartlyKernel = "Ended with the run: tego refused part of it while it was in force; the file changes the kernel decided were not covered"
	textEndedMarked       = "Ended with the run: this run was only watched, so it recorded what matched and refused nothing"
	textEndedNever        = "Ended with the run before the run put it in force: it refused nothing"
	textEnded             = "Ended with the run"
)

// liveGroupCopy is the live group's heading, lede and footer for its rules' states: "Blocked live now" while at
// least one block refuses something, "Marked live now" when every block is a mark on a watched run, which records
// and refuses nothing, "Live blocks, none refusing now" when every block is unblocked for a while or past its time
// limit, and "Blocking live" when the blocks wait for the run to put them in force. The heading never claims more
// than its rows do.
func liveGroupCopy(rules []Rule) (title, lede, foot string) {
	refuses, marks, waits := false, true, false
	for _, r := range rules {
		if r.Live.Refuses() {
			refuses = true
		}
		if r.Live == livestatus.Waiting {
			waits = true
		}
		if r.Live != livestatus.RecordedOnly {
			marks = false
		}
	}
	switch {
	case refuses:
		c := groupCopy[GroupLive]
		return c[0], c[1], "A live block refuses more than the rules file, never less, and ends with the run. Removing one gives back only what it took."
	case marks:
		return "Marked live now", "Marks you added while the agent is watched. They record what matches and refuse nothing. They end with the run.",
			"A mark refuses nothing: it records what matches and ends with the run. Removing one stops the recording."
	case !waits:
		// Every block is unblocked for a while or past its time limit (ADR 0125 decision 4): none refuses now.
		return "Live blocks, none refusing now", "Blocks you added while the agent runs. Each is unblocked for a while or past its time limit, so none refuses anything now.",
			"A block unblocked for a while refuses again at its time limit; one past its limit refuses nothing and leaves the run's list."
	}
	return "Blocking live", "Blocks you added while the agent runs. The run puts each one in force in about a second. They end with the run.",
		"A block refuses nothing until the run puts it in force. From then on it refuses more than the rules file, never less, and ends with the run."
}

// liveWhat is what a live block names, with no word of its state: "cannot run curl". A write block names changes
// only; the sentences that say one add whether reads go through.
func liveWhat(kind, value string) string {
	switch kind {
	case "exec":
		if isDir(value) {
			return "cannot run programs in " + value
		}
		return "cannot run " + value
	case "net":
		return "cannot connect to " + liveNetTarget(value)
	case "path":
		return "cannot open or change " + value
	case "read":
		return "cannot read " + value
	case "write":
		return "cannot change " + value
	}
	return kind + " " + value
}

// liveSentence says a live block.
func liveSentence(kind, value string) string {
	if kind == "write" {
		return "Blocked now: " + liveWhat(kind, value) + " (reads still go through)"
	}
	return "Blocked now: " + liveWhat(kind, value)
}

// liveSentenceIn says a live block in its state now (livestatus): "Blocked now" only while it refuses, "Marked now"
// on a watched run, which records what it names and refuses nothing, and a path block that refuses changes only says
// so. A block of an ended run says only that it ended, since its state now does not say what it did while the run
// ran; liveEnded says that.
func liveSentenceIn(kind, value string, state livestatus.State) string {
	s := liveSentence(kind, value)
	switch state {
	case livestatus.RecordedOnly:
		return "Marked now (recorded, not refused): " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Waiting:
		return "Blocking: " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Ended:
		return "Ended with the run: " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Dormant:
		return "Unblocked for a while (refuses nothing until its time limit): " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Expired:
		return "Ended by its time limit: " + strings.TrimPrefix(s, "Blocked now: ")
	case livestatus.Partial:
		if kind == "path" {
			return "Blocked now: cannot change " + value + " (reads still go through)"
		}
	case livestatus.PartlyKernel:
		return "Partly blocked now: " + strings.TrimPrefix(s, "Blocked now: ") + "; changes the kernel decides in this run are not covered"
	case livestatus.InForce:
	}
	return s
}

// liveEnded says a live block of a run that has ended by what it did while the run ran: was is its state as
// livestatus.Status gave it on the run's facts with the run not ended. sentence is its line: "Was blocked" only for a
// block the run put in force, with "(reads went through)" when it refused changes only, "Was marked (recorded, not
// refused)" for a watched run's mark, and "Never put in force" for a block the run ended before taking up. text says
// the same as the rule's EnforcedText. Neither says the block refuses anything now, and any other state claims nothing.
func liveEnded(kind, value string, was livestatus.State) (sentence, text string) {
	what := liveWhat(kind, value)
	switch was {
	case livestatus.InForce:
		if kind == "write" {
			return "Was blocked: " + what + " (reads went through)", textEndedInForce
		}
		return "Was blocked: " + what, textEndedInForce
	case livestatus.Partial:
		if kind == "path" {
			return "Was blocked: cannot change " + value + " (reads went through)", textEndedPartial
		}
		return "Was blocked: " + what, textEndedInForce
	case livestatus.PartlyKernel:
		if kind == "write" {
			what += " (reads went through)"
		}
		return "Was partly blocked: " + what + "; changes the kernel decided in this run were not covered", textEndedPartlyKernel
	case livestatus.RecordedOnly:
		return "Was marked (recorded, not refused): " + what, textEndedMarked
	case livestatus.Waiting:
		return "Never put in force: " + what, textEndedNever
	case livestatus.Ended, livestatus.Dormant, livestatus.Expired:
		// Status gives none of these of a run it is told has not ended, and none says what the block did.
	}
	return "Ended with the run: " + what, textEnded
}

// liveNetTarget is a live net block's value as a place; it has no scheme, and no port means every port.
func liveNetTarget(v string) string {
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "@") {
		return netTarget("unix:" + v)
	}
	return netTarget(v)
}
