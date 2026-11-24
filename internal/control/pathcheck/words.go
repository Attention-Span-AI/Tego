// SPDX-License-Identifier: Apache-2.0

package pathcheck

import (
	"context"
	"errors"
	"strings"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// diskWords is the cause of a check that waited for this computer's own disk or journal.
const diskWords = "the disk of this computer did not finish writing in time (it is very busy or nearly full)"

// Words is the cause of a check that did not finish, in the words the page shows, chosen by the error's type and
// never by its text: the machine is busy, the check was still working, the checker could not start, the request was
// cancelled, earlier checks are stuck, or the location does not answer. It is "" for an error that is none of these.
// The words say what is known and no more: a submitted save may be in either state, which the page says beside them.
func Words(err error) string {
	var remote *RemoteError
	switch {
	case err == nil:
		return ""
	case contracts.IsHelpersStuck(err):
		return "earlier checks are stuck on a location and hold every checker slot, so no new check could start"
	case contracts.IsCheckTooSlow(err):
		return "the machine is very busy: the checker was too slow to finish"
	case contracts.IsCheckWorking(err):
		return "the check was still working when its time ran out"
	case contracts.IsCheckDisk(err):
		return diskWords
	case contracts.IsCheckUnclear(err):
		return "the check did not finish in time, and Tego cannot tell whether a location is stuck or the machine is very busy"
	case contracts.IsStartFailure(err):
		return "the checker could not start"
	case contracts.IsStartupUnavailable(err):
		return "the machine is very busy: the checker did not start in time"
	case contracts.IsLocationUnavailable(err):
		return "the location does not answer (a disconnected or stuck mount?)"
	case contracts.IsCancelledCheck(err), errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded):
		return "the request was cancelled before the check finished"
	case contracts.IsCompileUnfinished(err):
		var nf interface{ NotFinishedWords() string }
		if errors.As(err, &nf) {
			return WordsOf(nf.NotFinishedWords())
		}
		return "the contract check did not finish in time"
	case errors.As(err, &remote):
		return WordsOf(remote.Message)
	case errors.Is(err, context.DeadlineExceeded):
		return "the check ran out of time"
	}
	return ""
}

// WordsOf is Words for text a view carries as a string (an error that crossed the helper pipe, or a refusal a view
// holds): the cause whose own words it contains.
func WordsOf(text string) string {
	for _, c := range []struct{ has, words string }{
		{"earlier checks are still stuck", "earlier checks are stuck on a location and hold every checker slot, so no new check could start"},
		{TooSlow, "the machine is very busy: the checker was too slow to finish"},
		{Working, "the check was still working when its time ran out"},
		{contracts.CompileStillWorking, "the compile was still working when its time ran out"},
		{contracts.CompileBusy, "the compiler is busy with other checks"},
		{contracts.CompileCouldNotRun, "Tego's compiler could not run"},
		{Disk, diskWords},
		{Unclear, "the check did not finish in time, and Tego cannot tell whether a location is stuck or the machine is very busy"},
		{StartFailed, "the checker could not start"},
		{Busy, "the machine is very busy: the checker did not start in time"},
		{contracts.CompileUnfinished, "the machine is very busy: the contract check did not finish in time"},
		{contracts.CompileNoAnswer, "the contract check did not finish in time"},
		{Unavailable, "the location does not answer (a disconnected or stuck mount?)"},
		{contracts.CancelledCheck, "the request was cancelled before the check finished"},
		{contracts.CompileCancelled, "the request was cancelled before the check finished"},
	} {
		if strings.Contains(text, c.has) {
			return c.words
		}
	}
	return ""
}
