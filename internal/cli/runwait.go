// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"sync"
	"time"
)

const codeStartupWait = "startup-wait"

// startupWaitAfter is how long a start is silent before startupWait explains it. A variable so a test that pins a run's
// whole stderr can keep a host that is slow to start from adding the note to it (TestRunLegacyOutput).
var startupWaitAfter = time.Second

// startupWait explains a slow start without adding output to an ordinary one.
// The owner stops and joins the callback before handing the agent its streams,
// or on any early return, including a panic. It never outlives this run.
func startupWait(ctx context.Context, stderr io.Writer, cmd string) func() {
	done := make(chan struct{})
	timer := time.AfterFunc(startupWaitAfter, func() {
		defer close(done)
		if ctx.Err() == nil {
			message(stderr, "", 0, 0, "note: "+cmd+": preparing enforcement; kernel checks and program loads can take several seconds on first use", codeStartupWait)
		}
	})
	var stopped sync.Once
	return func() {
		stopped.Do(func() {
			if !timer.Stop() {
				<-done
			}
		})
	}
}
