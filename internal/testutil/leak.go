// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

// leakProfile is the runtime profile that lists goroutines the collector proved can never run again.
// Go 1.27 registers it by default; Go 1.26 has it only under GOEXPERIMENT=goroutineleakprofile.
const leakProfile = "goroutineleak"

// lookupProfile is pprof.Lookup, a variable so the gate's own test can take the profile away.
var lookupProfile = pprof.Lookup

// errNoLeakProfile is a toolchain without leakProfile. go.mod names go1.27.4 as the toolchain, so only a
// build that refused it (GOTOOLCHAIN=local on an older Go) gets here, and its gate would check nothing.
var errNoLeakProfile = fmt.Errorf("this toolchain has no %q profile, so no leak can be found: "+
	"build with the toolchain go.mod names (Go 1.27)", leakProfile)

// settleRounds and settleStep bound how long LeakCheckMain waits for goroutines a test started just
// before it returned to reach the operation they block on. The profile reports only a goroutine that is
// already parked, so one checked while still on its way there is missed, never misreported: waiting
// can only find more leaks, and the check stops at the first round that finds any.
const (
	settleRounds = 5
	settleStep   = 10 * time.Millisecond
)

// LeakCheckMain runs m's tests and returns the exit code TestMain should pass to os.Exit: m.Run's own
// code, or 1 when the tests passed and the goroutineleak profile then names a leaked goroutine, whose
// stacks it writes to stderr. On a toolchain without the profile it returns 1 as well: it used to pass
// there, and a gate that passes when it cannot look passes vacuously (ADR 0029 step 1).
func LeakCheckMain(m *testing.M) int { return leakCheckAfter(m.Run) }

// leakCheckAfter is LeakCheckMain over the call that runs the tests and returns their code: m.Run, or GuardedMain
// for GuardedLeakCheckMain.
func leakCheckAfter(run func() int) int {
	code := run()
	if code != 0 {
		// The tests already failed, and a test that stopped at t.Fatal can leave a goroutine it would
		// otherwise have ended; reporting that as a leak would bury the failure that caused it.
		return code
	}
	n, err := checkLeaks(os.Stderr)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "testutil: goroutine leak check: %v\n", err)
		return 1
	case n > 0:
		return 1
	}
	return 0
}

// checkLeaks runs the leak-detecting collection and, when it finds leaked goroutines, writes the
// profile with their stacks to w and returns how many there are. No profile is errNoLeakProfile.
func checkLeaks(w io.Writer) (int, error) {
	p := lookupProfile(leakProfile)
	if p == nil {
		return 0, errNoLeakProfile
	}
	var buf bytes.Buffer
	for round := 0; ; round++ {
		buf.Reset()
		// WriteTo runs the collection that marks goroutines leaked; Count reads the marks it left.
		if err := p.WriteTo(&buf, 1); err != nil {
			return 0, err
		}
		n := p.Count()
		if n > 0 {
			fmt.Fprintf(w, "testutil: %d goroutine(s) leaked: blocked on something nothing running can reach\n", n)
			_, _ = w.Write(buf.Bytes())
			return n, nil
		}
		if round == settleRounds {
			return 0, nil
		}
		time.Sleep(settleStep)
	}
}
