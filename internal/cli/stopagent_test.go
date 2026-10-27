// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestStopByAgentName is the `tego stop --agent <name>`: a unit that restarts its agent starts a run with a new id
// each time, so the operator stops the agent by its contract's name. Every live run of that agent is stopped as a stop
// by id stops it (the stop marker, then SIGTERM to the verified launcher); a live-listed run of another agent is left
// alone; a name with no live run says so and exits 0, as "not running" does; a run id beside --agent, or a name that
// is no agent id, is a usage error.
func TestStopByAgentName(t *testing.T) {
	dir, id, info := liveRun(t) // agent "tester", its lock held by a stand-in launcher
	// The stand-in holds the lock without saying who it is; a launcher writes that line (ledger.Open).
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), []byte(info.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(dir)
	other := endedRunAs(t, root, [32]byte{}, "other-agent", time.Now())
	for _, run := range []string{id, other} {
		if err := ledger.MarkLive(root, run); err != nil {
			t.Fatal(err)
		}
	}
	prevSig, prevEsc := signalTarget, escalateRun
	signalled := 0
	signalTarget = func(_ *tegoruntime.StopTarget, sig syscall.Signal) error {
		if sig == syscall.SIGTERM {
			signalled++
		}
		return nil
	}
	escalateRun = func(string, string, io.Writer) {}
	t.Cleanup(func() { signalTarget, escalateRun = prevSig, prevEsc })

	code, out, errs := run(t, "stop", "--agent", "tester", "--grace", "100ms")
	if code != identity.ExitOK || signalled != 1 {
		t.Fatalf("stop --agent tester: exit %d, %d SIGTERMs, want 0 and one (stdout %q stderr %q)", code, signalled, out, errs)
	}
	if !strings.Contains(out, id+":") || strings.Contains(out, other) {
		t.Errorf("stdout %q names the wrong runs: want %s alone", out, id)
	}
	if !tegoruntime.StopRequested(dir) {
		t.Error("no stop marker in the run: the launcher would end it reason=signal, not stopped")
	}

	if code, out, _ := run(t, "stop", "--agent", "nobody"); code != identity.ExitOK || !strings.Contains(out, "nobody: no live run") {
		t.Errorf("stop --agent nobody: exit %d stdout %q, want 0 and \"nobody: no live run\"", code, out)
	}
	for _, args := range [][]string{{"stop", "--agent", "tester", id}, {"stop", "--agent", "Not An Agent"}} {
		if code, _, _ := run(t, args...); code != identity.ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, identity.ExitUsage)
		}
	}
	if signalled != 1 {
		t.Errorf("%d SIGTERMs after the other stops, want still one", signalled)
	}
}
