// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// readFile reads a file or fails the test.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// writeFile replaces a file's content or fails the test.
func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// events reads every complete event of a run directory.
func events(t *testing.T, dir string) []*record.Event {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader %s: %v", dir, err)
	}
	defer r.Close()
	var out []*record.Event
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		out = append(out, e)
	}
	return out
}

// lastReason returns the run_end reason of a run, or "" when it has none.
func lastReason(t *testing.T, dir string) string {
	t.Helper()
	evs := events(t, dir)
	if len(evs) == 0 {
		return ""
	}
	last := evs[len(evs)-1]
	if last.Kind != record.KindRunEnd {
		return ""
	}
	var p record.RunEndPayload
	if err := last.DecodePayload(&p); err != nil {
		t.Fatalf("decode run_end: %v", err)
	}
	return p.Reason
}

// lastKind returns the kind of a run's last complete event.
func lastKind(t *testing.T, dir string) record.Kind {
	t.Helper()
	evs := events(t, dir)
	if len(evs) == 0 {
		return ""
	}
	return evs[len(evs)-1].Kind
}

// TestMain keeps this package's temporary directories under one parent instead of scattering
// hundreds of short-lived entries directly in the system temp directory: a sibling appearing or
// vanishing there while another package's test enumerates it is a race between test binaries,
// which `go test ./...` runs in parallel (seen against internal/runtime/enforce/landlock's
// sibling-enumeration tests). The parent is created once and removed when the package is done.
func TestMain(m *testing.M) {
	reapMainHelper()         // the binary started as a run's reaper: runs ReapMain and exits
	opathExecHelper()        // the binary started as an integration test's agent: never returns
	runtimeDirHolderHelper() // the binary started as a launcher that holds a runtime directory: never returns
	harnessHookHelper()      // the binary started as a run's granted harness hook: never returns
	parent, err := os.MkdirTemp("", "tego-runtime-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("TMPDIR", parent); err != nil {
		fmt.Fprintf(os.Stderr, "set TMPDIR: %v\n", err)
		os.Exit(1)
	}
	// A run keeps its CODEX_HOME in $XDG_RUNTIME_DIR/tego/<run id> and sweeps the directories its parent holds of
	// runs whose launcher is gone: under the developer's /run/user/<uid> the unit tests' runs made that parent and
	// swept their crashed runs' directories (identity-config.md R27 clause b4). The tego binaries the integration
	// tests start inherit it.
	if err := testutil.PrivateRuntimeDir(parent); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	// The unit tests' runs are minted with host8 00000000 and stand for this host's; a real run's own host8
	// is this host's anyway. TestASweepLeavesAnotherHostsRun names another.
	local := foreignRun
	foreignRun = func(id string) bool { return identity.RunID(id).Host8() != "00000000" && local(id) }
	// testutil.GuardedStdioLeakCheckMain runs the tests and then fails the binary on a goroutine a run left blocked
	// for good: every worker a run starts must end with it. The binary fails, too, when anything in the invoking
	// user's real ~/.tego or ~/.bash_history changed while the tests ran: the integration tests drive the
	// tegotesthooks binary, which keeps its chain anchor and own log out of it only when the test's environment
	// says where (writeMachineConfig), and one that did not appended to the real chain.log unseen.
	//
	// It fails, as well, when a test closed or replaced descriptor 0, 1 or 2: a hand-built runner that left
	// notifyFD at its zero value had shutdown close the binary's stdin, the next file any test opened became
	// descriptor 0, and sys.Own's refusal of a standard number (ADR 0023) then failed whichever unrelated
	// test opened it (TestAForkRefusedBeforeTheWatcherStartsStillEndsTheRunAsPids read its cgroup baseline so).
	code := testutil.GuardedStdioLeakCheckMain(m)
	_ = os.RemoveAll(parent)
	os.Exit(code)
}

// collectFinalizers runs the collector until every finalizer that was already pending when it was
// called has run.
//
// A second close arrives from no code path an audit can read: a descriptor an
// *os.File still owns is closed again by that File's finalizer, whenever the collector next happens
// to run. A test that wants to catch that close cannot wait for it, it has to make it happen. Two
// canary generations are what makes the wait conclusive: the first proves one cycle found everything
// that was already unreachable, and the second is queued only after that generation's finalizers ran,
// so when it fires nothing older is still pending.
func collectFinalizers(t *testing.T) {
	t.Helper()
	for range 2 {
		ran := make(chan struct{})
		func() {
			canary := new(int)
			runtime.SetFinalizer(canary, func(*int) { close(ran) })
		}()
		deadline := time.Now().Add(30 * time.Second)
		for {
			runtime.GC()
			select {
			case <-ran:
			case <-time.After(time.Millisecond):
				if time.Now().After(deadline) {
					t.Fatal("the collector ran no finalizer in 30s; a second close cannot be ruled out")
				}
				continue
			}
			break
		}
	}
}
