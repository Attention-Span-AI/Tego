// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// listedAndUnlisted is a ledger root whose live index names one orphan and not another: what a root holds
// when a launcher died while listed, beside an orphan the index does not name (one lost before any tego
// kept an index, since a launcher lists its run before run_start).
func listedAndUnlisted(t *testing.T) (root, listed, unlisted string) {
	t.Helper()
	root = gcRoot(t)
	listed = lostRun(t, root, time.Now())
	unlisted = lostRun(t, root, time.Now())
	if err := ledger.MarkLive(root, listed); err != nil {
		t.Fatal(err)
	}
	return root, listed, unlisted
}

// stateIn reads a run's state under root.
func stateIn(t *testing.T, root, id string) ledger.RunState {
	t.Helper()
	s, err := ledger.NewRunRepository(root).State(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRunSweepsTheLiveIndex: the sweep `run` makes before it starts ends the orphans the live index names
// and reads no other run, which is what keeps a start from costing every run the root holds. The orphan
// the index does not name is gc's.
func TestRunSweepsTheLiveIndex(t *testing.T) {
	root, listed, unlisted := listedAndUnlisted(t)
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sweepBeforeRun(context.Background(), m, &stderr)
	if !strings.Contains(stderr.String(), "ended 1 orphaned run(s)") {
		t.Errorf("stderr %q", stderr.String())
	}
	if s := stateIn(t, root, listed); s != ledger.StateEnded {
		t.Errorf("the listed orphan is %s, want ended", s)
	}
	if s := stateIn(t, root, unlisted); s != ledger.StateLost {
		t.Errorf("the orphan the index does not name is %s: run's sweep read it", s)
	}
	code, out, errs := gcOut(t)
	if code != identity.ExitOK || !strings.Contains(out, "ended 1 orphaned") {
		t.Fatalf("gc: exit %d, %q %q", code, out, errs)
	}
	if s := stateIn(t, root, unlisted); s != ledger.StateEnded {
		t.Errorf("after gc the unlisted orphan is %s, want ended", s)
	}
}

// TestStopSweepsTheLiveIndex: `stop`'s standing sweep is the same index pass as run's.
func TestStopSweepsTheLiveIndex(t *testing.T) {
	root, listed, unlisted := listedAndUnlisted(t)
	target := endedRun(t, root, time.Now())
	code, out, errs := run(t, "stop", target)
	if code != identity.ExitOK || !strings.Contains(out, target+": not running") {
		t.Fatalf("stop: exit %d, %q %q", code, out, errs)
	}
	if s := stateIn(t, root, listed); s != ledger.StateEnded {
		t.Errorf("the listed orphan is %s, want ended", s)
	}
	if s := stateIn(t, root, unlisted); s != ledger.StateLost {
		t.Errorf("the orphan the index does not name is %s: stop's sweep read it", s)
	}
}
