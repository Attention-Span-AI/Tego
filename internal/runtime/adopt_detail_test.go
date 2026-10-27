// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// wantCutDetail fails unless detail is run_end's cut form of a detail longer than record.MaxDetailBytes that began
// with prefix: at most MaxDetailBytes, the start kept, ended with " [cut N bytes]".
func wantCutDetail(t *testing.T, what, detail, prefix string) {
	t.Helper()
	if len(detail) > record.MaxDetailBytes || !strings.HasPrefix(detail, prefix) ||
		!strings.Contains(detail, " [cut ") || !strings.HasSuffix(detail, " bytes]") {
		t.Errorf("%s: run_end detail of %d bytes (max %d) is not the cut form: ...%q", what, len(detail),
			record.MaxDetailBytes, detail[max(0, len(detail)-40):])
	}
}

// TestAdoptionEndCutsALongDetail is ADR 0073's run_end bound at the adoption's own sink: whichever arm of end decided
// the detail (a run ended by an error, or a release), run_end's detail is cut to record.MaxDetailBytes, so a long
// cause still leaves the adoption a run_end the ledger takes.
func TestAdoptionEndCutsALongDetail(t *testing.T) {
	long := func(c string) string { return strings.Repeat(c, 2*record.MaxDetailBytes) }
	released := &adopt.ReleaseResult{To: map[string][]int{"/sys/fs/cgroup/user.slice/session-1.scope": {200, 201}}}
	for _, tc := range []struct {
		name   string
		set    func(a *adoption)
		prefix string
	}{
		{"an error ended the run", func(a *adoption) { a.r.fail(identity.ReasonError, long("e")) }, "eeee"},
		{"released at a request", func(a *adoption) { a.releasedBy = long("u") }, "released at the request of uuuu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &adoption{r: &runner{}, env: adopt.Env{Mount: "/sys/fs/cgroup"}, release: released}
			tc.set(a)
			end, _ := a.end()
			wantCutDetail(t, tc.name, end.Detail, tc.prefix)
		})
	}
}

// TestReleaseOrphanCutsALongDetail is the same bound at the reaper's sink: an orphan's run_end (orphaned) carries
// why and what the release did, cut to record.MaxDetailBytes.
func TestReleaseOrphanCutsALongDetail(t *testing.T) {
	f := newAdoptFixture(t)
	const run = "r-00000000-000000000000a-orphan"
	runs := t.TempDir()
	startedRun(t, runs, run)
	scope := filepath.Join(f.host.mount, "tego.slice", adopt.ScopeName(run))
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := adoptRecord{Run: run, Agent: "tester", Dir: filepath.Join(runs, run), Mount: f.host.mount, Scope: scope,
		From: adoptSession, Anchor: filepath.Join(runs, "chain.log")}
	why := strings.Repeat("w", 2*record.MaxDetailBytes)
	out, err := releaseOrphan(&adoptStore{dir: f.state}, rec, f.host.env(), -1, why, nil)
	if !out.Ended {
		t.Fatalf("releaseOrphan wrote no run_end: %v", err)
	}
	evs := events(t, rec.Dir)
	var end record.RunEndPayload
	if last := evs[len(evs)-1]; last.Kind != record.KindRunEnd || last.DecodePayload(&end) != nil {
		t.Fatalf("the last line is %s, not a run_end", last.Kind)
	}
	if end.Reason != record.RunEndOrphaned {
		t.Errorf("run_end reason %q, want orphaned", end.Reason)
	}
	wantCutDetail(t, "releaseOrphan", end.Detail, "wwww")
}
