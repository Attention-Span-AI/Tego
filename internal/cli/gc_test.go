// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gcRoot points the machine config at a temp ledger root for one test. The config file has to be 0600
// and under a 0700 directory or the trust check refuses it, which is the same rule a real operator meets.
func gcRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "runs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	return root
}

// endedRun writes a complete run whose id embeds the given mint time, which is what retention ages it by
// (R16: the run id's time36, never the wall timestamp of an event).
func endedRun(t *testing.T, root string, at time.Time) string {
	t.Helper()
	return endedRunOnHost(t, root, [32]byte{}, at)
}

// endedRunOnHost is endedRun minted by another host: its id's host8 is host's first four bytes.
func endedRunOnHost(t *testing.T, root string, host [32]byte, at time.Time) string {
	t.Helper()
	return endedRunAs(t, root, host, "tester", at)
}

// endedRunAs is endedRunOnHost for agent agentID.
func endedRunAs(t *testing.T, root string, host [32]byte, agentID string, at time.Time) string {
	t.Helper()
	id, err := identity.NewRunID(host, at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: agentID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"true"}, Cwd: "/", Tier: "landlock", TegoVersion: "test", Kernel: "test",
		ContractHash: strings.Repeat("a", 64), LauncherPID: 1, LauncherStartNS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// gcOut runs the command through Main, so the flag parsing and the dispatch are exercised too.
func gcOut(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := Main(append([]string{"tego", "gc"}, args...), &out, &errs)
	return code, out.String(), errs.String()
}

// TestGCDryRunRemovesNothing is the flag's whole promise: it must report the same deletion a real pass
// would make and leave the directory on disk.
func TestGCDryRunRemovesNothing(t *testing.T) {
	root := gcRoot(t)
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))

	code, out, errs := gcOut(t, "--dry-run")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "would delete 1") {
		t.Errorf("output %q does not report the deletion it would make", out)
	}
	if _, err := os.Stat(filepath.Join(root, old)); err != nil {
		t.Errorf("a dry run removed the run: %v", err)
	}
}

// TestGCDeletesOnlyWhatAgedOut pins retention: a run older than the window goes, a fresh one stays.
func TestGCDeletesOnlyWhatAgedOut(t *testing.T) {
	root := gcRoot(t)
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	fresh := endedRun(t, root, time.Now())

	code, out, errs := gcOut(t)
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "deleted 1") {
		t.Errorf("output %q", out)
	}
	if _, err := os.Stat(filepath.Join(root, old)); !os.IsNotExist(err) {
		t.Errorf("the aged-out run survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, fresh)); err != nil {
		t.Errorf("a run inside the window was removed: %v", err)
	}
}

// TestGCKeepOverridesTheMachine checks the flag beats the configured retention, in the direction that
// keeps data: a window wide enough to cover everything must delete nothing.
func TestGCKeepOverridesTheMachine(t *testing.T) {
	root := gcRoot(t)
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))

	code, _, errs := gcOut(t, "--keep", "8760h")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(root, old)); err != nil {
		t.Errorf("a wider window still deleted the run: %v", err)
	}
}

// TestGCKeepZeroKeepsNothing: an explicit --keep 0s removes every run that is not running (record-ledger.md's "gc
// --keep 0" sweep). It used to be read as "no --keep" and silently became the machine's 30-day retention, keeping the
// runs it was asked to remove.
func TestGCKeepZeroKeepsNothing(t *testing.T) {
	root := gcRoot(t)
	fresh := endedRun(t, root, time.Now().Add(-time.Minute))

	code, out, errs := gcOut(t, "--keep", "0s")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "deleted 1 older than 0s") {
		t.Errorf("output %q", out)
	}
	if _, err := os.Stat(filepath.Join(root, fresh)); !os.IsNotExist(err) {
		t.Errorf("--keep 0s kept an ended run: %v", err)
	}
}

// TestGCKeepTakesTheConfigGrammar: --keep takes what the machine config's retention takes and what gc prints, days
// included; flag.DurationVar used to refuse "1d".
func TestGCKeepTakesTheConfigGrammar(t *testing.T) {
	root := gcRoot(t)
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	fresh := endedRun(t, root, time.Now().Add(-2*24*time.Hour))

	code, out, errs := gcOut(t, "--keep", "30d")
	if code != identity.ExitOK || !strings.Contains(out, "deleted 1 older than 30d") {
		t.Fatalf("exit %d out %q stderr %q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(root, old)); !os.IsNotExist(err) {
		t.Errorf("the 60-day run survived --keep 30d: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, fresh)); err != nil {
		t.Errorf("the 2-day run was removed by --keep 30d: %v", err)
	}
	for _, bad := range []string{"1w", "-1d", ""} {
		code, _, errs := gcOut(t, "--keep", bad)
		if code != identity.ExitUsage || !strings.Contains(errs, "--keep") || !strings.Contains(errs, "[usage]") {
			t.Errorf("--keep %q: exit %d stderr %q, want a usage error", bad, code, errs)
		}
	}
}

// TestGCJSON pins the machine-readable shape.
func TestGCJSON(t *testing.T) {
	root := gcRoot(t)
	endedRun(t, root, time.Now().Add(-60*24*time.Hour))

	code, out, errs := gcOut(t, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got gcJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("output is not one JSON object: %v (%q)", err, out)
	}
	if got.Root != root || got.Scanned != 1 || got.Deleted != 1 || got.DryRun {
		t.Errorf("json %+v", got)
	}
}

// TestGCEmptyRootIsNotAnError covers a machine where no run has ever been recorded: gc is something an
// operator puts in a timer, and it must not fail before the first run exists.
func TestGCEmptyRootIsNotAnError(t *testing.T) {
	root := gcRoot(t)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	code, out, errs := gcOut(t)
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "scanned 0") {
		t.Errorf("output %q", out)
	}
}

// localHost is this machine's host id as internal/runtime derives it for the runs it mints (hostID).
func localHost() [32]byte {
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		h, herr := os.Hostname()
		if b = []byte(h); herr != nil {
			b = []byte("tego")
		}
	}
	return identity.HostID(b)
}

// lostRun writes a run that has run_start and no run_end and holds no lock: what a launcher killed with SIGKILL
// leaves behind. It is minted with this machine's host id: a sweep leaves a run of another host alone, and these
// tests expect theirs ended.
func lostRun(t *testing.T, root string, at time.Time) string {
	t.Helper()
	id, err := identity.NewRunID(localHost(), at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"true"}, Cwd: "/", Tier: "landlock", TegoVersion: "test", Kernel: "test",
		ContractHash: strings.Repeat("a", 64), LauncherPID: 1, LauncherStartNS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// Close releases the lock and writes run_end; dropping that last line leaves exactly what a killed
	// launcher leaves behind, a free lock over a ledger that never ended. The ledger package's own
	// tests build a lost run the same way.
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	dropLastLine(t, filepath.Join(dir, ledger.EventsFile))
	return string(id)
}

// dropLastLine truncates a file at the start of its final line.
func dropLastLine(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(b) - 2; i >= 0; i-- {
		if b[i] == '\n' {
			if err := os.WriteFile(path, b[:i+1], 0o600); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("%s has no line to drop", path)
}

// TestGCEndsAnOrphan is the recovery path gc exists for. A run whose launcher died holds no lock and has
// no run_end, so every reader calls it lost forever; gc is what closes it with reason=orphaned.
func TestGCEndsAnOrphan(t *testing.T) {
	root := gcRoot(t)
	// Inside the retention window, so the pass ends it and keeps it rather than deleting the evidence.
	lost := lostRun(t, root, time.Now())

	code, out, errs := gcOut(t)
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "ended 1 orphaned") {
		t.Errorf("output %q does not report the orphan", out)
	}
	r, err := ledger.OpenReader(filepath.Join(root, lost))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var last *record.Event
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		last = e
	}
	if last == nil || last.Kind != record.KindRunEnd {
		t.Fatalf("the orphan's last line is %v, want run_end", last)
	}
	var p record.RunEndPayload
	if err := last.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Reason != record.RunEndOrphaned {
		t.Errorf("run_end reason %q, want %q", p.Reason, record.RunEndOrphaned)
	}
}
