// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/config"
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
	return endedRunNamed(t, root, id, agentID)
}

// endedRunNamed writes a complete run of agent agentID under root with the id given.
func endedRunNamed(t *testing.T, root string, id identity.RunID, agentID string) string {
	t.Helper()
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

// gcUserLayer is a ledger root in the test's own ~/.tego (userStateFor) whose machine config is the per-user layer
// alone, that root and body; it returns the root, the layer and an ended run 60 days old.
func gcUserLayer(t *testing.T, body string) (root, layer, old string) {
	t.Helper()
	state, layer := userStateFor(t)
	root = filepath.Join(state, "runs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layer, []byte("version: 0\nledger_root: "+root+"\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", "") // the per-user layer alone
	return root, layer, endedRun(t, root, time.Now().Add(-60*24*time.Hour))
}

// TestGCGivesTheLayerBackBeforeItReadsIt is GAPS C52's gc. No Landlock ABI has a chmod right, so an agent can chmod 000
// ~/.tego/config.yaml and ~/.tego, and gc read the config warn-and-skip: the layer was passed over with a warning, and
// the daily pass deleted by the built-in 30 days a 60-day-old run the user's 365 days kept. gc now gives both back to
// their owner first, as run does, reads the layer and keeps the run.
func TestGCGivesTheLayerBackBeforeItReadsIt(t *testing.T) {
	skipAsRoot(t)
	root, layer, old := gcUserLayer(t, "retention: 365d\n")
	if code, out, errs := gcOut(t, "--dry-run"); code != identity.ExitOK || !strings.Contains(out, "would delete 0 older than 365d") {
		t.Fatalf("with the layer readable: exit %d out %q stderr %q, want the run kept for 365 days", code, out, errs)
	}
	state := filepath.Dir(layer)
	for _, p := range []string{layer, state} { // ~/.tego last: its owner can no longer search it
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := gcOut(t)
	for p, want := range map[string]os.FileMode{state: 0o700, layer: 0o400} {
		if st, err := os.Lstat(p); err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v, want mode %04o given back before the config was read\nstderr %q", p, err, want, errs)
		}
		if !strings.Contains(errs, "warning: tego gc: "+p+" had mode 0000") {
			t.Errorf("gc did not say it gave %s back: %q", p, errs)
		}
	}
	if strings.Count(errs, "["+codeOwnStateMode+"]") != 2 {
		t.Errorf("gc's warnings: %q, want one [%s] for each of the two", errs, codeOwnStateMode)
	}
	if code != identity.ExitOK || !strings.Contains(out, "deleted 0 older than 365d") || !exists(t, root, old) {
		t.Errorf("gc after the agent's chmod: exit %d out %q stderr %q, run kept %v; want the 365 days read and the run kept",
			code, out, errs, exists(t, root, old))
	}
}

// TestGCDeletesNothingByAConfigItCannotRead: gc deletes by the retention and the ledger root the config sets, so a
// layer it cannot read whole, after its owner's rights are back, refuses the pass with 125 [config-untrusted], and
// nothing is swept or deleted, whatever --keep says, since such a layer may set the ledger root too. Read
// warn-and-skip, each of these layers was passed over and the run it keeps for 365 days deleted by the built-in 30, or
// by --keep 0s in a ledger root the skipped layer may not have named.
func TestGCDeletesNothingByAConfigItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		body string      // the layer after its ledger_root
		mode os.FileMode // the layer's mode
		env  bool        // $TEGO_CONFIG names a file that is not there
		args []string
		why  string // in the refusal
	}{
		{name: "others can write the layer", body: "retention: 365d\n", mode: 0o620, why: "group or other writable"},
		{name: "a value of the layer does not parse", body: "retention: 365d\nstop_grace: soon\n", mode: 0o600,
			why: "invalid layer"},
		{name: "--keep beside a layer that does not parse", body: "retention: 365d\nstop_grace: soon\n", mode: 0o600,
			args: []string{"--keep", "0s"}, why: "invalid layer"},
		{name: "--keep beside a $TEGO_CONFIG that is not there", body: "retention: 365d\n", mode: 0o600, env: true,
			args: []string{"--keep", "0s"}, why: "$TEGO_CONFIG names"},
		{name: "--json", body: "retention: 365d\n", mode: 0o602, args: []string{"--json"}, why: "group or other writable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, layer, old := gcUserLayer(t, c.body)
			if err := os.Chmod(layer, c.mode); err != nil {
				t.Fatal(err)
			}
			if c.env {
				t.Setenv("TEGO_CONFIG", filepath.Join(t.TempDir(), "machine.yaml"))
			}
			code, out, errs := gcOut(t, c.args...)
			if code != identity.ExitError || !strings.Contains(errs, c.why) || !strings.Contains(errs, "[config-untrusted]") ||
				!strings.Contains(errs, "tego gc: nothing was swept or deleted") {
				t.Errorf("exit %d stderr %q, want 125 [config-untrusted] naming %q and saying nothing was deleted", code, errs, c.why)
			}
			if out != "" {
				t.Errorf("stdout %q, want nothing: no pass was made", out)
			}
			if !exists(t, root, old) {
				t.Errorf("gc deleted the run by a config it could not read")
			}
		})
	}
}

// TestGCDryRunGivesNoModeBack: a dry run changes nothing, so it leaves a layer an agent took as it is, refuses as gc
// refuses any layer it cannot read, and says which command gives the mode back.
func TestGCDryRunGivesNoModeBack(t *testing.T) {
	skipAsRoot(t)
	root, layer, old := gcUserLayer(t, "retention: 365d\n")
	if err := os.Chmod(layer, 0); err != nil {
		t.Fatal(err)
	}
	code, out, errs := gcOut(t, "--dry-run")
	if code != identity.ExitError || !strings.Contains(errs, "permission denied") || !strings.Contains(errs, "--dry-run gives no mode back") {
		t.Errorf("exit %d out %q stderr %q, want 125 naming the layer it could not read and how to give its mode back", code, out, errs)
	}
	if st, err := os.Lstat(layer); err != nil || st.Mode().Perm() != 0 {
		t.Errorf("%s: %v, a dry run changed its mode", layer, err)
	}
	if !exists(t, root, old) {
		t.Errorf("a dry run deleted a run")
	}
}

// journaled records two changes of a contract outside root in root's rule-change journal, as `tego rule` and the
// dashboard do, and removes the contract, so that no line of it is kept as one of its newest: a pass with --keep 0s
// prunes 2 lines, 3 blobs (each text) and 1 lock file (the contract's).
func journaled(t *testing.T, root string) {
	t.Helper()
	journaledIn(t, root, t.TempDir(), "", false)
}

// journaledIn is journaled with the contract, dir/agent.yaml, named name in its texts, so that no line of another
// contract names one of its 3 blobs; it returns the contract's path, and leaves the file there when keep.
func journaledIn(t *testing.T, root, dir, name string, keep bool) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(dir) // the journal names a contract by its resolved path
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.yaml")
	var texts []string
	for _, v := range []string{"a", "b", "c"} {
		texts = append(texts, "version: 0\nname: "+name+v+"\n")
	}
	if err := os.WriteFile(path, []byte(texts[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	g := rulefile.Guard{LedgerRoot: root}
	for i := 1; i < len(texts); i++ {
		if _, err := rulefile.Replace(context.Background(), g, path, rulefile.Sum([]byte(texts[i-1])), []byte(texts[i]),
			rulefile.Change{Via: "cli"}); err != nil {
			t.Fatal(err)
		}
	}
	if !keep {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// journalLines is how many lines root's rule-change journal holds.
func journalLines(t *testing.T, root string) int {
	t.Helper()
	es, err := rulefile.ReadJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// TestGCPrunesTheRuleChangeJournal: gc's retention applies to the ledger root's rule-change journal too: lines inside
// it stay, --dry-run counts what would go and changes nothing, and the pass removes just that.
func TestGCPrunesTheRuleChangeJournal(t *testing.T) {
	root := gcRoot(t)
	journaled(t, root)

	if code, out, errs := gcOut(t); code != identity.ExitOK || strings.Contains(out, "rule-change journal") || journalLines(t, root) != 2 {
		t.Fatalf("lines inside the retention: exit %d, stdout %q, stderr %q, %d lines left", code, out, errs, journalLines(t, root))
	}
	code, out, errs := gcOut(t, "--keep", "0s", "--dry-run")
	if code != identity.ExitOK || !strings.Contains(out, "rule-change journal: would prune 2 line(s), 3 blob(s), 1 lock file(s)") {
		t.Fatalf("--dry-run: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	blobs := filepath.Join(root, rulefile.JournalDirName, rulefile.BlobsDir)
	if ents, err := os.ReadDir(blobs); err != nil || len(ents) != 3 || journalLines(t, root) != 2 {
		t.Fatalf("--dry-run pruned: %d blobs (%v), %d lines", len(ents), err, journalLines(t, root))
	}
	code, out, errs = gcOut(t, "--keep", "0s", "--json")
	var got gcJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); code != identity.ExitOK || err != nil {
		t.Fatalf("exit %d, %v: stdout %q, stderr %q", code, err, out, errs)
	}
	if got.JournalLines != 2 || got.JournalBlobs != 3 || got.JournalLocks != 1 || len(got.Errors) != 0 {
		t.Errorf("json %+v, want 2 lines, 3 blobs and 1 lock file pruned", got)
	}
	if ents, err := os.ReadDir(blobs); err != nil || len(ents) != 0 || journalLines(t, root) != 0 {
		t.Errorf("after the pass: %d blobs (%v), %d lines", len(ents), err, journalLines(t, root))
	}
}

// TestGCJournalNotPrunedWhenALayerWasSkipped: a machine config layer gc cannot read whole may set the retention and the
// ledger root, so gc refuses with 125 and removes nothing, runs or journal, with or without --keep (GAPS C52's rule,
// identity-config.md R20); the rule-change journal keeps both lines.
func TestGCJournalNotPrunedWhenALayerWasSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "runs")
	user, env := filepath.Join(dir, "user.yaml"), filepath.Join(dir, "env.yaml")
	for p, body := range map[string]string{user: "ledger_root: " + root + "\n", env: "retention: forever\n"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	prev := machineSources
	t.Cleanup(func() { machineSources = prev })
	machineSources = func(int, bool) (config.Sources, string, []config.Diagnostic) {
		return config.Sources{User: user, EnvFile: env}, dir, nil
	}
	journaled(t, root)

	for _, args := range [][]string{nil, {"--keep", "0s"}} {
		code, out, errs := gcOut(t, args...)
		if code != identity.ExitError || !strings.Contains(errs, "[config-") || strings.Contains(out, "rule-change journal") {
			t.Errorf("gc %v: exit %d, stdout %q, stderr %q, want 125 naming the layer and nothing pruned", args, code, out, errs)
		}
		if n := journalLines(t, root); n != 2 {
			t.Errorf("gc %v: the journal holds %d lines, want both", args, n)
		}
	}
}

// TestGCDryRunCountsTheJournalAfterTheRunsItRemoves: a run still in the ledger root keeps the journal lines written
// since it started, but gc prunes the journal after it removed the runs; a dry run removes none, so it counts the
// runs it would remove as gone, and says what the pass then prunes.
func TestGCDryRunCountsTheJournalAfterTheRunsItRemoves(t *testing.T) {
	root := gcRoot(t)
	endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	journaled(t, root)
	want := "rule-change journal: %s 2 line(s), 3 blob(s), 1 lock file(s)"
	code, out, errs := gcOut(t, "--keep", "0s", "--dry-run")
	if code != identity.ExitOK || !strings.Contains(out, "would delete 1") || !strings.Contains(out, fmt.Sprintf(want, "would prune")) {
		t.Fatalf("--dry-run: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if n := journalLines(t, root); n != 2 {
		t.Fatalf("--dry-run pruned: %d lines left", n)
	}
	code, out, errs = gcOut(t, "--keep", "0s")
	if code != identity.ExitOK || !strings.Contains(out, "deleted 1") || !strings.Contains(out, fmt.Sprintf(want, "pruned")) {
		t.Errorf("the pass: exit %d, stdout %q, stderr %q", code, out, errs)
	}
}

// TestGCKeepsTheJournalLinesARunningRunReads: a run that still runs, however long, lists the changes of its rules
// file made since it started and an Undo reads the live blocks placed on it, so gc --keep 0s keeps every journal line
// written since it started, and the texts they name.
func TestGCKeepsTheJournalLinesARunningRunReads(t *testing.T) {
	root := gcRoot(t)
	heldRun(t, root, time.Now().Add(-60*24*time.Hour))
	journaled(t, root)
	code, out, errs := gcOut(t, "--keep", "0s")
	if code != identity.ExitOK || strings.Contains(out, "rule-change journal") || strings.Contains(errs, "rule-change journal") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	blobs, err := os.ReadDir(filepath.Join(root, rulefile.JournalDirName, rulefile.BlobsDir))
	if n := journalLines(t, root); n != 2 || err != nil || len(blobs) != 3 {
		t.Errorf("%d lines and %d blobs (%v) left; want both lines and their 3 texts", n, len(blobs), err)
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
