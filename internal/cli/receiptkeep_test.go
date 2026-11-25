// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// keptRun is an ended, anchored run whose summary can be made and kept: the ledger root of the cli is its parent.
func keptRun(t *testing.T) (id, dir, anchor string, res tegoruntime.Result) {
	t.Helper()
	useStamp(t, releasedStamp)
	id, dir = stampedRun(t, releasedStamp)
	root := filepath.Dir(dir)
	prev := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = prev })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	return id, dir, ledger.DefaultAnchorPath(dir), tegoruntime.Result{RunID: id, Reason: record.RunEndExit}
}

// stampedRun is verifiedRun for a run whose run_start names the tego that ran it, as a real run's does: a kept receipt is
// made by that tego, and --verify holds the copy to it.
func stampedRun(t *testing.T, by receipt.MadeBy) (id, dir string) {
	t.Helper()
	return stampedRunAt(t, by, record.MinorEveryLaunch)
}

// stampedRunAt is stampedRun for a run whose record is of revision minor: the revision this build writes for a run of
// this build, or an older one for a run of a build that never kept a receipt.
func stampedRunAt(t *testing.T, by receipt.MadeBy, minor int) (id, dir string) {
	t.Helper()
	root := gcRoot(t)
	rid, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, dir = string(rid), filepath.Join(root, string(rid))
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"true"}, Cwd: "/", Tier: "landlock", TegoVersion: by.TegoVersion, Commit: by.Commit, Kernel: "test", RecordMinor: minor,
		ContractHash: strings.Repeat("a", 64), LauncherPID: 1, LauncherStartNS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	useAnchor(t, ledger.DefaultAnchorPath(dir))
	return id, dir
}

// summarizeRun is the summary of a run with no copy of its receipt kept: what a test reads the summary's words from.
func summarizeRun(ctx context.Context, m *config.Machine, anchor string, res tegoruntime.Result, mode agent.RecordMode) *endSummary {
	return summarizeRunKeeping(ctx, m, anchor, res, mode, false)
}

// finishKeeping is what tego run does at the end: the summary in one pass, then the kept receipt.
func finishKeeping(ctx context.Context, anchor string, res tegoruntime.Result) (*endSummary, string) {
	s := summarizeRunKeeping(ctx, &config.Machine{}, anchor, res, agent.RecordSummary, true)
	var errs bytes.Buffer
	keepReceipt(ctx, &errs, "tego run", res, s)
	return s, errs.String()
}

// TestRunEndKeepsTheBoundReceipt: after a run ends, its directory holds receipt.json, 0600, the very bytes `tego receipt
// --json` prints for it, bound to the record, and `tego receipt --check` and `--verify` both take it.
func TestRunEndKeepsTheBoundReceipt(t *testing.T) {
	id, dir, anchor, res := keptRun(t)
	s, warn := finishKeeping(t.Context(), anchor, res)
	if warn != "" || s == nil || s.kept == nil {
		t.Fatalf("kept %v, warning %q", s != nil && s.kept != nil, warn)
	}
	path := filepath.Join(dir, ledger.ReceiptFile)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatalf("receipt.json: %v %v", st, err)
	}
	kept, _ := os.ReadFile(path)
	code, out, errs := run(t, "receipt", id, "--json")
	if code != identity.ExitOK || out != string(kept) {
		t.Fatalf("kept bytes differ from `tego receipt --json` (exit %d, stderr %q)\nkept %s\nnow  %s", code, errs, kept, out)
	}
	var m struct {
		Binding *struct {
			Chain struct {
				Run   string `json:"run"`
				Lines uint64 `json:"lines"`
			} `json:"chain"`
		} `json:"binding"`
	}
	if json.Unmarshal(kept, &m) != nil || m.Binding == nil || m.Binding.Chain.Run != id || m.Binding.Chain.Lines == 0 {
		t.Fatalf("the kept receipt is not bound: %s", kept)
	}
	if code, out, errs := run(t, "receipt", "--check", path, dir); code != identity.ExitOK {
		t.Fatalf("--check: exit %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = run(t, "receipt", id, "--verify")
	if code != identity.ExitOK || !strings.Contains(out, "Chain: ") || !strings.Contains(out, "Kept receipt: "+path+" matches the record.") {
		t.Fatalf("--verify: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	code, out, errs = run(t, "receipt", id, "--verify", "--json")
	var obj map[string]any
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &obj) != nil || !strings.Contains(errs, "Kept receipt: ") {
		t.Fatalf("--verify --json: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestKeptReceiptDoesNotChangeTheSummary: keeping the receipt binds and prices it in the summary's own pass and adds
// not one word to the summary.
func TestKeptReceiptDoesNotChangeTheSummary(t *testing.T) {
	_, _, anchor, res := keptRun(t)
	kept := summarizeRunKeeping(t.Context(), &config.Machine{}, anchor, res, agent.RecordSummary, true)
	plain := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordSummary)
	if kept == nil || plain == nil || kept.kept == nil || plain.kept != nil {
		t.Fatalf("kept %+v plain %+v", kept, plain)
	}
	if a, b := kept.textWithMore("tego receipt"), plain.textWithMore("tego receipt"); a != b {
		t.Errorf("the summary changed:\n%s\n%s", a, b)
	}
}

// TestKeptReceiptIsNeverReplacedOrFollowed: a name already under receipt.json (a file, a link to somewhere) is left as
// it is, nothing is written through it, and one warning line says why; the run's summary is still made.
func TestKeptReceiptIsNeverReplacedOrFollowed(t *testing.T) {
	_, dir, anchor, res := keptRun(t)
	path := filepath.Join(dir, ledger.ReceiptFile)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	s, warn := finishKeeping(t.Context(), anchor, res)
	if s == nil || s.rc == nil || !strings.Contains(warn, "already in the run directory") || strings.Count(warn, "\n") != 1 {
		t.Fatalf("summary made %v, warning %q", s != nil, warn)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the link under receipt.json was followed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, warn := finishKeeping(t.Context(), anchor, res); !strings.Contains(warn, "already in the run directory") {
		t.Errorf("warning %q", warn)
	}
	if b, _ := os.ReadFile(path); string(b) != "planted\n" {
		t.Errorf("a receipt.json already there was replaced: %q", b)
	}
	// the planted file is no match: --verify says so, and does not pass it
	if code, _, errs := run(t, "receipt", res.RunID, "--verify"); code == identity.ExitOK || !strings.Contains(errs, "kept receipt") {
		t.Errorf("--verify over a planted receipt.json: exit %d (stderr %q)", code, errs)
	}
}

// TestKeptReceiptIsSkippedWhenTheRunHasNoCompleteRecord: no run, a record that could not be completed, an interrupted
// tego run and a run directory that refuses the write each keep no receipt, and none of them is more than one warning
// line.
func TestKeptReceiptIsSkippedWhenTheRunHasNoCompleteRecord(t *testing.T) {
	_, dir, anchor, res := keptRun(t)
	path := filepath.Join(dir, ledger.ReceiptFile)

	bad := res
	bad.RecordErr = errors.New("disk full")
	if _, warn := finishKeeping(t.Context(), anchor, bad); warn != "" {
		t.Errorf("a record that could not be completed: warning %q", warn)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := summarizeRunKeeping(context.Background(), &config.Machine{}, anchor, res, agent.RecordSummary, true)
	var errs bytes.Buffer
	keepReceipt(ctx, &errs, "tego run", res, s)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) || errs.Len() != 0 {
		t.Errorf("an interrupted tego run kept a receipt (%v) or warned (%q)", err, errs.String())
	}
	if _, warn := finishKeeping(t.Context(), anchor, tegoruntime.Result{}); warn != "" {
		t.Errorf("no run: warning %q", warn)
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		_, warn := finishKeeping(t.Context(), anchor, res)
		if !strings.HasPrefix(warn, "warning: tego run: the receipt was not kept in "+dir) || strings.Count(warn, "\n") != 1 {
			t.Errorf("a run directory that refuses the write: warning %q", warn)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("receipt.json exists after a refused write: %v", err)
		}
	}
}

// TestVerifyComparesTheKeptReceipt: --verify with a kept receipt: clean passes; one byte of the receipt changed fails
// naming what differs; another receipt version is never a pass; a receipt that is absent says nothing; and one changed
// ledger line is the chain's failure, as before.
func TestVerifyComparesTheKeptReceipt(t *testing.T) {
	id, dir, anchor, res := keptRun(t)
	if _, warn := finishKeeping(t.Context(), anchor, res); warn != "" {
		t.Fatal(warn)
	}
	path := filepath.Join(dir, ledger.ReceiptFile)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	put := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, edit := range map[string][2]string{
		"a changed count":         {`"lines": 2`, `"lines": 3`},
		"another receipt version": {`"receipt_v": 1`, `"receipt_v": 2`},
	} {
		if !bytes.Contains(good, []byte(edit[0])) {
			t.Fatalf("%s: the kept receipt has no %q:\n%s", name, edit[0], good)
		}
		put(bytes.Replace(good, []byte(edit[0]), []byte(edit[1]), 1))
		code, out, errs := run(t, "receipt", id, "--verify")
		if code == identity.ExitOK || !strings.Contains(errs, "the kept receipt") || strings.Contains(out, "Kept receipt: ") {
			t.Errorf("%s: exit %d\nstdout %s\nstderr %s", name, code, out, errs)
		}
	}
	put(good)
	if code, out, errs := run(t, "receipt", id, "--verify"); code != identity.ExitOK || !strings.Contains(out, "matches the record") {
		t.Fatalf("restored: exit %d\n%s\n%s", code, out, errs)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "receipt", id, "--verify")
	if code != identity.ExitOK || strings.Contains(out+errs, "Kept receipt") || strings.Contains(out+errs, "kept receipt") {
		t.Errorf("absent: exit %d\n%s\n%s", code, out, errs)
	}
	put(good)
	dropLastLine(t, filepath.Join(dir, ledger.EventsFile))
	if code, _, errs := run(t, "receipt", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "does not verify") {
		t.Errorf("a dropped ledger line: exit %d (stderr %s)", code, errs)
	}
}

// otherBuilds are the tegos that are not the one that kept a receipt: a later release, a build with uncommitted changes
// and a build with no version control stamp. None can compare the receipt's figures; every one can compare its chain.
var otherBuilds = map[string]receipt.MadeBy{
	"a later release":       {TegoVersion: "v0.1.3", Commit: "fedcba9876543210fedcba9876543210fedcba98"},
	"a dirty build":         {TegoVersion: "v0.1.2+dirty", Commit: releasedStamp.Commit},
	"a build with no stamp": {TegoVersion: "dev", Commit: buildinfo.None},
}

// TestVerifyAnotherBuildIsANoteNotAnError: a run kept under one tego and checked by another (an upgrade, a dirty build, a
// build with no stamp) has a chain that verifies, so --verify exits 0 and says the kept receipt's figures were not
// compared; it never says the receipt matches, and a changed count or head is still a difference (exit 1).
func TestVerifyAnotherBuildIsANoteNotAnError(t *testing.T) {
	id, dir, anchor, res := keptRun(t)
	if _, warn := finishKeeping(t.Context(), anchor, res); warn != "" {
		t.Fatal(warn)
	}
	path := filepath.Join(dir, ledger.ReceiptFile)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, by := range otherBuilds {
		t.Run(name, func(t *testing.T) {
			useStamp(t, by)
			code, out, errs := run(t, "receipt", id, "--verify")
			if code != identity.ExitOK || !strings.Contains(out, "Chain: ") || !strings.Contains(out, "Kept receipt: "+path) ||
				!strings.Contains(out, "not compared") || strings.Contains(out, "matches the record") || strings.Contains(errs, "could not be checked") {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			code, out, errs = run(t, "receipt", id, "--verify", "--json")
			var obj map[string]any
			if code != identity.ExitOK || json.Unmarshal([]byte(out), &obj) != nil || !strings.Contains(errs, "not compared") {
				t.Fatalf("--json: exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			// the figures are not compared, but the receipt's own claim of the record still is
			if err := os.WriteFile(path, bytes.Replace(good, []byte(`"lines": 2`), []byte(`"lines": 3`), 1), 0o600); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, good, 0o600); err != nil {
					t.Fatal(err)
				}
			}()
			if code, out, errs := run(t, "receipt", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "only the kept receipt") || strings.Contains(out, "Kept receipt: ") {
				t.Errorf("a changed line count: exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
		})
	}
	// a file that is no receipt at all is still not a pass: only the kept copy differs
	if err := os.WriteFile(path, []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	useStamp(t, otherBuilds["a later release"])
	if code, _, errs := run(t, "receipt", id, "--verify"); code != identity.ExitFinding || !strings.Contains(errs, "only the kept receipt") {
		t.Errorf("a file that is no receipt: exit %d (stderr %q)", code, errs)
	}
}

// TestRunKeepsNoReceiptFromABuildNoTegoCanCheck: a tego that is no exact build (dirty, or with no version stamp) keeps no
// receipt.json, since no tego could ever compare its figures, and says nothing: the receipt is rebuilt from the record
// when asked for, and --verify of such a run still exits 0.
func TestRunKeepsNoReceiptFromABuildNoTegoCanCheck(t *testing.T) {
	for name, by := range otherBuilds {
		if receipt.Exact(by) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			id, dir, anchor, res := keptRun(t)
			useStamp(t, by)
			s, warn := finishKeeping(t.Context(), anchor, res)
			if warn != "" || s == nil || s.kept != nil || s.rc == nil {
				t.Fatalf("summary made %v, copy %v, warning %q", s != nil, s != nil && s.kept != nil, warn)
			}
			if _, err := os.Lstat(filepath.Join(dir, ledger.ReceiptFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("receipt.json exists: %v", err)
			}
			if code, out, errs := run(t, "receipt", id, "--verify"); code != identity.ExitOK || strings.Contains(out+errs, "ept receipt") {
				t.Errorf("--verify: exit %d\n%s\n%s", code, out, errs)
			}
		})
	}
}

// stubRun makes tego run (or tego watch) reach the end of a run that ended with id, with every machine probe answered, so
// that runRun's own end-of-run steps are what a test sees.
func stubRun(t *testing.T, id string) {
	t.Helper()
	prevProbe, prevCapture, prevRun, prevRecorder, prevFailed := probeMachine, captureFor, startRun, recorderFor, startFailed
	t.Cleanup(func() {
		probeMachine, captureFor, startRun, recorderFor, startFailed = prevProbe, prevCapture, prevRun, prevRecorder, prevFailed
	})
	probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
		return &doctor.Report{Tiers: backend.Probe{backend.TierLandlock: true}}, nil
	}
	captureFor = func(*agent.RuleTable, *config.Machine, enforce.Backend) ([]source.Source, []source.Gap) {
		return nil, nil
	}
	recorderFor = func(*agent.RuleTable, *slog.Logger) func(string) (source.Source, error) { return nil }
	startFailed = func(*doctor.Report) {}
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		return tegoruntime.Result{RunID: id, Reason: record.RunEndExit}, nil
	}
}

// TestRunRunPlacesTheReceipt is the wiring: runRun (tego run, and tego watch's, which calls it) leaves receipt.json in
// the run directory when the run ends, with the summary printed or not (--no-summary), and a run that returns no run id
// leaves nothing. The unit tests above call keepReceipt directly; this one fails if runRun does not.
func TestRunRunPlacesTheReceipt(t *testing.T) {
	requireLandlockABI(t)
	for _, tc := range []struct {
		name string
		o    runOptions
		said string // in stderr: the summary's line, or its absence
	}{
		{"tego run", runOptions{}, "tego run: "},
		{"tego run --no-summary", runOptions{noSummary: true}, ""},
		{"tego watch", runOptions{cmd: "tego watch", watched: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, dir, anchor, _ := keptRun(t)
			useAnchor(t, anchor)
			stubRun(t, id)
			o := tc.o
			o.contract, o.command, o.offline = filepath.Join("testdata", "minimal.yaml"), []string{"true"}, true
			var stderr bytes.Buffer
			code := runRun(context.Background(), o, &stderr)
			if code != identity.ExitOK {
				t.Fatalf("exit %d:\n%s", code, stderr.String())
			}
			b, err := os.ReadFile(filepath.Join(dir, ledger.ReceiptFile))
			if err != nil {
				t.Fatalf("no kept receipt after the run: %v\n%s", err, stderr.String())
			}
			if cmp, out, _ := run(t, "receipt", id, "--json"); cmp != identity.ExitOK || out != string(b) {
				t.Errorf("the kept receipt is not what `tego receipt --json` prints:\n%s\n%s", b, out)
			}
			if tc.said != "" && !strings.Contains(stderr.String(), tc.said) {
				t.Errorf("no summary in stderr:\n%s", stderr.String())
			}
			if tc.o.noSummary && strings.Contains(stderr.String(), id+" ended") {
				t.Errorf("--no-summary printed the summary:\n%s", stderr.String())
			}
		})
	}
	t.Run("no run", func(t *testing.T) {
		_, dir, anchor, _ := keptRun(t)
		useAnchor(t, anchor)
		stubRun(t, "")
		var stderr bytes.Buffer
		runRun(context.Background(), runOptions{contract: filepath.Join("testdata", "minimal.yaml"), command: []string{"true"}, offline: true}, &stderr)
		if _, err := os.Lstat(filepath.Join(dir, ledger.ReceiptFile)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a run that never started kept a receipt: %v", err)
		}
	})
}
