// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/registry"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/selftest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The tests in this file hold the chain of next: lines to one rule: the command a hint prints works as written, from
// where the person types it.

// hintMachine is the machine config saveHarness wrote, as tego loads it.
func hintMachine(t *testing.T) *config.Machine {
	t.Helper()
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// recordsOnly is a watch's run_start.reads_notified.
var recordsOnly = &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}

// shortOf is a run id's last part.
func shortOf(id string) string { return id[strings.LastIndexByte(id, '-')+1:] }

// A run folder ~/bot that holds a file named bot (what go build makes there): tego run bot typed in it is
// agent-ambiguous, so neither the watch's hint nor learn's proposes bot, and --save bot is refused from anywhere,
// since learn's hint then runs tego run bot in that folder. A name a registry already resolves is not proposed again
// (a second watch of the same folder).
func TestHintNamesAreFreeInTheRunFolder(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	m := hintMachine(t)
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(project, "bot"), "#!/bin/sh\n")
	id := readsRun(t, root, anchor, project, recordsOnly, false)
	short := shortOf(id)
	hintsAt(t, false, "on")
	saved := filepath.Join(reg, "agents", "bot.yaml")

	if _, cmd := watchHint(tegoruntime.Result{RunID: id}, &endSummary{root: root, machine: m}, "", project, false); cmd != "tego learn "+short+" --save <name>" {
		t.Errorf("the watch's hint in a folder holding a file bot: %q", cmd)
	}
	code, _, errs := run(t, "learn", short)
	if code != identity.ExitOK || lastHint(t, errs) != "tego learn "+short+" --save <name>" {
		t.Errorf("learn's hint, typed elsewhere: exit %d\n%s", code, errs)
	}
	code, _, errs = run(t, "learn", short, "--save", "bot")
	if _, err := os.Stat(saved); code != identity.ExitFinding || err == nil || !strings.Contains(errs, project) ||
		!strings.Contains(errs, "nothing was written") {
		t.Errorf("--save bot typed elsewhere: exit %d, file there %v:\n%s", code, err == nil, errs)
	}
	t.Chdir(project)
	code, _, errs = run(t, "learn", short, "--save", "bot")
	if _, err := os.Stat(saved); code != identity.ExitFinding || err == nil {
		t.Errorf("--save bot typed in the folder: exit %d, file there %v:\n%s", code, err == nil, errs)
	}

	// A second watch of a folder whose name is saved already.
	other := filepath.Join(resolvedTemp(t), "helper")
	if err := os.MkdirAll(filepath.Join(other, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	first := readsRun(t, root, anchor, other, recordsOnly, false)
	t.Chdir(other)
	if code, _, errs := run(t, "learn", shortOf(first), "--save", "helper"); code != identity.ExitOK {
		t.Fatalf("--save helper: exit %d\n%s", code, errs)
	}
	second := readsRun(t, root, anchor, other, recordsOnly, false)
	if _, cmd := watchHint(tegoruntime.Result{RunID: second}, &endSummary{root: root, machine: m}, "", other, false); cmd !=
		"tego learn "+shortOf(second)+" --save <name>" {
		t.Errorf("the second watch's hint proposes a saved name: %q", cmd)
	}
}

// A name that starts with - is read by tego run as a flag: --save refuses it (exit 2, nothing written), and a folder
// so named is not proposed.
func TestSaveNameNeverStartsWithADash(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, root, anchor, project, recordsOnly, false)
	for _, name := range []string{"-x", "--x", "-"} {
		code, _, errs := run(t, "learn", id, "--save="+name)
		if _, err := os.Stat(filepath.Join(reg, "agents")); code != identity.ExitUsage || err == nil {
			t.Errorf("--save=%s: exit %d, agents/ made %v:\n%s", name, code, err == nil, errs)
		}
	}
	if got := nameFromFolder("/home/dana/-bot"); got != "<name>" {
		t.Errorf("a folder -bot: %q", got)
	}
}

// learn's hint for a run directory given by its path outside the ledger root names the directory: a short id
// resolves only under the ledger root.
func TestLearnHintNamesARunOutsideTheLedgerRootByPath(t *testing.T) {
	_, anchor, reg := saveHarness(t, "")
	elsewhere := filepath.Join(resolvedTemp(t), "copies")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, elsewhere, anchor, project, recordsOnly, false)
	hintsAt(t, false, "on")
	code, _, errs := run(t, "learn", filepath.Join(elsewhere, id))
	if code != identity.ExitOK {
		t.Fatalf("learn <dir>: exit %d\n%s", code, errs)
	}
	next := lastHint(t, errs)
	if next != "tego learn "+filepath.Join(elsewhere, id)+" --save bot" {
		t.Errorf("hint %q", next)
	}
	if code, _, errs := run(t, strings.Fields(next)[1:]...); code != identity.ExitOK {
		t.Errorf("%s: exit %d\n%s", next, code, errs)
	}
	if _, err := os.Stat(filepath.Join(reg, "agents", "bot.yaml")); err != nil {
		t.Error(err)
	}
}

// A run whose supervisor did not answer its read notices (no-supervisor) is not told to run again with --record
// full, which does not change that; its hint is the check of its record.
func TestNoSupervisorRunIsNotToldToRecordEveryRead(t *testing.T) {
	root, _ := summaryHarness(t)
	project := t.TempDir()
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		return tegoruntime.Result{RunID: readsRun(t, root, d.AnchorPath, project,
			&record.ReadsNotified{Why: record.ReadsNotifiedWhyNoSupervisor}, false), Reason: record.RunEndExit}, nil
	}
	hintsAt(t, false, "on")
	var stderr bytes.Buffer
	argv := []string{"tego", "run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--record", "full", "--", "true"}
	if code := mainWith(t.Context(), argv, io.Discard, &stderr, []Command{cmdRun()}); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
	out := stderr.String()
	if !strings.Contains(out, readsLineNoSupervisor) {
		t.Fatalf("no reads line:\n%s", out)
	}
	if got := lastHint(t, out); !strings.HasPrefix(got, "tego receipt ") || !strings.HasSuffix(got, " --verify") {
		t.Errorf("hint %q, want tego receipt <run> --verify", got)
	}
}

// The watch's stop: line is guidance: none with --no-summary.
func TestWatchStopLineIsGuidance(t *testing.T) {
	sandboxedLaunch(t)
	hintsAt(t, false, "on")
	var errs bytes.Buffer
	if code := mainWith(t.Context(), []string{"tego", "watch", "--offline", "--no-summary", "--", "python3"}, io.Discard, &errs,
		[]Command{cmdWatch()}); code != identity.ExitOK {
		t.Fatalf("--no-summary: exit %d\n%s", code, errs.String())
	}
	if strings.Contains(errs.String(), "stop:") {
		t.Errorf("--no-summary printed the stop: line:\n%s", errs.String())
	}
}

// After doctor exit 211, the hint's command checks the tier --require asked for again, never by the command that
// printed it (acceptance B, 2026-11-11): sudo doctor --require for a root tier a person's report lacked, tego setup for tier
// landlock, and for a root report, which a sudo doctor printed, the sentence alone.
func TestDoctorRequireHintKeepsTheTier(t *testing.T) {
	hintsAt(t, false, "on")
	for _, tc := range []struct {
		rep  doctor.Report
		want string
	}{
		{doctor.Report{Tier: backend.TierLandlock, Require: backend.TierCgroup, Fix: "run as root"},
			"\nnext: do what the fix: line above says, then check again:\n  sudo \"$(command -v tego)\" doctor --require cgroup\n"},
		{doctor.Report{Tier: backend.TierCgroup, Require: backend.TierBPFLSM, Root: true, Fix: "boot with lsm=bpf"},
			"\nnext: do what the fix: line above says, then run this check again.\n"},
		{doctor.Report{Require: backend.TierLandlock, Fix: "start tego inside a cgroup of your own"},
			"\nnext: do what the fix: line above says, then check again:\n  tego setup\n"},
	} {
		var b bytes.Buffer
		writeDoctorVerdict(&b, &tc.rep)
		if !strings.HasSuffix(b.String(), tc.want) {
			t.Errorf("%+v: %q, want the end %q", tc.rep, b.String(), tc.want)
		}
	}
}

// learn --save as root for another user (sudo) is refused, nothing written: the file would be root's, mode 0600, in
// the user's own registry, where the user's tego run cannot read it.
func TestLearnSaveRefusesSudo(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, root, anchor, project, recordsOnly, false)
	// sudo by the user 4242: as root InvokingUID reads it; as a user it is ignored and the stand-in euid below is root
	// acting for this user. saveHarness's ownShell removed the one the test binary inherited, so this is the test's own.
	t.Setenv("SUDO_UID", "4242")
	if uid, _ := config.InvokingUID(); uid == 0 {
		t.Skip("the invoking user is root; the refusal is for another user's sudo")
	}
	prev := learnEUID
	learnEUID = func() int { return 0 }
	t.Cleanup(func() { learnEUID = prev })
	code, _, errs := run(t, "learn", id, "--save", "bot")
	if _, err := os.Stat(filepath.Join(reg, "agents")); code != identity.ExitLauncher || err == nil ||
		!strings.Contains(errs, "["+codePrivilege+"]") {
		t.Errorf("exit %d, agents/ made %v:\n%s", code, err == nil, errs)
	}
}

// A registry --save cannot look into (agents/ a link) is refused with the registry's own words, nothing written, and
// not called a name that is taken.
func TestLearnSaveSaysWhyTheRegistryRefused(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(resolvedTemp(t), "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(reg, "agents")); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, root, anchor, project, recordsOnly, false)
	code, _, errs := run(t, "learn", id, "--save", "bot")
	ents, _ := os.ReadDir(target)
	if code != identity.ExitFinding || len(ents) != 0 || strings.Contains(errs, "taken") || strings.Contains(errs, "give another name") ||
		!strings.Contains(errs, "nothing was written") {
		t.Errorf("exit %d, %d files written:\n%s", code, len(ents), errs)
	}
}

// After tego test passed, its hint: record your own agent with tego watch. None after a failed check or with --json.
func TestTestEndsWithTheWatchStep(t *testing.T) {
	prev := selftestRun
	t.Cleanup(func() { selftestRun = prev })
	hintsAt(t, false, "on")
	for _, tc := range []struct {
		verdict string
		json    bool
		code    int
		hint    bool
	}{
		{selftest.VerdictPass, false, identity.ExitOK, true},
		{selftest.VerdictFail, false, identity.ExitFinding, false},
		{selftest.VerdictPass, true, identity.ExitOK, false},
	} {
		selftestRun = func(context.Context, selftest.Options) (selftest.Report, error) {
			return selftest.Report{Tier: "landlock", Verdict: tc.verdict}, nil
		}
		args := []string{"test"}
		if tc.json {
			args = append(args, "--json")
		}
		code, _, errs := run(t, args...)
		want := "\nnext: " + testNext + "\n  tego watch -- " + startPlaceholder + "\n"
		if code != tc.code || strings.HasSuffix(errs, want) != tc.hint || !tc.hint && strings.Contains(errs, "next:") {
			t.Errorf("%s json=%v: exit %d, stderr %q", tc.verdict, tc.json, code, errs)
		}
	}
}

// learn's warning that it skipped lines of a newer record version comes before the hint, which stays last.
func TestLearnHintStaysLastAfterTheNewerRecordWarning(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	spliceVersionLineAt1(t, root, id, "2")
	hintsAt(t, false, "on")
	code, _, errs := run(t, "learn", id)
	if code != identity.ExitOK || strings.Count(errs, "skipped 1 line(s) of a record version newer") != 1 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	lastHint(t, errs)
}

// A run whose folder is not on this machine (a record copied from another): the name is looked up from the working
// directory alone, the save is not refused for the folder, and the hint does not cd to it.
func TestLearnSaveOfARunFolderNotHere(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	gone := filepath.Join(resolvedTemp(t), "gone", "bot")
	id := readsRun(t, root, anchor, gone, recordsOnly, false)
	hintsAt(t, false, "on")
	code, _, errs := run(t, "learn", id, "--save", "bot")
	if _, err := os.Stat(filepath.Join(reg, "agents", "bot.yaml")); code != identity.ExitOK || err != nil {
		t.Fatalf("exit %d, file: %v\n%s", code, err, errs)
	}
	if got := lastHint(t, errs); got != "tego run bot" {
		t.Errorf("hint %q, want no cd to a folder not here", got)
	}
}

// A run or a watch whose record could not be completed (a disk full, or the chain anchor not written) exits 125
// [ledger], tego's own error: it prints no next: block, and the [ledger] line is its last. The reads line is a fact
// and still prints.
func TestARunWhoseRecordIsIncompletePrintsNoNextStep(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		why  *record.ReadsNotified
		err  error
	}{
		{"run, disk full", []string{"run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true"},
			&record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff}, errors.New("write events.jsonl: no space left on device")},
		{"run, anchor not written", []string{"run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true"},
			&record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff}, fmt.Errorf("ledger: run x: %w: permission denied", ledger.ErrAnchorWrite)},
		{"watch, disk full", []string{"watch", "--offline", "--", "true"},
			recordsOnly, errors.New("write events.jsonl: no space left on device")},
		{"watch, anchor not written", []string{"watch", "--offline", "--", "true"},
			recordsOnly, fmt.Errorf("ledger: run x: %w: permission denied", ledger.ErrAnchorWrite)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := summaryHarness(t)
			project := t.TempDir()
			startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
				id := readsRun(t, root, d.AnchorPath, project, tc.why, false)
				return tegoruntime.Result{RunID: id, Reason: record.RunEndExit, RecordErr: tc.err}, nil
			}
			hintsAt(t, false, "on")
			var stderr bytes.Buffer
			code := mainWith(t.Context(), append([]string{"tego"}, tc.argv...), io.Discard, &stderr, []Command{cmdRun(), cmdWatch()})
			got := stderr.String()
			lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
			if code != identity.ExitLauncher || strings.Contains(got, "next:") || !strings.HasSuffix(lines[len(lines)-1], "[ledger]") {
				t.Errorf("exit %d, want 125 with the [ledger] line last and no next: block:\n%s", code, got)
			}
			if tc.argv[0] == "run" && !strings.Contains(got, readsLineReasonOff) {
				t.Errorf("the reads line, a fact, is gone:\n%s", got)
			}
		})
	}
}

// learn's hint saves the proposal it just printed: the flags that shaped it (--workspace, --reads on) are in the hint's
// command, the workspace by its full path, quoted for a shell. Typed as printed, the hint writes the printed proposal,
// with the name it gives, and, as its sentence says, refused reads recorded (--save's default).
func TestLearnHintSavesTheProposalItPrinted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		workspace string // under the run folder; "" is no --workspace
		reads     bool
	}{
		{"no flag", "", false},
		{"reads on", "", true},
		{"workspace", "out dir", false},
		{"both", "out dir", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _, reg := saveHarness(t, "")
			project := filepath.Join(resolvedTemp(t), "bot")
			for _, d := range []string{"out dir", "notes"} {
				if err := os.MkdirAll(filepath.Join(project, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			id := learnWriteRun(t, root, project, func(w *ledger.Writer) {
				learnWrite(t, w, filepath.Join(project, "out dir", "a.txt"))
				learnWrite(t, w, filepath.Join(project, "notes", "b.txt"))
			})
			hintsAt(t, false, "on")
			args := []string{"learn", id}
			if tc.workspace != "" {
				args = append(args, "--workspace", filepath.Join(project, tc.workspace))
			}
			if tc.reads {
				args = append(args, "--reads", "on")
			}
			code, printed, errs := run(t, args...)
			if code != identity.ExitOK {
				t.Fatalf("%q: exit %d\n%s", args, code, errs)
			}
			hint := shellWords(t, lastHint(t, errs))
			if code, _, errs := run(t, hint[1:]...); code != identity.ExitOK {
				t.Fatalf("the hint %q: exit %d\n%s", hint, code, errs)
			}
			if !tc.reads {
				// --save records refused reads, as its hint says (learnSaveHint): it writes what --reads on prints.
				code, printed, errs = run(t, append(args, "--reads", "on")...)
				if code != identity.ExitOK {
					t.Fatalf("%q --reads on: exit %d\n%s", args, code, errs)
				}
			}
			saved, err := os.ReadFile(filepath.Join(reg, "agents", "bot.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if want := strings.Replace(printed, "\nname: \"learned-tester\"\n", "\nname: \"bot\"\n", 1); string(saved) != want || want == printed {
				t.Errorf("the hint %q saved a contract other than the one printed:\nprinted:\n%s\nsaved:\n%s", hint, printed, saved)
			}
		})
	}
}

// learn --out <a bare file name> ends with tego run ./<file>: tego run takes a bare word that is an agent name for an
// agent's, and refuses it as agent-ambiguous when a file of that name is in the working directory, whether or not a
// registry holds it; ./<file> is read as the path.
func TestLearnOutHintNamesTheFileByAPath(t *testing.T) {
	root, anchor, _ := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "proj")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, root, anchor, project, recordsOnly, false)
	hintsAt(t, false, "on")
	if code, _, errs := run(t, "learn", id, "--save", "bot"); code != identity.ExitOK {
		t.Fatalf("--save bot: exit %d\n%s", code, errs)
	}
	t.Chdir(resolvedTemp(t))
	for out, want := range map[string]string{"bot": "tego run ./bot", "lone": "tego run ./lone", "p.yaml": "tego run ./p.yaml",
		"sub/q.yaml": "tego run sub/q.yaml"} {
		if err := os.MkdirAll("sub", 0o755); err != nil {
			t.Fatal(err)
		}
		code, _, errs := run(t, "learn", id, "--out", out)
		if got := lastHint(t, errs); code != identity.ExitOK || got != want {
			t.Errorf("--out %s: exit %d, hint %q, want %q", out, code, got, want)
		}
	}
	// The bare names are refused, the one a registry holds (bot) and the one none holds (lone); the hint, typed as
	// printed, names the file.
	for _, name := range []string{"bot", "lone"} {
		if _, rerr := resolveContract(name, false, hintMachine(t)); rerr == nil || rerr.Code != registry.CodeAmbiguous {
			t.Errorf("tego run %s here: %v, want agent-ambiguous", name, rerr)
		}
		ref, rerr := resolveContract("./"+name, false, hintMachine(t))
		if rerr != nil || ref.entry != nil || ref.arg != "./"+name {
			t.Errorf("tego run ./%s does not read the file: %+v, error %v", name, ref, rerr)
		}
	}
}

// shellWords splits a command line the way a shell reads shellword.Quote's words: spaces split, single quotes hold
// everything up to the next one, and a \ outside them keeps the next byte.
func shellWords(t *testing.T, line string) []string {
	t.Helper()
	var words []string
	var w strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted && c == '\'':
			quoted = false
		case quoted:
			w.WriteByte(c)
		case c == '\'':
			quoted, inWord = true, true
		case c == '\\' && i+1 < len(line):
			i++
			w.WriteByte(line[i])
			inWord = true
		case c == ' ':
			if inWord {
				words = append(words, w.String())
				w.Reset()
				inWord = false
			}
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	if quoted {
		t.Fatalf("an unclosed quote in %q", line)
	}
	if inWord {
		words = append(words, w.String())
	}
	return words
}
