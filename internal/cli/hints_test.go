// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// hintsAt makes this test's stderr a terminal or not (a bytes.Buffer never is) and sets TEGO_HINTS ("" leaves it
// unset in effect: anything but on and off is the default).
func hintsAt(t *testing.T, terminal bool, env string) {
	t.Helper()
	prev := stderrTerminal
	stderrTerminal = func(io.Writer) bool { return terminal }
	t.Cleanup(func() { stderrTerminal = prev })
	t.Setenv(hintsEnv, env)
}

// The guidance lines are on when stderr is a terminal; TEGO_HINTS=on turns them on where it is not and TEGO_HINTS=off
// off everywhere; any other value is the default; and never inside a governed run, whatever the variable says.
func TestHintsFollowTheTerminalAndTEGO_HINTS(t *testing.T) {
	for _, tc := range []struct {
		terminal bool
		env      string
		inRun    bool
		want     bool
	}{
		{true, "", false, true},
		{false, "", false, false},
		{false, "on", false, true},
		{true, "off", false, false},
		{true, "yes", false, true},
		{false, "yes", false, false},
		{true, "on", true, false},
	} {
		hintsAt(t, tc.terminal, tc.env)
		prev := selfInRun
		selfInRun = func() (bool, error) { return tc.inRun, nil }
		var b bytes.Buffer
		writeHint(&b, "say it:", "tego it")
		writeGuide(&b, "  stop: x\n")
		selfInRun = prev
		want := ""
		if tc.want {
			want = "\nnext: say it:\n  tego it\n  stop: x\n"
		}
		if b.String() != want {
			t.Errorf("terminal %v, TEGO_HINTS=%q, in a run %v: wrote %q, want %q", tc.terminal, tc.env, tc.inRun, b.String(), want)
		}
	}
	if got := hintBlock("no command here.", ""); got != "\nnext: no command here.\n" {
		t.Errorf("a block with no command: %q", got)
	}
}

// readsRun writes an ended run under root, anchored at anchor: started in cwd at tier landlock with reads_notified rn
// (nil writes a run_start without the field, as a record from before it), and with one refused read of a credential
// file when refused.
func readsRun(t *testing.T, root, anchor, cwd string, rn *record.ReadsNotified, refused bool) string {
	t.Helper()
	rid, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "bot"}, ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"python3", "bot.py"}, Cwd: cwd, Tier: "landlock", Capture: "off",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true}, ReadsNotified: rn}); err != nil {
		t.Fatal(err)
	}
	if refused {
		e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: record.VerdictRefused,
			Rule: "fs.deny_read[~/.aws/credentials]", Reason: record.ReasonReadDenied, Attr: record.Unattributed(), Authority: record.AuthorityRule}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/home/u/.aws/credentials"}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return id
}

// T2: the reads line follows run_start.reads_notified, never the record level. It is printed
// exactly for reason-off, no-supervisor and a record without the field, and never for a run whose every read open
// reached the supervisor, a root tier's (its kernel record holds refused reads) or a run that refused nothing by design.
func TestReadsLineFollowsTheFieldNeverTheLevel(t *testing.T) {
	for _, tc := range []struct {
		rn   *record.ReadsNotified
		want string
	}{
		{&record.ReadsNotified{Notified: false, Why: record.ReadsNotifiedWhyReasonOff}, readsLineReasonOff},
		{&record.ReadsNotified{Notified: false, Why: record.ReadsNotifiedWhyNoSupervisor}, readsLineNoSupervisor},
		{nil, readsLineUnknown},
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}, ""},
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyReason}, ""},
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyAskRead}, ""},
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyGate}, ""},
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyHeld}, ""},
		{&record.ReadsNotified{Notified: false, Why: record.ReadsNotifiedWhyKernel}, ""},
		{&record.ReadsNotified{Notified: false, Why: record.ReadsNotifiedWhyRecordsOnly}, ""},
	} {
		s := &endSummary{run: "r-x", rc: &receipt.Receipt{ReadsNotified: tc.rn}}
		if got := s.readsLine(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.rn, got, tc.want)
		}
	}
	if got := (&endSummary{run: "r-x"}).readsLine(); got != "" {
		t.Errorf("a summary with no receipt said %q", got)
	}
	want := `  reads: not recorded at this level; a read the contract refused left no line and is not counted in "refused N".` + "\n"
	if readsLineReasonOff != want {
		t.Errorf("the reason-off line is %q, want the spec's %q", readsLineReasonOff, want)
	}
}

// A run's stderr ends: the summary's two lines byte for byte, the reads line when it applies (a fact, printed with
// TEGO_HINTS=off too), then the next step. --no-summary prints none of them.
func TestRunEndsWithTheReadsLineAndTheNextStep(t *testing.T) {
	root, _ := summaryHarness(t)
	project := t.TempDir()
	var rn *record.ReadsNotified
	refused := false
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		return tegoruntime.Result{RunID: readsRun(t, root, d.AnchorPath, project, rn, refused), Reason: record.RunEndExit}, nil
	}
	contract := filepath.Join("testdata", "minimal.yaml")
	reasonOff := &record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff}
	for _, tc := range []struct {
		name    string
		env     string
		args    []string
		rn      *record.ReadsNotified
		refused bool
		reads   string
		next    func(short string) string
	}{
		{"reads not recorded", "on", nil, reasonOff, false, readsLineReasonOff, func(string) string {
			return "\nnext: to see a read the contract refuses, run it again recording every read:\n  tego run " + contract +
				" --record full -- true\n"
		}},
		{"a refusal", "on", nil, &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}, true, "", func(s string) string {
			return "\nnext: see what it refused, under which rule:\n  tego receipt " + s + "\n"
		}},
		{"a refusal, reads not recorded", "on", nil, reasonOff, true, readsLineReasonOff, func(s string) string {
			return "\nnext: see what it refused, under which rule:\n  tego receipt " + s + "\n"
		}},
		{"nothing refused, reads recorded", "on", nil, &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyReason}, false, "",
			func(s string) string {
				return "\nnext: check its record against the chain anchor:\n  tego receipt " + s + " --verify\n"
			}},
		{"an old record", "on", nil, nil, false, readsLineUnknown, func(string) string {
			return "\nnext: to see a read the contract refuses, run it again recording every read:\n  tego run " + contract +
				" --record full -- true\n"
		}},
		{"TEGO_HINTS=off", "off", nil, reasonOff, false, readsLineReasonOff, func(string) string { return "" }},
		{"a record-only run", "on", []string{"--observe"}, &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}, false, "",
			func(string) string {
				return "\nnext: to enforce the contract, run it again without --observe:\n  tego run " + contract + " -- true\n"
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hintsAt(t, false, tc.env)
			rn, refused = tc.rn, tc.refused
			var stderr bytes.Buffer
			argv := append(append([]string{"tego", "run", contract, "--offline"}, tc.args...), "--", "true")
			if code := mainWith(t.Context(), argv, io.Discard, &stderr, []Command{cmdRun()}); code != identity.ExitOK {
				t.Fatalf("exit %d:\n%s", code, stderr.String())
			}
			out := stderr.String()
			i := strings.Index(out, "tego run: r-")
			if i < 0 {
				t.Fatalf("no summary:\n%s", out)
			}
			lines := strings.SplitAfter(out[i:], "\n")
			id := strings.Fields(lines[0])[2]
			if !strings.HasPrefix(lines[0], "tego run: "+id+" ended (exited with code 0) · tier landlock · refused ") ||
				lines[1] != "  more: tego receipt "+id+"\n" {
				t.Fatalf("the summary's two lines changed:\n%s", out)
			}
			want := lines[0] + lines[1] + tc.reads + tc.next(id[strings.LastIndexByte(id, '-')+1:])
			if got := out[i:]; got != want {
				t.Errorf("stderr after the summary:\n%s\nwant:\n%s", got, want)
			}
		})
	}
	hintsAt(t, false, "on")
	rn = reasonOff
	var stderr bytes.Buffer
	if code := mainWith(t.Context(), []string{"tego", "run", "--no-summary", contract, "--offline", "--", "true"}, io.Discard, &stderr,
		[]Command{cmdRun()}); code != identity.ExitOK {
		t.Fatalf("--no-summary: exit %d", code)
	}
	if out := stderr.String(); strings.Contains(out, "reads:") || strings.Contains(out, "next:") {
		t.Errorf("--no-summary printed a reads line or a hint:\n%s", out)
	}
}

// tego receipt --json gains one field, reads_notified, copied from run_start, and none for a record written before
// the field (T2: jq -c .reads_notified gives null).
func TestReceiptJSONCarriesReadsNotified(t *testing.T) {
	root, anchor := summaryHarness(t)
	for _, tc := range []struct {
		rn   *record.ReadsNotified
		want string
	}{
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyReason}, `{"notified":true,"why":"reason"}`},
		{&record.ReadsNotified{Notified: false, Why: record.ReadsNotifiedWhyReasonOff}, `{"notified":false,"why":"reason-off"}`},
		{&record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}, `{"notified":true,"why":"record-full"}`},
		{nil, ""},
	} {
		id := readsRun(t, root, anchor, "/w", tc.rn, false)
		code, out, errs := run(t, "receipt", id, "--json")
		if code != identity.ExitOK {
			t.Fatalf("exit %d: %s", code, errs)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &obj); err != nil {
			t.Fatal(err)
		}
		got, ok := obj["reads_notified"]
		var compact bytes.Buffer
		if ok {
			if err := json.Compact(&compact, got); err != nil {
				t.Fatal(err)
			}
		}
		if tc.want == "" && ok || tc.want != "" && compact.String() != tc.want {
			t.Errorf("%+v: reads_notified %s (present %v), want %q", tc.rn, got, ok, tc.want)
		}
		if strings.Contains(errs, "next:") {
			t.Errorf("--json printed a hint: %q", errs)
		}
	}
}

// After a record-only watch: the notice gains the stop: line (how a recording of an agent that runs until stopped
// ends, and that the record is kept), the footer is unchanged, and the next step is tego learn of this run, saved under
// the run folder's name. A bounded watch, --record off and --no-summary print no learn step; --no-summary and
// TEGO_HINTS=off neither the stop: line nor the step.
func TestWatchSaysHowToStopAndWhatIsNext(t *testing.T) {
	sandboxedLaunch(t)
	dir := trustedDir(t)
	contract := filepath.Join(dir, "agent.yaml")
	writeTestFile(t, contract, "version: 0\nname: caged\ncommand: [\"true\"]\nnet: {}\n")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	learn := "\nnext: make a contract from what it did, and read it before you use it:\n  tego learn r-test-run --save " +
		nameFromFolder(wd) + "\n"
	for _, tc := range []struct {
		env   string
		argv  []string
		stop  bool
		tail  string
		learn bool
	}{
		{"on", []string{"watch", "--offline", "--", "/usr/bin/python3", "-c", "pass"}, true, learn, true},
		{"on", []string{"watch", "--offline", "--boundary", contract, "--", "true"}, true, "", false},
		{"on", []string{"watch", "--offline", "--record", "off", "--", "python3"}, true, "", false},
		{"on", []string{"watch", "--offline", "--no-summary", "--", "python3"}, false, "", false},
		{"off", []string{"watch", "--offline", "--", "python3"}, false, "", false},
	} {
		hintsAt(t, false, tc.env)
		var errs bytes.Buffer
		if code := mainWith(t.Context(), append([]string{"tego"}, tc.argv...), io.Discard, &errs, []Command{cmdWatch()}); code != identity.ExitOK {
			t.Fatalf("%q: exit %d:\n%s", tc.argv, code, errs.String())
		}
		got := errs.String()
		if strings.Contains(got, watchStopLine) != tc.stop {
			t.Errorf("%q TEGO_HINTS=%s: the stop: line printed %v, want %v:\n%s", tc.argv, tc.env, !tc.stop, tc.stop, got)
		}
		if tc.learn && !strings.HasSuffix(got, tc.tail) || !tc.learn && strings.Contains(got, "next:") {
			t.Errorf("%q TEGO_HINTS=%s: want the last lines %q:\n%s", tc.argv, tc.env, tc.tail, got)
		}
		if !strings.Contains(got, "tego watch: recorded as run r-test-run") {
			t.Errorf("%q: the footer is gone:\n%s", tc.argv, got)
		}
	}
	if nameFromFolder("/home/dana/bot") != "bot" || nameFromFolder("/home/dana/My Bot") != "<name>" || nameFromFolder("") != "<name>" {
		t.Error("the name a hint proposes is the folder's when it is an agent name, else <name>")
	}
}

// saveHarness is a ledger root and an anchor in a private directory, and the user registry reg, with the machine config
// naming them, for a user in their own shell (ownShell). reg "" is a registry that does not exist yet, in a private
// directory of its own: one inside the directory that holds the anchor is refused (R6a).
func saveHarness(t *testing.T, reg string) (root, anchor, registryDir string) {
	t.Helper()
	ownShell(t)
	root, anchor = summaryHarness(t)
	if reg == "" {
		reg = filepath.Join(resolvedTemp(t), "reg")
		if err := os.Chmod(filepath.Dir(reg), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(filepath.Dir(root), "tego.yaml")
	writeTestFile(t, cfg, "ledger_root: "+root+"\nregistry: "+reg+"\n")
	if err := os.Chmod(cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, anchor, reg
}

// tego learn <run> --save <name> writes the proposal as the agent <name> of the user registry, where tego run <name>
// finds it: the folder made 0700, the file 0600, its name: the name, compiled before it is written. It never writes
// over a name a registry holds (T3: exit 1, the first file unchanged), takes no invalid name or --out beside it
// (exit 2), and refuses inside a governed run (T4: exit 125 [governed], nothing written). --reads on adds reason:
// {reads: on}. Each form ends with its next step.
func TestLearnSaveWritesTheRegistryEntry(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	id := readsRun(t, root, anchor, project, &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}, false)
	short := id[strings.LastIndexByte(id, '-')+1:]
	hintsAt(t, false, "on")

	code, _, errs := run(t, "learn", short)
	if code != identity.ExitOK || !strings.HasSuffix(errs, "\nnext: "+learnSaveHint+"\n  tego learn "+short+" --save bot\n") {
		t.Fatalf("learn with no flag: exit %d, stderr %q", code, errs)
	}
	// --save records refused reads unless --reads off (TestLearnSaveRecordsRefusedReads): what it writes is the
	// proposal --reads on prints.
	code, out, errs := run(t, "learn", short, "--reads", "on")
	if code != identity.ExitOK {
		t.Fatalf("learn --reads on: exit %d, stderr %q", code, errs)
	}
	printed := out

	code, out, errs = run(t, "learn", short, "--save", "bot")
	path := filepath.Join(reg, "agents", "bot.yaml")
	if code != identity.ExitOK || out != "" {
		t.Fatalf("--save: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	for _, want := range []string{
		"tego learn: saved " + path + " (mode 0600), made only from what run " + id + " was recorded doing.\n",
		"\nnext: run your agent under it:\n  cd " + project + " && tego run bot\n",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("--save: stderr lacks %q:\n%s", want, errs)
		}
	}
	if !strings.HasSuffix(errs, "  cd "+project+" && tego run bot\n") {
		t.Errorf("--save: the hint is not last:\n%s", errs)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(printed, "name: \"learned-bot\"\n", "name: \"bot\"\n", 1); string(data) != want || !strings.Contains(want, "name: \"bot\"\n") {
		t.Errorf("the saved file is not the printed proposal named bot:\n%s", data)
	}
	for p, mode := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: mode %v (%v), want %v", p, fi.Mode().Perm(), err, mode)
		}
	}
	if code, _, errs := run(t, "compile", "bot"); code != identity.ExitOK {
		t.Errorf("tego compile bot does not find and compile the saved entry: exit %d\n%s", code, errs)
	}

	// T3: a second save of the same name writes nothing and leaves the first file as it was.
	code, _, errs = run(t, "learn", short, "--save", "bot", "--reads", "on")
	if again, _ := os.ReadFile(path); code != identity.ExitFinding || !bytes.Equal(again, data) || strings.Contains(errs, "next:") {
		t.Errorf("a second --save bot: exit %d, the file changed %v, stderr %q", code, !bytes.Equal(again, data), errs)
	}

	code, _, errs = run(t, "learn", short, "--save", "bot2", "--reads", "on")
	saved, _ := os.ReadFile(filepath.Join(reg, "agents", "bot2.yaml"))
	if code != identity.ExitOK || !strings.Contains(string(saved), "\nreason:\n") || !strings.Contains(string(saved), "\n  reads: on\n") {
		t.Errorf("--reads on: exit %d, stderr %q, file:\n%s", code, errs, saved)
	}

	for _, args := range [][]string{{"--save", "Bad Name"}, {"--save", "x", "--out", "f.yaml"}, {"--reads", "yes"}, {"--bogus"}} {
		code, _, errs := run(t, append([]string{"learn", short}, args...)...)
		if code != identity.ExitUsage || strings.Contains(errs, "next:") {
			t.Errorf("%v: exit %d, stderr %q; want a usage error with no hint", args, code, errs)
		}
	}

	prev := selfInRun
	selfInRun = func() (bool, error) { return true, nil }
	code, _, errs = run(t, "learn", short, "--save", "x")
	selfInRun = prev
	if _, err := os.Stat(filepath.Join(reg, "agents", "x.yaml")); code != identity.ExitLauncher || !strings.Contains(errs, "[governed]") || err == nil {
		t.Errorf("--save inside a run: exit %d, stderr %q, file there: %v", code, errs, err == nil)
	}

	out2 := filepath.Join(resolvedTemp(t), "p.yaml")
	code, _, errs = run(t, "learn", short, "--out", out2)
	if code != identity.ExitOK || !strings.HasSuffix(errs, "\nnext: run your agent under it:\n  tego run "+out2+"\n") {
		t.Errorf("--out: exit %d, stderr %q", code, errs)
	}
}

// --save refuses a file that would lie inside one of the proposal's own fs.write entries, as tego refuses to run such
// a contract, and writes nothing.
func TestLearnSaveRefusesItsOwnWriteEntry(t *testing.T) {
	project := resolvedTemp(t)
	if err := os.Chmod(project, 0o700); err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(project, "reg")
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	root, _, _ := saveHarness(t, reg)
	id := learnWriteRun(t, root, project, func(w *ledger.Writer) { learnWrite(t, w, filepath.Join(reg, "notes.txt")) })
	code, _, errs := run(t, "learn", id, "--save", "bot")
	if _, err := os.Stat(filepath.Join(reg, "agents", "bot.yaml")); code != identity.ExitFinding || err == nil ||
		!strings.Contains(errs, "inside its own fs.write entry") {
		t.Errorf("exit %d, file there %v, stderr %q", code, err == nil, errs)
	}
}

// After tego test passed: record your own agent. Doctor's verdict: Ready leads to tego test (as root for a root
// report), not ready to doctor's own fix and the check again by tego setup, never tego doctor itself (acceptance B,
// 2026-11-11); a root report's sentence says to run the check again. Neither with TEGO_HINTS=off.
func TestDoctorAndTestHints(t *testing.T) {
	hintsAt(t, false, "on")
	var b bytes.Buffer
	writeDoctorVerdict(&b, &doctor.Report{Tier: backend.TierLandlock})
	if want := "\nReady: this shell can enforce at tier 1 (landlock), no root needed.\n\nnext: see Tego refuse four harmless actions on decoy files:\n  tego test\n"; b.String() != want {
		t.Errorf("ready: %q, want %q", b.String(), want)
	}
	b.Reset()
	writeDoctorVerdict(&b, &doctor.Report{Tier: backend.TierCgroup, Root: true})
	if want := "\nReady: a run started as root here can enforce at tier 2 (cgroup).\n\nnext: see Tego refuse four harmless actions on decoy files:\n  sudo \"$(command -v tego)\" test\n"; b.String() != want {
		t.Errorf("root: %q, want %q", b.String(), want)
	}
	b.Reset()
	writeDoctorVerdict(&b, &doctor.Report{Fix: "boot a kernel >= 5.19"})
	if want := "\nNot ready: this shell can only record.\n\nnext: do what the fix: line above says, then check again:\n  tego setup\n"; b.String() != want {
		t.Errorf("not ready: %q, want %q", b.String(), want)
	}
	b.Reset()
	writeDoctorVerdict(&b, &doctor.Report{Root: true, Fix: "boot a kernel >= 5.19"})
	if want := "\nNot ready: a run started as root here can only record.\n\nnext: do what the fix: line above says, then run this check again.\n"; b.String() != want {
		t.Errorf("root, not ready: %q, want %q", b.String(), want)
	}
	hintsAt(t, false, "off")
	b.Reset()
	writeDoctorVerdict(&b, &doctor.Report{Tier: backend.TierLandlock})
	if b.Len() != 0 {
		t.Errorf("TEGO_HINTS=off: %q", b.String())
	}
	if n := len("next: " + testNext); n > 80 {
		t.Errorf("tego test's hint is %d columns", n)
	}
}

// Every hint sentence fits in 80 columns with its "next: " (T1), and its command, when it has a placeholder, puts what
// Tego cannot know in angle brackets.
func TestHintSentencesFitEightyColumns(t *testing.T) {
	texts := []string{testNext, "make a contract from what it did, and read it before you use it:", "save it as a contract:",
		learnSaveHint, learnNameHint, watchNameHint,
		"run your agent under it:", "make a contract from what it did:", "see Tego refuse four harmless actions on decoy files:",
		"do what the fix: line above says, then check again:", "do what the failing check above says, then check again:",
		"do what the fix: line above says, then run this check again.", "open a shell in your user manager's cgroup, then run this again there:",
		"open a shell in your user manager's cgroup, then run tego setup there:", "make it without the names learn refused:",
		"make it without --allow-host; learn allows the addresses it kept:",
		`the "missing for" lines above say what this machine lacks.`}
	s := &endSummary{run: "r-x", rc: &receipt.Receipt{}}
	for _, o := range []runOptions{{observe: true}, {}} {
		text, _ := s.runHint(o)
		texts = append(texts, text)
	}
	s.rc.ReadsNotified = &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}
	text, _ := s.runHint(runOptions{})
	texts = append(texts, text)
	s.rc.Refusals.Total = 1
	text, _ = s.runHint(runOptions{})
	texts = append(texts, text)
	for _, f := range []func() (string, string){
		func() (string, string) { return agentsNext([]int32{1}, nil) },
		func() (string, string) { return agentsNext(nil, []string{"r-x"}) },
		func() (string, string) { return agentsNext(nil, nil) },
	} {
		text, _ := f()
		texts = append(texts, text)
	}
	for _, text := range texts {
		if n := len([]rune("next: " + text)); n > 80 || strings.Contains(text, "\n") {
			t.Errorf("%d columns: %q", n, text)
		}
	}
	if got := runAgain(runOptions{contract: "my bot.yaml", given: []string{"python3", "a b.py"}}, "--record full"); got !=
		"tego run 'my bot.yaml' --record full -- python3 'a b.py'" {
		t.Errorf("runAgain: %q", got)
	}
}

// An adoption's record is a run like any other: after its end line, tego adopt names tego learn of it.
func TestAdoptEndsWithTheLearnStep(t *testing.T) {
	sandboxAdopt(t, terminalProcs(), true)
	hintsAt(t, false, "on")
	code, _, errs := runAdoptCmd(t, t.Context(), "--pid", "500")
	const want = "  tego status r-0a1b2c3d-0123456789abc-xyz500    tego events r-0a1b2c3d-0123456789abc-xyz500    tego drift r-0a1b2c3d-0123456789abc-xyz500\n" +
		"\nnext: make a contract from what it did:\n  tego learn r-0a1b2c3d-0123456789abc-xyz500 --save <name>\n"
	if code != identity.ExitOK || !strings.HasSuffix(errs, want) {
		t.Errorf("exit %d, want the end line then the learn step:\n%s", code, errs)
	}
}

// lastHint is the command of the "next:" block stderr ends with: its last line, without the two spaces.
func lastHint(t *testing.T, stderr string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[len(lines)-2], "next: ") || !strings.HasPrefix(lines[len(lines)-1], "  ") {
		t.Fatalf("stderr does not end with a next: block:\n%s", stderr)
	}
	return strings.TrimPrefix(lines[len(lines)-1], "  ")
}

// T1, as far as this package can run it without an agent or a guest: from a recorded run to
// the agent's own contract enforced, typing only the commands the next: lines print. The recording is a watch's
// record of python3 bot.py in ~/bot; the runs' records stand in for the agent's (refused 0 with reads not recorded,
// then refused 1 with every read recorded). The real run, Ctrl-C and doctor's Ready line need an agent and a guest,
// which no test here has. A guest walk of these next: lines (2026-11-11, Ubuntu 24.04.5 and AlmaLinux 9.8, over SSH,
// a build of that morning) reached an enforced run and doctor's Ready line only from a shell in the user manager's
// cgroup, a shell no next: line then named; Ctrl-C was not part of that walk.
func TestFollowingTheNextLinesFromARecordToAnEnforcedRun(t *testing.T) {
	root, anchor, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "bot")
	if err := os.MkdirAll(filepath.Join(project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	watched := readsRun(t, root, anchor, project, &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}, false)
	hintsAt(t, true, "")

	// The watch's hint, as watchHint writes it for this run in ~/bot.
	_, learnCmd := watchHint(tegoruntime.Result{RunID: watched}, &endSummary{root: root, machine: hintMachine(t)}, "", project, false)
	short := watched[strings.LastIndexByte(watched, '-')+1:]
	if learnCmd != "tego learn "+short+" --save bot" {
		t.Fatalf("watch's next command %q", learnCmd)
	}
	code, _, errs := run(t, strings.Fields(learnCmd)[1:]...)
	if code != identity.ExitOK {
		t.Fatalf("%s: exit %d\n%s", learnCmd, code, errs)
	}
	if fi, err := os.Stat(filepath.Join(reg, "agents", "bot.yaml")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("bot.yaml: %v %v", fi, err)
	}
	runCmd := lastHint(t, errs)
	if runCmd != "cd "+project+" && tego run bot" {
		t.Fatalf("learn's next command %q", runCmd)
	}

	var rn *record.ReadsNotified
	refused := false
	startRun = func(_ context.Context, _ *agent.RuleTable, _ []string, d tegoruntime.Deps) (tegoruntime.Result, error) {
		return tegoruntime.Result{RunID: readsRun(t, root, d.AnchorPath, project, rn, refused), Reason: record.RunEndExit}, nil
	}
	t.Chdir(project)
	runIt := func(argv []string) string {
		t.Helper()
		var stderr bytes.Buffer
		if code := mainWith(t.Context(), append([]string{"tego"}, argv...), io.Discard, &stderr, []Command{cmdRun()}); code != identity.ExitOK {
			t.Fatalf("%v: exit %d\n%s", argv, code, stderr.String())
		}
		return stderr.String()
	}
	// The default record level at tier 1: the read the contract refused left no line.
	rn = &record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff}
	out := runIt(strings.Fields(strings.SplitN(runCmd, " && ", 2)[1])[1:])
	if !strings.Contains(out, " · refused 0 · ") || !strings.Contains(out, readsLineReasonOff) {
		t.Fatalf("the first enforced run:\n%s", out)
	}
	again := lastHint(t, out)
	if again != "tego run bot --record full" {
		t.Fatalf("run's next command %q", again)
	}
	// Every read recorded: the refused read is counted, and no reads line follows.
	rn, refused = &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyFull}, true
	out = runIt(strings.Fields(again)[1:])
	if !strings.Contains(out, " · refused 1 (") || !strings.Contains(out, "chain verified") || strings.Contains(out, "  reads: ") {
		t.Fatalf("the run with every read recorded:\n%s", out)
	}
	if got := lastHint(t, out); !strings.HasPrefix(got, "tego receipt ") || len(strings.Fields(got)[2]) != 6 {
		t.Errorf("the last next command %q, want tego receipt <6 characters>", got)
	}
}
