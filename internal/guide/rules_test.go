// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/selfbin"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The tests below are the rules of ADR 0142 (3), "What the state never guesses", one each, named after the rule.

func step(s *guide.State, id string) guide.Step {
	for _, st := range s.Steps {
		if st.ID == id {
			return st
		}
	}
	return guide.Step{}
}

// TestASourceItCannotReadGivesNullAndOneNotKnownLine: a ledger root it cannot list, a user registry it cannot list and
// a check.json that does not decode each give the state not-known, a null fact and a line in not_known, never a
// default; and `tego setup` exits 125 for the first two (State.Unreadable).
func TestASourceItCannotReadGivesNullAndOneNotKnownLine(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a folder of mode 000")
	}
	f := guidetest.Make(t, guidetest.Finished)
	if err := os.MkdirAll(filepath.Join(f.Home, ".tego", "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guide.CheckPath(f.Home), []byte(`{"schema":"tego.check/1","checks":[{"where":"shell"`), 0o600); err != nil {
		t.Fatal(err)
	}
	agents := filepath.Join(f.Registry, "agents")
	for _, d := range []string{f.Ledger, agents} {
		if err := os.Chmod(d, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(d, 0o700) })
	}
	s := guide.Compute(t.Context(), f.Inputs(t))
	for _, id := range []string{guide.StepCheck, guide.StepFind, guide.StepRecord, guide.StepContract, guide.StepEnforce} {
		if st := step(s, id); st.State != guide.NotKnown || st.Fact != nil {
			t.Errorf("%s: state %s, fact %v; want not-known and null", id, st.State, st.Fact)
		}
	}
	nk := strings.Join(s.NotKnown, "\n")
	for _, want := range []string{"the stored machine check: ", "the record under " + f.Ledger, "the user registry " + agents} {
		if !strings.Contains(nk, want) {
			t.Errorf("not_known lacks %q:\n%s", want, nk)
		}
	}
	if !s.Unreadable() {
		t.Error("an unreadable record is not Unreadable")
	}
	b, _ := json.Marshal(step(s, guide.StepFind))
	if !bytes.Contains(b, []byte(`"fact":null`)) {
		t.Errorf("a not-known step's fact is not null in JSON: %s", b)
	}
}

// TestItNeverSaysNoAgentsCompleteOrClean: no fixture's object says "no agents", "complete" or "clean", and the
// not_known lines always say that agents Tego never recorded are not known.
func TestItNeverSaysNoAgentsCompleteOrClean(t *testing.T) {
	for _, name := range guidetest.Names {
		f := guidetest.Make(t, name)
		s := stored(t, f)
		b := strings.ToLower(string(object(t, f, s)))
		for _, word := range []string{"no agents", "complete", "clean"} {
			if strings.Contains(b, word) {
				t.Errorf("%s says %q:\n%s", name, word, b)
			}
		}
		if !strings.Contains(strings.Join(s.NotKnown, "\n"), "agents outside a scan") {
			t.Errorf("%s: not_known does not say agents Tego never recorded are not known: %q", name, s.NotKnown)
		}
	}
}

// TestItNeverTicksVerifiedForARunThatIsStillGoing: a run under a contract that has not ended is waiting, never done,
// even though its record so far checks out.
func TestItNeverTicksVerifiedForARunThatIsStillGoing(t *testing.T) {
	f := guidetest.Make(t, guidetest.ContractMade)
	start := record.RunStartPayload{Tier: "landlock", Command: []string{"sh"}, Cwd: f.Project, TegoVersion: "t", Kernel: "t",
		ContractHash: strings.Repeat("0", 64)}
	id := heldRun(t, f, start)
	s := stored(t, f)
	if st := step(s, guide.StepEnforce); st.State != guide.Waiting || st.Run != id {
		t.Errorf("enforce: %s about %s, want waiting about %s", st.State, st.Run, id)
	}
	if s.Next.Rule != guide.RuleEnforceWaiting {
		t.Errorf("next rule %s, want %s", s.Next.Rule, guide.RuleEnforceWaiting)
	}
	// A finished run and a newer one still going: done is about the finished one, and the fact names the other.
	f = guidetest.Make(t, guidetest.Finished)
	id = heldRun(t, f, start)
	st := step(stored(t, f), guide.StepEnforce)
	if st.State != guide.Done || st.Run == id || !strings.Contains(*st.Fact, "is running now and is checked when it ends") {
		t.Errorf("enforce with a newer run going: %s about %s: %v", st.State, st.Run, *st.Fact)
	}
}

// heldRun writes a run under f's ledger root whose writer the test holds open, minted after every fixture run.
func heldRun(t *testing.T, f *guidetest.Fixture, start record.RunStartPayload) string {
	t.Helper()
	rid, err := identity.NewRunID(identity.HostID([]byte("fixture")), guidetest.CheckTime.Add(time.Hour),
		bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(f.Ledger, id), record.RunRef{ID: id, Agent: "bot"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	return id
}

// TestItNeverUsesACheckFromAnotherBootOrAnotherBuild: a stored check that says ready, from another boot or another
// build, leaves the check step to do, and the fact says which was left out.
func TestItNeverUsesACheckFromAnotherBootOrAnotherBuild(t *testing.T) {
	for _, tc := range []struct {
		name, boot, build, says string
	}{
		{"another boot", "00000000-0000-4000-8000-000000000000", guidetest.Build, "before this machine last started"},
		{"another build", guidetest.BootID, "tego=v9 commit=other exe=9:9:9:9.000000000", "another tego build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			c := f.Probe
			c.BootID, c.Build = tc.boot, tc.build
			if err := guide.StoreCheck(f.Home, c); err != nil {
				t.Fatal(err)
			}
			s := guide.Compute(t.Context(), f.Inputs(t))
			st := step(s, guide.StepCheck)
			if st.State != guide.Todo || !strings.Contains(*st.Fact, tc.says) {
				t.Errorf("check: %s, %q", st.State, *st.Fact)
			}
			if s.Next.Rule != guide.RuleCheckTodo || s.Next.Command != "tego setup" {
				t.Errorf("next: %+v", s.Next)
			}
			// A boot id that cannot be read uses no stored check either.
			in := f.Inputs(t)
			in.Host.BootID = ""
			if st := step(guide.Compute(t.Context(), in), guide.StepCheck); st.State != guide.Todo {
				t.Errorf("with no boot id: %s", st.State)
			}
		})
	}
}

// TestItNeverFillsInHowThePersonStartsTheirAgent: the next step before anything is recorded writes the placeholder,
// never a command it found; and a run's recorded words are a fact, never the next command.
func TestItNeverFillsInHowThePersonStartsTheirAgent(t *testing.T) {
	s := stored(t, guidetest.Make(t, guidetest.Fresh))
	if s.Next.Command != "tego watch -- <the command you start it with>" || !s.Next.Placeholder {
		t.Errorf("next: %+v", s.Next)
	}
	for _, name := range guidetest.Names {
		s := stored(t, guidetest.Make(t, name))
		if strings.Contains(s.Next.Command, "python3") || strings.Contains(s.Next.Command, "bot.py") {
			t.Errorf("%s: the next command holds a recorded word: %q", name, s.Next.Command)
		}
	}
}

// TestItNeverCountsRefusals: slice 2 counts no refusal, so no step says "refused" and nothing needs reads_notified
// beside it; a count, when a later slice adds one, must carry it (ADR 0142 (3)).
func TestItNeverCountsRefusals(t *testing.T) {
	for _, name := range guidetest.Names {
		f := guidetest.Make(t, name)
		if b := object(t, f, stored(t, f)); bytes.Contains(bytes.ToLower(b), []byte("refused")) {
			t.Errorf("%s counts refusals without reads_notified:\n%s", name, b)
		}
	}
}

// TestItNeverNamesAServiceFromAnAddress: a recorded command that holds an address is shown as recorded; no name is
// looked up or written for it.
func TestItNeverNamesAServiceFromAnAddress(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	heldRun(t, f, record.RunStartPayload{Tier: "observe", Command: []string{"curl", "https://140.82.112.3/"}, Cwd: f.Project,
		TegoVersion: "t", Kernel: "t", ContractHash: strings.Repeat("0", 64)})
	st := step(stored(t, f), guide.StepFind)
	if *st.Fact != "you recorded curl https://140.82.112.3/" {
		t.Errorf("find: %q", *st.Fact)
	}
}

// TestItNeverTrustsItsOwnFilesForStepsFourToSix: steps record, contract and enforce come from the record and the
// registries alone. A check.json with extra lines about runs is refused whole, a file beside it is never read, and a
// run folder an ungoverned process wrote with no line in the chain anchor is a record that does not check out, never
// an enforced run.
func TestItNeverTrustsItsOwnFilesForStepsFourToSix(t *testing.T) {
	f := guidetest.Make(t, guidetest.ContractMade)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	state := filepath.Dir(guide.CheckPath(f.Home))
	if err := os.WriteFile(filepath.Join(state, "enforced.json"), []byte(`{"enforce":"done"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A forged run: a copy of the recorded run's folder renamed as a newer run under a contract, with no anchor line.
	rid, err := identity.NewRunID(identity.HostID([]byte("fixture")), guidetest.CheckTime.Add(2*time.Hour), bytes.NewReader([]byte{9, 9, 9, 9}))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(f.Ledger, f.Runs[0], ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(src, []byte(`"tier":"observe"`), []byte(`"tier":"landlock"`), 1)
	dir := filepath.Join(f.Ledger, string(rid))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	s := guide.Compute(t.Context(), f.Inputs(t))
	if st := step(s, guide.StepEnforce); st.State != guide.Blocked || st.Run != string(rid) {
		t.Errorf("a forged run under a contract: %s about %s, want blocked", st.State, st.Run)
	}
	if s.Next.Rule != guide.RuleEnforceUnverified {
		t.Errorf("next: %+v", s.Next)
	}
}

// TestNextCommandsQuoteOrRefuseRecordedText: a next step that names a recorded folder writes it as one shell word, and
// leaves it out when a character in it would not print as itself; a folder name that is no agent name is the <name>
// placeholder, never a word from the record.
func TestNextCommandsQuoteOrRefuseRecordedText(t *testing.T) {
	f := guidetest.Make(t, guidetest.ContractMade)
	odd := filepath.Join(f.Root, "a b;$(touch pwned)`id`", "bot")
	if err := os.MkdirAll(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	start := record.RunStartPayload{Tier: "observe", Command: []string{"sh"}, Cwd: odd, TegoVersion: "t", Kernel: "t",
		ContractHash: strings.Repeat("0", 64)}
	endedRun(t, f, start, 3)
	s := stored(t, f)
	want := "cd '" + odd + "' && tego run bot"
	if s.Next.Command != want {
		t.Errorf("next command %q, want %q", s.Next.Command, want)
	}

	f = guidetest.Make(t, guidetest.ContractMade)
	nl := filepath.Join(f.Root, "x\ny", "bot")
	if err := os.MkdirAll(nl, 0o700); err != nil {
		t.Fatal(err)
	}
	start.Cwd = nl
	endedRun(t, f, start, 3)
	if s := stored(t, f); s.Next.Command != "tego run bot" {
		t.Errorf("a folder with a newline: next command %q", s.Next.Command)
	}

	f = guidetest.Make(t, guidetest.Fresh)
	start.Cwd = filepath.Join(f.Root, "$(id)")
	endedRun(t, f, start, 3)
	if s := stored(t, f); s.Next.Command != "tego rules learn "+short(s)+" --save <name>" || !s.Next.Placeholder {
		t.Errorf("a folder that is no agent name: next %+v", s.Next)
	}
}

// short is the record step's run as the next step names it.
func short(s *guide.State) string {
	id := step(s, guide.StepRecord).Run
	return id[strings.LastIndexByte(id, '-')+1:]
}

// endedRun writes an ended run of start under f, minted n*10 minutes after the fixture's check.
func endedRun(t *testing.T, f *guidetest.Fixture, start record.RunStartPayload, n int) string {
	t.Helper()
	rid, err := identity.NewRunID(identity.HostID([]byte("fixture")), guidetest.CheckTime.Add(time.Duration(n)*10*time.Minute),
		bytes.NewReader([]byte{7, byte(n), 7, 7}))
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(f.Ledger, id), record.RunRef{ID: id, Agent: "bot"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return id
}

// forgeRun copies the fixture's first run's events.jsonl into a new run folder minted at CheckTime plus after, with
// the recorded working folder replaced by cwd: a run an ungoverned process of the same user wrote, with no line in the
// chain anchor. It returns the run's id.
func forgeRun(t *testing.T, f *guidetest.Fixture, cwd string, after time.Duration) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(f.Ledger, f.Runs[0], ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.ReplaceAll(src, []byte(`"cwd":"`+f.Project+`"`), []byte(`"cwd":"`+cwd+`"`))
	if bytes.Equal(forged, src) {
		t.Fatal("the recorded run's cwd is not in its record")
	}
	rid, err := identity.NewRunID(identity.HostID([]byte("forger")), guidetest.CheckTime.Add(after), bytes.NewReader([]byte{4, 4, 4, 4}))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.Ledger, string(rid))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	return string(rid)
}

// TestAForgedRunNeverChoosesTheNextCommand: a recorded run's working folder becomes the next step's cd, and a recorded
// run becomes what tego rules learn reads, only when that run's record checks out against the chain anchor. A newer observe
// run folder an ungoverned process wrote, with no anchor line, gives `tego run bot` with no cd, and on a half-done
// machine the record step is blocked and the next step is to see where the record breaks, never `tego rules learn` of it.
func TestAForgedRunNeverChoosesTheNextCommand(t *testing.T) {
	f := guidetest.Make(t, guidetest.ContractMade)
	evil := filepath.Join(f.Root, "attacker", "bot")
	if err := os.MkdirAll(evil, 0o700); err != nil {
		t.Fatal(err)
	}
	forgeRun(t, f, evil, 5*time.Hour)
	s := stored(t, f)
	if s.Next.Rule != guide.RuleContractDone || s.Next.Command != "tego run bot" {
		t.Errorf("contract made, a forged newer run: next %+v, want tego run bot and no cd", s.Next)
	}

	f = guidetest.Make(t, guidetest.HalfDone)
	id := forgeRun(t, f, evil, 5*time.Hour)
	s = stored(t, f)
	st := step(s, guide.StepRecord)
	if st.State != guide.Blocked || st.Run != id || st.Fact == nil || !strings.Contains(*st.Fact, "does not check out") {
		t.Errorf("record with a forged newest run: %+v", st)
	}
	if s.Next.Rule != guide.RuleRecordUnverified || !strings.HasPrefix(s.Next.Command, "tego events ") ||
		!strings.HasSuffix(s.Next.Command, " --verify") || strings.Contains(s.Next.Command, "learn") {
		t.Errorf("half-done, a forged newer run: next %+v", s.Next)
	}

	// Without a chain anchor no recorded run can be checked: no cd, and the record step is not known.
	f = guidetest.Make(t, guidetest.ContractMade)
	in := f.Inputs(t)
	in.Anchor = ""
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s = guide.Compute(t.Context(), in)
	if strings.Contains(s.Next.Command, "cd ") {
		t.Errorf("no anchor: next %+v", s.Next)
	}
	if st := step(s, guide.StepRecord); st.State != guide.NotKnown {
		t.Errorf("no anchor: record %s", st.State)
	}
}

// TestTheStoredCheckNeverDecidesTheContractStep: step 5 compiles an auto contract with no linked run at the machine's
// ceiling on both surfaces, whatever check.json says. A contract with net.limits compiles above tier landlock only, so
// a stored check of tier landlock that reached the compile would block it.
func TestTheStoredCheckNeverDecidesTheContractStep(t *testing.T) {
	f := guidetest.Make(t, guidetest.ContractMade)
	auto := "version: 0\nname: bot\ncommand: [\"sh\"]\nexec:\n  allow: [sh]\nnet:\n  limits: {connections: 5}\n"
	if err := os.WriteFile(filepath.Join(f.Registry, "agents", "bot.yaml"), []byte(auto), 0o600); err != nil {
		t.Fatal(err)
	}
	none := step(guide.Compute(t.Context(), f.Inputs(t)), guide.StepContract)
	for _, c := range []guide.Check{f.Probe, {Where: guide.WhereRoot, Tier: "cgroup"}} {
		c.Build, c.BootID, c.Time = f.Probe.Build, f.Probe.BootID, f.Probe.Time
		if err := guide.StoreCheck(f.Home, c); err != nil {
			t.Fatal(err)
		}
		got := step(guide.Compute(t.Context(), f.Inputs(t)), guide.StepContract)
		if got.State != none.State || *got.Fact != *none.Fact {
			t.Errorf("with a stored check of tier %s: contract %s %q; with none: %s %q", c.Tier, got.State, *got.Fact,
				none.State, *none.Fact)
		}
	}
}

// TestAnUnreadableProjectRegistryIsNotKnown: the working directory's .tego/agents that exists and cannot be listed is
// a registry not read, as the user registry's is: not-known, a null fact, a not_known line naming it, and exit 125.
func TestAnUnreadableProjectRegistryIsNotKnown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a folder of mode 000")
	}
	f := guidetest.Make(t, guidetest.HalfDone)
	pa := filepath.Join(f.Project, ".tego", "agents")
	if err := os.MkdirAll(pa, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pa, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(pa, 0o700) })
	s := stored(t, f)
	if st := step(s, guide.StepContract); st.State != guide.NotKnown || st.Fact != nil {
		t.Errorf("contract: %s %v, want not-known and null", st.State, st.Fact)
	}
	if !strings.Contains(strings.Join(s.NotKnown, "\n"), "the project registry "+pa+": ") {
		t.Errorf("not_known does not name %s: %q", pa, s.NotKnown)
	}
	if !s.Unreadable() || s.Next.Rule != guide.RuleRecordUnreadable {
		t.Errorf("unreadable %v, next %+v", s.Unreadable(), s.Next)
	}
}

// TestMoreNamesThanTheGuideCompilesSaysSo: the contract step compiles the first 20 names; with more, a not_known line
// says how many were not looked at, and a blocked step says it is the first 20.
func TestMoreNamesThanTheGuideCompilesSaysSo(t *testing.T) {
	f := guidetest.Make(t, guidetest.HalfDone)
	for i := range 21 {
		name := "a" + string(rune('a'+i))
		body := "version: 0\nname: " + name + "\ncommand: [\"sh\"]\ntier: landlock\nexec:\n  allow: [nosuchprogramzz]\n"
		if i == 20 {
			name = "zz"
			body = "version: 0\nname: zz\ncommand: [\"sh\"]\ntier: landlock\nexec:\n  allow: [sh]\n"
		}
		if err := os.WriteFile(filepath.Join(f.Registry, "agents", name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := stored(t, f)
	st := step(s, guide.StepContract)
	if st.State != guide.Blocked || !strings.Contains(st.Link, "of the first 20") {
		t.Errorf("contract: %s, link %q", st.State, st.Link)
	}
	if !strings.Contains(strings.Join(s.NotKnown, "\n"), "agents past the first 20 in name order were not compiled") {
		t.Errorf("not_known does not say names were left: %q", s.NotKnown)
	}
}

// TestRunStepsFromAnOutsideShellOpenTheirOwnScope: over SSH (place shell, no tier from here) with a stored check
// from the user manager's cgroup that is ready, the next step names the run or watch command directly: that command
// opens its own scope before any run state. If a scope cannot be opened, the guide gives the reason and no command.
// With only root's check ready and a shell that fails for another cause, the words say that
// check holds a run started with sudo, and the command is tego doctor, never tego run (F9).
func TestRunStepsFromAnOutsideShellOpenTheirOwnScope(t *testing.T) {
	for _, name := range []string{guidetest.Fresh, guidetest.ContractMade} {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			in := f.Inputs(t)
			in.As = &guide.As{User: "dana", UID: os.Getuid(), SSH: true, Where: guide.WhereShell, Scope: "systemd-run --user --scope zsh"}
			in.Fresh = &guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
				FirstFix: guidetest.Fix, Cause: guide.CauseOutsideUserManager}
			s := guide.Compute(t.Context(), in)
			if st := step(s, guide.StepCheck); st.State != guide.Done || !strings.Contains(*st.Fact, "run, watch and test can try a user scope") {
				t.Fatalf("check: %s %q", st.State, *st.Fact)
			}
			if !guide.StartsRun(s.Next.Command) || strings.Contains(s.Next.Command, "systemd-run") {
				t.Errorf("run should open its own scope: %+v", s.Next)
			}
			if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
			// No command opens one from here: the sentence alone, and the check step says why.
			in.As.Scope, in.As.ScopeMissing = "", "systemd-run is not on your PATH"
			s = guide.Compute(t.Context(), in)
			if s.Next.Command != "" || !strings.Contains(*step(s, guide.StepCheck).Fact, "systemd-run is not on your PATH") {
				t.Errorf("no scope: next %+v, check %q", s.Next, *step(s, guide.StepCheck).Fact)
			}
			// From the ready place itself the step is the run's own.
			in.As, in.Fresh = &guide.As{User: "dana", UID: os.Getuid(), Where: guide.WhereUserManager}, &f.Probe
			if s := guide.Compute(t.Context(), in); !guide.StartsRun(s.Next.Command) {
				t.Errorf("from the ready place: next %+v", s.Next)
			}
		})
	}
	t.Run("root only", func(t *testing.T) {
		f := guidetest.Make(t, guidetest.ContractMade)
		root := f.Probe
		root.Where, root.Tier = guide.WhereRoot, "bpflsm"
		if err := guide.StoreCheck(f.Home, root); err != nil {
			t.Fatal(err)
		}
		in := f.Inputs(t)
		in.As = &guide.As{User: "dana", UID: os.Getuid(), Where: guide.WhereUserManager, InUserCgroup: true}
		in.Fresh = &guide.Check{Where: guide.WhereUserManager, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
			FirstFix: "boot a kernel with Landlock"}
		s := guide.Compute(t.Context(), in)
		if s.Next.Rule != guide.RuleHereRootOnly || s.Next.Command != "tego machine check" || !strings.Contains(s.Next.Text, "sudo") {
			t.Errorf("next %+v", s.Next)
		}
		if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
			t.Errorf("the next: line is wider than 80 columns: %q", line)
		}
		if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "holds only a run started as root, with sudo") {
			t.Errorf("check fact %q", fact)
		}
	})
	// The ready check is a shell entry, not root's: the words never say root's check is ready when there is none
	// (it needs an unusual or forged check.json). The command is still tego doctor.
	t.Run("another place", func(t *testing.T) {
		f := guidetest.Make(t, guidetest.ContractMade)
		shell := f.Probe
		shell.Where = guide.WhereShell
		if err := guide.StoreCheck(f.Home, shell); err != nil {
			t.Fatal(err)
		}
		in := f.Inputs(t)
		in.As = &guide.As{User: "dana", UID: os.Getuid(), Where: guide.WhereUserManager, InUserCgroup: true}
		in.Fresh = &guide.Check{Where: guide.WhereUserManager, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
			FirstFix: "boot a kernel with Landlock"}
		s := guide.Compute(t.Context(), in)
		if s.Next.Rule != guide.RuleHereElsewhere || s.Next.Command != "tego machine check" || strings.Contains(s.Next.Text, "root") {
			t.Errorf("next %+v", s.Next)
		}
		if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
			t.Errorf("the next: line is wider than 80 columns: %q", line)
		}
	})
}

// TestAfterARebootThePlacesNotCheckedAreSaid: a check of another place from before this machine last started is not
// used, and the check step says that place is not checked since this machine started, beside the place checked now,
// on both surfaces.
func TestAfterARebootThePlacesNotCheckedAreSaid(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	old := f.Probe // the user manager's check, ready, of the last boot
	old.BootID = "00000000-0000-4000-8000-000000000000"
	if err := guide.StoreCheck(f.Home, old); err != nil {
		t.Fatal(err)
	}
	in := f.Inputs(t)
	in.As = &guide.As{User: "dana", UID: os.Getuid(), SSH: true, Where: guide.WhereShell, Scope: guide.DefaultScope}
	in.Fresh = &guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
		FirstFix: guidetest.OutsideFix, Cause: guide.CauseOutsideUserManager}
	s := guide.Compute(t.Context(), in)
	st := step(s, guide.StepCheck)
	if want := "a shell in your user manager's cgroup: " + guide.NotCheckedSinceStart; st.State != guide.Blocked ||
		!strings.Contains(*st.Fact, want) {
		t.Errorf("check: %s %q, want it to say %q", st.State, *st.Fact, want)
	}
	if s.Next.Rule != guide.RuleRecordTodo || !guide.StartsRun(s.Next.Command) {
		t.Errorf("next %+v", s.Next)
	}
	// The dashboard, with only the old boot's check stored: the spec's sentence, and tego setup.
	s = guide.Compute(t.Context(), f.Inputs(t))
	if st := step(s, guide.StepCheck); st.State != guide.Todo || !strings.HasPrefix(*st.Fact, guide.NotCheckedSinceStart) ||
		s.Next.Command != "tego setup" {
		t.Errorf("dashboard: %s %q, next %+v", st.State, *st.Fact, s.Next)
	}
}

// TestTheContractStepNamesTheContractTheRunUsed: with several contracts that compile, the contract step names the one
// the newest ended run under a contract ran when that run's record checks out, else the one named after the recorded
// run's folder, never simply the first in name order. A run whose record does not check out
// chooses nothing.
func TestTheContractStepNamesTheContractTheRunUsed(t *testing.T) {
	other := "version: 0\nname: aaa\ncommand: [\"sh\"]\ntier: landlock\nexec:\n  allow: [sh]\n"
	for _, tc := range []struct {
		fixture, want, link string
	}{
		{guidetest.Finished, "bot", "the newest ended run under a contract"},
		{guidetest.ContractMade, "bot", "named after the folder of run"},
		{guidetest.Tampered, "bot", "named after the folder of run"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			f := guidetest.Make(t, tc.fixture)
			if err := os.WriteFile(filepath.Join(f.Registry, "agents", "aaa.yaml"), []byte(other), 0o600); err != nil {
				t.Fatal(err)
			}
			st := step(stored(t, f), guide.StepContract)
			if st.State != guide.Done || *st.Fact != tc.want+" compiles now" || !strings.Contains(st.Link, tc.link) {
				t.Errorf("contract: %s %q, link %q", st.State, *st.Fact, st.Link)
			}
		})
	}
	// With no run to go by, the first in name order.
	f := guidetest.Make(t, guidetest.Fresh)
	for _, n := range []string{"aaa", "bot"} {
		body := strings.Replace(other, "aaa", n, 1)
		if err := os.WriteFile(filepath.Join(f.Registry, "agents", n+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if st := step(stored(t, f), guide.StepContract); *st.Fact != "aaa compiles now" {
		t.Errorf("no run: %q", *st.Fact)
	}
}

// TestTheLearnStepReadsTheRunWithinABudget: the learn step's --allow-host <host> rests on a read of the whole recorded
// run (SuggestHosts), which the dashboard's Overview makes on each load; past its budget the step is the plain form,
// which names no host. A run that reached addresses and read no secret names --allow-host within it.
func TestTheLearnStepReadsTheRunWithinABudget(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	rid, err := identity.NewRunID(identity.HostID([]byte("fixture")), guidetest.CheckTime, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(f.Ledger, id), record.RunRef{ID: id, Agent: "bot"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "observe", Command: []string{"python3", "bot.py"}, Cwd: f.Project,
		TegoVersion: guidetest.Version, Kernel: guidetest.Kernel, ContractHash: strings.Repeat("0", 64), LauncherPID: 1,
		LauncherStartNS: 1, StopGrace: "1s", Capture: "off"}); err != nil {
		t.Fatal(err)
	}
	e := ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: "tcp", Dst: "104.20.23.154:443"}, func(e *record.Event) {
		e.Source, e.Rule, e.Verdict, e.Authority, e.Attr = record.SourceSupervisor, "unmatched", record.VerdictObserved,
			record.AuthorityRule, record.Unattributed()
	})
	if err := w.Append(e); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	if s := guide.Compute(t.Context(), f.Inputs(t)); s.Next.Rule != guide.RuleRecordDone ||
		!strings.HasSuffix(s.Next.Command, " --allow-host <host>") {
		t.Fatalf("within the budget: next %+v", s.Next)
	}
	guide.SetSuggestBudget(t, 0)
	if s := guide.Compute(t.Context(), f.Inputs(t)); s.Next.Rule != guide.RuleRecordDone ||
		strings.Contains(s.Next.Command, "--allow-host") || s.Next.Command == "" {
		t.Errorf("past the budget: next %+v", s.Next)
	}
}

// TestNoUserManagerNamesTheCommandThatStartsOne: a check that found no user manager running for the user
// (CauseNoUserManager: a nologin service account reached through sudo -u) keeps its cause
// through the file, says why in step 2, and its next step is the command that starts that manager (Inputs.Linger, built
// by the caller from the passwd entry), never tego setup; where the caller cannot build it (the dashboard), tego
// doctor, which names it. The stored cause chooses among these fixed commands only, never a word of one.
func TestNoUserManagerNamesTheCommandThatStartsOne(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	c := guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
		FirstFix: "start a user manager for this user that runs without a login: ...", Cause: guide.CauseNoUserManager}
	b, err := guide.EncodeChecks([]guide.Check{c})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := guide.DecodeChecks(b); err != nil || len(got) != 1 || got[0] != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	ready := c
	ready.Tier, ready.FirstFix = "landlock", ""
	if b, err := guide.EncodeChecks([]guide.Check{ready}); err == nil {
		if _, err := guide.DecodeChecks(b); !errors.Is(err, guide.ErrBadCheck) {
			t.Errorf("a cause beside a tier decodes: %v", err)
		}
	}
	in := f.Inputs(t)
	in.As = &guide.As{User: "svc", UID: 1001, Where: guide.WhereShell, ScopeMissing: "XDG_RUNTIME_DIR is not set in this shell"}
	in.Fresh = &c
	in.Linger = "sudo loginctl enable-linger svc"
	s := guide.Compute(t.Context(), in)
	st := step(s, guide.StepCheck)
	if st.State != guide.Blocked || !strings.HasPrefix(*st.Fact, "no user manager runs for you, so tego starts no run from ") {
		t.Errorf("check: %s %q", st.State, *st.Fact)
	}
	if s.Next.Rule != guide.RuleCheckNoManager || s.Next.Command != in.Linger || !s.Next.Built() || !s.Next.NeedsRoot {
		t.Errorf("next %+v", s.Next)
	}
	in.Linger = ""
	if s := guide.Compute(t.Context(), in); s.Next.Rule != guide.RuleCheckNoManager || s.Next.Command != "tego machine check" {
		t.Errorf("no linger command: next %+v", s.Next)
	}
}

// TestTheAutomaticScopeStepKeepsTheReadersAccount: after linger, tego setup started as a service account from an administrator's
// shell (sudo -u svc) named XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash with "open a shell in your
// user manager's cgroup": the administrator typed it in their own shell, which opened their own scope on Ubuntu 24.04
// and AlmaLinux 9.8 (where tego setup then said ready, for the wrong user) and failed on Fedora 44 (acceptance 3,
// 2026-11-11). With As.ScopeAs the next command carries the account and this binary's absolute path. Run-starting
// commands open their own scope as that account; receipt and learn keep the same account too. Step 2 says whose
// command it is. The reader who is the user keeps the bare command.
func TestTheAutomaticScopeStepKeepsTheReadersAccount(t *testing.T) {
	guidetest.SelfAs(t, guidetest.SelfWord, "")
	const asSvc = "sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash"
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, state)
			c := guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
				FirstFix: guidetest.OutsideFix, Cause: guide.CauseOutsideUserManager}
			in := f.Inputs(t)
			in.As = &guide.As{User: "svc", UID: 1002, Where: guide.WhereShell, Scope: asSvc, ScopeAs: "svc"}
			in.Fresh = &c
			s := guide.Compute(t.Context(), in)
			if !strings.HasPrefix(s.Next.Command, "sudo -u svc "+guidetest.SelfWord+" ") || strings.Contains(s.Next.Command, "systemd-run") {
				t.Errorf("next %+v", s.Next)
			}
			if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
			if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "it runs as svc (sudo -u), not as you") {
				t.Errorf("step 2 does not say whose shell: %q", fact)
			}
			// Read in a shell sudo su -s opened as svc, "your own shell" would be that shell, where sudo -u svc fails:
			// the words say which shell.
			if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "in your own login shell, not in one sudo or su opened (if you are in one, type exit first)") {
				t.Errorf("step 2 does not say to leave a shell sudo or su opened: %q", fact)
			}
			in.As.Scope, in.As.ScopeAs = "XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash", ""
			s = guide.Compute(t.Context(), in)
			if !strings.HasPrefix(s.Next.Command, "tego ") || strings.Contains(s.Next.Command, "systemd-run") || strings.Contains(s.Next.Text, "own shell") || strings.Contains(*step(s, guide.StepCheck).Fact, "svc's") {
				t.Errorf("the user's own shell: next %+v, fact %q", s.Next, *step(s, guide.StepCheck).Fact)
			}
		})
	}
}

// TestANameSystemdRefusesNamesNoCommand: for an account whose name systemd refuses (Inputs.ManagerRefused: digits
// only, the user 4242 on Ubuntu 24.04), linger starts no user manager, and tego setup named
// sudo loginctl enable-linger 1004 again after it ran. Step 2 now says why, and the next step names no command:
// neither linger nor tego doctor nor tego setup.
func TestANameSystemdRefusesNamesNoCommand(t *testing.T) {
	const why = "systemd starts no user manager for this account: the name of uid 1004, 4242, is digits only, which systemd reads as a uid (systemd.io/USER_NAMES)"
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, state)
			c := guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
				FirstFix: "start a user manager for this user that runs without a login: ...", Cause: guide.CauseNoUserManager}
			in := f.Inputs(t)
			in.As = &guide.As{User: "4242", UID: 1004, Where: guide.WhereShell, ScopeMissing: "XDG_RUNTIME_DIR is not set in this shell"}
			in.Fresh = &c
			in.Linger, in.ManagerRefused = "sudo loginctl enable-linger 1004", why
			s := guide.Compute(t.Context(), in)
			if s.Next.Rule != guide.RuleCheckNoManagerName || s.Next.Command != "" || s.Next.NeedsRoot {
				t.Errorf("next %+v", s.Next)
			}
			if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
			if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, why) || strings.Contains(fact, "enable-linger") {
				t.Errorf("step 2: %q", fact)
			}
		})
	}
}

// TestAnotherReadersCommandCarriesSudo: tego setup started as a service account from an administrator's shell
// (sudo -u svc tego setup), after the account was set up, ended with "next: tego session show <id>". The administrator reads
// the line in their own shell, where that command reads their record and fails (acceptance 4, 2026-11-11). With
// As.ScopeAs the command is written with sudo -u and the account in front, whatever the step: the receipt, the learn
// of a recorded run and the watch of the first one; and a command already written to run as another user, such as the
// shell that opens the account's scope, is left alone. The reader who is the user keeps the bare commands.
func TestAnotherReadersCommandCarriesSudo(t *testing.T) {
	guidetest.SelfAs(t, guidetest.SelfWord, "")
	cases := []struct{ state, bare string }{
		{guidetest.Finished, "tego session show "},
		{guidetest.HalfDone, "tego rules learn "},
		{guidetest.Fresh, "tego watch -- <the command you start it with>"},
	}
	for _, c := range cases {
		t.Run(c.state, func(t *testing.T) {
			f := guidetest.Make(t, c.state)
			in := f.Inputs(t)
			in.As = &guide.As{User: "svc", UID: 1002, Where: guide.WhereShell, ScopeAs: "svc",
				ScopeMissing: "the user manager of uid 1002 keeps no socket under /run/user/1002"}
			probe := f.Probe
			in.Fresh = &probe
			s := guide.Compute(t.Context(), in)
			if !strings.HasPrefix(s.Next.Command, "sudo -u svc "+guidetest.SelfWord+" "+strings.TrimPrefix(c.bare, "tego ")) {
				t.Errorf("next %+v: the command is not the bare one with sudo -u svc in front", s.Next)
			}
			// Step 2 says what the next command does: it runs as the account. It claimed the receipt "opens a shell as
			// svc in svc's user manager's cgroup, not in yours" (acceptance 4).
			if fact := *step(s, guide.StepCheck).Fact; strings.Contains(fact, "opens a shell") {
				t.Errorf("step 2 says the next command opens a shell: %q", fact)
			}
			in.As.ScopeAs = ""
			s = guide.Compute(t.Context(), in)
			if !strings.HasPrefix(s.Next.Command, c.bare) {
				t.Errorf("the reader who is the user: next %+v", s.Next)
			}
		})
	}
	const self = guidetest.SelfWord
	for command, want := range map[string]string{
		"tego session show abc":             "sudo -u svc " + self + " session show abc",
		"cd /home/svc/bot && tego run bot":  "sudo -u svc sh -c 'cd /home/svc/bot && exec " + self + " run bot'",
		"sudo loginctl enable-linger svc":   "sudo loginctl enable-linger svc",
		"sudo -u svc systemd-run --scope b": "sudo -u svc systemd-run --scope b",
		"cd /x && sudo tego test":           "cd /x && sudo tego test",
		"":                                  "",
		"tegoish receipt":                   "tegoish receipt",
	} {
		got, why := guide.ForReader("svc", command)
		if got != want || why != "" {
			t.Errorf("ForReader(svc, %q) = %q, %q, want %q", command, got, why, want)
		}
		if got, _ := guide.ForReader("", command); got != command {
			t.Errorf("ForReader(\"\", %q) = %q", command, got)
		}
	}
}

// TestASudoLineNamesTheRunningBinary: a sudo line is typed in a shell whose sudo resets PATH to its secure_path, which
// leaves out the installer's ~/.local/bin (Ubuntu, Fedora) and /usr/local/bin too (AlmaLinux 9.8), so `sudo -u svc
// tego session show` answered "command not found". The line names the running
// binary's absolute path, quoted, read once from the executable and never from PATH. A binary whose path cannot be read,
// or that the account cannot execute (a copy in another user's closed home), gives no command and says why.
func TestASudoLineNamesTheRunningBinary(t *testing.T) {
	real := guide.SelfPath
	for _, tc := range []struct{ self, want string }{
		{"/home/svc/.local/bin/tego", "sudo -u svc /home/svc/.local/bin/tego session show abc"},
		{"/usr/local/bin/tego", "sudo -u svc /usr/local/bin/tego session show abc"},
		{"'/home/a b/it'\\''s/tego'", "sudo -u svc '/home/a b/it'\\''s/tego' session show abc"},
	} {
		guidetest.SelfAs(t, tc.self, "")
		if got, why := guide.ForReader("svc", "tego session show abc"); got != tc.want || why != "" {
			t.Errorf("self %s: %q, %q, want %q", tc.self, got, why, tc.want)
		}
	}
	for _, why := range []string{guide.ReaderNoPathText, guide.ReaderUnsafePathText, guide.ReaderNoExecText, guide.ReaderUntrustedText} {
		guidetest.SelfAs(t, "", why)
		// The ownership refusal includes the installation remedy, which is longer than a short next line.
		if line := "next: " + why; why != guide.ReaderUntrustedText && len([]rune(line)) > 80 {
			t.Errorf("the next: line is wider than 80 columns: %q", line)
		}
		if got, w := guide.ForReader("svc", "tego session show abc"); got != "" || w != why {
			t.Errorf("no usable binary: %q, %q, want no command and %q", got, w, why)
		}
		// The bare reader is told nothing of it: a command sudo does not run needs no binary.
		if got, w := guide.ForReader("svc", "sudo loginctl enable-linger svc"); got == "" || w != "" {
			t.Errorf("a sudo command needs no tego: %q, %q", got, w)
		}
		if got, w := guide.ForReader("", "tego session show abc"); got != "tego session show abc" || w != "" {
			t.Errorf("the user's own shell: %q, %q", got, w)
		}
		// Through the guide: the step names no command and says why.
		f := guidetest.Make(t, guidetest.Finished)
		in := f.Inputs(t)
		in.As = &guide.As{User: "svc", UID: 1002, Where: guide.WhereShell, ScopeAs: "svc", ScopeMissing: "no socket"}
		probe := f.Probe
		in.Fresh = &probe
		if s := guide.Compute(t.Context(), in); s.Next.Command != "" || s.Next.Text != why {
			t.Errorf("next %+v, want no command and %q", s.Next, why)
		}
	}
	// The real binary follows the same checked path; a shared build directory may require refusing it.
	word, why := real()
	wantWord, wantWhy := selfbin.Named(os.Executable)
	if word != wantWord || why != wantWhy {
		t.Errorf("SelfPath() = %q, %q: want %q, %q", word, why, wantWord, wantWhy)
	}
	if why != "" {
		namedGroupRepair := strings.HasPrefix(why, "cannot establish membership of group ") && strings.Contains(why, "run chmod g-w ") && strings.HasSuffix(why, "then run this step again.")
		if word != "" || why != selfbin.Untrusted && !namedGroupRepair {
			t.Errorf("SelfPath() = %q, %q: want no command and an installation-trust refusal", word, why)
		}
	} else if !strings.HasPrefix(word, "/") && !strings.HasPrefix(word, "'/") {
		t.Errorf("SelfPath() = %q, %q: want the test binary's absolute path", word, why)
	}
}

// TestTheSudoLineRunsTheCommandInTheFolderAsTheAccount: "cd <folder> && tego run bot" typed by an administrator runs the cd
// as the administrator, which fails when the account's home is closed to them (mode 0700) before sudo starts. The line does the cd and the command together as the account:
// sudo -u svc sh -c 'cd <folder> && exec <tego> run <name>', quoted as one word. sudo -D is not used: it wants sudo 1.9.3 and
// a sudoers option. The test runs the line for real in a shell with a stand-in sudo and a folder and a binary whose names
// hold a space and a quote: the command runs in the folder, with its arguments, as one process.
func TestTheSudoLineRunsTheCommandInTheFolderAsTheAccount(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "my agent's dir")
	bin := filepath.Join(root, "bin dir", "tego")
	for _, d := range []string{dir, filepath.Dir(bin)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'cwd=%s\\n' \"$PWD\"\nprintf 'arg=%s\\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shq := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	guidetest.SelfAs(t, shq(bin), "")
	line, why := guide.ForReader("svc", "cd "+shq(dir)+" && tego run 'a b'")
	if why != "" || !strings.HasPrefix(line, "sudo -u svc sh -c ") {
		t.Fatalf("line %q, %q", line, why)
	}
	if strings.HasPrefix(line, "cd ") {
		t.Errorf("the cd runs in the reader's shell: %q", line)
	}
	// A stand-in sudo: drop "-u <account>" and run the rest, as sudo does.
	out, err := exec.Command("sh", "-c", "sudo() { shift 2; \"$@\"; }\n"+line).CombinedOutput()
	if err != nil {
		t.Fatalf("running %q: %v\n%s", line, err, out)
	}
	want := "cwd=" + dir + "\narg=run\narg=a b\n"
	if string(out) != want {
		t.Errorf("the line ran as\n%s\nwant\n%s", out, want)
	}
}

// TestAnotherReadersStepNamesNoCommandWhereNoneWorks: the user manager runs but keeps no socket under the user's logind
// folder, so no command opens a shell in it from another user's shell (sudo -u svc tego setup; Opening.As is set, the
// command is ""). The fix: line names no command there either, and the step says whose manager it is, not "your user
// manager's", which an administrator reads as their own (integration pass 5, 2026-11-11).
func TestAnotherReadersStepNamesNoCommandWhereNoneWorks(t *testing.T) {
	const missing = "the user manager of uid 1002 keeps no socket under /run/user/1002, so systemd-run --user cannot reach it from another user's shell"
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, state)
			c := guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
				FirstFix: guidetest.OutsideFix, Cause: guide.CauseOutsideUserManager}
			in := f.Inputs(t)
			in.As = &guide.As{User: "svc", UID: 1002, Where: guide.WhereShell, ScopeAs: "svc", ScopeMissing: missing}
			in.Fresh = &c
			s := guide.Compute(t.Context(), in)
			if s.Next.Command != "" || s.Next.Text != guide.ScopeAsMissingText {
				t.Errorf("next %+v", s.Next)
			}
			if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
			if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "no command opens one from here: "+missing) {
				t.Errorf("step 2 does not say why: %q", fact)
			}
			// The reader who is the user keeps the words as they were.
			in.As.ScopeAs = ""
			s = guide.Compute(t.Context(), in)
			if s.Next.Command != "" || s.Next.Text != "systemd-run cannot open a shell in your user manager's cgroup here." {
				t.Errorf("the user's own shell: next %+v", s.Next)
			}
		})
	}
}

// TestTheStepDoesNotClaimTheReceiptOpensAShell: after the account is ready (its check was stored from its scope), tego
// setup started from the administrator's shell (sudo -u svc) says in step 2 that the next command opens a shell as
// svc "in svc's user manager's cgroup, not in yours", and the next command is the receipt, which opens none (acceptance
// 4, 2026-11-11: "the step text says the next command opens a shell as svc, but it does not"). The sentence is kept
// for the step that does open one; for any other next command the fact says it runs as the account.
func TestTheStepDoesNotClaimTheReceiptOpensAShell(t *testing.T) {
	guidetest.SelfAs(t, guidetest.SelfWord, "")
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	here := guide.Check{Where: guide.WhereShell, Build: f.Probe.Build, BootID: f.Probe.BootID, Time: f.Probe.Time,
		FirstFix: guidetest.OutsideFix, Cause: guide.CauseOutsideUserManager}
	in := f.Inputs(t)
	in.As = &guide.As{User: "svc", UID: 1002, Where: guide.WhereShell, ScopeAs: "svc",
		Scope: "sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash"}
	in.Fresh = &here
	s := guide.Compute(t.Context(), in)
	fact := *step(s, guide.StepCheck).Fact
	// The finished walk's next step is the receipt; it runs as the account and opens no shell.
	if s.Next.Rule != guide.RuleEnforceDone || !strings.HasPrefix(s.Next.Command, "sudo -u svc "+guidetest.SelfWord+" session show ") {
		t.Fatalf("next %+v", s.Next)
	}
	if !strings.Contains(fact, "ready: ") || !strings.Contains(fact, "tego ran as svc") || strings.Contains(fact, "opens a shell") ||
		!strings.Contains(fact, "it runs as svc (sudo -u), not as you") {
		t.Errorf("step 2: %q", fact)
	}
	// A machine with a contract made names the run directly, with cd inside the account's shell form. Its check step
	// says whose command it is, without claiming to open an interactive shell.
	h := guidetest.Make(t, guidetest.ContractMade)
	if err := guide.StoreCheck(h.Home, h.Probe); err != nil {
		t.Fatal(err)
	}
	in = h.Inputs(t)
	in.As = &guide.As{User: "svc", UID: 1002, Where: guide.WhereShell, ScopeAs: "svc",
		Scope: "sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash"}
	here.Build, here.BootID, here.Time = h.Probe.Build, h.Probe.BootID, h.Probe.Time
	in.Fresh = &here
	s = guide.Compute(t.Context(), in)
	if s.Next.Rule != guide.RuleContractDone || !strings.HasPrefix(s.Next.Command, "sudo -u svc sh -c ") ||
		!strings.Contains(s.Next.Command, "exec "+guidetest.SelfWord+" run ") {
		t.Fatalf("next %+v", s.Next)
	}
	if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "it runs as svc (sudo -u), not as you") {
		t.Errorf("step 2 lost the sentence naming the account: %q", fact)
	}
}

func TestGroupedMachineTestStartsARun(t *testing.T) {
	for command, want := range map[string]bool{
		"tego machine test":                true,
		"tego machine test --observe":      true,
		"cd /project && tego machine test": true,
		"tego machine check":               false,
		"tego machine":                     false,
		"sudo tego machine test":           false,
	} {
		if got := guide.StartsRun(command); got != want {
			t.Errorf("StartsRun(%q) = %v, want %v", command, got, want)
		}
	}
}
