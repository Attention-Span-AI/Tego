// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
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
		if !strings.Contains(strings.Join(s.NotKnown, "\n"), "agents Tego never recorded") {
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
	if s := stored(t, f); s.Next.Command != "tego learn "+short(s)+" --save <name>" || !s.Next.Placeholder {
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
// run becomes what tego learn reads, only when that run's record checks out against the chain anchor. A newer observe
// run folder an ungoverned process wrote, with no anchor line, gives `tego run bot` with no cd, and on a half-done
// machine the record step is blocked and the next step is to see where the record breaks, never `tego learn` of it.
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

// TestFromAShellThatCannotEnforceTheNextStepOpensOne: over SSH (place shell, no tier from here) with a stored check
// from the user manager's cgroup that is ready, the step that would start a run (tego run, tego watch) is never named
// from here, where it exits 125: the next step opens a shell in the user manager's cgroup and runs tego setup there
// (acceptance B, 2026-11-11). With only root's check ready and a shell that fails for another cause, the words say that
// check holds a run started with sudo, and the command is tego doctor, never tego run (F9).
func TestFromAShellThatCannotEnforceTheNextStepOpensOne(t *testing.T) {
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
			if st := step(s, guide.StepCheck); st.State != guide.Done || !strings.Contains(*st.Fact, "not even tego watch") {
				t.Fatalf("check: %s %q", st.State, *st.Fact)
			}
			if s.Next.Rule != guide.RuleHereOutside || s.Next.Command != "systemd-run --user --scope zsh" ||
				guide.StartsRun(s.Next.Command) || !strings.Contains(s.Next.Text, "tego setup") {
				t.Errorf("next %+v", s.Next)
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
		if s.Next.Rule != guide.RuleHereRootOnly || s.Next.Command != "tego doctor" || !strings.Contains(s.Next.Text, "sudo") {
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
	// (the review's S3; it needs an unusual or forged check.json). The command is still tego doctor.
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
		if s.Next.Rule != guide.RuleHereElsewhere || s.Next.Command != "tego doctor" || strings.Contains(s.Next.Text, "root") {
			t.Errorf("next %+v", s.Next)
		}
		if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
			t.Errorf("the next: line is wider than 80 columns: %q", line)
		}
	})
}

// TestAfterARebootThePlacesNotCheckedAreSaid: a check of another place from before this machine last started is not
// used, and the check step says that place is not checked since this machine started, beside the place checked now,
// on both surfaces (acceptance B, 2026-11-11).
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
	if s.Next.Rule != guide.RuleCheckOutside || s.Next.Command != guide.DefaultScope {
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
// run's folder, never simply the first in name order (acceptance B, 2026-11-11). A run whose record does not check out
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
// which names no host (the review's S4). A run that reached addresses and read no secret names --allow-host within it.
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
// (CauseNoUserManager, acceptance 2B, 2026-11-11: a nologin service account reached through sudo -u) keeps its cause
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
	if s := guide.Compute(t.Context(), in); s.Next.Rule != guide.RuleCheckNoManager || s.Next.Command != "tego doctor" {
		t.Errorf("no linger command: next %+v", s.Next)
	}
}

// TestTheScopeLineSaysWhoseShellItOpens: after linger, tego setup started as a service account from an administrator's
// shell (sudo -u svc) named XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash with "open a shell in your
// user manager's cgroup": the administrator typed it in their own shell, which opened their own scope on Ubuntu 24.04
// and AlmaLinux 9.8 (where tego setup then said ready, for the wrong user) and failed on Fedora 44 (acceptance 3,
// 2026-11-11). With As.ScopeAs the step's words say to type it in your own shell and that it opens a shell as this
// user, and step 2 names that user; the command is the invoker's (OpenScope's sudo -u form). The reader who is the
// user keeps the words as they were.
func TestTheScopeLineSaysWhoseShellItOpens(t *testing.T) {
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
			if s.Next.Command != asSvc || s.Next.Text != guide.ScopeAsText || !strings.Contains(s.Next.Text, "from your own shell") {
				t.Errorf("next %+v", s.Next)
			}
			if line := "next: " + s.Next.Text; len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
			if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "it opens a shell as svc in svc's user manager's cgroup, not in yours") {
				t.Errorf("step 2 does not say whose shell: %q", fact)
			}
			// Read in a shell sudo su -s opened as svc, "your own shell" was that shell, where sudo -u svc fails (the
			// review's S4): the words say which shell.
			if fact := *step(s, guide.StepCheck).Fact; !strings.Contains(fact, "in your own login shell, not in one sudo or su opened") {
				t.Errorf("step 2 does not say to leave a shell sudo or su opened: %q", fact)
			}
			in.As.Scope, in.As.ScopeAs = "XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash", ""
			s = guide.Compute(t.Context(), in)
			if s.Next.Command != in.As.Scope || strings.Contains(s.Next.Text, "own shell") || strings.Contains(*step(s, guide.StepCheck).Fact, "svc's") {
				t.Errorf("the user's own shell: next %+v, fact %q", s.Next, *step(s, guide.StepCheck).Fact)
			}
		})
	}
}

// TestANameSystemdRefusesNamesNoCommand: for an account whose name systemd refuses (Inputs.ManagerRefused: digits
// only, the user 4242 on Ubuntu 24.04, acceptance 3, 2026-11-11), linger starts no user manager, and tego setup named
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
