// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fakeUserUnits is a user service manager of the test's own: the units it knows, and every call it was given.
type fakeUserUnits struct {
	present   map[string]bool
	calls     []string
	failStop  map[string]bool
	unavail   bool
	liveCount int
}

func (f *fakeUserUnits) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.unavail {
		return "", errors.New("Failed to connect to bus")
	}
	switch args[0] {
	case "list-units", "list-unit-files":
		var names []string
		for n := range f.present {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			b.WriteString(n + " loaded active running a unit\n")
		}
		return b.String(), nil
	case "stop", "disable", "reset-failed":
		// systemd refuses to start or stop a bare template: it names no instance
		if strings.Contains(args[1], "@.") && args[0] == "stop" {
			return "Failed to stop " + args[1] + ": Unit name " + args[1] + " is missing the instance name.", errors.New("exit status 1")
		}
		if args[0] != "stop" {
			return "", nil
		}
		if f.failStop[args[1]] {
			return "Failed to stop " + args[1] + ": access denied", errors.New("exit status 1")
		}
		if !f.present[args[1]] {
			return "Unit " + args[1] + " not loaded.", errors.New("exit status 5")
		}
		delete(f.present, args[1])
	}
	return "", nil
}

func (f *fakeUserUnits) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

type uninstallRig struct {
	t     *testing.T
	home  string
	units *fakeUserUnits
	env   *uninstallEnv
	out   *bytes.Buffer
}

const (
	rigControl = "tego-control bytes"
	rigRunOne  = "r-0a0a0a0a-0000000000001-aaaaaa"
	rigRunTwo  = "r-0a0a0a0a-0000000000002-bbbbbb"
)

// newRig is a home folder with everything `tego start` and the installer leave behind, and an environment that works only
// in it.
func newRig(t *testing.T) *uninstallRig {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	r := &uninstallRig{t: t, home: home, units: &fakeUserUnits{present: map[string]bool{
		"tego-dashboard.service": true, retentionTimerUnit + ".timer": true, retentionTimerUnit + ".service": true,
	}, failStop: map[string]bool{}}, out: &bytes.Buffer{}}
	sum := sha256.Sum256([]byte(rigControl))
	for rel, data := range map[string]string{
		".local/bin/tego":                     "tego bytes",
		".local/bin/tego-control":             rigControl,
		".tego/dashboard.log":                 "http://127.0.0.1:8484/?t=aa\n",
		".tego/setup-install.log":             "log\n",
		".tego/chain.log":                     "chain\n",
		".tego/tego.log":                      "own log\n",
		".tego/runs/" + rigRunOne + "/ledger": "run one\n",
		".tego/runs/" + rigRunTwo + "/ledger": "run two\n",
		// the dot entries a real runs folder holds beside its runs, and a stray folder: none is a run
		".tego/runs/.gc-stamp":            "stamp\n",
		".tego/runs/.held-label-note":     "note\n",
		".tego/runs/.live/x":              "live\n",
		".tego/runs/notarun/ledger":       "x\n",
		".config/tego/agent.env":          "TOKEN='secret'\n",
		".config/tego/last-project":       "/work\n",
		".config/tego/agents/claude.yaml": "contract\n",
		".bashrc":                         "# my bashrc\nalias ll='ls -l'\n\n" + bashrcLine + "\nexport EDITOR=vi\n",
	} {
		write(t, filepath.Join(home, rel), data)
	}
	r.env = &uninstallEnv{
		home: home, self: filepath.Join(home, ".local/bin/tego"), euid: os.Geteuid(),
		out: r.out, errOut: &bytes.Buffer{}, interactive: true,
		systemctl: r.units.run,
		pin:       func() (string, bool) { return hex.EncodeToString(sum[:]), true },
		liveRuns:  func(context.Context) (int, error) { return r.units.liveCount, nil },
	}
	if r.env.euid == 0 {
		t.Skip("the removal refuses to run as root")
	}
	return r
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *uninstallRig) path(rel string) string { return filepath.Join(r.home, rel) }

func (r *uninstallRig) exists(rel string) bool {
	_, err := os.Lstat(r.path(rel))
	return err == nil
}

func (r *uninstallRig) read(rel string) string {
	b, err := os.ReadFile(r.path(rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

// run answers the questions with input and returns the exit code.
func (r *uninstallRig) run(input string) int {
	r.out.Reset()
	r.env.in = strings.NewReader(input)
	return runUninstall(context.Background(), r.env)
}

func TestUninstallListsWhatItWillRemoveAndAsksOnce(t *testing.T) {
	r := newRig(t)
	r.units.present["tego-agent@retriever.service"] = true
	code := r.run("n\n")
	out := r.out.String()
	if code != identity.ExitOK || !strings.Contains(out, "Nothing was changed.") {
		t.Fatalf("declined: exit %d\n%s", code, out)
	}
	for _, want := range []string{
		"Tego will remove", "stop the dashboard (tego-dashboard)", "tego-gc.timer", "tego-gc.service",
		"~/.local/bin/tego (the program", "~/.local/bin/tego-control", "~/.bashrc", "agent sign-ins", "dashboard.log",
		"Services you set up", "tego-agent@retriever",
		"Your records and contracts (kept unless you say so)", "2 runs", "1 agent contract",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the list lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "[Y/n]")+strings.Count(out, "[y/N]") != 1 {
		t.Errorf("a no to the first question asks nothing more; got:\n%s", out)
	}
	for _, rel := range []string{".local/bin/tego", ".local/bin/tego-control", ".tego/dashboard.log", ".config/tego/agent.env"} {
		if !r.exists(rel) {
			t.Errorf("declined, yet %s is gone", rel)
		}
	}
	if r.units.called("stop") {
		t.Errorf("declined, yet a unit was stopped: %v", r.units.calls)
	}
}

func TestUninstallYesKeepsRecordsContractsAndAgentServices(t *testing.T) {
	r := newRig(t)
	r.units.present["tego-agent@retriever.service"] = true
	r.env.yes, r.env.interactive = true, false
	before := r.read(".bashrc")
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	out := r.out.String()
	for _, rel := range []string{".local/bin/tego", ".local/bin/tego-control", ".tego/dashboard.log", ".tego/setup-install.log", ".config/tego/agent.env", ".config/tego/last-project"} {
		if r.exists(rel) {
			t.Errorf("%s is still there", rel)
		}
	}
	for _, rel := range []string{".tego/chain.log", ".tego/tego.log", ".tego/runs/" + rigRunOne + "/ledger", ".tego/runs/" + rigRunTwo + "/ledger", ".config/tego/agents/claude.yaml"} {
		if !r.exists(rel) {
			t.Errorf("--yes deleted %s: the records and contracts stay without their own answer", rel)
		}
	}
	for _, n := range []string{"tego-dashboard.service", "tego-gc.timer", "tego-gc.service"} {
		if r.units.present[n] {
			t.Errorf("%s was not stopped", n)
		}
	}
	if !r.units.present["tego-agent@retriever.service"] || r.units.called("stop tego-agent@") || r.units.called("disable") {
		t.Errorf("--yes touched the agent service: %v", r.units.calls)
	}
	for _, want := range []string{"Left running: your agent services", "Kept: your records", "Tego is removed. Your records and contracts stay"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// Only the one line went; everything else in the file is byte for byte as it was, and a backup holds the original.
	after := r.read(".bashrc")
	if strings.Contains(after, "added by tego start") || after != strings.Replace(before, bashrcLine+"\n", "", 1) {
		t.Errorf(".bashrc after = %q", after)
	}
	if r.read(".bashrc.tego-backup") != before {
		t.Errorf("the backup is not the original")
	}
}

func TestUninstallQuestionsDefaultToNoForServicesAndRecords(t *testing.T) {
	r := newRig(t)
	r.units.present["tego-agent@retriever.service"] = true
	// yes to the removal; Enter on the services question; Enter on the records question.
	if code := r.run("y\n\n\n"); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if !r.exists(".tego/runs/"+rigRunOne+"/ledger") || !r.exists(".config/tego/agents/claude.yaml") {
		t.Errorf("Enter deleted the records")
	}
	if !r.units.present["tego-agent@retriever.service"] {
		t.Errorf("Enter stopped the agent service")
	}
	if got := strings.Count(r.out.String(), "[Y/n]") + strings.Count(r.out.String(), "[y/N]"); got != 3 {
		t.Errorf("expected three separate questions, saw %d:\n%s", got, r.out)
	}
}

func TestUninstallRecordsAndServicesOnlyOnTheirOwnYes(t *testing.T) {
	r := newRig(t)
	r.units.present["tego-agent@retriever.service"] = true
	if code := r.run("y\ny\ny\n"); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if r.exists(".tego") || r.exists(".config/tego") {
		t.Errorf("the records answer was yes, yet a folder is left")
	}
	if r.units.present["tego-agent@retriever.service"] || !r.units.called("disable tego-agent@retriever.service") || !r.units.called("daemon-reload") {
		t.Errorf("the service was not stopped and disabled: %v", r.units.calls)
	}
	if !strings.Contains(r.out.String(), "with your records and contracts") {
		t.Errorf("output: %s", r.out)
	}
}

func TestUninstallScriptFlagsAnswerTheOtherTwoQuestions(t *testing.T) {
	r := newRig(t)
	r.units.present["tego-agent@retriever.service"] = true
	r.env.yes, r.env.interactive, r.env.stopAgents, r.env.deleteRecords = true, false, true, true
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if r.exists(".tego") || r.units.present["tego-agent@retriever.service"] {
		t.Errorf("the flags did not remove the records and the service")
	}
}

func TestUninstallRefusesToDeleteRecordsWhileASessionRuns(t *testing.T) {
	r := newRig(t)
	r.units.liveCount = 1
	r.env.deleteRecords, r.env.yes, r.env.interactive = true, true, false
	code := r.run("")
	if code != identity.ExitError || !r.exists(".tego/runs/"+rigRunOne+"/ledger") || !strings.Contains(r.out.String(), "1 session still running") {
		t.Fatalf("exit %d, records kept=%v:\n%s", code, r.exists(".tego/runs/"+rigRunOne+"/ledger"), r.out)
	}
	if r.exists(".local/bin/tego") {
		t.Errorf("the rest of the removal should still have happened")
	}
	// and when it cannot tell, it also keeps them
	r2 := newRig(t)
	r2.env.liveRuns = func(context.Context) (int, error) { return 0, errors.New("ledger unreadable") }
	r2.env.deleteRecords, r2.env.yes, r2.env.interactive = true, true, false
	if code := r2.run(""); code != identity.ExitError || !r2.exists(".tego/chain.log") {
		t.Fatalf("unreadable ledger: exit %d, chain kept=%v", code, r2.exists(".tego/chain.log"))
	}
}

func TestUninstallTwiceIsSafe(t *testing.T) {
	r := newRig(t)
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("first: exit %d\n%s", code, r.out)
	}
	bashrc := r.read(".bashrc")
	calls := len(r.units.calls)
	code := r.run("")
	out := r.out.String()
	if code != identity.ExitOK || !strings.Contains(out, "already gone") {
		t.Fatalf("second: exit %d\n%s", code, out)
	}
	if r.read(".bashrc") != bashrc || r.exists(".bashrc.tego-backup-1") {
		t.Errorf("the second run changed .bashrc again")
	}
	if !r.exists(".tego/chain.log") {
		t.Errorf("the second run touched the records")
	}
	for _, c := range r.units.calls[calls:] {
		if strings.HasPrefix(c, "stop") {
			t.Errorf("the second run stopped %q", c)
		}
	}
	// With nothing of Tego's left and no records either, it says so and exits clean.
	r3 := newRig(t)
	r3.env.yes, r3.env.interactive, r3.env.deleteRecords = true, false, true
	if code := r3.run(""); code != identity.ExitOK {
		t.Fatal(code)
	}
	if code := r3.run(""); code != identity.ExitOK || !strings.Contains(r3.out.String(), "Nothing of Tego is installed") {
		t.Fatalf("empty: exit %d\n%s", code, r3.out)
	}
}

func TestUninstallWorksWithoutTheUnitsOrTheServiceManager(t *testing.T) {
	r := newRig(t)
	r.units.present = map[string]bool{} // the dashboard is already gone
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK || r.exists(".local/bin/tego") {
		t.Fatalf("no units: exit %d\n%s", code, r.out)
	}
	r2 := newRig(t)
	r2.units.unavail = true
	r2.env.yes, r2.env.interactive = true, false
	if code := r2.run(""); code != identity.ExitOK || r2.exists(".local/bin/tego") {
		t.Fatalf("no user manager: exit %d\n%s", code, r2.out)
	}
	if !strings.Contains(r2.out.String(), "units were not checked") {
		t.Errorf("it did not say the units were not checked:\n%s", r2.out)
	}
	r3 := newRig(t)
	r3.env.systemctl = nil // no systemctl at all
	r3.env.yes, r3.env.interactive = true, false
	if code := r3.run(""); code != identity.ExitOK || r3.exists(".local/bin/tego") {
		t.Fatalf("no systemctl: exit %d\n%s", code, r3.out)
	}
}

func TestUninstallReportsAUnitItCouldNotStopAndGoesOn(t *testing.T) {
	r := newRig(t)
	r.units.failStop["tego-dashboard.service"] = true
	r.env.yes, r.env.interactive = true, false
	code := r.run("")
	if code != identity.ExitError || !strings.Contains(r.out.String(), "access denied") || !strings.Contains(r.out.String(), "did not finish") {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if r.exists(".local/bin/tego") || r.units.present["tego-gc.timer"] {
		t.Errorf("one failure should not stop the other steps")
	}
}

// The documented install of the example unit (docs/user/run-as-a-service.md) copies the template into the user's
// folder; the service manager lists it by its template name beside the running instances. Uninstall stops each
// instance by its full name and never stops the template, which systemd refuses.
func TestUninstallStopsEveryInstanceOfATemplateItRemovesNotTheTemplate(t *testing.T) {
	r := newRig(t)
	unit := ".config/systemd/user/tego-agent@.service"
	write(t, r.path(unit), "# SPDX\n[Unit]\nDescription=Tego agent %i\n")
	r.units.present["tego-agent@.service"] = true
	r.units.present["tego-agent@alpha.service"] = true
	r.units.present["tego-agent@beta.service"] = true
	r.env.yes, r.env.interactive, r.env.stopAgents, r.env.deleteRecords = true, false, true, true
	code := r.run("")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, though every step could be done:\n%s", code, r.out)
	}
	for _, c := range r.units.calls {
		if strings.HasPrefix(c, "stop") && strings.Contains(c, "@.") {
			t.Errorf("a template was stopped: %q", c)
		}
	}
	for _, inst := range []string{"stop tego-agent@alpha.service", "stop tego-agent@beta.service"} {
		if !r.units.called(inst) {
			t.Errorf("%q was never called: %v", inst, r.units.calls)
		}
	}
	if r.units.present["tego-agent@alpha.service"] || r.units.present["tego-agent@beta.service"] || r.exists(unit) {
		t.Errorf("an instance runs on, or the copied template stays")
	}
	if strings.Contains(r.out.String(), "stop and remove tego-agent@.service") {
		t.Errorf("the listing offers to stop a template:\n%s", r.out)
	}
}

// A unit that really fails to stop still makes the command say so: the other steps are done, and the exit code
// and the last line say that one step was not.
func TestUninstallOneFailedStopIsReportedTheRestIsDoneAndTheExitSaysSo(t *testing.T) {
	r := newRig(t)
	r.units.present["tego-agent@alpha.service"] = true
	r.units.present["tego-agent@beta.service"] = true
	r.units.failStop["tego-agent@alpha.service"] = true
	r.env.yes, r.env.interactive, r.env.stopAgents, r.env.deleteRecords = true, false, true, true
	code := r.run("")
	out := r.out.String()
	if code != identity.ExitError || !strings.Contains(out, "1 step(s) did not finish") || !strings.Contains(out, "the other steps were done") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if r.units.present["tego-agent@beta.service"] || r.exists(".tego") || r.exists(".local/bin/tego") {
		t.Errorf("the failure of one stop kept the rest from being done")
	}
}

func TestUninstallRemovesOnlyTheExactPathLine(t *testing.T) {
	r := newRig(t)
	// no other program in ~/.local/bin, so the installer's line can go
	other := `export PATH="$HOME/.local/bin:$PATH"`
	text := "first\n" + other + "\n" + installerPathLine + "\n" + installerPathLine + " extra\n  " + installerPathLine + "\nlast\n"
	write(t, r.path(".zshrc"), text)
	write(t, r.path(".profile"), "no tego here\n")
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	want := "first\n" + other + "\n" + installerPathLine + " extra\n  " + installerPathLine + "\nlast\n"
	if got := r.read(".zshrc"); got != want {
		t.Errorf(".zshrc = %q\nwant    %q", got, want)
	}
	if r.read(".zshrc.tego-backup") != text {
		t.Errorf("the backup is not the original .zshrc")
	}
	if r.exists(".profile.tego-backup") || r.read(".profile") != "no tego here\n" {
		t.Errorf("a file without the line was touched")
	}
}

func TestUninstallKeepsThePathLineWhileOtherProgramsNeedIt(t *testing.T) {
	r := newRig(t)
	write(t, r.path(".zshrc"), installerPathLine+"\n")
	write(t, r.path(".local/bin/othertool"), "x")
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if r.read(".zshrc") != installerPathLine+"\n" || !strings.Contains(r.out.String(), "still holds 1 other file(s)") {
		t.Errorf(".zshrc = %q\n%s", r.read(".zshrc"), r.out)
	}
}

func TestUninstallFishFileOfOurOwnGoesWhenOnlyTheLineWasInIt(t *testing.T) {
	r := newRig(t)
	write(t, r.path(".config/fish/conf.d/tego.fish"), "\n"+installerFishLine+"\n")
	write(t, r.path(".config/fish/conf.d/mine.fish"), installerFishLine+"\n")
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if r.exists(".config/fish/conf.d/tego.fish") || !r.exists(".config/fish/conf.d/tego.fish.tego-backup") {
		t.Errorf("tego.fish should be removed, with a backup beside it")
	}
	if !r.exists(".config/fish/conf.d/mine.fish") {
		t.Errorf("a fish file that is not Tego's was removed")
	}
}

func TestUninstallEditsThroughALinkWithoutReplacingIt(t *testing.T) {
	r := newRig(t)
	dots := r.path("dotfiles")
	write(t, filepath.Join(dots, "bashrc"), "keep\n"+bashrcLine+"\n")
	if err := os.Remove(r.path(".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dots, "bashrc"), r.path(".bashrc")); err != nil {
		t.Fatal(err)
	}
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if fi, err := os.Lstat(r.path(".bashrc")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf(".bashrc is no longer a link: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dots, "bashrc")); string(got) != "keep\n" {
		t.Errorf("target = %q", got)
	}
}

func TestUninstallProgramsAreRemovedOnlyWhenTheyAreTegos(t *testing.T) {
	// a tego-control that is not the pinned one stays, and is said to
	r := newRig(t)
	write(t, r.path(".local/bin/tego-control"), "someone else's program")
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if !r.exists(".local/bin/tego-control") || !strings.Contains(r.out.String(), "not the tego-control this tego was built with") {
		t.Errorf("a tego-control that is not pinned was removed or not explained:\n%s", r.out)
	}
	if r.exists(".local/bin/tego") {
		t.Errorf("the running tego should go")
	}
	// no pin at all (a build without one): tego-control cannot be vouched for
	r2 := newRig(t)
	r2.env.pin = func() (string, bool) { return "", false }
	r2.env.yes, r2.env.interactive = true, false
	r2.run("")
	if !r2.exists(".local/bin/tego-control") {
		t.Errorf("an unpinned build removed a tego-control")
	}
	// a program not named tego is not Tego's installed command
	r3 := newRig(t)
	r3.env.self = r3.path(".local/bin/tego-control")
	r3.env.yes, r3.env.interactive = true, false
	r3.run("")
	if !r3.exists(".local/bin/tego") || !r3.exists(".local/bin/tego-control") {
		t.Errorf("a program whose name is not tego was removed")
	}
	// a build in a source checkout is left
	r4 := newRig(t)
	write(t, r4.path(".local/bin/go.mod"), "module x\n")
	r4.env.yes, r4.env.interactive = true, false
	r4.run("")
	if !r4.exists(".local/bin/tego") || !strings.Contains(r4.out.String(), "source checkout") {
		t.Errorf("a program beside a go.mod was removed:\n%s", r4.out)
	}
}

func TestUninstallSystemInstallNamesSudoCommandsAndTouchesNothing(t *testing.T) {
	r := newRig(t)
	sys := filepath.Join(filepath.Dir(r.home), "sys")
	write(t, filepath.Join(sys, "etc/tego/config.yaml"), "x")
	write(t, filepath.Join(sys, "etc/systemd/system/tego-agent@.service"), "x")
	write(t, filepath.Join(sys, "usr/local/bin/tego"), "x")
	r.env.systemPaths = []string{filepath.Join(sys, "etc/tego"), filepath.Join(sys, "etc/systemd/system/tego*.service"), filepath.Join(sys, "usr/local/bin/tego")}
	// the running tego is a root-owned system copy: the folder is not the user's to change
	root := filepath.Join(sys, "usr/local/bin")
	r.env.self = filepath.Join(root, "tego")
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })
	r.env.yes, r.env.interactive = true, false
	code := r.run("")
	out := r.out.String()
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, want := range []string{"needs sudo", "sudo rm -r '" + filepath.Join(sys, "etc/tego") + "'", "sudo rm '" + filepath.Join(root, "tego") + "'"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, rel := range []string{"etc/tego/config.yaml", "etc/systemd/system/tego-agent@.service", "usr/local/bin/tego"} {
		if _, err := os.Stat(filepath.Join(sys, rel)); err != nil {
			t.Errorf("%s was touched: %v", rel, err)
		}
	}
	if strings.Contains(out, "disable --now tego-agent@.service") || !strings.Contains(out, "sudo systemctl daemon-reload") {
		t.Errorf("no system unit commands:\n%s", out)
	}
}

func TestUninstallCopiedExampleUnitsAreRemovedOnlyWithTheServices(t *testing.T) {
	r := newRig(t)
	unit := ".config/systemd/user/tego-agent@.service"
	write(t, r.path(unit), "# SPDX\n[Unit]\nDescription=Tego agent %i\n")
	write(t, r.path(".config/systemd/user/tego-gc.timer"), "[Unit]\nDescription=my own timer\n")
	r.env.yes, r.env.interactive = true, false
	r.run("")
	if !r.exists(unit) {
		t.Fatalf("--yes alone removed a unit file you copied")
	}
	r.env.stopAgents = true
	r.run("")
	if r.exists(unit) || !r.units.called("daemon-reload") {
		t.Errorf("the copy was not removed and the manager reloaded: %v", r.units.calls)
	}
	if !r.exists(".config/systemd/user/tego-gc.timer") {
		t.Errorf("a timer that is not Tego's example was removed")
	}
}

func TestUninstallAsksOnlyInATerminalOrWithYes(t *testing.T) {
	r := newRig(t)
	r.env.interactive = false
	if code := r.run(""); code != identity.ExitUsage || !strings.Contains(r.out.String(), "runs in a terminal") || !r.exists(".local/bin/tego") {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	if r.units.called("stop") {
		t.Errorf("a unit was stopped without an answer")
	}
	// an input that ends before the answer is a no
	r.env.interactive = true
	if code := r.run(""); code != identity.ExitOK || !r.exists(".local/bin/tego") {
		t.Fatalf("closed input: exit %d", code)
	}
}

func TestUninstallRefusesRootAndAnUnknownHome(t *testing.T) {
	r := newRig(t)
	r.env.euid = 0
	if code := r.run("y\n"); code != identity.ExitUsage || !r.exists(".local/bin/tego") {
		t.Fatalf("root: exit %d", code)
	}
	if got := r.out.String(); strings.Contains(got, "without sudo or as root") || !strings.Contains(got, "without sudo") || !strings.Contains(got, "as the user it was installed for") {
		t.Errorf("the root refusal contradicts itself or does not say who runs it:\n%s", got)
	}
	r.env.euid = os.Geteuid()
	for _, h := range []string{"", "/", "relative"} {
		r.env.home = h
		if code := r.run("y\n"); code != identity.ExitError {
			t.Errorf("home %q: exit %d", h, code)
		}
	}
}

func TestUninstallCommandArguments(t *testing.T) {
	if code, _, errs := run(t, "uninstall", "extra"); code != identity.ExitUsage || !strings.Contains(errs, "takes no arguments") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if code, _, errs := run(t, "uninstall", "--bogus"); code != identity.ExitUsage || !strings.Contains(errs, "flag provided but not defined") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	_, out, _ := run(t, "help", "-a")
	if !strings.Contains(out, "uninstall") {
		t.Errorf("tego help -a does not list uninstall")
	}
}

func TestUninstallRealEnvironmentIsRefusedInATestBuild(t *testing.T) {
	// A binary built with tegotesthooks must never remove the invoking user's real files; without the tag the guard is
	// nil and the real command runs against the real home, so this test only exercises the guarded build.
	if uninstallRealGuard() == nil {
		t.Skip("a product build")
	}
	if _, err := realUninstallEnv(&bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "tegotesthooks") {
		t.Fatalf("err = %v", err)
	}
}

// TestUninstallStopsTheUnitsTheRetentionTimerMakes pins uninstall to retain_timer.go: the timer `tego start` makes is
// `systemd-run --unit=<retentionTimerUnit>`, so systemd creates <name>.timer and <name>.service, and `tego uninstall`
// must stop exactly those two. The rig names them from the real constant, so a rename in one place fails here.
func TestUninstallStopsTheUnitsTheRetentionTimerMakes(t *testing.T) {
	argv := retentionTimerArgv("/home/u/.local/bin/tego", "")
	if !slices.Contains(argv, "--unit="+retentionTimerUnit) {
		t.Fatalf("the systemd-run call does not name its unit %q: %v", retentionTimerUnit, argv)
	}
	r := newRig(t)
	if code := r.run("y\n"); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out.String())
	}
	for _, unit := range []string{retentionTimerUnit + ".timer", retentionTimerUnit + ".service"} {
		if !r.units.called("stop " + unit) {
			t.Errorf("uninstall did not stop %s; calls: %v", unit, r.units.calls)
		}
		if r.units.present[unit] {
			t.Errorf("%s is still present after uninstall", unit)
		}
	}
}

// A system unit the printed `sudo systemctl disable --now` line names is one shell word as typed: a plain unit file's
// name stays as it is, and a name outside systemd's alphabet (made by whoever has /etc/systemd/system) is quoted.
func TestUninstallSystemUnitNamesAreOneShellWord(t *testing.T) {
	r := newRig(t)
	sys := filepath.Join(filepath.Dir(r.home), "sys")
	odd := "tego x;touch y.service"
	write(t, filepath.Join(sys, "etc/systemd/system/tego-agent.service"), "x")
	write(t, filepath.Join(sys, "etc/systemd/system", odd), "x")
	r.env.systemPaths = []string{filepath.Join(sys, "etc/systemd/system/tego*.service")}
	r.env.yes, r.env.interactive = true, false
	if code := r.run(""); code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, r.out)
	}
	out := r.out.String()
	for _, want := range []string{"sudo systemctl disable --now tego-agent.service\n", "sudo systemctl disable --now '" + odd + "'\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"--now tego x;touch"} {
		if strings.Contains(out, bad) {
			t.Errorf("an unquoted unit name in a printed sudo line (%q):\n%s", bad, out)
		}
	}
}

const guideDropIn = ".config/systemd/user/tego-agent@.service.d/10-delegate.conf"

func TestUninstallRemovesTheGuidesDropInAndItsEmptyFolderWithTheServices(t *testing.T) {
	r := newRig(t)
	write(t, r.path(".config/systemd/user/tego-agent@.service"), "[Unit]\nDescription=Tego agent %i\n")
	write(t, r.path(guideDropIn), "[Service]\nDelegate=yes\n")
	r.env.yes, r.env.interactive = true, false
	r.run("")
	if !r.exists(guideDropIn) {
		t.Fatalf("--yes alone removed the drop-in of a service you set up")
	}
	r.env.stopAgents = true
	if code := r.run(""); code != 0 {
		t.Fatalf("exit %d: %s", code, r.out)
	}
	if r.exists(".config/systemd/user/tego-agent@.service.d") {
		t.Errorf("the drop-in folder is still there:\n%s", r.out)
	}
	if !r.units.called("daemon-reload") {
		t.Errorf("no reload after removing a drop-in: %v", r.units.calls)
	}
	if code := r.run(""); code != 0 {
		t.Errorf("second uninstall exit %d", code)
	}
}

func TestUninstallDropInFolderWithoutACopiedTemplateStillGoes(t *testing.T) {
	r := newRig(t)
	write(t, r.path(guideDropIn), "[Service]\nDelegate=yes\n")
	r.env.yes, r.env.interactive, r.env.stopAgents = true, false, true
	r.run("")
	if r.exists(".config/systemd/user/tego-agent@.service.d") {
		t.Errorf("the drop-in folder is still there")
	}
}

func TestUninstallLeavesAndNamesFilesTheGuideDidNotNameInTheDropInFolder(t *testing.T) {
	r := newRig(t)
	other := ".config/systemd/user/tego-agent@.service.d/20-mine.conf"
	write(t, r.path(guideDropIn), "[Service]\nDelegate=yes\n")
	write(t, r.path(other), "[Service]\nNice=5\n")
	r.env.yes, r.env.interactive, r.env.stopAgents = true, false, true
	r.run("")
	if !r.exists(other) {
		t.Fatalf("a file the guide did not name was removed")
	}
	if r.exists(guideDropIn) {
		t.Errorf("the guide's own drop-in was kept")
	}
	if !strings.Contains(r.out.String(), "20-mine.conf") {
		t.Errorf("the output does not name the file it left:\n%s", r.out)
	}
}

func TestUninstallKeepsADropInTheGuideNamesButThePersonChanged(t *testing.T) {
	r := newRig(t)
	write(t, r.path(guideDropIn), "[Service]\nDelegate=yes\nNice=5\n")
	r.env.yes, r.env.interactive, r.env.stopAgents = true, false, true
	r.run("")
	if !r.exists(guideDropIn) || !strings.Contains(r.out.String(), "10-delegate.conf") {
		t.Errorf("an edited drop-in was removed or not named:\n%s", r.out)
	}
}

func TestUninstallNeverFollowsALinkedDropInFolder(t *testing.T) {
	r := newRig(t)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "10-delegate.conf"), "[Service]\nDelegate=yes\n")
	if err := os.MkdirAll(r.path(".config/systemd/user"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, r.path(".config/systemd/user/tego-agent@.service.d")); err != nil {
		t.Fatal(err)
	}
	r.env.yes, r.env.interactive, r.env.stopAgents = true, false, true
	r.run("")
	if _, err := os.Stat(filepath.Join(outside, "10-delegate.conf")); err != nil {
		t.Errorf("a file behind a linked folder was removed: %v", err)
	}
}
