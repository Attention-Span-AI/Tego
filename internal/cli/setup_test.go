// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// sudoVars are the variables sudo sets for the command it starts.
var sudoVars = []string{"SUDO_UID", "SUDO_GID", "SUDO_USER", "SUDO_COMMAND"}

// ownShell makes this test's environment a person's own shell, not a sudo: it removes sudoVars until the test ends.
// The test binary inherits them under `sudo go test` (CI's root-suites job, test/vm/root-suites.sh's guests), and as
// root config.InvokingUID then names sudo's caller, so tego setup and tego learn --save refuse as root for another
// user (125 [privilege]): a test of a person's own setup or save tested the refusal instead (acceptance 2C,
// 2026-11-11, 26 tests). As root it is root's own shell (root logged in, or su -), which those commands serve; as a
// user it changes nothing, since InvokingUID reads SUDO_UID only for uid 0. A test of the refusal sets SUDO_UID
// itself (TestSetupExitCodes, TestLearnSaveRefusesSudo).
func ownShell(t *testing.T) {
	t.Helper()
	for _, k := range sudoVars {
		t.Setenv(k, "") // registers the variable's restore
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
}

// danaUID is the fixture user's uid, which setup -v prints (testdata/setup-finished-v.golden). It was the test
// process's own uid, so the golden held only where the test ran as uid 1000: as root it printed uid 0 (the 7.0 guest's
// root suite, 2026-11-11), and as GitHub's runner user uid 1001.
const danaUID = 1000

// onFixture points every machine read of this test at fixture f, as `tego setup` run by its user from its agent's
// folder, in the user's own shell (ownShell): the machine config is f's file alone, the passwd home is f's home, the
// chain anchor is f's, and the probe, the clock and the host are the fixture's. It returns the fixture.
func onFixture(t *testing.T, name string) *guidetest.Fixture {
	t.Helper()
	ownShell(t)
	f := guidetest.Make(t, name)
	t.Setenv(config.EnvConfigVar, f.Config)
	t.Setenv("PATH", guidetest.PATH)
	prevSources := machineSources
	machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
		src, _, diags := config.Resolve(uid, secure)
		src.Etc, src.User = "", filepath.Join(f.Home, config.UserRelPath)
		return src, f.Home, diags
	}
	useAnchor(t, f.Anchor)
	prevProbe, prevNow, prevInputs := setupProbe, setupNow, setupInputs
	setupProbe = func(context.Context, *config.Machine) (probeAnswer, error) {
		return probeAnswer{tier: backend.Tier(f.Probe.Tier), fix: f.Probe.FirstFix,
			outside: f.Probe.Cause == guide.CauseOutsideUserManager, noManager: f.Probe.Cause == guide.CauseNoUserManager}, nil
	}
	setupNow = func() time.Time { return guidetest.CheckTime }
	setupInputs = func(in *guide.Inputs) {
		in.As = &guide.As{User: "dana", UID: danaUID, Where: f.Probe.Where,
			InUserCgroup: f.Probe.Where == guide.WhereUserManager}
		in.Host = guide.Host{Kernel: guidetest.Kernel, BootID: guidetest.BootID}
		in.Version, in.Commit, in.Build = guidetest.Version, guidetest.Commit, guidetest.Build
	}
	t.Cleanup(func() {
		machineSources, setupProbe, setupNow, setupInputs = prevSources, prevProbe, prevNow, prevInputs
	})
	t.Chdir(f.Project)
	return f
}

// TestSetupGolden pins what a person reads from `tego setup` on a fresh, a half-done and a finished machine, and with
// -v on the finished one: the steps on stdout, then the next: block on stderr (testdata/setup-<fixture>.golden;
// -update rewrites them). The fixture's root is written <root>, its home ~.
func TestSetupGolden(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		args    []string
		golden  string
		code    int
	}{
		{guidetest.Fresh, nil, "setup-fresh", identity.ExitOK},
		{guidetest.HalfDone, nil, "setup-half-done", identity.ExitOK},
		{guidetest.Finished, nil, "setup-finished", identity.ExitOK},
		{guidetest.Finished, []string{"-v"}, "setup-finished-v", identity.ExitOK},
		{guidetest.NotReady, nil, "setup-not-ready", identity.ExitFinding},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join("testdata", tc.golden+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			f := onFixture(t, tc.fixture) // changes the working directory
			hintsAt(t, false, "on")
			code, out, errs := run(t, append([]string{"setup"}, tc.args...)...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, errs)
			}
			got := f.Normal([]byte("--- stdout\n" + out + "--- stderr\n" + errs))
			if *updateGolden {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs (go test -run TestSetupGolden -update):\n%s", path, got)
			}
			for _, line := range strings.Split(errs, "\n") {
				if strings.HasPrefix(line, "next: ") && len([]rune(line)) > 80 {
					t.Errorf("the next: line is wider than 80 columns: %q", line)
				}
			}
		})
	}
}

// withoutAs is a tego.setup/1 object with its "as" left out: the one part that describes the shell that asked, which
// the dashboard leaves null.
func withoutAs(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not one JSON object: %v: %s", err, b)
	}
	delete(m, "as")
	return m
}

// TestSetupParityWithTheFiles: for every fixture, `tego setup --json` prints the object the dashboard computes from
// the files once tego setup has run (guide.Compute with no check made now and no shell asking), "as" aside. This is
// the parity the two surfaces rest on (ADR 0142 (1)), with the command itself in the loop.
func TestSetupParityWithTheFiles(t *testing.T) {
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := onFixture(t, name)
			code, out, errs := run(t, "setup", "--json")
			if want := map[bool]int{true: identity.ExitOK, false: identity.ExitFinding}[f.Probe.Tier != ""]; code != want {
				t.Fatalf("exit %d, want %d: %s", code, want, errs)
			}
			if strings.Contains(errs, "next:") {
				t.Errorf("--json printed a hint: %q", errs)
			}
			var head struct {
				Schema string    `json:"schema"`
				As     *guide.As `json:"as"`
			}
			if err := json.Unmarshal([]byte(out), &head); err != nil || head.Schema != guide.Schema || head.As == nil {
				t.Fatalf("schema %q, as %v: %v", head.Schema, head.As, err)
			}
			dash, err := json.Marshal(guide.Compute(t.Context(), f.Inputs(t)))
			if err != nil {
				t.Fatal(err)
			}
			cli, files := withoutAs(t, []byte(out)), withoutAs(t, dash)
			cb, _ := json.Marshal(cli)
			fb, _ := json.Marshal(files)
			if !bytes.Equal(cb, fb) {
				t.Errorf("tego setup --json:\n%s\nthe dashboard's object from the files:\n%s", cb, fb)
			}
		})
	}
}

// TestSetupStoresTheCheckDoctorDoesNot: tego setup stores its check, 0600, for this boot and this build; tego doctor
// writes no check (it stays read-only for the scripts that run it).
func TestSetupStoresTheCheckDoctorDoesNot(t *testing.T) {
	f := onFixture(t, guidetest.Fresh)
	if code, _, errs := run(t, "setup"); code != identity.ExitOK {
		t.Fatalf("setup: exit %d: %s", code, errs)
	}
	cs, err := guide.ReadChecks(f.Home)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].BootID != guidetest.BootID || cs[0].Build != guidetest.Build || cs[0].Where != f.Probe.Where ||
		cs[0].Tier != "landlock" || !cs[0].Time.Equal(guidetest.CheckTime) {
		t.Errorf("stored %+v", cs)
	}
	if fi, err := os.Stat(guide.CheckPath(f.Home)); err != nil || fi.Mode() != 0o600 {
		t.Errorf("check.json: %v %v", fi, err)
	}
	if err := os.Remove(guide.CheckPath(f.Home)); err != nil {
		t.Fatal(err)
	}
	run(t, "doctor")
	run(t, "doctor", "--json")
	if _, err := os.Stat(guide.CheckPath(f.Home)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("tego doctor wrote the check: %v", err)
	}
}

// TestSetupExitCodes: usage is 2; a governed agent is refused (125 [governed]) and root for another user under sudo
// (125 [privilege]), each before anything is written; a record it cannot read is 125 after the object, with no hint.
func TestSetupExitCodes(t *testing.T) {
	f := onFixture(t, guidetest.Fresh)
	if code, _, errs := run(t, "setup", "extra"); code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
		t.Errorf("an argument: exit %d: %s", code, errs)
	}
	if code, _, _ := run(t, "setup", "--bogus"); code != identity.ExitUsage {
		t.Errorf("a bad flag: exit %d", code)
	}

	prev := selfInRun
	selfInRun = func() (bool, error) { return true, nil }
	code, _, errs := run(t, "setup")
	selfInRun = prev
	if code != identity.ExitError || !strings.Contains(errs, "["+codeGoverned+"]") {
		t.Errorf("governed: exit %d: %s", code, errs)
	}
	// As root SUDO_UID names the invoking user; unprivileged, InvokingUID ignores it and the refusal is reached
	// through the stand-in euid with the real uid as the invoking user, which is not 0. Either way it is another user
	// (but for uid 0 of a user namespace of its own, where SUDO_UID is ignored and the invoking user is root).
	prevEUID := learnEUID
	learnEUID = func() int { return 0 }
	t.Setenv("SUDO_UID", "4242")
	code, _, errs = run(t, "setup")
	learnEUID = prevEUID
	if uid, _ := config.InvokingUID(); uid != 0 && (code != identity.ExitError || !strings.Contains(errs, "["+codePrivilege+"]")) {
		t.Errorf("root for another user: exit %d: %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(f.Home, ".tego", guide.StateDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused setup made the state folder: %v", err)
	}

	if os.Geteuid() != 0 {
		if err := os.Chmod(f.Ledger, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(f.Ledger, 0o700) })
		hintsAt(t, false, "on")
		code, out, errs := run(t, "setup")
		if code != identity.ExitError || !strings.Contains(out, "[?]") || strings.Contains(errs, "next:") {
			t.Errorf("an unreadable record: exit %d:\n%s\n%s", code, out, errs)
		}
	}
}

// TestSetupHintsFollowTEGO_HINTS: the next: block is on stderr, last, in the one hint format; TEGO_HINTS=off leaves it
// out and stdout is unchanged.
func TestSetupHintsFollowTEGO_HINTS(t *testing.T) {
	onFixture(t, guidetest.HalfDone)
	hintsAt(t, false, "on")
	_, on, errsOn := run(t, "setup")
	hintsAt(t, true, "off")
	_, off, errsOff := run(t, "setup")
	if on != off {
		t.Errorf("stdout depends on TEGO_HINTS:\n%s\n%s", on, off)
	}
	if !regexp.MustCompile(`(?m)^next: .+\n  tego learn [0-9a-z]+ --save bot\n\z`).MatchString(errsOn) {
		t.Errorf("TEGO_HINTS=on: stderr %q", errsOn)
	}
	if strings.Contains(errsOff, "next:") {
		t.Errorf("TEGO_HINTS=off: stderr %q", errsOff)
	}
}

// TestSetupSaysWhenTheCheckIsNotStored: a link at ~/.tego/state is not written through; the guide still uses the check
// it made now, and its first not-known line says the check was not stored.
func TestSetupSaysWhenTheCheckIsNotStored(t *testing.T) {
	f := onFixture(t, guidetest.Fresh)
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(f.Home, ".tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(f.Home, ".tego", guide.StateDir)); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "setup", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var s guide.State
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	if s.Steps[1].State != guide.Done || len(s.NotKnown) == 0 || !strings.HasPrefix(s.NotKnown[0], "this check was not stored") {
		t.Errorf("check %s, not known %q", s.Steps[1].State, s.NotKnown)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Errorf("setup wrote through the link: %v", ents)
	}
}

// TestSetupRealProbeAgreesWithDoctor runs tego setup's own probe on this machine and tego doctor --json beside it:
// setup is ready (exit 0, a stored tier) exactly when doctor names a tier, and for a user who is not root, whose runs
// doctor gives tier landlock at most, setup stores doctor's tier and exits as doctor does.
func TestSetupRealProbeAgreesWithDoctor(t *testing.T) {
	f := onFixture(t, guidetest.Fresh)
	setupProbe = probeHere
	code, _, errs := run(t, "setup")
	cs, err := guide.ReadChecks(f.Home)
	if err != nil || len(cs) != 1 {
		t.Fatalf("stored %+v: %v (%s)", cs, err, errs)
	}
	dcode, out, _ := run(t, "doctor", "--json")
	var rep struct{ Tier string }
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("doctor --json %q: %v", out, err)
	}
	want := identity.ExitOK
	if rep.Tier == "" {
		want = identity.ExitFinding
	}
	if code != want || (cs[0].Tier == "") != (rep.Tier == "") {
		t.Errorf("setup exit %d, stored tier %q; doctor names tier %q: %s", code, cs[0].Tier, rep.Tier, errs)
	}
	if cs[0].Tier == "" && cs[0].FirstFix == "" {
		t.Error("a check with no tier stored no fix")
	}
	if os.Geteuid() != 0 && (cs[0].Tier != rep.Tier || code != dcode) {
		t.Errorf("not root: setup stored tier %q and exited %d; doctor said tier %q and exited %d", cs[0].Tier, code,
			rep.Tier, dcode)
	}
}

// TestHelpListsSetup: scripts/install.sh names tego setup as the next step only when `tego help` prints a line that
// starts with two spaces and "setup " on stdout (its grep '^  setup '); a help regrouping that drops it would send the
// installer back to tego doctor without a word.
func TestHelpListsSetup(t *testing.T) {
	code, out, _ := run(t, "help")
	if code != identity.ExitOK || !regexp.MustCompile(`(?m)^  setup `).MatchString(out) {
		t.Errorf("tego help exited %d and has no line starting \"  setup \" on stdout:\n%s", code, out)
	}
}
