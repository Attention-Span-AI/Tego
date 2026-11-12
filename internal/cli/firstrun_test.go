// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	rtcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/selftest"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The new user's walk of acceptance B (2026-11-11, ADR 0142's amendment), as tests: a guest's
// SSH and console logins run beside the user manager's cgroup, where tego starts no run; a systemd-run --user --scope
// shell runs inside it. The next: lines looped there (tego setup -> tego doctor -> tego doctor) and sent the SSH shell
// to tego watch and tego run, which exit 125 from it.

// place is where a person types: the guest's SSH login, its console login (both beside the user manager's cgroup),
// or a systemd-run --user --scope shell inside it.
type place struct {
	name string
	ssh  bool
	// inside is a shell in the user manager's cgroup, where tego's probe is ready; beside it the probe finds no tier,
	// only because of the placement (doctor.Report.OutsideUserManager).
	inside bool
}

var places = []place{{"ssh", true, false}, {"console", false, false}, {"scope", false, true}}

// canRun is the predicate the commands refuse by, as the place gives it: from a shell beside the user manager's cgroup
// every command that starts a run (guide.RunCommands: tego run, watch and test) exits 125, through FS.CanPlace's
// cgroup.ErrBesideSubtree or doctor's D3, which asks the same (TestEveryRunCommandRefusesBesideTheUserManager holds the
// commands to it).
func (p place) canRun(command string) bool { return p.inside || !guide.StartsRun(command) }

// onPlace makes the fixture's tego setup run from p: its probe and its shell. scopeChecked stores, first, the check a
// systemd-run --user --scope tego setup made on this boot (the walk's later steps).
func onPlace(t *testing.T, name string, p place, scopeChecked bool) *guidetest.Fixture {
	t.Helper()
	f := onFixture(t, name)
	if scopeChecked {
		if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
			t.Fatal(err)
		}
	}
	if !p.inside {
		f.Probe.Where, f.Probe.Tier, f.Probe.FirstFix, f.Probe.Cause = guide.WhereShell, "", guidetest.OutsideFix, guide.CauseOutsideUserManager
	}
	prev, prevOpener, prevBeside := setupInputs, scopeOpener, besideUserManager
	scopeOpener = func() guide.Opening { return guide.Opening{Command: guide.DefaultScope} }
	besideUserManager = func() bool { return !p.inside }
	setupInputs = func(in *guide.Inputs) {
		prev(in)
		in.As.SSH, in.As.Where, in.As.InUserCgroup = p.ssh, f.Probe.Where, p.inside
		if !p.inside {
			in.As.Scope = guide.DefaultScope
		}
	}
	t.Cleanup(func() { setupInputs, scopeOpener, besideUserManager = prev, prevOpener, prevBeside })
	return f
}

// outsideReport is doctor's report from a shell beside the user manager's cgroup, as the guests printed it: D3's
// placement refusal and nothing else missing for tier landlock.
func outsideReport() *doctor.Report {
	return &doctor.Report{OutsideUserManager: true, Fix: guidetest.OutsideFix,
		Missing: map[backend.Tier][]string{backend.TierLandlock: {"cgroupv2: cgroup: this process runs outside its delegated cgroup v2 subtree"}},
		Results: []doctor.Result{{ID: doctor.CheckCgroupV2, Detail: "cgroup: this process runs outside its delegated cgroup v2 subtree", Fix: guidetest.OutsideFix}}}
}

// doctorAt is what tego doctor prints on stderr after its report, from p (writeDoctorVerdict: stdout is the probes'
// table, which this machine's own probes would decide).
func doctorAt(p place) string {
	rep := &doctor.Report{Tier: backend.TierLandlock}
	if !p.inside {
		rep = outsideReport()
	}
	var b bytes.Buffer
	writeDoctorVerdict(&b, rep)
	return b.String()
}

// nextCommand is the command of the last next: block in stderr, "" for a block with none; ok is false with no block.
func nextCommand(stderr string) (string, bool) {
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "next: ") {
			if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  ") {
				return strings.TrimPrefix(lines[i+1], "  "), true
			}
			return "", true
		}
	}
	return "", false
}

// TestTheNextLinesNeverLoopFromAnyPlace is the walk's table: for each state the walk passed (fresh, half-done, a
// contract made, finished) and each place (SSH, console, a user-manager scope; beside it before and after the scope's
// check was stored), the next: command tego setup and tego doctor print is (a) never the command that printed it and
// (b) one the place can run, by the predicate the commands refuse by (canRun). On the base it failed: from SSH tego
// setup named tego doctor, tego doctor named itself, and with the scope's check stored tego setup named tego watch
// and tego run, which exit 125 there. Its side paths (sidePaths): `sudo tego agents` from each place on three guests,
// and a user with no user manager running.
func TestTheNextLinesNeverLoopFromAnyPlace(t *testing.T) {
	t.Run("side paths", sidePaths)
	t.Run("side paths of acceptance 3", sidePathsAcc3)
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.ContractMade, guidetest.Finished} {
		for _, p := range places {
			for _, scopeChecked := range []bool{false, true} {
				if p.inside && scopeChecked {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/scope-checked=%v", state, p.name, scopeChecked), func(t *testing.T) {
					onPlace(t, state, p, scopeChecked)
					hintsAt(t, false, "on")
					_, _, errs := run(t, "setup")
					outs := []struct{ printed, stderr string }{{"tego setup", errs}, {"tego doctor", doctorAt(p)}}
					// The hop after setup's step, typed where setup printed it: tego learn --save named tego run from
					// SSH, which exits 125 there (the review's M1).
					if cmd, _ := nextCommand(errs); followable(cmd) {
						_, _, hop := run(t, strings.Fields(cmd)[1:]...)
						outs = append(outs, struct{ printed, stderr string }{cmd, hop})
					}
					for _, out := range outs {
						cmd, ok := nextCommand(out.stderr)
						if !ok && strings.HasPrefix(out.printed, "tego receipt ") {
							continue // the walk's end: every step is done
						}
						if !ok {
							t.Errorf("%s printed no next: line:\n%s", out.printed, out.stderr)
							continue
						}
						if cmd == out.printed {
							t.Errorf("%s's next: command is itself:\n%s", out.printed, out.stderr)
						}
						if !p.canRun(cmd) {
							t.Errorf("%s's next: command %q exits 125 from %s:\n%s", out.printed, cmd, p.name, out.stderr)
						}
					}
				})
			}
		}
	}
}

// sidePaths is the table's two side places of acceptance 2B (2026-11-11), each failing on the base:
//   - `sudo tego agents` (its next: step starts a run, so runHint decides by rootBeside), on the three guests' measured
//     cgroups: from an SSH login the step opens the scope; from inside a systemd-run --user scope it is the step
//     itself, typed without sudo. On Fedora 44 sudo opened a root session there, and the step sent the person to open
//     the scope they were in, again and again;
//   - a user with no user manager running (a nologin service account reached through sudo -u): tego setup named tego
//     doctor and doctor named tego setup, with a delegation fix that changed nothing. Both now name the command that
//     starts the manager (cgroup.LingerCommand), a change of state.
//
// In each, no next: command is the command that printed it, a shell already inside the user manager's cgroup is never
// sent to open one, a shell beside it is never sent to start a run, and no two commands point at each other.
func sidePaths(t *testing.T) {
	prevOpener, prevBeside := scopeOpener, besideUserManager
	scopeOpener = func() guide.Opening { return guide.Opening{Command: guide.DefaultScope} }
	t.Cleanup(func() { scopeOpener, besideUserManager = prevOpener, prevBeside })
	hintsAt(t, false, "on")
	text, command := agentsNext(nil, nil)
	for _, c := range []struct {
		guest, from string
		chain       [][]byte
		inside      bool
	}{
		{"ubuntu-24.04", "ssh", [][]byte{sudoSSH, sudoSSH}, false},
		{"almalinux-9.8", "ssh", [][]byte{sudoSSH, sudoSSH}, false},
		{"fedora-44", "ssh", [][]byte{sudoSSH, sudoSSH}, false},
		{"ubuntu-24.04", "scope", [][]byte{sudoScope, sudoScope}, true},
		{"almalinux-9.8", "scope", [][]byte{sudoScope, sudoScope}, true},
		{"fedora-44", "scope", fedoraSudoInScope, true},
	} {
		t.Run("sudo tego agents/"+c.guest+"/"+c.from, func(t *testing.T) {
			besideUserManager = func() bool { return rootBeside(1000, c.chain, true) }
			var b bytes.Buffer
			runHint(&b, text, command)
			got, ok := nextCommand(b.String())
			switch {
			case !ok:
				t.Errorf("no next: line:\n%s", b.String())
			case got == "tego agents" || got == "sudo tego agents":
				t.Errorf("the next: command is itself:\n%s", b.String())
			case c.inside && strings.HasPrefix(got, "systemd-run --user --scope"):
				t.Errorf("a shell inside the user manager's cgroup is sent to open one again:\n%s", b.String())
			case !c.inside && guide.StartsRun(got):
				t.Errorf("%q exits 125 from %s:\n%s", got, c.from, b.String())
			}
		})
	}

	const linger = "sudo loginctl enable-linger svc"
	prevLinger := lingerCommand
	lingerCommand = func(int) string { return linger }
	t.Cleanup(func() { lingerCommand = prevLinger })
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run("no user manager/"+state, func(t *testing.T) {
			onNoManager(t, state, linger)
			_, out, errs := run(t, "setup")
			var b bytes.Buffer
			writeDoctorVerdict(&b, noManagerReport())
			next := map[string]string{}
			for printed, stderr := range map[string]string{"tego setup": errs, "tego doctor": b.String()} {
				cmd, ok := nextCommand(stderr)
				if !ok {
					t.Errorf("%s printed no next: line:\n%s", printed, stderr)
					continue
				}
				if cmd == printed {
					t.Errorf("%s's next: command is itself:\n%s", printed, stderr)
				}
				if cmd != linger {
					t.Errorf("%s's next: command is %q, not the one that starts the user manager:\n%s", printed, cmd, stderr)
				}
				next[printed] = cmd
			}
			if next["tego setup"] == "tego doctor" && next["tego doctor"] == "tego setup" {
				t.Errorf("tego setup and tego doctor point at each other:\n%s\n%s", errs, b.String())
			}
			if !strings.Contains(out, "no user manager runs for you") || strings.Contains(out, "Delegate=") {
				t.Errorf("step 2 does not say why:\n%s", out)
			}
		})
	}

	// After linger the user manager runs, and sudo -u still leaves XDG_RUNTIME_DIR unset: the cause is the placement
	// (outside its cgroup), and guide.OpenScope names the logind folder (the review's S5; its test is
	// TestOpenScopeNamesOnlyACommandThatCanWork). tego setup and tego doctor both name that command: a change of place,
	// never each other, never themselves and never no command.
	const viaLogind = "XDG_RUNTIME_DIR=/run/user/1001 systemd-run --user --scope bash"
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run("after linger/"+state, func(t *testing.T) {
			onPlace(t, state, places[1], false)
			scopeOpener = func() guide.Opening { return guide.Opening{Command: viaLogind} }
			prev := setupInputs
			setupInputs = func(in *guide.Inputs) { prev(in); in.As.Scope = viaLogind }
			t.Cleanup(func() { setupInputs = prev })
			hintsAt(t, false, "on")
			_, _, errs := run(t, "setup")
			var b bytes.Buffer
			writeDoctorVerdict(&b, outsideReport())
			for printed, stderr := range map[string]string{"tego setup": errs, "tego doctor": b.String()} {
				if cmd, ok := nextCommand(stderr); !ok || cmd != viaLogind {
					t.Errorf("%s's next: command is %q, not the one that opens the scope through the logind folder:\n%s", printed, cmd, stderr)
				}
			}
		})
	}
}

// sidePathsAcc3 is the table's two places of acceptance 3 (2026-11-11), each failing on the base:
//   - after linger, tego setup started as the service account from an administrator's shell (sudo -u svc): the next:
//     command was XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash, which the administrator typed in their
//     own shell, where it opened their own scope (Ubuntu 24.04, AlmaLinux 9.8; tego setup there said ready for the
//     wrong user) or failed (Fedora 44). It is now the command that works from that shell, sudo -u svc in front
//     (measured on all three), and the words say to type it in your own shell and whose shell it opens;
//   - a user whose name systemd refuses (4242, digits only, on Ubuntu 24.04): enable-linger exits 0, no user manager
//     starts, and tego setup named the same linger command again. Neither tego setup nor tego doctor now names a
//     command, and both say why.
func sidePathsAcc3(t *testing.T) {
	const asSvc = "sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash"
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run("after linger, from another user's shell/"+state, func(t *testing.T) {
			onPlace(t, state, places[0], false)
			scopeOpener = func() guide.Opening { return guide.Opening{Command: asSvc, As: "svc"} }
			prev := setupInputs
			setupInputs = func(in *guide.Inputs) { prev(in); in.As.Scope, in.As.ScopeAs = asSvc, "svc" }
			t.Cleanup(func() { setupInputs = prev })
			hintsAt(t, false, "on")
			_, out, errs := run(t, "setup")
			// Doctor's report as D3 makes it there: CanPlace's refusal, whose remedy (cgroup.PlacementFix) is read by
			// the administrator, so stdout's fix: line names the sudo -u command too, never the bare one, which opens
			// the administrator's own scope (the review's M1: it did, beside a next: line that named sudo -u).
			rep := outsideReport()
			fix := rtcgroup.PlacementFix(1002, true)
			rep.Fix, rep.Results[0].Fix = fix, fix
			var table bytes.Buffer
			if err := rep.WriteText(&table); err != nil {
				t.Fatal(err)
			}
			if fixLine := lineWith(table.String(), "; fix: "); strings.Contains(fixLine, "open one with systemd-run --user --scope bash") ||
				!strings.Contains(fixLine, "sudo -u ") ||
				!strings.Contains(fixLine, " XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash") {
				t.Errorf("tego doctor's fix: line names a command that opens the administrator's own scope:\n%s", table.String())
			}
			var b bytes.Buffer
			writeDoctorVerdict(&b, rep)
			for printed, stderr := range map[string]string{"tego setup": errs, "tego doctor": b.String()} {
				if cmd, ok := nextCommand(stderr); !ok || cmd != asSvc {
					t.Errorf("%s's next: command is %q, not the one that opens the user's shell from the administrator's:\n%s", printed, cmd, stderr)
				}
				if !strings.Contains(stderr, "next: from your own shell, open a shell as this user; run tego setup in it:") {
					t.Errorf("%s's next: line does not say whose shell to open, or where to type it:\n%s", printed, stderr)
				}
			}
			if !strings.Contains(b.String(), "it opens a shell as svc, in svc's user manager's cgroup, not in yours") ||
				!strings.Contains(b.String(), "in your own login shell, not in one sudo or su opened") {
				t.Errorf("tego doctor does not say whose shell the command opens, or which shell to type it in:\n%s", b.String())
			}
			if !strings.Contains(out, "it opens a shell as svc in svc's user manager's cgroup, not in yours") {
				t.Errorf("step 2 does not say whose shell the command opens:\n%s", out)
			}
		})
	}

	const linger = "sudo loginctl enable-linger 1004"
	const why = "systemd starts no user manager for this account: the name of uid 1004, 4242, is digits only, which " +
		"systemd reads as a uid (systemd.io/USER_NAMES)"
	prevLinger, prevRefused := lingerCommand, managerRefused
	lingerCommand = func(int) string { return linger }
	managerRefused = func(int) string { return why }
	t.Cleanup(func() { lingerCommand, managerRefused = prevLinger, prevRefused })
	refusedFix := why + ", so loginctl enable-linger starts none and tego starts no run for this account: an " +
		"administrator runs the agent as an account whose name starts with a letter and holds only letters, digits, '_' and '-'"
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		t.Run("a name systemd refuses/"+state, func(t *testing.T) {
			f := onNoManager(t, state, linger)
			f.Probe.FirstFix = refusedFix
			managerRefused = func(int) string { return why } // onNoManager's own stub says no refusal
			_, out, errs := run(t, "setup")
			rep := noManagerReport()
			rep.Fix, rep.Results[0].Fix = refusedFix, refusedFix
			var b bytes.Buffer
			writeDoctorVerdict(&b, rep)
			for printed, stderr := range map[string]string{"tego setup": errs, "tego doctor": b.String()} {
				cmd, ok := nextCommand(stderr)
				if !ok {
					t.Errorf("%s printed no next: line:\n%s", printed, stderr)
					continue
				}
				if cmd != "" {
					t.Errorf("%s's next: command is %q; no command starts a user manager for this name:\n%s", printed, cmd, stderr)
				}
				for _, line := range strings.Split(stderr, "\n") {
					if strings.HasPrefix(line, "next: ") && len([]rune(line)) > 80 {
						t.Errorf("the next: line is wider than 80 columns: %q", line)
					}
				}
			}
			if !strings.Contains(out, why) || strings.Contains(out, "enable-linger 1004") {
				t.Errorf("step 2 does not say why:\n%s", out)
			}
		})
	}
}

// lineWith is the first line of s that holds part, "" when none does.
func lineWith(s, part string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, part) {
			return line
		}
	}
	return ""
}

// onNoManager is the fixture's tego setup run by a user for whom no user manager runs, reached through sudo -u: no
// tier, D3's ErrNoUserManager (its fix names linger), a shell outside every user manager whose XDG_RUNTIME_DIR is unset,
// and Inputs.Linger the command the guide may name.
func onNoManager(t *testing.T, name, linger string) *guidetest.Fixture {
	t.Helper()
	f := onFixture(t, name)
	f.Probe.Where, f.Probe.Tier, f.Probe.FirstFix, f.Probe.Cause = guide.WhereShell, "", noManagerFix, guide.CauseNoUserManager
	prev, prevOpener, prevBeside, prevRefused := setupInputs, scopeOpener, besideUserManager, managerRefused
	scopeOpener = func() guide.Opening { return guide.Opening{Missing: noXDG} }
	besideUserManager = func() bool { return false } // Detect refuses: no subtree to be beside
	managerRefused = func(int) string { return "" }  // systemd accepts the name
	setupInputs = func(in *guide.Inputs) {
		prev(in)
		in.As.Where, in.As.InUserCgroup, in.As.Scope, in.As.ScopeMissing = guide.WhereShell, false, "", noXDG
		in.Linger, in.ManagerRefused = linger, managerRefused(in.As.UID)
	}
	t.Cleanup(func() {
		setupInputs, scopeOpener, besideUserManager, managerRefused = prev, prevOpener, prevBeside, prevRefused
	})
	hintsAt(t, false, "on")
	return f
}

// noXDG is guide.OpenScope's reason after sudo -u, as the guests printed it.
const noXDG = "XDG_RUNTIME_DIR is not set in this shell (as after su or sudo -u), so systemd-run --user cannot reach your user manager"

// noManagerFix is D3's fix when no user manager runs for uid 1001 (cgroup.NoManagerFix), with the name svc.
const noManagerFix = "start a user manager for this user that runs without a login: an administrator runs sudo loginctl " +
	"enable-linger svc; then run tego from a shell in it, opened with XDG_RUNTIME_DIR=/run/user/1001 systemd-run --user --scope bash"

// noManagerReport is doctor's report as uid 1001 with no user manager running (Ubuntu 24.04, acceptance 2B): D3's
// ErrNoUserManager, and nothing else missing for tier landlock.
func noManagerReport() *doctor.Report {
	detail := "cgroup: no delegated cgroup v2 subtree for uid 1001: no user manager runs for uid 1001: " +
		"/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service does not exist"
	return &doctor.Report{NoUserManager: true, Fix: noManagerFix,
		Missing: map[backend.Tier][]string{backend.TierLandlock: {"cgroupv2: " + detail}},
		Results: []doctor.Result{{ID: doctor.CheckCgroupV2, Detail: detail, Fix: noManagerFix}}}
}

// followable reports whether a next: command is one the table types in its place: a tego command that starts no run
// and is neither tego setup nor tego doctor (which the table holds itself), with no part only the person knows.
func followable(command string) bool {
	f := strings.Fields(command)
	return len(f) >= 2 && f[0] == "tego" && f[1] != "setup" && f[1] != "doctor" && !guide.StartsRun(command) &&
		!strings.Contains(command, "<")
}

// TestFirstRunGolden pins what the walk's person reads, from SSH, a console login and a user-manager scope, on a fresh,
// a half-done and a finished machine: tego setup's steps and next: block, and tego doctor's stderr after its table
// (testdata/firstrun-<state>-<place>.golden; -update rewrites them).
func TestFirstRunGolden(t *testing.T) {
	type at struct {
		p            place
		scopeChecked bool
		name         string
	}
	ats := []at{{places[0], false, "ssh"}, {places[1], false, "console"}, {places[2], false, "scope"},
		{places[0], true, "ssh-scopechecked"}}
	for _, state := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.Finished} {
		for _, a := range ats {
			p := a.p
			t.Run(state+"-"+a.name, func(t *testing.T) {
				path, err := filepath.Abs(filepath.Join("testdata", "firstrun-"+state+"-"+a.name+".golden"))
				if err != nil {
					t.Fatal(err)
				}
				f := onPlace(t, state, p, a.scopeChecked)
				hintsAt(t, false, "on")
				_, out, errs := run(t, "setup")
				text := "--- tego setup: stdout\n" + out + "--- tego setup: stderr\n" + errs +
					"--- tego doctor: stderr after its table\n" + doctorAt(p)
				if cmd, _ := nextCommand(errs); followable(cmd) {
					// The step setup names, typed from the same place, and what it says next.
					_, _, hop := run(t, strings.Fields(cmd)[1:]...)
					text += "--- " + cmd + ": stderr\n" + hop
				}
				got := f.Normal([]byte(text))
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
					t.Errorf("%s differs (go test -run TestFirstRunGolden -update):\n%s", path, got)
				}
				for _, line := range strings.Split(string(got), "\n") {
					if strings.HasPrefix(line, "next: ") && len([]rune(line)) > 80 {
						t.Errorf("the next: line is wider than 80 columns: %q", line)
					}
				}
			})
		}
	}
}

// TestEveryRunCommandRefusesBesideTheUserManager: each command guide.RunCommands names exits 125 from a shell beside
// the user manager's cgroup, and then ends with the next: block that opens a shell inside it (never itself, never a
// command that starts a run), not with "Nothing got through": tego run when its probe finds tier landlock missing only
// for that (doctor.Report.OutsideUserManager), tego watch when its run's cgroup cannot be placed
// (cgroup.ErrBesideSubtree), tego test when no run under it started and the probe says the same (acceptance B, 2026-11-11). A run pinned above tier landlock gets no such line: that shell would not cure it.
func TestEveryRunCommandRefusesBesideTheUserManager(t *testing.T) {
	prevOpener := scopeOpener
	scopeOpener = func() guide.Opening { return guide.Opening{Command: guide.DefaultScope} }
	t.Cleanup(func() { scopeOpener = prevOpener })
	hintsAt(t, false, "on")
	want := "\nnext: open a shell in your user manager's cgroup, then run this again there:\n  " + guide.DefaultScope + "\n"
	seen := map[string]bool{}

	t.Run("run", func(t *testing.T) {
		seen["run"] = true
		sandboxedLaunch(t)
		prev := probeMachine
		probeMachine = func(context.Context, *config.Machine, backend.Tier) (*doctor.Report, error) {
			return outsideReport(), nil
		}
		t.Cleanup(func() { probeMachine = prev })
		code, _, errs := run(t, "run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--", "true")
		if code != identity.ExitLauncher || !strings.HasSuffix(errs, want) {
			t.Errorf("exit %d:\n%s", code, errs)
		}
		code, _, errs = run(t, "run", filepath.Join("testdata", "minimal.yaml"), "--offline", "--tier", "cgroup", "--", "true")
		if code != identity.ExitLauncher || strings.Contains(errs, "next:") {
			t.Errorf("--tier cgroup: exit %d:\n%s", code, errs)
		}
	})
	t.Run("watch", func(t *testing.T) {
		seen["watch"] = true
		sandboxedLaunch(t)
		prev := startRun
		startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
			return tegoruntime.Result{ExitCode: identity.ExitLauncher}, fmt.Errorf("runtime: cgroup: %w: %w", rtcgroup.ErrOutsideSubtree,
				rtcgroup.ErrBesideSubtree)
		}
		t.Cleanup(func() { startRun = prev })
		code, _, errs := run(t, "watch", "--offline", "--", "python3")
		if code != identity.ExitLauncher || !strings.HasSuffix(errs, want) {
			t.Errorf("exit %d:\n%s", code, errs)
		}
	})
	t.Run("test", func(t *testing.T) {
		seen["test"] = true
		prevRun, prevProbe := selftestRun, testProbe
		selftestRun = func(context.Context, selftest.Options) (selftest.Report, error) {
			return selftest.Report{Tier: "", Verdict: selftest.VerdictInconclusive, Actions: 4,
				Checks: []selftest.Row{{Name: "x", Baseline: selftest.Outcome{Result: selftest.ResultSucceeded},
					UnderTego: selftest.Outcome{Result: selftest.ResultError}}}}, nil
		}
		testProbe = func(context.Context, *config.Machine) (probeAnswer, error) { return probeAnswer{outside: true}, nil }
		t.Cleanup(func() { selftestRun, testProbe = prevRun, prevProbe })
		code, out, errs := run(t, "test")
		if code != identity.ExitError || !strings.HasSuffix(errs, want) || strings.Contains(out, "Nothing got through") {
			t.Errorf("exit %d:\n%s%s", code, out, errs)
		}
		testProbe = func(context.Context, *config.Machine) (probeAnswer, error) { return probeAnswer{}, nil }
		if _, _, errs := run(t, "test"); strings.Contains(errs, "next:") {
			t.Errorf("another cause: %s", errs)
		}
	})
	for _, c := range guide.RunCommands {
		if !seen[c] {
			t.Errorf("guide.RunCommands names %q, which this test does not hold to the refusal", c)
		}
	}
	// No command opens one from here: a line says why, and the block has no command.
	scopeOpener = func() guide.Opening { return guide.Opening{Missing: "systemd-run is not on your PATH"} }
	var b bytes.Buffer
	outsideHint(&b, "run this again there")
	if cmd, ok := nextCommand(b.String()); !ok || cmd != "" || !strings.Contains(b.String(), "systemd-run is not on your PATH") {
		t.Errorf("no scope: %q", b.String())
	}
}

// leakRun is the walk's agent's record (acceptance B, 2026-11-11): one connect early on, then it read an SSH key file and
// connected to the addresses example.com resolved to; the leak rule withholds those, and the early one stays an
// address the proposal allows.
func leakRun(t *testing.T, root, project string) string {
	t.Helper()
	return learnWriteRun(t, root, project, func(w *ledger.Writer) {
		// First, far from the read (more than secretpath.NearLines lines before it), a connect the proposal keeps.
		first := ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: "tcp", Dst: "93.184.215.14:443"}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Authority, e.Attr = record.SourceSupervisor, "unmatched", record.VerdictObserved, record.AuthorityRule, record.Unattributed()
		})
		if err := w.Append(first); err != nil {
			t.Fatal(err)
		}
		for range 20 {
			learnWrite(t, w, filepath.Join(project, "out.txt"))
		}
		read := ledgertest.Event(t, record.KindFS, record.FSPayload{Op: record.FSOpen, Path: "/home/dana/.ssh/id_ed25519"}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Authority, e.Attr = record.SourceSeccomp, "unmatched", record.VerdictObserved, record.AuthorityRule, record.Unattributed()
		})
		if err := w.Append(read); err != nil {
			t.Fatal(err)
		}
		// The address-sorting UDP connects, which send nothing and are kept as addresses, then the one TCP connect.
		for _, l := range []struct{ proto, dst string }{{"udp", "104.20.23.154:443"}, {"udp", "172.66.147.243:443"},
			{"tcp", "104.20.23.154:443"}} {
			e := ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: l.proto, Dst: l.dst}, func(e *record.Event) {
				e.Source, e.Rule, e.Verdict, e.Authority, e.Attr = record.SourceSupervisor, "unmatched", record.VerdictObserved, record.AuthorityRule, record.Unattributed()
			})
			if err := w.Append(e); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// TestTheLearnStepNeverNamesAHostASecretMayHaveGoneTo: for a run whose secrets may have gone to the addresses it
// reached, tego watch's next: line, tego learn's own and tego setup's guide all name the plain learn step, never
// --allow-host <host>, which learn refuses for a host it withheld; and learn's refusal of such a host ends with that
// plain step (acceptance B, 2026-11-11). For a run with no leak, all three name --allow-host alike.
func TestTheLearnStepNeverNamesAHostASecretMayHaveGoneTo(t *testing.T) {
	root, _, _ := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := leakRun(t, root, project)
	short := shortOf(id)
	withLearnResolver(t, tableResolver{table: map[string][]netip.Addr{"example.com": exampleComAnswer}})
	hintsAt(t, false, "on")
	sum := &endSummary{root: root, machine: hintMachine(t)}
	plain := "tego learn " + short + " --save myagent"
	if _, command := watchNext(t.Context(), os.Stderr, tegoruntime.Result{RunID: id}, sum, "", project); command != plain {
		t.Errorf("watch: %q, want %q", command, plain)
	}
	if guide.SuggestHosts(t.Context(), filepath.Join(root, id)) {
		t.Error("the guide's learn step would name --allow-host")
	}
	// The proposal still allows addresses (learn's own warning names them), so only the leak keeps --allow-host out.
	if code, _, errs := run(t, "learn", short); code != identity.ExitOK || strings.Contains(lastHint(t, errs), "--allow-host") ||
		!strings.Contains(errs, "allowed by address, not by name") {
		t.Errorf("learn: exit %d\n%s", code, errs)
	}
	code, _, errs := run(t, "learn", short, "--save", "myagent", "--allow-host", "example.com")
	if code != identity.ExitFinding || !strings.Contains(errs, "which learn withheld because the run's secrets may have gone there") ||
		lastHint(t, errs) != plain {
		t.Errorf("--allow-host refused: exit %d\n%s", code, errs)
	}
	// A run that reached addresses and read no secret: the three name --allow-host alike.
	clean := u2404Run(t, root, project)
	if _, command := watchNext(t.Context(), os.Stderr, tegoruntime.Result{RunID: clean}, sum, "", project); !strings.HasSuffix(command, " --allow-host <host>") ||
		!guide.SuggestHosts(t.Context(), filepath.Join(root, clean)) {
		t.Errorf("a run with no leak: watch %q, guide %v", command, guide.SuggestHosts(t.Context(), filepath.Join(root, clean)))
	}
}

// TestLearnsWarningForAWithheldHostNamesOnlyWhatWorks: for a run that read a secret and then connected out, learn
// withholds the destination, and its warnings said "Name each with --allow-host <host>" for the addresses it kept, a
// flag learn then refuses for the withheld host (acceptance 2B, 2026-11-11: on AlmaLinux the contract then blocked the
// agent's own fetch). The warnings now name no --allow-host; they say which destination was withheld and why, and
// what works: add it by hand to the saved file, or tego rule on the line of a later run that refused it. Both are
// typed here: the hand-written name compiles, and tego rule writes the entry, exit 0. Nothing names it again by itself.
func TestLearnsWarningForAWithheldHostNamesOnlyWhatWorks(t *testing.T) {
	outsideEveryRun(t)
	root, _, reg := saveHarness(t, "")
	project := filepath.Join(resolvedTemp(t), "myagent")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	id := leakRun(t, root, project)
	withLearnResolver(t, tableResolver{table: map[string][]netip.Addr{"example.com": exampleComAnswer}})
	hintsAt(t, false, "on")
	code, _, errs := run(t, "learn", shortOf(id), "--save", "myagent")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	saved := filepath.Join(reg, "agents", "myagent.yaml")
	for _, want := range []string{
		"learn withheld 104.20.23.154:443, 172.66.147.243:443, because the run opened a secret for reading next to a send to each, so a secret may have gone there",
		"A run under this contract is refused those connections, and --allow-host refuses a name that stands for one of them.",
		"write the host's name under net.allow in " + saved + " (for example tcp://api.example.com:443)",
		"tego rule <run> <line> --allow, with the line tego events <run> --verdict refused shows",
		"allowed by address, not by name: tcp 93.184.215.14:443. A later run can be refused another address of the same service",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "--allow-host <host>") || strings.Contains(errs, "Name each with --allow-host") {
		t.Errorf("a warning names --allow-host <host>, which learn refuses for the withheld host:\n%s", errs)
	}
	text, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), `- "tcp://104.20.23.154:443"`) {
		t.Fatalf("the withheld destination is allowed:\n%s", text)
	}
	// What the warning names, typed: a run under the saved contract refused the connect, and tego rule on its line
	// allows it, writing the file (the person said so explicitly).
	dir := filepath.Join(resolvedTemp(t), "r-fixture")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"python3"}, Cwd: project, Kernel: "6", StopGrace: "1s",
		ContractSource: &record.ContractSource{Path: saved}})
	refused := ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "connect", Target: "104.20.23.154:443"}, func(e *record.Event) {
		e.Seq, e.Rule, e.Reason = 1, "unmatched", record.ReasonNetNotAllowed
		e.Prev = strings.Repeat("a", 64)
	})
	var buf bytes.Buffer
	for _, e := range []*record.Event{start, refused} {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "rule", dir, "1", "--allow")
	if code != identity.ExitOK {
		t.Fatalf("tego rule <run> 1 --allow: exit %d\n%s%s", code, out, errs)
	}
	if b, _ := os.ReadFile(saved); !strings.Contains(string(b), "104.20.23.154:443") {
		t.Errorf("tego rule did not write the entry:\n%s", b)
	}
}

// TestALinkAtTheCheckIsSaidAndReplaced: a link at check.json is said as not known by the tego setup that finds it, and
// that same tego setup replaces it with a regular 0600 file, never writing through it (acceptance B, 2026-11-11: the link
// used to be replaced in silence; the docs said "reported as not known and replaced on the next tego setup").
func TestALinkAtTheCheckIsSaidAndReplaced(t *testing.T) {
	f := onFixture(t, guidetest.Fresh)
	state := filepath.Dir(guide.CheckPath(f.Home))
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(f.Root, "elsewhere.json")
	if err := os.WriteFile(target, []byte("not mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, guide.CheckPath(f.Home)); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "setup")
	if code != identity.ExitOK || !strings.Contains(out, "Not known:\n") || !strings.Contains(out, "a link or not a folder there") {
		t.Errorf("exit %d: the link is not said:\n%s%s", code, out, errs)
	}
	fi, err := os.Lstat(guide.CheckPath(f.Home))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("check.json after: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "not mine\n" {
		t.Errorf("the link's target was written: %q", b)
	}
}

// TestAfterARebootSetupSaysWhatIsNotChecked: tego setup after a reboot checks its own place and says the other place's
// check, from before this machine started, is not used (acceptance B, 2026-11-11), before it stores its own and drops that one.
func TestAfterARebootSetupSaysWhatIsNotChecked(t *testing.T) {
	f := onPlace(t, guidetest.Fresh, places[0], false)
	old := guide.Check{Where: guide.WhereUserManager, Build: guidetest.Build, BootID: "00000000-0000-4000-8000-000000000000",
		Tier: "landlock", Time: guidetest.CheckTime}
	if err := guide.StoreCheck(f.Home, old); err != nil {
		t.Fatal(err)
	}
	hintsAt(t, false, "on")
	_, out, _ := run(t, "setup")
	if !strings.Contains(out, "a shell in your user manager's cgroup: "+guide.NotCheckedSinceStart) {
		t.Errorf("the place checked before the reboot is not said:\n%s", out)
	}
	if cs, err := guide.ReadChecks(f.Home); err != nil || len(cs) != 1 || cs[0].Where != guide.WhereShell {
		t.Errorf("stored %+v %v", cs, err)
	}
}

// TestARunHintFromBesideTheUserManagerOpensTheShell: a next: step whose command starts a run (tego learn --save's tego
// run, tego agents' tego watch) is said in a guidance line from a shell beside the user manager's cgroup, and the
// block opens a shell inside it instead, never the command that exits 125 there (the review's M1). A step that starts
// no run, and any step from inside, is the step itself. Root asks for the invoking user (rootBeside).
func TestARunHintFromBesideTheUserManagerOpensTheShell(t *testing.T) {
	prevOpener, prevBeside := scopeOpener, besideUserManager
	scopeOpener = func() guide.Opening { return guide.Opening{Command: guide.DefaultScope} }
	t.Cleanup(func() { scopeOpener, besideUserManager = prevOpener, prevBeside })
	hintsAt(t, false, "on")
	text, command := agentsNext(nil, nil)
	for _, beside := range []bool{false, true} {
		besideUserManager = func() bool { return beside }
		var b bytes.Buffer
		runHint(&b, text, command)
		got, _ := nextCommand(b.String())
		switch {
		case !beside && got != command:
			t.Errorf("inside: %q", b.String())
		case beside && (got != guide.DefaultScope || !strings.Contains(b.String(), "In a shell inside it, "+text+" "+command+"\n") ||
			strings.Contains(b.String(), "next: "+text)):
			t.Errorf("beside: %q", b.String())
		}
		for _, line := range strings.Split(b.String(), "\n") {
			if strings.HasPrefix(line, "next: ") && len([]rune(line)) > 80 {
				t.Errorf("the next: line is wider than 80 columns: %q", line)
			}
		}
		b.Reset()
		runHint(&b, "make a contract from what it did:", "tego learn b883rx --save bot")
		if got, _ := nextCommand(b.String()); got != "tego learn b883rx --save bot" {
			t.Errorf("a step that starts no run, beside=%v: %q", beside, b.String())
		}
	}
	for _, c := range []struct {
		uid     int
		chain   [][]byte
		managed bool
		want    bool
	}{
		{1000, [][]byte{sudoSSH}, true, true},
		{1000, [][]byte{sudoScope}, true, false},
		{0, [][]byte{sudoSSH}, true, false},        // root's own run is placed anywhere
		{1000, [][]byte{sudoSSH}, false, false},    // no user manager: no shell opens one
		{1000, [][]byte{nil}, true, false},         // a cgroup it cannot read
		{1000, nil, true, false},                   // nothing read at all
		{1001, [][]byte{sudoScope}, true, true},    // another user's manager is not this user's
		{1000, fedoraSudoInScope, true, false},     // sudo opened a root session; the shell is in the scope
		{1000, fedoraSudoFromSSH, true, true},      // the same root session, typed from an SSH login
		{1000, [][]byte{rootSession}, true, false}, // only root's session can be read: not told
		{1000, [][]byte{rootSession, nil}, true, false},
	} {
		if got := rootBeside(c.uid, c.chain, c.managed); got != c.want {
			t.Errorf("rootBeside(%d, %q, %v) = %v, want %v", c.uid, c.chain, c.managed, got, c.want)
		}
	}
	// The chain starts at this process's cgroup, then its parent's, unless the parent is pid 1, where it stops: a KVM
	// guest's suite binary is init's child (its chain held one entry, and the test required two), go test's is go's.
	chain := cgroupChain(os.Getpid())
	switch ppid := os.Getppid(); {
	case len(chain) == 0 || !bytes.Equal(chain[0], readFileT(t, "/proc/self/cgroup")):
		t.Errorf("cgroupChain of this test: %q", chain)
	case ppid <= 1 && len(chain) != 1:
		t.Errorf("cgroupChain went past pid 1: %q", chain)
	case ppid > 1 && (len(chain) < 2 || !bytes.Equal(chain[1], readFileT(t, fmt.Sprintf("/proc/%d/cgroup", ppid)))):
		t.Errorf("cgroupChain of this test lacks its parent %d's cgroup: %q", ppid, chain)
	}
	if ppid, ok := parentOf(os.Getpid()); !ok || ppid != os.Getppid() {
		t.Errorf("parentOf = %d %v, want %d", ppid, ok, os.Getppid())
	}
}

// The /proc/<pid>/cgroup files of `sudo tego agents` as the three guests showed them (acceptance 2B, 2026-11-11), this
// process first, then its ancestors: from an SSH login sudo keeps the login's session scope (Ubuntu 24.04, AlmaLinux
// 9.8 and Fedora 44 alike); from a systemd-run --user scope Ubuntu and AlmaLinux keep the scope, and Fedora 44's sudo
// opens a session of root's own (pam_systemd through system-auth) and moves sudo into it, with the shell in the scope.
var (
	sudoSSH     = []byte("0::/user.slice/user-1000.slice/session-14.scope\n")
	sudoScope   = []byte("0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p2090-i2091.scope\n")
	rootSession = []byte("0::/user.slice/user-0.slice/session-c3.scope\n")
	// tego, sudo's monitor and sudo in root's session; the shell in the scope; systemd-run's parent shell, sshd.
	fedoraSudoInScope = [][]byte{rootSession, rootSession, rootSession, sudoScope, sudoSSH, sudoSSH}
	fedoraSudoFromSSH = [][]byte{rootSession, rootSession, sudoSSH, sudoSSH}
)

// readFileT is path's content.
func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
