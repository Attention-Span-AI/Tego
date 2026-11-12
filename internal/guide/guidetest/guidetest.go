// SPDX-License-Identifier: Apache-2.0

// Package guidetest builds the fixture trees both callers of internal/guide test against: `tego setup`
// (internal/cli) and the dashboard's Overview guide (internal/control/web). Each tree is a home, a ledger root of real,
// anchored records, a user registry and a machine config, for one state a machine can be in; the same tree gives the
// same object on both surfaces (guide's TestParityFixtures, cli's TestSetupParityWithTheFiles).
//
// It is for tests only and is linked by no binary.
//
// Imports: the standard library, internal/guide, internal/ledger, pkg/spec/{config,identity,record}.
// Must not import: internal/cli, internal/control, internal/testutil (a non-test package may not).
package guidetest

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The machine every fixture describes: one boot and one build, a check made at CheckTime.
const (
	BootID = "6b1c2d3e-4f50-4a6b-8c7d-8e9fa0b1c2d3"
	Build  = "tego=v0.0.0-fixture commit=f1x7ure exe=1:2:3:4.000000000"
	// Version and Commit are the fixture build's, as Inputs carries them.
	Version = "v0.0.0-fixture"
	Commit  = "f1x7ure"
	// Kernel is the fixture host's kernel release.
	Kernel = "6.8.0-fixture"
	// PATH is the PATH every fixture compiles on.
	PATH = "/usr/bin:/bin"
	// Fix is the not-ready fixture's first fix.
	Fix = "start a shell in your user's cgroup first: systemd-run --user --scope bash"
	// OutsideFix is the outside fixture's first fix: doctor's D3 fix from a shell beside the user manager's cgroup.
	OutsideFix = "start tego from a shell in your user manager's cgroup: open one with systemd-run --user --scope bash, then run tego there"
)

// CheckTime is when every fixture's check was made.
var CheckTime = time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)

// The fixtures, by name, with the rule of internal/guide/next.go that picks each one's next step.
const (
	// Fresh: installed and checked; nothing recorded, no contract.
	Fresh = "fresh"
	// NotReady: the check found no tier from the place it ran.
	NotReady = "not-ready"
	// Outside: the check ran from a shell outside the user manager's cgroup (an SSH or console login), where no tier
	// runs only for that (guide.CauseOutsideUserManager); nothing recorded, no contract.
	Outside = "outside"
	// Recording: a tego watch run is still going.
	Recording = "recording"
	// HalfDone: a tego watch run in ~/bot ended; no contract yet.
	HalfDone = "half-done"
	// ContractMade: the watch run and a contract bot in the user registry that compiles; nothing enforced.
	ContractMade = "contract-made"
	// Finished: a run under bot ended and its record checks out.
	Finished = "finished"
	// Tampered: as Finished, with one byte of the enforced run's record changed.
	Tampered = "tampered"
	// HandWritten: a run under a contract given by its path ended; no recorded run and no registry entry.
	HandWritten = "hand-written"
)

// Names is every fixture, in the order a machine goes through them.
var Names = []string{Fresh, NotReady, Outside, Recording, HalfDone, ContractMade, Finished, Tampered, HandWritten}

// Fixture is one tree.
type Fixture struct {
	Name string
	// Root holds everything below; goldens write it as <root>.
	Root string
	// Home is the user's home; Project its agent's folder (~/bot), where a run was recorded.
	Home, Project string
	// Ledger, Anchor, Registry and Config are the ledger root, the chain anchor (~/.tego/chain.log), the user
	// registry (~/.config/tego) and the machine config file naming them.
	Ledger, Anchor, Registry, Config string
	// Probe is what doctor's probes said: the check `tego setup` stores. Where is the place it ran from.
	Probe guide.Check
	// Runs are the run ids written, oldest first.
	Runs []string
}

// contract is the registry's bot contract: it compiles wherever sh is on PATH.
const contract = "version: 0\nname: bot\ncommand: [\"sh\"]\ntier: landlock\nexec:\n  allow: [sh]\n"

// Make builds the fixture name under a new temporary folder. A run that is still going keeps its writer open until
// the test ends.
func Make(t testing.TB, name string) *Fixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A machine config layer in a folder others may write is skipped (spec/config/v0 Trust), and t.TempDir's folder
	// carries the umask.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	f := &Fixture{Name: name, Root: root, Home: home, Project: filepath.Join(home, "bot"),
		Ledger: filepath.Join(home, ".tego", "runs"), Anchor: filepath.Join(home, ".tego", ledger.ChainLogFile),
		Registry: filepath.Join(home, ".config", "tego"), Config: filepath.Join(root, "tego.yaml"),
		Probe: guide.Check{Where: guide.WhereUserManager, Build: Build, BootID: BootID, Tier: "landlock", Time: CheckTime}}
	for _, d := range []string{f.Project, f.Ledger, filepath.Join(f.Registry, "agents")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "ledger_root: " + f.Ledger + "\nregistry: " + f.Registry + "\n"
	if err := os.WriteFile(f.Config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	watch := record.RunStartPayload{Tier: "observe", Command: []string{"python3", "bot.py", "--loop"}, Cwd: f.Project}
	saved := filepath.Join(f.Registry, "agents", "bot.yaml")
	under := record.RunStartPayload{Tier: "landlock", Command: []string{"sh"}, Cwd: f.Project,
		ContractSource: &record.ContractSource{Path: saved, Name: "bot", Registry: "user"}}
	switch name {
	case Fresh:
	case NotReady:
		f.Probe.Tier, f.Probe.FirstFix, f.Probe.Where = "", Fix, guide.WhereShell
	case Outside:
		f.Probe.Tier, f.Probe.FirstFix, f.Probe.Where, f.Probe.Cause = "", OutsideFix, guide.WhereShell, guide.CauseOutsideUserManager
	case Recording:
		f.run(t, 0, watch, false)
	case HalfDone:
		f.run(t, 0, watch, true)
	case ContractMade:
		f.run(t, 0, watch, true)
		f.save(t, saved)
	case Finished, Tampered:
		f.run(t, 0, watch, true)
		f.save(t, saved)
		id := f.run(t, 1, under, true)
		if name == Tampered {
			events := filepath.Join(f.Ledger, id, ledger.EventsFile)
			b, err := os.ReadFile(events)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(events, bytes.Replace(b, []byte(`"sh"`), []byte(`"zz"`), 1), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	case HandWritten:
		path := filepath.Join(f.Project, "agent.yaml")
		under.ContractSource = &record.ContractSource{Path: path}
		f.run(t, 1, under, true)
	default:
		t.Fatalf("no fixture %q", name)
	}
	return f
}

// save writes the registry's bot contract.
func (f *Fixture) save(t testing.TB, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
}

// run writes the n-th run (its id minted n*10 minutes after CheckTime, with a random part fixed by n) from start, and
// ends it when ended; a run that does not end keeps its lock until the test ends.
func (f *Fixture) run(t testing.TB, n int, start record.RunStartPayload, ended bool) string {
	t.Helper()
	rid, err := identity.NewRunID(identity.HostID([]byte("fixture")), CheckTime.Add(time.Duration(n)*10*time.Minute),
		bytes.NewReader([]byte{0x5a, byte(0x10 + n), 0x3c, 0x77}))
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	start.TegoVersion, start.Kernel, start.ContractHash = Version, Kernel, strings.Repeat("0", 64)
	start.LauncherPID, start.LauncherStartNS, start.StopGrace, start.Capture = 1, 1, "1s", "off"
	w, err := ledger.Open(filepath.Join(f.Ledger, id), record.RunRef{ID: id, Agent: "bot"},
		ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	if ended {
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Cleanup(func() { _ = w.Abandon() })
	}
	f.Runs = append(f.Runs, id)
	return id
}

// Machine is the fixture's machine config, loaded from its file alone (no /etc layer, no user layer).
func (f *Fixture) Machine(t testing.TB) *config.Machine {
	t.Helper()
	m, ds, err := config.LoadSources(config.Sources{EnvFile: f.Config}, f.Home, os.Getuid(), config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) > 0 || m.LedgerRoot.Value != f.Ledger {
		t.Fatalf("the fixture's machine config was not read as written: %v, ledger root %s", ds, m.LedgerRoot.Value)
	}
	return m
}

// Inputs are the fixture's inputs from the stored files alone: no shell asks (As nil) and no check is made now (Fresh
// nil). Dir is the agent's folder, as `tego setup` run from it fills it; the dashboard, which has no working
// directory, sets Dir "" (guide's TestParityWithNoWorkingDirectory).
func (f *Fixture) Inputs(t testing.TB) guide.Inputs {
	t.Helper()
	return guide.Inputs{Machine: f.Machine(t), Home: f.Home, UID: os.Getuid(), LedgerRoot: f.Ledger, Anchor: f.Anchor,
		Dir: f.Project, Version: Version, Commit: Commit, Build: Build, Host: guide.Host{Kernel: Kernel, BootID: BootID},
		PATH: PATH}
}

// sha256Hex is a line id or hash in an error: a record's line ids hash its wall-clock times, which differ every run.
var sha256Hex = regexp.MustCompile(`\b[0-9a-f]{64}\b`)

// Normal is b with the fixture's root written as <root> and every SHA-256 in hex as <sha256>, for goldens.
func (f *Fixture) Normal(b []byte) []byte {
	return sha256Hex.ReplaceAll(bytes.ReplaceAll(b, []byte(f.Root), []byte("<root>")), []byte("<sha256>"))
}
