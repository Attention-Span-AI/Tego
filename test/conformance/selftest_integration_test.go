// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The suite's self-test against the real kernel (ADR 0017, amended 2026-10-19; A-0017-3): a contract that grants
// more than the model beside it drives the unchanged product into exactly the fail-open shape the invariants exist
// to catch, and the axis report must hold it. It needs no mutated build: a test-hook that forced a decision open
// would be a fail-open switch inside the trusted code, even behind a build tag (plan decision D3).

// mutatedContracts are the self-test's fixtures. Each cell is generated (the kernel judges it) and acts where the
// contract grants and the model refuses.
func mutatedContracts() []Fixture {
	write := Fixture{
		Name: "selftest-write-widened",
		// The contract grants out/ and w/; the model says out/ only.
		Contract: "version: 0\nname: conformance-selftest\ncommand: [\"{{P}}/bin/actor\", \"run\", \"{{P}}/script.json\"]\n" +
			"fs:\n  write: [\"./out/\", \"./w/\"]\nexec:\n  allow: [\"{{P}}/bin/actor\"]\nnet:\n  allow: []\n" + footer,
		Dirs:  []string{"out"},
		Files: map[string]string{"w/notes.txt": "x"},
		Model: Model{Write: []string{"out"}, ExecAllow: []string{"bin/actor"}, NetDeclared: true},
		Cells: []Cell{{Name: "write-open-outside-the-model", Op: OpWriteOpen, Path: "w/notes.txt", Generated: true,
			Source: "ADR 0017 (c): no write succeeds outside the write entries"}},
	}
	exec := Fixture{
		Name: "selftest-exec-widened",
		// The contract allows every image under t/; the model allows the actor alone.
		Contract: "version: 0\nname: conformance-selftest\ncommand: [\"{{P}}/bin/actor\", \"run\", \"{{P}}/script.json\"]\n" +
			"fs:\n  write: [\"./out/\"]\nexec:\n  allow: [\"{{P}}/bin/actor\", \"{{P}}/t/\"]\nnet:\n  allow: []\n" + footer,
		Dirs:   []string{"out"},
		Actors: []string{"t/tool"},
		Model:  Model{Write: []string{"out"}, ExecAllow: []string{"bin/actor"}, NetDeclared: true},
		Cells: []Cell{{Name: "exec-outside-the-model", Op: OpExec, Path: "t/tool", Generated: true,
			Source: "ADR 0017 (c): no exec of a file outside exec.allow succeeds"}},
	}
	// The write mutation again, as a handwritten cell that asks nothing of the self-test's axes (Cell.Unasked): the
	// invariants still bind there, so the fail-open is caught on a column the cell leaves unasked.
	unasked := write
	unasked.Name = "selftest-write-widened-unasked"
	unasked.Cells = []Cell{{Name: "write-open-unasked", Op: OpWriteOpen, Path: "w/notes.txt",
		Want:      map[Key]Want{{TierCgroup, ModeFanotify}: {Verdict: Refused}},
		Unasked:   map[Key]string{{TierLandlock, ModeNone}: "the self-test's", {TierBPFLSM, ModeLSM}: "the self-test's"},
		NoCompile: "the self-test asks the kernel alone",
		Source:    "Cell.Unasked: an unasked column is still judged by the invariants"}}
	return []Fixture{write, exec, unasked}
}

// TestJudgeCatchesAMutatedContract runs each mutated contract for real and requires the axis report to hold the
// fail-open on the cell, with nothing else wrong: on the tier landlock axis always (without root as the caller),
// and as root on one plane axis, cgroup in mode lsm where the machine selects it, else fmod_ret.
func TestJudgeCatchesAMutatedContract(t *testing.T) {
	root := os.Geteuid() == 0
	uid, gid := -1, -1
	if root {
		var ok bool
		if uid, gid, ok = sudoIDs(); !ok {
			t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
		}
	}
	actor := buildActor(t)
	tags := []string{}
	if root {
		tags = append(tags, "tegobpf")
	}
	bin, err := buildTego(t.TempDir(), tags...)
	if err != nil {
		t.Fatal(err)
	}
	doctorEnv := machineConfig(t, &env{base: t.TempDir()})
	if out, err := doctor(bin, doctorEnv, "--require", "landlock").CombinedOutput(); err != nil {
		if root || AxisRequired(os.Getenv(RequireEnv), string(TierLandlock)) {
			t.Fatalf("tego doctor --require landlock: %v\n%s", err, out)
		}
		t.Skipf("this machine offers no tier landlock (tego doctor --require landlock: %v):\n%s", err, out)
	}
	axes := []axis{{tier: TierLandlock, want: Key{TierLandlock, ModeNone}, invariant: TierLandlock, label: TierLandlock}}
	if root {
		for _, m := range []Mode{ModeLSM, ModeFmodRet} {
			if planeSelected(bin, doctorEnv, string(m)) == string(m) {
				axes = append(axes, planeAxis(m))
				break
			}
		}
		if len(axes) == 1 {
			if AxisRequired(os.Getenv(RequireEnv), string(ModeFmodRet)) || AxisRequired(os.Getenv(RequireEnv), string(ModeLSM)) {
				t.Fatalf("%s names a plane mode but doctor selects neither lsm nor fmod_ret", RequireEnv)
			}
			t.Log("no plane mode is selectable here: the self-test runs the tier landlock axis alone")
		}
	}
	if _, err := sys.LandlockABI(); err != nil {
		t.Fatal(err)
	}
	machine, err := CurrentMachine()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := mutatedContracts()
	gen := generatedColumns(t, bin, actor, fixtures)
	for _, ax := range axes {
		for i := range fixtures {
			fx := &fixtures[i]
			t.Run(fmt.Sprintf("%s/%s", ax.label, fx.Name), func(t *testing.T) {
				rep := runFixture(t, bin, actor, uid, gid, fx, ax, machine, gen[fx.Name])
				id := fx.ID(&fx.Cells[0])
				caught := false
				for _, f := range rep.FailOpens {
					caught = caught || strings.HasPrefix(f, id+" at "+string(ax.label)+": ")
				}
				if !caught || len(rep.FailOpens) != 1 || len(rep.Effects) != 0 || len(rep.Problems) != 0 {
					t.Errorf("the axis report does not hold exactly the mutated contract's fail-open on %s:\nfail-opens %q\neffects %q\nproblems %q",
						id, rep.FailOpens, rep.Effects, rep.Problems)
				}
				t.Logf("SELFTEST %s at %s: caught %q", id, ax.label, rep.FailOpens)
			})
		}
	}
}
