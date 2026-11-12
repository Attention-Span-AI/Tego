// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fixedClock always reports the same instant: paired with a fixed Rand source it makes
// identity.NewRunID deterministic, which is what lets this file plant something at the exact path
// mintRun is about to create (docs/p0/runtime-launch.md §6 case 1).
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
func (c fixedClock) MonoNS() uint64 { return 1 }

// TestMintRunNeverReusesAnOccupiedPath pins §6 cases 1 and 16 together, because mintRun enforces
// both the same way: os.Mkdir on a path that already exists, of any kind.
//
// Case 1: "a random-suffix collision (astronomically unlikely) hits mkdir EEXIST, exit 125, never
// overwritten." Case 16: "Symlink at the run-directory path (never legitimately pre-exists):
// treated as EEXIST-equivalent corruption like case 1 — refused, exit 125, never followed."
//
// Both matter for the same reason: the run directory is the only record of an agent's run, and
// "never overwritten" is the whole guarantee — a run that silently reused an existing path could
// splice one run's ledger into another's or, for the symlink case, write into a location the
// contract never declared. mkdir(2) refusing to walk into an existing dirent (symlink or not) is
// what mintRun leans on; this test proves the facade actually surfaces that refusal as an error and
// touches nothing at the occupied path, rather than e.g. falling back to some other mkdir call that
// would follow the link or clear the directory first.
//
// Also pins runtime-launch.md E1, E16, E35: an occupied run path, a symlink included, is refused; the id is
// never trusted for uniqueness.
func TestMintRunNeverReusesAnOccupiedPath(t *testing.T) {
	clk := fixedClock{at: time.Unix(1_700_000_000, 0)}
	randBytes := []byte{0xAB, 0xCD, 0xEF, 0x01}
	machineID := []byte("mintrun-test-machine")

	// The exact id mintRun will compute from these fixed inputs, so the test can plant an occupant
	// at that precise path before calling it.
	wantID, err := identity.NewRunID(hostID(machineID), clk.Now(), bytes.NewReader(randBytes))
	if err != nil {
		t.Fatalf("NewRunID: %v", err)
	}

	tests := []struct {
		name string
		// plant creates whatever already occupies the run directory's path.
		plant func(t *testing.T, path string)
		// verify checks the occupant survived mintRun's refusal untouched.
		verify func(t *testing.T, path string)
	}{
		{
			name: "a directory left by an earlier run",
			plant: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "sentinel"),
					[]byte("earlier run's record"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, path string) {
				got, err := os.ReadFile(filepath.Join(path, "sentinel"))
				if err != nil || string(got) != "earlier run's record" {
					t.Fatalf("the earlier run's content was disturbed: %q err=%v", got, err)
				}
			},
		},
		{
			name: "a symlink planted at the path",
			plant: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(path), "elsewhere")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, path string) {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatalf("the symlink itself was removed: %v", err)
				}
				if info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("the path is no longer a symlink: mintRun replaced it")
				}
				target, err := os.Readlink(path)
				if err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(target)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("mintRun followed the symlink and wrote into its target: %v", entries)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := identity.RunDir(root, wantID)
			tc.plant(t, path)

			m := config.Builtin()
			m.LedgerRoot = config.Setting[string]{Value: root}
			rt := &agent.RuleTable{Contract: &agent.Contract{Name: "mint-collision"}}
			deps := Deps{
				Config: m, Enforce: &fakeBackend{}, Clock: clk,
				Rand: bytes.NewReader(bytes.Repeat(randBytes, mintRunAttempts)), MachineID: machineID,
			}
			r, err := newRunner(rt, []string{"/bin/true"}, deps)
			if err != nil {
				t.Fatalf("newRunner: %v", err)
			}

			mintErr := r.mintRun()
			if mintErr == nil {
				t.Fatal("mintRun must refuse an occupied path instead of reusing it")
			}
			if !errors.Is(mintErr, os.ErrExist) {
				t.Fatalf("mintRun err = %v, want an EEXIST-class error", mintErr)
			}
			tc.verify(t, path)
		})
	}
}

// TestMintRunRetriesATakenPath pins identity-config.md R2b: when mkdir(runs/<id>) finds the path taken
// (EEXIST), mintRun mints another id from a fresh read of the random source, up to three retries, and fails
// with the EEXIST error only when all four ids are taken. The taken paths are left as they were, and the
// random source is read no further than the attempt that succeeded or the last one.
//
// Also pins runtime-launch.md E1: a taken path mints a fresh id, up to the retry bound.
func TestMintRunRetriesATakenPath(t *testing.T) {
	clk := fixedClock{at: time.Unix(1_700_000_000, 0)}
	machineID := []byte("mintrun-retry-machine")
	// Five distinct 4-byte draws, each a distinct id (they differ in their high bytes, which R1 keeps).
	draws := [][]byte{{0x10, 0, 0, 0}, {0x20, 0, 0, 0}, {0x30, 0, 0, 0}, {0x40, 0, 0, 0}, {0x50, 0, 0, 0}}
	ids := make([]identity.RunID, len(draws))
	for i, d := range draws {
		id, err := identity.NewRunID(hostID(machineID), clk.Now(), bytes.NewReader(d))
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	for _, tc := range []struct {
		name    string
		taken   int // how many of the first ids are already taken
		wantErr bool
	}{
		{"one collision, the second id is used", 1, false},
		{"three collisions, the fourth id is used", 3, false},
		{"four collisions fail with EEXIST", 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for i := 0; i < tc.taken; i++ {
				if err := os.Mkdir(identity.RunDir(root, ids[i]), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			m := config.Builtin()
			m.LedgerRoot = config.Setting[string]{Value: root}
			rt := &agent.RuleTable{Contract: &agent.Contract{Name: "mint-retry"}}
			rnd := bytes.NewReader(bytes.Join(draws, nil))
			r, err := newRunner(rt, []string{"/bin/true"}, Deps{
				Config: m, Enforce: &fakeBackend{}, Clock: clk, Rand: rnd, MachineID: machineID,
			})
			if err != nil {
				t.Fatalf("newRunner: %v", err)
			}
			err = r.mintRun()
			if tc.wantErr {
				if !errors.Is(err, os.ErrExist) {
					t.Fatalf("mintRun err = %v, want EEXIST after %d attempts", err, mintRunAttempts)
				}
				if rnd.Len() != 4 {
					t.Fatalf("%d random bytes left, want exactly the fifth draw: %d attempts, no more",
						rnd.Len(), mintRunAttempts)
				}
			} else {
				if err != nil {
					t.Fatalf("mintRun: %v", err)
				}
				if r.id != ids[tc.taken] {
					t.Fatalf("run id = %s, want the first free one %s", r.id, ids[tc.taken])
				}
				if fi, err := os.Stat(r.dir); err != nil || !fi.IsDir() {
					t.Fatalf("run dir %s not created: %v", r.dir, err)
				}
			}
			for i := 0; i < tc.taken; i++ {
				entries, err := os.ReadDir(identity.RunDir(root, ids[i]))
				if err != nil || len(entries) != 0 {
					t.Fatalf("taken path %d disturbed: %v %v", i, entries, err)
				}
			}
		})
	}
}

// TestMintRunRefusesAnUnreadableLauncherStartTime: a launcher whose /proc/self/stat cannot be read used to run
// on and write "<pid> 0" to its lock file, which OpenStopTarget reads as "skip the pid-reuse check". It is
// refused before any run directory is made.
func TestMintRunRefusesAnUnreadableLauncherStartTime(t *testing.T) {
	prev := launcherStartBootNS
	launcherStartBootNS = func(int) (uint64, error) { return 0, errors.New("EMFILE") }
	t.Cleanup(func() { launcherStartBootNS = prev })

	root := t.TempDir()
	m := config.Builtin()
	m.LedgerRoot = config.Setting[string]{Value: root}
	rt := &agent.RuleTable{Contract: &agent.Contract{Name: "no-start"}}
	deps := Deps{Config: m, Enforce: &fakeBackend{}, Clock: fixedClock{at: time.Unix(1_700_000_000, 0)},
		Rand: bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4}, mintRunAttempts)), MachineID: []byte("m")}
	r, err := newRunner(rt, []string{"/bin/true"}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.mintRun(); err == nil {
		t.Fatal("mintRun accepted a launcher with no readable start time")
	}
	entries, _ := os.ReadDir(filepath.Join(root, "runs"))
	if len(entries) != 0 {
		t.Fatalf("a run directory was made before the refusal: %v", entries)
	}
}
