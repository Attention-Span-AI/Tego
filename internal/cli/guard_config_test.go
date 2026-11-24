// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

type guardConfigFixture struct {
	home, layer, root, first, second string
	ownerHome                        string
	ownerErr                         error
	sources                          config.Sources
	loads                            int
}

func newGuardConfigFixture(t *testing.T) *guardConfigFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := &guardConfigFixture{home: filepath.Join(dir, "home"), layer: filepath.Join(dir, "config.yaml"),
		first: filepath.Join(dir, "first"), second: filepath.Join(dir, "second")}
	f.root = filepath.Join(f.home, ".tego", "runs")
	f.ownerHome = filepath.Join(dir, "owner-home")
	f.sources.User = f.layer
	if err := os.Mkdir(f.home, 0o700); err != nil {
		t.Fatal(err)
	}
	makeGuardOwnerHome(t, f.ownerHome)
	for _, path := range []string{f.first, f.second} {
		if err := os.WriteFile(path, []byte("baseline target fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old, oldHome := guardLoadMachine, adoptHomeOf
	guardLoadMachine = func(mode config.TrustMode) (*config.Machine, []config.Diagnostic, error) {
		if mode != config.TrustAbort {
			t.Errorf("fresh adoption loaded with trust mode %v", mode)
		}
		f.loads++
		return config.LoadSources(f.sources, f.home, os.Getuid(), mode)
	}
	adoptHomeOf = func(int) (string, error) { return f.ownerHome, f.ownerErr }
	t.Cleanup(func() { guardLoadMachine, adoptHomeOf = old, oldHome })
	return f
}

func makeGuardOwnerHome(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "floor"), []byte("owner baseline target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *guardConfigFixture) write(t *testing.T, baseline string) {
	t.Helper()
	text := "ledger_root: " + f.root + "\n"
	if baseline != "" {
		text += "baseline: {fs: {deny_write: [" + baseline + "]}}\n"
	}
	if err := os.WriteFile(f.layer, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func guardConfigBaseline(t *testing.T, m *config.Machine) string {
	t.Helper()
	b, known := m.BaselineSnapshot()
	if !known {
		t.Fatal("test received an unknown machine snapshot")
	}
	entries := b.Entries()
	if len(entries) == 0 {
		return ""
	}
	if len(entries) != 1 {
		t.Fatalf("test expected at most one baseline entry: %v", entries)
	}
	return entries[0].Value
}

func guardWithConfigFixture(t *testing.T) (*guard, *int) {
	t.Helper()
	m, ds, err := guardLoadMachine(config.TrustAbort)
	if err != nil {
		t.Fatalf("initial machine: %v %v", err, ds)
	}
	prepares := 0
	old := adoptPrepare
	adoptPrepare = func(_ context.Context, m *config.Machine, o adoptOptions, _ adopt.Process, owner int, out io.Writer) (*preparedAdoption, int) {
		home, err := adoptHomeOf(owner)
		if err != nil || home == "" {
			fmt.Fprintf(out, "uid %d has no passwd home: %v", owner, err)
			return nil, identity.ExitLauncher
		}
		baseline, _ := m.BaselineSnapshot()
		resolved, err := baseline.Resolve(config.BaselineOwner{UID: owner, Home: home})
		if err != nil {
			fmt.Fprint(out, err)
			return nil, identity.ExitLauncher
		}
		rt := &agent.RuleTable{Contract: &agent.Contract{Name: fmt.Sprintf("generation-%d", prepares+1)}}
		if len(resolved.Entries) > 0 {
			rt.Baseline = &agent.BaselineTable{Owner: resolved.Owner, Applied: o.boundary != ""}
			for _, entry := range resolved.Entries {
				rt.Baseline.Entries = append(rt.Baseline.Entries, agent.BaselineRule{ResolvedBaselineEntry: entry})
			}
		}
		prepares++
		records, _ := ownRecordsDir(home)
		return &preparedAdoption{m: m, owner: owner, home: home, records: records, boundary: o.boundary != "", cleanup: func() {}, rt: rt}, identity.ExitOK
	}
	t.Cleanup(func() { adoptPrepare = old })
	o := adoptOptions{boundary: "boundary.yaml"}
	a, code := adoptPrepare(t.Context(), m, o, adopt.Process{}, 1000, io.Discard)
	if a == nil || code != identity.ExitOK {
		t.Fatalf("initial adoption fixture: table=%t code=%d", a != nil, code)
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := anchorPath(m)
	if err != nil {
		t.Fatal(err)
	}
	g := &guard{ctx: t.Context(), m: m, o: o, shared: map[int]*preparedAdoption{1000: a}, recordRoot: root, recordAnchor: anchor}
	if err := g.captureRecordLocations(); err != nil {
		t.Fatal(err)
	}
	return g, &prepares
}

func TestGuardFreshMachineLayerMatrix(t *testing.T) {
	for _, name := range []string{"unchanged", "metadata only", "absent becomes present", "empty becomes baseline", "nonempty baseline changes", "selected layer deleted", "ordinary empty layer edit", "trusted alternate spelling", "home absent at guard startup", "invoking home unavailable"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			if name != "absent becomes present" {
				baseline := ""
				if name == "nonempty baseline changes" || name == "selected layer deleted" {
					baseline = f.first
				}
				f.write(t, baseline)
			}
			if name == "home absent at guard startup" || name == "invoking home unavailable" {
				oldAnchor := anchorPath
				anchorPath = tegoruntime.AnchorPath
				t.Cleanup(func() { anchorPath = oldAnchor })
				switch name {
				case "home absent at guard startup":
					if err := os.Remove(f.home); err != nil {
						t.Fatal(err)
					}
				case "invoking home unavailable":
					f.home = ""
					f.sources.User, f.sources.EnvFile = "", f.layer
				}
			}
			g, prepares := guardWithConfigFixture(t)
			initial := g.shared[1000]
			wantBaseline := ""
			switch name {
			case "unchanged", "home absent at guard startup", "invoking home unavailable":
			case "metadata only":
				at := time.Unix(1_700_000_000, 0)
				if err := os.Chtimes(f.layer, at, at); err != nil {
					t.Fatal(err)
				}
			case "absent becomes present", "empty becomes baseline":
				f.write(t, f.first)
				wantBaseline = f.first
			case "nonempty baseline changes":
				f.write(t, f.second)
				wantBaseline = f.second
			case "selected layer deleted":
				if err := os.Remove(f.layer); err != nil {
					t.Fatal(err)
				}
			case "ordinary empty layer edit":
				if err := os.WriteFile(f.layer, []byte("# ordinary config edit\nledger_root: "+f.root+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "trusted alternate spelling":
				dir := filepath.Join(filepath.Dir(f.layer), "existing")
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				f.sources.User = dir + "/../config.yaml"
			}
			got, err := g.prepareAdoption(adopt.Process{}, 1000)
			if err != nil || got == nil {
				t.Fatalf("ordinary current config refused: %v", err)
			}
			defer got.cleanup()
			if got == initial || guardConfigBaseline(t, got.m) != wantBaseline {
				t.Fatalf("stale/current table mismatch: new=%t baseline=%q want=%q", got != initial, guardConfigBaseline(t, got.m), wantBaseline)
			}
			again, err := g.prepareAdoption(adopt.Process{}, 1000)
			if err != nil || again == got || *prepares != 3 || f.loads != 3 {
				t.Fatalf("each adoption must reload and compile its own table: err=%v loads=%d prepares=%d", err, f.loads, *prepares)
			}
			defer again.cleanup()
			if initial.m != g.m || g.shared[1000] != initial {
				t.Fatal("refresh changed an already running adoption's snapshot")
			}
		})
	}
}

func TestGuardFreshMachineNeverFallsBack(t *testing.T) {
	for _, name := range []string{"untrusted later", "malformed later", "fresh boundary rejected", "loader returned unknown"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			f.write(t, "")
			g, prepares := guardWithConfigFixture(t)
			initial := g.shared[1000]
			want := f.layer
			switch name {
			case "untrusted later":
				if err := os.Chmod(f.layer, 0o666); err != nil {
					t.Fatal(err)
				}
			case "malformed later":
				if err := os.WriteFile(f.layer, []byte("baseline: [bad-schema]\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "fresh boundary rejected":
				f.write(t, f.first)
				adoptPrepare = func(_ context.Context, _ *config.Machine, _ adoptOptions, _ adopt.Process, _ int, out io.Writer) (*preparedAdoption, int) {
					fmt.Fprintf(out, "%s: baseline refusal cannot hold this boundary", f.layer)
					return nil, identity.ExitLauncher
				}
			case "loader returned unknown":
				if err := os.Chmod(f.layer, 0o666); err != nil {
					t.Fatal(err)
				}
				guardLoadMachine = func(mode config.TrustMode) (*config.Machine, []config.Diagnostic, error) {
					if mode != config.TrustAbort {
						t.Errorf("fresh adoption used %v", mode)
					}
					return config.LoadSources(f.sources, f.home, os.Getuid(), config.TrustWarn)
				}
			}
			got, err := g.prepareAdoption(adopt.Process{}, 1000)
			if got != nil || err == nil || !strings.Contains(err.Error(), want) || g.shared[1000] != initial || *prepares != 1 {
				t.Fatalf("failed current decision borrowed cached permissions: table=%t err=%v prepares=%d", got != nil, err, *prepares)
			}
		})
	}
}

func TestGuardFreshMachineKeepsRecordingOnlyContext(t *testing.T) {
	f := newGuardConfigFixture(t)
	f.write(t, "")
	g, prepares := guardWithConfigFixture(t)
	g.shared, g.o.boundary = nil, ""
	f.write(t, f.first)
	got, err := g.prepareAdoption(adopt.Process{}, 1000)
	if err != nil || got == nil || guardConfigBaseline(t, got.m) != f.first || got.rt.Baseline.Applied || *prepares != 2 {
		t.Fatalf("record-only route used startup config: err=%v prepares=%d", err, *prepares)
	}
}

func TestGuardFreshMachinePreservesRecordLocation(t *testing.T) {
	for _, name := range []string{"ledger", "anchor", "anchor home disappears", "ledger home disappears"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			if name == "anchor home disappears" {
				// An external ledger makes the no-home fallback differ from the
				// startup home anchor. The default ledger resolves to the same file.
				f.root = filepath.Join(filepath.Dir(f.home), "external-ledger")
			}
			f.write(t, "")
			oldAnchor := anchorPath
			anchorPath = tegoruntime.AnchorPath
			t.Cleanup(func() { anchorPath = oldAnchor })
			g, prepares := guardWithConfigFixture(t)
			switch name {
			case "ledger":
				f.root = filepath.Join(filepath.Dir(f.home), "different-ledger")
				f.write(t, "")
			case "anchor home disappears", "ledger home disappears":
				if err := os.Remove(f.home); err != nil {
					t.Fatal(err)
				}
			default:
				f.home = filepath.Join(filepath.Dir(f.home), "different-home")
				if err := os.Mkdir(f.home, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			got, err := g.prepareAdoption(adopt.Process{}, 1000)
			if got != nil || err == nil || !strings.Contains(err.Error(), strings.Fields(name)[0]) || !strings.Contains(err.Error(), "restart") || *prepares != 1 {
				t.Fatalf("changed %s silently redirected adoption records: table=%t err=%v prepares=%d", name, got != nil, err, *prepares)
			}
		})
	}
}

func TestGuardFreshOwnerHome(t *testing.T) {
	for _, name := range []string{"unchanged", "moved home", "trusted home alias", "missing owner lookup", "empty owner home"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			f.write(t, "~/floor")
			g, prepares := guardWithConfigFixture(t)
			initial := g.shared[1000]
			startupHome := initial.home
			wantError := false
			switch name {
			case "unchanged":
			case "moved home":
				f.ownerHome = filepath.Join(filepath.Dir(f.ownerHome), "new-owner-home")
				makeGuardOwnerHome(t, f.ownerHome)
			case "trusted home alias":
				alias := filepath.Join(filepath.Dir(f.ownerHome), "owner-alias")
				if err := os.Symlink(f.ownerHome, alias); err != nil {
					t.Fatal(err)
				}
				f.ownerHome = alias
			case "missing owner lookup":
				f.ownerErr = fmt.Errorf("passwd lookup for uid 1000 failed")
				wantError = true
			case "empty owner home":
				f.ownerHome = ""
				// PasswdHome returns this error when its real entry has no home.
				f.ownerErr = fmt.Errorf("the passwd database names no home directory for uid 1000")
				wantError = true
			}
			got, err := g.prepareAdoption(adopt.Process{}, 1000)
			if wantError {
				if got != nil || err == nil || !strings.Contains(err.Error(), "uid 1000") || !strings.Contains(err.Error(), "home") || g.shared[1000] != initial || *prepares != 1 {
					t.Fatalf("unavailable owner context reused old permissions: table=%t err=%v prepares=%d", got != nil, err, *prepares)
				}
				return
			}
			if err != nil || got == nil {
				t.Fatalf("ordinary owner context refused: %v", err)
			}
			defer got.cleanup()
			if got == initial || got.home != f.ownerHome || got.rt.Baseline.Owner.Home != f.ownerHome || got.rt.Baseline.Entries[0].Expanded != f.ownerHome+"/floor" {
				t.Fatalf("owner's ~/ baseline was not refreshed: new=%t home=%q baseline=%+v", got != initial, got.home, got.rt.Baseline)
			}
			if initial.home != startupHome || initial.rt.Baseline.Entries[0].Expanded != startupHome+"/floor" {
				t.Fatal("owner lookup changed an already running adoption's snapshot")
			}
		})
	}
}
