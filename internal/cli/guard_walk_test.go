// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// guardWithRealBoundary compiles actual R10 paths and owner state, stopping before
// backend selection and kernel resources. All passwd homes and groups are fixture facts.
func guardWithRealBoundary(t *testing.T, f *guardConfigFixture, grant string, owner int) (*guard, *int) {
	t.Helper()
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	// The selected layer can pass through an alias. Keep the contract outside that
	// alias so retargeting the layer does not also retarget its boundary.
	path := filepath.Join(filepath.Dir(f.home), "boundary.yaml")
	body := "version: 0\nname: current-placement\ncommand: [/bin/sh]\ncapture: off\nfs:\n  write: [" + fmt.Sprintf("%q", grant) + "]\nexec:\n  allow: [/bin/sh]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPrepare, oldEUID, oldGroups := adoptPrepare, adoptEUID, adoptGroupsOf
	adoptEUID = func() int { return 0 }
	adoptGroupsOf = func(int) ([]int, error) { return nil, nil }
	attempts := 0
	adoptPrepare = func(ctx context.Context, m *config.Machine, o adoptOptions, process adopt.Process, owner int, out io.Writer) (*preparedAdoption, int) {
		attempts++
		a := &preparedAdoption{m: m, owner: owner, boundary: true, cleanup: func() {}}
		rt, code := compileAdoptionTable(ctx, m, o, process, a, out)
		if rt == nil {
			a.cleanup()
			return nil, code
		}
		a.rt = rt
		return a, code
	}
	t.Cleanup(func() { adoptPrepare, adoptEUID, adoptGroupsOf = oldPrepare, oldEUID, oldGroups })
	m, ds, err := guardLoadMachine(config.TrustAbort)
	if err != nil {
		t.Fatalf("initial machine: %v %v", err, ds)
	}
	o := adoptOptions{boundary: path}
	var diagnostics strings.Builder
	a, code := adoptPrepare(t.Context(), m, o, adopt.Process{}, owner, &diagnostics)
	if a == nil || code != identity.ExitOK {
		t.Fatalf("ordinary initial boundary failed: exit=%d\n%s", code, diagnostics.String())
	}
	t.Cleanup(a.cleanup)
	root, err := ledgerRootOf(m)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := anchorPath(m)
	if err != nil {
		t.Fatal(err)
	}
	g := &guard{ctx: t.Context(), m: m, o: o, shared: map[int]*preparedAdoption{owner: a}, recordRoot: root, recordAnchor: anchor}
	if err := g.captureRecordLocations(); err != nil {
		t.Fatal(err)
	}
	return g, &attempts
}

func writeGuardWalkFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceGuardWalkLink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func TestGuardFreshLayerPlacement(t *testing.T) {
	for _, name := range []string{"unchanged regular", "same bytes replacement", "final alias safe", "final alias reaches grant", "ancestor alias safe", "ancestor alias reaches grant"} {
		t.Run(name, func(t *testing.T) {
			gcRoot(t)
			// These cases model another owner even when the runner itself has UID 1001.
			owner := os.Geteuid() + 1
			f := newGuardConfigFixture(t)
			f.write(t, "")
			data, err := os.ReadFile(f.layer)
			if err != nil {
				t.Fatal(err)
			}
			base := filepath.Dir(f.home)
			first, second, grant := filepath.Join(base, "first-config"), filepath.Join(base, "second-config"), filepath.Join(base, "write")
			for _, dir := range []string{first, second, grant} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			wantRefusal := strings.Contains(name, "reaches grant")
			if wantRefusal {
				second = grant
			}
			before, after := f.layer, f.layer
			link := ""
			if strings.HasPrefix(name, "final alias") {
				before, after = filepath.Join(first, "config.yaml"), filepath.Join(second, "config.yaml")
				writeGuardWalkFile(t, before, data)
				writeGuardWalkFile(t, after, data)
				replaceGuardWalkLink(t, f.layer, before)
				link = f.layer
			} else if strings.HasPrefix(name, "ancestor alias") {
				before, after = filepath.Join(first, "config.yaml"), filepath.Join(second, "config.yaml")
				writeGuardWalkFile(t, before, data)
				writeGuardWalkFile(t, after, data)
				link = filepath.Join(base, "selected")
				if err := os.Symlink(first, link); err != nil {
					t.Fatal(err)
				}
				f.layer, f.sources.User = link+"/config.yaml", link+"/config.yaml"
			}
			g, attempts := guardWithRealBoundary(t, f, grant, owner)
			initial := g.shared[owner]
			switch name {
			case "same bytes replacement":
				replacement := f.layer + ".new"
				writeGuardWalkFile(t, replacement, data)
				if err := os.Rename(replacement, f.layer); err != nil {
					t.Fatal(err)
				}
			default:
				if link != "" {
					target := after
					if strings.HasPrefix(name, "ancestor alias") {
						target = second
					}
					replaceGuardWalkLink(t, link, target)
				}
			}
			current, ds, err := config.LoadSources(f.sources, f.home, os.Getuid(), config.TrustAbort)
			if err != nil || !slices.Equal(current.LayerSources(), initial.m.LayerSources()) {
				t.Fatalf("placement fixture must remain trusted with identical paths and bytes: %v %v", err, ds)
			}
			if !slices.Contains(initial.rt.OwnReadable, before) {
				t.Fatalf("initial real compiler did not retain its layer target %s", before)
			}
			got, err := g.prepareAdoption(adopt.Process{}, owner)
			if wantRefusal {
				if got != nil || err == nil || !strings.Contains(err.Error(), "machine config") || !strings.Contains(err.Error(), "fs.write") || *attempts != 2 {
					t.Fatalf("retargeted layer borrowed a table allowing its write grant: table=%t attempts=%d err=%v", got != nil, *attempts, err)
				}
				return
			}
			if err != nil || got == nil || got == initial || *attempts != 2 || !slices.Contains(got.rt.OwnReadable, after) {
				t.Fatalf("ordinary current layer was not compiled afresh: table=%t attempts=%d err=%v", got != nil, *attempts, err)
			}
			defer got.cleanup()
			if !slices.Contains(initial.rt.OwnReadable, before) || g.shared[owner] != initial {
				t.Fatal("fresh placement changed an earlier table")
			}
		})
	}
}

func TestGuardFreshOwnerPlacement(t *testing.T) {
	for _, name := range []string{"missing home alias safe", "missing home alias reaches grant", "nonowner home alias safe", "nonowner home alias reaches grant", "home mode changes"} {
		t.Run(name, func(t *testing.T) {
			gcRoot(t)
			// These cases model another owner even when the runner itself has UID 1001.
			owner := os.Geteuid() + 1
			f := newGuardConfigFixture(t)
			f.write(t, "")
			base := filepath.Dir(f.home)
			grant := filepath.Join(base, "write")
			if err := os.Mkdir(grant, 0o700); err != nil {
				t.Fatal(err)
			}
			first, second := filepath.Join(base, "first-owner"), filepath.Join(base, "second-owner")
			wantRefusal := strings.Contains(name, "reaches grant")
			if wantRefusal {
				second = filepath.Join(grant, "new-owner")
			}
			if strings.HasPrefix(name, "nonowner") {
				for _, dir := range []string{first, second} {
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			alias := filepath.Join(base, "owner-alias")
			if name != "home mode changes" {
				if err := os.Symlink(first, alias); err != nil {
					t.Fatal(err)
				}
				f.ownerHome = alias
			}
			g, attempts := guardWithRealBoundary(t, f, grant, owner)
			initial := g.shared[owner]
			if name == "home mode changes" {
				if err := os.Chmod(f.ownerHome, 0o750); err != nil {
					t.Fatal(err)
				}
			} else {
				if strings.HasPrefix(name, "nonowner") {
					if !initial.homeNotOwners || initial.homeMissing {
						t.Fatal("fixture must use an existing home owned by a different uid")
					}
				} else if !initial.homeMissing {
					t.Fatal("fixture must leave the owner's home absent without making it")
				}
				replaceGuardWalkLink(t, alias, second)
				if initial.stale() {
					t.Fatal("fixture must bypass the former records-only cache check")
				}
			}
			got, err := g.prepareAdoption(adopt.Process{}, owner)
			if wantRefusal {
				if got != nil || err == nil || !strings.Contains(err.Error(), "machine config") || *attempts != 2 {
					t.Fatalf("owner alias borrowed a table allowing its next user layer: table=%t attempts=%d err=%v", got != nil, *attempts, err)
				}
				return
			}
			if err != nil || got == nil || got == initial || *attempts != 2 || got.home != initial.home {
				t.Fatalf("ordinary stable owner spelling was not compiled afresh: table=%t attempts=%d err=%v", got != nil, *attempts, err)
			}
			defer got.cleanup()
			if name != "home mode changes" && !slices.Contains(got.rt.OwnReadable, second+"/.tego/config.yaml") {
				t.Fatal("new owner layer placement is absent from the current table")
			}
		})
	}
}

func TestGuardFreshBoundaryRejectsUnknownOwner(t *testing.T) {
	f := newGuardConfigFixture(t)
	f.write(t, "")
	g, prepares := guardWithConfigFixture(t)
	if a, err := g.prepareAdoption(adopt.Process{}, 1001); a != nil || err == nil || !strings.Contains(err.Error(), "uid 1001") || *prepares != 1 {
		t.Fatalf("owner without a startup preflight admitted: table=%t err=%v prepares=%d", a != nil, err, *prepares)
	}
}

func TestGuardFreshBoundaryCleanup(t *testing.T) {
	p := terminalProcs()
	p.add(510, 300, "/usr/bin/claude", "/user.slice/user-1000.slice/session-2.scope", 1000)
	calls := sandboxAdopt(t, p, true)
	var mu sync.Mutex
	prepared, cleaned := 0, map[int]int{}
	adoptPrepare = func(_ context.Context, m *config.Machine, _ adoptOptions, _ adopt.Process, owner int, _ io.Writer) (*preparedAdoption, int) {
		mu.Lock()
		prepared++
		generation := prepared
		mu.Unlock()
		return &preparedAdoption{m: m, owner: owner, boundary: true,
			rt:      &agent.RuleTable{Contract: &agent.Contract{Name: fmt.Sprint(generation)}, Tier: backend.TierCgroup},
			cleanup: func() { mu.Lock(); cleaned[generation]++; mu.Unlock() }}, identity.ExitOK
	}
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGuard(t.Context(), m, []int{1000}, adoptOptions{boundary: "boundary.yaml"}, func(watcher.Sighting) error { return nil }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			g.wait()
		}
	}()
	outside := true
	for i, pid := range []int32{500, 510} {
		g.observe(watcher.Sighting{Event: watcher.EventAgentStarted, PID: pid, OutsideGovernedRun: &outside, Exe: "/usr/bin/claude"})
		g.wg.Wait()
		mu.Lock()
		count := cleaned[i+2]
		mu.Unlock()
		if count != 1 {
			t.Fatalf("ended adoption %d left its fresh preparation uncleared: cleanup calls=%d", pid, count)
		}
	}
	mu.Lock()
	if prepared != 3 || cleaned[1] != 0 || len(cleaned) != 2 {
		t.Errorf("preflight/per-adoption lifetime mismatch: prepared=%d cleaned=%v", prepared, cleaned)
	}
	mu.Unlock()
	if len(calls.roots()) != 2 || len(g.shared) != 1 {
		t.Fatal("fresh preparations accumulated in the guard")
	}
	g.wait()
	waited = true
	mu.Lock()
	defer mu.Unlock()
	if cleaned[1] != 1 || cleaned[2] != 1 || cleaned[3] != 1 {
		t.Fatalf("cleanup did not occur once per preparation: %v", cleaned)
	}
}
