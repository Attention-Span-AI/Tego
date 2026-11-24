// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
)

func TestGuardRecordLocationPlacementAndIdentity(t *testing.T) {
	for _, name := range []string{"ledger ancestor link", "ledger final link", "ledger absent ancestor link", "ledger replaced directory", "ledger replaced absent ancestor", "anchor home link", "anchor replaced directory", "anchor absent ancestor link"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			base := filepath.Dir(f.home)
			first, second := filepath.Join(base, "storage-one"), filepath.Join(base, "storage-two")
			for _, dir := range []string{first, second} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			alias := filepath.Join(base, "current")
			if err := os.Symlink(first, alias); err != nil {
				t.Fatal(err)
			}
			changed, moved := "ledger", ""
			switch name {
			case "ledger ancestor link", "ledger absent ancestor link":
				f.root = alias + "/runs"
			case "ledger final link":
				f.root = alias
			case "ledger replaced directory":
				f.root, moved = first, first
			case "ledger replaced absent ancestor":
				f.root, moved = first+"/future/runs", first
			default:
				changed = "anchor"
				f.root = filepath.Join(base, "independent-runs")
				f.home = alias
				oldAnchor := anchorPath
				anchorPath = tegoruntime.AnchorPath
				t.Cleanup(func() { anchorPath = oldAnchor })
				if name == "anchor replaced directory" {
					moved = first + "/.tego"
				}
			}
			if !strings.Contains(name, "absent") {
				for _, path := range []string{first + "/runs", second + "/runs", first + "/.tego", second + "/.tego"} {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			f.write(t, "")
			g, prepares := guardWithConfigFixture(t)
			if moved == "" {
				replaceGuardWalkLink(t, alias, second)
			} else {
				if err := os.Rename(moved, moved+"-retired"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(moved, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			got, err := g.prepareAdoption(adopt.Process{}, 1000)
			if got != nil || err == nil || !strings.Contains(err.Error(), changed) || !strings.Contains(err.Error(), "restart") || *prepares != 1 {
				t.Fatalf("changed %s placement/identity reached preparation: table=%t prepares=%d err=%v", changed, got != nil, *prepares, err)
			}
		})
	}
}

func TestGuardRecordLocationOrdinarySetups(t *testing.T) {
	for _, name := range []string{"default location", "configured ledger root", "stable ledger link", "network home directory semantics"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			base := filepath.Dir(f.home)
			switch name {
			case "default location":
				f.root = "~/.tego/runs"
			case "configured ledger root":
				f.root = filepath.Join(base, "configured-runs")
			case "stable ledger link":
				storage := filepath.Join(base, "storage")
				if err := os.Mkdir(storage, 0o700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(base, "ledger")
				if err := os.Symlink(storage, link); err != nil {
					t.Fatal(err)
				}
				f.root = link + "/runs"
			case "network home directory semantics":
				// Model the stable device/inode and ordinary directory creation
				// observed on a mounted home. No network filesystem is mounted here.
				f.root = "~/.tego/runs"
			}
			oldAnchor := anchorPath
			anchorPath = tegoruntime.AnchorPath
			t.Cleanup(func() { anchorPath = oldAnchor })
			f.write(t, "")
			g, prepares := guardWithConfigFixture(t)
			for i := range 3 {
				got, err := g.prepareAdoption(adopt.Process{}, 1000)
				if err != nil || got == nil {
					t.Fatalf("ordinary setup refused at adoption %d: %v", i+1, err)
				}
				got.cleanup()
				// The first adoption may create previously absent output directories.
				if i == 0 {
					if err := os.MkdirAll(g.recordRoot, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(filepath.Dir(g.recordAnchor), 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if *prepares != 4 {
				t.Fatalf("preparations = %d, want startup plus three adoptions", *prepares)
			}
			t.Logf("ordinary setup: 3 decision checks, 3 accepted, 0 refused (%s)", name)
		})
	}
}

func TestGuardRecordLocationRemembersCreatedDirectory(t *testing.T) {
	for _, name := range []string{"ledger", "anchor"} {
		t.Run(name, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			f.root = filepath.Join(filepath.Dir(f.home), "separate-ledger")
			oldAnchor := anchorPath
			anchorPath = tegoruntime.AnchorPath
			t.Cleanup(func() { anchorPath = oldAnchor })
			f.write(t, "")
			g, prepares := guardWithConfigFixture(t)
			path := g.recordRoot
			if name == "anchor" {
				path = filepath.Dir(g.recordAnchor)
			}
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			got, err := g.prepareAdoption(adopt.Process{}, 1000)
			if got == nil || err != nil {
				t.Fatalf("ordinary created directory refused: %v", err)
			}
			got.cleanup()
			if err := os.Rename(path, path+"-retired"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			got, err = g.prepareAdoption(adopt.Process{}, 1000)
			if got != nil || err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "restart") || *prepares != 2 {
				t.Fatalf("created %s directory identity was forgotten: table=%t prepares=%d err=%v", name, got != nil, *prepares, err)
			}
		})
	}
}

func TestGuardRecordLocationWalksAndAbsence(t *testing.T) {
	base := t.TempDir()
	storage := filepath.Join(base, "storage")
	if err := os.MkdirAll(storage+"/deep", 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(storage+"/deep", link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(base, "dangling")
	if err := os.Symlink(storage+"/missing", dangling); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(base, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, resolved, existing string
	}{
		{"links before parent", link + "/..", storage, storage},
		{"absent suffix", link + "/../future/runs/", storage + "/future/runs", storage},
		{"relative", "runs", "", ""},
		{"dangling link", dangling + "/runs", "", ""},
		{"link loop", loop + "/runs", "", ""},
		{"file parent", file + "/runs", "", ""},
		{"parent after absent name", storage + "/future/../runs", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveGuardRecordDirectory(tc.path)
			if tc.resolved == "" {
				if err == nil {
					t.Fatalf("uncertain directory placement accepted: %+v", got)
				}
				return
			}
			if err != nil || got.resolved != tc.resolved || got.existing != tc.existing || got.identity == nil || !got.identity.IsDir() {
				t.Fatalf("directory walk = %+v, err=%v; want resolved=%q existing=%q", got, err, tc.resolved, tc.existing)
			}
		})
	}
}

// Only the anchor directory needs a placement identity: the shared ledger opener
// rejects a final symlink before append, including for an ordinary user.
func TestGuardRecordAnchorFinalLinkCannotRedirect(t *testing.T) {
	dir := t.TempDir()
	anchor := filepath.Join(dir, "chain.log")
	for _, name := range []string{"first", "second"} {
		target := filepath.Join(dir, name)
		if err := os.WriteFile(target, []byte("unchanged\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if name == "second" {
			if err := os.Remove(anchor); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(target, anchor); err != nil {
			t.Fatal(err)
		}
		if err := ledger.ProbeAnchor(anchor); err == nil {
			t.Fatal("anchor append probe followed a final link")
		}
		data, err := os.ReadFile(target)
		if err != nil || string(data) != "unchanged\n" {
			t.Fatalf("anchor target changed: %q, %v", data, err)
		}
	}
}
