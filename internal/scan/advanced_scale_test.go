// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type advancedStockEntry struct {
	Root, Path, Kind, Target, SHA256 string
}

func TestAdvancedRepositoryUnitExamples(t *testing.T) {
	for _, tc := range []struct {
		name  string
		want  error
		execs int
	}{
		{"tego-agent@.service", errUnresolved, 0},
		{"tego-gc.service", errUnresolved, 0},
		{"tego-agent-restart@.service", nil, 1},
		{"example-restart-myapp@.service", nil, 1},
		{"tego-agent-restart@.timer", nil, 0},
		{"tego-gc.timer", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../examples/systemd", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseUnit(t.Context(), bytes.NewReader(data))
			if err != tc.want || len(got.Exec) != tc.execs {
				t.Fatalf("example parse: %+v err=%v, want %d commands and %v", got, err, tc.execs, tc.want)
			}
			for _, command := range got.Exec {
				if command.Program != "" {
					t.Fatalf("example command claimed a catalog program: %+v", command)
				}
			}
		})
	}
}

// Shared machine input must not spend its allowance once per account, or fill
// result sources before a later account's independently configured agent.
func TestAdvanced100AccountsStockUserUnitsAndSystemScale(t *testing.T) {
	for _, systemCount := range []int{0, 3000} {
		t.Run(fmt.Sprintf("system-%d", systemCount), func(t *testing.T) {
			advancedManyAccountsStockUserUnits(t, systemCount)
		})
	}
}

func advancedManyAccountsStockUserUnits(t *testing.T, systemCount int) {
	t.Helper()
	fixture := "testdata/unit-layouts/content/ubuntu-25.10-host"
	data, err := os.ReadFile(filepath.Join(fixture, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct{ Entries []advancedStockEntry }
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	base := unitFixtureRoot(t)
	for _, entry := range manifest.Entries {
		if !filepath.IsLocal(entry.Path) {
			t.Fatalf("fixture path leaves root: %q", entry.Path)
		}
		path := filepath.Join(base, entry.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		switch entry.Kind {
		case "directory":
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
		case "symlink":
			target := entry.Target
			if filepath.IsAbs(target) {
				target = filepath.Join(base, strings.TrimPrefix(target, "/"))
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		case "file":
			content, err := os.ReadFile(filepath.Join(fixture, "root", storedFixtureName(entry.Path)))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(content)
			if hex.EncodeToString(digest[:]) != entry.SHA256 {
				t.Fatalf("original user unit changed: %s", entry.Path)
			}
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unknown fixture kind: %q", entry.Kind)
		}
	}
	uid := uint32(os.Getuid())
	accounts := make([]localAccount, 100)
	for i := range accounts {
		accounts[i] = localAccount{UID: uid, Home: filepath.Join(base, "homes", fmt.Sprintf("user-%02d", i)), Name: fmt.Sprintf("user-%02d", i)}
	}
	last := accounts[len(accounts)-1]
	writeSettings(t, last.Home, ".config/systemd/user/last-account-agent.service", []byte("[Service]\nExecStart=/usr/bin/codex --token "+mcpCanary+"\n"))
	budget := &contentBudget{remaining: 32 << 20, fileLimit: 8192,
		units: &unitWorkBudget{entries: 16384, perDirectory: 8192, maxDirectories: 4096}}
	roots := []string{filepath.Join(base, "etc/systemd/user"), filepath.Join(base, "usr/lib/systemd/user")}
	systemRoot := unitFixtureRoot(t)
	for i := range systemCount {
		writeSettings(t, systemRoot, fmt.Sprintf("stock-%04d.service", i), []byte("[Service]\nExecStart=/usr/bin/true\n"))
	}
	users, system := collectAdvancedUnitsOwned(t.Context(), accounts, roots, []string{systemRoot}, budget, uid)
	found := false
	for _, item := range users.Items {
		if item.Name == "last-account-agent.service" && item.UID != nil && *item.UID == uid && item.Exec.Program == "codex-native" {
			found = true
		}
	}
	for _, source := range append(users.Sources, system.Sources...) {
		if source.Reason == "limit" || source.Reason == "size" {
			t.Errorf("ordinary 100-account layout with %d system units exhausted allowance: %+v", systemCount, source)
		}
	}
	if !found {
		t.Fatalf("last local account lost its independent agent unit: %d items, %d sources, %d attempts, %d bytes left", len(users.Items), len(users.Sources), budget.files, budget.remaining)
	}
	if budget.files > systemCount+200 {
		t.Fatalf("machine documents reread across accounts: %d attempts for %d system files", budget.files, systemCount)
	}
	if systemCount > 0 {
		if len(system.Sources) != 1 || system.Sources[0].Path != systemRoot || system.Sources[0].Read != systemCount {
			t.Fatalf("system source summary lost successful document count: %+v", system.Sources)
		}
	}
	assertNoCanary(t, users)
	t.Logf("100 accounts, %d system units, %d retained sources, %d content attempts, %d charged bytes, %d unit names left; last account observed", systemCount, len(users.Sources)+len(system.Sources), budget.files, (32<<20)-budget.remaining, budget.units.entries)
}
