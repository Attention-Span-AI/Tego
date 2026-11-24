// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAdvancedUnitMachineCachePreservesAccountPrecedence(t *testing.T) {
	machine, homes := unitFixtureRoot(t), unitFixtureRoot(t)
	uid := uint32(os.Getuid())
	accounts := []localAccount{{UID: uid, Home: filepath.Join(homes, "first")}, {UID: uid, Home: filepath.Join(homes, "last")}}
	writeSettings(t, machine, "agent.service", []byte("[Service]\nExecStart=codex\n"))
	writeSettings(t, machine, "agent.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=codex\n"))
	writeSettings(t, accounts[0].Home, ".config/systemd/user/agent.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
	budget := advancedUnitTestBudget()
	users, _ := collectAdvancedUnitsOwned(t.Context(), accounts, []string{machine}, nil, budget, uid)
	if len(users.Items) != 2 || users.Items[0].Exec.Program != "gemini-native" || users.Items[1].Exec.Program != "codex-native" {
		t.Fatalf("one account changed another's cached merge: %+v", users.Items)
	}
	if budget.files != 3 {
		t.Fatalf("machine document was parsed repeatedly: %d attempts", budget.files)
	}
}

func TestAdvancedUnitCacheRechecksChangedMachineInput(t *testing.T) {
	for _, changed := range []string{"root", "listing", "document", "dropin", "alias", "mode"} {
		t.Run(changed, func(t *testing.T) {
			root := unitFixtureRoot(t)
			writeSettings(t, root, "agent.service", []byte("[Service]\nExecStart=codex\n"))
			writeSettings(t, root, "agent.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
			if err := os.Symlink("agent.service", filepath.Join(root, "alias.service")); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			budget := advancedUnitTestBudget()
			budget.unitCache = newUnitReadCache([]string{root}, uid)
			first := collectUnits(t.Context(), []string{root}, uid, budget)
			if len(first.Items) != 1 {
				t.Fatalf("first merge: %+v", first)
			}
			files, bytes, entries := budget.files, budget.remaining, budget.units.entries
			again := collectUnits(t.Context(), []string{root}, uid, budget)
			if len(again.Items) != 1 || budget.files != files || budget.remaining != bytes || budget.units.entries != entries {
				t.Fatalf("unchanged cache reread input: files %d/%d bytes %d/%d entries %d/%d", budget.files, files, budget.remaining, bytes, budget.units.entries, entries)
			}
			switch changed {
			case "root":
				if err := os.Rename(root, root+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "listing":
				writeSettings(t, root, "new.service", []byte("[Service]\nExecStart=claude\n"))
			case "document":
				writeSettings(t, root, "agent.service", []byte("[Service]\nExecStart=claude --changed\n"))
			case "dropin":
				writeSettings(t, root, "agent.service.d/20-reset.conf", []byte("[Service]\nExecStart=\nExecStart=claude --changed\n"))
			case "mode":
				if err := os.Chmod(root, 0777); err != nil {
					t.Fatal(err)
				}
			case "alias":
				if err := os.Remove(filepath.Join(root, "alias.service")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("missing.service", filepath.Join(root, "alias.service")); err != nil {
					t.Fatal(err)
				}
			}
			got := collectUnits(t.Context(), []string{root}, uid, budget)
			if len(got.Items) != 0 {
				t.Fatalf("changed %s reused stale evidence: %+v", changed, got.Items)
			}
			for _, src := range got.Sources {
				if src.Reason == "changed" {
					var system unitSnapshot
					budget.unitCache.finish(&first, &system)
					if len(first.Items) != 0 {
						t.Fatalf("changed machine input left an earlier account's evidence: %+v", first.Items)
					}
					return
				}
			}
			t.Fatalf("changed %s was not named: %+v", changed, got.Sources)
		})
	}
}

func TestAdvancedUnitMachineCacheChargesRejectedListingOnce(t *testing.T) {
	root := unitFixtureRoot(t)
	for i := range 5 {
		writeSettings(t, root, fmt.Sprintf("stock-%d.service", i), []byte("[Service]\nExecStart=/usr/bin/true\n"))
	}
	uid := uint32(os.Getuid())
	budget := advancedUnitTestBudget()
	budget.units.perDirectory = 2
	budget.unitCache = newUnitReadCache([]string{root}, uid)
	for i := range 3 {
		got := collectUnits(t.Context(), []string{root}, uid, budget)
		if len(got.Items) != 0 || len(got.Sources) != 1 || got.Sources[0].Reason != "limit" {
			t.Fatalf("rejected listing %d: %+v", i, got)
		}
	}
	if budget.units.entries != 16384-3 || budget.units.directories != 1 {
		t.Fatalf("rejected machine listing reread: %+v", budget.units)
	}
}

func advancedUnitTestBudget() *contentBudget {
	return &contentBudget{remaining: 32 << 20, fileLimit: 8192, units: &unitWorkBudget{entries: 16384, perDirectory: 8192, maxDirectories: 4096}}
}

func TestAdvancedUnitSourceLimitKeepsUnknownRemainder(t *testing.T) {
	base := unitFixtureRoot(t)
	accounts := make([]localAccount, 1000)
	uid := uint32(os.Getuid())
	for i := range accounts {
		accounts[i] = localAccount{UID: uid, Home: filepath.Join(base, fmt.Sprintf("missing-%04d", i))}
	}
	users, _ := collectAdvancedUnitsOwned(t.Context(), accounts, nil, nil, advancedUnitTestBudget(), uid)
	if len(users.Items) != 0 || len(users.Sources) > 1701 || len(users.Sources) >= 2*len(accounts) {
		t.Fatalf("unit source cap did not stop account coverage: %d sources", len(users.Sources))
	}
	last := users.Sources[len(users.Sources)-1]
	if last.State != "not-read" || last.Reason != "limit" || last.Path != "" || last.NotRead != 1 {
		t.Fatalf("source cap lost explicit unknown remainder: %+v", last)
	}
}

func TestUnitAliasReadFailureKeepsBound(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, "regular.service", []byte("[Service]\nExecStart=codex\n"))
	fd, _, err := metadataPath(t.Context(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fd.Close() }()
	pin, err := projectPath(fd, "regular.service")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pin.Close() }()
	before, err := unitIdentity(fd, "regular.service")
	if err != nil {
		t.Fatal(err)
	}
	budget := advancedUnitTestBudget()
	text, err := readUnitAlias(pin, before, root, filepath.Join(root, "regular.service"), budget)
	if err == nil || text != "" || budget.remaining != (32<<20)-4097 {
		t.Fatalf("failed readlink retained data or escaped allowance: %q %v remaining %d", text, err, budget.remaining)
	}
}

func TestAdvancedUnitCacheEarlyRootRefusalInvalidatesEarlierAccount(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, "agent.service", []byte("[Service]\nExecStart=codex\n"))
	uid := uint32(os.Getuid())
	budget := advancedUnitTestBudget()
	budget.unitCache = newUnitReadCache([]string{root}, uid)
	first := collectUnits(t.Context(), []string{root}, uid, budget)
	if len(first.Items) != 1 {
		t.Fatalf("first account merge: %+v", first)
	}
	// The explicit fixture machine owner forces the same early refusal as a
	// chowned root, without a privileged ownership change in a unit test.
	budget.unitCache.uid = uid + 1
	later := collectUnits(t.Context(), []string{root}, uid, budget)
	budget.unitCache.finish(&first, &later)
	if len(first.Items) != 0 || len(later.Items) != 0 {
		t.Fatalf("early machine-root refusal left an earlier account's evidence: first=%+v later=%+v", first.Items, later.Items)
	}
	if len(later.Sources) != 1 || later.Sources[0].Reason != "changed" {
		t.Fatalf("early root refusal did not name changed shared input: %+v", later.Sources)
	}
}

func TestAdvancedUnitAliasOwnerRefusalInvalidatesCache(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, "agent.service", []byte("[Service]\nExecStart=codex\n"))
	if err := os.Symlink("agent.service", filepath.Join(root, "alias.service")); err != nil {
		t.Fatal(err)
	}
	fd, _, err := metadataPath(t.Context(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fd.Close() }()
	before, err := unitIdentity(fd, "alias.service")
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	budget := advancedUnitTestBudget()
	budget.unitCache = newUnitReadCache([]string{root}, uid+1)
	// Supply the old trusted ownership as cache metadata. The real alias now
	// has the fixture uid; the owner refusal must not bypass the identity check.
	previous := before
	previous.Uid = uid + 1
	path := filepath.Join(root, "alias.service")
	budget.unitCache.aliases[path] = checkedUnitAlias{target: "agent.service", before: previous}
	roots := []unitRoot{{path: root, fd: fd}}
	all := map[string]unitLocation{"alias.service": {root: 0, name: "alias.service"}, "agent.service": {root: 0, name: "agent.service"}}
	_, _, _, err = resolveUnitAlias(t.Context(), roots, all, "alias.service", uid, budget)
	if err != errChanged || !budget.unitCache.changed {
		t.Fatalf("alias owner refusal bypassed cached identity: err=%v changed=%t", err, budget.unitCache.changed)
	}
}
