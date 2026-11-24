// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRunByNameRefusesAnEntryOnTheWindowsDrive (ADR 0059, amended 2026-11-19, round 5; review F3; guest row
// W-N3-DRIVE): `tego run <name>` and `tego compile <name>` find the name in the registries (here the working directory's
// agent.yaml, the file tego init writes, .tego/agents/<name>.yaml, and an entry of the user registry), and each entry on
// WSL's Windows drive, a 9p share or a FAT disk is refused before anything is compiled or started, with the words that
// say why and where to keep it, as the same file given by its path is. The entries are 0644 and the person's own, as drvfs shows them with
// the metadata option or umask=022, so nothing but their file system refuses them.
func TestRunByNameRefusesAnEntryOnTheWindowsDrive(t *testing.T) {
	for _, c := range []struct {
		name                 string
		magic                int64
		fstype, point, super string
		words                string
	}{
		{"drvfs", unix.V9FS_MAGIC, "9p", "/mnt/c", `rw,aname=drvfs;path=C:\;uid=1000`, "the Windows drive (9p mounted at /mnt/c)"},
		{"9p", unix.V9FS_MAGIC, "9p", "/srv/share", "rw,trans=virtio", "a 9p share mounted at /srv/share"},
		{"FAT", unix.MSDOS_SUPER_MAGIC, "vfat", "/media/u/STICK", "rw,uid=1000", "a FAT disk mounted at /media/u/STICK"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newRegistryWorld(t)
			project := w.contract(t, filepath.Join(w.project, "agent.yaml"), "probe")
			inProject := w.contract(t, filepath.Join(w.project, ".tego", "agents", "inproject.yaml"), "inproject")
			user := w.contract(t, filepath.Join(w.user, "agents", "mine.yaml"), "mine")
			restore := config.SetRulesFileFSForTest(func(f *os.File) (int64, string, string, string, error) {
				if n := f.Name(); n == project || n == inProject || n == user {
					return c.magic, c.fstype, c.point, c.super, nil
				}
				var sfs unix.Statfs_t
				if err := unix.Statfs(f.Name(), &sfs); err != nil {
					return 0, "", "", "", err
				}
				return sfs.Type, "", "", "", nil
			})
			defer restore()
			for _, args := range [][]string{{"run", "probe"}, {"compile", "probe", "--offline"}, {"run", "inproject"}, {"run", "mine"},
				{"compile", project, "--offline"}} {
				code, _, errs := run(t, args...)
				if code == identity.ExitOK || !strings.Contains(errs, c.words) || !strings.Contains(errs, "keep the rules file") {
					t.Errorf("tego %s: exit %d, stderr %s; want refused naming %s and where to keep the file", strings.Join(args, " "), code, errs, c.words)
				}
			}
		})
	}
}

// TestARefusedRulesFileOpensNoScope (ADR 0142, amended 2026-11-19, round 5; guest row W-N3-DRIVE): every check of the
// rules file a run or a bounded watch names runs before the command opens a user scope, so a rules file refused for its
// file system (or one that is missing or does not load) never opens a scope and never prints "opened a user scope"; the
// refusal is the run's own words and exit code. A rules file that loads goes on to the scope as before.
func TestARefusedRulesFileOpensNoScope(t *testing.T) {
	w := newRegistryWorld(t)
	drive := w.contract(t, filepath.Join(w.project, "drive", "agent.yaml"), "drive")
	byName := w.contract(t, filepath.Join(w.user, "agents", "ondrive.yaml"), "ondrive")
	good := w.contract(t, filepath.Join(w.project, "home", "agent.yaml"), "good")
	restore := config.SetRulesFileFSForTest(func(f *os.File) (int64, string, string, string, error) {
		if f.Name() == drive || f.Name() == byName {
			return unix.V9FS_MAGIC, "9p", "/mnt/c", `rw,aname=drvfs;path=C:\;uid=1000`, nil
		}
		var sfs unix.Statfs_t
		if err := unix.Statfs(f.Name(), &sfs); err != nil {
			return 0, "", "", "", err
		}
		return sfs.Type, "", "", "", nil
	})
	defer restore()
	scopeStands(t)
	opened := 0
	scopeExec = func(context.Context, scopePlan, io.Writer) (int, error) { opened++; return 37, nil }
	for _, c := range []struct {
		args  []string
		words string
	}{
		{[]string{"run", drive}, "the Windows drive (9p mounted at /mnt/c)"},
		{[]string{"run", "ondrive"}, "the Windows drive (9p mounted at /mnt/c)"},
		{[]string{"watch", "--boundary", drive, "--", "true"}, "the Windows drive (9p mounted at /mnt/c)"},
		{[]string{"run", filepath.Join(w.project, "missing.yaml")}, "missing.yaml"},
	} {
		opened = 0
		code, _, errs := run(t, c.args...)
		if opened != 0 || strings.Contains(errs, "opened a user scope") || code != identity.ExitLauncher || !strings.Contains(errs, c.words) {
			t.Errorf("tego %s: exit %d, %d scopes opened, stderr %s; want 125 naming %q and no scope", strings.Join(c.args, " "), code, opened, errs, c.words)
		}
	}
	opened = 0
	if code, _, errs := run(t, "run", good); opened != 1 || code != 37 {
		t.Errorf("tego run of a rules file that loads: exit %d, %d scopes opened, stderr %s; want the scope's 37", code, opened, errs)
	}
}
