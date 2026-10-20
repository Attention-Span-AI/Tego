// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// Layout writes fx's tree under project, which it creates: bin/actor and every Actors entry as copies of actor
// (0755), and every ExecOnlyActors entry (0111), the Dirs, the Files (0644) and Scripts (0755) with subst applied to their content, the Fifos, the
// HardLinks, each mount's own tree beneath its mount point, and then the Links. The kernel runner, the compile runner and the decide core's test of the tables
// lay a fixture out alike, so a cell's path means one file to all three.
func Layout(project string, fx *Fixture, actor []byte, subst func(string) string) error {
	path := func(rel string) string { return filepath.Join(project, rel) }
	mkParent := func(rel string) error { return os.MkdirAll(filepath.Dir(path(rel)), 0o755) }
	write := func(rel string, data []byte, mode os.FileMode) error {
		if err := mkParent(rel); err != nil {
			return err
		}
		return os.WriteFile(path(rel), data, mode)
	}
	if err := write("bin/actor", actor, 0o755); err != nil {
		return err
	}
	for _, d := range fx.Dirs {
		if err := os.MkdirAll(path(d), 0o755); err != nil {
			return err
		}
	}
	for _, a := range fx.Actors {
		if err := write(a, actor, 0o755); err != nil {
			return err
		}
	}
	for _, a := range fx.ExecOnlyActors {
		if err := write(a, actor, 0o111); err != nil {
			return err
		}
		if err := os.Chmod(path(a), 0o111); err != nil { // past the umask
			return err
		}
	}
	for _, set := range []struct {
		files map[string]string
		mode  os.FileMode
	}{{fx.Files, 0o644}, {fx.Scripts, 0o755}} {
		for rel, c := range set.files {
			if err := write(rel, []byte(subst(c)), set.mode); err != nil {
				return err
			}
		}
	}
	for _, rel := range fx.Fifos {
		if err := mkParent(rel); err != nil {
			return err
		}
		if err := syscall.Mkfifo(path(rel), 0o755); err != nil {
			return err
		}
		// Past the umask: an exec of it reaches the kernel's own S_ISREG check.
		if err := os.Chmod(path(rel), 0o755); err != nil {
			return err
		}
	}
	for rel, target := range fx.HardLinks {
		if err := mkParent(rel); err != nil {
			return err
		}
		if err := os.Link(path(target), path(rel)); err != nil {
			return err
		}
	}
	// A mount's own tree (its subvolumes and files) also lies beneath its mount point on the filesystem below, for the
	// runners that make no mount (compile --test, the decide core), which compile the contract against these paths;
	// the root runner's mount hides it (Fixture.Mounts).
	for _, m := range fx.Mounts {
		// What a bind or an overlay shows at its mount point: a copy of its source, or of its lower directory.
		if src := m.From + m.Lower; src != "" {
			if err := copyTree(path(src), path(m.At)); err != nil {
				return err
			}
		}
		for _, sv := range m.Subvolumes {
			if err := os.MkdirAll(path(filepath.Join(m.At, sv)), 0o755); err != nil {
				return err
			}
		}
		for rel, c := range m.Files {
			if err := write(filepath.Join(m.At, rel), []byte(subst(c)), 0o644); err != nil {
				return err
			}
		}
	}
	links := make([]string, 0, len(fx.Links))
	for rel := range fx.Links {
		links = append(links, rel)
	}
	sort.Strings(links)
	for _, rel := range links {
		if err := mkParent(rel); err != nil {
			return err
		}
		if err := os.Symlink(fx.Links[rel], path(rel)); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies the directories and regular files beneath src into dst, with their permission bits.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(to, info.Mode().Perm())
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(to, data, info.Mode().Perm())
		}
		return fmt.Errorf("%s: only directories and regular files are copied to a mount point", p)
	})
}
