// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Binary discovery must preserve a failed stat instead of treating it as a
// missing install. Otherwise a write grant is admitted with no target to compare.
func TestCompileRefusesUnknownBinaryDiscovery(t *testing.T) {
	for _, source := range []string{"running", "PATH", "install", "beside running"} {
		t.Run(source, func(t *testing.T) {
			f := newFixture(t)
			bin := filepath.Join(f.root, "unknown-bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			unknown := filepath.Join(bin, "tego")
			opts := []CompileOption{WithOwnBinaries(""), withInstallDirs()}
			switch source {
			case "running":
				opts = append(opts, WithOwnBinaries(unknown))
			case "PATH":
				opts = append(opts, WithPATH(bin+":"+f.bin))
			case "install":
				opts = append(opts, withInstallDirs(bin))
			case "beside running":
				f.file(unknown, "tego", 0o755)
				opts = append(opts, WithOwnBinaries(unknown))
				unknown = filepath.Join(bin, "tego-control")
			}
			// ELOOP is deterministic for root and unprivileged tests alike.
			if err := os.Symlink(unknown, unknown); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"write", "ask"} {
				body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [./out/]}\n"
				_, ds, err := Compile(f.load(body), f.machine, f.opts(opts...)...)
				text := render(ds)
				if err == nil || !strings.Contains(text, "binary discovery cannot examine "+unknown) || !strings.Contains(text, "too many levels of symbolic links") {
					t.Errorf("fs.%s with unknown %s discovery must refuse and name the failed inspection: err=%v\n%s", field, source, err, text)
				}
			}
		})
	}
}

func TestCompileAllowsAbsentBinaryCandidates(t *testing.T) {
	f := newFixture(t)
	plain := filepath.Join(f.root, "not-a-directory")
	f.file(plain, "plain", 0o644)
	for _, missing := range []string{filepath.Join(f.root, "absent"), filepath.Join(plain, "absent")} {
		for _, field := range []string{"write", "ask"} {
			body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [./out/]}\n"
			f.compile(f.load(body), WithOwnBinaries(filepath.Join(missing, "tego")), WithPATH(missing+":"+f.bin), withInstallDirs(missing))
		}
	}
}

func TestCompileRefusesUnsearchableInstall(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("root can search mode-000 directories; ELOOP discovery cases cover this refusal for root")
		return
	}
	f := newFixture(t)
	bin := filepath.Join(f.home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "tego")
	f.file(exe, "tego", 0o755)
	if err := os.Chmod(bin, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
	for _, field := range []string{"write", "ask"} {
		// The owner can chmod this directory and then rewrite the hidden binary.
		body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [" + bin + "]}\n"
		_, ds, err := Compile(f.load(body), f.machine, f.opts(WithOwnBinaries(""))...)
		text := render(ds)
		if err == nil || !strings.Contains(text, "binary discovery cannot examine "+exe) || !strings.Contains(text, "permission denied") {
			t.Errorf("fs.%s over an owned unsearchable install must preserve EACCES: err=%v\n%s", field, err, text)
		}
	}
}

func TestCompileRefusesUnknownBinaryIdentity(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	old := statOwnFile
	statOwnFile = func(p string, st *unix.Stat_t) error {
		if p == exe {
			return unix.EIO
		}
		return old(p, st)
	}
	t.Cleanup(func() { statOwnFile = old })
	for _, field := range []string{"write", "ask"} {
		body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [./out/]}\n"
		_, ds, err := Compile(f.load(body), f.machine, f.opts(WithOwnBinaries(exe))...)
		text := render(ds)
		if err == nil || !strings.Contains(text, "cannot read the file identity of "+exe) || !strings.Contains(text, "input/output error") {
			t.Errorf("fs.%s with unknown binary identity must refuse and name EIO: err=%v\n%s", field, err, text)
		}
	}
}

func TestCompileRefusesUnknownHardLinkGrantFilesystem(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	if err := os.Chmod(exe, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(exe, filepath.Join(f.root, "other-name")); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(f.project, "out")
	old := statOwnFile
	statOwnFile = func(p string, st *unix.Stat_t) error {
		if isAncestorOrSelf(p, entry) {
			return unix.EIO
		}
		return old(p, st)
	}
	t.Cleanup(func() { statOwnFile = old })
	for _, field := range []string{"write", "ask"} {
		body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [" + entry + "]}\n"
		_, ds, err := Compile(f.load(body), f.machine, f.opts(WithOwnBinaries(exe), WithMountInfo(""))...)
		text := render(ds)
		if err == nil || !strings.Contains(text, "cannot read the filesystem holding "+entry) || !strings.Contains(text, "input/output error") {
			t.Errorf("fs.%s with unplaceable grant filesystem must retain hard-link uncertainty: err=%v\n%s", field, err, text)
		}
	}
}

func TestCompileIgnoresHiddenHardLinkFilesystemMounts(t *testing.T) {
	f := newFixture(t)
	exe := filepath.Join(ownInstall(f), "tego")
	if err := os.Chmod(exe, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(exe, filepath.Join(f.root, "other-name")); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(f.project, "out")
	hidden := filepath.Join(entry, "hidden")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatal(err)
	}
	mi := fakeMountInfo(f,
		"2 1 0:90 / "+entry+" rw - tmpfs none rw",
		"3 2 8:1 /data "+hidden+" rw - ext4 disk rw",
		"4 2 0:91 / "+entry+" rw - tmpfs none rw")
	old := statOwnFile
	statOwnFile = func(p string, st *unix.Stat_t) error {
		err := old(p, st)
		if err == nil && p == entry {
			// Model the visible covering tmpfs without a privileged mount.
			st.Dev = ^uint64(0)
		}
		return err
	}
	t.Cleanup(func() { statOwnFile = old })
	for _, field := range []string{"write", "ask"} {
		body := "version: 0\nname: a\ncommand: [python]\nfs: {" + field + ": [" + entry + "]}\n"
		_, ds, err := Compile(f.load(body), f.machine, f.opts(WithOwnBinaries(exe), mi, withInstallDirs())...)
		if err != nil {
			t.Errorf("fs.%s on another filesystem was refused because of a hidden binary-device mount: %v\n%s", field, err, render(ds))
		}
	}
}
