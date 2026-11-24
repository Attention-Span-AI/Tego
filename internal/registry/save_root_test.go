// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveNeverFollowsRegistryRootLink(t *testing.T) {
	top := t.TempDir()
	outside := filepath.Join(top, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(top, "registry")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	sv := Save{Places: Places{User: link}, Name: "builder", Text: []byte("version: 0\nname: builder\ncommand: [sh]\n")}
	if _, err := sv.Write(); err == nil {
		t.Fatal("Save followed linked registry")
	}
	if _, err := os.Stat(filepath.Join(outside, "agents", "builder.yaml")); !os.IsNotExist(err) {
		t.Fatal("contract written outside real registry")
	}
}

func TestSaveRefusesRegistrySwappedDuringCompile(t *testing.T) {
	top := t.TempDir()
	root := filepath.Join(top, "registry")
	outside := filepath.Join(top, "outside")
	for _, p := range []string{root, outside} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sv := Save{Places: Places{User: root}, Name: "builder", Text: []byte("version: 0\nname: builder\ncommand: [sh]\n")}
	sv.Compile = func(string, []byte) error {
		if err := os.Rename(root, root+"-old"); err != nil {
			return err
		}
		return os.Symlink(outside, root)
	}
	if _, err := sv.Write(); err == nil {
		t.Fatal("followed swapped registry root")
	}
	if _, err := os.Stat(filepath.Join(outside, "agents", "builder.yaml")); !os.IsNotExist(err) {
		t.Fatal("wrote outside pinned registry")
	}
}
