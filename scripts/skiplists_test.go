// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Embed the checker so go test -overlay can exercise the old shell implementation
// against these same fixtures, without modifying the caller's worktree.
//
//go:embed check-skiplists.sh tree-files.sh check-skiprows.py skipgate.sh
var skiplistScripts embed.FS

func TestScopedMustPassHasAScheduledRow(t *testing.T) {
	for _, tc := range []struct {
		name, row, workflow, want string
	}{
		{"scheduled", "fedora-7.0", "", ""},
		{"misspelled row", "fedora-7.00", "", "unknown matrix row fedora-7.00"},
		{"unscheduled package", "rhel-9", "", "p TestProof: no scheduled full package run on row=rhel-9"},
		{"doctor only", "ubuntu-22.04", "", "no scheduled full package run"},
		{"removed dispatch", "fedora-7.0", "# no root suite step\n", "no scheduled full package run"},
		{"different package", "fedora-7.0", "TEGO_VM_ROW=\"$KERNEL\" test/vm/root-suites.sh '=q'", "no scheduled full package run"},
		{"narrowed tests", "fedora-7.0", "TEGO_VM_ROW=\"$KERNEL\" VM_RUN=TestOther test/vm/root-suites.sh '=p'", "no scheduled full package run"},
		{"narrowed shard", "fedora-7.0", "TEGO_VM_ROW=\"$KERNEL\" VM_SHARD=rest test/vm/root-suites.sh '=p'", "no scheduled full package run"},
		{"shell conditional", "fedora-7.0", "if false; then TEGO_VM_ROW=\"$KERNEL\" test/vm/root-suites.sh '=p'; fi", "no scheduled full package run"},
		{"wrong row assignment", "fedora-7.0", "TEGO_VM_ROW=rhel-9 test/vm/root-suites.sh '=p'", "no scheduled full package run"},
		{"overridden kernel", "fedora-7.0", "KERNEL=rhel-9 TEGO_VM_ROW=\"$KERNEL\" test/vm/root-suites.sh '=p'", "no scheduled full package run"},
		{"commented dispatch", "fedora-7.0", "# test/vm/root-suites.sh '=p'", "no scheduled full package run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, body string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"check-skiplists.sh", "tree-files.sh", "check-skiprows.py", "skipgate.sh"} {
				body, err := skiplistScripts.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				write("scripts/"+name, string(body), 0o755)
			}
			// check-skiplists.sh builds tools/rootskips from the tree it checks (the scan for a needs-root
			// skip no list names); the tool is stdlib-only, so it builds in the fixture's own module.
			rootskips, err := os.ReadFile(filepath.Join("..", "tools", "rootskips", "main.go"))
			if err != nil {
				t.Fatal(err)
			}
			write("tools/rootskips/main.go", string(rootskips), 0o644)
			write("go.mod", "module example.test/skiplists\n", 0o644)
			write("p/proof_test.go", "package p\n\nimport \"testing\"\n\nfunc TestProof(t *testing.T) {}\n", 0o644)
			write("test/unit-skips.txt", "# empty\n", 0o644)
			write("test/integration-skips.txt", "# empty\n", 0o644)
			// This global allowance is why an inert row obligation must fail.
			write("test/vm/root-skips.txt", "p TestProof # may skip without the feature\n", 0o644)
			write("test/vm/root-must-pass.txt", "p TestProof row="+tc.row+" # must pass on proof row\n", 0o644)
			write("test/vm/suites.sh", "PKGS=(p)\n", 0o644)
			write("test/vm/fetch-kernel.py", "print('fedora-7.0 7.0 koji full Fedora')\nprint('rhel-9 5.14 rpm full RHEL')\nprint('ubuntu-22.04 5.15 deb doctor-only Ubuntu')\n", 0o644)
			command := tc.workflow
			if command == "" {
				command = "TEGO_VM_ROW=\"$KERNEL\" VM_BPF=yes \\\n            test/vm/root-suites.sh '=p'"
			}
			write(".github/workflows/vm-matrix.yml", `jobs:
  matrix:
    env:
      KERNEL: ${{ matrix.kernel }}
    strategy:
      matrix:
        part: [row, lsm-bpf, default-lsm]
        kernel:
          - fedora-7.0
          - rhel-9
          - ubuntu-22.04
    steps:
      - name: proof
        if: matrix.part == 'row' && matrix.kernel == 'fedora-7.0'
        run: |
          `+command+"\n", 0o644)
			cmd := exec.Command("bash", "scripts/check-skiplists.sh")
			cmd.Dir = root
			// tree-files.sh uses git, but this fixture has no repository metadata.
			// An empty index in its own repository prevents discovering the caller's.
			init := exec.Command("git", "init", "-q", root)
			if out, err := init.CombinedOutput(); err != nil {
				t.Fatalf("git init: %v\n%s", err, out)
			}
			out, err := cmd.CombinedOutput()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("scheduled obligation refused: %v\n%s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("want rejection %q, got %v\n%s", tc.want, err, out)
			}
		})
	}
}

// TestARootSkipNoRootListNamesIsFound: a test that skips when the process is root (`if os.Geteuid() == 0 { t.Skip }`,
// the usual shape of a test that makes its failure with a mode bit) is no candidate of the unprivileged builds, and the
// root run's strict skip gate printed five of them UNLISTED only after a three-hour guest run. check-skiplists.sh now
// reads them from the syntax tree (tools/rootskips -asroot) and asks test/vm/root-skips.txt (or the must-pass list) for
// each one in a package the root run starts.
func TestARootSkipNoRootListNamesIsFound(t *testing.T) {
	const tests = `package p

import (
	"os"
	"testing"
)

func TestWrite(t *testing.T) {
	t.Run("a file that cannot be written is exit 125 [io]", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes into a folder whatever its mode")
		}
	})
}

func TestRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
}

func TestPlain(t *testing.T) {}
`
	const otherPkg = "package q\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestElsewhere(t *testing.T) {\n\tif os.Geteuid() == 0 {\n\t\tt.Skip(\"no root run starts this package\")\n\t}\n}\n"
	for _, tc := range []struct {
		name, rootSkips, mustPass, want string
	}{
		{"both unlisted", "p TestPlain # a skip nothing reads\n", "", "p TestWrite/a_file_that_cannot_be_written_is_exit_125_[io] (p/p_test.go:10) skips when the process is root"},
		{"the other one too", "p TestPlain # a skip nothing reads\n", "", "p TestRead (p/p_test.go:17) skips when the process is root"},
		{"a subtest entry does not name its sibling test", "p TestWrite/a_file_that_cannot_be_written_is_exit_125_[io] # root writes past a mode\n", "", "p TestRead (p/p_test.go:17)"},
		{"listed as tests", "p TestWrite # root writes past a mode\np TestRead # root reads past a mode\n", "", ""},
		{"listed as the subtest and the test", "p TestWrite/a_file_that_cannot_be_written_is_exit_125_[io] # root writes past a mode\np TestRead # root reads past a mode\n", "", ""},
		{"listed under the subtests' wildcard", "p TestWrite/* # root writes past a mode\np TestRead # root reads past a mode\n", "", ""},
		{"held by the must-pass list", "p TestPlain # a skip nothing reads\n", "p TestWrite # a conditional skip the root run holds\np TestRead # a conditional skip the root run holds\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, body string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"check-skiplists.sh", "tree-files.sh", "check-skiprows.py", "skipgate.sh"} {
				body, err := skiplistScripts.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				write("scripts/"+name, string(body), 0o755)
			}
			rootskips, err := os.ReadFile(filepath.Join("..", "tools", "rootskips", "main.go"))
			if err != nil {
				t.Fatal(err)
			}
			write("tools/rootskips/main.go", string(rootskips), 0o644)
			write("go.mod", "module example.test/skiplists\n", 0o644)
			write("p/p_test.go", tests, 0o644)
			write("q/q_test.go", otherPkg, 0o644)
			write("test/unit-skips.txt", "# empty\n", 0o644)
			write("test/integration-skips.txt", "# empty\n", 0o644)
			write("test/vm/root-skips.txt", tc.rootSkips, 0o644)
			write("test/vm/root-must-pass.txt", tc.mustPass+"# end\n", 0o644)
			write("test/vm/suites.sh", "PKGS=(p)\n", 0o644)
			write("test/vm/fetch-kernel.py", "print('fedora-7.0 7.0 koji full Fedora')\n", 0o644)
			write(".github/workflows/vm-matrix.yml", "jobs: {}\n", 0o644)
			if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
				t.Fatalf("git init: %v\n%s", err, out)
			}
			cmd := exec.Command("bash", "scripts/check-skiplists.sh")
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("a listed root skip was refused: %v\n%s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("want rejection %q, got %v\n%s", tc.want, err, out)
			}
			// q is no package of suites.sh's PKGS: the root run never starts it, so its skip is no business of the lists.
			if strings.Contains(string(out), "q TestElsewhere") {
				t.Errorf("a package no root run starts was held to the root lists:\n%s", out)
			}
		})
	}
}
