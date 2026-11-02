// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestAnEmptyStringIsNoDefault: an unset "$RUN", "$DIR" or "$AGENT" is an argument the caller meant to fill. Where
// the empty string reads as "none given" it answered silently for something else (the receipt of whichever run was
// newest, a scaffold in the current directory), and elsewhere it left a library's sentence (exit 1 from compile, 125
// from run).
func TestAnEmptyStringIsNoDefault(t *testing.T) {
	id, _ := verifiedRun(t)
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{
		{"receipt", ""},
		{"init", ""},
		{"compile", ""},
		{"run", ""},
		{"run", filepath.Join("testdata", "minimal.yaml"), "--", ""},
	} {
		code, out, errs := run(t, args...)
		if code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
			t.Errorf("tego %q: exit %d stderr %q, want a usage error", args, code, errs)
		}
		if strings.Contains(out, id) {
			t.Errorf("tego %q answered with run %s:\n%s", args, id, out)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the current directory after tego init \"\": %v, %v; want nothing written", entries, err)
	}
}

// TestALongRunNameIsNotARun: a name too long to be a file is the same typo as any other argument that is no run, the
// usage error every command gives for it, not ENAMETOOLONG as tego's own failure.
func TestALongRunNameIsNotARun(t *testing.T) {
	long := "r-" + strings.Repeat("x", 300)
	for _, cmd := range []string{"events", "receipt", "measure", "drift", "learn"} {
		if code, _, errs := run(t, cmd, long); code != identity.ExitUsage || !strings.Contains(errs, "not a run id") {
			t.Errorf("tego %s <300 bytes>: exit %d stderr %q, want a usage error", cmd, code, errs)
		}
	}
}

// TestADeletedWorkingDirectorySaysSo: compile joins relative paths to the working directory, and with it gone the
// failure was "agent: Compile: getwd: no such file or directory [schema]": no word on what to do, and the wrong class.
func TestADeletedWorkingDirectorySaysSo(t *testing.T) {
	contract, err := filepath.Abs(filepath.Join("testdata", "minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	gone := filepath.Join(dir, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "compile", contract)
	if code != identity.ExitFinding || !strings.Contains(errs, "current directory") || !strings.Contains(errs, "["+agent.CodePathMissing+"]") ||
		strings.Contains(errs, "["+agent.CodeSchema+"]") {
		t.Errorf("compile from a deleted directory: exit %d stderr %q", code, errs)
	}
}

// TestCompileOfAContractItMayNotOpenIsAnIOFailure: such a contract was tagged [io] and still exited 1, a finding,
// where every other [io] of compile, and EACCES everywhere (E26), is tego's own failure at 125.
func TestCompileOfAContractItMayNotOpenIsAnIOFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a file of mode 000")
	}
	data, err := os.ReadFile(filepath.Join("testdata", "minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, data, 0o000); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "compile", p)
	if code != identity.ExitError || !strings.Contains(errs, "["+codeIO+"]") {
		t.Errorf("compile of a mode 000 contract: exit %d stderr %q, want %d [%s]", code, errs, identity.ExitError, codeIO)
	}
}

// TestLoadCodeIsNotSchemaForAFileItCouldNotOpen: a contract its reader may not open has no schema to fault.
func TestLoadCodeIsNotSchemaForAFileItCouldNotOpen(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("open: %w", fs.ErrPermission):     codeIO,
		fmt.Errorf("open: %w", fs.ErrNotExist):       agent.CodePathMissing,
		errors.New("a contract that does not parse"): agent.CodeSchema,
	} {
		if got := loadCode(err); got != want {
			t.Errorf("loadCode(%v) = %q, want %q", err, got, want)
		}
	}
}
