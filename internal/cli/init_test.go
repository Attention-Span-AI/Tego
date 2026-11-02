// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func hashTree(t *testing.T, dir string) [32]byte {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		h.Write([]byte(p))
		if !info.IsDir() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h.Write(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestInitIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "My Project_v2")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "init", dir)
	if code != identity.ExitOK || errs != "" {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	for _, want := range []string{"created .tego/", "created agent.yaml (name: my-project-v2)", "added .tego/runs/ to .gitignore"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout %q lacks %q", out, want)
		}
	}
	st, err := os.Stat(filepath.Join(dir, ".tego"))
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf(".tego: %v %v", st, err)
	}
	contract, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if err != nil || !strings.HasPrefix(string(contract), initMarker) || !strings.Contains(string(contract), "name: \"my-project-v2\"\n") {
		t.Fatalf("agent.yaml: %q %v", contract, err)
	}
	if strings.Contains(string(contract), "__NAME__") {
		t.Fatal("template placeholder left in place")
	}
	gi, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil || string(gi) != ".tego/runs/\n" {
		t.Fatalf(".gitignore: %q %v", gi, err)
	}
	before := hashTree(t, dir)
	code, out, errs = run(t, "init", dir)
	if code != identity.ExitOK || errs != "" || !strings.Contains(out, "already initialized") {
		t.Fatalf("second run: exit %d stdout %q stderr %q", code, out, errs)
	}
	if hashTree(t, dir) != before {
		t.Fatal("second init changed the tree")
	}
}

// TestInitWritesAContractThatLoadsForAnyName: the contract's name is a YAML string (R3), so a name
// YAML would read as a number, a boolean or null must be written quoted, or tego init writes a
// contract tego compile refuses. Every directory name and --name value here is a valid agent id.
func TestInitWritesAContractThatLoadsForAnyName(t *testing.T) {
	for _, tc := range []struct{ dir, flag, want string }{
		{dir: "2024", want: "2024"},
		{dir: "true", want: "true"},
		{dir: "null", want: "null"},
		{dir: "proj", flag: "123", want: "123"},
		{dir: "proj", flag: "1e3", want: "1e3"},
		{dir: "proj", flag: "0x1f", want: "0x1f"},
		{dir: "proj", flag: "-1", want: "-1"},
		{dir: "proj", flag: "no", want: "no"},
	} {
		t.Run(tc.dir+"_"+tc.flag, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), tc.dir)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			args := []string{"init"}
			if tc.flag != "" {
				args = append(args, "--name", tc.flag)
			}
			if code, _, errs := run(t, append(args, dir)...); code != identity.ExitOK {
				t.Fatalf("init: exit %d %q", code, errs)
			}
			c, ds, err := agent.Load(filepath.Join(dir, "agent.yaml"), nil)
			if err != nil {
				t.Fatalf("the written agent.yaml does not load: %v %v", err, ds)
			}
			if c.Name != tc.want {
				t.Fatalf("name %q, want %q", c.Name, tc.want)
			}
		})
	}
}

// TestInitStarterCountsReads: the starter ends a run that records nothing for ten minutes (stall_after), so it must
// record reads (record: full) or `tego compile` warns [stall-reads-unseen] on the first contract a person compiles.
// TestInitThenCompile holds the compile's stderr empty; this holds the cause where python3 is not needed.
func TestInitStarterCountsReads(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := run(t, "init", "--name", "starter", dir); code != identity.ExitOK {
		t.Fatalf("init: exit %d %q", code, errs)
	}
	c, ds, err := agent.Load(filepath.Join(dir, "agent.yaml"), nil)
	if err != nil || len(ds) != 0 {
		t.Fatalf("the starter must load with no diagnostic: %v %v", err, ds)
	}
	if c.Limits.StallAfter != nil && c.Record != agent.RecordFull {
		t.Fatalf("the starter sets stall_after under record %q: a read is then not recorded (stall-reads-unseen); want record: full", c.Record)
	}
}

func TestInitGitignoreAppend(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("bin/"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := run(t, "init", "--name", "a", dir); code != identity.ExitOK {
		t.Fatalf("exit %d %q", code, errs)
	}
	gi, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if string(gi) != "bin/\n.tego/runs/\n" {
		t.Fatalf(".gitignore %q", gi)
	}
	if code, _, _ := run(t, "init", "--name", "a", dir); code != identity.ExitOK {
		t.Fatal(code)
	}
	gi2, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if string(gi2) != string(gi) {
		t.Fatalf("line appended twice: %q", gi2)
	}
}

func TestInitForeignContract(t *testing.T) {
	dir := t.TempDir()
	foreign := "version: 0\nname: theirs\ncommand: [\"true\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "init", dir)
	if code != identity.ExitFinding { // R25: a finding, the file is not ours
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	if !strings.Contains(errs, "agent.yaml: tego init: exists and was not written by tego init") || !strings.Contains(errs, "[exists]") {
		t.Fatalf("stderr %q", errs)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "agent.yaml")); string(got) != foreign {
		t.Fatal("foreign file was touched")
	}
	code, out, errs := run(t, "init", "--force", "--name", "mine", dir)
	if code != identity.ExitOK || errs != "" || !strings.Contains(out, "created agent.yaml (name: mine)") {
		t.Fatalf("--force: exit %d stdout %q stderr %q", code, out, errs)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "agent.yaml")); !strings.HasPrefix(string(got), initMarker) {
		t.Fatal("--force did not replace the file")
	}
}

func TestInitRefusesFileAtDotTego(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".tego"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := run(t, "init", dir)
	if code != identity.ExitFinding || !strings.Contains(errs, "[exists]") {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	// --force replaces agent.yaml and nothing else, so the refusal must not send the reader round to it.
	if strings.Contains(errs, "--force") {
		t.Errorf("the refusal offers --force, which never replaces .tego: %q", errs)
	}
	if code, _, errs := run(t, "init", "--force", dir); code != identity.ExitFinding || !strings.Contains(errs, "[exists]") {
		t.Errorf("--force: exit %d stderr %q, want the same refusal", code, errs)
	}
}

// TestInitReadOnlyParent is the init I/O failure case: a project directory with no write
// permission makes os.Mkdir(.tego) fail before anything is written, so init must report a clear
// one-line error at Tego's own-error exit code and leave the directory exactly as it found it
// (nothing to roll back, since ensureDir's Mkdir is the first and only write attempt).
func TestInitReadOnlyParent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission, which this test relies on")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "ro-project")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { // r-xr-xr-x: no writer can create .tego inside it
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) // restore write so t.TempDir()'s own cleanup can remove it

	code, out, errs := run(t, "init", dir)
	if code != identity.ExitError { // R25: an I/O failure is Tego's own error, not a finding
		t.Fatalf("exit %d, want %d; stdout=%q stderr=%q", code, identity.ExitError, out, errs)
	}
	if out != "" {
		t.Errorf("stdout not empty on failure: %q", out)
	}
	if strings.Count(strings.TrimRight(errs, "\n"), "\n") != 0 {
		t.Fatalf("stderr is not one line: %q", errs)
	}
	if !strings.Contains(errs, "[io]") {
		t.Fatalf("stderr %q lacks the io code", errs)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tego")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".tego left half-written: stat = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("read-only project directory is no longer empty: %v", entries)
	}
}

func TestInitUsage(t *testing.T) {
	if code, _, errs := run(t, "init", "--name", "Bad Name", t.TempDir()); code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
		t.Fatalf("exit %d %q", code, errs)
	}
	if code, _, _ := run(t, "init", "a", "b"); code != identity.ExitUsage {
		t.Fatal(code)
	}
}

func TestAgentNameFor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/x/retriever", "retriever"},
		{"/x/My Project_v2", "my-project-v2"},
		{"/x/---", "agent"},
		{"/x/ünïcode", "n-code"},
		{"/x/" + strings.Repeat("a", 50), strings.Repeat("a", 40)},
		{"/", "agent"},
	}
	for _, tc := range tests {
		if got := agentNameFor(tc.in); got != tc.want {
			t.Errorf("agentNameFor(%q) = %q want %q", tc.in, got, tc.want)
		}
		if _, err := identity.ParseAgentID(agentNameFor(tc.in)); err != nil {
			t.Errorf("%q: derived name is not an agent id: %v", tc.in, err)
		}
	}
}
