// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileAndRunRefuseAWriteEntryOverTegosRuntimeDir is agent-contract.md R10a through the CLI:
// `tego compile` and `tego run` name the user's runtime directories to the compiler (anchorCompileOptions), so a
// contract whose fs.write covers $XDG_RUNTIME_DIR/tego, where every run keeps its private directory, is a compile
// error (exit 1) and a refused run (exit 125), each with a contradiction naming tego's runtime directory, before any
// agent starts. Nothing pinned the CLI's half: a compile handed another directory passed every test.
func TestCompileAndRunRefuseAWriteEntryOverTegosRuntimeDir(t *testing.T) {
	gcRoot(t)
	useAnchor(t, filepath.Join(t.TempDir(), "chain.log"))
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", xdg)
	work := t.TempDir()
	contract := filepath.Join(work, "agent.yaml")
	body := "version: 0\nname: runtime-dir\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\"" + filepath.Join(xdg, "tego") + "/\"]\n"
	if err := os.WriteFile(contract, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	refused := func(what string, want, code int, errs string) {
		t.Helper()
		if code != want || !strings.Contains(errs, "contradiction") || !strings.Contains(errs, "runtime directory") {
			t.Fatalf("%s: exit %d, want %d with a contradiction naming tego's runtime directory\nstderr %s", what, code, want, errs)
		}
	}
	code, _, errs := run(t, "compile", contract, "--offline")
	refused("compile", identity.ExitFinding, code, errs)
	marker := filepath.Join(work, "ran")
	code, _, errs = run(t, "run", "--observe", contract, "--", "/bin/sh", "-c", "touch "+marker)
	refused("run", identity.ExitLauncher, code, errs)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the agent ran although its contract was refused")
	}
}
