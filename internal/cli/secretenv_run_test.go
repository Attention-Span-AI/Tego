// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// secretEnvContract writes a contract with no env.pass, the shape secret-env warns on.
func secretEnvContract(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("version: 0\nname: probe\ncommand: [\"/bin/sh\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunCompileNamesSecretEnv (ADR 0067 D4): `tego run`'s compile is given
// the launcher's environment, so a contract with no env.pass draws secret-env naming the variable and never its
// value. compileForRun is the compile of every `tego run`; without its WithEnviron option nothing warns.
func TestRunCompileNamesSecretEnv(t *testing.T) {
	const value = "csd-probe-value-never-printed"
	t.Setenv("CSD_PROBE_API_KEY", value)
	var stderr bytes.Buffer
	rt, _, _, _ := compileForRun(context.Background(), runOptions{contract: secretEnvContract(t)}, config.Builtin(), &stderr)
	if rt == nil {
		t.Fatalf("compile failed:\n%s", stderr.String())
	}
	out := stderr.String()
	if !strings.Contains(out, "[secret-env]") || !strings.Contains(out, "CSD_PROBE_API_KEY") {
		t.Errorf("tego run's compile does not name CSD_PROBE_API_KEY under secret-env:\n%s", out)
	}
	if strings.Contains(out, value) {
		t.Errorf("tego run's compile printed the variable's value:\n%s", out)
	}
}

// TestGeneratedContractDrawsNoSecretEnv (r6 B1-SECRETS-DEFAULTS): `tego watch` with no --boundary runs a contract
// tego wrote, which passes the whole environment by choice; its user cannot add the env.pass the fix names, and the
// supply-chain demo's watched side exports fake credential names, so the compile checks none for it.
func TestGeneratedContractDrawsNoSecretEnv(t *testing.T) {
	t.Setenv("CSD_PROBE_API_KEY", "x")
	var stderr bytes.Buffer
	rt, _, _, _ := compileForRun(context.Background(), runOptions{contract: secretEnvContract(t), generated: true}, config.Builtin(), &stderr)
	if rt == nil {
		t.Fatalf("compile failed:\n%s", stderr.String())
	}
	if out := stderr.String(); strings.Contains(out, "secret-env") || strings.Contains(out, "CSD_PROBE_API_KEY") {
		t.Errorf("a generated contract's compile warned secret-env:\n%s", out)
	}
}

// TestAdoptionCompileDrawsNoSecretEnv: an adoption governs a process that is
// already running, whose environment is its own, not that of the `tego adopt` or guard process that compiles its
// boundary, and env: is refused for an adoption (unenforceableForAdoption), so secret-env's fix could not be taken.
// compileAdoptionTable gives its compile no environment, and no secret-env is printed.
func TestAdoptionCompileDrawsNoSecretEnv(t *testing.T) {
	t.Setenv("CSD_PROBE_API_KEY", "x")
	agentHome := t.TempDir()
	prevHome := adoptHomeOf
	adoptHomeOf = func(int) (string, error) { return agentHome, nil }
	t.Cleanup(func() { adoptHomeOf = prevHome })
	m := config.Builtin()
	var errs bytes.Buffer
	a := &preparedAdoption{m: m, boundary: true, cleanup: func() {}, owner: os.Getuid()}
	rt, code := compileAdoptionTable(t.Context(), m, adoptOptions{boundary: secretEnvContract(t)}, adopt.Process{}, a, &errs)
	if rt == nil {
		t.Fatalf("compile: exit %d stderr %q", code, errs.String())
	}
	if out := errs.String(); strings.Contains(out, "secret-env") || strings.Contains(out, "CSD_PROBE_API_KEY") {
		t.Errorf("an adoption's compile warned about tego's own environment:\n%s", out)
	}
}

// fixedEnviron makes the compiles of `tego compile` and `tego run` in this test see only PATH and HOME, so a test
// that wants no warning does not depend on the credentials in its caller's shell. A test that calls it must not be
// parallel: launchEnviron is package state.
func fixedEnviron(t *testing.T) {
	t.Helper()
	prev := launchEnviron
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	launchEnviron = func() []string { return env }
	t.Cleanup(func() { launchEnviron = prev })
}
