// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	tables "github.com/attention-span-ai/tego/spec/policy/conformance"
)

// Every embedded contract is loaded even when all its cells have no_compile.
// No actor runs, socket opens, mount or kernel enforcement probe is needed.
func TestFixtureContractsAreStrictAndCompile(t *testing.T) {
	embedded, err := tables.List()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, name := range embedded {
		known[name] = true
	}
	spec := filepath.Join("..", "..", "spec", "policy", "conformance")
	if err := filepath.WalkDir(spec, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
			return nil
		}
		rel, err := filepath.Rel(spec, path)
		if err != nil {
			return err
		}
		if !known[filepath.ToSlash(rel)] {
			return fmt.Errorf("fixture %s is not embedded in the suite", rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fixtures, _, err := LoadTables()
	if err != nil {
		t.Fatal(err)
	}
	actor, err := os.ReadFile(loaderProgram)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for i := range fixtures {
		fx := &fixtures[i]
		t.Run(fx.Name, func(t *testing.T) {
			checked++
			if err := fixtureContract(fx, t.TempDir(), actor); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Logf("strictly checked %d fixtures (including declared variants)", checked)
}

func fixtureContract(fx *Fixture, root string, actor []byte) error {
	project := filepath.Join(root, "project")
	subst := strings.NewReplacer("{{P}}", project, "{{PORT}}", "40001", "{{PORT2}}", "40002").Replace
	if strings.Contains(fx.Contract, "{{LOADER}}") {
		loader, err := Loader()
		if err != nil {
			return err
		}
		base := subst
		subst = func(s string) string { return strings.ReplaceAll(base(s), "{{LOADER}}", loader) }
	}
	if err := Layout(project, fx, actor, subst); err != nil {
		return err
	}
	for _, dir := range []string{"home", "ledger"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			return err
		}
	}
	path := filepath.Join(project, "agent.yaml")
	c, ds, err := agent.LoadBytes(path, []byte(subst(fx.Contract)), nil)
	want := fx.ContractError
	if want != nil && want.Stage == "load" {
		return expectedContractError("load", ds, err, want)
	}
	if err != nil {
		return fmt.Errorf("strict load: %w; diagnostics: %v", err, ds)
	}
	if !hasCompileRow(fx) && want == nil {
		return nil
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	_, ds, err = agent.Compile(c, m, agent.WithCwd(project), agent.WithHome(filepath.Join(root, "home")),
		agent.WithMountInfo(""), agent.Offline())
	if want != nil {
		return expectedContractError("compile", ds, err, want)
	}
	if err != nil {
		return fmt.Errorf("compile: %w; diagnostics: %v", err, ds)
	}
	return nil
}

func expectedContractError(stage string, ds []agent.Diagnostic, err error, want *ContractError) error {
	if err == nil {
		return fmt.Errorf("contract_error expects %s error %s containing %q, but %s succeeded", want.Stage, want.Code, want.Contains, stage)
	}
	for _, d := range ds {
		if stage == want.Stage && d.Severity == "error" && d.Code == want.Code && strings.Contains(d.Message, want.Contains) {
			return nil
		}
	}
	return fmt.Errorf("%s: %w; want %s error %s containing %q; diagnostics: %v", stage, err, want.Stage, want.Code, want.Contains, ds)
}

func TestFixtureContractExpectedErrors(t *testing.T) {
	actor, err := os.ReadFile(loaderProgram)
	if err != nil {
		t.Fatal(err)
	}
	fx := Fixtures()[0]
	fx.Contract += "unknown_contract_key: []\n"
	fx.ContractError = &ContractError{Stage: "load", Code: agent.CodeSchema, Contains: "unknown_contract_key", Why: "loader negative control"}
	if err := fixtureContract(&fx, t.TempDir(), actor); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name string
		edit func(*ContractError)
	}{
		{"wrong stage", func(e *ContractError) { e.Stage = "compile" }},
		{"wrong code", func(e *ContractError) { e.Code = "not-schema" }},
		{"wrong message", func(e *ContractError) { e.Contains = "not-the-error" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := fx
			expected := *fx.ContractError
			f.ContractError = &expected
			change.edit(&expected)
			if err := fixtureContract(&f, t.TempDir(), actor); err == nil {
				t.Fatal("wrong error expectation accepted")
			}
		})
	}
	fx.Contract = strings.TrimSuffix(fx.Contract, "unknown_contract_key: []\n")
	if err := fixtureContract(&fx, t.TempDir(), actor); err == nil {
		t.Fatal("expected load error accepted a valid contract")
	}
}

func TestFixtureContractExpectedCompileError(t *testing.T) {
	actor, err := os.ReadFile(loaderProgram)
	if err != nil {
		t.Fatal(err)
	}
	var fx Fixture
	for _, candidate := range Fixtures() {
		if hasCompileRow(&candidate) {
			fx = candidate
			break
		}
	}
	if fx.Name == "" {
		t.Fatal("no fixture with compile rows")
	}
	fx.Contract = strings.ReplaceAll(fx.Contract, "{{P}}/bin/actor", "missing-conformance-program")
	fx.ContractError = &ContractError{Stage: "compile", Code: agent.CodeExecNotOnPath, Contains: "missing-conformance-program", Why: "compiler negative control"}
	if err := fixtureContract(&fx, t.TempDir(), actor); err != nil {
		t.Fatal(err)
	}
	fx.ContractError = nil
	if err := fixtureContract(&fx, t.TempDir(), actor); err == nil {
		t.Fatal("invalid compile without metadata accepted")
	}
}
