// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestContractsCLIListShowAndSchema(t *testing.T) {
	schema, err := filepath.Abs("../../spec/contracts/v1/contracts.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	w := newRegistryWorld(t)
	f := contracttest.Build(t, "version: 0\nname: fixture\ncommand: [fixture]\nenv: {pass: [PATH]}\nnet: {allow: []}\n", nil)
	t.Setenv("PATH", filepath.Join(f.Root, "bin"))
	data, err := os.ReadFile(f.Path("contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.user, "agents/fixture.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"contracts"}, {"contracts", "--verbose"}, {"contracts", "--json"}, {"contracts", "show", "fixture"}, {"contracts", "show", "fixture", "-v"}, {"contracts", "--json", "show", path}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out, errs := run(t, args...)
			if code != identity.ExitOK {
				t.Fatalf("exit %d stdout %s stderr %s", code, out, errs)
			}
			if strings.Contains(strings.Join(args, " "), "--json") {
				var doc any
				if err := json.Unmarshal([]byte(out), &doc); err != nil {
					t.Fatal(err)
				}
				jsonschema.Validate(t, schema, doc)
			} else if !strings.Contains(out, contracts.Footer) {
				t.Fatal("lost footer")
			}
		})
	}
	code, out, errs := run(t, "contracts", "show", "fixture", "-v")
	if code != 0 || !strings.Contains(out, "Compiled table (tego compile):") || !strings.Contains(out, "from contract "+path) {
		t.Fatalf("show exit %d %s %s", code, out, errs)
	}
	// An ambiguous name is refused; an explicit path is still usable.
	if err := os.WriteFile(filepath.Join(w.project, "agent.yaml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs = run(t, "contracts", "show", "fixture")
	if code != identity.ExitFinding || !strings.Contains(errs, "more than one") {
		t.Fatalf("ambiguity exit %d: %s", code, errs)
	}
	code, _, errs = run(t, "contracts", "show", path)
	if code != identity.ExitOK {
		t.Fatalf("path exit %d %s", code, errs)
	}
}

func TestContractsCLIUsageAndFailures(t *testing.T) {
	schema, err := filepath.Abs("../../spec/contracts/v1/contracts.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	newRegistryWorld(t)
	for _, args := range [][]string{{"contracts", "show"}, {"contracts", "show", ""}, {"contracts", "add"}, {"contracts", "show", "a", "b"}, {"contracts", "--force-break"}} {
		code, _, errs := run(t, args...)
		if code != identity.ExitUsage {
			t.Errorf("%v exit %d: %s", args, code, errs)
		}
	}
	code, out, errs := run(t, "contracts", "--json")
	if code != identity.ExitOK || !strings.Contains(out, `"contracts":[]`) {
		t.Fatalf("empty exit %d: %s %s", code, out, errs)
	}
	code, _, errs = run(t, "contracts", "show", "missing")
	if code != identity.ExitFinding || !strings.Contains(errs, "no contract named") {
		t.Fatalf("missing name exit %d %s", code, errs)
	}
	code, out, errs = run(t, "contracts", "show", "./missing.yaml", "--json")
	if code != identity.ExitFinding || !strings.Contains(out, `"state":"missing"`) {
		t.Fatalf("missing file exit %d: %s %s", code, out, errs)
	}
	cfg := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(cfg, []byte("not_a_config_key: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	code, out, errs = run(t, "contracts", "--json")
	if code != identity.ExitError {
		t.Fatalf("bad machine exit %d %s %s", code, out, errs)
	}
	var doc any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	jsonschema.Validate(t, schema, doc)
}

func TestContractsCLIOutputFailure(t *testing.T) {
	newRegistryWorld(t)
	m, _, err := loadMachine(config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	places, rerr := registryPlaces(m)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var errs bytes.Buffer
	code := runContracts(context.Background(), nil, contracts.Options{Machine: m, Places: places}, false, false, contractBrokenWriter{}, &errs)
	if code != identity.ExitError || !strings.Contains(errs.String(), "write output") {
		t.Fatalf("exit %d %s", code, errs.String())
	}
}

type contractBrokenWriter struct{}

func (contractBrokenWriter) Write(p []byte) (int, error) { return 0, errors.New("test broken output") }
