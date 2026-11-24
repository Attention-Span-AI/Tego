// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestGeneralSourceIsObservationOnly(t *testing.T) {
	f, o := fixture(t)
	write(t, filepath.Join(f.Root, "agent.yaml"), simpleContract)
	before := Discover(context.Background(), o)
	var beforeText bytes.Buffer
	if err := PrintList(&beforeText, before, true); err != nil {
		t.Fatal(err)
	}
	o.General = &contractsrc.General{State: "absent"}
	absent := Discover(context.Background(), o)
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	absentJSON, err := json.Marshal(absent)
	if err != nil {
		t.Fatal(err)
	}
	var absentText bytes.Buffer
	if err := PrintList(&absentText, absent, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeJSON, absentJSON) || absentText.String() != beforeText.String() || absent.ExitCode() != before.ExitCode() {
		t.Fatal("absent general changed legacy JSON, text or exit")
	}
	owner := 1000
	o.General = &contractsrc.General{State: "loaded", Name: "shared", Scope: "Your agents on this machine", Hash: strings.Repeat("a", 64), Note: contractsrc.LoadedNote, Sources: []contractsrc.Source{{Layer: "system", State: config.LayerAbsent}, {Layer: "user", State: config.LayerPresent, Path: "/passwd-owner/.tego/general.yaml", SHA256: strings.Repeat("b", 64), Resolved: "/passwd-owner/.tego/general.yaml", Owner: &owner, Mode: "0600", Walk: []string{"/", "/passwd-owner", "/passwd-owner/.tego", "/passwd-owner/.tego/general.yaml"}}}, Profiles: []contractsrc.Profile{}}
	after := Discover(context.Background(), o)
	if after.General == nil || after.General.State != "loaded" || len(after.General.Hash) != 64 {
		t.Fatalf("missing general source: %+v", after.General)
	}
	if after.ExitCode() != before.ExitCode() || len(after.Contracts) != len(before.Contracts) {
		t.Fatal("general changed existing check")
	}
	beforeEntry, err := before.Select("fixture")
	if err != nil {
		t.Fatal(err)
	}
	afterEntry, err := after.Select("fixture")
	if err != nil {
		t.Fatal(err)
	}
	oldShow, err := before.Describe(*beforeEntry)
	if err != nil {
		t.Fatal(err)
	}
	newShow, err := after.Describe(*afterEntry)
	if err != nil {
		t.Fatal(err)
	}
	oldBytes, err := json.Marshal(oldShow)
	if err != nil {
		t.Fatal(err)
	}
	newBytes, err := json.Marshal(newShow)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldBytes, newBytes) || beforeEntry.State != "compiles" {
		t.Fatal("general source changed standalone compile/show bytes")
	}
	jsonschema.Validate(t, filepath.Join("..", "..", "spec", "contracts", "v1", "contracts.schema.json"), after)
	schema := filepath.Join("..", "..", "spec", "contracts", "v1", "contracts.schema.json")
	originalHash := o.General.Hash
	o.General.Hash = ""
	if err := jsonschema.Check(schema, after); err == nil {
		t.Fatal("loaded general accepted without a canonical digest")
	}
	o.General.Hash = originalHash
	var text bytes.Buffer
	if err := PrintList(&text, after, true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text.String(), "General contract: loaded\n") || !strings.Contains(text.String(), "Machine baseline: locked") || !strings.HasSuffix(text.String(), beforeText.String()) {
		t.Fatalf("general changed old list bytes: %s", text.String())
	}
	o.General.State = "unknown"
	o.General.Hash = ""
	o.General.Note = "General contract UNKNOWN: unsafe source"
	bad := Discover(context.Background(), o)
	if bad.General == nil || bad.General.State != "unknown" || bad.ExitCode() != before.ExitCode() {
		t.Fatalf("source problem changed standalone exit: %+v", bad)
	}
}
