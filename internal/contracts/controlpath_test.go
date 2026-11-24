// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestContractsControlCharacterPathsAreEscapedAndRoundTrip(t *testing.T) {
	f, o := fixture(t)
	project := f.Path("registry\x1b[31m\nproject")
	registryPath := filepath.Join(project, "agent.yaml")
	recordedPath := f.Path("recorded\x1b[31m\ncontract.yaml")
	write(t, registryPath, simpleContract)
	write(t, recordedPath, strings.Replace(simpleContract, "name: fixture", "name: recorded", 1))
	o.Places.Dir = project
	o.Snapshot.Runs = append(o.Snapshot.Runs, run(recordedPath, f.Root, "recorded", "", "landlock", metadataRunID))
	c := Discover(context.Background(), o)
	for _, tc := range []struct {
		path string
		from string
	}{{registryPath, "project"}, {recordedPath, "run"}} {
		e, err := c.Select(tc.path)
		if err != nil || e.State != "compiles" || !strings.Contains(strings.Join(e.FoundIn, ","), tc.from) {
			t.Fatalf("control path did not pass through %s discovery: path %q, entry %+v, error %v", tc.from, tc.path, e, err)
		}
	}
	for _, verbose := range []bool{false, true} {
		var text bytes.Buffer
		if err := PrintList(&text, c, verbose); err != nil {
			t.Fatal(err)
		}
		assertEscapedControlPath(t, text.Bytes(), registryPath, recordedPath)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Catalog
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{registryPath, recordedPath} {
		if _, err := decoded.Select(path); err != nil {
			t.Fatalf("JSON did not preserve path %q: %v", path, err)
		}
	}
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", decoded)
	for _, path := range []string{registryPath, recordedPath} {
		// Retain the selected table, so PrintShow -v also exercises the real
		// compiler table and provenance path printer, not a synthetic Show.
		o.KeepTableFor = path
		one := Discover(context.Background(), o)
		e, err := one.Select(path)
		if err != nil {
			t.Fatal(err)
		}
		show, err := one.Describe(*e)
		if err != nil {
			t.Fatal(err)
		}
		if show.Table == "" {
			t.Fatal("verbose show fixture has no compiled table")
		}
		var text bytes.Buffer
		if err := PrintShow(&text, show, true); err != nil {
			t.Fatal(err)
		}
		assertEscapedControlPath(t, text.Bytes(), path)
		encoded, err := json.Marshal(show)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Show
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Contract.Path != path {
			t.Fatalf("show JSON changed path: got %q, want %q", decoded.Contract.Path, path)
		}
		jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", decoded)
	}
}

func assertEscapedControlPath(t *testing.T, text []byte, paths ...string) {
	t.Helper()
	for i, b := range text {
		if b < 0x20 && b != '\n' && b != '\t' {
			t.Errorf("text contains raw control byte %#x at %d", b, i)
		}
	}
	for _, path := range paths {
		if bytes.Contains(text, []byte(path)) || !bytes.Contains(text, []byte(record.Printable(path))) {
			t.Errorf("text did not escape path %q", path)
		}
	}
}
