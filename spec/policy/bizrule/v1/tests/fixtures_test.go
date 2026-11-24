// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
)

// TestFixtureForm checks B060 and W020: complete schema-valid files, distinct IDs
// and real requirement citations, coverage inventory and canonical byte examples.
// It never derives or compares policy answers.
func TestFixtureForm(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(root, "schema.json")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := js.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := js.NewCompiler()
	c.DefaultDraft(js.Draft2020)
	if err := c.AddResource(schemaPath, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	requirements := map[string]bool{}
	ids := regexp.MustCompile(`\*\*([BAW][0-9]{3})\.\*\*`)
	for _, name := range []string{"README.md", "WIRE.md", "ADAPTER.md"} {
		text, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range ids.FindAllSubmatch(text, -1) {
			requirements[string(match[1])] = true
		}
	}
	t.Run("canonical-string-literals", func(t *testing.T) {
		wire, err := os.ReadFile(filepath.Join(root, "WIRE.md"))
		if err != nil {
			t.Fatal(err)
		}
		match := regexp.MustCompile("backslash only as `([^`]+)` and `([^`]+)`").FindSubmatch(wire)
		if len(match) != 3 || string(match[1]) != `\"` || string(match[2]) != `\\` {
			t.Fatal("W002 must spell a quote and backslash with exactly their JSON escapes")
		}
	})
	t.Run("canonical-string-examples", func(t *testing.T) {
		wire, err := os.ReadFile(filepath.Join(root, "WIRE.md"))
		if err != nil {
			t.Fatal(err)
		}
		rows := regexp.MustCompile(`(?m)^\| (quote|backslash) \| ([0-9a-f]+) \| ([0-9a-f]+) \|$`).FindAllSubmatch(wire, -1)
		if len(rows) != 2 {
			t.Fatalf("need two exact W002 string byte examples, found %d", len(rows))
		}
		wantValues := map[string]string{"quote": "22", "backslash": "5c"}
		for _, row := range rows {
			if wantValues[string(row[1])] != string(row[3]) {
				t.Fatalf("missing, repeated or incorrect decoded value for %s", row[1])
			}
			delete(wantValues, string(row[1]))
			encoded, err := hex.DecodeString(string(row[2]))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := hex.DecodeString(string(row[3]))
			if err != nil {
				t.Fatal(err)
			}
			var value string
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatal(err)
			}
			if value != string(decoded) {
				t.Errorf("%s: JSON bytes decode to %x, want %x", row[1], value, decoded)
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(canonical, encoded) {
				t.Errorf("%s: nonminimal JSON string bytes %x", row[1], encoded)
			}
		}
	})
	files, err := filepath.Glob(filepath.Join(root, "vectors", "*", "*.json"))
	if err != nil || len(files) < 80 {
		t.Fatalf("fixture inventory: %d files, error %v; need at least 80", len(files), err)
	}
	seen := map[string]bool{}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			value, err := js.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(value); err != nil {
				t.Fatalf("fixture form: %v", err)
			}
			var header struct {
				ID    string   `json:"id"`
				Group string   `json:"group"`
				Pins  []string `json:"pins"`
				Why   string   `json:"why"`
			}
			if err := json.Unmarshal(raw, &header); err != nil {
				t.Fatal(err)
			}
			if seen[header.ID] || filepath.Base(path) != header.ID+".json" || filepath.Base(filepath.Dir(path)) != header.Group {
				t.Fatalf("duplicate or misplaced fixture %q", header.ID)
			}
			seen[header.ID] = true
			cited := false
			for _, pin := range header.Pins {
				if !requirements[pin] {
					t.Errorf("unknown requirement %q", pin)
				}
				cited = cited || strings.Contains(header.Why, pin)
			}
			if !cited {
				t.Error("why names no pinned requirement")
			}
		})
	}
	t.Run("coverage-inventory", func(t *testing.T) {
		// Read all headers here so -run may select this check independently.
		coveragePins := map[string][]string{}
		for _, path := range files {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var header struct {
				ID   string   `json:"id"`
				Pins []string `json:"pins"`
			}
			if err := json.Unmarshal(raw, &header); err != nil {
				t.Fatal(err)
			}
			for _, pin := range header.Pins {
				coveragePins[pin] = append(coveragePins[pin], header.ID)
			}
		}
		raw, err := os.ReadFile(filepath.Join(root, "COVERAGE.md"))
		if err != nil {
			t.Fatal(err)
		}
		rows := regexp.MustCompile(`(?m)^\| ([BAW][0-9]{3}) \| [^|]+ \| ([^|]+) \|$`).FindAllSubmatch(raw, -1)
		seen := map[string]bool{}
		for _, row := range rows {
			id := string(row[1])
			if !requirements[id] || seen[id] {
				t.Errorf("unknown or repeated coverage row %s", id)
			}
			seen[id] = true
			sort.Strings(coveragePins[id])
			want := strings.Join(coveragePins[id], ", ")
			if want == "" {
				want = "Implementation acceptance required"
			}
			if got := string(row[2]); got != want {
				t.Errorf("%s coverage inventory: got %q, want %q", id, got, want)
			}
		}
		for id := range requirements {
			if !seen[id] {
				t.Errorf("missing coverage row %s", id)
			}
		}
	})
}
