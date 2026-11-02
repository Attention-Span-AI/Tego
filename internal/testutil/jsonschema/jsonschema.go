// SPDX-License-Identifier: Apache-2.0

// Package jsonschema validates a document against a JSON Schema file with the real validator
// (github.com/santhosh-tekuri/jsonschema/v6, Apache-2.0), for tests only. The schemas under spec/ are the
// published contract; pkg/spec/agent's agreement tests hold their shape equal to the Go types, and this package
// is the other half: it proves the schema, read by an independent implementation of JSON Schema 2020-12,
// accepts the documents the repository ships and refuses the ones it must. A hand-written validator would prove
// only our own reading of the standard.
//
// Only _test.go files import this package, as for the rest of internal/testutil (depguard
// testutil-never-in-binary), and TestValidatorNotInBinary holds the validator module out of cmd/tego's link
// closure, so the module stays a test dependency: it is in go.mod and go.sum, never in a shipped binary and
// never in THIRD_PARTY_NOTICES.txt.
//
// Imports: the standard library and the validator module. Must not import anything under internal/ or pkg/.
package jsonschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"
)

// Validate fails t, with every violation the validator reports, when doc does not satisfy the JSON Schema in the
// file at schemaPath. doc is any value encoding/json can marshal (a decoded YAML or JSON document, a struct):
// it is validated as the JSON it encodes to, so the key names are the JSON ones.
func Validate(t testing.TB, schemaPath string, doc any) {
	t.Helper()
	if err := Check(schemaPath, doc); err != nil {
		t.Errorf("%v", err)
	}
}

// Check is Validate's result as an error, for a test that expects a refusal: nil when doc satisfies the schema,
// an error naming the file and each violation when it does not or when the schema itself cannot be compiled.
func Check(schemaPath string, doc any) error {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("jsonschema: read schema: %w", err)
	}
	schemaDoc, err := js.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("jsonschema: %s is not JSON: %w", schemaPath, err)
	}
	c := js.NewCompiler()
	c.DefaultDraft(js.Draft2020)
	if err := c.AddResource(schemaPath, schemaDoc); err != nil {
		return fmt.Errorf("jsonschema: %s: %w", schemaPath, err)
	}
	schema, err := c.Compile(schemaPath)
	if err != nil {
		return fmt.Errorf("jsonschema: compile %s: %w", schemaPath, err)
	}
	enc, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("jsonschema: the document is not JSON: %w", err)
	}
	inst, err := js.UnmarshalJSON(bytes.NewReader(enc))
	if err != nil {
		return fmt.Errorf("jsonschema: re-read the document: %w", err)
	}
	if err := schema.Validate(inst); err != nil {
		var ve *js.ValidationError
		if errors.As(err, &ve) {
			return fmt.Errorf("document does not satisfy %s:\n%#v", schemaPath, ve)
		}
		return fmt.Errorf("jsonschema: validate against %s: %w", schemaPath, err)
	}
	return nil
}
