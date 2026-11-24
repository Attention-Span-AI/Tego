// SPDX-License-Identifier: Apache-2.0
package record

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestNewerMajorBaselineRemainsOpaque(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Split(data, []byte{'\n'})[0]
	line = bytes.Replace(line, []byte(`"v":1`), []byte(`"v":2`), 1)
	line = bytes.Replace(line, []byte(`"plane":""`), []byte(`"plane":null`), 1)
	if _, err := Decode(line); !errors.Is(err, ErrNewerVersion) {
		t.Fatalf("newer major interpreted as v1 baseline: %v", err)
	}
}
