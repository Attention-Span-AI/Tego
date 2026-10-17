// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// This checks every committed endian/architecture variant, including ones this
// host cannot execute, and proves the generated registry is reproducible.
func TestCommittedRegistry(t *testing.T) {
	out := filepath.Join(t.TempDir(), "registry.go")
	if err := generate("../../internal/bpf", out); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../internal/bpf/adoption_specs_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("adoption metadata is stale: go run ./tools/adoptiongen from the repository root")
	}
}

func TestGenerationRejectsMissingAndBrokenELF(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "registry.go")
	if err := generate(dir, out); err == nil {
		t.Fatal("empty input accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "broken_bpfel.o"), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := generate(dir, out); err == nil {
		t.Fatal("malformed ELF accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed generation wrote output: %v", err)
	}
}
