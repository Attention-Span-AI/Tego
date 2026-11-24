// SPDX-License-Identifier: Apache-2.0

//go:build linux && (386 || amd64 || arm64)

package doctor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestCaptureTranslatedDumpFixtures exercises the stock guest dump encoder on
// authentic translated streams, including helpers encoded as relative offsets.
// Byte identity preserves the provenance hashes used by the row acceptance test.
func TestCaptureTranslatedDumpFixtures(t *testing.T) {
	root := filepath.Join("..", "bpf", "testdata", "capture-stack")
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest []struct {
		Row, Program, Fixture, SHA256 string
		Bytes                         int
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 64 {
		t.Fatalf("got %d fixtures, want 64", len(manifest))
	}
	for _, f := range manifest {
		t.Run(f.Row+"/"+f.Program, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, f.Fixture))
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != f.Bytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != f.SHA256 {
				t.Fatal("fixture length or digest differs from provenance manifest")
			}
			insns, err := asm.AppendInstructions(nil, bytes.NewReader(raw), binary.LittleEndian, "linux")
			if err != nil {
				t.Fatal(err)
			}
			dumped, err := marshalCaptureInstructions(insns)
			if err != nil {
				t.Fatalf("encode translated instructions: %v", err)
			}
			if !bytes.Equal(dumped, raw) {
				t.Fatal("dump changed kernel bytes")
			}
		})
	}
}
