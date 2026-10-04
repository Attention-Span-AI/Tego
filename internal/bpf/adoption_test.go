// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf/adoptionmeta"
)

func TestLoadAdoptionDigestFallback(t *testing.T) {
	raw := []byte("the exact embedded ELF")
	metadata := adoptionmeta.Spec{Version: adoptionmeta.Version, Maps: map[string]*adoptionmeta.Map{
		"map": {Name: "map", Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 16, Pinning: ebpf.PinByName}},
		Programs: map[string]adoptionmeta.Program{"prog": {Name: "prog", Type: ebpf.LSM}}}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		key     [32]byte
		data    string
		compact bool
	}{
		{"matching bytes", sha256.Sum256(raw), string(encoded), true},
		{"stale ELF", sha256.Sum256([]byte("old ELF")), string(encoded), false},
		{"malformed metadata", sha256.Sum256(raw), "{", false},
		{"unknown schema", sha256.Sum256(raw), `{"Version":999}`, false},
		{"incomplete schema", sha256.Sum256(raw), `{"Version":1}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			full := &ebpf.CollectionSpec{ByteOrder: binary.BigEndian}
			b := binding{raw: raw, load: func() (*ebpf.CollectionSpec, error) { calls++; return full, nil }}
			registry := map[[32]byte]string{tc.key: tc.data}
			got, compact, err := loadAdoptionBinding(b, registry)
			if err != nil || compact != tc.compact {
				t.Fatalf("compact=%v err=%v", compact, err)
			}
			if compact {
				if calls != 0 || got.Maps["map"].MaxEntries != 16 || len(got.Programs["prog"].Instructions) != 0 {
					t.Fatalf("unexpected compact result or full load: %+v calls=%d", got, calls)
				}
				got.Maps["map"].MaxEntries = 1
				again, _, err := loadAdoptionBinding(b, registry)
				if err != nil || again.Maps["map"].MaxEntries != 16 {
					t.Fatalf("result mutation leaked: %v", err)
				}
			} else if got != full || calls != 1 {
				t.Fatalf("full fallback did not return original loader's result: calls=%d", calls)
			}
		})
	}
	want := errors.New("ELF cannot load")
	_, compact, err := loadAdoptionBinding(binding{raw: raw, load: func() (*ebpf.CollectionSpec, error) {
		return nil, want
	}}, nil)
	if compact || !errors.Is(err, want) {
		t.Fatalf("fallback hid original error: compact=%v err=%v", compact, err)
	}
}

func TestLoadAdoptionMissingObject(t *testing.T) {
	_, compact, err := LoadAdoption(Object("not-an-embedded-object"))
	if compact || !errors.Is(err, ErrNotGenerated) {
		t.Fatalf("compact=%v err=%v", compact, err)
	}
}
