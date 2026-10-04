// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf/adoptionmeta"
)

// LoadAdoption returns a fresh specification for validating pinned objects. When
// compact is true it contains only map definitions and program names/types: it
// must never be used to create a collection or map, including an inner map.
// Call Load before any such creation or after adoption fails.
//
// Generated metadata is keyed by the full SHA-256 of this binding's embedded ELF.
// An absent, stale or unsupported descriptor falls back to the original loader
// with compact=false. Reader and architecture selection are the same as Load.
func LoadAdoption(o Object) (spec *ebpf.CollectionSpec, compact bool, err error) {
	b, ok := bindingOf(o)
	if !ok {
		return nil, false, fmt.Errorf("%w: %s", ErrNotGenerated, o)
	}
	if HasReaders(o) {
		b, err = readerBinding(o, KernelReader().Reader)
		if err != nil {
			return nil, false, err
		}
	}
	spec, compact, err = loadAdoptionBinding(b, adoptionMetadata)
	if err != nil {
		return nil, false, fmt.Errorf("bpf: load %s adoption: %w", o, err)
	}
	return spec, compact, nil
}

func loadAdoptionBinding(b binding, registry map[[sha256.Size]byte]string) (*ebpf.CollectionSpec, bool, error) {
	if data, ok := registry[sha256.Sum256(b.raw)]; ok {
		var metadata adoptionmeta.Spec
		if err := json.Unmarshal([]byte(data), &metadata); err == nil {
			if spec, err := metadata.Collection(); err == nil {
				return spec, true, nil
			}
		}
	}
	spec, err := b.load()
	return spec, false, err
}
