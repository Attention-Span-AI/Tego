// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf/adoptionmeta"
)

func TestAdoptionMetadataMatchesEmbeddedELF(t *testing.T) {
	for group, registry := range map[string]map[Object]binding{
		"objects": generated, "plane": planeGenerated, "fill": planeFillGenerated, "reader": readerGenerated,
	} {
		for object, b := range registry {
			t.Run(group+"/"+string(object), func(t *testing.T) {
				full, err := b.load()
				if err != nil {
					t.Fatal(err)
				}
				got, compact, err := loadAdoptionBinding(b, adoptionMetadata)
				if err != nil || !compact {
					t.Fatalf("committed object has no matching descriptor: compact=%v err=%v", compact, err)
				}
				want, err := adoptionmeta.Project(full)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := adoptionmeta.Project(got)
				if err != nil || !reflect.DeepEqual(actual, want) {
					t.Fatalf("adoption checks differ from exact ELF: got %+v want %+v err=%v", actual, want, err)
				}
				if got.Types != nil || got.Variables != nil {
					t.Fatal("compact descriptor retained ELF/BTF graph")
				}
			})
		}
	}
}

func TestLoadAdoptionSelectsSameReader(t *testing.T) {
	for _, o := range Objects() {
		full, err := Load(o)
		if err != nil {
			t.Fatal(err)
		}
		got, compact, err := LoadAdoption(o)
		if err != nil || !compact {
			t.Fatalf("%s: compact=%v err=%v", o, compact, err)
		}
		want, err := adoptionmeta.Project(full)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := adoptionmeta.Project(got)
		if err != nil || !reflect.DeepEqual(actual, want) {
			t.Fatalf("%s: different reader/projection: %v", o, err)
		}
	}
}

func BenchmarkAdoptionSpecs(b *testing.B) {
	for _, object := range []Object{ObjectCgroupNet, ObjectCgroupTrack, ObjectTraceProc, ObjectPlaneProbe, ObjectUprobeSSL} {
		binding, ok := bindingOf(object)
		if !ok {
			continue
		}
		b.Run(string(object)+"/full", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := binding.load(); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(string(object)+"/compact", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, compact, err := loadAdoptionBinding(binding, adoptionMetadata); err != nil || !compact {
					b.Fatalf("compact=%v err=%v", compact, err)
				}
			}
		})
	}
}
