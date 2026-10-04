// SPDX-License-Identifier: Apache-2.0

package adoptionmeta

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestProjectionKeepsMapChecksAndIsNotLoadable(t *testing.T) {
	inner := &ebpf.MapSpec{Name: "inner", Type: ebpf.Hash, KeySize: 8, ValueSize: 56, MaxEntries: 4096,
		Flags: 1, NumaNode: 4, MapExtra: 123, Tags: []string{"test"},
		Key: &btf.Int{Size: 8}, Value: &btf.Int{Size: 56}}
	outer := &ebpf.MapSpec{Name: "truncated_name", Type: ebpf.HashOfMaps, KeySize: 4,
		ValueSize: 0, MaxEntries: 128, Flags: 2, Pinning: ebpf.PinByName, InnerMap: inner}
	full := &ebpf.CollectionSpec{ByteOrder: binary.BigEndian,
		Maps: map[string]*ebpf.MapSpec{"complete_map_name": outer,
			".bss": {Name: "bss", Type: ebpf.Array, KeySize: 4, ValueSize: 12, MaxEntries: 1,
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: make([]byte, 12)}}}},
		Programs: map[string]*ebpf.ProgramSpec{"complete_program_name": {Name: "debug_name", Type: ebpf.LSM}}}
	metadata, err := Project(full)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := metadata.Collection()
	if err != nil {
		t.Fatal(err)
	}
	want := outer.Copy()
	want.InnerMap.Key, want.InnerMap.Value = nil, nil
	if !reflect.DeepEqual(compact.Maps["complete_map_name"], want) {
		t.Fatalf("map definition changed: got %+v, want %+v", compact.Maps["complete_map_name"], want)
	}
	if compact.ByteOrder != binary.BigEndian || compact.Types != nil || compact.Variables != nil ||
		len(compact.Maps[".bss"].Contents) != 0 ||
		!reflect.DeepEqual(compact.Programs["complete_program_name"], full.Programs["complete_program_name"]) {
		t.Fatal("compact projection lost identity/byte order or retained load-only contents")
	}
	compact.Maps["complete_map_name"].InnerMap.Tags[0] = "changed"
	compact.Maps["complete_map_name"].InnerMap.MaxEntries = 1
	again, err := metadata.Collection()
	if err != nil || again.Maps["complete_map_name"].InnerMap.Tags[0] != "test" ||
		again.Maps["complete_map_name"].InnerMap.MaxEntries != 4096 || inner.Tags[0] != "test" {
		t.Fatalf("compact result aliases metadata/full spec: %v", err)
	}
}

func TestProjectionRejectsUnsupportedInitialization(t *testing.T) {
	valid := func() *ebpf.MapSpec {
		return &ebpf.MapSpec{Name: "data", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1,
			Contents: []ebpf.MapKV{{Key: uint32(0), Value: []byte{1, 2, 3, 4}}}}
	}
	for _, tc := range []struct {
		name   string
		key    string
		change func(*ebpf.MapSpec)
	}{
		{"ordinary initial values", "values", func(*ebpf.MapSpec) {}},
		{"pinned globals", ".data", func(m *ebpf.MapSpec) { m.Pinning = ebpf.PinByName }},
		{"global map reference", ".data", func(m *ebpf.MapSpec) { m.Contents[0].Value = "map_name" }},
		{"wrong global key", ".data", func(m *ebpf.MapSpec) { m.Contents[0].Key = uint32(1) }},
		{"wrong global size", ".data", func(m *ebpf.MapSpec) { m.ValueSize = 8 }},
		{"extra definition bytes", ".data", func(m *ebpf.MapSpec) { m.Extra = bytes.NewReader([]byte{1}) }},
		{"initialized inner", ".data", func(m *ebpf.MapSpec) { m.InnerMap = valid() }},
		{"recursive inner", ".data", func(m *ebpf.MapSpec) { m.Contents = nil; m.InnerMap = m }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := valid()
			tc.change(m)
			_, err := Project(&ebpf.CollectionSpec{ByteOrder: binary.LittleEndian, Maps: map[string]*ebpf.MapSpec{tc.key: m}})
			if err == nil {
				t.Fatal("unsupported initialization accepted")
			}
		})
	}
}

func TestCollectionRefusesInvalidMetadata(t *testing.T) {
	for _, spec := range []*Spec{nil, {Version: Version + 1}, {Version: Version},
		{Version: Version, Programs: map[string]Program{"p": {}}},
		{Version: Version, Programs: map[string]Program{"p": {Type: ebpf.LSM}}, Maps: map[string]*Map{"m": nil}},
		{Version: Version, Programs: map[string]Program{"p": {Type: ebpf.LSM}}, Maps: map[string]*Map{"m": {}}},
	} {
		if _, err := spec.Collection(); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
}

// A dependency upgrade introducing another map definition field requires an
// explicit projection decision before adoption can omit that field.
func TestMapSpecProjectionFields(t *testing.T) {
	known := map[string]bool{}
	for _, name := range []string{"Name", "Type", "KeySize", "ValueSize", "MaxEntries", "Flags", "Pinning",
		"NumaNode", "Contents", "InnerMap", "MapExtra", "Extra", "Key", "Value", "Tags"} {
		known[name] = true
	}
	typ := reflect.TypeFor[ebpf.MapSpec]()
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; !known[name] {
			t.Errorf("MapSpec.%s needs an explicit adoption projection decision", name)
		}
	}
}
