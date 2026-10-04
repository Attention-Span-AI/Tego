// SPDX-License-Identifier: Apache-2.0

// Package adoptionmeta projects embedded ELF specifications into the metadata
// needed to validate pinned objects. Its output cannot create kernel objects.
package adoptionmeta

import (
	"encoding/binary"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
)

// Spec describes adoption checks without instructions, relocations or BTF.
// Version changes whenever the interpretation or supported projection changes.
type Spec struct {
	Version   int
	BigEndian bool
	Maps      map[string]*Map
	Programs  map[string]Program
}

const Version = 1

// Map retains every scalar map definition and recursively its inner template.
// Key/value BTF and global data contents are deliberately absent: a caller must
// load the original ELF before creating any map, including an inner template.
type Map struct {
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Pinning    ebpf.PinType
	NumaNode   uint32
	MapExtra   uint64
	Tags       []string `json:",omitempty"`
	InnerMap   *Map     `json:",omitempty"`
}

// Program retains the identity and type checked when opening a pinned program.
type Program struct {
	Name string
	Type ebpf.ProgramType
}

// Project rejects definitions whose initialization cannot be represented safely
// for adoption. A rejected object must use the original full ELF loader.
func Project(spec *ebpf.CollectionSpec) (*Spec, error) {
	if spec == nil || (spec.ByteOrder != binary.LittleEndian && spec.ByteOrder != binary.BigEndian) {
		return nil, fmt.Errorf("adoption metadata: missing spec or byte order")
	}
	out := &Spec{Version: Version, BigEndian: spec.ByteOrder == binary.BigEndian,
		Maps: make(map[string]*Map, len(spec.Maps)), Programs: make(map[string]Program, len(spec.Programs))}
	for _, name := range slices.Sorted(maps.Keys(spec.Maps)) {
		m := spec.Maps[name]
		projected, err := projectMap(name, m, 0)
		if err != nil {
			return nil, err
		}
		out.Maps[name] = projected
	}
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		p := spec.Programs[name]
		if name == "" || p == nil || p.Type == ebpf.UnspecifiedProgram {
			return nil, fmt.Errorf("adoption metadata: invalid program %q", name)
		}
		out.Programs[name] = Program{Name: p.Name, Type: p.Type}
	}
	return out, nil
}

func projectMap(name string, m *ebpf.MapSpec, depth int) (*Map, error) {
	if name == "" || m == nil || m.Type == ebpf.UnspecifiedMap || depth > 8 {
		return nil, fmt.Errorf("adoption metadata: invalid map %q or recursive template", name)
	}
	if m.Extra != nil && m.Extra.Size() != 0 {
		return nil, fmt.Errorf("adoption metadata: map %q has extra definition bytes", name)
	}
	if len(m.Contents) != 0 && !(depth == 0 && globalData(name, m)) {
		return nil, fmt.Errorf("adoption metadata: map %q has unsupported initial contents", name)
	}
	out := &Map{Name: m.Name, Type: m.Type, KeySize: m.KeySize, ValueSize: m.ValueSize,
		MaxEntries: m.MaxEntries, Flags: m.Flags, Pinning: m.Pinning, NumaNode: m.NumaNode,
		MapExtra: m.MapExtra, Tags: append([]string(nil), m.Tags...)}
	if m.InnerMap != nil {
		inner, err := projectMap(name+"/inner", m.InnerMap, depth+1)
		if err != nil {
			return nil, err
		}
		out.InnerMap = inner
	}
	return out, nil
}

// An object's unpinned global sections are checked by map shape, never read or
// initialized by adoption. Other map contents may encode map/program references
// and must not be dropped from a compact descriptor.
func globalData(name string, m *ebpf.MapSpec) bool {
	if !strings.HasPrefix(name, ".") || m.Pinning != ebpf.PinNone || m.Type != ebpf.Array ||
		m.KeySize != 4 || m.MaxEntries != 1 || len(m.Contents) != 1 {
		return false
	}
	key, ok := m.Contents[0].Key.(uint32)
	value, bytes := m.Contents[0].Value.([]byte)
	return ok && key == 0 && bytes && uint64(len(value)) == uint64(m.ValueSize)
}

// Collection returns a fresh adoption-only spec. The absence of instructions,
// BTF and initial contents makes this unsuitable for any kernel object creation.
func (s *Spec) Collection() (*ebpf.CollectionSpec, error) {
	if s == nil || s.Version != Version || len(s.Programs) == 0 {
		return nil, fmt.Errorf("adoption metadata: unsupported version or empty program set")
	}
	result := &ebpf.CollectionSpec{Maps: make(map[string]*ebpf.MapSpec, len(s.Maps)),
		Programs: make(map[string]*ebpf.ProgramSpec, len(s.Programs)), ByteOrder: binary.LittleEndian}
	if s.BigEndian {
		result.ByteOrder = binary.BigEndian
	}
	for name, m := range s.Maps {
		ms, err := m.spec(name, 0)
		if err != nil {
			return nil, err
		}
		result.Maps[name] = ms
	}
	for name, p := range s.Programs {
		if name == "" || p.Type == ebpf.UnspecifiedProgram {
			return nil, fmt.Errorf("adoption metadata: invalid program %q", name)
		}
		result.Programs[name] = &ebpf.ProgramSpec{Name: p.Name, Type: p.Type}
	}
	return result, nil
}

func (m *Map) spec(name string, depth int) (*ebpf.MapSpec, error) {
	if name == "" || m == nil || m.Type == ebpf.UnspecifiedMap || depth > 8 {
		return nil, fmt.Errorf("adoption metadata: invalid map %q or recursive template", name)
	}
	result := &ebpf.MapSpec{Name: m.Name, Type: m.Type, KeySize: m.KeySize, ValueSize: m.ValueSize,
		MaxEntries: m.MaxEntries, Flags: m.Flags, Pinning: m.Pinning, NumaNode: m.NumaNode,
		MapExtra: m.MapExtra, Tags: append([]string(nil), m.Tags...)}
	if m.InnerMap != nil {
		inner, err := m.InnerMap.spec(name+"/inner", depth+1)
		if err != nil {
			return nil, err
		}
		result.InnerMap = inner
	}
	return result, nil
}
