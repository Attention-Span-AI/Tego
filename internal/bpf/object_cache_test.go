// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func cacheFixture() *ebpf.CollectionSpec {
	fn := &btf.Func{Name: "entry", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}, Params: []btf.FuncParam{}}, Tags: []string{"tag"}}
	inner := &ebpf.MapSpec{Name: "inner", Contents: []ebpf.MapKV{{Key: []byte{1}, Value: []byte{2}}}}
	inner.InnerMap = inner
	return &ebpf.CollectionSpec{
		ByteOrder: binary.BigEndian,
		Maps: map[string]*ebpf.MapSpec{"map": {
			Name: "map", MaxEntries: 8, Pinning: ebpf.PinByName, InnerMap: inner,
			Contents: []ebpf.MapKV{{Key: uint32(0), Value: []byte{3, 4}}},
			Value:    &btf.Struct{Name: "value", Size: 4, Members: []btf.Member{{Name: "count", Type: &btf.Int{Size: 4}}}},
		}},
		Programs: map[string]*ebpf.ProgramSpec{"entry": {
			Name: "entry", AttachTo: "target",
			Instructions: asm.Instructions{btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 1), fn), asm.Return()},
		}},
		Variables: map[string]*ebpf.VariableSpec{"constant": {
			Name: "constant", SectionName: ".rodata", Value: []byte{5, 6, 7, 8},
			Type: &btf.Var{Name: "constant", Type: &btf.Int{Size: 4}},
		}},
	}
}

func mutateCachedSpec(spec *ebpf.CollectionSpec) {
	m := spec.Maps["map"]
	m.MaxEntries = 1
	m.Pinning = ebpf.PinNone
	m.Contents[0].Value.([]byte)[0] = 99
	m.Value.(*btf.Struct).Members[0].Name = "changed"
	m.InnerMap.Contents[0].Key.([]byte)[0] = 99
	m.InnerMap.Contents[0].Value.([]byte)[0] = 99
	p := spec.Programs["entry"]
	p.AttachTo = "changed"
	p.Instructions[0].Constant = 99
	fn := btf.FuncMetadata(&p.Instructions[0])
	fn.Name = "changed"
	fn.Tags[0] = "changed"
	fn.Type.(*btf.FuncProto).Return.(*btf.Int).Name = "changed"
	spec.Variables["constant"].Value[0] = 99
	spec.Variables["constant"].Type.Name = "changed"
}

func TestObjectSpecCacheParsesOnceAndDetachesMutableValues(t *testing.T) {
	pristine := cacheFixture()
	want := cacheFixture()
	calls := 0
	c := objectSpec{parse: func() (*ebpf.CollectionSpec, error) { calls++; return pristine, nil }}
	one, err := c.load()
	if err != nil {
		t.Fatal(err)
	}
	mutateCachedSpec(one)
	delete(one.Programs, "entry")
	delete(one.Maps, "map")
	two, err := c.load()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || one == two || !reflect.DeepEqual(two, want) || !reflect.DeepEqual(pristine, want) {
		t.Fatalf("calls=%d: caller rewrites contaminated a later spec or the cache", calls)
	}
	if two.Maps["map"].InnerMap.InnerMap != two.Maps["map"].InnerMap {
		t.Fatal("inner-map self reference was not preserved")
	}
}

func TestObjectSpecCacheConcurrentLoads(t *testing.T) {
	var calls atomic.Int32
	c := objectSpec{parse: func() (*ebpf.CollectionSpec, error) {
		calls.Add(1)
		return cacheFixture(), nil
	}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			<-start
			spec, err := c.load()
			if err != nil {
				t.Error(err)
				return
			}
			if !reflect.DeepEqual(spec, cacheFixture()) {
				t.Error("another caller's writes contaminated this spec")
			}
			mutateCachedSpec(spec)
		})
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("parsed %d times", calls.Load())
	}
	got, err := c.load()
	if err != nil || !reflect.DeepEqual(got, cacheFixture()) {
		t.Fatalf("concurrent rewrites contaminated pristine spec: %v", err)
	}
}

func TestObjectSpecCachePreservesParseErrors(t *testing.T) {
	want := errors.New("invalid embedded ELF")
	calls := 0
	c := objectSpec{parse: func() (*ebpf.CollectionSpec, error) { calls++; return nil, want }}
	for range 3 {
		if spec, err := c.load(); spec != nil || !errors.Is(err, want) {
			t.Fatalf("spec=%v err=%v, want original parse error", spec, err)
		}
	}
	if calls != 1 {
		t.Fatalf("immutable invalid ELF parsed %d times", calls)
	}
}

func TestObjectSpecCacheAdoptionFallback(t *testing.T) {
	calls := 0
	c := objectSpec{parse: func() (*ebpf.CollectionSpec, error) { calls++; return cacheFixture(), nil }}
	b := binding{raw: []byte("embedded ELF"), load: c.load}
	one, compact, err := loadAdoptionBinding(b, nil)
	if err != nil || compact {
		t.Fatalf("compact=%v err=%v", compact, err)
	}
	mutateCachedSpec(one)
	two, compact, err := loadAdoptionBinding(b, nil)
	if err != nil || compact || calls != 1 || !reflect.DeepEqual(two, cacheFixture()) {
		t.Fatalf("full adoption fallback lost independent cached copy: compact=%v calls=%d err=%v", compact, calls, err)
	}
}

func TestObjectSpecRegistryIsBounded(t *testing.T) {
	before := len(objectSpecs())
	for i := range 100 {
		if _, err := LoadReader(Object("unknown"), Reader(string(rune(i)))); !errors.Is(err, ErrNotGenerated) {
			t.Fatalf("unknown object load: %v", err)
		}
	}
	if got := len(objectSpecs()); got != before {
		t.Fatalf("caller strings grew cache from %d to %d", before, got)
	}
	for key := range objectSpecs() {
		if key.rdonly {
			if _, ok := readerGenerated[key.object]; !ok {
				t.Fatalf("unregistered reader variant cached: %+v", key)
			}
		} else if _, ok := bindingOf(key.object); !ok {
			t.Fatalf("unregistered object cached: %+v", key)
		}
	}
}
