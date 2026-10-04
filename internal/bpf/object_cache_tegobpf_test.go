// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Exercise every actual embedded variant, including the plane/fill and reader
// builds. A directly parsed reference proves the cache preserves object shape,
// instruction/relocation metadata, constants and ELF byte order.
func TestObjectSpecCacheEmbeddedMutationIsolation(t *testing.T) {
	for key, entry := range objectSpecs() {
		t.Run(fmt.Sprintf("%s/rdonly=%v", key.object, key.rdonly), func(t *testing.T) {
			want, err := entry.parse()
			if err != nil {
				t.Fatal(err)
			}
			one, err := entry.load()
			if err != nil {
				t.Fatal(err)
			}
			assertParsedSpec(t, one, want)
			mutateEmbeddedSpec(t, one)
			two, err := entry.load()
			if err != nil {
				t.Fatal(err)
			}
			assertParsedSpec(t, two, want)
		})
	}
}

func TestObjectSpecCacheEmbeddedConcurrentMutation(t *testing.T) {
	// Trace has data sections, variables, CO-RE metadata and both reader builds.
	for _, reader := range []Reader{ReaderProbe, ReaderRdonly} {
		t.Run(string(reader), func(t *testing.T) {
			want, err := LoadReader(ObjectTraceProc, reader)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					spec, err := LoadReader(ObjectTraceProc, reader)
					if err != nil {
						t.Error(err)
						return
					}
					assertParsedSpec(t, spec, want)
					mutateEmbeddedSpec(t, spec)
				})
			}
			wg.Wait()
			after, err := LoadReader(ObjectTraceProc, reader)
			if err != nil {
				t.Fatal(err)
			}
			assertParsedSpec(t, after, want)
		})
	}
}

func TestObjectSpecCacheReaderFallbackUsesRegisteredVariant(t *testing.T) {
	before := len(objectSpecs())
	for _, object := range []Object{ObjectTraceProc, ObjectCgroupTrack} {
		base, err := readerBinding(object, ReaderProbe)
		if err != nil {
			t.Fatal(err)
		}
		want, err := base.load()
		if err != nil {
			t.Fatal(err)
		}
		for _, reader := range []Reader{"future-reader", "", ReaderRdonly} {
			if object == ObjectTraceProc && reader == ReaderRdonly {
				continue // This object actually has a separate rdonly variant.
			}
			got, err := LoadReader(object, reader)
			if err != nil {
				t.Fatal(err)
			}
			assertParsedSpec(t, got, want)
		}
	}
	if got := len(objectSpecs()); got != before {
		t.Fatalf("reader fallback grew cache from %d to %d", before, got)
	}
}

func assertParsedSpec(t *testing.T, got, want *ebpf.CollectionSpec) {
	t.Helper()
	if got.ByteOrder != want.ByteOrder || len(got.Maps) != len(want.Maps) || len(got.Programs) != len(want.Programs) || len(got.Variables) != len(want.Variables) {
		t.Fatal("parsed collection shape or byte order changed")
	}
	var compareMap func(*ebpf.MapSpec, *ebpf.MapSpec)
	compareMap = func(a, b *ebpf.MapSpec) {
		if a == nil || b == nil {
			if a != b {
				t.Fatal("inner-map shape changed")
			}
			return
		}
		if a.Name != b.Name || a.Type != b.Type || a.KeySize != b.KeySize || a.ValueSize != b.ValueSize || a.MaxEntries != b.MaxEntries || a.Flags != b.Flags || a.Pinning != b.Pinning || !reflect.DeepEqual(a.Contents, b.Contents) || !reflect.DeepEqual(a.Tags, b.Tags) {
			t.Fatalf("map %s changed after cached load", b.Name)
		}
		if a.InnerMap != a && b.InnerMap != b {
			compareMap(a.InnerMap, b.InnerMap)
		} else if (a.InnerMap == a) != (b.InnerMap == b) {
			t.Fatal("inner-map self reference changed")
		}
	}
	for name, m := range want.Maps {
		compareMap(got.Maps[name], m)
	}
	for name, variable := range want.Variables {
		v := got.Variables[name]
		if v == nil || v.Name != variable.Name || v.SectionName != variable.SectionName || v.Offset != variable.Offset || !reflect.DeepEqual(v.Value, variable.Value) {
			t.Fatalf("variable %s changed after cached load", name)
		}
	}
	for name, program := range want.Programs {
		p := got.Programs[name]
		if p == nil {
			t.Fatalf("program %s disappeared", name)
		}
		a, b := *p, *program
		a.Instructions, b.Instructions = nil, nil
		if !reflect.DeepEqual(a, b) || len(p.Instructions) != len(program.Instructions) {
			t.Fatalf("program %s shape changed", name)
		}
		for i := range program.Instructions {
			a, b := p.Instructions[i], program.Instructions[i]
			fnA, fnB := btf.FuncMetadata(&a), btf.FuncMetadata(&b)
			reloA, reloB := btf.CORERelocationMetadata(&a), btf.CORERelocationMetadata(&b)
			if fmt.Sprint(fnA) != fmt.Sprint(fnB) || fmt.Sprint(reloA) != fmt.Sprint(reloB) || a.Symbol() != b.Symbol() || a.Reference() != b.Reference() || fmt.Sprint(a.Source()) != fmt.Sprint(b.Source()) {
				t.Fatalf("program %s instruction%d ELF metadata changed", name, i)
			}
			a.Metadata, b.Metadata = asm.Metadata{}, asm.Metadata{}
			if a != b {
				t.Fatalf("program %s instruction%d changed", name, i)
			}
		}
	}
}

func mutateEmbeddedSpec(t *testing.T, spec *ebpf.CollectionSpec) {
	t.Helper()
	seen := make(map[*ebpf.MapSpec]bool)
	var mutateMap func(*ebpf.MapSpec)
	mutateMap = func(m *ebpf.MapSpec) {
		if m == nil || seen[m] {
			return
		}
		seen[m] = true
		m.Name = "changed"
		m.Pinning = ebpf.PinNone
		m.MaxEntries = 1
		for i := range m.Contents {
			// Pin the actual parser's content contract. A future mutable form must
			// be detached before it can be admitted to the pristine cache.
			for _, value := range []any{m.Contents[i].Key, m.Contents[i].Value} {
				switch v := value.(type) {
				case []byte:
					if len(v) > 0 {
						v[0] ^= 0xff
					}
				case string, uint32, int, nil:
				default:
					t.Errorf("unreviewed parsed MapKV value %T", value)
				}
			}
		}
		mutateMap(m.InnerMap)
	}
	for _, m := range spec.Maps {
		mutateMap(m)
	}
	for _, v := range spec.Variables {
		v.Name = "changed"
		if len(v.Value) > 0 {
			v.Value[0] ^= 0xff
		}
	}
	for _, p := range spec.Programs {
		p.AttachTo = "changed"
		p.Name = "changed"
		for i := range p.Instructions {
			ins := &p.Instructions[i]
			ins.Constant = 0
			if fn := btf.FuncMetadata(ins); fn != nil {
				fn.Name = "changed"
				if len(fn.Tags) > 0 {
					fn.Tags[0] = "changed"
				}
			}
		}
	}
}
