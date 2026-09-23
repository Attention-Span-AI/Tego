// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// ErrNotGenerated is returned by Load, Hash and Raw when this binary was built without the compiled objects:
// they are embedded only under `-tags tegobpf` (the committed bpf2go output needs no clang; bpf/README.md),
// and ObjectUprobeSSL only on the architectures gen.go compiles it for. Callers turn it into a
// tier-unavailable diagnostic naming that fix, never into a panic.
var ErrNotGenerated = errors.New("bpf: object bindings are not generated")

// HashLen is the number of hex characters of Hash, the build identity that names a pin directory and a build
// lock (docs/p0/enforce-cgroup-observe.md §3, §5 R14).
const HashLen = 16

// binding is one generated object: its CollectionSpec loader and the raw ELF the hash is taken over. The map
// of bindings is defined exactly once, by objects_gen.go under the tegobpf tag or by objects_stub.go
// without it, and is never written after package initialization.
type binding struct {
	load func() (*ebpf.CollectionSpec, error)
	raw  []byte
}

// Available reports whether this binary carries the compiled objects.
func Available() bool { return len(generated) > 0 }

// Objects lists the objects this binary carries, sorted, or nothing when it carries none.
func Objects() []Object {
	out := make([]Object, 0, len(generated))
	for o := range generated {
		out = append(out, o)
	}
	sortObjects(out)
	return out
}

// sortObjects orders object names lexically, the order Hash folds them in.
func sortObjects(out []Object) { slices.SortFunc(out, compareObject) }

// bindingOf returns the registered object o: tier-2, plane or the plane's fill.
func bindingOf(o Object) (binding, bool) {
	if b, ok := generated[o]; ok {
		return cachedBinding(o, false, b), true
	}
	if b, ok := planeGenerated[o]; ok {
		return cachedBinding(o, false, b), true
	}
	b, ok := planeFillGenerated[o]
	if ok {
		b = cachedBinding(o, false, b)
	}
	return b, ok
}

// Load returns a fresh CollectionSpec for one object, tier-2 or plane. The embedded ELF is parsed once per
// registered build; callers receive independent copies and may rewrite maps, constants and programs without
// affecting later loads. An object compiled once per reader
// (HasReaders: trace_proc) is the build KernelReader picks for the running kernel; LoadReader names one.
func Load(o Object) (*ebpf.CollectionSpec, error) {
	b, ok := bindingOf(o)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotGenerated, o)
	}
	if HasReaders(o) {
		return LoadReader(o, KernelReader().Reader)
	}
	spec, err := b.load()
	if err != nil {
		return nil, fmt.Errorf("bpf: load %s: %w", o, err)
	}
	return spec, nil
}

type objectSpecKey struct {
	object Object
	rdonly bool
}

// The registry is fixed by the compiled objects, never by a caller-supplied object
// or reader string. Each entry parses independently, and construction waits until
// package initialization has completed, including architecture-specific bindings.
var objectSpecs = sync.OnceValue(func() map[objectSpecKey]*objectSpec {
	out := make(map[objectSpecKey]*objectSpec)
	for _, registry := range []map[Object]binding{generated, planeGenerated, planeFillGenerated} {
		for o, b := range registry {
			key := objectSpecKey{object: o}
			if _, exists := out[key]; !exists {
				out[key] = &objectSpec{parse: b.load}
			}
		}
	}
	for o, b := range readerGenerated {
		out[objectSpecKey{object: o, rdonly: true}] = &objectSpec{parse: b.load}
	}
	return out
})

// cachedBinding preserves the raw ELF identity. Its loader is also used by the
// full-spec fallback when compact adoption metadata is absent or stale.
func cachedBinding(o Object, rdonly bool, b binding) binding {
	b.load = objectSpecs()[objectSpecKey{object: o, rdonly: rdonly}].load
	return b
}

type objectSpec struct {
	once  sync.Once
	parse func() (*ebpf.CollectionSpec, error)
	spec  *ebpf.CollectionSpec
	err   error
}

func (c *objectSpec) load() (*ebpf.CollectionSpec, error) {
	c.once.Do(func() { c.spec, c.err = c.parse() })
	if c.err != nil {
		// Parsing only immutable embedded bytes has no transient dependencies.
		return nil, c.err
	}
	return copyObjectSpec(c.spec), nil
}

// CollectionSpec.Copy duplicates specs, variables and BTF. In the pinned ebpf
// library it deliberately leaves MapKV contents and instruction metadata values
// shallow. Detach the mutable values the ELF parser produces; the other content
// values are scalar keys or symbol names, and other ELF metadata has no mutable
// public fields. This helper is for pristine parsed ELF, not arbitrary populated
// collections containing live Map or Program objects.
func copyObjectSpec(pristine *ebpf.CollectionSpec) *ebpf.CollectionSpec {
	out := pristine.Copy()
	if out == nil {
		return nil
	}
	seen := make(map[*ebpf.MapSpec]bool)
	var detachMap func(*ebpf.MapSpec)
	detachMap = func(m *ebpf.MapSpec) {
		if m == nil || seen[m] {
			return
		}
		seen[m] = true
		for i := range m.Contents {
			if b, ok := m.Contents[i].Key.([]byte); ok {
				m.Contents[i].Key = slices.Clone(b)
			}
			if b, ok := m.Contents[i].Value.([]byte); ok {
				m.Contents[i].Value = slices.Clone(b)
			}
		}
		detachMap(m.InnerMap)
	}
	for _, m := range out.Maps {
		detachMap(m)
	}
	functions := make(map[*btf.Func]*btf.Func)
	for _, p := range out.Programs {
		for i := range p.Instructions {
			ins := &p.Instructions[i]
			if fn := btf.FuncMetadata(ins); fn != nil {
				copied := functions[fn]
				if copied == nil {
					copied = btf.Copy(fn).(*btf.Func)
					functions[fn] = copied
				}
				*ins = btf.WithFuncMetadata(*ins, copied)
			}
		}
	}
	return out
}

// PinAttempts is how many loads of spec with MapOptions.PinPath a caller makes while they fail with EEXIST.
// cilium/ebpf opens a map already pinned and creates and pins one that is not, and a concurrent first load of
// the same build can pin a name between the two: this load's pin then fails with EEXIST. Each such failure
// means one more of spec's pinned names is pinned, and a pin stays for the build's life (the loaders hold its
// build lock), so a load fails that way at most once per pinned map: one attempt more than there are always
// settles it.
func PinAttempts(spec *ebpf.CollectionSpec) int {
	n := 1
	for _, m := range spec.Maps {
		if m.Pinning == ebpf.PinByName {
			n++
		}
	}
	return n
}

// Hash is this build's bpf_hash: the first HashLen hex characters of a SHA-256 over every embedded object, the
// tier-2 objects, then the plane builds, then the fill builds (which write the plane's pinned maps), then the rdonly
// builds of the tier-2 objects compiled per reader, each contributing its name and its bytes in a fixed order. Two
// binaries built from the same C produce the same value and share one pin directory, one build lock and one run_idx
// space; any difference produces two of each, which is exactly what makes an upgrade mid-run safe (§6 E22).
//
// The embedded bytes never change, so the hash is computed once per process.
func Hash() (string, error) {
	if len(generated) == 0 {
		return "", ErrNotGenerated
	}
	hashOnce.Do(func() { hashValue = computeHash() })
	return hashValue, nil
}

var (
	hashOnce  sync.Once
	hashValue string
)

func computeHash() string {
	sum := sha256.New()
	for _, o := range append(append(Objects(), PlaneObjects()...), PlaneFillObjects()...) {
		b, _ := bindingOf(o)
		// Length-prefixing the name keeps the hash unambiguous if an object is ever renamed to a prefix of
		// another's name.
		fmt.Fprintf(sum, "%d:%s:%d:", len(o), o, len(b.raw))
		sum.Write(b.raw)
	}
	// The rdonly builds after, under a name no object has, so adding them changed every hash once and no
	// build's bytes can stand in for another's.
	for _, o := range readerObjects() {
		b := readerGenerated[o]
		name := string(o) + "@" + string(ReaderRdonly)
		fmt.Fprintf(sum, "%d:%s:%d:", len(name), name, len(b.raw))
		sum.Write(b.raw)
	}
	return hex.EncodeToString(sum.Sum(nil))[:HashLen]
}

// readerObjects lists the objects with an rdonly build, sorted.
func readerObjects() []Object {
	out := make([]Object, 0, len(readerGenerated))
	for o := range readerGenerated {
		out = append(out, o)
	}
	sortObjects(out)
	return out
}

// compareObject orders object names lexically.
func compareObject(a, b Object) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
