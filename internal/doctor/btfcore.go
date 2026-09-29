// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// coreNeed is one kernel type, member or enum value that an embedded BPF object reads through a CO-RE
// relocation, named the way the loader matches it: by the type's name without its ___flavor suffix and
// by member names (enforce-cgroup-observe.md E31). D2 checks each against the kernel's BTF before any
// program load is attempted. That way a kernel that lacks one is diagnosed by the name of what is
// missing, not by a verifier tail at Prepare.
type coreNeed struct {
	// Type is the kernel type's name, "task_struct".
	Type string
	// Path is the members read below Type, outermost first. An array step is "[]". It is empty for a
	// relocation on the type itself (its existence, size or id).
	Path []string
	// Enum is the enum value a relocation reads, "" for any other kind.
	Enum string
	// Objects are the objects that need it, sorted.
	Objects []string
}

// String is the need as D2 names it: "task_struct.real_parent", "cgroup.kn.id", "enum bpf_attach_type.X".
func (n coreNeed) String() string {
	if n.Enum != "" {
		return n.Type + "::" + n.Enum
	}
	s := n.Type
	for _, p := range n.Path {
		if p == "[]" {
			s += "[]"
			continue
		}
		s += "." + p
	}
	return s
}

// key identifies a need across objects.
func (n coreNeed) key() string { return n.String() }

// coreReloString is how cilium/ebpf prints a btf.CORERelocation: its kind, its local type, the accessor and
// the local type's id. The fields are not exported, so the string is the only way to read them.
// TestCORENeedsOfTheObjects fails when a cilium/ebpf upgrade changes the format.
var coreReloString = regexp.MustCompile(`^CORERelocation\(([a-z_0-9]+), .*\[([0-9:]+)\], local_id=([0-9]+)\)$`)

// Relocation kinds, as btf's coreKind prints them, by what they read.
var (
	coreFieldKinds = []string{"byte_off", "byte_sz", "field_exists", "signed", "lshift_u64", "rshift_u64"}
	coreTypeKinds  = []string{"target_type_id", "type_exists", "type_size", "type_matches"}
	coreEnumKinds  = []string{"enumval_exists", "enumval_value"}
	// coreExistsKinds resolve to 0 or 1 and never fail the load, so they are no need.
	coreExistsKinds = []string{"field_exists", "type_exists", "type_matches", "enumval_exists"}
)

// objectCORENeeds lists what every object this binary carries reads from the kernel's types, merged across
// objects and sorted. It lists nothing for a build without the objects (bpfobj.Available). The objects are
// embedded and never change, so the list is read once per process.
var objectCORENeeds = sync.OnceValues(readObjectCORENeeds)

// readObjectCORENeeds is objectCORENeeds' reading.
func readObjectCORENeeds() ([]coreNeed, error) {
	byKey := map[string]*coreNeed{}
	for _, o := range bpfobj.Objects() {
		spec, err := bpfobj.Load(o)
		if err != nil {
			return nil, err
		}
		for name, prog := range spec.Programs {
			if o == bpfobj.ObjectCgroupNet && slices.Contains(bpfobj.UnixPrograms, name) {
				// Optional: a kernel without the unix sockaddr hooks, or the field they read, runs the tier
				// without them (enforce-cgroup-observe.md R7), so what only they read decides nothing here.
				continue
			}
			for i := range prog.Instructions {
				relo := btf.CORERelocationMetadata(&prog.Instructions[i])
				if relo == nil {
					continue
				}
				n, ok, err := needOf(relo, spec.Types)
				if err != nil {
					return nil, fmt.Errorf("%s/%s: %w", o, prog.Name, err)
				}
				if !ok {
					continue
				}
				have := byKey[n.key()]
				if have == nil {
					have = &n
					byKey[n.key()] = have
				}
				if !slices.Contains(have.Objects, o.String()) {
					have.Objects = append(have.Objects, o.String())
				}
			}
		}
	}
	out := make([]coreNeed, 0, len(byKey))
	for _, n := range byKey {
		slices.Sort(n.Objects)
		out = append(out, *n)
	}
	slices.SortFunc(out, func(a, b coreNeed) int { return strings.Compare(a.key(), b.key()) })
	return out, nil
}

// needOf reads one relocation into a need, walking its accessor over the object's own copy of the type to
// name each member. ok is false for a relocation that reads nothing of the kernel's (local_type_id).
func needOf(relo *btf.CORERelocation, local *btf.Spec) (coreNeed, bool, error) {
	return needOfString(relo.String(), local)
}

// needOfString is needOf over the relocation's printed form.
func needOfString(rs string, local *btf.Spec) (coreNeed, bool, error) {
	m := coreReloString.FindStringSubmatch(rs)
	if m == nil {
		return coreNeed{}, false, fmt.Errorf("unreadable CO-RE relocation %q", rs)
	}
	kind, accStr := m[1], m[2]
	if kind == "local_type_id" || slices.Contains(coreExistsKinds, kind) {
		// An existence relocation guards optional kernel layout: the loader resolves it to 0 when the target
		// is absent and never poisons it, so D2 must not fail a kernel over one.
		return coreNeed{}, false, nil
	}
	id, err := strconv.ParseUint(m[3], 10, 32)
	if err != nil {
		return coreNeed{}, false, fmt.Errorf("relocation %q: %w", rs, err)
	}
	var acc []int
	for _, s := range strings.Split(accStr, ":") {
		i, err := strconv.Atoi(s)
		if err != nil {
			return coreNeed{}, false, fmt.Errorf("relocation %q: %w", rs, err)
		}
		acc = append(acc, i)
	}
	typ, err := local.TypeByID(btf.TypeID(id))
	if err != nil {
		return coreNeed{}, false, fmt.Errorf("relocation %q: %w", rs, err)
	}
	n := coreNeed{Type: essentialName(typ.TypeName())}
	if n.Type == "" {
		return coreNeed{}, false, fmt.Errorf("relocation %q on an anonymous type", rs)
	}
	switch {
	case slices.Contains(coreTypeKinds, kind):
		return n, true, nil
	case slices.Contains(coreEnumKinds, kind):
		e, ok := btf.As[*btf.Enum](typ)
		if !ok || len(acc) != 1 || acc[0] < 0 || acc[0] >= len(e.Values) {
			return coreNeed{}, false, fmt.Errorf("relocation %q: not an enum value", rs)
		}
		n.Enum = e.Values[acc[0]].Name
		return n, true, nil
	case slices.Contains(coreFieldKinds, kind):
	default:
		return coreNeed{}, false, fmt.Errorf("relocation %q: unknown kind %s", rs, kind)
	}
	// acc[0] indexes the base pointer as an array; every later index is a member, or an array element.
	cur := typ
	for _, i := range acc[1:] {
		switch t := btf.UnderlyingType(cur).(type) {
		case *btf.Struct:
			if i < 0 || i >= len(t.Members) {
				return coreNeed{}, false, fmt.Errorf("relocation %q: member %d of %s", rs, i, t.Name)
			}
			// An anonymous member is found through its parent's name lookup; it adds no step.
			if name := t.Members[i].Name; name != "" {
				n.Path = append(n.Path, name)
			}
			cur = t.Members[i].Type
		case *btf.Union:
			if i < 0 || i >= len(t.Members) {
				return coreNeed{}, false, fmt.Errorf("relocation %q: member %d of %s", rs, i, t.Name)
			}
			if name := t.Members[i].Name; name != "" {
				n.Path = append(n.Path, name)
			}
			cur = t.Members[i].Type
		case *btf.Array:
			n.Path = append(n.Path, "[]")
			cur = t.Type
		default:
			return coreNeed{}, false, fmt.Errorf("relocation %q: step %d into %s", rs, i, cur)
		}
	}
	return n, true, nil
}

// essentialName is a local type's name without the ___flavor suffix the loader ignores when it matches it.
func essentialName(name string) string {
	if i := strings.Index(name, "___"); i > 0 {
		return name[:i]
	}
	return name
}

// errCORENotFound is a need the kernel's BTF does not carry.
var errCORENotFound = errors.New("not in the kernel's BTF")

// missingCORE returns the needs the kernel's BTF does not satisfy, each as its String and why.
func missingCORE(kernel *btf.Spec, needs []coreNeed) []string {
	var out []string
	for _, n := range needs {
		if err := resolveCORE(kernel, n); err != nil {
			out = append(out, fmt.Sprintf("%s (%s: %v)", n, strings.Join(n.Objects, ","), err))
		}
	}
	return out
}

// resolveCORE reports whether one of the kernel's types of the need's name has what the need reads, as the
// loader's candidate search does: any one type of that name will do.
func resolveCORE(kernel *btf.Spec, n coreNeed) error {
	cands, err := kernel.AnyTypesByName(n.Type)
	if errors.Is(err, btf.ErrNotFound) || len(cands) == 0 {
		return fmt.Errorf("type %s %w", n.Type, errCORENotFound)
	}
	if err != nil {
		return err
	}
	var first error
	for _, c := range cands {
		err := resolveIn(c, n)
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// resolveIn checks one candidate type.
func resolveIn(t btf.Type, n coreNeed) error {
	if n.Enum != "" {
		e, ok := btf.As[*btf.Enum](t)
		if !ok {
			return fmt.Errorf("%s is not an enum", n.Type)
		}
		for _, v := range e.Values {
			if v.Name == n.Enum {
				return nil
			}
		}
		return fmt.Errorf("enum value %s %w", n.Enum, errCORENotFound)
	}
	cur := t
	at := n.Type
	for _, step := range n.Path {
		if step == "[]" {
			a, ok := btf.UnderlyingType(cur).(*btf.Array)
			if !ok {
				return fmt.Errorf("%s is not an array", at)
			}
			cur, at = a.Type, at+"[]"
			continue
		}
		next, ok := memberByName(cur, step)
		if !ok {
			return fmt.Errorf("field %s.%s %w", at, step, errCORENotFound)
		}
		cur, at = next, at+"."+step
	}
	return nil
}

// memberByName finds a named member of a struct or union, looking through anonymous members as a C
// compiler, and the loader, do.
func memberByName(t btf.Type, name string) (btf.Type, bool) {
	var members []btf.Member
	switch c := btf.UnderlyingType(t).(type) {
	case *btf.Struct:
		members = c.Members
	case *btf.Union:
		members = c.Members
	default:
		return nil, false
	}
	for _, m := range members {
		if m.Name == name {
			return m.Type, true
		}
	}
	for _, m := range members {
		if m.Name == "" {
			if mt, ok := memberByName(m.Type, name); ok {
				return mt, true
			}
		}
	}
	return nil, false
}
