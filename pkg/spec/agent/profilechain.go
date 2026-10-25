// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxExtendsList bounds the names one extends: list may hold (agent-contract R5, ADR 0066).
const MaxExtendsList = 8

// BuiltinPrefix opens the reserved namespace of built-in profiles: a name beginning with it resolves only through
// the built-in sources the composition root registers on a ProfileChain, never through a profiles directory
// (ADR 0066 D2).
const BuiltinPrefix = "tego/"

// IsBuiltinName reports whether name is in the reserved built-in namespace.
func IsBuiltinName(name string) bool { return strings.HasPrefix(name, BuiltinPrefix) }

// ExtendsList is extends: the profiles a file is laid over, in the order they merge. It is written as one name or as
// a list of names; Canonical writes one name as the scalar it has always been, so a single-name contract's canonical
// form and contract_hash are what they were before lists (R13), and two or more as a list.
type ExtendsList []string

// UnmarshalYAML reads one name or a list of names. The schema walk has already held the node to that shape and
// to the profile-name rule.
func (e *ExtendsList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*e = ExtendsList{n.Value}
		return nil
	}
	var names []string
	if err := n.Decode(&names); err != nil {
		return err
	}
	*e = names
	return nil
}

// MarshalYAML writes one name as a scalar and more as a list.
func (e ExtendsList) MarshalYAML() (any, error) {
	if len(e) == 1 {
		return e[0], nil
	}
	return []string(e), nil
}

// ProfileKind is the kind of source a profile was read from, as run_start.profiles records it.
type ProfileKind string

const (
	// ProfileBuiltin is a profile built into the binary, under the reserved tego/ namespace.
	ProfileBuiltin ProfileKind = "builtin"
	// ProfileDir is a profile read from a profiles directory (the machine config's profiles:).
	ProfileDir ProfileKind = "dir"
)

// ProfileUse is one profile a contract was merged from: its extends name, the kind of source that served it and
// the sha256 of the bytes read. Contract.Profiles lists them in merge order, each profile once.
type ProfileUse struct {
	Name   string
	Source ProfileKind
	SHA256 [32]byte
}

// ProfileProber is optional on a profiles-directory source: whether it holds a file for name, said without reading
// the file. ProfileChain asks it for every name in the reserved namespace, so a file there under tego/ is reported
// shadowed-builtin rather than silently passed over (ADR 0066 D2).
type ProfileProber interface {
	// Holds is the file the source would read name from and whether it exists.
	Holds(name string) (path string, ok bool)
}

// ProfileNamer is optional on a built-in source: every name it serves. A tego/ name no built-in source holds is
// extends-not-found, and its fix lists the names the sources implementing this serve, so a mistyped preset name or a
// revision pin that does not exist is answered with the names there are (ADR 0068).
type ProfileNamer interface {
	Names() []string
}

// builtinNames is every name the built-in sources that can list theirs serve, sorted, each once.
func (c *ProfileChain) builtinNames() []string {
	var names []string
	for _, s := range c.builtin {
		if n, ok := s.(ProfileNamer); ok {
			names = append(names, n.Names()...)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// ProfileChain is the ProfileSource every load site of the CLI reads extends: through (ADR 0066): ordered built-in
// sources, which alone serve the reserved tego/ namespace, and ordered profiles-directory sources, which serve every
// other name. The first source that holds a name serves it; an error other than "not found" from a source stops the
// walk there, so a profile that exists and cannot be read is never passed over for a later one. The zero value
// resolves nothing.
type ProfileChain struct {
	builtin, dir []ProfileSource
}

// WithBuiltin appends a built-in source and returns c. Only the composition root registers one.
func (c *ProfileChain) WithBuiltin(s ProfileSource) *ProfileChain {
	c.builtin = append(c.builtin, s)
	return c
}

// WithDir appends a profiles-directory source and returns c.
func (c *ProfileChain) WithDir(s ProfileSource) *ProfileChain {
	c.dir = append(c.dir, s)
	return c
}

// Resolve implements ProfileSource.
func (c *ProfileChain) Resolve(name string) (string, []byte, error) {
	r := c.resolve(name)
	return r.path, r.data, r.err
}

// Location implements ProfileLocator for a name a directory serves: the first directory source that can place it.
// A built-in name has no file to create.
func (c *ProfileChain) Location(name string) string {
	if IsBuiltinName(name) {
		return ""
	}
	for _, s := range c.dir {
		if loc, ok := s.(ProfileLocator); ok {
			if where := loc.Location(name); where != "" {
				return where
			}
		}
	}
	return ""
}

// resolvedProfile is one name's resolution: the file and bytes, the kind of source that served them, and, for a
// built-in name, a directory file that the name shadows.
type resolvedProfile struct {
	path     string
	data     []byte
	kind     ProfileKind
	err      error
	shadowed string
}

func (c *ProfileChain) resolve(name string) resolvedProfile {
	sources, kind := c.dir, ProfileDir
	r := resolvedProfile{}
	if IsBuiltinName(name) {
		sources, kind = c.builtin, ProfileBuiltin
		for _, s := range c.dir {
			if p, ok := s.(ProfileProber); ok {
				if path, held := p.Holds(name); held {
					r.shadowed = path
					break
				}
			}
		}
	}
	for _, s := range sources {
		path, data, err := s.Resolve(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		r.path, r.data, r.err = path, data, err
		if err == nil {
			r.kind = kind
		}
		return r
	}
	r.err = fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
	return r
}

// resolveProfile resolves name through src. A source that is no ProfileChain is a profiles directory and serves no
// built-in name, so the reserved namespace stays closed whatever a caller passes.
func resolveProfile(src ProfileSource, name string) resolvedProfile {
	if c, ok := src.(*ProfileChain); ok {
		return c.resolve(name)
	}
	return (&ProfileChain{dir: []ProfileSource{src}}).resolve(name)
}

// profileUse is the record of a profile read for a merge.
func profileUse(name string, r resolvedProfile) ProfileUse {
	return ProfileUse{Name: name, Source: r.kind, SHA256: sha256.Sum256(r.data)}
}

// extendsConflict is a contract-wins key two parents of one extends list wrote with different values (ADR 0065 D4):
// an error at both lines unless the file naming the list writes the key, which then decides.
type extendsConflict struct {
	path        string
	first, then Pos
}

// combineParents combines the parents of one extends list left to right by the classes of ADR 0065 D4, before the
// file naming them is laid on top: concat, union and keymerge in list order, stricter keeping the stricter, and a
// contract-wins or env.set key two parents wrote differently keeping the first writer's value. A parent the walk
// merged earlier is not among them (it merges once, at its first position); whether the list conflicts is
// checkParents' to say, on the parents' whole views.
func combineParents(parents []*Contract) *Contract {
	r, _ := combine(parents, false)
	return r
}

// checkParents combines the whole views of every parent one extends list names (ADR 0066 D3), its scalar keys
// only, and returns each contract-wins or env.set key two of them wrote with different values: what a list means
// never depends on which entry above it reached a shared ancestor first.
func checkParents(wholes []*Contract) (*Contract, []extendsConflict) { return combine(wholes, true) }

func combine(parents []*Contract, scalars bool) (*Contract, []extendsConflict) {
	acc := parents[0]
	var conflicts []extendsConflict
	for _, p := range parents[1:] {
		m := newMerger(acc.origins, p.origins)
		m.parents, m.scalars = true, scalars
		r := &Contract{file: p.file, origins: m.out}
		contractTable.merge(m, reflect.ValueOf(acc).Elem(), reflect.ValueOf(p).Elem(), reflect.ValueOf(r).Elem())
		conflicts = append(conflicts, m.conflicts...)
		acc = r
	}
	return acc, conflicts
}

// sameValue reports whether two written values of one key would give the merged contract the same canonical form
// (ADR 0065 D4 as amended): compared by the YAML Canonical writes for each, so a spelling or a comment never
// differs and an order or a length always does.
func sameValue(a, b reflect.Value) bool {
	if reflect.DeepEqual(a.Interface(), b.Interface()) {
		return true
	}
	x, errA := canonicalValue(a)
	y, errB := canonicalValue(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

func canonicalValue(v reflect.Value) ([]byte, error) {
	if v.CanAddr() {
		v = v.Addr()
	}
	return yaml.Marshal(v.Interface())
}
