// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ErrNotLoaded is returned by Canonical on a Contract that did not come from
// a successful Load.
var ErrNotLoaded = errors.New("contract was not produced by Load")

// Canonical is the deterministic re-serialization of the merged contract
// (R13): Go struct field order, omitempty per the struct tags, 2-space indent,
// "\n" line endings, trailing newline. The one departure from the tags is an
// explicit `deny_read: []`, which switches the built-in list off and so is
// emitted (FSSection.MarshalYAML). It is computed from the decoded
// structure, so comments and whitespace never change it, and before any
// ceiling clamp, so it is the same on every machine (I3). Every
// not-yet-supported field is still emitted when non-empty. internal/ledger
// writes these exact bytes as contract.yaml. A string yaml.v3 would write as a
// block that does not load back, one holding a line break that starts with a
// tab or a line break, is written double-quoted (canonicalDoc).
func (c *Contract) Canonical() ([]byte, error) {
	if c == nil || !c.loaded {
		return nil, ErrNotLoaded
	}
	doc, err := canonicalDoc(c)
	if err != nil {
		return nil, fmt.Errorf("agent: canonical: %w", err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("agent: canonical: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("agent: canonical: %w", err)
	}
	return buf.Bytes(), nil
}

// Hash is contract_hash: sha256 of Canonical() (R13).
func (c *Contract) Hash() ([32]byte, error) {
	b, err := c.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// canonicalDoc is what Canonical encodes: c itself, unless c holds a string yaml.v3 writes as a block scalar that
// does not load back as that string (blockLossy); then canonicalNode, c's encoding with each such string
// double-quoted. A contract without one takes the encoder's path it always took, so its bytes and contract_hash
// are unchanged.
func canonicalDoc(c *Contract) (any, error) {
	lossy := false
	mapStrings(reflect.ValueOf(c), func(s string) (string, bool) {
		lossy = lossy || blockLossy(s)
		return "", false
	})
	if !lossy {
		return c, nil
	}
	return canonicalNode(c)
}

// blockLossy reports whether yaml.v3 may write s as a block scalar that does not load back as s (R13). s holds a
// "\n", so the encoder writes it as a literal block, and it starts with a character the emitter mishandles there.
// A tab: the emitter gives a block an indentation indicator only for a leading space or line break, and without
// one the scanner takes the indentation from the first line and refuses the tab it finds there ("found a tab
// character where an indentation space is expected"), so FuzzLoad's 0de5fd1b2ddbbf92, `command: ["\t0\n"]`, made
// a contract.yaml that did not load back for tego drift. A line break: the emitter lets it end the indicator's own
// line, so it is dropped, and `"\nz\n"` loaded back as `"z\n"`. Of every string of up to five characters over a,
// space, tab, \n, \r, U+2028 and #, as a sequence item, a nested one and a mapping value, each that did not load
// back is one this names, and each loads back double-quoted; the rest it names the emitter double-quotes anyway,
// for a \r or a space before a break, so naming them changes no byte (TestBlockLossyNamesEveryBlockYAMLCannotReadBack).
// go.yaml.in/yaml/v3 v3.0.6 has the tab case too; v4 writes the indicator.
func blockLossy(s string) bool {
	if !strings.Contains(s, "\n") {
		return false
	}
	switch r, _ := utf8.DecodeRuneInString(s); r {
	case '\t', '\n', '\r', '\u0085', '\u2028', '\u2029':
		return true
	}
	return false
}

// canonicalNode is c's own encoding as a node tree, with each blockLossy string double-quoted and every other
// node as the encoder makes it. yaml.v3 makes a node by writing text, at an indent of 4, and parsing it back,
// and that text cannot carry every string that holds a line break: a blockLossy one fails as blockLossy says,
// and at that indent a block in a sequence whose string starts with a space is given the indicator 4 where
// its content sits 2 further in, which the scanner refuses too. So c is copied with every string that holds a
// line break replaced by a plain stand-in, and each stand-in's scalar is given its string back: double-quoted
// when it is blockLossy, otherwise with no style, which Canonical's encoder writes as the literal block it
// writes from c (TestCanonicalNodeIsTheEncoders).
func canonicalNode(c *Contract) (*yaml.Node, error) {
	taken := map[string]bool{}
	var block []string
	mapStrings(reflect.ValueOf(c), func(s string) (string, bool) {
		if !taken[s] && strings.Contains(s, "\n") {
			block = append(block, s)
		}
		taken[s] = true
		return "", false
	})
	// A stand-in is a string the contract does not hold, so a scalar that comes back as one held a block
	// string. Which stand-in a string gets does not reach the output: each is replaced before the encode.
	standIn := make(map[string]string, len(block))
	back := make(map[string]string, len(block))
	n := 0
	for _, s := range block {
		p := fmt.Sprintf("tego-canonical-%d", n)
		for taken[p] {
			n++
			p = fmt.Sprintf("tego-canonical-%d", n)
		}
		taken[p] = true
		standIn[s], back[p] = p, s
	}
	cp, _ := mapStrings(reflect.ValueOf(c), func(s string) (string, bool) {
		p, ok := standIn[s]
		return p, ok
	})
	var doc yaml.Node
	if err := doc.Encode(cp.Interface()); err != nil {
		return nil, err
	}
	untagMerge(&doc)
	restoreStandIns(&doc, back)
	return &doc, nil
}

// restoreStandIns gives every scalar that is a stand-in the string it stands for (canonicalNode).
func restoreStandIns(n *yaml.Node, back map[string]string) {
	if s, ok := back[n.Value]; ok && n.Kind == yaml.ScalarNode {
		n.Value, n.Tag, n.Style = s, "!!str", 0
		if blockLossy(s) {
			n.Style = yaml.DoubleQuotedStyle
		}
	}
	for _, c := range n.Content {
		restoreStandIns(c, back)
	}
}

// mapStrings returns v with f applied to each string the encoder can reach from it: exported struct fields,
// through pointers, interfaces, slices, arrays and maps, map keys included. f answers a string and whether it
// changed it. A part in which f changes nothing is v's own, so only the path to a changed string is copied and
// v is never written.
func mapStrings(v reflect.Value, f func(string) (string, bool)) (reflect.Value, bool) {
	switch v.Kind() {
	case reflect.String:
		s, ok := f(v.String())
		if !ok {
			return v, false
		}
		nv := reflect.New(v.Type()).Elem()
		nv.SetString(s)
		return nv, true
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return v, false
		}
		e, ok := mapStrings(v.Elem(), f)
		if !ok {
			return v, false
		}
		if v.Kind() == reflect.Pointer {
			nv := reflect.New(v.Type().Elem())
			nv.Elem().Set(e)
			return nv, true
		}
		nv := reflect.New(v.Type()).Elem()
		nv.Set(e)
		return nv, true
	case reflect.Slice, reflect.Array:
		var nv reflect.Value
		for i := range v.Len() {
			e, ok := mapStrings(v.Index(i), f)
			if !ok {
				continue
			}
			if !nv.IsValid() {
				nv = reflect.New(v.Type()).Elem()
				if v.Kind() == reflect.Slice {
					nv.Set(reflect.MakeSlice(v.Type(), v.Len(), v.Len()))
					reflect.Copy(nv, v)
				} else {
					nv.Set(v)
				}
			}
			nv.Index(i).Set(e)
		}
		return mapped(v, nv)
	case reflect.Map:
		type entry struct{ k, e reflect.Value }
		var entries []entry
		changed := false
		for it := v.MapRange(); it.Next(); {
			k, kok := mapStrings(it.Key(), f)
			e, eok := mapStrings(it.Value(), f)
			entries = append(entries, entry{k, e})
			changed = changed || kok || eok
		}
		if !changed {
			return v, false
		}
		nv := reflect.MakeMapWithSize(v.Type(), len(entries))
		for _, x := range entries {
			nv.SetMapIndex(x.k, x.e)
		}
		return nv, true
	case reflect.Struct:
		var nv reflect.Value
		for i := range v.NumField() {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			e, ok := mapStrings(v.Field(i), f)
			if !ok {
				continue
			}
			if !nv.IsValid() {
				nv = reflect.New(v.Type()).Elem()
				nv.Set(v)
			}
			nv.Field(i).Set(e)
		}
		return mapped(v, nv)
	}
	return v, false
}

// mapped is mapStrings' answer for a value it copied into nv, or left alone when nv is unset.
func mapped(v, nv reflect.Value) (reflect.Value, bool) {
	if !nv.IsValid() {
		return v, false
	}
	return nv, true
}
