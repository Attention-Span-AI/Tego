// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The parent computes this once. A canceled request stops waiting immediately;
// only this one initializer continues, independent of the number of requests.
// Check and its child execute the same /proc/self/exe, so the child can use that
// trusted fingerprint and register references without serializing the grammar.
var builtinGrammar = new(grammarFingerprintCache)

type grammarFingerprintCache struct {
	once  sync.Once
	done  chan struct{}
	value string
	err   error
}

func (c *grammarFingerprintCache) get(ctx context.Context, compute func() (string, error)) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.once.Do(func() {
		c.done = make(chan struct{})
		go func() {
			defer func() {
				if recover() != nil {
					c.err = errors.New("built-in grammar initialization failed")
				}
				close(c.done)
			}()
			c.value, c.err = compute()
		}()
	})
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-c.done:
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return c.value, c.err
	}
}

func builtinGrammarFingerprint(ctx context.Context) (string, error) {
	return builtinGrammar.get(ctx, computeBuiltinGrammarFingerprint)
}

func computeBuiltinGrammarFingerprint() (string, error) {
	e := &snapshotEncoder{builtin: map[snapshotPointer]string{}, active: map[snapshotPointer]bool{}}
	grammar, err := e.value(reflect.ValueOf(rows.Builtin().All()), "builtin", true)
	if err != nil {
		return "", err
	}
	grammarBytes, err := json.Marshal(grammar)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(grammarBytes)), nil
}

// compiledBindingWithGrammar describes the actual compiled tables, including the command
// index's private patterns, closures, identities, loader identities, normalizers
// and autocorrect candidates, and the opaque DNS, HTTP, proxy and gate policies.
// JSON omits private policy fields and fails on built-in grammar callbacks and
// device/inode map keys. Dropping those fields binds a different compiled result.
//
// The immutable built-in grammar is described once, with stable references to
// its objects. A callback's identity is its slot in that trusted grammar, never
// a process address. Code cannot change within a service session: restarting
// the service changes the acknowledgement key. Unknown grammar objects or
// functions fail closed. Prepared grammar lookup caches are derived from its
// exported declaration; actual contract-specific index state is encoded whole.
// This helper performs no I/O and links no decision evaluator.

func compiledBindingWithGrammar(sources string, before, after *agent.RuleTable, grammarDigest string) ([]byte, error) {
	needsGrammar := before != nil && (before.ExecCommands != nil || before.Gate != nil) || after != nil && (after.ExecCommands != nil || after.Gate != nil)
	if needsGrammar && grammarDigest == "" {
		var err error
		grammarDigest, err = builtinGrammarFingerprint(context.Background())
		if err != nil {
			return nil, err
		}
	}
	e := &snapshotEncoder{builtin: map[snapshotPointer]string{}, active: map[snapshotPointer]bool{}}
	if needsGrammar {
		e.registerGrammar(reflect.ValueOf(rows.Builtin().All()), "builtin")
	} else {
		grammarDigest = ""
	}
	a, err := e.table(before)
	if err != nil {
		return nil, err
	}
	b, err := e.table(after)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Version       string
		Sources       string
		Grammar       string
		Before, After any
	}{"compiled-review-v2", sources, grammarDigest, a, b})
}

// registerGrammar follows the same deterministic exported declaration paths as
// the fingerprint encoder, but allocates no serialized grammar tree. It only
// records trusted data-object locations. Scalar values and callbacks are already
// covered by the parent's immutable grammar fingerprint.
func (e *snapshotEncoder) registerGrammar(v reflect.Value, path string) {
	if !grammarHasObjects(v.Type()) {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		key := snapshotPointer{v.Type(), v.Pointer()}
		if _, exists := e.builtin[key]; exists {
			return
		}
		e.builtin[key] = path
		e.registerGrammar(v.Elem(), path)
	case reflect.Struct:
		if v.CanAddr() {
			e.builtin[snapshotPointer{v.Addr().Type(), v.Addr().Pointer()}] = path
		}
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if field.IsExported() && grammarHasObjects(field.Type) {
				e.registerGrammar(v.Field(i), path+"/"+field.Name)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			e.registerGrammar(v.Index(i), fmt.Sprintf("%s/%d", path, i))
		}
	case reflect.Map:
		keys := v.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
		for _, key := range keys {
			encoded, _ := json.Marshal(key.String()) // Grammar maps have string keys.
			e.registerGrammar(v.MapIndex(key), path+"/"+string(encoded))
		}
	}
}

func grammarHasObjects(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Pointer, reflect.Struct:
		return true
	case reflect.Array, reflect.Slice, reflect.Map:
		return grammarHasObjects(t.Elem())
	default:
		return false
	}
}

func (e *snapshotEncoder) table(rt *agent.RuleTable) (any, error) {
	return e.value(reflect.ValueOf(rt), "table", false)
}

type snapshotPointer struct {
	typeOf  reflect.Type
	address uintptr // Used only for object lookup; never encoded or used for functions.
}

type snapshotEncoder struct {
	builtin map[snapshotPointer]string
	active  map[snapshotPointer]bool
}

type snapshotReference struct{ Builtin string }
type snapshotMapEntry struct{ Key, Value any }
type snapshotField [2]any // field name, then its complete value

// value also reads private matcher data through reflect's scalar accessors,
// without unsafe or Interface on unexported values. New fields are therefore
// included automatically, and unsupported kinds cause a refused check.
func (e *snapshotEncoder) value(v reflect.Value, path string, grammar bool) (any, error) {
	if !v.IsValid() {
		return nil, nil
	}
	if v.Type() == reflect.TypeFor[time.Time]() && v.CanInterface() {
		return v.Interface().(time.Time).UTC().Format(time.RFC3339Nano), nil
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return nil, nil
		}
		return e.value(v.Elem(), path, grammar)
	case reflect.Pointer:
		if v.IsNil() {
			return nil, nil
		}
		key := snapshotPointer{v.Type(), v.Pointer()}
		if name, ok := e.builtin[key]; ok {
			return snapshotReference{name}, nil
		}
		if grammar {
			e.builtin[key] = path
		} else if builtinObject(v.Type()) {
			return nil, fmt.Errorf("unknown compiled grammar object at %s", path)
		}
		// The row-set's private lookup map is a prepared cache of All(). The
		// exact built-in set is required, rather than an arbitrary replacement.
		if v.Type() == reflect.TypeFor[*execmatch.Rows]() {
			if !v.CanInterface() || v.Interface() != rows.Builtin() {
				// Unexported Index.rows cannot Interface; pointer identity is
				// safe for checking the trusted data object, never callback code.
				if v.Pointer() != reflect.ValueOf(rows.Builtin()).Pointer() {
					return nil, fmt.Errorf("unknown compiled grammar set at %s", path)
				}
			}
			return snapshotReference{"builtin"}, nil
		}
		if !grammar {
			if e.active[key] {
				return nil, fmt.Errorf("cyclic compiled data at %s", path)
			}
			e.active[key] = true
			defer delete(e.active, key)
		}
		return e.value(v.Elem(), path, grammar)
	case reflect.Struct:
		if grammar && v.CanAddr() {
			e.builtin[snapshotPointer{v.Addr().Type(), v.Addr().Pointer()}] = path
		}
		// Declaration order is stable and includes private fields. A named-field
		// list avoids building and sorting a new JSON object for every node.
		out := make([]snapshotField, 0, v.NumField())
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if grammar && !field.IsExported() {
				continue
			}
			childPath := ""
			if grammar {
				childPath = path + "/" + field.Name
			}
			x, err := e.value(v.Field(i), childPath, grammar)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", path, field.Name, err)
			}
			out = append(out, snapshotField{field.Name, x})
		}
		return out, nil
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return nil, nil
		}
		out := make([]any, v.Len())
		for i := range out {
			childPath := ""
			if grammar {
				childPath = fmt.Sprintf("%s/%d", path, i)
			}
			x, err := e.value(v.Index(i), childPath, grammar)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", path, i, err)
			}
			out[i] = x
		}
		return out, nil
	case reflect.Map:
		if v.IsNil() {
			return nil, nil
		}
		type item struct {
			key     reflect.Value
			encoded any
			value   any
			order   string
		}
		items := make([]item, 0, v.Len())
		for _, key := range v.MapKeys() {
			childPath := ""
			if grammar {
				childPath = path + "/key"
			}
			x, err := e.value(key, childPath, grammar)
			if err != nil {
				return nil, err
			}
			b, err := json.Marshal(x)
			if err != nil {
				return nil, err
			}
			items = append(items, item{key: key, encoded: x, order: string(b)})
		}
		slices.SortFunc(items, func(a, b item) int { return strings.Compare(a.order, b.order) })
		// Compound keys can contain pointers or normalized values, so different
		// Go keys may encode identical contents. Primitive keys are already
		// unique; avoid encoding their values a second time for sorting.
		keyKind := v.Type().Key().Kind()
		tieBreakValues := !grammar && (keyKind == reflect.Pointer || keyKind == reflect.Struct || keyKind == reflect.Array || keyKind == reflect.Interface)
		for i := range items {
			item := &items[i]
			childPath := ""
			if grammar {
				childPath = path + "/" + item.order
			}
			x, err := e.value(v.MapIndex(item.key), childPath, grammar)
			if err != nil {
				return nil, err
			}
			item.value = x
			if tieBreakValues {
				encoded, err := json.Marshal(x)
				if err != nil {
					return nil, err
				}
				item.order += "\x00" + string(encoded)
			}
		}
		if tieBreakValues {
			// Distinct pointer keys can have identical structural contents.
			// Their associated values break ties, independent of map iteration.
			slices.SortFunc(items, func(a, b item) int { return strings.Compare(a.order, b.order) })
		}
		out := make([]snapshotMapEntry, len(items))
		for i, item := range items {
			out[i] = snapshotMapEntry{item.encoded, item.value}
		}
		return out, nil
	case reflect.Func:
		if v.IsNil() {
			return nil, nil
		}
		if !grammar {
			return nil, fmt.Errorf("unknown compiled callback at %s", path)
		}
		return snapshotReference{"execmatch-builtins-v1/" + path}, nil
	case reflect.String:
		return v.String(), nil
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return v.Float(), nil
	default:
		return nil, fmt.Errorf("unsupported compiled field %s at %s", v.Kind(), path)
	}
}

func builtinObject(t reflect.Type) bool {
	return t == reflect.TypeFor[*execmatch.Row]() || t == reflect.TypeFor[*execmatch.Level]() ||
		t == reflect.TypeFor[*execmatch.Opt]() || t == reflect.TypeFor[*execmatch.InterpSpec]()
}
