// SPDX-License-Identifier: Apache-2.0

package agentdiff

import "reflect"

type equalPointerPair struct {
	typeOf reflect.Type
	a, b   uintptr
}

// compiledEqual reads the complete compiled state, including private indexes.
// Indexes use *Pattern map keys: separately compiling the same rules allocates
// different keys, so reflect.DeepEqual incorrectly reports those maps changed.
// Pointer keys are matched by their complete contents instead. Immutable shared
// grammar pointers compare directly; unrelated nonnil callbacks remain unknown.
func compiledEqual(a, b reflect.Value, active map[equalPointerPair]bool) bool {
	if !a.IsValid() || !b.IsValid() {
		return a.IsValid() == b.IsValid()
	}
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return compiledEqual(a.Elem(), b.Elem(), active)
	case reflect.Pointer:
		if a.Pointer() == b.Pointer() {
			return true
		}
		if a.IsNil() || b.IsNil() {
			return false
		}
		pair := equalPointerPair{a.Type(), a.Pointer(), b.Pointer()}
		if active[pair] {
			return true
		}
		active[pair] = true
		defer delete(active, pair)
		return compiledEqual(a.Elem(), b.Elem(), active)
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if !compiledEqual(a.Field(i), b.Field(i), active) {
				return false
			}
		}
		return true
	case reflect.Array, reflect.Slice:
		if a.Len() != b.Len() {
			return false
		}
		if a.Kind() == reflect.Slice && a.IsNil() != b.IsNil() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !compiledEqual(a.Index(i), b.Index(i), active) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.IsNil() != b.IsNil() || a.Len() != b.Len() {
			return false
		}
		if a.Type().Key().Kind() != reflect.Pointer {
			for _, key := range a.MapKeys() {
				if !compiledEqual(a.MapIndex(key), b.MapIndex(key), active) {
					return false
				}
			}
			return true
		}
		keys, matched := b.MapKeys(), make([]bool, b.Len())
		for _, key := range a.MapKeys() {
			found := false
			for i, other := range keys {
				if !matched[i] && compiledEqual(key, other, active) && compiledEqual(a.MapIndex(key), b.MapIndex(other), active) {
					matched[i], found = true, true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case reflect.Bool:
		return a.Bool() == b.Bool()
	case reflect.String:
		return a.String() == b.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return a.Int() == b.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return a.Uint() == b.Uint()
	case reflect.Float32, reflect.Float64:
		return a.Float() == b.Float()
	case reflect.Complex64, reflect.Complex128:
		return a.Complex() == b.Complex()
	case reflect.Chan, reflect.UnsafePointer:
		return a.Pointer() == b.Pointer()
	case reflect.Func:
		return a.IsNil() && b.IsNil()
	default:
		return false
	}
}
