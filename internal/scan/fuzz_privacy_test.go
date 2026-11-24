// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// Arbitrary value text can equal a closed catalog id or transport. The seeded
// secret gives an unambiguous taint marker instead. Check every eight-byte
// fragment, including private fields and errors. Server names and timer target
// names are intentionally retained metadata, so those fields are exempt.
func assertFuzzValuePrivacy(t testing.TB, v any) {
	t.Helper()
	if retainsFuzzSecret(reflect.ValueOf(v)) {
		t.Fatal("input value fragment retained")
	}
}

func retainsFuzzSecret(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	contains := func(s string) bool {
		for i := 0; i+8 <= len(mcpCanary); i++ {
			if strings.Contains(s, mcpCanary[i:i+8]) {
				return true
			}
		}
		return false
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		return !v.IsNil() && retainsFuzzSecret(v.Elem())
	case reflect.String:
		return contains(v.String())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type() == reflect.TypeFor[mcpServer]() && v.Type().Field(i).Name == "Name" || v.Type() == reflect.TypeFor[unitDocument]() && v.Type().Field(i).Name == "Trigger" {
				continue
			}
			if retainsFuzzSecret(v.Field(i)) {
				return true
			}
		}
	case reflect.Array, reflect.Slice:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return contains(string(bytes.Clone(v.Bytes())))
		}
		for i := 0; i < v.Len(); i++ {
			if retainsFuzzSecret(v.Index(i)) {
				return true
			}
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			if retainsFuzzSecret(key) || retainsFuzzSecret(v.MapIndex(key)) {
				return true
			}
		}
	}
	return false
}

func TestFuzzPrivacyGuard(t *testing.T) {
	for i := 0; i+8 <= len(mcpCanary); i++ {
		if !retainsFuzzSecret(reflect.ValueOf(struct{ private string }{mcpCanary[i : i+8]})) {
			t.Fatal("eight-byte fragment not checked")
		}
	}
	if retainsFuzzSecret(reflect.ValueOf(mcpServer{Name: mcpCanary, Program: "codex-native"})) {
		t.Fatal("server-name metadata treated as a secret value")
	}
}
