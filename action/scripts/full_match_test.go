// SPDX-License-Identifier: Apache-2.0

package scripts_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFullMatchRequiresBindingCheckForVersion2(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "bindings", "v2", "check.json"))
	if err != nil {
		t.Fatal(err)
	}
	var check map[string]any
	if err := json.Unmarshal(data, &check); err != nil {
		t.Fatal(err)
	}
	var checks []any
	for _, step := range check["checks"].([]any) {
		if step.(map[string]any)["name"] != "binding" {
			checks = append(checks, step)
		}
	}
	check["checks"] = checks
	encoded, err := json.Marshal(check)
	if err != nil {
		t.Fatal(err)
	}
	runFullMatch(t, encoded, false)
}

func TestFullMatchRefusesUnknownBindingVersion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "bindings", "v2", "check.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0", "4", "-1", "1.0", "2.0", "2.5", "null", "true", `"2"`} {
		t.Run(version, func(t *testing.T) {
			encoded := bytes.Replace(data, []byte(`"binding_v": 2`), []byte(`"binding_v": `+version), 1)
			runFullMatch(t, encoded, false)
		})
	}
	t.Run("missing", func(t *testing.T) {
		encoded := bytes.Replace(data, []byte(`"binding_v": 2,`), nil, 1)
		runFullMatch(t, encoded, false)
	})
}

func TestFullMatchRefusesDuplicateKeys(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "bindings", "v2", "check.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]string{
		"top result":       `"result":"mismatch","result":"match"`,
		"equal values":     `"result":"match","result":"match"`,
		"escaped key":      `"res\u0075lt":"mismatch","result":"match"`,
		"check result":     `"extra":[{"result":"fail","result":"pass"}],"result":"match"`,
		"nested object":    `"extra":{"a":{"x":1,"x":2}},"result":"match"`,
		"container key":    `"extra":{"a":{"x":1},"a":{"y":2}},"result":"match"`,
		"empty containers": `"extra":{"a":{},"a":[]},"result":"match"`,
	} {
		t.Run(name, func(t *testing.T) {
			encoded := bytes.Replace(data, []byte(`"result": "match"`), []byte(replacement), 1)
			runFullMatch(t, encoded, false)
		})
	}
	t.Run("listed check", func(t *testing.T) {
		encoded := bytes.Replace(data, []byte(`"result": "pass"`), []byte(`"result":"fail","result":"pass"`), 1)
		runFullMatch(t, encoded, false)
	})
}

// Embedding the production script lets go test -overlay demonstrate that these
// regressions fail with the old script, without changing the checkout.
//
//go:embed full-match.sh
var fullMatch []byte

func TestFullMatchProductBindings(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "testdata", "bindings", version, "check.json"))
			if err != nil {
				t.Fatal(err)
			}
			runFullMatch(t, data, true)
		})
	}
}

func TestFullMatchEveryCheckMustPass(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "bindings", "v2", "check.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []string{"pass", "fail", "not-checked", "unknown", ""} {
		t.Run(result, func(t *testing.T) {
			var check map[string]any
			if err := json.Unmarshal(data, &check); err != nil {
				t.Fatal(err)
			}
			check["checks"] = append(check["checks"].([]any), map[string]any{"name": "future-check", "result": result})
			encoded, err := json.Marshal(check)
			if err != nil {
				t.Fatal(err)
			}
			runFullMatch(t, encoded, result == "pass")
		})
	}
}

func TestFullMatchRefusesMalformedChecks(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "bindings", "v1", "check.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(map[string]any){
		"missing minimum": func(c map[string]any) { c["checks"] = c["checks"].([]any)[1:] },
		"duplicate":       func(c map[string]any) { c["checks"] = append(c["checks"].([]any), c["checks"].([]any)[0]) },
		"empty name": func(c map[string]any) {
			c["checks"] = append(c["checks"].([]any), map[string]any{"name": "", "result": "pass"})
		},
		"missing result": func(c map[string]any) { delete(c["checks"].([]any)[0].(map[string]any), "result") },
		"unknown schema": func(c map[string]any) { c["check_v"] = 2 },
		"unended":        func(c map[string]any) { c["ended"] = false },
		"uncertain":      func(c map[string]any) { c["result"] = "cannot-check" },
	} {
		t.Run(name, func(t *testing.T) {
			var check map[string]any
			if err := json.Unmarshal(data, &check); err != nil {
				t.Fatal(err)
			}
			edit(check)
			encoded, err := json.Marshal(check)
			if err != nil {
				t.Fatal(err)
			}
			runFullMatch(t, encoded, false)
		})
	}
}

func runFullMatch(t *testing.T, data []byte, pass bool) {
	t.Helper()
	dir := t.TempDir()
	script, input := filepath.Join(dir, "full-match.sh"), filepath.Join(dir, "check.json")
	if err := os.WriteFile(script, fullMatch, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/bash", "-p", script, "--tego-ci-clean", input).CombinedOutput()
	if (err == nil) != pass {
		t.Fatalf("pass=%v, want %v: %v\n%s", err == nil, pass, err, out)
	}
}
