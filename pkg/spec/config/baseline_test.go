// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// fixtureLoad exercises discovery/parse/merge with generic trusted test files. Production's
// additional system placement check is exercised separately in TestBaselineSystemTrustWalk.
func fixtureLoad(src Sources, home string, uid int, mode TrustMode) (*Machine, []Diagnostic, error) {
	return loadSources(src, home, uid, mode, func(path string, _ Layer, uid int) ([]byte, bool, error) { return readTrusted(path, uid) })
}

func TestBaselineSchema(t *testing.T) {
	for _, tc := range []struct {
		text, message string
		line          int
	}{
		{"baseline: null\n", "mapping", 1},
		{"baseline: !!str {exec: {deny: [sh]}}\n", "mapping", 1},
		{"baseline: {exec: {deny: !!map [sh]}}\n", "list", 1},
		{"baseline:\n  fs: null\n", "mapping", 2},
		{"baseline:\n  fs:\n    deny_reed: [/x]\n", "baseline.fs.deny_reed", 3},
		{"baseline:\n  fs: {read: [/x]}\n", "baseline.fs.read", 2},
		{"baseline:\n  fs: {ask_read: [/x]}\n", "baseline.fs.ask_read", 2},
		{"baseline:\n  exec: {allow: [sh]}\n", "baseline.exec.allow", 2},
		{"baseline:\n  env: {set: {X: y}}\n", "baseline.env.set", 2},
		{"baseline:\n  net: {deny: [example.com]}\n", "baseline.net", 2},
		{"baseline:\n  limits: {pids: 1}\n", "baseline.limits", 2},
		{"baseline:\n  fs: {deny_read: null}\n", "list", 2},
		{"baseline:\n  fs: {deny_read: /x}\n", "list", 2},
		{"baseline:\n  exec: {deny: [null]}\n", "string", 2},
		{"baseline:\n  exec: {deny: [true]}\n", "string", 2},
		{"baseline:\n  exec: {deny: [42]}\n", "string", 2},
		{"baseline:\n  exec: {deny: [{x: y}]}\n", "string", 2},
		{"baseline:\n  exec: {deny: ['']}\n", "string", 2},
		{"baseline:\n  fs: {deny_read: [relative]}\n", "literal absolute", 2},
		{"baseline:\n  fs: {deny_read: ['~other/a']}\n", "literal absolute", 2},
		{"baseline:\n  fs: {deny_read: ['/x/*']}\n", "without patterns", 2},
		{"baseline:\n  env: {deny: [X=y]}\n", "variable name", 2},
		{"baseline:\n  exec: {deny: [x], deny: []}\n", "duplicate", 2},
		{"baseline: {}\nbaseline: {}\n", "duplicate", 2},
		{"baseline:\n  fs: {<<: {deny_read: [/x]}}\n", "string key", 2},
		{"baseline:\n  fs: {deny_read: &x [/x], deny_write: *x}\n", "list", 2},
		{"!!null baseline: {}\n", "string key", 1},
		{"baseline: {!!null fs: {deny_read: []}}\n", "string key", 1},
	} {
		t.Run(tc.message+tc.text, func(t *testing.T) {
			_, ds := parseLayer("bad.yaml", []byte(tc.text))
			for _, d := range ds {
				if d.File == "bad.yaml" && d.Line == tc.line && strings.Contains(d.Message, tc.message) && d.Severity == SeverityError {
					return
				}
			}
			t.Fatalf("missing %q at bad.yaml:%d: %v", tc.message, tc.line, ds)
		})
	}
	for _, text := range []string{"", "baseline: {}", "baseline: {fs: {deny_read: [], deny_write: []}, exec: {deny: []}, env: {deny: []}}", "baseline: {fs: {deny_read: [~/a, /b]}, exec: {deny: ['git push']}, env: {deny: [TOKEN]}}"} {
		if _, ds := parseLayer("good.yaml", []byte(text)); HasErrors(ds) {
			t.Fatalf("%s: %v", text, ds)
		}
	}
}

func TestBaselineImmutableUnionSources(t *testing.T) {
	m := Builtin()
	var ds []Diagnostic
	for i, text := range []string{
		"baseline:\n  fs:\n    deny_read:\n      - /a\n      - /a\n      - /b\n  exec: {deny: ['git push']}\n",
		"baseline: {fs: {deny_read: [/b, /c]}, exec: {deny: ['git push']}}",
		"baseline: {fs: {deny_read: []}, env: {deny: [TOKEN]}}",
	} {
		d, parsed := parseLayer("layer", []byte(text))
		if HasErrors(parsed) {
			t.Fatal(parsed)
		}
		before, saved := m.baseline, m.baseline.Entries()
		merger{file: "layer", layer: Layer(i + 1), diags: &ds}.apply(m, d)
		if !reflect.DeepEqual(before.Entries(), saved) {
			t.Fatal("merge mutated an older snapshot")
		}
	}
	got := m.baseline.Entries()
	want := []BaselineEntry{
		{BaselineDenyRead, "/a", []Provenance{{"layer", 4, LayerEtc}, {"layer", 5, LayerEtc}}},
		{BaselineDenyRead, "/b", []Provenance{{"layer", 6, LayerEtc}, {"layer", 1, LayerUser}}},
		{BaselineDenyRead, "/c", []Provenance{{"layer", 1, LayerUser}}},
		{BaselineDenyExec, "git push", []Provenance{{"layer", 7, LayerEtc}, {"layer", 1, LayerUser}}},
		{BaselineDenyEnv, "TOKEN", []Provenance{{"layer", 1, LayerEnvFile}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%#v, want %#v", got, want)
	}
	got[0].Value, got[0].Sources[0].File = "changed", "changed"
	if !reflect.DeepEqual(m.baseline.Entries(), want) {
		t.Fatal("accessor exposes mutable storage")
	}
}

func TestBaselineCannotBeRemovedByConfig(t *testing.T) {
	dir := trustedDir(t)
	base := writeFile(t, dir, "system", "baseline: {env: {deny: [TOKEN]}}", 0o644)
	for _, tc := range []struct {
		name, text string
		invalid    bool
	}{
		{"empty list", "baseline: {env: {deny: []}}", false},
		{"absent key", "log: {level: debug}", false},
		{"empty file", "", false},
		{"null file", "null\n", false},
		{"second document", "baseline: {}\n---\nbaseline: {env: {deny: []}}", true},
		{"null list", "baseline: {env: {deny: null}}", true},
		{"null section", "baseline: {env: null}", true},
		{"null baseline", "baseline: null", true},
		{"duplicate baseline", "baseline: {env: {deny: [X]}}\nbaseline: {}", true},
		{"duplicate list", "baseline: {env: {deny: [X], deny: []}}", true},
		{"override key", "baseline: {override: true}", true},
		{"include", "include: other.yaml\nbaseline: {}", true},
		{"yaml merge", "baseline: {<<: {env: {deny: []}}}", true},
	} {
		for _, layer := range []Layer{LayerUser, LayerEnvFile} {
			t.Run(tc.name+layer.String(), func(t *testing.T) {
				path := writeFile(t, dir, "later", tc.text, 0o600)
				src := Sources{Etc: base}
				if layer == LayerUser {
					src.User = path
				} else {
					src.EnvFile = path
				}
				m, ds, err := fixtureLoad(src, "", os.Getuid(), TrustAbort)
				if tc.invalid {
					if err == nil || m != nil || !HasErrors(ds) {
						t.Fatalf("override accepted: %v %v", err, ds)
					}
					return
				}
				if err != nil || len(m.baseline.Entries()) != 1 || m.baseline.Entries()[0].Value != "TOKEN" {
					t.Fatalf("lost baseline: %v %v", m, err)
				}
			})
		}
	}
	// TEGO_CONFIG selects only the additional layer. Resolve keeps the fixed system and passwd layers.
	t.Setenv(EnvConfigVar, writeFile(t, dir, "extra", "baseline: {}", 0o600))
	src, _, _ := Resolve(os.Getuid(), false)
	if src.Etc != EtcPath || src.User == "" || src.EnvFile != os.Getenv(EnvConfigVar) {
		t.Fatalf("replacement discovery: %+v", src)
	}
	// There is no command-line config flag: Load accepts uid/secure, not a replacement Sources.
	// The separate CLI registration assertion lives with the compiler compatibility proof.
}

func TestBaselineLayerStateTable(t *testing.T) {
	for _, layer := range []Layer{LayerEtc, LayerUser, LayerEnvFile} {
		for _, state := range []string{"good", "empty", "bad-parse", "bad-mode", "bad-type", "bad-read", "absent", "unselected"} {
			for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
				t.Run(layer.String()+"/"+state+"/"+string(rune('0'+mode)), func(t *testing.T) {
					dir := trustedDir(t)
					path := filepath.Join(dir, "layer.yaml")
					switch state {
					case "good":
						writeFile(t, dir, "layer.yaml", "baseline: {env: {deny: [TOKEN]}}", 0o644)
					case "empty":
						writeFile(t, dir, "layer.yaml", "", 0o644)
					case "bad-parse":
						writeFile(t, dir, "layer.yaml", "baseline: {env: {denyy: [TOKEN]}}", 0o644)
					case "bad-mode":
						writeFile(t, dir, "layer.yaml", "baseline: {}", 0o666)
					case "bad-type":
						if err := syscall.Mkfifo(path, 0o600); err != nil {
							t.Fatal(err)
						}
					case "bad-read":
						writeFile(t, dir, "layer.yaml", "baseline: {}", 0)
					case "unselected":
						path = ""
					}
					src := Sources{}
					switch layer {
					case LayerEtc:
						src.Etc = path
					case LayerUser:
						src.User = path
					case LayerEnvFile:
						src.EnvFile = path
					case LayerBuiltin, LayerContract:
						t.Fatalf("layer %v has no file source", layer)
					}
					m, ds, err := fixtureLoad(src, "", os.Getuid(), mode)
					if state == "bad-read" && os.Geteuid() == 0 {
						// Root can read mode 000; model an actual reader failure without a privilege-dependent skip.
						m, ds, err = loadSources(src, "", os.Getuid(), mode, func(string, Layer, int) ([]byte, bool, error) { return nil, false, fs.ErrPermission })
					}
					bad := strings.HasPrefix(state, "bad-") || state == "absent" && layer == LayerEnvFile
					if bad {
						if mode == TrustWarn {
							if err != nil || m == nil || m.BaselineKnown() || m.baseline.Empty() || HasErrors(ds) {
								t.Fatalf("bad layer lost unknown: %v %v %v", m, ds, err)
							}
							return
						}
						if err == nil || m != nil {
							t.Fatalf("bad layer returned a snapshot: %v %v %v", m, ds, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					observations := m.LayerSources()
					if len(observations) != 3 {
						t.Fatalf("missing layer observations: %+v", observations)
					}
					observation := observations[int(layer)-1]
					want := LayerPresent
					if state == "absent" {
						want = LayerAbsent
					}
					if state == "unselected" {
						want = LayerUnselected
					}
					if observation.State != want {
						t.Fatalf("%+v, want %s", observation, want)
					}
					if want == LayerPresent {
						data, e := os.ReadFile(path)
						if e != nil {
							t.Fatal(e)
						}
						sum := sha256.Sum256(data)
						if observation.SHA256 != hex.EncodeToString(sum[:]) {
							t.Fatal(observation)
						}
					} else if observation.SHA256 != "" {
						t.Fatal(observation)
					}
					copy := m.LayerSources()
					copy[0].File = "changed"
					if m.LayerSources()[0].File == "changed" {
						t.Fatal("source storage escaped")
					}
				})
			}
		}
	}
}

func TestBaselineOwnerHomeAndAbsence(t *testing.T) {
	dir := trustedDir(t)
	ownerA, ownerB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, d := range []string{ownerA, ownerB} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, d, "secret", "x", 0o600)
	}
	t.Setenv("HOME", "/caller/wrong")
	baseline := func(layer Layer, value string) Baseline {
		return Baseline{entries: []BaselineEntry{{BaselineDenyRead, value, []Provenance{{"config.yaml", 7, layer}}}}}
	}
	for _, layer := range []Layer{LayerEtc, LayerUser, LayerEnvFile} {
		b := baseline(layer, "~/secret")
		for _, owner := range []BaselineOwner{{1001, ownerA}, {1002, ownerB}} {
			r, err := b.Resolve(owner)
			if err != nil {
				t.Fatal(err)
			}
			if r.Owner != owner || r.Entries[0].Expanded != owner.Home+"/secret" || r.Entries[0].Value != "~/secret" || b.Entries()[0].Value != "~/secret" {
				t.Fatal(r)
			}
		}
		for _, home := range []string{"", "relative", ownerA + "/absent-home"} {
			r, err := b.Resolve(BaselineOwner{1003, home})
			if layer == LayerEtc && filepath.IsAbs(home) {
				if err != nil || r.Entries[0].State != LayerAbsent || r.Entries[0].Ancestor != ownerA || r.Entries[0].Missing != "absent-home/secret" {
					t.Fatalf("%+v %v", r, err)
				}
			} else {
				repair := "give the entry an absolute path, or run as a user with a passwd entry"
				if filepath.IsAbs(home) {
					repair = "use an absolute existing target, or remove this baseline entry"
				}
				if err == nil || !strings.Contains(err.Error(), layer.String()+" layer") || !strings.Contains(err.Error(), "owner uid 1003") || !strings.Contains(err.Error(), "config.yaml:7") || !strings.Contains(err.Error(), repair) {
					t.Fatalf("missing context accepted or bad diagnostic: %+v %v", r, err)
				}
			}
		}
		b = baseline(layer, ownerA+"/missing")
		r, err := b.Resolve(BaselineOwner{1001, ""})
		if layer == LayerEtc {
			if err != nil || r.Entries[0].State != LayerAbsent {
				t.Fatal(r, err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	b := baseline(LayerEtc, ownerA+"/missing")
	b.entries[0].Sources = append(b.entries[0].Sources, Provenance{"user.yaml", 3, LayerUser})
	if _, err := b.Resolve(BaselineOwner{1001, ownerA}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("system duplicate hid missing user target", err)
	}
	if err := os.MkdirAll(ownerB+"/sub", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ownerB+"/sub", ownerA+"/link"); err != nil {
		t.Fatal(err)
	}
	b = baseline(LayerUser, ownerA+"/link/../secret")
	r, err := b.Resolve(BaselineOwner{1001, ownerA})
	if err != nil || r.Entries[0].Target != ownerB+"/secret" || r.Entries[0].Expanded != ownerA+"/link/../secret" {
		t.Fatal(r, err)
	}
	for _, path := range []string{ownerA + "/missing/../secret", ownerA + "/secret/child", "/proc/self/environ"} {
		if _, err := baseline(LayerEtc, path).Resolve(BaselineOwner{1001, ownerA}); err == nil {
			t.Fatalf("unplaceable target accepted: %s", path)
		}
	}
}

func TestBaselineResolveLookupErrors(t *testing.T) {
	dir := trustedDir(t)
	blocked := dir + "/blocked"
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, blocked, "secret", "x", 0o600)
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0o700); err != nil {
			t.Error(err)
		}
	})
	for _, layer := range []Layer{LayerEtc, LayerUser, LayerEnvFile} {
		b := Baseline{entries: []BaselineEntry{{BaselineDenyWrite, blocked + "/secret", []Provenance{{"config.yaml", 9, layer}}}}}
		r, err := b.Resolve(BaselineOwner{1001, dir})
		if os.Geteuid() == 0 {
			if err != nil || r.Entries[0].State != LayerPresent {
				t.Fatalf("root's readable walk: %v", err)
			}
		} else if !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("%s unreadable walk: %v", layer, err)
		}
		loop := dir + "/loop-" + layer.String()
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
		b.entries[0].Value = loop
		if _, err := b.Resolve(BaselineOwner{1001, dir}); !errors.Is(err, syscall.ELOOP) {
			t.Fatalf("%s lookup loop: %v", layer, err)
		}
	}
}

func TestBaselineLoadedSnapshotAndOwnerContext(t *testing.T) {
	dir := trustedDir(t)
	ownerHome := dir + "/owner"
	if err := os.Mkdir(ownerHome, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, ownerHome, "secret", "x", 0o600)
	path := writeFile(t, dir, "config.yaml", "baseline: {fs: {deny_read: [~/secret]}, env: {deny: [TOKEN]}}", 0o600)
	first, _, err := LoadSources(Sources{User: path}, "/adopter/home", os.Getuid(), TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	savedEntries, savedSources := first.baseline.Entries(), first.LayerSources()
	r, err := first.baseline.Resolve(BaselineOwner{1001, ownerHome})
	if err != nil || r.Entries[0].Expanded != ownerHome+"/secret" || savedEntries[0].Value != "~/secret" {
		t.Fatal(r, err)
	}
	writeFile(t, dir, "config.yaml", "baseline: {env: {deny: [OTHER]}}", 0o600)
	second, _, err := LoadSources(Sources{User: path}, "/adopter/home", os.Getuid(), TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.baseline.Entries(), savedEntries) || !reflect.DeepEqual(first.LayerSources(), savedSources) {
		t.Fatal("disk edit mutated a loaded snapshot")
	}
	if second.baseline.Entries()[0].Value != "OTHER" || second.LayerSources()[1].SHA256 == savedSources[1].SHA256 {
		t.Fatal("new load did not read changed bytes")
	}
}

// Same path may be consulted twice while an outside writer changes its contents.
// Evidence must retain each trusted read, rather than reopen or key bytes by path.
func TestBaselineRetainsEachLayerRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, dir, "config.yaml", "baseline: {env: {deny: [FIRST]}}\n", 0600)
	m := Builtin()
	var diags []Diagnostic
	if err := applyFile(m, path, path, LayerUser, os.Getuid(), &diags, readLayer, pinLocalAuthority); err != nil {
		t.Fatal(err)
	}
	// The edit is between complete trusted reads, never during either read.
	writeFile(t, dir, "config.yaml", "baseline: {env: {deny: [SECOND]}}\n", 0600)
	if err := applyFile(m, path, path, LayerEnvFile, os.Getuid(), &diags, readLayer, pinLocalAuthority); err != nil {
		t.Fatal(err)
	}
	if string(m.LayerBytes(LayerUser)) != "baseline: {env: {deny: [FIRST]}}\n" || string(m.LayerBytes(LayerEnvFile)) != "baseline: {env: {deny: [SECOND]}}\n" {
		t.Fatal("consulted layer bytes were overwritten by path")
	}
	data := m.LayerBytes(LayerUser)
	data[0] = 'X'
	if m.LayerBytes(LayerUser)[0] == 'X' {
		t.Fatal("retained layer bytes are mutable")
	}
}

func TestBaselineEnvironmentNameDiagnosticHidesValue(t *testing.T) {
	for _, value := range []string{"QZ", "private-environment-value-that-is-long"} {
		_, ds := parseLayer("config.yaml", []byte("baseline: {env: {deny: [PRIVATE_TOKEN="+value+"]}}"))
		text := fmt.Sprint(ds)
		if !HasErrors(ds) || !strings.Contains(text, "PRIVATE_TOKEN") || strings.Contains(text, value) {
			t.Errorf("baseline environment diagnostic: %s", text)
		}
	}
}

// TestEnvEntryMessages: a baseline entry with no name to tell from its value is not shown; the diagnostic's position
// says which entry it is (the rule is pkg/spec/identity's envtext.go, (a)).
func TestEnvEntryMessages(t *testing.T) {
	for _, entry := range []string{"sk-live-qz", "\"=sk-live-qz\"", "1BAD=sk-live-qz"} {
		_, ds := parseLayer("config.yaml", []byte("baseline: {env: {deny: [OK_NAME, "+entry+"]}}"))
		text := fmt.Sprint(ds)
		if !HasErrors(ds) || strings.Contains(text, "qz") || strings.Contains(text, "BAD") || !strings.Contains(text, "this entry is not an environment variable name (the entry is not shown)") {
			t.Errorf("baseline entry %q: %s", entry, text)
		}
	}
}
