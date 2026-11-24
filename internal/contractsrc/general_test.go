// SPDX-License-Identifier: Apache-2.0

package contractsrc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

const generalText = "version: 0\nname: shared\ncommand: [true]\nenv: {pass: []}\n"

func TestGeneralSelection(t *testing.T) {
	for _, tc := range []struct {
		name, system   string
		failure        error
		home, wantUser bool
		state          string
	}{
		{"system", generalText, nil, true, false, "loaded"},
		{"user fallback", "", nil, true, true, "loaded"},
		{"no home", "", nil, false, false, "absent"},
		{"malformed system", "bad: [", nil, true, false, "invalid"},
		{"unsafe system", "", config.ErrUntrusted, true, false, "unknown"},
		{"unreadable system", "", os.ErrPermission, true, false, "unknown"},
		{"uncertain system", "", errors.New("indeterminate walk"), true, false, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := config.Builtin()
			if tc.home {
				m.Home = "/passwd-owner"
			}
			var paths []string
			read := func(path string, system bool, uid int, max int64) (config.PolicySource, bool, error) {
				paths = append(paths, path)
				if max != agent.MaxContractSize || uid != 123 {
					t.Fatal("wrong bound/owner")
				}
				if system {
					if tc.failure != nil {
						return config.PolicySource{}, false, tc.failure
					}
					if tc.system == "" {
						return config.PolicySource{}, true, nil
					}
					return config.PolicySource{Data: []byte(tc.system), Owner: 0, Mode: 0644, Resolved: path}, false, nil
				}
				return config.PolicySource{Data: []byte(generalText), Owner: 123, Mode: 0600, Resolved: path}, false, nil
			}
			g := readGeneral(context.Background(), m, 123, SystemPath, read)
			if g.State != tc.state {
				t.Fatalf("%+v", g)
			}
			want := 1
			if tc.wantUser {
				want = 2
			}
			if len(paths) != want {
				t.Fatalf("fallback: %v", paths)
			}
			if tc.wantUser && paths[1] != "/passwd-owner/.tego/general.yaml" {
				t.Fatalf("paths %v", paths)
			}
			if g.State == "loaded" && (len(g.Hash) != 64 || g.Note != LoadedNote) {
				t.Fatalf("missing digest/status %+v", g)
			}
			if g.State != "loaded" && g.Hash != "" {
				t.Fatal("failed source has hash")
			}
		})
	}
}

func TestGeneralDigestsAndProfiles(t *testing.T) {
	// These bytes follow R13's field order, scalar extends, quoted command string,
	// and 2-space indentation. They are handwritten, never obtained from Canonical.
	const canonical = "version: 0\nname: shared\nextends: shared\ncommand:\n  - \"true\"\nenv:\n  pass:\n    - PATH\n"
	const canonicalHash = "637e614a92a7eef85bb8ecedbb28283374ae8ed6a24731617fb37db9c9772534"
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical))); got != canonicalHash {
		t.Fatalf("independent canonical fixture digest = %s, want %s", got, canonicalHash)
	}
	m := config.Builtin()
	m.Home = t.TempDir()
	m.Profiles.Value = filepath.Join(m.Home, "profiles")
	if err := os.Mkdir(m.Profiles.Value, 0700); err != nil {
		t.Fatal(err)
	}
	profile := []byte("version: 0\nenv: {pass: [PATH]}\n")
	if err := os.WriteFile(filepath.Join(m.Profiles.Value, "shared.yaml"), profile, 0600); err != nil {
		t.Fatal(err)
	}
	text := "version: 0\nname: shared\ncommand: [true]\nextends: shared\n"
	load := func(body string) General {
		return readGeneral(context.Background(), m, os.Getuid(), SystemPath, func(path string, _ bool, _ int, _ int64) (config.PolicySource, bool, error) {
			return config.PolicySource{Data: []byte(body), Resolved: path}, false, nil
		})
	}
	a, b := load(text), load("# comment\n"+text)
	if a.State != "loaded" || b.State != "loaded" {
		t.Fatalf("%+v %+v", a, b)
	}
	if a.Hash != b.Hash || a.Sources[0].SHA256 == b.Sources[0].SHA256 {
		t.Fatal("raw and canonical digests conflated")
	}
	if a.Hash != canonicalHash {
		t.Fatalf("canonical general digest = %s, want %s for independent bytes:\n%s", a.Hash, canonicalHash, canonical)
	}
	if len(a.Profiles) != 1 || a.Profiles[0].SHA256 != "beccd69f8e26f7aee98d9989087b1fdef55290e109b75060d9c0281be831fefd" {
		t.Fatalf("profiles %+v", a.Profiles)
	}
	if a.Sources[1].State != config.LayerUnselected {
		t.Fatal("user was consulted with system selected")
	}
	if err := os.WriteFile(filepath.Join(m.Profiles.Value, "shared.yaml"), []byte("version: 0\nenv: {pass: [PATH, LANG]}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed := load(text)
	const changedHash = "7bef9cdb6e5f15df330d79cd43ae96fecec1aca625944199b46c7007be33ff45"
	if changed.State != "loaded" || changed.Hash != changedHash || changed.Hash == a.Hash {
		t.Fatalf("profile edit did not change canonical digest: before=%s after=%+v", a.Hash, changed)
	}
	if changed.Sources[0].SHA256 != a.Sources[0].SHA256 {
		t.Fatal("profile edit changed unchanged general source digest")
	}
	if len(changed.Profiles) != 1 || changed.Profiles[0].SHA256 != "2e15b55b4f1bfd2c59700c603971475305e4a029e4de0fa6dfabd7cfc1178d5c" {
		t.Fatalf("profile edit digest %+v", changed.Profiles)
	}
}

func TestGeneralFixedPathsAndUnknown(t *testing.T) {
	for _, key := range []string{"HOME", "TEGO_CONFIG"} {
		t.Setenv(key, t.TempDir())
	}
	m := config.Builtin()
	m.Home = "/passwd-owner"
	var paths []string
	read := func(path string, _ bool, _ int, _ int64) (config.PolicySource, bool, error) {
		paths = append(paths, path)
		return config.PolicySource{}, true, nil
	}
	g := readGeneral(context.Background(), m, os.Getuid(), SystemPath, read)
	if strings.Join(paths, ",") != SystemPath+",/passwd-owner/.tego/general.yaml" || g.State != "absent" {
		t.Fatalf("%v %+v", paths, g)
	}
	paths = nil
	g = readGeneral(context.Background(), nil, os.Getuid(), SystemPath, read)
	if len(paths) != 0 || g.State != "unknown" {
		t.Fatalf("incomplete config: %v %+v", paths, g)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	paths = nil
	g = readGeneral(ctx, m, os.Getuid(), SystemPath, read)
	if len(paths) != 0 || g.State != "unknown" {
		t.Fatalf("cancelled: %v %+v", paths, g)
	}
}

func TestGeneralSchemaProblemsHideValues(t *testing.T) {
	m := config.Builtin()
	g := readGeneral(context.Background(), m, os.Getuid(), SystemPath, func(path string, _ bool, _ int, _ int64) (config.PolicySource, bool, error) {
		return config.PolicySource{Data: []byte("version: 0\nname: shared\ncommand: [true]\nenv: {pass: z9value}\n"), Resolved: path}, false, nil
	})
	if g.State != "invalid" || len(g.Diagnostics) == 0 {
		t.Fatalf("invalid source accepted: %+v", g)
	}
	if strings.Contains(g.Note, "z9value") {
		t.Fatal("error note disclosed a value")
	}
	for _, d := range g.Diagnostics {
		if strings.Contains(d.Error(), "z9value") {
			t.Fatal("diagnostic disclosed a value")
		}
	}
}

func TestGeneralUnsafeSystemNeverFallsBack(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "general.yaml")
	if err := os.WriteFile(path, []byte(generalText), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Home = root
	calls := 0
	g := readGeneral(context.Background(), m, os.Getuid(), path, func(p string, system bool, uid int, max int64) (config.PolicySource, bool, error) {
		calls++
		return config.ReadPolicySource(p, system, uid, max)
	})
	if g.State != "unknown" || calls != 1 || g.Sources[1].State != config.LayerUnselected {
		t.Fatalf("unsafe source selected fallback: calls=%d %+v", calls, g)
	}
}
