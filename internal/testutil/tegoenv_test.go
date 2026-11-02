// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestTegoEnvIsolatesWhateverTheDeveloperExported: the anchor and the own-log home point into dir's own state directory (not dir itself) even when
// the inherited environment names others, extra comes last, and the own-log home exists.
func TestTegoEnvIsolatesWhateverTheDeveloperExported(t *testing.T) {
	t.Setenv(envTestChainAnchor, "/home/dev/.tego/chain.log")
	t.Setenv(envTestOwnLogHome, "/home/dev")
	dir := t.TempDir()
	env := TegoEnv(t, dir, "TEGO_CONFIG=/c")

	last := func(key string) string {
		v := ""
		for _, kv := range env {
			if rest, ok := strings.CutPrefix(kv, key+"="); ok {
				v = rest
			}
		}
		return v
	}
	if got, want := last(envTestChainAnchor), filepath.Join(OwnStateDir(dir), "chain.log"); got != want {
		t.Errorf("anchor %q, want %q", got, want)
	}
	if got, want := last(envTestOwnLogHome), filepath.Join(OwnStateDir(dir), "home"); got != want {
		t.Errorf("own-log home %q, want %q", got, want)
	}
	if got := last("TEGO_CONFIG"); got != "/c" {
		t.Errorf("extra %q", got)
	}
	if st, err := os.Stat(filepath.Join(OwnStateDir(dir), "home")); err != nil || !st.IsDir() {
		t.Errorf("own-log home not made: %v", err)
	}
	if env[len(env)-1] != "TEGO_CONFIG=/c" {
		t.Errorf("extra is not last: %v", env[len(env)-1])
	}
}

// TestTegoEnvGivesTheRunAPrivateRuntimeDir: XDG_RUNTIME_DIR is OwnStateDir(dir)/run, mode 0700 whatever the umask
// or an earlier mode, after every inherited value (the developer's /run/user/<uid>, a relative one, an empty one) and
// before extra, so a test that names its own in extra keeps it (identity-config.md R27 clause b4).
func TestTegoEnvGivesTheRunAPrivateRuntimeDir(t *testing.T) {
	for _, inherited := range []string{"/run/user/1000", "run/user/1000", ""} {
		t.Run(strconv.Quote(inherited), func(t *testing.T) {
			t.Setenv(envXDGRuntimeDir, inherited)
			dir := t.TempDir()
			run := filepath.Join(OwnStateDir(dir), "run")
			if err := os.MkdirAll(run, 0o755); err != nil { // an earlier, wider mode is narrowed
				t.Fatal(err)
			}
			env := TegoEnv(t, dir, "TEGO_CONFIG=/c")
			at := func(kv string) int { return slices.Index(env, kv) }
			own := at(envXDGRuntimeDir + "=" + run)
			if own < 0 || own < at(envXDGRuntimeDir+"="+inherited) || own > at("TEGO_CONFIG=/c") {
				t.Errorf("XDG_RUNTIME_DIR=%s at %d, the inherited value at %d, extra at %d: %v", run, own,
					at(envXDGRuntimeDir+"="+inherited), at("TEGO_CONFIG=/c"), env)
			}
			if got := lastValue(env, envXDGRuntimeDir); got != run {
				t.Errorf("XDG_RUNTIME_DIR %q, want %q", got, run)
			}
			st, err := os.Stat(run)
			if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
				t.Errorf("runtime dir %s: %v %v, want a 0700 directory", run, st, err)
			}
		})
	}
	own := t.TempDir()
	if got := lastValue(TegoEnv(t, t.TempDir(), envXDGRuntimeDir+"="+own), envXDGRuntimeDir); got != own {
		t.Errorf("a test's own XDG_RUNTIME_DIR in extra lost: %q, want %q", got, own)
	}
}

// TestPrivateRuntimeDirPointsTheProcessAtItsOwnParent: a TestMain's call makes parent/run with mode 0700 and points
// this process's XDG_RUNTIME_DIR at it; as root it removes the variable and makes nothing.
func TestPrivateRuntimeDirPointsTheProcessAtItsOwnParent(t *testing.T) {
	t.Setenv(envXDGRuntimeDir, "/run/user/1000")
	parent := t.TempDir()
	if err := privateRuntimeDir(parent, 1000); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(parent, "run")
	if got := os.Getenv(envXDGRuntimeDir); got != want {
		t.Errorf("XDG_RUNTIME_DIR %q, want %q", got, want)
	}
	if st, err := os.Stat(want); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v %v, want mode 0700", want, st, err)
	}
	if err := privateRuntimeDir(filepath.Join(parent, "run", "x\x00"), 1000); err == nil {
		t.Error("an unusable parent was accepted")
	}

	t.Setenv(envXDGRuntimeDir, "/run/user/1000")
	root := t.TempDir()
	if err := privateRuntimeDir(root, 0); err != nil {
		t.Fatal(err)
	}
	if v, set := os.LookupEnv(envXDGRuntimeDir); set {
		t.Errorf("as root XDG_RUNTIME_DIR is %q, want it unset", v)
	}
	if _, err := os.Lstat(filepath.Join(root, "run")); !os.IsNotExist(err) {
		t.Errorf("as root a runtime directory was made: %v", err)
	}
}

// lastValue is the value the last key= entry of env gives key, as exec takes it.
func lastValue(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, key+"="); ok {
			v = rest
		}
	}
	return v
}
