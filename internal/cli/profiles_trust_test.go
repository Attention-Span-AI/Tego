// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// trustedDir is a fresh directory the machine config's trust rule accepts whatever the umask: t.TempDir is
// 0775 under umask 002.
func trustedDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// asInvoker gives path to the uid the trust rule judges for (config.InvokingUID). Under sudo, as the root suites run
// (test/vm/root-suites.sh, CI), that is SUDO_UID, not the root that created the file, and the one-name rule spares a
// file someone else owns that is not group- or other-writable (ADR 0059): a test of the rule's refusal holds a file
// of the invoking uid's own, as a user's contract or profile is.
func asInvoker(t *testing.T, path string) {
	t.Helper()
	uid, _ := config.InvokingUID()
	if uid == os.Geteuid() {
		return
	}
	if err := os.Chown(path, uid, -1); err != nil {
		t.Fatal(err)
	}
}

// TestDirProfilesTrustRule: a profile is merged into the contract beneath it, so a profiles directory moved out
// of ~/.tego follows the machine config's trust rule (limits-check-doctor-cli.md §3) as ~/.tego/profiles
// does: the profile file, the directory holding it and the profiles directory itself owned by root or the
// invoking user and not group- or other-writable. Whoever could rewrite one could widen every contract that
// extends it.
func TestDirProfilesTrustRule(t *testing.T) {
	setup := func(t *testing.T) (root string) {
		root = filepath.Join(trustedDir(t), "profiles")
		if err := os.MkdirAll(filepath.Join(root, "base"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{root, filepath.Join(root, "base")} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "base", "py.yaml"), []byte("version: 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	if _, _, err := (dirProfiles{Root: setup(t)}).Resolve("base/py"); err != nil {
		t.Fatalf("a trusted profile: %v", err)
	}
	for name, loosen := range map[string]string{
		"a world-writable profile":             "base/py.yaml",
		"a profile in a world-writable folder": "base",
		"a world-writable profiles directory":  ".",
	} {
		t.Run(name, func(t *testing.T) {
			root := setup(t)
			p := filepath.Join(root, loosen)
			mode := os.FileMode(0o777)
			if strings.HasSuffix(loosen, ".yaml") {
				mode = 0o666
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			_, data, err := (dirProfiles{Root: root}).Resolve("base/py")
			if err == nil || data != nil {
				t.Fatalf("read %q from an untrusted profile (err %v)", data, err)
			}
			if !errors.Is(err, config.ErrUntrusted) {
				t.Errorf("error %v is not an untrusted-config error", err)
			}
		})
	}
	// A profile with a second name (a hard link outside the profiles directory) is refused too (ADR 0059): R10 keeps
	// every write entry off the profiles directory, and none is compared with the other name, so a run whose write
	// entry holds it could widen every contract that extends the profile.
	t.Run("a profile with a second name", func(t *testing.T) {
		root := setup(t)
		asInvoker(t, filepath.Join(root, "base", "py.yaml"))
		if err := os.Link(filepath.Join(root, "base", "py.yaml"), filepath.Join(filepath.Dir(root), "kept.yaml")); err != nil {
			t.Fatal(err)
		}
		_, data, err := (dirProfiles{Root: root}).Resolve("base/py")
		if err == nil || data != nil || !errors.Is(err, config.ErrUntrusted) || !strings.Contains(err.Error(), "2 names") {
			t.Fatalf("read %q from a profile with 2 names (err %v), want config.ErrUntrusted naming them", data, err)
		}
	})
}

// TestUntrustedProfileSaysUntrusted: a profiles directory the trust rule refuses (0775 here) is reported as
// untrusted, naming the path, owner and mode, with the trust rule's fix, never as a profile not found.
func TestUntrustedProfileSaysUntrusted(t *testing.T) {
	root := filepath.Join(trustedDir(t), "profiles")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "base.yaml"), []byte("version: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(trustedDir(t), "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: t\nextends: base\ncommand: [\"true\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, ds, err := agent.Load(contract, dirProfiles{Root: root})
	if err == nil {
		t.Fatal("a profile in an untrusted directory loaded")
	}
	for _, d := range ds {
		if d.Code != agent.CodeExtendsNotFound {
			continue
		}
		if strings.Contains(d.Message, "not found") || !strings.Contains(d.Message, "untrusted") ||
			!strings.Contains(d.Message, root) || !strings.Contains(d.Message, "mode=0775") ||
			!strings.Contains(d.Message, "uid=") {
			t.Errorf("message %q: want untrusted, with the path, uid and mode", d.Message)
		}
		if d.Fix != (&config.UntrustedError{}).Fix() {
			t.Errorf("fix %q, want the trust rule's", d.Fix)
		}
		return
	}
	t.Fatalf("want an untrusted-profile diagnostic, got %v", ds)
}
