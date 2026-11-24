// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalRolesExactClosedSelector(t *testing.T) {
	for _, raw := range []string{
		"auto", "", `""`, "null", "~", "true", "false", "0", "1", "1.5", "[]", "[owner_only]", "{}",
		"OWNER_ONLY", "Owner_Only", "OFF", "Off", "approver", `" owner_only"`, `"owner_only "`,
		"!!bool owner_only", "owner_only\nlocal_roles: off",
	} {
		t.Run(raw, func(t *testing.T) {
			root, src, read, pin := localRolesFixture(t, "local_roles: "+raw+"\n")
			// Every launch rejects the system layer, even when a personal layer asks for off.
			src.User = writeFile(t, root, "user.yaml", "local_roles: off\n", 0o600)
			for launch := 1; launch <= 2; launch++ {
				if m, ds, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin); err == nil || m != nil || !HasErrors(ds) {
					t.Fatalf("launch %d accepted unsupported system selector %q: machine present=%v diagnostics=%v err=%v", launch, raw, m != nil, ds, err)
				}
			}
			m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustWarn, read, pin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.ApprovalAuthority(); err == nil {
				t.Fatal("observation fallback enabled personal approval authority")
			}
			if err := os.WriteFile(root+EtcPath, []byte("local_roles: owner_only\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			m, ds, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
			if err != nil || !m.localAuthority.OwnerOnly() {
				t.Fatalf("corrected selector did not enable the next launch: %v %v", ds, err)
			}
		})
	}
}

func TestSecuritySelectorVocabularies(t *testing.T) {
	// ranked is now used only by the two ceilings whose specification includes auto.
	for _, raw := range []string{"tier: auto", "capture: auto", "bpf: {plane: auto}", "resolver: auto", "landlock: {audit: off}"} {
		if _, ds := parseLayer("config", []byte(raw+"\n")); HasErrors(ds) {
			t.Errorf("documented selector rejected %q: %v", raw, ds)
		}
	}
	for _, raw := range []string{"tier: unknown", "capture: unknown", "bpf: {plane: unknown}", "resolver: unknown", "landlock: {audit: auto}"} {
		if _, ds := parseLayer("config", []byte(raw+"\n")); !HasErrors(ds) {
			t.Errorf("security selector accepted unsupported value %q", raw)
		}
	}
}

func TestLocalRolesOrdinaryEditOutcomes(t *testing.T) {
	const original = "local_roles: owner_only\n"
	for _, method := range []struct {
		name    string
		replace bool
		changed bool
	}{
		{"editor replaces file", true, true},
		{"editor writes in place", false, true},
		{"sudo tee", false, true},
		{"config management atomic replacement", true, true},
		{"package upgrade rewrites file", true, true},
		{"replacement with identical bytes", true, false},
		{"in place with identical bytes", false, false},
	} {
		t.Run(method.name, func(t *testing.T) {
			root, src, read, pin := localRolesFixture(t, original)
			m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
			if err != nil {
				t.Fatal(err)
			}
			a, err := m.ApprovalAuthority()
			if err != nil {
				t.Fatal(err)
			}
			path := root + EtcPath
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			body := original
			if method.changed {
				body += "# ordinary edit\n"
			}
			dest := path
			if method.replace {
				dest = filepath.Join(filepath.Dir(path), "replacement")
			}
			if err := os.WriteFile(dest, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if method.replace {
				if err := os.Rename(dest, path); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.Stat(path)
			if err != nil || os.SameFile(before, after) == method.replace {
				t.Fatalf("replacement=%v before=%v after=%v err=%v", method.replace, before, after, err)
			}
			wantRefused := method.replace || method.changed
			if err := a.Check(); (err != nil) != wantRefused {
				t.Fatalf("running run: refused=%v want=%v err=%v", err != nil, wantRefused, err)
			}
			fresh, ds, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
			if err != nil || !fresh.localAuthority.OwnerOnly() || fresh.localAuthority.Check() != nil {
				t.Fatalf("next launch: %v %v", ds, err)
			}
			// Restoring the text on the replacement inode is still a different source.
			if method.replace {
				if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := a.Check(); err == nil {
					t.Fatal("restoring text on a replacement inode restored old authority")
				}
			} else if method.changed {
				if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := a.Check(); err != nil {
					t.Fatalf("restoring original bytes on the original inode refused authority: %v", err)
				}
			}
		})
	}
}

func TestLocalRolesUnreadableSystemNeverFallsBack(t *testing.T) {
	for _, value := range []string{"owner_only", "off"} {
		t.Run(value, func(t *testing.T) {
			root, src, read, pin := localRolesFixture(t, "local_roles: "+value+"\n")
			src.User = writeFile(t, root, "user.yaml", "local_roles: off\n", 0o600)
			if err := os.Chmod(root+EtcPath, 0o600); err != nil {
				t.Fatal(err)
			}
			for launch := 1; launch <= 2; launch++ {
				if m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin); err == nil || m != nil {
					t.Fatalf("launch %d accepted unreadable system %q: machine present=%v err=%v", launch, value, m != nil, err)
				}
			}
			m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustWarn, read, pin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.ApprovalAuthority(); err == nil {
				t.Fatal("unreadable system source fell back to personal authority")
			}
			if err := os.Chmod(root+EtcPath, 0o644); err != nil {
				t.Fatal(err)
			}
			m, _, err = loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
			if err != nil {
				t.Fatal(err)
			}
			a, err := m.ApprovalAuthority()
			if err != nil || a.OwnerOnly() != (value == LocalRolesOwnerOnly) {
				t.Fatalf("corrected system source: authority=%+v err=%v", a, err)
			}
		})
	}
}
