// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func localRolesFixture(t *testing.T, system string) (string, Sources, layerReader, authorityPinner) {
	t.Helper()
	root := trustedDir(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/etc/tego", 0o755); err != nil {
		t.Fatal(err)
	}
	if system != "" {
		writeFile(t, root+"/etc/tego", "config.yaml", system, 0o644)
	}
	// The loader also probes the layer's identity at the path it is given, so the fixture names the layer by its
	// real path under root and the rooted readers take the system-relative name.
	src := Sources{Etc: root + EtcPath}
	read := func(path string, layer Layer, uid int) ([]byte, bool, error) {
		if layer == LayerEtc {
			return readSystemTrustedAt(root, strings.TrimPrefix(path, root), os.Getuid(), uid, MaxLayerSize)
		}
		return readLayer(path, layer, uid)
	}
	pin := func(path string, uid int, data []byte) (LocalAuthority, error) {
		return pinLocalAuthorityAt(root, strings.TrimPrefix(path, root), os.Getuid(), uid, data)
	}
	return root, src, read, pin
}

func TestLocalRolesSystemFloor(t *testing.T) {
	const system = "local_roles: owner_only\n"
	root, src, read, pin := localRolesFixture(t, system)
	src.User = writeFile(t, root, "user.yaml", "local_roles: off\n", 0o600)
	src.EnvFile = writeFile(t, root, "explicit.yaml", "local_roles: off\n", 0o600)
	m, ds, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
	if err != nil {
		t.Fatal(err, ds)
	}
	a, err := m.ApprovalAuthority()
	sum := sha256.Sum256([]byte(system))
	if err != nil || !a.OwnerOnly() || a.Digest() != hex.EncodeToString(sum[:]) || a.Check() != nil || countCode(ds, CodeIgnored) != 2 || m.LocalRoles.Source.Layer != LayerEtc {
		t.Fatalf("floor: %+v %v %v", m, ds, err)
	}
}

func TestLocalRolesLegacyAbsentAndUserOnly(t *testing.T) {
	for _, system := range []string{"", "version: 0\n", "local_roles: off\n"} {
		t.Run(strings.TrimSpace(system), func(t *testing.T) {
			root, src, read, pin := localRolesFixture(t, system)
			src.EnvFile = writeFile(t, root, "explicit.yaml", "local_roles: owner_only\n", 0o600)
			m, ds, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
			if err != nil {
				t.Fatal(ds, err)
			}
			a, err := m.ApprovalAuthority()
			if err != nil || a.OwnerOnly() || a.Digest() != "" || a.Check() != nil {
				t.Fatalf("legacy: %+v %v", a, err)
			}
		})
	}
}

func TestLocalRolesSourceLoss(t *testing.T) {
	for _, change := range []string{"removed", "unreadable", "writable", "replaced equal", "edited", "parent replaced"} {
		t.Run(change, func(t *testing.T) {
			root, src, read, pin := localRolesFixture(t, "local_roles: owner_only\n")
			m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin)
			if err != nil {
				t.Fatal(err)
			}
			a, err := m.ApprovalAuthority()
			if err != nil {
				t.Fatal(err)
			}
			path := root + EtcPath
			switch change {
			case "removed":
				err = os.Remove(path)
			case "unreadable":
				err = os.Chmod(path, 0o600)
			case "writable":
				err = os.Chmod(path, 0o666)
			case "replaced equal":
				writeFile(t, filepath.Dir(path), "new", "local_roles: owner_only\n", 0o644)
				err = os.Rename(filepath.Dir(path)+"/new", path)
			case "edited":
				err = os.WriteFile(path, []byte("local_roles: off\n"), 0o644)
			case "parent replaced":
				err = os.Rename(filepath.Dir(path), filepath.Dir(path)+".old")
				if err == nil {
					err = os.Mkdir(filepath.Dir(path), 0o755)
				}
				if err == nil {
					err = os.WriteFile(path, []byte("local_roles: owner_only\n"), 0o644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Check(); err == nil {
				t.Fatal("source loss retained approval authority")
			}
			if !a.OwnerOnly() {
				t.Fatal("source loss downgraded the pinned mode")
			}
		})
	}
}

func TestLocalRolesClosedAndUntrusted(t *testing.T) {
	for _, raw := range []string{"null", "true", "[]", "{}", "OWNER_ONLY", "approver", "owner_only\nlocal_roles: off"} {
		if _, ds := parseLayer("config", []byte("local_roles: "+raw+"\n")); !HasErrors(ds) {
			t.Fatalf("accepted %q", raw)
		}
	}
	root, src, read, pin := localRolesFixture(t, "local_roles: owner_only\n")
	if err := os.Chmod(root+"/etc", 0o777); err != nil {
		t.Fatal(err)
	}
	if m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustAbort, read, pin); err == nil || m != nil {
		t.Fatal("untrusted source activated")
	}
	m, _, err := loadSourcesWithAuthority(src, root, os.Getuid(), TrustWarn, read, pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApprovalAuthority(); err == nil {
		t.Fatal("unknown source became legacy")
	}
	m = Builtin()
	m.LocalRoles.Value = LocalRolesOwnerOnly
	if _, err := m.ApprovalAuthority(); err == nil {
		t.Fatal("unproved mode activated")
	}
}
