// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// LocalRolesOwnerOnly permits once answers from initial-namespace root only.
const LocalRolesOwnerOnly = "owner_only"

// LocalAuthority pins the trusted system source for one run. Its zero value is
// legacy authority. It never reloads or merges the machine's ordinary settings.
type LocalAuthority struct {
	digest       string
	root, path   string
	rootUID, uid int
	walk         systemLayerWalk
}

// OwnerOnly reports whether this run has the root-only approval floor.
func (a LocalAuthority) OwnerOnly() bool { return a.digest != "" }

// Digest is the SHA-256 of the exact trusted system layer bytes at activation.
func (a LocalAuthority) Digest() string { return a.digest }

// Check refuses authority loss or drift, including replacement with equal bytes.
// No cached permission survives a failed read. Legacy authority performs no I/O.
func (a LocalAuthority) Check() error {
	if !a.OwnerOnly() {
		return nil
	}
	if err := a.walk.recheck(); err != nil {
		return err
	}
	data, absent, err := readSystemTrustedAt(a.root, a.path, a.rootUID, a.uid, MaxLayerSize)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if absent || hex.EncodeToString(sum[:]) != a.digest {
		return fmt.Errorf("config: local approval authority changed or disappeared")
	}
	return a.walk.recheck()
}

// ApprovalAuthority returns the pinned floor. A degraded system source and a
// hand-built owner_only setting without its trust proof cannot activate a run.
func (m *Machine) ApprovalAuthority() (LocalAuthority, error) {
	if m == nil || m.localAuthorityUnknown {
		return LocalAuthority{}, fmt.Errorf("config: local approval authority is unknown")
	}
	if m.LocalRoles.Value == LocalRolesOwnerOnly && !m.localAuthority.OwnerOnly() {
		return LocalAuthority{}, fmt.Errorf("config: local approval authority has no trusted source")
	}
	return m.localAuthority, nil
}

func pinLocalAuthority(path string, uid int, data []byte) (LocalAuthority, error) {
	return pinLocalAuthorityAt("/", path, 0, uid, data)
}

func pinLocalAuthorityAt(root, path string, rootUID, uid int, data []byte) (LocalAuthority, error) {
	walk, absent, err := inspectSystemLayer(root, path, rootUID)
	if err != nil {
		return LocalAuthority{}, err
	}
	if absent {
		return LocalAuthority{}, fmt.Errorf("config: local approval authority disappeared")
	}
	read, absent, err := readSystemTrustedAt(root, path, rootUID, uid, MaxLayerSize)
	if err != nil {
		return LocalAuthority{}, err
	}
	if absent || !bytes.Equal(read, data) {
		return LocalAuthority{}, fmt.Errorf("config: local approval authority changed during activation")
	}
	if err := walk.recheck(); err != nil {
		return LocalAuthority{}, err
	}
	sum := sha256.Sum256(data)
	return LocalAuthority{digest: hex.EncodeToString(sum[:]), root: root, path: path, rootUID: rootUID, uid: uid, walk: walk}, nil
}
