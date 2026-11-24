// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// layerIdentity names the resolved file and containing directory, or the existing
// ancestor and unresolved suffix of an optional absent layer. Mode and timestamps are not identity: a
// reload applies trust again, and harmless metadata changes need not refuse it.
type layerIdentity struct {
	Target, Ancestor, Missing string
	Device, Inode             uint64
	ParentDevice, ParentInode uint64
}

type layerObservation struct {
	layerIdentity
	Size              int64
	Modified, Changed syscall.Timespec
}

func inspectLayerIdentity(path string) (layerObservation, error) {
	target, ancestor, missing, st, err := resolveBaselinePath(path)
	if err != nil {
		return layerObservation{}, err
	}
	observation := layerObservation{layerIdentity: layerIdentity{
		Target: target, Ancestor: ancestor, Missing: missing,
		Device: uint64(st.Dev), Inode: st.Ino,
	}}
	if missing == "" {
		parent, err := os.Stat(filepath.Dir(target))
		if err != nil {
			return layerObservation{}, err
		}
		parentStat, ok := parent.Sys().(*syscall.Stat_t)
		if !ok || !parent.IsDir() {
			return layerObservation{}, fmt.Errorf("layer has no directory identity")
		}
		observation.ParentDevice, observation.ParentInode = uint64(parentStat.Dev), parentStat.Ino
		// An in-place rewrite during the descriptor read is also uncertain. For
		// absence the directory's metadata can change due to unrelated siblings.
		observation.Size, observation.Modified, observation.Changed = st.Size, st.Mtim, st.Ctim
	}
	return observation, nil
}

// CheckAdmissionSnapshot checks that a newly loaded strict decision snapshot
// still names exactly the configuration an adoption was prepared with. It does
// no I/O: current must be freshly loaded after the migration lock wait. Existing
// adopted runs intentionally keep their original snapshot.
func (m *Machine) CheckAdmissionSnapshot(current *Machine) error {
	if !m.BaselineKnown() || !current.BaselineKnown() {
		return fmt.Errorf("machine configuration admission is UNKNOWN")
	}
	if m.Home != current.Home || !slices.Equal(m.sources, current.sources) || m.layerIdentities != current.layerIdentities {
		return fmt.Errorf("machine configuration changed after adoption preparation")
	}
	prepared, err := admissionBaselineDigest(m.baseline)
	if err != nil {
		return err
	}
	fresh, err := admissionBaselineDigest(current.baseline)
	if err != nil {
		return err
	}
	if prepared != fresh {
		return fmt.Errorf("machine baseline changed after adoption preparation")
	}
	return nil
}

func admissionBaselineDigest(b Baseline) ([sha256.Size]byte, error) {
	data, err := json.Marshal(b.Entries())
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("config: digest admission baseline: %w", err)
	}
	return sha256.Sum256(data), nil
}
