// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// PolicySource is a bounded trusted descriptor read and the placement facts checked
// for those bytes. It does not parse a policy or authorize a launch (ADR 0153).
type PolicySource struct {
	Data     []byte
	Resolved string
	Owner    int
	Mode     fs.FileMode
	Walk     []string
}

// ReadPolicySource reuses system placement and absence checks for a system policy,
// or checks an owner/root walk for a private user policy. Unknown never means absent.
// User files and their resolved containing directory must be private. No descriptor escapes.
func ReadPolicySource(path string, system bool, uid int, maxBytes int64) (PolicySource, bool, error) {
	return readPolicySourceAt("/", path, system, 0, uid, maxBytes)
}

func readPolicySourceAt(root, path string, system bool, rootUID, uid int, maxBytes int64) (PolicySource, bool, error) {
	var out PolicySource
	if maxBytes <= 0 || maxBytes > MaxLayerSize {
		return out, false, fmt.Errorf("config: invalid policy source bound")
	}
	if why := layerPathProblem(path, true); why != "" {
		return out, false, fmt.Errorf("config: policy source %s: %s", path, why)
	}
	owner := uid
	if system {
		owner = rootUID
	}
	walk, absent, err := inspectPolicyLayer(root, path, owner, system)
	if err != nil {
		return out, false, err
	}
	for _, c := range walk.checks {
		out.Walk = append(out.Walk, c.path)
	}
	if walk.missing != "" {
		out.Walk = append(out.Walk, walk.missing)
	}
	if err := walk.recheck(); err != nil {
		return PolicySource{}, false, err
	}
	if absent {
		return out, true, nil
	}
	f, err := os.OpenFile(walk.resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return out, false, fmt.Errorf("config: open policy source %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // No descriptor escapes, including on a failed trust check.
	st, err := fstat(f)
	if err != nil {
		return out, false, fmt.Errorf("config: stat policy source %s: %w", path, err)
	}
	if !sameSystemComponent(st, walk.file) {
		return out, false, untrusted(path, st, reasonSystemReplaced)
	}
	if !system {
		if st.Mode&0o077 != 0 {
			return out, false, untrusted(path, st, "user policy source must be private (0600)")
		}
		// Walk observations include symlinks as well as directories. Apply privacy
		// to the actual parent and bind it to the already opened source descriptor.
		if err := checkDirectoryForRead(f, walk.resolved, uid, true); err != nil {
			return out, false, err
		}
	}
	// A policy layer is a rules file: read through the one function that checks its file system (ReadRulesFile).
	if err := checkTrustedFile(f, path, uid, maxBytes); err != nil {
		return out, false, err
	}
	data, err := ReadRulesFile(context.Background(), f, path, maxBytes+1)
	if err == nil && int64(len(data)) > maxBytes {
		err = fmt.Errorf("config: %s: layer file exceeds %d bytes", path, maxBytes)
		if maxBytes == MaxLayerSize {
			err = fmt.Errorf("config: %s: %w", path, errTooLarge)
		}
	}
	if err != nil {
		return out, false, err
	}
	if err := walk.recheck(); err != nil {
		return PolicySource{}, false, err
	}
	out.Data, out.Resolved, out.Owner, out.Mode = data, walk.resolved, int(st.Uid), fs.FileMode(st.Mode&0o7777)
	return out, false, nil
}
