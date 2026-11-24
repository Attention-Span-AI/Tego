// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// releaseAssets refuses ambiguous checksums, even for assets this check does
// not use. The caller authenticates the complete byte string independently.
func releaseAssets(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return nil, errors.New("release checksums missing or exceed 64 KiB")
	}
	assets := map[string]string{}
	for i, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		if len(line) < 67 || line[64] != ' ' || line[65] != ' ' || !hashPattern.Match(line[:64]) {
			return nil, fmt.Errorf("checksums line %d: require lowercase SHA-256, two spaces and one asset name", i+1)
		}
		name := string(line[66:])
		if !clean(name) || strings.ContainsAny(name, " /\\\t") || name == "." || name == ".." {
			return nil, fmt.Errorf("checksums line %d: unsafe asset name", i+1)
		}
		if _, ok := assets[name]; ok {
			return nil, fmt.Errorf("checksums line %d: duplicate asset", i+1)
		}
		assets[name] = string(line[:64])
	}
	return assets, nil
}
