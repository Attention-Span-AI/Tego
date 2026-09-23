// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ErrNotLoaded is returned by Canonical on a Contract that did not come from
// a successful Load.
var ErrNotLoaded = errors.New("contract was not produced by Load")

// Canonical is the deterministic re-serialization of the merged contract
// (R13): Go struct field order, omitempty per the struct tags, 2-space indent,
// "\n" line endings, trailing newline. The one departure from the tags is an
// explicit `deny_read: []`, which switches the built-in list off and so is
// emitted (FSSection.MarshalYAML). It is computed from the decoded
// structure, so comments and whitespace never change it, and before any
// ceiling clamp, so it is the same on every machine (I3). Every
// not-yet-supported field is still emitted when non-empty. internal/ledger
// writes these exact bytes as contract.yaml.
func (c *Contract) Canonical() ([]byte, error) {
	if c == nil || !c.loaded {
		return nil, ErrNotLoaded
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, fmt.Errorf("agent: canonical: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("agent: canonical: %w", err)
	}
	return buf.Bytes(), nil
}

// Hash is contract_hash: sha256 of Canonical() (R13).
func (c *Contract) Hash() ([32]byte, error) {
	b, err := c.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}
