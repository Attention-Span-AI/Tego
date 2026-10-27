// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// RunStartExtras are the reserved run_start blocks (record minors 32 to 34) that the caller of
// Run knows and the engine does not compute. Nothing in this tree fills one. Each holds names, versions, hashes and modes, never an argv, an environment value or a
// secret value. Every field nil is a run with none of them.
//
// This is the one way such a block reaches run_start. Below a block's revision Run refuses it.
type RunStartExtras struct {
	Deployment *record.Deployment
	Secrets    []record.SecretUse
	Vault      *record.VaultUse
	Shares     []record.ShareUse
}

// clone is a deep copy of x: nothing in it shares memory with the caller's value, and a nil field stays nil.
func (x RunStartExtras) clone() RunStartExtras {
	c := RunStartExtras{Secrets: slices.Clone(x.Secrets), Shares: slices.Clone(x.Shares)}
	if x.Deployment != nil {
		d := *x.Deployment
		if d.Change != nil {
			ch := *d.Change
			d.Change = &ch
		}
		c.Deployment = &d
	}
	if x.Vault != nil {
		v := *x.Vault
		c.Vault = &v
	}
	return c
}

// apply puts x's blocks into p.
func (x RunStartExtras) apply(p *record.RunStartPayload) {
	p.Deployment, p.Secrets, p.Vault, p.Shares = x.Deployment, x.Secrets, x.Vault, x.Shares
}

// launchMinor is the record revision a launched run's run_start carries and its RunStartExtras are checked at:
// record.Minor. One value for both, so the check and the stamp cannot disagree; a variable only so a test can stand
// in for the binary that raises Minor to a block's revision.
var launchMinor = record.Minor

// check refuses blocks that run_start at launchMinor may not carry, or that are malformed: ErrDeps naming the
// record's code (a block whose revision is above it is [below-minor]).
func (x RunStartExtras) check() error {
	p := record.RunStartPayload{RecordMinor: launchMinor}
	x.apply(&p)
	if err := p.ValidateFields(); err != nil {
		return fmt.Errorf("%w: run_start extras: %w", ErrDeps, err)
	}
	return nil
}
