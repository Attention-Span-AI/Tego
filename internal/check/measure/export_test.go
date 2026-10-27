// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"context"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// Compute is ComputeAt (whose doc is the contract) with no context to stop on and no clock reading.
func Compute(r *ledger.Reader, p Prices) (*Report, error) {
	return ComputeAt(context.Background(), r, p, 0)
}
