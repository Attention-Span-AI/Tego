// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"context"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Compute is ComputeCtx (whose doc is the contract) with a context that is never cancelled.
func Compute(r *ledger.Reader, rt *agent.RuleTable) (*Report, error) {
	return ComputeCtx(context.Background(), r, rt)
}
