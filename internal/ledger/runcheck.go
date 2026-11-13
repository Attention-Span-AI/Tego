// SPDX-License-Identifier: Apache-2.0

package ledger

import "github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"

// runCheck is the check of one run's lines, one line at a time, that Verify, the Binder and the Follower share:
// chaincheck.LineCheck, the pure check (spec/record/v1/CHAIN.md) this package hands the lines it reads.
type runCheck = chaincheck.LineCheck
