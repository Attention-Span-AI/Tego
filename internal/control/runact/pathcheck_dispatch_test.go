// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"github.com/attention-span-ai/tego/internal/contracts"
	"os"
)

// Tests re-execute their own image just as the control binary does. This test
// dispatch has no product startup, ledger, config or owner's log side effects.
func init() {
	if len(os.Args) > 1 && os.Args[1] == contracts.HelperCommand {
		os.Exit(contracts.HelperMain(os.Args[2:]))
	}
}
