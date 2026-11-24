// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// Tests re-execute their own image just as the control binary does. This test
// dispatch has no product startup, ledger, config or owner's log side effects.
func init() {
	if len(os.Args) > 1 && os.Args[1] == contracts.HelperCommand {
		if executable, err := os.Executable(); err == nil && len(os.Args) > 2 {
			if fi, err := os.Stat(executable + ".count"); err == nil && fi.IsDir() {
				if err := os.WriteFile(filepath.Join(executable+".count", os.Args[2]+"-"+strconv.Itoa(os.Getpid())), nil, 0o600); err != nil {
					os.Exit(125)
				}
			}
		}
		os.Exit(contracts.HelperMain(os.Args[2:]))
	}
}
