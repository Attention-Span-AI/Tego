// SPDX-License-Identifier: Apache-2.0

package rulesview

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
		exe, _ := os.Executable()
		if st, err := os.Stat(exe + ".source-block"); err == nil && st.IsDir() {
			if err := os.WriteFile(filepath.Join(exe+".source-block", os.Args[2]+"-"+strconv.Itoa(os.Getpid())), nil, 0600); err != nil {
				os.Exit(125)
			}
			readNoFollow = blockSourceRead
		}
		os.Exit(contracts.HelperMain(os.Args[2:]))
	}
}
