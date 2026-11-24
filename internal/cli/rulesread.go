// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// readRulesPath reads the rules file at path, as a contract is opened (agent.OpenFlags) and through the one function
// every rules file is read through (config.ReadRulesFile, which checks the file system of the descriptor it reads),
// under the contract's cap. The commands that read a person's rules file to show, edit or save it use it, so a rules
// file on a file system whose owner tego cannot rely on (WSL's Windows drive) is refused there as at load.
func readRulesPath(path string) ([]byte, error) {
	f, err := os.OpenFile(path, agent.OpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	data, err := config.ReadRulesFile(context.Background(), f, path, agent.MaxContractSize+1)
	if err != nil {
		return nil, err
	}
	if len(data) > agent.MaxContractSize {
		return nil, fmt.Errorf("%s: %w", path, agent.ErrTooLarge)
	}
	return data, nil
}
