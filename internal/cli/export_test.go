// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strconv"
	"strings"
)

// writeContract publishes the starter under name, as writeContractBytes publishes any contract.
func writeContract(path, name string, force bool) error {
	return writeContractBytes(path, []byte(strings.ReplaceAll(starter, "__NAME__", name)), force)
}

func (a privAction) String() string {
	switch a {
	case privNone:
		return "none"
	case privClear:
		return "clear"
	case privRefuse:
		return "refuse"
	}
	return "privAction(" + strconv.Itoa(int(a)) + ")"
}
