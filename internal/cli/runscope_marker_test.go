// SPDX-License-Identifier: Apache-2.0

package cli

import "os"

// scopeWriteMarker publishes a complete helper acknowledgement. Creation alone is not readiness: a reader can
// open os.WriteFile's new file before its data is written, especially in a race build on a loaded machine.
func scopeWriteMarker(path string, data []byte) error {
	tmp := path + ".ready"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
