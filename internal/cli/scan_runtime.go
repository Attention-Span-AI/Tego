// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strconv"
	"strings"
)

// The binary defaults containermaxprocs to zero to disable quota adaptation.
// Mirror runtime parsing: valid int32 values overwrite left to right; malformed
// values leave the earlier value. This checks the override, not descriptor state:
// a v1 period-open failure can retain an unread quota descriptor even at zero.
func scanRuntimeQuotaClosed(debug string) bool {
	value := int64(0)
	for _, field := range strings.Split(debug, ",") {
		key, raw, ok := strings.Cut(field, "=")
		if !ok || key != "containermaxprocs" {
			continue
		}
		if n, err := strconv.ParseInt(raw, 10, 32); err == nil {
			value = n
		}
	}
	return value <= 0
}
