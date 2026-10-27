// SPDX-License-Identifier: Apache-2.0

package sig

import (
	"fmt"
	"strings"
)

// String is the rule in the spelling Parse reads back.
func (r Rule) String() string {
	var spec string
	switch {
	case r.Basename != "":
		spec = r.Basename
	case r.Path != "":
		spec = r.Path
	case r.File != FileID{}:
		spec = fmt.Sprintf("file:%d:%d", r.File.Dev, r.File.Ino)
	default:
		spec = strings.Join(r.Argv, " ")
	}
	return r.Name + "=" + spec
}
