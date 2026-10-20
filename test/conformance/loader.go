// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"debug/elf"
	"fmt"
	"io"
	"strings"
	"sync"
)

// loaderProgram is the dynamic program whose PT_INTERP names the machine's loader; the exec space's direct-loader
// cells run it through that loader (OpExecLoader).
const loaderProgram = "/usr/bin/true"

var loader = sync.OnceValues(func() (string, error) {
	f, err := elf.Open(loaderProgram)
	if err != nil {
		return "", fmt.Errorf("the exec space's loader: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b, err := io.ReadAll(p.Open())
			if err != nil {
				return "", fmt.Errorf("the exec space's loader: %s's PT_INTERP: %w", loaderProgram, err)
			}
			return strings.TrimRight(string(b), "\x00"), nil
		}
	}
	return "", fmt.Errorf("the exec space's loader: %s is static (no PT_INTERP), so it names no loader", loaderProgram)
})

// Loader is the dynamic loader as the machine's /usr/bin/true names it in PT_INTERP, which a table spells {{LOADER}}.
func Loader() (string, error) { return loader() }
