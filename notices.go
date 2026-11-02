// SPDX-License-Identifier: Apache-2.0

// Package tego is the module's root, and holds the licensing material the shipped binaries carry (docs/GAPS.md B12):
// LICENSE, NOTICE, THIRD_PARTY_NOTICES.txt and the licence texts under LICENSES/, the licence files of the release's
// tego_<version>_licenses.tar.gz. A tego or tego-control passed on without that archive still holds them, and
// `tego licenses` and `tego-control licenses` print them. go:embed reaches no parent directory, so the root's package
// is the one that embeds these files where they are, with no copy to keep in step; scripts/check-licenses.sh holds
// the embedded set to the licence files it checks the release archive for.
//
// Imports: the standard library only. Both binaries link it, so it never imports the engine or the control plane.
package tego

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"slices"
)

// texts is the licensing material. A pattern that matches no file fails the build.
//
//go:embed LICENSE NOTICE THIRD_PARTY_NOTICES.txt LICENSES/*.txt
var texts embed.FS

// lead is how the print starts: the project's licence, its NOTICE, and the third-party notices NOTICE refers to. The
// full texts under LICENSES/ follow, by name.
var lead = []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt"}

// WriteLicenses writes every embedded file to w whole, each under a line naming it ("==> NOTICE <=="), with a blank
// line between two.
func WriteLicenses(w io.Writer) error { return write(w, texts) }

// write is WriteLicenses over fsys.
func write(w io.Writer, fsys fs.FS) error {
	full, err := fs.Glob(fsys, "LICENSES/*.txt")
	if err != nil {
		return fmt.Errorf("list the licence texts: %w", err)
	}
	slices.Sort(full)
	for i, name := range append(slices.Clone(lead), full...) {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read the embedded %s: %w", name, err)
		}
		sep := "\n"
		if i == 0 {
			sep = ""
		}
		if len(b) > 0 && b[len(b)-1] != '\n' {
			b = append(b, '\n')
		}
		if _, err := fmt.Fprintf(w, "%s==> %s <==\n%s", sep, name, b); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}
