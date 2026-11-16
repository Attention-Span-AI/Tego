// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"embed"
	"io/fs"
)

// sample is the test project tego start offers: a tiny Python app whose bundled dependency is poisoned on purpose,
// and harmless by design (it reads only the project's fake .env and connects only to 127.0.0.1:8801, where nothing
// listens), so a first session shows what Tego blocks. "all:" keeps the .env, which a plain embed pattern skips.
//
//go:embed all:sample
var sample embed.FS

// Sample is the test project's files, rooted at the project folder.
func Sample() fs.FS {
	sub, err := fs.Sub(sample, "sample")
	if err != nil {
		panic(err) // the embedded tree always has the folder
	}
	return sub
}
