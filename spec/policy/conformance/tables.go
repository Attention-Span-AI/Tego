// SPDX-License-Identifier: Apache-2.0

// Package conformance embeds the specification's shared decision tables (README.md: table schema v2). The
// pure-core and actual-kernel test runners consume the same immutable bytes.
package conformance

import (
	"embed"
	"io/fs"
	"sort"
)

//go:embed *.yaml
var tables embed.FS

// Read returns a fresh copy of the named specification table.
func Read(name string) ([]byte, error) { return tables.ReadFile(name) }

// List names every table, sorted.
func List() ([]string, error) {
	names, err := fs.Glob(tables, "*.yaml")
	sort.Strings(names)
	return names, err
}
