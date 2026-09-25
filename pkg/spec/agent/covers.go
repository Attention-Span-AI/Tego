// SPDX-License-Identifier: Apache-2.0

package agent

import "path/filepath"

// Covers reports whether entry is path or one of its ancestor directories, comparing whole components
// (docs/ARCHITECTURE.md §10: the walk is on components, never a string prefix), so /work covers /work/a and
// never /work-secret or /workshop. entry is cleaned first, so a trailing slash does not matter; an empty entry
// covers nothing, and "/" covers every absolute path. path must be clean: it is compared as given.
//
// It is the one containment test: evaluation (internal/policy/decide), the runtime's run-directory check and the
// recorder's fs index all ask it, and they used to ask three copies that differed on "" and a trailing slash.
// It allocates nothing: filepath.Clean returns an already clean entry as is.
func Covers(entry, path string) bool {
	_, ok := CoverSteps(entry, path)
	return ok
}

// Canonical is the spelling of r the kernel reports: its resolved path, or its declared one when compile
// resolved none, cleaned.
func (r FSRule) Canonical() string {
	if r.Resolved != "" {
		return filepath.Clean(r.Resolved)
	}
	return filepath.Clean(r.Path)
}

// Spellings is every path r is matched under: the declared path and, where it differs, the canonical one
// (Canonical). Both are kept because the declared one is what a path with no link in it resolves to, and
// what a hand-built table names, while the kernel reports the resolved one. The recorder's fs index and tier
// 2's fanotify policy both match by it.
func (r FSRule) Spellings() []string { return Spellings(r.Path, r.Resolved) }

// Spellings is FSRule.Spellings for any declared path and its resolution ("" when it has none): the
// declared path cleaned, then the resolved one cleaned when that is another path.
func Spellings(declared, resolved string) []string {
	out := []string{filepath.Clean(declared)}
	if resolved != "" {
		if r := filepath.Clean(resolved); r != out[0] {
			out = append(out, r)
		}
	}
	return out
}
