// SPDX-License-Identifier: Apache-2.0

package setup

import "path/filepath"

// eco is what a project's markers add to a contract whose writes are restricted: the folders its package manager
// writes, the cache variables pointed inside the project, and the .gitignore lines for what init generates.
type eco struct {
	writes []entry
	env    []entry
	ignore []string
}

// ecosystem reads dir's markers: package.json gives ./node_modules/, Cargo.toml ./target/, pyproject.toml or a
// requirements*.txt ./.venv/, and go.mod points GOCACHE and GOMODCACHE under ./.tego/cache/ with its write entry.
func ecosystem(dir string) eco {
	var e eco
	at := func(name string) bool { return exists(filepath.Join(dir, name)) }
	if at("package.json") {
		e.writes = append(e.writes, entry{"./node_modules/", "package.json: npm installs here"})
	}
	if at("Cargo.toml") {
		e.writes = append(e.writes, entry{"./target/", "Cargo.toml: cargo builds here"})
	}
	reqs, _ := filepath.Glob(filepath.Join(dir, "requirements*.txt"))
	if at("pyproject.toml") || len(reqs) > 0 {
		e.writes = append(e.writes, entry{"./.venv/", "pyproject.toml or requirements*.txt: the virtualenv"})
	}
	if at("go.mod") {
		cache := filepath.Join(dir, ".tego", "cache")
		e.writes = append(e.writes, entry{"./.tego/cache/", "go.mod: the Go build and module caches"})
		e.env = append(e.env,
			entry{"GOCACHE=" + filepath.Join(cache, "go-build"), "go.mod: the build cache inside the writable ./.tego/cache/"},
			entry{"GOMODCACHE=" + filepath.Join(cache, "go-mod"), "go.mod: the module cache inside the writable ./.tego/cache/"})
		e.ignore = append(e.ignore, ".tego/cache/")
	}
	return e
}
