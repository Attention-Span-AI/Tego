// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Env is everything a scan reads from the machine. FromOS fills it from the running process; tests
// build one by hand.
type Env struct {
	// Home is the user's home directory, where the personal scope and the credential files live.
	Home string
	// Environ holds NAME=VALUE pairs as os.Environ returns them. Only the names are ever used.
	Environ []string
	// Path is the PATH value used to find installed programs.
	Path string
}

// FromOS reads the home directory, the environment and PATH of the running process.
func FromOS() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("find the home directory: %w", err)
	}
	return Env{Home: home, Environ: os.Environ(), Path: os.Getenv("PATH")}, nil
}

// names returns the variable names in e.Environ, without their values.
func (e Env) names() []string {
	out := make([]string, 0, len(e.Environ))
	for _, kv := range e.Environ {
		name, _, _ := strings.Cut(kv, "=")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// LookPath finds an executable named name in e.Path. It returns "" when there is none.
//
// It is a stat over PATH, not os/exec.LookPath: the repo starts and probes processes only through
// internal/platform/proc (ADR 0021 (3)), and finding a program needs no process. An empty PATH entry
// is skipped rather than read as the current directory, so a planted ./npm in the repo is never
// reported as the user's npm.
func (e Env) LookPath(name string) string {
	if name == "" || strings.ContainsRune(name, filepath.Separator) {
		return ""
	}
	for _, dir := range filepath.SplitList(e.Path) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// exists reports whether path names something, following no final symbolic link.
func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// homeRel renders an absolute path under home as ~/rel, and any other path unchanged.
func homeRel(home, path string) string {
	if home == "" {
		return path
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return "~/" + filepath.ToSlash(rel)
}
