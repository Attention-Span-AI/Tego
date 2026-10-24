// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// EnvAdvice is what init suggests for one .env file the engine would block by default: keep blocking
// it, or keep it readable because the tool that loads it treats every key in it as public build settings.
type EnvAdvice struct {
	// Path is the file, relative to the project.
	Path string `json:"path"`
	// Keys are the variable names in it. Values are never kept.
	Keys []string `json:"keys"`
	// LoadedBy names the frontend tool that loads the file when building, if one was found beside it.
	LoadedBy string `json:"loaded_by,omitempty"`
	// Prefix is that tool's prefix for public keys, e.g. VITE_.
	Prefix string `json:"public_prefix,omitempty"`
	// NotPublic lists the keys without that prefix.
	NotPublic []string `json:"not_public,omitempty"`
	// Readable is the suggestion: true when a tool loads the file and every key in it is public for that tool.
	// Enforcing it needs the engine's per-path exception; until then it is a suggestion only.
	Readable bool `json:"suggest_readable"`
}

// framework is a frontend tool that loads .env files from its project folder when it builds, and the prefix
// that marks a key as public (shipped to the browser, so not a secret by the tool's own rules).
type framework struct {
	dep, name, prefix string
}

// frameworks are checked in this order against package.json's dependencies.
var frameworks = []framework{
	{"vite", "Vite", "VITE_"},
	{"next", "Next.js", "NEXT_PUBLIC_"},
	{"react-scripts", "Create React App", "REACT_APP_"},
	{"expo", "Expo", "EXPO_PUBLIC_"},
	{"@sveltejs/kit", "SvelteKit", "PUBLIC_"},
	{"astro", "Astro", "PUBLIC_"},
	{"nuxt", "Nuxt", "NUXT_PUBLIC_"},
}

// maxConfigBytes bounds what is read of a package.json or a .env file: a hand-written one is far smaller.
const maxConfigBytes = 1 << 20

// AdviseEnvFiles looks at each .env file in secrets that the engine blocks by default and suggests whether it
// can stay readable. It reads the package.json beside the file (to learn which tool loads it) and the variable
// names in the file. A value is read only as far as the '=' that ends its name and is never kept. A file that is
// a symbolic link, or not a regular file, is left alone: a link could lead to ~/.aws.
func AdviseEnvFiles(root string, secrets []Finding) ([]EnvAdvice, error) {
	var out []EnvAdvice
	for _, f := range secrets {
		if !f.BuiltIn || strings.HasSuffix(f.Path, "/") {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(f.Path))
		keys, err := envKeyNames(abs)
		if err != nil {
			return nil, fmt.Errorf("read the names in %s: %w", f.Path, err)
		}
		a := EnvAdvice{Path: f.Path, Keys: keys}
		fw, err := frameworkIn(filepath.Dir(abs))
		if err != nil {
			return nil, err
		}
		if fw != nil {
			a.LoadedBy, a.Prefix = fw.name, fw.prefix
			for _, k := range keys {
				if !strings.HasPrefix(k, fw.prefix) {
					a.NotPublic = append(a.NotPublic, k)
				}
			}
			a.Readable = len(keys) > 0 && len(a.NotPublic) == 0
		}
		out = append(out, a)
	}
	return out, nil
}

// frameworkIn returns the frontend tool the package.json in dir depends on, or nil.
func frameworkIn(dir string) (*framework, error) {
	data, err := readRegular(filepath.Join(dir, "package.json"))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrOnlyInCloud) || errors.Is(err, errNotRegular) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil, nil // not JSON we understand: no suggestion rather than a failed setup
	}
	for i := range frameworks {
		dep := frameworks[i].dep
		if _, ok := pkg.Dependencies[dep]; ok {
			return &frameworks[i], nil
		}
		if _, ok := pkg.DevDependencies[dep]; ok {
			return &frameworks[i], nil
		}
	}
	return nil, nil
}

// envKeyNames returns the variable names a .env file sets, sorted, each once. Lines that are blank, comments,
// or not NAME=… are skipped; "export NAME=…" counts. Nothing after the '=' is kept.
func envKeyNames(path string) ([]string, error) {
	data, err := readRegular(path)
	if errors.Is(err, errNotRegular) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrOnlyInCloud) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), maxConfigBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, _, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if ok && validEnvName(name) {
			seen[name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// validEnvName reports whether s is a shell variable name: letters, digits and '_', not starting with a digit.
func validEnvName(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// errNotRegular marks a path that is a symbolic link or not a regular file.
var errNotRegular = errors.New("not a regular file")

// ErrOnlyInCloud is a file whose contents aren't on this disk (iCloud keeps only its name here).
var ErrOnlyInCloud = errors.New("only in iCloud, not on this disk")

// readRegular reads path, at most maxConfigBytes, refusing a symbolic link or anything but a regular file, and
// a file that is only in iCloud. The open does not follow a link (O_NOFOLLOW) and does not wait on a FIFO
// (O_NONBLOCK), and what it opened must be the file Lstat saw, so a link or a FIFO swapped in between is refused.
func readRegular(path string) (data []byte, err error) {
	defer func() { noted(path, err) }()
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if dataless(fi) {
		return nil, ErrOnlyInCloud // opening it would wait on a download: Maze never does
	}
	betweenStatAndOpen(path)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, errNotRegular // a link was put there after the Lstat
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	if now, err := f.Stat(); err != nil {
		return nil, err
	} else if !now.Mode().IsRegular() || !os.SameFile(fi, now) {
		return nil, errNotRegular
	}
	data, err = io.ReadAll(io.LimitReader(f, maxConfigBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return data, nil
}

// betweenStatAndOpen runs between readRegular's Lstat and its open; a test swaps the file there.
var betweenStatAndOpen = func(string) {}
