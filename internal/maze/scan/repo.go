// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Bounds on the repo walk, the same as the engine's built-in .env scan (compile_fs.go: envScanMaxDepth,
// envScanMaxEntries), so what init reports and what the engine covers agree on large repos too.
const (
	maxDepth   = 6
	maxEntries = 50000
	// markerDepth is how deep a toolchain file still counts: the root and one level down, which finds
	// backend/pyproject.toml and frontend/package.json in a two-part repo.
	markerDepth = 2
)

// skipDirs mirrors envScanSkipDirs in pkg/spec/agent/compile_fs.go: folders neither the engine's scan
// nor this one descends into.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, "target": true, ".venv": true, "venv": true}

// isEnvFile mirrors isEnvFile in pkg/spec/agent/compile_fs.go: .env and .env.<anything> except the
// four names that hold examples rather than values.
func isEnvFile(name string) bool {
	if name == ".env" {
		return true
	}
	if !strings.HasPrefix(name, ".env.") {
		return false
	}
	switch strings.TrimPrefix(name, ".env.") {
	case "example", "sample", "template", "dist":
		return false
	}
	return true
}

// secretFileWhy reports why a file name looks like it holds a secret. .env files are handled by
// isEnvFile, since the engine covers those itself.
func secretFileWhy(name string) (string, bool) {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".pub") {
		return "", false
	}
	switch lower {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519":
		return "SSH private key", true
	case "credentials.json", "service-account.json", ".pgpass", ".netrc", ".git-credentials":
		return "credentials file", true
	case ".npmrc", ".pypirc", ".yarnrc.yml":
		return "may hold a publish token", true
	case ".envrc":
		return "environment file (direnv)", true
	}
	if strings.HasSuffix(lower, ".env") || strings.HasPrefix(lower, "secrets.") {
		return "may hold secrets", true
	}
	for _, ext := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"} {
		if strings.HasSuffix(lower, ext) {
			return "key or certificate file (" + ext + ")", true
		}
	}
	return "", false
}

// Tool is a program the repo's toolchain needs.
type Tool struct {
	// Name is the program's name.
	Name string `json:"name"`
	// Path is where it was found on PATH; empty when it is not installed.
	Path string `json:"path,omitempty"`
	// From lists the files that showed the repo uses it, relative to the workspace root.
	From []string `json:"from"`
}

// Host is a network destination a found tool needs.
type Host struct {
	// Name is the host name.
	Name string `json:"name"`
	// Port is the TCP port.
	Port int `json:"port"`
	// For names the tool that needs it.
	For string `json:"for"`
}

// Repo is what the workspace holds and needs: the proposal for the workspace scope.
type Repo struct {
	// Secrets are files whose names say they hold secrets.
	Secrets []Finding `json:"secrets"`
	// Tools are the programs the toolchain files point to, installed or not.
	Tools []Tool `json:"tools"`
	// Hosts are the package registries the installed tools reach.
	Hosts []Host `json:"hosts"`
	// EnvLoaders are Python files that load .env files when the backend starts (pydantic-settings env_file,
	// python-dotenv): with .env blocked, the agent runs that backend without those values.
	EnvLoaders []string `json:"env_loaders,omitempty"`
	// Files is how many files and folders the walk looked at.
	Files int `json:"files"`
	// InCloud counts files whose contents are only in iCloud: their names count (a .env is still found), but Maze
	// doesn't open them, since that waits on a download.
	InCloud int `json:"in_cloud,omitempty"`
	// Cut reports whether the walk stopped at maxEntries before reading everything.
	Cut bool `json:"cut,omitempty"`
	// Unprintable counts files skipped because their names hold control characters.
	Unprintable int `json:"unprintable_names,omitempty"`
}

// printable reports whether a name has no control characters or invisible reordering marks.
func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}

// readBudget is how long the walk may spend opening files (the Python files that may load .env); names are
// still all looked at after it runs out.
const readBudget = 2 * time.Second

// maxPyFiles bounds how many Python files are searched for a .env loader, and maxPyBytes how much of each.
const (
	maxPyFiles   = 400
	maxPyBytes   = 256 << 10
	maxEnvLoader = 5
)

// envLoaderMarks are what a Python file that loads .env files contains.
var envLoaderMarks = []string{"env_file", "load_dotenv(", "dotenv_values("}

// loadsEnv reports whether the Python file at path loads .env files. It reads at most maxPyBytes and never
// follows a link.
func loadsEnv(path string) bool {
	data, err := readRegular(path)
	if err != nil {
		return false
	}
	if len(data) > maxPyBytes {
		data = data[:maxPyBytes]
	}
	for _, m := range envLoaderMarks {
		if strings.Contains(string(data), m) {
			return true
		}
	}
	return false
}

// markers maps a toolchain file name to the programs it shows the repo uses.
var markers = map[string][]string{
	"package.json":      {"node", "npm"},
	"package-lock.json": {"npm"},
	"bun.lock":          {"bun"},
	"bun.lockb":         {"bun"},
	"pnpm-lock.yaml":    {"pnpm"},
	"yarn.lock":         {"yarn"},
	"pyproject.toml":    {"python3", "pip"},
	"requirements.txt":  {"python3", "pip"},
	"setup.py":          {"python3", "pip"},
	"uv.lock":           {"uv"},
	"poetry.lock":       {"poetry"},
	"go.mod":            {"go"},
	"Cargo.toml":        {"cargo"},
	"Gemfile":           {"ruby", "bundle"},
	"composer.json":     {"php", "composer"},
	"Makefile":          {"make"},
}

// registries maps a program to the hosts it downloads packages from.
var registries = map[string][]string{
	"npm":      {"registry.npmjs.org"},
	"bun":      {"registry.npmjs.org"},
	"pnpm":     {"registry.npmjs.org"},
	"yarn":     {"registry.yarnpkg.com"},
	"pip":      {"pypi.org", "files.pythonhosted.org"},
	"uv":       {"pypi.org", "files.pythonhosted.org"},
	"poetry":   {"pypi.org", "files.pythonhosted.org"},
	"go":       {"proxy.golang.org", "sum.golang.org"},
	"cargo":    {"index.crates.io", "static.crates.io"},
	"bundle":   {"rubygems.org"},
	"composer": {"repo.packagist.org"},
}

// RegistryTool names the package tool whose registries are exactly hosts (all of them belong to it), or "".
func RegistryTool(hosts []string) string {
	for _, tool := range []string{"npm", "yarn", "pip", "go", "cargo", "bundle", "composer"} {
		known := registries[tool]
		all := len(hosts) > 0
		for _, h := range hosts {
			found := false
			for _, k := range known {
				found = found || k == h
			}
			all = all && found
		}
		if all {
			return tool
		}
	}
	return ""
}

// ScanRepo walks the workspace at root: it reports secret-looking files, the toolchain its marker
// files point to (installed on e.Path or not), and the package hosts the installed tools need.
// git is part of the toolchain whenever ws.Git is set.
func ScanRepo(ctx context.Context, ws Workspace, e Env) (Repo, error) {
	return ScanRepoProgress(ctx, ws, e, nil)
}

// ScanRepoProgress is ScanRepo telling progress how many entries it has looked at, every thousand or so, so a
// person watching a large project sees it move.
func ScanRepoProgress(ctx context.Context, ws Workspace, e Env, progress func(entries int)) (Repo, error) {
	var r Repo
	seen := map[string][]string{}
	if ws.Git {
		seen["git"] = []string{".git"}
	}
	entries, pyFiles := 0, 0
	started := time.Now()
	err := filepath.WalkDir(ws.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable folder is reported by the engine at compile time; here it is skipped,
			// not fatal, so one locked folder does not hide the rest of the repo.
			if d != nil && d.IsDir() && path != ws.Root {
				return fs.SkipDir
			}
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if path == ws.Root {
			return nil
		}
		entries++
		if progress != nil && entries%1000 == 0 {
			progress(entries)
		}
		if entries > maxEntries {
			r.Cut = true
			return fs.SkipAll
		}
		rel, err := filepath.Rel(ws.Root, path)
		if err != nil {
			return fmt.Errorf("relative path of %s: %w", path, err)
		}
		rel = filepath.ToSlash(rel)
		depth := strings.Count(rel, "/") + 1
		name := d.Name()
		if d.IsDir() {
			if skipDirs[name] {
				return fs.SkipDir
			}
			if lower := strings.ToLower(name); lower == "secrets" || lower == ".secrets" {
				r.Secrets = append(r.Secrets, Finding{Path: rel + "/", Why: "folder named " + name})
			}
			if depth >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !printable(rel) {
			// A name with control characters could rewrite the screen it's shown on. The engine still blocks a
			// .env file by its name; Maze just doesn't print it.
			r.Unprintable++
			return nil
		}
		if isEnvFile(name) {
			r.Secrets = append(r.Secrets, Finding{Path: rel, Why: "environment file", BuiltIn: true})
		} else if isEnvFile(strings.ToLower(name)) {
			// .ENV.local: the engine's list goes by exact name, so Maze blocks it with a rule of its own.
			r.Secrets = append(r.Secrets, Finding{Path: rel, Why: "environment file"})
		} else if why, ok := secretFileWhy(name); ok {
			r.Secrets = append(r.Secrets, Finding{Path: rel, Why: why})
		}
		if !d.IsDir() {
			if fi, err := d.Info(); err == nil && dataless(fi) {
				r.InCloud++
			}
		}
		// Reading contents has a time budget too: a slow disk or a huge project mustn't hold the setup up.
		if strings.HasSuffix(name, ".py") && pyFiles < maxPyFiles && len(r.EnvLoaders) < maxEnvLoader && time.Since(started) >= readBudget {
			noted(path, errBudget)
		}
		if strings.HasSuffix(name, ".py") && pyFiles < maxPyFiles && len(r.EnvLoaders) < maxEnvLoader && time.Since(started) < readBudget {
			pyFiles++
			if loadsEnv(path) {
				r.EnvLoaders = append(r.EnvLoaders, rel)
			}
		}
		if depth <= markerDepth {
			for _, tool := range markers[name] {
				seen[tool] = append(seen[tool], rel)
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return Repo{}, fmt.Errorf("scan %s: %w", ws.Root, err)
	}
	r.Files = min(entries, maxEntries)
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	hostSeen := map[string]bool{}
	for _, name := range names {
		t := Tool{Name: name, Path: e.LookPath(name), From: seen[name]}
		r.Tools = append(r.Tools, t)
		if t.Path == "" {
			continue
		}
		for _, h := range registries[name] {
			if !hostSeen[h] {
				hostSeen[h] = true
				r.Hosts = append(r.Hosts, Host{Name: h, Port: 443, For: name})
			}
		}
	}
	return r, nil
}
